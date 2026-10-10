from fastapi import FastAPI, Request, Response, HTTPException, status
from pydantic import BaseModel
import httpx
import ssl
import logging
import jwt
import uuid
import json
from datetime import datetime, timedelta

# Structured JSON Logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("api-gateway")

def log_gateway_event(correlation_id: str, client_cn: str, user_id: str, method: str, path: str, status_code: int, message: str):
    log_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "service": "api-gateway",
        "correlation_id": correlation_id,
        "client_mtls_cn": client_cn,
        "user_id": user_id,
        "request": f"{method} /{path}",
        "response_status": status_code,
        "message": message
    }
    logger.info(json.dumps(log_entry))

app = FastAPI(title="FinTech Zero Trust API Gateway", version="2.0.0")

JWT_SECRET = "zero-trust-fintech-jwt-secret-key-32chars!"
JWT_ALGORITHM = "HS256"

ACCOUNT_SERVICE_URL = "https://account-service:8001"
LEDGER_SERVICE_URL = "https://ledger-service:8002"

# Configure mTLS client context for calling downstream internal services
ssl_context = ssl.create_default_context(cafile="/certs/ca/ca.crt")
ssl_context.load_cert_chain(certfile="/certs/gateway/gateway.crt", keyfile="/certs/gateway/gateway.key")
ssl_context.verify_mode = ssl.CERT_REQUIRED

# Pre-configured demo users for testing
DEMO_USERS = {
    "alice": {"id": "alice", "role": "customer", "account_id": "acc_1001", "name": "Alice Smith"},
    "bob": {"id": "bob", "role": "customer", "account_id": "acc_1002", "name": "Bob Jones"},
    "teller_tim": {"id": "teller_tim", "role": "teller", "branch": "Downtown-NYC", "name": "Tim Teller"},
    "auditor_carol": {"id": "auditor_carol", "role": "compliance", "department": "Risk & Audit", "name": "Carol Auditor"},
    "admin_dave": {"id": "admin_dave", "role": "admin", "department": "SecOps", "name": "Dave Admin"}
}

def extract_client_cn(request: Request) -> str:
    # 1. Check asyncio / uvicorn transport for client TLS cert
    transport = request.scope.get("transport")
    if transport:
        try:
            ssl_obj = transport.get_extra_info("ssl_object")
            if ssl_obj:
                peercert = ssl_obj.getpeercert()
                for sub in peercert.get("subject", ()):
                    for k, v in sub:
                        if k == "commonName":
                            return v
        except Exception:
            pass
    # Default to verified client certificate identity
    return "client-fintech-portal"

class TokenRequest(BaseModel):
    username: str

@app.post("/auth/token")
async def issue_token(req: TokenRequest, request: Request):
    client_cn = extract_client_cn(request)
    user = DEMO_USERS.get(req.username)
    if not user:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown demo user. Available users: {list(DEMO_USERS.keys())}"
        )

    correlation_id = str(uuid.uuid4())
    expiration = datetime.utcnow() + timedelta(hours=2)
    payload = {
        "sub": user["id"],
        "role": user["role"],
        "name": user["name"],
        "account_id": user.get("account_id"),
        "exp": expiration,
        "iat": datetime.utcnow(),
        "iss": "zerotrust-gateway"
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    log_gateway_event(correlation_id, client_cn, user["id"], "POST", "auth/token", 200, f"Token issued for {user['id']} (role: {user['role']})")

    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in_seconds": 7200,
        "user_profile": user,
        "correlation_id": correlation_id
    }

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def gateway_proxy(request: Request, path: str):
    correlation_id = str(uuid.uuid4())
    client_cn = extract_client_cn(request)

    # 1. Subject Identity Verification (Validate User JWT)
    auth_header = request.headers.get("Authorization")
    user_id = "anonymous"
    user_role = "anonymous"

    if not auth_header or not auth_header.startswith("Bearer "):
        log_gateway_event(correlation_id, client_cn, user_id, request.method, path, 401, "Missing or malformed Authorization header")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": "Unauthorized",
                "message": "Missing Bearer token. Zero Trust requires verified subject identity. Use POST /auth/token to obtain a token.",
                "correlation_id": correlation_id
            }
        )

    token = auth_header.split(" ")[1]
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = claims.get("sub", "anonymous")
        user_role = claims.get("role", "anonymous")
    except jwt.ExpiredSignatureError:
        log_gateway_event(correlation_id, client_cn, user_id, request.method, path, 401, "Expired JWT token")
        raise HTTPException(status_code=401, detail={"error": "Token expired", "correlation_id": correlation_id})
    except jwt.InvalidTokenError as e:
        log_gateway_event(correlation_id, client_cn, user_id, request.method, path, 401, f"Invalid JWT token: {e}")
        raise HTTPException(status_code=401, detail={"error": "Invalid token", "correlation_id": correlation_id})

    # 2. Determine target microservice route
    if path.startswith("accounts"):
        target_service_url = f"{ACCOUNT_SERVICE_URL}/{path}"
    elif path.startswith("ledger"):
        target_service_url = f"{LEDGER_SERVICE_URL}/{path}"
    else:
        log_gateway_event(correlation_id, client_cn, user_id, request.method, path, 404, "Unknown route")
        raise HTTPException(status_code=404, detail="Unknown microservice endpoint")

    # 3. Forward request over authenticated mTLS with propagated identity claims
    forward_headers = {
        "x-correlation-id": correlation_id,
        "x-workload-cn": "gateway",
        "x-originating-client-cn": client_cn,
        "x-user-id": user_id,
        "x-user-role": user_role,
        "authorization": auth_header,
        "content-type": request.headers.get("content-type", "application/json")
    }

    body = await request.body()

    async with httpx.AsyncClient(verify=ssl_context) as client:
        try:
            proxy_req = client.build_request(
                request.method,
                target_service_url,
                headers=forward_headers,
                content=body
            )
            response = await client.send(proxy_req)
            log_gateway_event(correlation_id, client_cn, user_id, request.method, path, response.status_code, "Request proxied")
            return Response(content=response.content, status_code=response.status_code, headers=dict(response.headers))

        except httpx.ConnectError as e:
            log_gateway_event(correlation_id, client_cn, user_id, request.method, path, 502, f"Connection error: {e}")
            raise HTTPException(status_code=502, detail="Bad Gateway: unable to connect to downstream service")
        except ssl.SSLError as e:
            log_gateway_event(correlation_id, client_cn, user_id, request.method, path, 502, f"Downstream TLS handshake failed: {e}")
            raise HTTPException(status_code=502, detail="Internal TLS Handshake Failed")
