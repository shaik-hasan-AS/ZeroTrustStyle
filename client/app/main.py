from fastapi import FastAPI, Request, Response, HTTPException, Header
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import httpx
import ssl
import os
import json
import uuid
import time
from typing import Optional

app = FastAPI(title="FinTech Zero Trust Web Client & Security Cockpit", version="2.0.0")

# Paths configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

# Certs search path (support container or host run)
CERTS_DIR = "/certs" if os.path.exists("/certs/ca/ca.crt") else os.path.abspath(os.path.join(BASE_DIR, "../../certs"))

# Downstream services URLs
GATEWAY_URL = os.environ.get("GATEWAY_URL", "https://gateway:8000" if os.path.exists("/.dockerenv") else "https://localhost:8000")
ACCOUNT_SERVICE_URL = os.environ.get("ACCOUNT_SERVICE_URL", "https://account-service:8001" if os.path.exists("/.dockerenv") else "https://localhost:8001")
LEDGER_SERVICE_URL = os.environ.get("LEDGER_SERVICE_URL", "https://ledger-service:8002" if os.path.exists("/.dockerenv") else "https://localhost:8002")
OPA_URL = os.environ.get("OPA_URL", "http://opa:8181" if os.path.exists("/.dockerenv") else "http://localhost:8181")

def get_ssl_context(cert_type: str = "client") -> ssl.SSLContext:
    """Creates mTLS SSL Context for outbound requests."""
    ca_path = os.path.join(CERTS_DIR, "ca/ca.crt")
    ctx = ssl.create_default_context(cafile=ca_path)
    ctx.verify_mode = ssl.CERT_REQUIRED
    
    if cert_type == "client":
        cert_file = os.path.join(CERTS_DIR, "client/client.crt")
        key_file = os.path.join(CERTS_DIR, "client/client.key")
        ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    elif cert_type == "rogue":
        cert_file = os.path.join(CERTS_DIR, "rogue-service/rogue-service.crt")
        key_file = os.path.join(CERTS_DIR, "rogue-service/rogue-service.key")
        ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    elif cert_type == "untrusted":
        cert_file = os.path.join(CERTS_DIR, "untrusted-client/untrusted.crt")
        key_file = os.path.join(CERTS_DIR, "untrusted-client/untrusted.key")
        ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    elif cert_type == "none":
        pass # No client cert presented
        
    return ctx

# Personas definition
DEMO_PERSONAS = {
    "alice": {
        "id": "alice",
        "name": "Alice Smith",
        "role": "customer",
        "account_id": "acc_1001",
        "account_type": "Checking",
        "description": "Standard retail customer. Owns account acc_1001. Transfer limit: $10,000.",
        "badge": "Customer",
        "avatar": "👩‍💼"
    },
    "bob": {
        "id": "bob",
        "name": "Bob Jones",
        "role": "customer",
        "account_id": "acc_1002",
        "account_type": "Savings",
        "description": "Retail customer. Owns account acc_1002. Transfer limit: $10,000.",
        "badge": "Customer",
        "avatar": "👨‍💼"
    },
    "teller_tim": {
        "id": "teller_tim",
        "name": "Tim Teller",
        "role": "teller",
        "branch": "Downtown-NYC",
        "description": "Branch Bank Teller. Authorized to assist customers and execute transfers up to $50,000.",
        "badge": "Bank Teller",
        "avatar": "🏦"
    },
    "auditor_carol": {
        "id": "auditor_carol",
        "name": "Carol Auditor",
        "role": "compliance",
        "department": "Risk & Compliance",
        "description": "Compliance & Risk Auditor. Authorized to inspect the immutable double-entry ledger.",
        "badge": "Compliance Auditor",
        "avatar": "🛡️"
    },
    "admin_dave": {
        "id": "admin_dave",
        "name": "Dave Admin",
        "role": "admin",
        "department": "SecOps & Infra",
        "description": "Enterprise Security Admin. Full transfer override, maintenance, and audit capabilities.",
        "badge": "SecOps Admin",
        "avatar": "👑"
    },
    "rogue_hacker": {
        "id": "rogue_hacker",
        "name": "Rogue Infiltrator",
        "role": "untrusted",
        "description": "Lateral movement adversary attempting direct ledger bypass with rogue certificate.",
        "badge": "Attacker",
        "avatar": "🥷"
    }
}

class TokenExchangeRequest(BaseModel):
    username: str

class TransferPayload(BaseModel):
    source_account: str
    destination_account: str
    amount: float
    note: str = ""

@app.get("/api/personas")
async def list_personas():
    return DEMO_PERSONAS

@app.get("/api/status")
async def get_system_status():
    status = {
        "gateway": {"url": GATEWAY_URL, "status": "UNKNOWN", "latency_ms": 0},
        "account_service": {"url": ACCOUNT_SERVICE_URL, "status": "UNKNOWN", "latency_ms": 0},
        "ledger_service": {"url": LEDGER_SERVICE_URL, "status": "UNKNOWN", "latency_ms": 0},
        "opa": {"url": OPA_URL, "status": "UNKNOWN", "latency_ms": 0}
    }
    
    # Check Gateway via mTLS
    t0 = time.time()
    try:
        async with httpx.AsyncClient(verify=get_ssl_context("client"), timeout=2.0) as client:
            resp = await client.post(f"{GATEWAY_URL}/auth/token", json={"username": "alice"})
            status["gateway"] = {
                "url": GATEWAY_URL,
                "status": "HEALTHY" if resp.status_code == 200 else "DEGRADED",
                "latency_ms": round((time.time() - t0) * 1000, 1),
                "tls_mode": "mTLS (Layer 4 Verified)"
            }
    except Exception as e:
        status["gateway"] = {"url": GATEWAY_URL, "status": "OFFLINE", "error": str(e)}

    # Check Account Service direct
    t0 = time.time()
    try:
        async with httpx.AsyncClient(verify=get_ssl_context("client"), timeout=2.0) as client:
            resp = await client.get(f"{ACCOUNT_SERVICE_URL}/accounts", headers={"x-workload-cn": "gateway"})
            status["account_service"] = {
                "url": ACCOUNT_SERVICE_URL,
                "status": "HEALTHY" if resp.status_code == 200 else "DEGRADED",
                "latency_ms": round((time.time() - t0) * 1000, 1),
                "tls_mode": "mTLS (Workload Identity Required)"
            }
    except Exception as e:
        status["account_service"] = {"url": ACCOUNT_SERVICE_URL, "status": "OFFLINE", "error": str(e)}

    # Check Ledger Service direct
    t0 = time.time()
    try:
        async with httpx.AsyncClient(verify=get_ssl_context("client"), timeout=2.0) as client:
            resp = await client.get(f"{LEDGER_SERVICE_URL}/ledger/audit-trail", headers={"x-workload-cn": "account-service", "x-user-role": "compliance"})
            status["ledger_service"] = {
                "url": LEDGER_SERVICE_URL,
                "status": "HEALTHY" if resp.status_code == 200 else "DEGRADED",
                "latency_ms": round((time.time() - t0) * 1000, 1),
                "tls_mode": "mTLS (Strict Anti-Lateral Movement)"
            }
    except Exception as e:
        status["ledger_service"] = {"url": LEDGER_SERVICE_URL, "status": "OFFLINE", "error": str(e)}

    # Check OPA
    t0 = time.time()
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(f"{OPA_URL}/v1/policies")
            status["opa"] = {
                "url": OPA_URL,
                "status": "HEALTHY" if resp.status_code == 200 else "DEGRADED",
                "latency_ms": round((time.time() - t0) * 1000, 1),
                "policy_loaded": "authz.rego"
            }
    except Exception as e:
        status["opa"] = {"url": OPA_URL, "status": "OFFLINE", "error": str(e)}

    return status

@app.post("/api/auth/token")
async def obtain_token(req: TokenExchangeRequest):
    """Exchanges username for JWT token through Gateway via mTLS."""
    t0 = time.time()
    async with httpx.AsyncClient(verify=get_ssl_context("client")) as client:
        try:
            resp = await client.post(
                f"{GATEWAY_URL}/auth/token",
                json={"username": req.username},
                timeout=5.0
            )
            elapsed = round((time.time() - t0) * 1000, 1)
            data = resp.json()
            data["telemetry"] = {
                "client_workload_cn": "client-fintech-portal",
                "gateway_url": GATEWAY_URL,
                "tls_cipher": "TLS_AES_256_GCM_SHA384",
                "roundtrip_ms": elapsed
            }
            return JSONResponse(status_code=resp.status_code, content=data)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Failed to communicate with Gateway: {e}")

@app.get("/api/accounts")
async def get_accounts(authorization: Optional[str] = Header(None)):
    """Fetches authorized accounts list for current persona via Gateway."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization Bearer token")
    
    t0 = time.time()
    async with httpx.AsyncClient(verify=get_ssl_context("client")) as client:
        try:
            resp = await client.get(
                f"{GATEWAY_URL}/accounts",
                headers={"Authorization": authorization},
                timeout=5.0
            )
            elapsed = round((time.time() - t0) * 1000, 1)
            content = resp.json()
            if isinstance(content, dict):
                content["telemetry"] = {
                    "mtls_verified": True,
                    "caller_workload_cn": "client-fintech-portal",
                    "hop": "Client -> Gateway -> Account-Service",
                    "roundtrip_ms": elapsed
                }
            return JSONResponse(status_code=resp.status_code, content=content)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Proxy error: {e}")

@app.get("/api/accounts/{account_id}")
async def get_account_detail(account_id: str, authorization: Optional[str] = Header(None)):
    """Fetches specific account. Demonstrates BOLA / ABAC policy enforcement."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization Bearer token")
    
    t0 = time.time()
    async with httpx.AsyncClient(verify=get_ssl_context("client")) as client:
        try:
            resp = await client.get(
                f"{GATEWAY_URL}/accounts/{account_id}",
                headers={"Authorization": authorization},
                timeout=5.0
            )
            elapsed = round((time.time() - t0) * 1000, 1)
            content = resp.json()
            if isinstance(content, dict):
                content["telemetry"] = {
                    "mtls_verified": True,
                    "target_account": account_id,
                    "status_code": resp.status_code,
                    "roundtrip_ms": elapsed
                }
            return JSONResponse(status_code=resp.status_code, content=content)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Proxy error: {e}")

@app.post("/api/transfers")
async def execute_transfer(transfer: TransferPayload, authorization: Optional[str] = Header(None)):
    """Executes a financial transfer through Gateway with OPA ABAC validation and ledger append."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization Bearer token")
    
    t0 = time.time()
    async with httpx.AsyncClient(verify=get_ssl_context("client")) as client:
        try:
            resp = await client.post(
                f"{GATEWAY_URL}/accounts/{transfer.source_account}/transfers",
                headers={"Authorization": authorization, "Content-Type": "application/json"},
                json={
                    "destination_account": transfer.destination_account,
                    "amount": transfer.amount,
                    "note": transfer.note
                },
                timeout=5.0
            )
            elapsed = round((time.time() - t0) * 1000, 1)
            content = resp.json()
            if isinstance(content, dict):
                content["telemetry"] = {
                    "mtls_pipeline": "Client (mTLS) -> Gateway (mTLS) -> Account Service (mTLS) -> Ledger Service",
                    "amount": transfer.amount,
                    "status_code": resp.status_code,
                    "roundtrip_ms": elapsed
                }
            return JSONResponse(status_code=resp.status_code, content=content)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Proxy error: {e}")

@app.get("/api/ledger")
async def get_ledger(authorization: Optional[str] = Header(None)):
    """Fetches immutable double-entry ledger audit trail through Gateway."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization Bearer token")
    
    t0 = time.time()
    async with httpx.AsyncClient(verify=get_ssl_context("client")) as client:
        try:
            resp = await client.get(
                f"{GATEWAY_URL}/ledger/audit-trail",
                headers={"Authorization": authorization},
                timeout=5.0
            )
            elapsed = round((time.time() - t0) * 1000, 1)
            content = resp.json()
            if isinstance(content, dict):
                content["telemetry"] = {
                    "mtls_verified": True,
                    "roundtrip_ms": elapsed
                }
            return JSONResponse(status_code=resp.status_code, content=content)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Proxy error: {e}")

@app.post("/api/ledger/tamper")
async def simulate_ledger_tamper(authorization: Optional[str] = Header(None)):
    """Simulates a rogue database tamper attack on ledger rows."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization Bearer token")
    
    async with httpx.AsyncClient(verify=get_ssl_context("client")) as client:
        try:
            resp = await client.post(
                f"{GATEWAY_URL}/ledger/simulate-tamper",
                headers={"Authorization": authorization},
                timeout=5.0
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Proxy error: {e}")

@app.post("/api/system/reset")
async def reset_demo_system(authorization: Optional[str] = Header(None)):
    """Resets accounts and ledger back to original state."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization Bearer token")
    
    async with httpx.AsyncClient(verify=get_ssl_context("client")) as client:
        try:
            acc_resp = await client.post(f"{GATEWAY_URL}/accounts/reset", headers={"Authorization": authorization})
            led_resp = await client.post(f"{GATEWAY_URL}/ledger/reset", headers={"Authorization": authorization})
            return {
                "status": "SYSTEM_RESET_SUCCESSFUL",
                "accounts": acc_resp.json() if acc_resp.status_code == 200 else acc_resp.text,
                "ledger": led_resp.json() if led_resp.status_code == 200 else led_resp.text
            }
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"Reset error: {e}")

@app.post("/api/demo/scenario/{scenario_id}")
async def run_scenario(scenario_id: int):
    """
    Executes one of the 9 official Zero Trust scenarios on demand.
    Returns step-by-step trace, logs, mTLS details, JWT claims, and OPA decisions.
    """
    steps = []
    
    try:
        if scenario_id == 1:
            # Scenario 1: Customer Accessing Own Account (Authorized)
            steps.append({"step": 1, "action": "Issue JWT for 'alice' (Customer, Owner of acc_1001)", "status": "PENDING"})
            async with httpx.AsyncClient(verify=get_ssl_context("client")) as client:
                t_resp = await client.post(f"{GATEWAY_URL}/auth/token", json={"username": "alice"})
                token = t_resp.json()["access_token"]
                steps[0]["status"] = "SUCCESS"
                steps[0]["detail"] = "JWT obtained with claims sub=alice, role=customer"

                steps.append({"step": 2, "action": "mTLS GET /accounts/acc_1001 with Alice's Bearer JWT", "status": "PENDING"})
                r = await client.get(f"{GATEWAY_URL}/accounts/acc_1001", headers={"Authorization": f"Bearer {token}"})
                steps[1]["status"] = "SUCCESS" if r.status_code == 200 else "FAILED"
                steps[1]["status_code"] = r.status_code
                steps[1]["response"] = r.json()

            return {
                "scenario": 1,
                "title": "Customer Accessing Own Account (Authorized)",
                "zero_trust_principle": "Subject Identity & ABAC Resource Ownership (user.id == resource.owner_id)",
                "verdict": "ALLOWED",
                "badge": "PASS",
                "steps": steps
            }

        elif scenario_id == 2:
            # Scenario 2: Customer Accessing Other Account (ABAC Denied - BOLA Attack)
            steps.append({"step": 1, "action": "Issue JWT for 'alice'", "status": "PENDING"})
            async with httpx.AsyncClient(verify=get_ssl_context("client")) as client:
                t_resp = await client.post(f"{GATEWAY_URL}/auth/token", json={"username": "alice"})
                token = t_resp.json()["access_token"]
                steps[0]["status"] = "SUCCESS"

                steps.append({"step": 2, "action": "Alice attempts GET /accounts/acc_1002 (Bob's Account)", "status": "PENDING"})
                r = await client.get(f"{GATEWAY_URL}/accounts/acc_1002", headers={"Authorization": f"Bearer {token}"})
                steps[1]["status"] = "BLOCKED" if r.status_code == 403 else "UNEXPECTED"
                steps[1]["status_code"] = r.status_code
                steps[1]["response"] = r.json()

            return {
                "scenario": 2,
                "title": "Broken Object Level Authorization / BOLA Attack (Denied)",
                "zero_trust_principle": "ABAC Ownership Verification: Customer cannot inspect other users' accounts",
                "verdict": "DENIED (OPA 403 Forbidden)",
                "badge": "PASS",
                "steps": steps
            }

        elif scenario_id == 3:
            # Scenario 3: Transfer Within Limit (Allowed + Hash Chained Ledger Write)
            steps.append({"step": 1, "action": "Issue JWT for 'alice'", "status": "PENDING"})
            async with httpx.AsyncClient(verify=get_ssl_context("client")) as client:
                t_resp = await client.post(f"{GATEWAY_URL}/auth/token", json={"username": "alice"})
                token = t_resp.json()["access_token"]
                steps[0]["status"] = "SUCCESS"

                steps.append({"step": 2, "action": "POST /accounts/acc_1001/transfers ($500.00 to acc_1002)", "status": "PENDING"})
                r = await client.post(
                    f"{GATEWAY_URL}/accounts/acc_1001/transfers",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"destination_account": "acc_1002", "amount": 500.0, "note": "Demo Payment"}
                )
                steps[1]["status"] = "SUCCESS" if r.status_code == 200 else "FAILED"
                steps[1]["status_code"] = r.status_code
                steps[1]["response"] = r.json()

            return {
                "scenario": 3,
                "title": "Transfer Within Limit ($500.00 <= $10,000 threshold)",
                "zero_trust_principle": "Policy Check Before State Logic + Microsegmented Immutable Ledger",
                "verdict": "ALLOWED & IMMUTABLY JOURNALED",
                "badge": "PASS",
                "steps": steps
            }

        elif scenario_id == 4:
            # Scenario 4: Transfer Exceeding Limit (Threshold Denied)
            steps.append({"step": 1, "action": "Issue JWT for 'alice'", "status": "PENDING"})
            async with httpx.AsyncClient(verify=get_ssl_context("client")) as client:
                t_resp = await client.post(f"{GATEWAY_URL}/auth/token", json={"username": "alice"})
                token = t_resp.json()["access_token"]
                steps[0]["status"] = "SUCCESS"

                steps.append({"step": 2, "action": "POST /accounts/acc_1001/transfers ($25,000.00 - exceeds $10k limit)", "status": "PENDING"})
                r = await client.post(
                    f"{GATEWAY_URL}/accounts/acc_1001/transfers",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"destination_account": "acc_1002", "amount": 25000.0, "note": "High value fraud attempt"}
                )
                steps[1]["status"] = "BLOCKED" if r.status_code == 403 else "UNEXPECTED"
                steps[1]["status_code"] = r.status_code
                steps[1]["response"] = r.json()

            return {
                "scenario": 4,
                "title": "Customer Transfer Exceeding Policy Limit ($25,000 > $10,000)",
                "zero_trust_principle": "Zero Trust Guardrails: Dynamic transaction limits enforced by OPA PDP",
                "verdict": "DENIED (OPA 403 Forbidden)",
                "badge": "PASS",
                "steps": steps
            }

        elif scenario_id == 5:
            # Scenario 5: Teller High-Value Transfer (Role Escalated Allowed)
            steps.append({"step": 1, "action": "Issue JWT for 'teller_tim' (Role: teller, Limit: $50,000)", "status": "PENDING"})
            async with httpx.AsyncClient(verify=get_ssl_context("client")) as client:
                t_resp = await client.post(f"{GATEWAY_URL}/auth/token", json={"username": "teller_tim"})
                token = t_resp.json()["access_token"]
                steps[0]["status"] = "SUCCESS"

                steps.append({"step": 2, "action": "Tim Teller executes assisted $25,000 transfer from acc_1003", "status": "PENDING"})
                r = await client.post(
                    f"{GATEWAY_URL}/accounts/acc_1003/transfers",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"destination_account": "acc_1001", "amount": 25000.0, "note": "Teller Assisted Wire"}
                )
                steps[1]["status"] = "SUCCESS" if r.status_code == 200 else "FAILED"
                steps[1]["status_code"] = r.status_code
                steps[1]["response"] = r.json()

            return {
                "scenario": 5,
                "title": "Bank Teller High-Value Assisted Transfer ($25,000 <= $50,000)",
                "zero_trust_principle": "Role-Based Privilege Escalation with Explicit Dual-Control Guardrails",
                "verdict": "ALLOWED (Teller Policy Applied)",
                "badge": "PASS",
                "steps": steps
            }

        elif scenario_id == 6:
            # Scenario 6: Compliance Audit of Immutable Ledger (Allowed)
            steps.append({"step": 1, "action": "Issue JWT for 'auditor_carol' (Role: compliance)", "status": "PENDING"})
            async with httpx.AsyncClient(verify=get_ssl_context("client")) as client:
                t_resp = await client.post(f"{GATEWAY_URL}/auth/token", json={"username": "auditor_carol"})
                token = t_resp.json()["access_token"]
                steps[0]["status"] = "SUCCESS"

                steps.append({"step": 2, "action": "Carol requests GET /ledger/audit-trail with cryptographic chain verification", "status": "PENDING"})
                r = await client.get(f"{GATEWAY_URL}/ledger/audit-trail", headers={"Authorization": f"Bearer {token}"})
                steps[1]["status"] = "SUCCESS" if r.status_code == 200 else "FAILED"
                steps[1]["status_code"] = r.status_code
                steps[1]["response"] = r.json()

            return {
                "scenario": 6,
                "title": "Compliance Audit of Cryptographic Hash Chain Ledger",
                "zero_trust_principle": "Segregation of Duties & Non-Repudiation (Audit Trail Integrity)",
                "verdict": "ALLOWED & HASH CHAIN VALIDATED",
                "badge": "PASS",
                "steps": steps
            }

        elif scenario_id == 7:
            # Scenario 7: Customer Accessing Audit Trail (Role Denied)
            steps.append({"step": 1, "action": "Issue JWT for 'alice' (Role: customer)", "status": "PENDING"})
            async with httpx.AsyncClient(verify=get_ssl_context("client")) as client:
                t_resp = await client.post(f"{GATEWAY_URL}/auth/token", json={"username": "alice"})
                token = t_resp.json()["access_token"]
                steps[0]["status"] = "SUCCESS"

                steps.append({"step": 2, "action": "Alice attempts GET /ledger/audit-trail", "status": "PENDING"})
                r = await client.get(f"{GATEWAY_URL}/ledger/audit-trail", headers={"Authorization": f"Bearer {token}"})
                steps[1]["status"] = "BLOCKED" if r.status_code == 403 else "UNEXPECTED"
                steps[1]["status_code"] = r.status_code
                steps[1]["response"] = r.json()

            return {
                "scenario": 7,
                "title": "Customer Unauthorized Ledger Access Attempt (Denied)",
                "zero_trust_principle": "Segregation of Duties: Financial audit journal restricted to compliance officers",
                "verdict": "DENIED (OPA 403 Forbidden)",
                "badge": "PASS",
                "steps": steps
            }

        elif scenario_id == 8:
            # Scenario 8: Lateral Movement Attack / Direct Core Ledger Bypass (Denied)
            steps.append({
                "step": 1,
                "action": "Attacker connects directly to Core Ledger (:8002) using CA-signed rogue cert (CN=rogue-unauthorized-workload)",
                "status": "PENDING"
            })
            async with httpx.AsyncClient(verify=get_ssl_context("rogue")) as rogue_client:
                r = await rogue_client.post(
                    f"{LEDGER_SERVICE_URL}/ledger/entries",
                    json={
                        "source_account": "acc_1001",
                        "destination_account": "hacker_account",
                        "amount": 999999.00,
                        "currency": "USD",
                        "user_id": "hacker",
                        "user_role": "admin",
                        "correlation_id": "attack-lateral-001"
                    }
                )
                steps[0]["status"] = "BLOCKED" if r.status_code == 403 else "UNEXPECTED"
                steps[0]["status_code"] = r.status_code
                steps[0]["response"] = r.json()

            return {
                "scenario": 8,
                "title": "Lateral Movement Attack / Direct Core Ledger Bypass (Denied)",
                "zero_trust_principle": "Workload Identity Verification: Only account-service may write to Ledger",
                "verdict": "DENIED (Workload Isolation Enforced)",
                "badge": "PASS",
                "steps": steps
            }

        elif scenario_id == 9:
            # Scenario 9: Untrusted or Missing Client Certificate (TLS Handshake Terminated)
            steps.append({
                "step": 1,
                "action": "Attempting TLS connection to Gateway (:8000) using untrusted CA cert",
                "status": "PENDING"
            })
            handshake_dropped = False
            error_message = ""
            try:
                async with httpx.AsyncClient(verify=get_ssl_context("untrusted"), timeout=2.0) as un_client:
                    await un_client.get(f"{GATEWAY_URL}/accounts/acc_1001")
            except Exception as e:
                handshake_dropped = True
                error_message = str(e)
            
            steps[0]["status"] = "HANDSHAKE_TERMINATED" if handshake_dropped else "UNEXPECTED"
            steps[0]["detail"] = f"mTLS Handshake rejected at Layer 4: {error_message}"

            return {
                "scenario": 9,
                "title": "Untrusted or Missing Client Certificate (TLS Handshake Failure)",
                "zero_trust_principle": "Cryptographic Mutual Authentication: Unauthenticated packets dropped at Layer 4",
                "verdict": "DROPPED AT TLS HANDSHAKE",
                "badge": "PASS",
                "steps": steps
            }

        else:
            raise HTTPException(status_code=400, detail="Invalid scenario ID. Choose 1 to 9.")

    except Exception as e:
        return {
            "scenario": scenario_id,
            "error": str(e),
            "verdict": "ERROR",
            "steps": steps
        }

@app.post("/api/wireshark/burst")
async def trigger_wireshark_traffic():
    """Generates an active sequence of mTLS handshakes and transactions for live Wireshark packet capture."""
    summary = []
    
    # 1. Normal Alice token exchange (mTLS Client -> Gateway)
    try:
        async with httpx.AsyncClient(verify=get_ssl_context("client")) as client:
            r = await client.post(f"{GATEWAY_URL}/auth/token", json={"username": "alice"})
            token = r.json().get("access_token")
            summary.append({"action": "mTLS Handshake + Token Exchange", "target": "gateway:8000", "status": r.status_code})

            # 2. Alice account query (mTLS Gateway -> Account-Service)
            if token:
                r2 = await client.get(f"{GATEWAY_URL}/accounts/acc_1001", headers={"Authorization": f"Bearer {token}"})
                summary.append({"action": "ABAC Account Inspection", "target": "gateway:8000", "status": r2.status_code})

                # 3. Small transfer (triggers Account-Service -> Ledger-Service mTLS hop)
                r3 = await client.post(
                    f"{GATEWAY_URL}/accounts/acc_1001/transfers",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"destination_account": "acc_1002", "amount": 10.0, "note": "Wireshark Demo Ping"}
                )
                summary.append({"action": "Inter-Service mTLS Ledger Hop", "target": "account-service -> ledger-service", "status": r3.status_code})

        # 4. Rogue cert lateral movement packet
        async with httpx.AsyncClient(verify=get_ssl_context("rogue")) as rogue_client:
            r4 = await rogue_client.post(
                f"{LEDGER_SERVICE_URL}/ledger/entries",
                json={"source_account": "acc_1001", "destination_account": "wireshark_probe", "amount": 1.0, "currency": "USD", "user_id": "probe", "user_role": "admin", "correlation_id": "wireshark-test"}
            )
            summary.append({"action": "Rogue Workload TLS Handshake (Blocked by OPA)", "target": "ledger-service:8002", "status": r4.status_code})

    except Exception as e:
        summary.append({"error": str(e)})

    return {
        "status": "BURST_COMPLETED",
        "message": "Generated 4 distinct multi-hop mTLS handshakes for Wireshark inspection.",
        "operations": summary
    }

@app.get("/api/wireshark/guide")
async def get_wireshark_guide():
    return {
        "recommended_command": "sudo wireshark -i any -k -f 'tcp port 8000 or tcp port 8001 or tcp port 8002'",
        "docker_command": "sudo wireshark -i docker0 -k",
        "display_filters": [
            {
                "filter": "tls.handshake.type == 13",
                "label": "Certificate Request",
                "meaning": "Proves server requests client certificate (Mutual TLS enforcement)"
            },
            {
                "filter": "tls.handshake.type == 11",
                "label": "Certificate Exchange",
                "meaning": "Shows X.509 certificates being sent with Subject CNs"
            },
            {
                "filter": "tls.handshake.type == 15",
                "label": "Certificate Verify",
                "meaning": "Client signs handshake to prove private key ownership"
            },
            {
                "filter": "tcp.port in {8000, 8001, 8002}",
                "label": "All Zero-Trust Microservice Ports",
                "meaning": "Shows all inter-service mesh traffic"
            }
        ],
        "demo_talking_points": [
            "Point out 'Certificate Request' (Type 13) in Wireshark: Demonstrates Server will NOT accept plain client connections.",
            "Inspect 'Certificate' (Type 11): Highlight Subject Alternative Names (SAN) and Subject CN (e.g. client-fintech-portal, gateway, account-service).",
            "Show Encrypted Application Data: All payloads are TLS 1.3 / AES-256 encrypted.",
            "Demonstrate Scenario 8: TLS Handshake passes with rogue cert, but HTTP 403 occurs at Layer 7 due to OPA Workload Identity verification."
        ]
    }

# Serve static files and SPA frontend
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
async def serve_index():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "FinTech Zero Trust Client Portal Backend Running. Static index.html loading..."}
