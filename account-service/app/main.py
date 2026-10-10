from fastapi import FastAPI, Request, Response, HTTPException
from pydantic import BaseModel
import httpx
import ssl
import logging
import sqlite3
import os
import uuid
import json
from datetime import datetime

# Structured JSON logging for SIEM / Security Auditing
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("account-service")

def log_security_event(event_type: str, correlation_id: str, caller_cn: str, user_id: str, user_role: str, action: str, resource: str, decision: str, reason: str):
    log_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "service": "account-service",
        "event_type": event_type,
        "correlation_id": correlation_id,
        "workload_identity": caller_cn,
        "user_identity": {"id": user_id, "role": user_role},
        "action": action,
        "resource": resource,
        "policy_decision": decision,
        "reason": reason
    }
    logger.info(json.dumps(log_entry))

app = FastAPI(title="FinTech Account Service", version="2.0.0")

DB_PATH = "/data/accounts.db" if os.path.exists("/data") else "accounts.db"
OPA_URL = "http://opa:8181/v1/data/authz/decision"
LEDGER_SERVICE_URL = "https://ledger-service:8002"

# Configure mTLS client context for calling Ledger Service
ssl_context = ssl.create_default_context(cafile="/certs/ca/ca.crt")
ssl_context.load_cert_chain(certfile="/certs/account-service/account-service.crt", keyfile="/certs/account-service/account-service.key")
ssl_context.verify_mode = ssl.CERT_REQUIRED

# Database initialization
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            account_id TEXT PRIMARY KEY,
            owner_id TEXT NOT NULL,
            account_type TEXT NOT NULL,
            balance REAL NOT NULL,
            currency TEXT NOT NULL
        )
    """)
    # Seed default accounts if empty
    cursor.execute("SELECT COUNT(*) FROM accounts")
    if cursor.fetchone()[0] == 0:
        cursor.executemany("""
            INSERT INTO accounts (account_id, owner_id, account_type, balance, currency)
            VALUES (?, ?, ?, ?, ?)
        """, [
            ("acc_1001", "alice", "Checking", 5000.0, "USD"),
            ("acc_1002", "bob", "Savings", 3200.0, "USD"),
            ("acc_1003", "charlie", "Investment", 25000.0, "USD")
        ])
        conn.commit()
    conn.close()

init_db()

def extract_workload_cn(request: Request) -> str:
    # 1. Check validated internal header set by gateway
    workload_cn = request.headers.get("x-workload-cn")
    if workload_cn:
        return workload_cn

    # 2. Inspect TLS transport peer certificate
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

    return "unknown-untrusted-workload"

async def evaluate_opa_policy(payload: dict) -> dict:
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(OPA_URL, json=payload, timeout=5.0)
            data = resp.json()
            return data.get("result", {"allow": False, "reason": "OPA returned empty decision"})
        except Exception as e:
            logger.error(json.dumps({"error": f"OPA connection failed: {e}"}))
            return {"allow": False, "reason": f"OPA PDP unavailable: {str(e)}"}

class TransferRequest(BaseModel):
    destination_account: str
    amount: float
    note: str = ""

@app.get("/accounts")
async def list_accounts(request: Request):
    caller_cn = extract_workload_cn(request)
    user_id = request.headers.get("x-user-id", "anonymous")
    user_role = request.headers.get("x-user-role", "anonymous")
    correlation_id = request.headers.get("x-correlation-id", str(uuid.uuid4()))

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if user_role in ["teller", "compliance", "admin"]:
        cursor.execute("SELECT * FROM accounts")
    else:
        cursor.execute("SELECT * FROM accounts WHERE owner_id = ?", (user_id,))
    
    rows = cursor.fetchall()
    conn.close()

    log_security_event("LIST_ACCOUNTS", correlation_id, caller_cn, user_id, user_role, "GET", "/accounts", "ALLOW", "User retrieved authorized account view")
    return {"accounts": [dict(r) for r in rows], "correlation_id": correlation_id}

@app.get("/accounts/{account_id}")
async def get_account(account_id: str, request: Request):
    caller_cn = extract_workload_cn(request)
    user_id = request.headers.get("x-user-id", "anonymous")
    user_role = request.headers.get("x-user-role", "anonymous")
    correlation_id = request.headers.get("x-correlation-id", str(uuid.uuid4()))

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,))
    account = cursor.fetchone()
    conn.close()

    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    account_data = dict(account)

    # Prepare OPA input payload for ABAC evaluation
    opa_input = {
        "input": {
            "service": "account-service",
            "caller": {"workload_cn": caller_cn},
            "user": {"id": user_id, "role": user_role},
            "action": {"method": "GET", "path": f"/accounts/{account_id}"},
            "resource": {
                "type": "account",
                "account_id": account_id,
                "owner_id": account_data["owner_id"],
                "balance": account_data["balance"]
            }
        }
    }

    decision = await evaluate_opa_policy(opa_input)
    is_allowed = decision.get("allow", False)
    reason = decision.get("reason", "No reason provided")

    log_security_event("AUTHZ_EVALUATION", correlation_id, caller_cn, user_id, user_role, f"GET /accounts/{account_id}", f"account:{account_id}", "ALLOW" if is_allowed else "DENY", reason)

    if not is_allowed:
        raise HTTPException(status_code=403, detail={
            "error": "Forbidden",
            "message": "Zero Trust Policy Denied Access",
            "reason": reason,
            "correlation_id": correlation_id
        })

    return {"account": account_data, "correlation_id": correlation_id, "authz_reason": reason}

@app.post("/accounts/{account_id}/transfers")
async def transfer_funds(account_id: str, transfer: TransferRequest, request: Request):
    caller_cn = extract_workload_cn(request)
    user_id = request.headers.get("x-user-id", "anonymous")
    user_role = request.headers.get("x-user-role", "anonymous")
    correlation_id = request.headers.get("x-correlation-id", str(uuid.uuid4()))

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,))
    src_account = cursor.fetchone()

    cursor.execute("SELECT * FROM accounts WHERE account_id = ?", (transfer.destination_account,))
    dst_account = cursor.fetchone()

    if not src_account:
        conn.close()
        raise HTTPException(status_code=404, detail="Source account not found")
    if not dst_account:
        conn.close()
        raise HTTPException(status_code=404, detail="Destination account not found")

    src_data = dict(src_account)

    # 1. EVALUATE OPA ABAC POLICY FIRST (Zero Trust Principle: Policy check before business state logic)
    opa_input = {
        "input": {
            "service": "account-service",
            "caller": {"workload_cn": caller_cn},
            "user": {"id": user_id, "role": user_role},
            "action": {
                "method": "POST",
                "path": f"/accounts/{account_id}/transfers",
                "amount": transfer.amount,
                "destination_account": transfer.destination_account
            },
            "resource": {
                "type": "account",
                "account_id": account_id,
                "owner_id": src_data["owner_id"],
                "balance": src_data["balance"]
            }
        }
    }

    decision = await evaluate_opa_policy(opa_input)
    is_allowed = decision.get("allow", False)
    reason = decision.get("reason", "No reason provided")

    log_security_event("TRANSFER_AUTHZ", correlation_id, caller_cn, user_id, user_role, f"POST /accounts/{account_id}/transfers", f"amount:{transfer.amount}", "ALLOW" if is_allowed else "DENY", reason)

    if not is_allowed:
        conn.close()
        raise HTTPException(status_code=403, detail={
            "error": "Forbidden",
            "message": "Transfer rejected by Zero Trust policy engine",
            "reason": reason,
            "correlation_id": correlation_id
        })

    # 2. Check sufficient funds
    if src_data["balance"] < transfer.amount:
        conn.close()
        raise HTTPException(status_code=400, detail="Insufficient funds in source account")

    # 3. Execute transfer locally
    new_src_balance = src_data["balance"] - transfer.amount
    new_dst_balance = dst_account["balance"] + transfer.amount
    cursor.execute("UPDATE accounts SET balance = ? WHERE account_id = ?", (new_src_balance, account_id))
    cursor.execute("UPDATE accounts SET balance = ? WHERE account_id = ?", (new_dst_balance, transfer.destination_account))
    conn.commit()
    conn.close()

    # 4. Propagate to Ledger Service via secure internal mTLS
    ledger_entry_payload = {
        "source_account": account_id,
        "destination_account": transfer.destination_account,
        "amount": transfer.amount,
        "currency": src_data["currency"],
        "note": transfer.note,
        "user_id": user_id,
        "user_role": user_role,
        "correlation_id": correlation_id
    }

    ledger_receipt = None
    async with httpx.AsyncClient(verify=ssl_context) as client:
        try:
            resp = await client.post(
                f"{LEDGER_SERVICE_URL}/ledger/entries",
                json=ledger_entry_payload,
                headers={
                    "x-correlation-id": correlation_id,
                    "x-workload-cn": "account-service",
                    "x-user-id": user_id,
                    "x-user-role": user_role
                },
                timeout=5.0
            )
            if resp.status_code == 200:
                ledger_receipt = resp.json()
            else:
                logger.error(f"Ledger service returned error status {resp.status_code}: {resp.text}")
        except Exception as e:
            logger.error(f"Failed to record transfer in Ledger Service: {e}")

    return {
        "status": "COMPLETED",
        "message": f"Successfully transferred ${transfer.amount:.2f} to {transfer.destination_account}",
        "source_account": account_id,
        "remaining_balance": new_src_balance,
        "ledger_receipt": ledger_receipt,
        "correlation_id": correlation_id,
        "authz_reason": reason
    }
