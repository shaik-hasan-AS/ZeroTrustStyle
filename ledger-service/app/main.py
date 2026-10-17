from fastapi import FastAPI, Request, Response, HTTPException
from pydantic import BaseModel
import httpx
import logging
import sqlite3
import os
import uuid
import json
import hashlib
from datetime import datetime

# Structured JSON logging for SIEM / Compliance Auditing
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("ledger-service")

def log_security_event(event_type: str, correlation_id: str, caller_cn: str, user_id: str, user_role: str, action: str, resource: str, decision: str, reason: str):
    log_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "service": "ledger-service",
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

app = FastAPI(title="FinTech Core Ledger Service", version="2.0.0")

DB_PATH = "/data/ledger.db" if os.path.exists("/data") else "ledger.db"
OPA_URL = "http://opa:8181/v1/data/authz/decision"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ledger_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entry_id TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            source_account TEXT NOT NULL,
            destination_account TEXT NOT NULL,
            amount REAL NOT NULL,
            currency TEXT NOT NULL,
            workload_cn TEXT NOT NULL,
            executed_by_user TEXT NOT NULL,
            user_role TEXT NOT NULL,
            correlation_id TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

def get_latest_hash(conn) -> str:
    cursor = conn.cursor()
    cursor.execute("SELECT entry_hash FROM ledger_entries ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    if row:
        return row[0]
    return "0000000000000000000000000000000000000000000000000000000000000000"

def extract_workload_cn(request: Request) -> str:
    # 1. Check verified header from internal mesh
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

class LedgerEntryRequest(BaseModel):
    source_account: str
    destination_account: str
    amount: float
    currency: str = "USD"
    note: str = ""
    user_id: str
    user_role: str
    correlation_id: str

@app.post("/ledger/entries")
async def create_ledger_entry(entry: LedgerEntryRequest, request: Request):
    caller_cn = extract_workload_cn(request)
    correlation_id = entry.correlation_id or request.headers.get("x-correlation-id", str(uuid.uuid4()))

    # Evaluate OPA Policy: Check if caller workload is authorized to write to the ledger
    opa_input = {
        "input": {
            "service": "ledger-service",
            "caller": {"workload_cn": caller_cn},
            "user": {"id": entry.user_id, "role": entry.user_role},
            "action": {
                "method": "POST",
                "path": "/ledger/entries",
                "amount": entry.amount
            },
            "resource": {
                "type": "ledger",
                "source": entry.source_account,
                "destination": entry.destination_account
            }
        }
    }

    decision = await evaluate_opa_policy(opa_input)
    is_allowed = decision.get("allow", False)
    reason = decision.get("reason", "No reason provided")

    log_security_event(
        "LEDGER_WRITE_AUTHZ",
        correlation_id,
        caller_cn,
        entry.user_id,
        entry.user_role,
        "POST /ledger/entries",
        f"{entry.source_account}->{entry.destination_account}",
        "ALLOW" if is_allowed else "DENY",
        reason
    )

    if not is_allowed:
        raise HTTPException(status_code=403, detail={
            "error": "Forbidden",
            "message": "Zero Trust Lateral Movement Blocked: Unauthorized workload or role for Core Ledger write",
            "workload_identity": caller_cn,
            "reason": reason,
            "correlation_id": correlation_id
        })

    conn = sqlite3.connect(DB_PATH)
    prev_hash = get_latest_hash(conn)
    entry_id = str(uuid.uuid4())
    ts = datetime.utcnow().isoformat() + "Z"

    # Compute tamper-evident hash chain
    raw_record = f"{prev_hash}|{entry_id}|{ts}|{entry.source_account}|{entry.destination_account}|{entry.amount}|{entry.currency}|{caller_cn}"
    entry_hash = hashlib.sha256(raw_record.encode("utf-8")).hexdigest()

    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO ledger_entries (
            entry_id, timestamp, source_account, destination_account, amount,
            currency, workload_cn, executed_by_user, user_role, correlation_id,
            prev_hash, entry_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        entry_id, ts, entry.source_account, entry.destination_account, entry.amount,
        entry.currency, caller_cn, entry.user_id, entry.user_role, correlation_id,
        prev_hash, entry_hash
    ))
    conn.commit()
    conn.close()

    return {
        "status": "RECORDED_IN_IMMUTABLE_LEDGER",
        "entry_id": entry_id,
        "entry_hash": entry_hash,
        "prev_hash": prev_hash,
        "timestamp": ts,
        "correlation_id": correlation_id
    }

@app.get("/ledger/audit-trail")
async def get_audit_trail(request: Request):
    caller_cn = extract_workload_cn(request)
    user_id = request.headers.get("x-user-id", "anonymous")
    user_role = request.headers.get("x-user-role", "anonymous")
    correlation_id = request.headers.get("x-correlation-id", str(uuid.uuid4()))

    # Evaluate OPA Policy: Only compliance officers or admins may inspect the audit trail
    opa_input = {
        "input": {
            "service": "ledger-service",
            "caller": {"workload_cn": caller_cn},
            "user": {"id": user_id, "role": user_role},
            "action": {
                "method": "GET",
                "path": "/ledger/audit-trail"
            },
            "resource": {"type": "ledger_audit"}
        }
    }

    decision = await evaluate_opa_policy(opa_input)
    is_allowed = decision.get("allow", False)
    reason = decision.get("reason", "No reason provided")

    log_security_event(
        "AUDIT_TRAIL_READ_AUTHZ",
        correlation_id,
        caller_cn,
        user_id,
        user_role,
        "GET /ledger/audit-trail",
        "ledger:audit_trail",
        "ALLOW" if is_allowed else "DENY",
        reason
    )

    if not is_allowed:
        raise HTTPException(status_code=403, detail={
            "error": "Forbidden",
            "message": "Audit trail access restricted: requires compliance or admin role",
            "reason": reason,
            "correlation_id": correlation_id
        })

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ledger_entries ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()

    # Verify blockchain-like cryptographic hash chain integrity
    is_chain_intact = True
    expected_prev = "0000000000000000000000000000000000000000000000000000000000000000"
    entries = []
    tampered_indices = []

    for idx, r in enumerate(rows):
        d = dict(r)
        # Recompute SHA-256 hash of this record
        raw_record = f"{d['prev_hash']}|{d['entry_id']}|{d['timestamp']}|{d['source_account']}|{d['destination_account']}|{d['amount']}|{d['currency']}|{d['workload_cn']}"
        recalculated_hash = hashlib.sha256(raw_record.encode("utf-8")).hexdigest()

        entry_intact = True
        if d["prev_hash"] != expected_prev:
            is_chain_intact = False
            entry_intact = False
        if d["entry_hash"] != recalculated_hash:
            is_chain_intact = False
            entry_intact = False

        if not entry_intact:
            tampered_indices.append(idx + 1)

        d["block_index"] = idx + 1
        d["is_cryptographically_valid"] = entry_intact
        d["recalculated_hash"] = recalculated_hash
        expected_prev = d["entry_hash"]
        entries.append(d)

    return {
        "total_entries": len(entries),
        "cryptographic_integrity_verified": is_chain_intact,
        "tampered_blocks": tampered_indices,
        "audit_entries": entries,
        "correlation_id": correlation_id,
        "inspected_by": {"user_id": user_id, "role": user_role}
    }

@app.post("/ledger/simulate-tamper")
async def simulate_tamper(request: Request):
    caller_cn = extract_workload_cn(request)
    user_id = request.headers.get("x-user-id", "anonymous")
    user_role = request.headers.get("x-user-role", "anonymous")
    correlation_id = request.headers.get("x-correlation-id", str(uuid.uuid4()))

    opa_input = {
        "input": {
            "service": "ledger-service",
            "caller": {"workload_cn": caller_cn},
            "user": {"id": user_id, "role": user_role},
            "action": {"method": "POST", "path": "/ledger/simulate-tamper"},
            "resource": {"type": "ledger_admin"}
        }
    }

    decision = await evaluate_opa_policy(opa_input)
    is_allowed = decision.get("allow", False)
    reason = decision.get("reason", "No reason provided")

    log_security_event("LEDGER_TAMPER_AUTHZ", correlation_id, caller_cn, user_id, user_role, "POST /ledger/simulate-tamper", "ledger:all", "ALLOW" if is_allowed else "DENY", reason)

    if not is_allowed:
        raise HTTPException(status_code=403, detail={
            "error": "Forbidden",
            "message": "Only administrator role can trigger ledger tamper simulation",
            "reason": reason,
            "correlation_id": correlation_id
        })

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, amount, destination_account FROM ledger_entries ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=400, detail="Cannot tamper: Ledger has no entries yet. Perform a transfer first.")

    entry_row_id = row[0]
    tampered_amount = 999999.00
    cursor.execute("UPDATE ledger_entries SET amount = ? WHERE id = ?", (tampered_amount, entry_row_id))
    conn.commit()
    conn.close()

    return {
        "status": "TAMPER_SIMULATION_EXECUTED",
        "message": f"Row #{entry_row_id} amount was secretly altered to ${tampered_amount:,.2f} in database without updating hash chain.",
        "tampered_row_id": entry_row_id,
        "correlation_id": correlation_id
    }

@app.post("/ledger/reset")
async def reset_ledger(request: Request):
    caller_cn = extract_workload_cn(request)
    user_id = request.headers.get("x-user-id", "anonymous")
    user_role = request.headers.get("x-user-role", "anonymous")
    correlation_id = request.headers.get("x-correlation-id", str(uuid.uuid4()))

    opa_input = {
        "input": {
            "service": "ledger-service",
            "caller": {"workload_cn": caller_cn},
            "user": {"id": user_id, "role": user_role},
            "action": {"method": "POST", "path": "/ledger/reset"},
            "resource": {"type": "ledger_admin"}
        }
    }

    decision = await evaluate_opa_policy(opa_input)
    is_allowed = decision.get("allow", False)
    reason = decision.get("reason", "No reason provided")

    log_security_event("LEDGER_RESET_AUTHZ", correlation_id, caller_cn, user_id, user_role, "POST /ledger/reset", "ledger:all", "ALLOW" if is_allowed else "DENY", reason)

    if not is_allowed:
        raise HTTPException(status_code=403, detail={
            "error": "Forbidden",
            "message": "Only administrator role can reset the ledger",
            "reason": reason,
            "correlation_id": correlation_id
        })

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM ledger_entries")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='ledger_entries'")
    conn.commit()
    conn.close()

    return {
        "status": "LEDGER_RESET_SUCCESSFUL",
        "message": "Ledger entries cleared for fresh demo.",
        "correlation_id": correlation_id
    }
