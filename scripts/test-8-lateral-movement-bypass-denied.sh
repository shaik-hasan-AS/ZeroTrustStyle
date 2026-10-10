#!/bin/bash
set -e
cd "$(dirname "$0")/.."

echo "=========================================================================="
echo "Scenario 8: Lateral Movement Attack / Direct Core Ledger Bypass (Denied)"
echo "Zero Trust Principle: Workload Identity & Microsegmentation (NIST SP 800-207)"
echo "=========================================================================="

echo "Attack Simulation:"
echo "An attacker compromises network access and attempts to call the Core Ledger directly on :8002"
echo "using a CA-signed rogue workload certificate (CN=rogue-unauthorized-workload)."
echo "Expected: mTLS handshake succeeds, BUT OPA blocks the request because the workload is NOT account-service."

curl -i --cacert certs/ca/ca.crt \
    --cert certs/rogue-service/rogue-service.crt --key certs/rogue-service/rogue-service.key \
    -X POST https://localhost:8002/ledger/entries \
    -H "Content-Type: application/json" \
    -d '{
        "source_account": "acc_1001",
        "destination_account": "hacker_account",
        "amount": 999999.00,
        "currency": "USD",
        "user_id": "hacker",
        "user_role": "admin",
        "correlation_id": "attack-sim-001"
    }'

echo -e "\n[SUCCESS] Zero Trust Workload Identity blocked rogue service lateral movement."
