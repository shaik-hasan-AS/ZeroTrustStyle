#!/bin/bash
set -e
cd "$(dirname "$0")/.."

echo "=========================================================================="
echo "Scenario 4: Transfer Exceeding Self-Service Limit ($15,000.00)"
echo "Zero Trust Principle: Policy-Enforced Least Privilege (Threshold Guardrails)"
echo "=========================================================================="

echo "Step 1: Obtain JWT Token for 'alice'..."
TOKEN=$(curl -s --cacert certs/ca/ca.crt \
    --cert certs/client/client.crt --key certs/client/client.key \
    -X POST https://localhost:8000/auth/token \
    -H "Content-Type: application/json" \
    -d '{"username": "alice"}' | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

echo "Step 2: Alice attempts to transfer $15,000 (exceeds $10,000 threshold)..."
echo "Expected Response: HTTP 403 Forbidden"
curl -i --cacert certs/ca/ca.crt \
    --cert certs/client/client.crt --key certs/client/client.key \
    -X POST https://localhost:8000/accounts/acc_1001/transfers \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"destination_account": "acc_1002", "amount": 15000.00, "note": "High value transfer"}'

echo -e "\n[SUCCESS] OPA policy successfully blocked high-risk unauthorized transaction."
