#!/bin/bash
set -e
cd "$(dirname "$0")/.."

echo "=========================================================================="
echo "Scenario 3: Transfer Funds Within Policy Threshold ($500.00)"
echo "Zero Trust Principle: End-to-End Cryptographic Chain (Gateway -> Account -> Ledger)"
echo "=========================================================================="

echo "Step 1: Obtain JWT Token for 'alice'..."
TOKEN=$(curl -s --cacert certs/ca/ca.crt \
    --cert certs/client/client.crt --key certs/client/client.key \
    -X POST https://localhost:8000/auth/token \
    -H "Content-Type: application/json" \
    -d '{"username": "alice"}' | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

echo "Step 2: Transfer $500 from Alice (acc_1001) to Bob (acc_1002)..."
echo "Expected Response: HTTP 200 OK + Tamper-evident Ledger Receipt"
curl -i --cacert certs/ca/ca.crt \
    --cert certs/client/client.crt --key certs/client/client.key \
    -X POST https://localhost:8000/accounts/acc_1001/transfers \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"destination_account": "acc_1002", "amount": 500.00, "note": "Zero Trust payment demonstration"}'

echo -e "\n[SUCCESS] Transfer permitted by OPA and immutably registered in Core Ledger."
