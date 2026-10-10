#!/bin/bash
set -e
cd "$(dirname "$0")/.."

echo "=========================================================================="
echo "Scenario 5: Bank Teller Assisted High-Value Transfer ($15,000.00)"
echo "Zero Trust Principle: Role-Based Privilege Escalation with Verified Claims"
echo "=========================================================================="

echo "Step 1: Obtain JWT Token for 'teller_tim' (Bank Teller role)..."
TOKEN=$(curl -s --cacert certs/ca/ca.crt \
    --cert certs/client/client.crt --key certs/client/client.key \
    -X POST https://localhost:8000/auth/token \
    -H "Content-Type: application/json" \
    -d '{"username": "teller_tim"}' | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

echo "Step 2: Bank Teller executes $15,000 transfer from Charlie (acc_1003) to Alice (acc_1001)..."
echo "Expected Response: HTTP 200 OK (Teller role allows up to $50,000)"
curl -i --cacert certs/ca/ca.crt \
    --cert certs/client/client.crt --key certs/client/client.key \
    -X POST https://localhost:8000/accounts/acc_1003/transfers \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"destination_account": "acc_1001", "amount": 15000.00, "note": "Teller branch authorized wire"}'

echo -e "\n[SUCCESS] Bank Teller authorized to process high-value transfer."
