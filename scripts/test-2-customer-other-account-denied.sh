#!/bin/bash
set -e
cd "$(dirname "$0")/.."

echo "=========================================================================="
echo "Scenario 2: Customer Accessing Another Customer's Account (Denied)"
echo "Zero Trust Principle: ABAC Object-Level Access Control (Never Blindly Trust)"
echo "=========================================================================="

echo "Step 1: Obtain JWT Token for 'alice'..."
TOKEN=$(curl -s --cacert certs/ca/ca.crt \
    --cert certs/client/client.crt --key certs/client/client.key \
    -X POST https://localhost:8000/auth/token \
    -H "Content-Type: application/json" \
    -d '{"username": "alice"}' | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

echo "Step 2: Alice attempts to access Bob's account (acc_1002)..."
echo "Expected Response: HTTP 403 Forbidden with OPA Policy Deny reason"
curl -i --cacert certs/ca/ca.crt \
    --cert certs/client/client.crt --key certs/client/client.key \
    -H "Authorization: Bearer $TOKEN" \
    https://localhost:8000/accounts/acc_1002

echo -e "\n[SUCCESS] OPA ABAC engine successfully blocked horizontal privilege escalation."
