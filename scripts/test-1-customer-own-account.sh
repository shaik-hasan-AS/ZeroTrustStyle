#!/bin/bash
set -e
cd "$(dirname "$0")/.."

echo "=========================================================================="
echo "Scenario 1: Customer Accessing Own Account (Authorized)"
echo "Zero Trust Principle: Subject Identity & Resource Ownership (ABAC)"
echo "=========================================================================="

echo "Step 1: Obtain JWT Token for 'alice' (Customer, Owner of acc_1001)..."
TOKEN=$(curl -s --cacert certs/ca/ca.crt \
    --cert certs/client/client.crt --key certs/client/client.key \
    -X POST https://localhost:8000/auth/token \
    -H "Content-Type: application/json" \
    -d '{"username": "alice"}' | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

if [ -z "$TOKEN" ]; then
    echo "Failed to obtain token"
    exit 1
fi
echo "JWT Token obtained."

echo -e "\nStep 2: Request GET /accounts/acc_1001 with Alice's token and Client mTLS cert..."
curl -i --cacert certs/ca/ca.crt \
    --cert certs/client/client.crt --key certs/client/client.key \
    -H "Authorization: Bearer $TOKEN" \
    https://localhost:8000/accounts/acc_1001

echo -e "\n[SUCCESS] Alice authorized to view her own account."
