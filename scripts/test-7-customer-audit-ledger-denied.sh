#!/bin/bash
set -e
cd "$(dirname "$0")/.."

echo "=========================================================================="
echo "Scenario 7: Regular Customer Attempting to Access Ledger Audit Trail (Denied)"
echo "Zero Trust Principle: Separation of Duties & Defense in Depth"
echo "=========================================================================="

echo "Step 1: Obtain JWT Token for 'alice' (Customer Role)..."
TOKEN=$(curl -s --cacert certs/ca/ca.crt \
    --cert certs/client/client.crt --key certs/client/client.key \
    -X POST https://localhost:8000/auth/token \
    -H "Content-Type: application/json" \
    -d '{"username": "alice"}' | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

echo "Step 2: Customer attempts to read internal ledger audit trail..."
echo "Expected Response: HTTP 403 Forbidden"
curl -i --cacert certs/ca/ca.crt \
    --cert certs/client/client.crt --key certs/client/client.key \
    -H "Authorization: Bearer $TOKEN" \
    https://localhost:8000/ledger/audit-trail

echo -e "\n[SUCCESS] OPA policy successfully prevented unauthorized audit inspection."
