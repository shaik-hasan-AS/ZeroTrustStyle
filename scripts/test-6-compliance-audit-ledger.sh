#!/bin/bash
set -e
cd "$(dirname "$0")/.."

echo "=========================================================================="
echo "Scenario 6: Compliance Officer Inspecting Immutable Ledger Audit Trail"
echo "Zero Trust Principle: Cryptographic Non-Repudiation & Continuous Verification"
echo "=========================================================================="

echo "Step 1: Obtain JWT Token for 'auditor_carol' (Compliance Role)..."
TOKEN=$(curl -s --cacert certs/ca/ca.crt \
    --cert certs/client/client.crt --key certs/client/client.key \
    -X POST https://localhost:8000/auth/token \
    -H "Content-Type: application/json" \
    -d '{"username": "auditor_carol"}' | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

echo "Step 2: Query GET /ledger/audit-trail..."
echo "Expected Response: HTTP 200 OK + Cryptographic Hash Chain Verification"
curl -i --cacert certs/ca/ca.crt \
    --cert certs/client/client.crt --key certs/client/client.key \
    -H "Authorization: Bearer $TOKEN" \
    https://localhost:8000/ledger/audit-trail

echo -e "\n[SUCCESS] Compliance officer successfully inspected immutable ledger audit records."
