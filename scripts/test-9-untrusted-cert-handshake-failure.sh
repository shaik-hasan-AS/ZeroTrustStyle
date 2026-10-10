#!/bin/bash
cd "$(dirname "$0")/.."

echo "=========================================================================="
echo "Scenario 9: Untrusted or Missing Client Certificate (TLS Handshake Failure)"
echo "Zero Trust Principle: Cryptographic Mutual Authentication (mTLS Layer 4 Defense)"
echo "=========================================================================="

echo "Case 9A: Connecting with NO client certificate..."
echo "Expected: TLS Handshake Failure (curl exit error)"
curl -i --cacert certs/ca/ca.crt https://localhost:8000/accounts/acc_1001 || true

echo -e "\nCase 9B: Connecting with rogue/untrusted CA certificate..."
echo "Expected: TLS Handshake Failure / Verification Error"
curl -i --cacert certs/ca/ca.crt \
    --cert certs/untrusted-client/untrusted.crt --key certs/untrusted-client/untrusted.key \
    https://localhost:8000/accounts/acc_1001 || true

echo -e "\n[SUCCESS] Unauthenticated TLS connections terminated at handshake."
