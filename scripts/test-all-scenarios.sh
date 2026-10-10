#!/bin/bash
set -e
cd "$(dirname "$0")/.."

echo "################################################################################"
echo "        ZERO TRUST ARCHITECTURE (FINTECH SUITE) - AUTOMATED VERIFICATION        "
echo "################################################################################"
echo ""

chmod +x scripts/*.sh

run_test() {
    SCRIPT=$1
    TITLE=$2
    echo "--------------------------------------------------------------------------------"
    echo " RUNNING: $TITLE"
    echo "--------------------------------------------------------------------------------"
    bash "$SCRIPT"
    echo ""
}

run_test "scripts/test-1-customer-own-account.sh" "Test 1: Customer Accessing Own Account (Allowed)"
run_test "scripts/test-2-customer-other-account-denied.sh" "Test 2: Customer Accessing Other Account (ABAC Denied)"
run_test "scripts/test-3-transfer-within-limit.sh" "Test 3: Transfer Within Limit (Allowed + Ledger Write)"
run_test "scripts/test-4-transfer-exceeding-limit-denied.sh" "Test 4: Transfer Exceeding Limit (Threshold Denied)"
run_test "scripts/test-5-teller-high-value-transfer.sh" "Test 5: Teller High-Value Transfer (Role Escalated Allowed)"
run_test "scripts/test-6-compliance-audit-ledger.sh" "Test 6: Compliance Audit of Immutable Ledger (Allowed)"
run_test "scripts/test-7-customer-audit-ledger-denied.sh" "Test 7: Customer Accessing Audit Trail (Role Denied)"
run_test "scripts/test-8-lateral-movement-bypass-denied.sh" "Test 8: Lateral Movement Bypass to Ledger (Workload Denied)"
run_test "scripts/test-9-untrusted-cert-handshake-failure.sh" "Test 9: Invalid mTLS Cert (TLS Handshake Terminated)"

echo "################################################################################"
echo " [COMPLETE] ALL 9 ZERO TRUST SCENARIOS VERIFIED SUCCESSFULLY!"
echo "################################################################################"
