package authz

import rego.v1

# Default Deny: Zero Trust core principle (Never trust, always verify)
default allow := false
default reason := "Access denied: Request does not satisfy any Zero Trust authorization rule"

# -------------------------------------------------------------
# WORKLOAD IDENTITY RULES (Service-to-Service mTLS caller check)
# -------------------------------------------------------------
valid_account_service_workload if {
    input.caller.workload_cn == "gateway"
}

valid_ledger_service_workload if {
    input.caller.workload_cn == "account-service"
}

# -------------------------------------------------------------
# ACCOUNT SERVICE POLICY RULES (ABAC)
# -------------------------------------------------------------

# Rule: Customer viewing their own account
allow if {
    input.service == "account-service"
    valid_account_service_workload
    input.action.method == "GET"
    input.action.path == concat("", ["/accounts/", input.resource.account_id])
    input.user.role == "customer"
    input.user.id == input.resource.owner_id
}

reason := "Customer authorized to access own account data" if {
    input.service == "account-service"
    valid_account_service_workload
    input.action.method == "GET"
    input.user.role == "customer"
    input.user.id == input.resource.owner_id
}

# Rule: Teller, Compliance, or Admin viewing any account
allow if {
    input.service == "account-service"
    valid_account_service_workload
    input.action.method == "GET"
    input.user.role in ["teller", "compliance", "admin"]
}

reason := "Staff member authorized to inspect account records" if {
    input.service == "account-service"
    valid_account_service_workload
    input.action.method == "GET"
    input.user.role in ["teller", "compliance", "admin"]
}

# Rule: Customer transferring funds under limit ($10,000) from their own account
allow if {
    input.service == "account-service"
    valid_account_service_workload
    input.action.method == "POST"
    input.user.role == "customer"
    input.user.id == input.resource.owner_id
    input.action.amount <= 10000
    input.action.amount > 0
}

reason := "Customer self-service transfer authorized (within $10,000 policy threshold)" if {
    input.service == "account-service"
    valid_account_service_workload
    input.action.method == "POST"
    input.user.role == "customer"
    input.user.id == input.resource.owner_id
    input.action.amount <= 10000
    input.action.amount > 0
}

# Rule: Bank Teller initiating transfer up to $50,000
allow if {
    input.service == "account-service"
    valid_account_service_workload
    input.action.method == "POST"
    input.user.role == "teller"
    input.action.amount <= 50000
    input.action.amount > 0
}

reason := "Bank Teller assisted transfer authorized (within $50,000 threshold)" if {
    input.service == "account-service"
    valid_account_service_workload
    input.action.method == "POST"
    input.user.role == "teller"
    input.action.amount <= 50000
    input.action.amount > 0
}

# Rule: System Admin executing transfer of any positive amount
allow if {
    input.service == "account-service"
    valid_account_service_workload
    input.action.method == "POST"
    input.user.role == "admin"
    input.action.amount > 0
}

reason := "Administrator override transfer authorized" if {
    input.service == "account-service"
    valid_account_service_workload
    input.action.method == "POST"
    input.user.role == "admin"
    input.action.amount > 0
}

# -------------------------------------------------------------
# LEDGER SERVICE POLICY RULES (Zero-Trust Core Financial Book)
# -------------------------------------------------------------

# Rule: Ledger journal entry creation (strictly requires account-service workload)
allow if {
    input.service == "ledger-service"
    valid_ledger_service_workload
    input.action.method == "POST"
    input.action.path == "/ledger/entries"
    input.user.role in ["customer", "teller", "admin"]
}

reason := "Ledger entry authorized from authenticated account-service" if {
    input.service == "ledger-service"
    valid_ledger_service_workload
    input.action.method == "POST"
    input.action.path == "/ledger/entries"
}

# Rule: Ledger audit trail query (restricted to compliance or admin)
allow if {
    input.service == "ledger-service"
    input.caller.workload_cn in ["account-service", "gateway"]
    input.action.method == "GET"
    input.action.path == "/ledger/audit-trail"
    input.user.role in ["compliance", "admin"]
}

reason := "Compliance/Admin officer authorized to inspect immutable ledger audit trail" if {
    input.service == "ledger-service"
    input.caller.workload_cn in ["account-service", "gateway"]
    input.action.method == "GET"
    input.action.path == "/ledger/audit-trail"
    input.user.role in ["compliance", "admin"]
}

# Rule: Ledger admin maintenance operations (tamper demo and reset)
allow if {
    input.service == "ledger-service"
    input.caller.workload_cn in ["account-service", "gateway"]
    input.action.method == "POST"
    input.action.path in ["/ledger/simulate-tamper", "/ledger/reset"]
    input.user.role == "admin"
}

reason := "Administrator authorized for ledger state maintenance" if {
    input.service == "ledger-service"
    input.caller.workload_cn in ["account-service", "gateway"]
    input.action.method == "POST"
    input.action.path in ["/ledger/simulate-tamper", "/ledger/reset"]
    input.user.role == "admin"
}

# Rule: Account service admin reset
allow if {
    input.service == "account-service"
    valid_account_service_workload
    input.action.method == "POST"
    input.action.path == "/accounts/reset"
    input.user.role == "admin"
}

reason := "Administrator authorized for account balance reset" if {
    input.service == "account-service"
    valid_account_service_workload
    input.action.method == "POST"
    input.action.path == "/accounts/reset"
    input.user.role == "admin"
}

# -------------------------------------------------------------
# SPECIFIC ZERO TRUST DENIAL REASONS
# -------------------------------------------------------------

reason := "Zero Trust ABAC Denied: Customer cannot view or operate on accounts owned by other users (Horizontal privilege escalation blocked)" if {
    input.service == "account-service"
    input.user.role == "customer"
    input.user.id != input.resource.owner_id
}

reason := "Zero Trust Guardrail Denied: Self-service customer transfer exceeds policy limit of $10,000 (Requires branch teller or officer approval)" if {
    input.service == "account-service"
    input.user.role == "customer"
    input.user.id == input.resource.owner_id
    input.action.amount > 10000
}

reason := "Zero Trust Workload Isolation Denied: Caller workload is not authorized to write directly to Core Ledger" if {
    input.service == "ledger-service"
    input.action.method == "POST"
    input.action.path == "/ledger/entries"
    not valid_ledger_service_workload
}

reason := "Zero Trust Separation of Duties Denied: Only compliance or admin roles are permitted to inspect the financial audit trail" if {
    input.service == "ledger-service"
    input.action.path == "/ledger/audit-trail"
    not (input.user.role in ["compliance", "admin"])
}

# Structured policy decision object
decision := {
    "allow": allow,
    "reason": reason
}
