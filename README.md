# FinTech Zero-Trust Microservice Architecture

A production-grade, enterprise-ready reference implementation of a **Zero-Trust Microservice Architecture (NIST SP 800-207)** for financial services.

Unlike basic demos that only implement perimeter TLS, this project enforces **dual-layer identity verification** (Machine-to-Machine Workload Identity + Subject-to-Machine JWT Claims), **fine-grained ABAC (Attribute-Based Access Control)** via Open Policy Agent (OPA), **immutable double-entry financial ledger journal with cryptographic hash chaining**, and **lateral movement attack prevention**.

---

## 🏛️ Architecture Overview

```
                                  +-------------------------------------------------------------+
                                  |                     CLIENT REQUEST                          |
                                  |     (mTLS Client Certificate + Signed Bearer JWT)           |
                                  +------------------------------+------------------------------+
                                                                 |
                                                                 v
                                                    +-------------------------+
                                                    |    API GATEWAY (PEP)    |
                                                    |  - Terminates Client    |
                                                    |    mTLS (Layer 4)       |
                                                    |  - Verifies User JWT    |
                                                    |    (Subject Claims)     |
                                                    |  - Injects Correlation  |
                                                    |    ID & Tracing Context |
                                                    +------------+------------+
                                                                 |
                                                                 | Internal mTLS (CN=gateway)
                                                                 | Identity Context Propagation
                                                                 v
                                                    +-------------------------+
                                                    |  ACCOUNT SERVICE (PEP)  |
                                                    |  - Validates Gateway    |
                                                    |    Workload Identity    |
                                                    |  - Evaluates Ownership  |
                                                    |    & Limits in OPA      |
                                                    |  - Manages Account DB   |
                                                    +------------+------------+
                                                           |     |
                 Queries Centralized PDP for ABAC Decision |     | Internal mTLS (CN=account-service)
                                                           v     v
+--------------------------+                        +-------------+  +--------------------------+
|  OPEN POLICY AGENT (PDP) |<-----------------------|  OPA (PDP)  |  |   CORE LEDGER SERVICE    |
| - Service Trust Matrix   |  Workload + Role +     |   Policy    |  |  (Database + Local PEP)  |
| - ABAC Ownership Checks  |  Amount Context Check  +-------------+  | - Strict Workload mTLS   |
| - Transfer Limits        |                                         |   (Rejects Direct Bypass)|
| - Role Permissions       |                                         | - Double-Entry Journal   |
+--------------------------+                                         | - Cryptographic Hash     |
                                                                     |   Chain Audit Trail      |
                                                                     +--------------------------+
                                                                                  |
                                                                                  v
                                                                     +--------------------------+
                                                                     | SIEM Security JSON Logs  |
                                                                     +--------------------------+
```

---

## 🛡️ NIST SP 800-207 Zero-Trust Tenets Implemented

| Zero Trust Tenet | How It Is Implemented in This System |
|---|---|
| **1. Never Trust, Always Verify** | Every inter-service hop is mutually authenticated (mTLS) and independently evaluated by OPA; private Docker network access is never assumed safe. |
| **2. Cryptographic Workload Identity** | Services authenticate peers by inspecting X.509 client certificate Subject Common Name (CN). Workloads without approved CNs are blocked at the PDP level. |
| **3. Dual-Layer Identity Propagation** | Workload identity (mTLS) secures the transport pipe, while Subject Identity (signed JWT claims: `sub`, `role`, `department`) is verified and propagated for authorization. |
| **4. Attribute-Based Access Control (ABAC)** | OPA evaluates multidimensional policies: caller identity, user role, resource ownership (`user_id == account.owner_id`), and action attributes (transfer amount &le; $10,000 threshold). |
| **5. Defense Against Lateral Movement** | The Core Ledger Service rejects direct invocations from API Gateway or rogue services, even if they possess a valid CA-signed certificate. Only `account-service` is authorized to post ledger entries. |
| **6. Non-Repudiation & Audit Integrity** | Financial transactions are recorded in a tamper-evident blockchain-like cryptographic hash chain (`SHA-256(prev_hash + entry + caller)`). |
| **7. Continuous Security Telemetry** | Every authorization evaluation (ALLOW and DENY) emits structured JSON events ready for SIEM ingestion. |

---

## 🚀 Quick Start

### 1. Generate PKI Certificates
Generates Root CA and certificates for `gateway`, `account-service`, `ledger-service`, `client`, and test rogue workloads:
```bash
./scripts/generate-certs.sh
```

### 2. Start the Zero-Trust Cluster
```bash
docker-compose up --build -d
```

### 3. Open the Interactive Banking Web App & Zero-Trust Cockpit
Open your browser at:
👉 **`http://localhost:3000`**

The Web Application features:
* **Banking Operations Dashboard**: Switch between Alice (Customer), Bob (Customer), Tim (Teller), Carol (Auditor), and Dave (Admin). Perform transfers, check balances, and view receipts.
* **Cryptographic Ledger Visualizer**: Inspect the blockchain-style SHA-256 hash-chain journal. Run live cryptographic verification and simulate database tamper attacks.
* **Live Zero-Trust Inspector**: Inspect Layer 4 mTLS workload identity, Layer 7 JWT claims, and OPA policy decisions in real time with structured SIEM event logs.
* **1-Click Attack & Verification Suite**: Run all 9 Zero-Trust security scenarios with live interactive terminal playback.
* **Wireshark Live Demo Studio**: One-click display filter copy chips, traffic burst generator, and step-by-step presentation script.

---

## 🦈 Live Wireshark Packet Inspection Guide

To demonstrate cryptographic mutual TLS (mTLS) enforcement to an audience:

1. **Launch Wireshark capturing on the Docker/host interface**:
   ```bash
   sudo wireshark -i any -k -f "tcp port 8000 or tcp port 8001 or tcp port 8002"
   ```
2. **Apply Wireshark Display Filters**:
   * `tls.handshake.type == 13` : **Certificate Request** (Proves the server requires client authentication).
   * `tls.handshake.type == 11` : **Certificate Exchange** (Inspect client CN `client-fintech-portal` and server CN `gateway`).
   * `tls.handshake.type == 15` : **Certificate Verify** (Proves client possesses the matching private key).
3. **Trigger Live Traffic**:
   Navigate to the **Wireshark Live Demo Studio** tab in the web app (`http://localhost:3000`) and click **"Generate Live Traffic Burst"**.

---

## 🧪 Comprehensive Test Scenarios (CLI)

Run the complete test suite verifying all 9 security scenarios:
```bash
./scripts/test-all-scenarios.sh
```

### Individual Test Scenarios:

#### Scenario 1: Customer Accessing Own Account (Authorized)
A valid client certificate with Alice's JWT accessing `acc_1001` (Alice's checking account).
```bash
./scripts/test-1-customer-own-account.sh
```
* **Result**: `HTTP 200 OK` (ABAC policy permits access).

#### Scenario 2: Horizontal Privilege Escalation Attempt (Denied)
Alice attempts to access Bob's account (`acc_1002`).
```bash
./scripts/test-2-customer-other-account-denied.sh
```
* **Result**: `HTTP 403 Forbidden` (OPA ABAC denies: `user.id != resource.owner_id`).

#### Scenario 3: Fund Transfer Within Policy Threshold (Authorized)
Alice initiates a $500 transfer from her account to Bob.
```bash
./scripts/test-3-transfer-within-limit.sh
```
* **Result**: `HTTP 200 OK`. Funds deducted, credited, and committed to the immutable cryptographic ledger.

#### Scenario 4: Transfer Exceeding Self-Service Threshold (Denied)
Alice attempts to transfer $15,000 (exceeds $10,000 self-service limit).
```bash
./scripts/test-4-transfer-exceeding-limit-denied.sh
```
* **Result**: `HTTP 403 Forbidden` (OPA rule: Self-service customer transfers capped at $10,000).

#### Scenario 5: Bank Teller High-Value Transfer (Role Escalation)
Bank Teller `teller_tim` initiates the $15,000 transfer on behalf of the customer.
```bash
./scripts/test-5-teller-high-value-transfer.sh
```
* **Result**: `HTTP 200 OK` (OPA rule: Teller role permitted up to $50,000).

#### Scenario 6: Compliance Audit of Immutable Ledger (Authorized)
Compliance Officer `auditor_carol` queries the core financial ledger and verifies hash chain integrity.
```bash
./scripts/test-6-compliance-audit-ledger.sh
```
* **Result**: `HTTP 200 OK` + complete cryptographic hash chain with `cryptographic_integrity_verified: true`.

#### Scenario 7: Customer Attempting Audit Inspection (Denied)
Customer Alice attempts to inspect the financial ledger audit trail.
```bash
./scripts/test-7-customer-audit-ledger-denied.sh
```
* **Result**: `HTTP 403 Forbidden` (OPA policy restricts audit trail to compliance and admin roles).

#### Scenario 8: Lateral Movement Attack / Direct Ledger Bypass (Denied)
A rogue actor bypasses the Gateway and calls `ledger-service:8002` directly using a CA-signed certificate (`CN=rogue-unauthorized-workload`).
```bash
./scripts/test-8-lateral-movement-bypass-denied.sh
```
* **Result**: `HTTP 403 Forbidden` (Zero Trust Workload Isolation: Only `account-service` is permitted to write to the ledger).

#### Scenario 9: Missing or Rogue mTLS Certificate (Layer 4 Rejection)
A client attempts to connect without a valid mTLS certificate.
```bash
./scripts/test-9-untrusted-cert-handshake-failure.sh
```
* **Result**: `TLS Handshake Failure` (Connection terminated before any application data is exchanged).

---

## 🔍 Network Packet Inspection (Wireshark)
To inspect the encrypted mTLS traffic between microservices on the Docker bridge network:
1. Open Wireshark and capture on the Docker bridge interface (e.g. `br-<network-id>`).
2. Filter: `tcp.port in {8000, 8001, 8002}`.
3. Run `./scripts/test-all-scenarios.sh`.
4. Observe that all inter-service communications, headers, and payloads remain strictly encrypted via TLS 1.3 mutual authentication.
# ZeroTrustStyle
