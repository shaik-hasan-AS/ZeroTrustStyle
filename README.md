# FinTech Zero-Trust Microservice Architecture (NIST SP 800-207)
### Computer Networks (CN) & Network Security Capstone Reference Implementation

[![TLS 1.3](https://img.shields.io/badge/Transport-TLS%201.3%20%2F%20mTLS-blue.svg)](https://en.wikipedia.org/wiki/Transport_Layer_Security)
[![NIST SP 800-207](https://img.shields.io/badge/Standard-NIST%20SP%20800--207-green.svg)](https://csrc.nist.gov/publications/detail/sp/800-207/final)
[![Policy Engine](https://img.shields.io/badge/PDP-Open%20Policy%20Agent%20(OPA)-blueviolet.svg)](https://www.openpolicyagent.org/)
[![FastAPI](https://img.shields.io/badge/Framework-FastAPI%20%2F%20Python%203.10-009688.svg)](https://fastapi.tiangolo.com/)
[![Docker Compose](https://img.shields.io/badge/Orchestration-Docker%20Compose-2496ED.svg)](https://docs.docker.com/compose/)
[![Wireshark Tested](https://img.shields.io/badge/Inspection-Wireshark%20Verified-1679A7.svg)](https://www.wireshark.org/)

---

## 📌 Executive Summary & CN Project Motivation

Traditional computer networks rely on **perimeter-based security** (the classic *"castle-and-moat"* model). In that architecture, firewalls defend the external boundary, but once an adversary, rogue employee, or compromised container gains access to the internal network, all internal traffic is implicitly trusted. This allows uninhibited **lateral movement**, eavesdropping, and privilege escalation.

This project implements an enterprise-grade, production-aligned **Zero-Trust Architecture** based on the **NIST Special Publication 800-207** framework for a mission-critical Financial Services (FinTech) environment.

Under the Zero-Trust principle of **"Never Trust, Always Verify"**, every single network interaction—whether from an external client or between internal microservices—is subjected to:
1. **Layer 4 Mutual Authentication (mTLS)**: Every hop validates X.509 digital certificates and enforces cryptographic Workload Identities (`CN`).
2. **Layer 7 Subject Identity & ABAC Policy Enforcement**: Every request must carry a cryptographically signed Bearer JWT (`sub`, `role`), which is evaluated against fine-grained Attribute-Based Access Control policies in a centralized Policy Decision Point (**Open Policy Agent - OPA**).
3. **Immutable Cryptographic Hash Chaining**: Every financial ledger entry is chained using SHA-256 (`H_n = SHA256(H_{n-1} || entry || caller_cn)`), guaranteeing non-repudiation and immediate tamper detection.
4. **Packet-Level Wireshark Verification**: Explicit support for live packet sniffing demonstrating TLS 1.3 handshake exchange (Certificate Request Type 13, Certificate Type 11, Certificate Verify Type 15) and ciphertext protection across the Docker network bridge.

---

## 🏛️ System Architecture & Network Topology

```
+---------------------------------------------------------------------------------------------------+
|                                      EXTERNAL CLIENT LAYER                                        |
|  - Web Browser Cockpit (http://localhost:3000)                                                    |
|  - CLI / Test Scripts presenting mTLS Client Certificate (CN=client-fintech-portal) + JWT Bearer   |
+-------------------------------------------------+-------------------------------------------------+
                                                  |
                                                  | Layer 4: mTLS (Client Auth Required)
                                                  | Layer 7: HTTPS + Authorization: Bearer <JWT>
                                                  v
+---------------------------------------------------------------------------------------------------+
|                              API GATEWAY (Policy Enforcement Point - PEP)                         |
|  Port: 8000 (TLS) | Identity: CN=gateway                                                          |
|  - Terminates Client mTLS Handshake (Rejects unauthorized/untrusted certificates)                 |
|  - Authenticates & Issues Subject Tokens (/auth/token)                                            |
|  - Injects Distributed Tracing & Telemetry Headers:                                               |
|      * x-correlation-id, x-workload-cn, x-originating-client-cn, x-user-id, x-user-role          |
|  - Secure Reverse Proxy with downstream mTLS context                                              |
+-------------------------------------------------+-------------------------------------------------+
                                                  |
                                                  | Internal Docker Bridge Network (zero-trust-net)
                                                  | Inter-Service mTLS (Caller CN=gateway)
                                                  v
+---------------------------------------------------------------------------------------------------+
|                             ACCOUNT SERVICE (Microsegment PEP)                                    |
|  Port: 8001 (TLS) | Identity: CN=account-service                                                  |
|  - Validates Gateway Workload Identity from incoming TLS socket                                   |
|  - Dispatches Policy Query to OPA PDP over HTTP (Input: caller CN, user ID, role, action, amount)  |
|  - Enforces ABAC Resource Ownership: user.id == account.owner_id                                  |
|  - Enforces Transfer Limits: Self-Service ($10k) vs. Teller ($50k) vs. Admin                      |
|  - Manages Account State (SQLite: accounts.db)                                                    |
+------------------------+--------------------------------------------------+-----------------------+
                         |                                                  |
       Queries PDP for   |                                                  | Secure Internal mTLS
       Authorization     |                                                  | Caller CN=account-service
                         v                                                  v
+-----------------------------------+             +-------------------------------------------------+
|   OPEN POLICY AGENT (PDP)         |             |        CORE LEDGER SERVICE (Local PEP)          |
|   Port: 8181 (HTTP)               |             |  Port: 8002 (TLS) | Identity: CN=ledger-service   |
|   Policy: authz.rego              |             |  - STRICT ANTI-LATERAL MOVEMENT CHECK:          |
|   - Workload Identity Trust Matrix|             |    Direct bypass from gateway or rogue nodes     |
|   - ABAC Rules & Role Permissions |             |    is REJECTED even with valid CA-signed cert!    |
|   - Transaction Guardrails        |             |  - Double-Entry Financial Journal               |
|   - Default DENY Evaluation       |             |  - Cryptographic Hash Chain (SHA-256)           |
+-----------------------------------+             |  - Tamper Detection Engine & SIEM Audit Logs    |
                                                  +-------------------------------------------------+
```

---

## 🌐 Mapping to OSI 7-Layer & TCP/IP Protocol Stack

This project maps directly to key Computer Networks concepts across the network stack:

| OSI Layer | Protocol / Technology | Zero-Trust Role & Implementation in this Project |
|---|---|---|
| **Layer 7: Application** | HTTP/1.1, REST, JSON, JWT (RFC 7519), OPA Rego | User subject identity (`sub`, `role`), distributed correlation IDs (`x-correlation-id`), fine-grained ABAC policy evaluations at PEPs, immutable double-entry ledger. |
| **Layer 6: Presentation** | TLS 1.3, X.509 v3 (RFC 5280), RSA 2048, SHA-256, AES-256-GCM | Cryptographic payload encryption, data serialization (JSON), digital signatures for certificates and JWT tokens, hash-chain calculation. |
| **Layer 5: Session** | TLS Session Management, Mutual TLS Handshake | Establishing mutually authenticated sessions between peers. Both client and server must exchange certificates and prove possession of private keys before session keys are derived. |
| **Layer 4: Transport** | TCP, Uvicorn/Python `ssl.SSLContext` (`ssl.CERT_REQUIRED`) | Port multiplexing (`8000`, `8001`, `8002`, `8181`, `3000`), TCP three-way handshake, immediate connection termination on failed TLS certificate verification. |
| **Layer 3: Network** | IPv4, Docker Bridge Network (`zero-trust-net`) | Container-to-container packet routing and IP isolation. Network perimeter defenses are treated as untrusted; no unauthenticated packet is accepted. |

---

## 🛡️ NIST SP 800-207 Zero-Trust Tenets Implemented

| Zero-Trust Tenet | Practical Implementation in this Architecture | Source File Reference |
|---|---|---|
| **1. All data sources and computing services are considered resources** | Every microservice (`gateway`, `account-service`, `ledger-service`) exposes protected endpoints behind dedicated PEPs. No service is "implicitly internal." | [`docker-compose.yml`](file:///home/hasan/Desktop/codes/ZeroTrustStyle/docker-compose.yml) |
| **2. All communication is secured regardless of network location** | Mutual TLS 1.3 (`ssl.CERT_REQUIRED`) is strictly enforced between all nodes on the Docker network bridge. Plaintext HTTP traffic is discarded. | [`gateway/Dockerfile`](file:///home/hasan/Desktop/codes/ZeroTrustStyle/gateway/Dockerfile), [`account-service/Dockerfile`](file:///home/hasan/Desktop/codes/ZeroTrustStyle/account-service/Dockerfile), [`ledger-service/Dockerfile`](file:///home/hasan/Desktop/codes/ZeroTrustStyle/ledger-service/Dockerfile) |
| **3. Access to individual resources is granted on a per-session basis** | Access tokens are short-lived JWTs (2 hours) requiring fresh authentication. Every transaction evaluates policy dynamically. | [`gateway/app/main.py`](file:///home/hasan/Desktop/codes/ZeroTrustStyle/gateway/app/main.py) |
| **4. Access is determined by dynamic policy (ABAC)** | Access is not purely role-based (RBAC); it considers caller workload CN, user ID, role, resource owner, and transaction amount via Open Policy Agent. | [`opa/policies/authz.rego`](file:///home/hasan/Desktop/codes/ZeroTrustStyle/opa/policies/authz.rego) |
| **5. Enterprise monitors and measures the integrity of assets** | Every service emits structured JSON security events to stdout for SIEM log ingestion (tracking timestamp, correlation ID, CN, decision, and reason). | [`account-service/app/main.py`](file:///home/hasan/Desktop/codes/ZeroTrustStyle/account-service/app/main.py), [`ledger-service/app/main.py`](file:///home/hasan/Desktop/codes/ZeroTrustStyle/ledger-service/app/main.py) |
| **6. Authentication and authorization are dynamic and strictly enforced** | Dual-layer verification: Layer 4 authenticates the *machine workload* (mTLS), while Layer 7 authenticates the *human subject* (JWT). | [`account-service/app/main.py`](file:///home/hasan/Desktop/codes/ZeroTrustStyle/account-service/app/main.py) |
| **7. Defense against lateral movement** | The Core Ledger Service blocks direct writes from rogue nodes or even the API Gateway, accepting write calls exclusively from `account-service`. | [`ledger-service/app/main.py`](file:///home/hasan/Desktop/codes/ZeroTrustStyle/ledger-service/app/main.py), [`opa/policies/authz.rego`](file:///home/hasan/Desktop/codes/ZeroTrustStyle/opa/policies/authz.rego) |

---

## 🔑 Public Key Infrastructure (PKI) & Certificate Hierarchy

The cluster operates a dedicated X.509 PKI hierarchy generated via OpenSSL (`./scripts/generate-certs.sh`):

```
                        +------------------------------------+
                        |     ZeroTrust Banking Root CA      |
                        |      (certs/ca/ca.crt, ca.key)     |
                        +-----------------+------------------+
                                          |
        +-------------------+-------------+-------------+--------------------+---------------------+
        |                   |                           |                    |                     |
        v                   v                           v                    v                     v
+---------------+   +-------------------+   +--------------------+   +---------------+   +----------------------+
|    Gateway    |   |  Account Service  |   |   Ledger Service   |   | Client Portal |   | Rogue Workload (Test)|
|  CN: gateway  |   |CN: account-service|   | CN: ledger-service |   |CN: client-... |   | CN: rogue-unauth...  |
+---------------+   +-------------------+   +--------------------+   +---------------+   +----------------------+
```

| Entity / Service | Common Name (`CN`) | Subject Alternative Names (SAN) | Purpose | Zero-Trust Enforcement |
|---|---|---|---|---|
| **Root CA** | `ZeroTrust Banking Root CA` | N/A | Signs all valid cluster workloads | Installed as trusted CA in all services |
| **API Gateway** | `gateway` | `DNS:gateway, DNS:localhost` | Ingress entry point | Server TLS + Client mTLS to downstream |
| **Account Service** | `account-service` | `DNS:account-service, DNS:localhost` | Account management PEP | Verifies caller CN is `gateway` |
| **Ledger Service** | `ledger-service` | `DNS:ledger-service, DNS:localhost` | Core financial journal | Verifies caller CN is `account-service` |
| **Client Workload** | `client-fintech-portal` | `DNS:client-fintech-portal, DNS:localhost` | Legitimate web client & scripts | Permitted to communicate with Gateway |
| **Rogue Service** | `rogue-unauthorized-workload` | `DNS:rogue-service, DNS:localhost` | CA-signed attacker node (lateral test) | L4 TLS passes, but blocked at L7 by OPA |
| **Untrusted Client** | `hacker` | `DNS:localhost` | Self-signed / untrusted CA cert | Terminated at Layer 4 TLS Handshake |

---

## ⛓️ Immutable Double-Entry Ledger with SHA-256 Hash Chaining

To ensure financial integrity and non-repudiation, the **Core Ledger Service** implements a blockchain-inspired cryptographic hash chain:

$$H_0 = \text{"0000000000000000000000000000000000000000000000000000000000000000"}$$

$$H_n = \text{SHA-256}(H_{n-1} \parallel \text{entry\_id} \parallel \text{timestamp} \parallel \text{source} \parallel \text{destination} \parallel \text{amount} \parallel \text{currency} \parallel \text{workload\_cn})$$

### Tamper-Evidence in Action
1. If a rogue database administrator alters a past transaction amount directly in the database (`UPDATE ledger_entries SET amount = 999999.00 WHERE id = 1`):
2. The recalculation of $H_1$ differs from the recorded `entry_hash`.
3. Consequently, all subsequent block hashes $H_2, H_3, \dots, H_n$ become invalid.
4. The `/ledger/audit-trail` verification endpoint flags `cryptographic_integrity_verified: false` and pinpoints the exact tampered row.

---

## 🧪 The 9 Security Verification Scenarios

The suite includes 9 automated verification scripts verifying both transport-layer and application-layer defenses:

```bash
./scripts/test-all-scenarios.sh
```

| # | Scenario Name | Attack / Test Description | Layer | Security Principle Verified | Expected Verdict |
|:---:|---|---|:---:|---|:---:|
| **1** | **Customer Access Own Account** | Alice queries `acc_1001` with valid mTLS cert + Alice's JWT | L4 + L7 | ABAC Ownership: `user.id == resource.owner_id` | `HTTP 200 OK` (ALLOW) |
| **2** | **BOLA / IDOR Attack** | Alice attempts to read Bob's account (`acc_1002`) | L7 | Horizontal Privilege Escalation prevention | `HTTP 403 Forbidden` (DENY) |
| **3** | **Transfer Within Limit** | Alice transfers $500.00 to Bob | L4 + L7 | Dynamic policy check before state mutation + Ledger append | `HTTP 200 OK` (ALLOW) |
| **4** | **Transfer Exceeding Limit** | Alice attempts to self-service transfer $25,000 | L7 | Dynamic transaction limit ($10,000 threshold for customers) | `HTTP 403 Forbidden` (DENY) |
| **5** | **Teller High-Value Wire** | Tim Teller executes $25,000 assisted transfer | L7 | Role-based privilege escalation ($50,000 teller threshold) | `HTTP 200 OK` (ALLOW) |
| **6** | **Compliance Audit Query** | Carol Auditor queries `/ledger/audit-trail` | L7 | Segregation of Duties: Compliance role permitted to read audit logs | `HTTP 200 OK` (ALLOW) |
| **7** | **Customer Unauthorized Audit** | Alice attempts to inspect `/ledger/audit-trail` | L7 | Segregation of Duties: Customer role forbidden from audit logs | `HTTP 403 Forbidden` (DENY) |
| **8** | **Lateral Movement Bypass** | Rogue node calls Ledger directly with valid CA cert | L4 + L7 | Workload Isolation: Only `account-service` may write to Ledger | `HTTP 403 Forbidden` (DENY) |
| **9** | **Untrusted / Missing Cert** | Client connects with untrusted CA or no cert | L4 | Mutual TLS Transport Defense: Rejected at socket handshake | `TLS Handshake Failure` |

---

## 🦈 Live Wireshark Packet Sniffing & CN Lab Guide

To inspect encrypted packet frames and verify mTLS handshakes in Wireshark:

### 1. Launch Wireshark on Docker Interface
```bash
# Capture across all interfaces on microservice ports:
sudo wireshark -i any -k -f "tcp port 8000 or tcp port 8001 or tcp port 8002"

# Or capture specifically on the Docker bridge interface:
sudo wireshark -i docker0 -k
```

### 2. Generate Multi-Hop Traffic
In the Web Cockpit (`http://localhost:3000`), open the **"Wireshark Demo"** tab and click **"Send Test Traffic Burst"**, or run:
```bash
./scripts/test-all-scenarios.sh
```

### 3. Key Wireshark Display Filters

| Filter Expression | TLS Handshake Message | Significance for CN Labs |
|---|---|---|
| `tls.handshake.type == 13` | **Certificate Request** | **Crucial Proof of mTLS:** Demonstrates the server explicitly requests the client's certificate. In standard HTTPS, servers never request client certs. |
| `tls.handshake.type == 11` | **Certificate Exchange** | Displays the X.509 certificate exchange. Inspect the Subject Common Names (`client-fintech-portal`, `gateway`, `account-service`). |
| `tls.handshake.type == 15` | **Certificate Verify** | Proves the client has possession of the matching private key by verifying the digital signature over preceding handshake messages. |
| `tls.record.content_type == 23` | **Application Data** | Proves that all account balances, transfer amounts, and JWT tokens remain strictly encrypted under AES-256-GCM. |
| `tcp.port in {8000, 8001, 8002}` | **All Mesh Ports** | Displays the full TCP lifecycle: `[SYN]`, `[SYN-ACK]`, `[ACK]`, TLS negotiation, and teardown. |

---

## 💻 Interactive Web Application & Security Cockpit

The web application runs on **`http://localhost:3000`** and provides an interactive interface for demonstrations:

1. **User / Persona Switcher**:
   - `Alice Smith` (Retail Customer, Account `acc_1001`, $10k limit)
   - `Bob Jones` (Retail Customer, Account `acc_1002`, $10k limit)
   - `Tim Teller` (Branch Bank Teller, Downtown NYC, $50k limit)
   - `Carol Auditor` (Compliance & Risk Auditor)
   - `Dave Admin` (SecOps System Administrator)
   - `Rogue Infiltrator` (Adversary simulating lateral movement attacks)
2. **Mesh Health Monitor**: Real-time status indicators for Gateway (`:8000`), Account Service (`:8001`), Ledger Service (`:8002`), and OPA (`:8181`).
3. **Accounts & Transfer Dashboard**: Perform transfers, observe real-time balance changes, and view structured responses.
4. **Cryptographic Ledger Visualizer**: Table of chained blocks with live cryptographic verification and a 1-click **"Simulate Tamper"** button.
5. **Policy Inspector**: Real-time breakdown of Layer 4 mTLS certificates, Layer 7 JWT claims, OPA decision logs, and raw SIEM event streams.
6. **1-Click Security Scenarios**: Execute any of the 9 scenarios directly from the UI with formatted output.
7. **Wireshark Demo Studio**: Quick copy buttons for Wireshark display filters, presentation talking points, and traffic burst trigger.

---

## 🚀 Quick Start Guide

### Prerequisites
- **Docker** and **Docker Compose** (`docker compose` or `docker-compose`)
- **OpenSSL** (for PKI certificate generation)
- **curl** and **bash** (for running CLI tests)
- **Wireshark** (optional, for packet analysis)

### Step 1: Clone the Repository
```bash
git clone git@github.com:shaik-hasan-AS/ZeroTrustStyle.git
cd ZeroTrustStyle
```

### Step 2: Generate PKI Certificates
```bash
./scripts/generate-certs.sh
```

### Step 3: Launch the Zero-Trust Mesh
```bash
docker-compose up --build -d
```

Verify that all 5 containers are running:
```bash
docker-compose ps
```

### Step 4: Access the Web Cockpit
Open your web browser and navigate to:
👉 **`http://localhost:3000`**

### Step 5: Run Automated CLI Verification
```bash
./scripts/test-all-scenarios.sh
```

### Step 6: Teardown
```bash
docker-compose down -v
```

---

## 🗂️ Project Directory Structure

```
ZeroTrustStyle/
├── docker-compose.yml              # Multi-container orchestration (Gateway, Accounts, Ledger, OPA, Client)
├── README.md                       # Comprehensive project documentation
├── .gitignore                      # Git ignore rules
│
├── certs/                          # Public Key Infrastructure (generated by scripts/generate-certs.sh)
│   ├── ca/                         # Root Certificate Authority (ca.crt, ca.key)
│   ├── gateway/                    # API Gateway certificate & private key (CN=gateway)
│   ├── account-service/            # Account Service certificate & private key (CN=account-service)
│   ├── ledger-service/             # Core Ledger certificate & private key (CN=ledger-service)
│   ├── client/                     # Web client certificate & private key (CN=client-fintech-portal)
│   ├── rogue-service/              # CA-signed attacker certificate (CN=rogue-unauthorized-workload)
│   └── untrusted-client/           # Rogue CA self-signed cert (untrusted handshake failure test)
│
├── gateway/                        # API Gateway Microservice (Policy Enforcement Point)
│   ├── Dockerfile                  # Uvicorn with --ssl-cert-reqs 2 (mTLS enforced)
│   ├── requirements.txt            # FastAPI, Uvicorn, HTTPX, PyJWT
│   └── app/
│       └── main.py                 # JWT token issuance, mTLS termination, reverse proxy
│
├── account-service/                # Account Service (PEP + ABAC)
│   ├── Dockerfile                  # Uvicorn with mTLS listener on :8001
│   ├── requirements.txt
│   └── app/
│       └── main.py                 # Account management, OPA evaluation, Ledger forwarding
│
├── ledger-service/                 # Core Financial Ledger (PEP + Cryptographic Hash Chain)
│   ├── Dockerfile                  # Uvicorn with mTLS listener on :8002
│   ├── requirements.txt
│   └── app/
│       └── main.py                 # SHA-256 hash chaining, tamper detection, audit trail
│
├── opa/                            # Open Policy Agent (Policy Decision Point - PDP)
│   └── policies/
│       └── authz.rego              # Rego policy defining workload identity, ABAC, limits, and roles
│
├── client/                         # Web Client Portal & Security Cockpit
│   ├── Dockerfile                  # Serves web interface on :3000
│   ├── requirements.txt
│   └── app/
│       ├── main.py                 # Backend bridge, scenario executor, Wireshark burst trigger
│       └── static/
│           ├── index.html          # Web UI layout
│           ├── css/styles.css      # Dark-mode FinTech design system
│           └── js/app.js           # Client-side state machine and telemetry visualizer
│
└── scripts/                        # Automated Verification & PKI Utility Scripts
    ├── generate-certs.sh           # Generates Root CA and all service certificates
    ├── test-all-scenarios.sh       # Runs complete suite of 9 verification scenarios
    ├── test-1-customer-own-account.sh
    ├── test-2-customer-other-account-denied.sh
    ├── test-3-transfer-within-limit.sh
    ├── test-4-transfer-exceeding-limit-denied.sh
    ├── test-5-teller-high-value-transfer.sh
    ├── test-6-compliance-audit-ledger.sh
    ├── test-7-customer-audit-ledger-denied.sh
    ├── test-8-lateral-movement-bypass-denied.sh
    └── test-9-untrusted-cert-handshake-failure.sh
```

---

## 🔒 Threat Model & STRIDE Analysis

| STRIDE Category | Network Threat | Traditional Perimeter Failure | Zero-Trust Defense in this Project |
|---|---|---|---|
| **Spoofing** | Adversary injects rogue packets into private Docker network | Private network assumed secure; plaintext traffic accepted | Mutual TLS with Root CA validation rejects non-enrolled workloads at Layer 4 socket level. |
| **Tampering** | Man-in-the-Middle modifies transfer amounts in transit | Internal traffic unencrypted (plaintext HTTP) | TLS 1.3 / AES-256-GCM encrypts all inter-service hops. Cryptographic SHA-256 ledger chaining detects database tampering. |
| **Repudiation** | Malicious user denies executing unauthorized transfer | Single server log without cryptographic proof | Every ledger entry records signed JWT subject (`sub`), caller workload CN, and is chained into immutable SHA-256 blocks. |
| **Information Disclosure** | Sniffing internal network bridge traffic | Internal mesh traffic unencrypted; Wireshark captures plaintext JSON | Wireshark confirms 100% of inter-service payloads are encrypted application data. |
| **Denial of Service** | Rogue client exhausts resources | Server processes requests before authentication | Missing or untrusted client certificates are dropped during TLS handshake before application processing. |
| **Elevation of Privilege** | Horizontal privilege escalation (BOLA) or lateral ledger write | Hardcoded service roles; internal networks unsegmented | Open Policy Agent PDP evaluates dynamic ABAC policies on every request (`user.id == owner_id`, CN checks). |

---

## 🎓 Computer Networks Viva Voce & Presentation Cheat Sheet

**Q1: What is the primary difference between standard HTTPS and Mutual TLS (mTLS)?**  
*Answer:* In standard HTTPS (one-way TLS), only the server authenticates itself to the client using a certificate; anyone can connect. In Mutual TLS (mTLS), the server also requires the client to present a valid X.509 certificate signed by a trusted Certificate Authority before establishing the TLS session.

**Q2: How does Wireshark prove that Mutual TLS is actively being enforced?**  
*Answer:* In Wireshark, filtering for `tls.handshake.type == 13` reveals a **"Certificate Request"** packet sent by the server to the client. This packet never occurs in ordinary one-way TLS connections.

**Q3: Why is Layer 4 mTLS alone not enough for Zero Trust? Why do we need Layer 7 ABAC?**  
*Answer:* Layer 4 mTLS only authenticates the *machine workload* (e.g., "this container is a valid microservice"). It does not know *which user* is making the request, what their role is, or whether they own the requested resource. Combining Layer 4 mTLS with Layer 7 JWT + OPA ABAC guarantees dual-layer verification (Workload Identity + Subject Identity).

**Q4: How does Scenario 8 demonstrate lateral movement prevention?**  
*Answer:* Even if an attacker obtains a valid CA-signed certificate (`CN=rogue-unauthorized-workload`) and successfully completes the TLS handshake to `ledger-service:8002`, the OPA policy checks the caller's Common Name. Because only `account-service` is authorized to post entries, the ledger rejects the request with HTTP 403 Forbidden.

**Q5: How does the cryptographic hash chain guarantee non-repudiation and audit integrity?**  
*Answer:* Each entry's hash incorporates the previous entry's hash ($H_{n-1}$), timestamp, transaction details, and caller CN. If an attacker alters any historical database record, the recalculated hash will not match the recorded hash, breaking the chain and exposing the modification.

---

## 📄 License & Academic Attribution
Developed as a Computer Networks (CN) Reference Project. Designed for educational demonstrations, security engineering workshops, and network protocol analysis.
