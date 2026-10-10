#!/bin/bash
set -e

# Go to project root relative to script
cd "$(dirname "$0")/.."

# Clean and recreate certs directory
rm -rf certs
mkdir -p certs/ca certs/gateway certs/account-service certs/ledger-service certs/client certs/rogue-service

# 1. Generate Root CA
echo "=== Generating Root CA ==="
openssl req -x509 -nodes -new -sha256 -days 1024 -newkey rsa:2048 \
    -keyout certs/ca/ca.key -out certs/ca/ca.crt \
    -subj "/C=US/ST=FinTech/L=NewYork/O=ZeroTrust Banking Corp/CN=ZeroTrust Banking Root CA"

# Function to generate a certificate for a service or client
generate_cert() {
    SERVICE=$1
    CN=$2
    SAN_EXTRA=$3
    
    echo "Generating certificate for $SERVICE (CN=$CN)..."
    
    # Generate private key
    openssl genrsa -out certs/$SERVICE/$SERVICE.key 2048
    
    # Generate CSR
    openssl req -new -key certs/$SERVICE/$SERVICE.key -out certs/$SERVICE/$SERVICE.csr \
        -subj "/C=US/ST=FinTech/L=NewYork/O=ZeroTrust Banking Corp/CN=$CN"
    
    # Create extension config for SAN (Subject Alternative Name)
    cat > certs/$SERVICE/ext.cnf <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $CN
DNS.2 = localhost
EOF

    if [ -n "$SAN_EXTRA" ]; then
        echo "DNS.3 = $SAN_EXTRA" >> certs/$SERVICE/ext.cnf
    fi
    
    # Sign certificate with Root CA
    openssl x509 -req -in certs/$SERVICE/$SERVICE.csr \
        -CA certs/ca/ca.crt -CAkey certs/ca/ca.key -CAcreateserial \
        -out certs/$SERVICE/$SERVICE.crt -days 500 -sha256 \
        -extfile certs/$SERVICE/ext.cnf
    
    # Cleanup CSR and ext config
    rm certs/$SERVICE/$SERVICE.csr certs/$SERVICE/ext.cnf
}

generate_cert "gateway" "gateway"
generate_cert "account-service" "account-service"
generate_cert "ledger-service" "ledger-service"
generate_cert "client" "client-fintech-portal"
generate_cert "rogue-service" "rogue-unauthorized-workload"

# Create invalid/untrusted cert signed by a rogue untrusted CA (to test untrusted TLS)
mkdir -p certs/untrusted-client
openssl req -x509 -nodes -new -sha256 -days 100 -newkey rsa:2048 \
    -keyout certs/untrusted-client/untrusted.key -out certs/untrusted-client/untrusted.crt \
    -subj "/C=US/ST=Hacker/L=DarkNet/O=Rogue Entity/CN=hacker"

echo "=== All certificates generated successfully ==="
