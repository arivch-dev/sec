#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../kms/certs" && pwd)"
mkdir -p "$DIR"
cd "$DIR"

echo "=== Generating CA ==="
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/CN=KMS-Root-CA"

echo "=== Generating Server Certificate ==="
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=kms.internal"
cat > server-ext.cnf << 'SAN_EOF'
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = kms.internal
DNS.2 = localhost
IP.1 = 127.0.0.1
SAN_EOF
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -extfile server-ext.cnf

echo "=== Generating Client Certificate ==="
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=client.internal"
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt

echo "=== Generating Admin Certificate ==="
openssl genrsa -out admin.key 2048
openssl req -new -key admin.key -out admin.csr -subj "/CN=kms-admin"
openssl x509 -req -days 365 -in admin.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out admin.crt

chmod 600 *.key
echo "Certificates successfully generated in $DIR"
