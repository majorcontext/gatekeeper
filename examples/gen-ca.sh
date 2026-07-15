#!/usr/bin/env bash
# Generate a self-signed CA certificate for TLS interception.
# The proxy uses this CA to dynamically sign certificates for
# upstream hosts so it can inspect and modify HTTPS traffic.
set -euo pipefail

cd "$(dirname "$0")"

if [ -f ca.crt ] && [ -f ca.key ]; then
  echo "CA certificate already exists (ca.crt, ca.key). Remove them to regenerate."
  exit 0
fi

# An explicit [v3_ca] section (referenced via -config/-extensions) is used
# instead of -addext. Some OpenSSL builds (e.g. Homebrew OpenSSL 1.1.1) merge
# -addext extensions with the default config's own req_extensions, producing
# a certificate with a duplicate basicConstraints extension that Go's x509
# parser rejects ("certificate contains duplicate extension"). A self-
# contained config file has no default extensions to collide with.
openssl_config=$(mktemp)
trap 'rm -f "$openssl_config"' EXIT

cat > "$openssl_config" <<'EOF'
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
CN = Gate Keeper Example CA

[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
EOF

# EC key generation is split into two steps (ecparam + req) rather than
# `openssl req -newkey ec -pkeyopt ...` because LibreSSL (the OpenSSL variant
# shipped as macOS system /usr/bin/openssl) mishandles the one-step form,
# emitting EC parameters that Go's x509 parser rejects with "invalid ECDSA
# parameters" when gatekeeper loads the CA.
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -new -x509 -key ca.key -days 365 \
  -out ca.crt \
  -config "$openssl_config" -extensions v3_ca \
  2>/dev/null

chmod 0600 ca.key
echo "Generated ca.crt and ca.key"
