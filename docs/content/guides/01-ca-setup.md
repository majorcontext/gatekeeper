---
title: "CA Setup"
description: "Generate a Certificate Authority for TLS interception and configure trust on macOS, Linux, and per-tool environments."
keywords: ["gatekeeper", "CA certificate", "TLS setup", "certificate trust"]
---

# CA certificate setup

Generate a Certificate Authority for TLS interception and trust it on your system. Gatekeeper uses this CA to sign per-host certificates dynamically, enabling credential injection into HTTPS requests.

## Prerequisites

- OpenSSL installed
- Gatekeeper repository cloned

## Generate the CA

Run the included script from the `examples/` directory:

```bash
cd examples && ./gen-ca.sh
```

This creates two files:

- `ca.crt` — the CA certificate (distribute to clients)
- `ca.key` — the CA private key (keep private, permissions set to `0600`)

The generated CA uses an EC P-256 key, valid for 365 days, with `CA:TRUE, pathlen:0` and `keyCertSign` constraints.

> **Note:** The script generates the certificate from an explicit OpenSSL config file (rather than `-addext`) and splits EC key generation into `openssl ecparam` + `openssl req -new -x509` steps. Both choices avoid toolchain-specific failures: some OpenSSL builds duplicate the `basicConstraints` extension when it's supplied via `-addext` alongside a default config that already defines `req_extensions`, which Go's `x509` parser rejects; LibreSSL (the `openssl` on a stock macOS install) mishandles the single-step `openssl req -newkey ec -pkeyopt ...` form, emitting EC parameters that Go's `x509` parser rejects with "invalid ECDSA parameters" when gatekeeper loads the CA.

## Trust the CA

### macOS

Add the CA to the system keychain:

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt
```

### Linux (Debian/Ubuntu)

Copy the certificate and update the trust store:

```bash
sudo cp ca.crt /usr/local/share/ca-certificates/gatekeeper-ca.crt
sudo update-ca-certificates
```

### Linux (RHEL/Fedora)

```bash
sudo cp ca.crt /etc/pki/ca-trust/source/anchors/gatekeeper-ca.crt
sudo update-ca-trust
```

## Per-tool trust

Some tools require explicit CA configuration instead of using the system store.

### curl

```bash
curl --cacert ca.crt --proxy http://127.0.0.1:9080 https://api.github.com/user
```

### Node.js

```bash
export NODE_EXTRA_CA_CERTS=/path/to/ca.crt
node app.js
```

### Python (requests)

```bash
export REQUESTS_CA_BUNDLE=/path/to/ca.crt
python script.py
```

### Go

```bash
export SSL_CERT_FILE=/path/to/ca.crt
go run main.go
```

## Verification

Confirm the proxy can intercept and re-sign a TLS connection:

```bash
curl --cacert ca.crt --proxy http://127.0.0.1:9080 -v https://example.com 2>&1 | grep "issuer"
```

The output should show the CN of your CA certificate as the issuer.

## Next steps

- [Environment Credentials](./02-environment-credentials.md) — inject your first credential through the proxy
