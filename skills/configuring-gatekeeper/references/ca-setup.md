# CA setup and client trust

Gatekeeper intercepts TLS by **minting a certificate for each upstream host on
the fly**, signed by a CA you control. Two consequences:

1. You must give Gatekeeper a CA cert + key (`tls.ca_cert`, `tls.ca_key`).
2. Every client must **trust that CA**, or TLS verification fails.

## Generate a CA

The repo ships a script:

```bash
cd examples && ./gen-ca.sh        # writes ca.crt + ca.key, refuses to overwrite
```

Or directly with openssl (EC P-256, 1-year, CA basic constraints):

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -days 365 -nodes \
  -keyout ca.key -out ca.crt \
  -subj "/CN=My Gatekeeper CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
chmod 0600 ca.key
```

Reference it in config:

```yaml
tls:
  ca_cert: ca.crt
  ca_key: ca.key
```

## Make clients trust the CA

Pick the mechanism for your client — do **not** disable TLS verification.

| Client            | How to trust `ca.crt`                                        |
|-------------------|-------------------------------------------------------------|
| curl              | `--cacert ca.crt`                                           |
| Node / opencode   | `export NODE_EXTRA_CA_CERTS=$PWD/ca.crt`                    |
| Python requests   | `export REQUESTS_CA_BUNDLE=$PWD/ca.crt`                     |
| git (per command) | `git -c http.sslCAInfo=$PWD/ca.crt ...`                     |
| Generic (OpenSSL) | `export SSL_CERT_FILE=$PWD/ca.crt`                          |
| System-wide (Linux) | Copy to `/usr/local/share/ca-certificates/` then `update-ca-certificates` |

## Security notes

- **Keep `ca.key` secret.** Anyone with it can mint trusted certs for any host.
  Gatekeeper keeps the key in memory only and never writes it to temp files —
  store the file with `0600` perms and don't commit it.
- Use a **dedicated** CA for Gatekeeper, scoped to the environments that route
  through it. Don't reuse an org-wide root.
- The example CA is for local development. Generate a fresh CA per real
  deployment.
