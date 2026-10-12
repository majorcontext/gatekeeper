---
name: verify
description: Build, launch, and drive gatekeeper locally to verify proxy changes end-to-end
---

# Verifying gatekeeper locally

## Build & launch

```bash
go build -o /tmp/gk/gatekeeper ./cmd/gatekeeper/
cp examples/ca.crt examples/ca.key /tmp/gk/   # checked-in example CA, valid to 2027
# config: proxy {host: 127.0.0.1, port: 19080}, tls {ca_cert, ca_key},
# network {policy: permissive}, log {format: json}
/tmp/gk/gatekeeper --config config.yaml > gk.log 2>&1 &
```

## Drive

- Health: `curl http://127.0.0.1:19080/healthz` → `{"status":"ok"}`
- CONNECT-intercepted HTTPS (the ~99.9% path): `curl --cacert ca.crt --proxy http://127.0.0.1:19080 https://api.github.com/zen`
- Canonical request log: JSON lines in gk.log with `msg":"request"` — fields `client_ip`, `http_host`, `proxy_type`, `http_status`. Grep `client_ip` to skip noise.

## Gotchas

- gk.log fills with OTLP export retries (`localhost:4318 connection refused`, one INFO line/sec) because cmd/gatekeeper registers OTel exporters unconditionally. Grep around it.
- To simulate a PROXY-protocol LB (GCP TCP Proxy), a ~30-line Python splice shim that prepends `PROXY TCP4 <ip> ...\r\n` before relaying to the gatekeeper port works with plain curl pointed at the shim.
- examples/gen-ca.sh can emit a CA that Go rejects (duplicate basicConstraints) on newer OpenSSL — prefer the checked-in examples/ca.crt.
