---
title: "Environment Variable Credentials"
description: "Read a credential from an environment variable and inject it into HTTPS requests through Gatekeeper."
keywords: ["gatekeeper", "environment variables", "credential injection", "env source"]
---

# Environment Variable Credentials

Read a credential from an environment variable and inject it into HTTPS requests. This is the simplest credential source.

## Prerequisites

- CA certificate generated ([CA Setup](./01-ca-setup.md))
- Gatekeeper binary built (`go build -o gatekeeper ./cmd/gatekeeper/`)

## Configuration

Create `gatekeeper.yaml`:

```yaml
proxy:
  host: 127.0.0.1
  port: 9080

tls:
  ca_cert: ca.crt
  ca_key: ca.key

credentials:
  - host: api.github.com
    header: Authorization
    grant: github
    source:
      type: env
      var: GITHUB_TOKEN

network:
  policy: permissive

log:
  level: info
  format: text
```

The `env` source reads the credential from the environment variable named in `var`. The variable must be set when the proxy starts.

## Start the Proxy

Set the token and start gatekeeper:

```bash
export GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxx"
gatekeeper --config gatekeeper.yaml
```

Gatekeeper resolves the credential at startup. For `Authorization` headers, the auth scheme is auto-detected from the token prefix (`ghp_` maps to `token`, `github_pat_` to `Bearer`). Override with the `prefix` field if needed.

## Make a Request

In another terminal:

```bash
curl --cacert ca.crt --proxy http://127.0.0.1:9080 https://api.github.com/user
```

The proxy intercepts the TLS connection, injects the `Authorization` header, and forwards the request. The proxy log shows `credential_injected=true`.

## Verification

Check the proxy log output. A successful injection produces a line like:

```text
level=INFO msg=request http_method=GET http_host=api.github.com http_status=200 credential_injected=true injected_headers=Authorization grants=github
```

## Next Steps

- [AWS Secrets Manager](./03-aws-secrets-manager.md) — fetch credentials from AWS instead of environment variables
- [Network Lockdown](./07-network-lockdown.md) — restrict which hosts the proxy can reach
