---
title: "Quick start"
description: "Start a credential-injecting proxy in under five minutes with a minimal configuration."
keywords: ["gatekeeper", "quick start", "getting started", "proxy setup"]
---

# Quick start

Start a credential-injecting proxy in under five minutes.

## Prerequisites

- Go 1.25+ installed
- `gatekeeper` binary on `$PATH` (see [Installation](./02-installation.md))
- `openssl` available (for CA generation)

## Step 1: Generate a CA certificate

The proxy needs a CA to sign per-host TLS certificates. Use the included script:

```bash
cd examples && ./gen-ca.sh
```

This creates `ca.crt` and `ca.key` in the `examples/` directory.

## Step 2: Write a minimal config

Create `gatekeeper.yaml`:

```yaml
proxy:
  host: 127.0.0.1
  port: 9080

tls:
  ca_cert: examples/ca.crt
  ca_key: examples/ca.key

credentials:
  - host: api.example.com
    header: Authorization
    grant: example-api
    source:
      type: env
      var: EXAMPLE_API_TOKEN

network:
  policy: permissive

log:
  level: info
  format: text
```

This configures the proxy to inject the value of the `EXAMPLE_API_TOKEN` environment variable as an `Authorization` header on all requests to `api.example.com`.

## Step 3: Start the proxy

Set the credential and start gatekeeper:

```bash
export EXAMPLE_API_TOKEN="sk-xxxx"
gatekeeper --config gatekeeper.yaml
```

The proxy logs a startup message:

```text
level=INFO msg="gatekeeper listening" addr=127.0.0.1:9080 version=dev
```

## Step 4: Make a request through the proxy

In a separate terminal, send a request through the proxy:

```bash
curl --proxy http://127.0.0.1:9080 --cacert examples/ca.crt \
  https://api.example.com/v1/resource
```

The `--proxy` flag routes the request through gatekeeper. The `--cacert` flag trusts the generated CA so curl accepts the intercepted TLS certificate.

Gatekeeper intercepts the connection, injects the `Authorization: Bearer sk-xxxx` header, and forwards the request to `api.example.com`. The credential never appears in the curl command or the client environment of the calling process.

## Step 5: Verify credential injection

The proxy logs each request with credential injection details:

```text
level=INFO msg=request http_method=GET http_host=api.example.com http_path=/v1/resource http_status=200 duration_ms=142 credential_injected=true injected_headers=Authorization grants=example-api
```

The `credential_injected=true` and `grants=example-api` fields confirm the proxy injected the credential.

## Next steps

- Configure [network policy](../guides/07-network-lockdown.md) to restrict which hosts the proxy forwards to
- Add credentials from [AWS Secrets Manager](../guides/03-aws-secrets-manager.md) or [GCP Secret Manager](../guides/04-gcp-secret-manager.md) for production deployments
- Enable [OpenTelemetry](../guides/08-opentelemetry.md) for distributed tracing and metrics
