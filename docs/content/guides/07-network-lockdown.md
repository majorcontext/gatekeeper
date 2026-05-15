---
title: "Network Lockdown"
description: "Restrict which hosts the proxy forwards traffic to using strict network policy with an allow list."
keywords: ["gatekeeper", "network lockdown", "strict policy", "allow list"]
---

# Network Lockdown

Restrict which hosts the proxy forwards traffic to. By default, gatekeeper operates in `permissive` mode -- it proxies requests to any host. Switch to `strict` mode to deny all traffic except explicitly allowed hosts.

## Prerequisites

- CA certificate generated ([CA Setup](./01-ca-setup.md))
- A working gatekeeper configuration with at least one credential

## Permissive Mode (Default)

The default configuration allows traffic to all hosts:

```yaml
network:
  policy: permissive
```

All CONNECT and HTTP requests pass through. Credentials are injected only for matching hosts; all other traffic is forwarded without modification.

## Strict Mode

Switch to `strict` to deny all traffic except listed hosts:

```yaml
network:
  policy: strict
  allow:
    - "api.github.com"
    - "*.anthropic.com"
```

Requests to unlisted hosts receive an HTTP `407` response with a `Proxy-Authenticate: Moat-Policy` header.

## Glob Patterns

The `allow` list supports glob patterns for flexible matching:

| Pattern               | Matches                                      |
|-----------------------|----------------------------------------------|
| `api.github.com`      | Exact match only                             |
| `*.github.com`        | `api.github.com`, `raw.github.com`, etc.     |
| `*.example.com`       | Any subdomain of `example.com`               |

Port numbers are stripped before matching -- `api.github.com:443` matches a rule for `api.github.com`.

## Combined Configuration

Combine credential injection with network lockdown:

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
  policy: strict
  allow:
    - "api.github.com"

log:
  level: info
  format: text
```

This configuration injects GitHub credentials for `api.github.com` and blocks all other outbound traffic.

## Verification

Start the proxy and test a denied request:

```bash
curl --cacert ca.crt --proxy http://127.0.0.1:9080 https://example.com
```

The proxy returns a `407` and logs:

```text
level=WARN msg=request http_host=example.com denied=true deny_reason="Host not in allow list: example.com"
```

Confirm allowed requests still work:

```bash
curl --cacert ca.crt --proxy http://127.0.0.1:9080 https://api.github.com/user
```

## Next Steps

- [OpenTelemetry](./08-opentelemetry.md) — monitor denied requests with metrics and traces
