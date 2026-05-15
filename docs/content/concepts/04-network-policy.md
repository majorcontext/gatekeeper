---
title: "Network Policy"
description: "How Gatekeeper enforces network access control with permissive and strict modes, allow lists, and per-path rules."
keywords: ["gatekeeper", "network policy", "allow list", "strict mode"]
---

# Network Policy

Gatekeeper enforces network policy to control which hosts a client can reach through the proxy. Policy evaluation happens before credential injection — blocked requests never receive credentials.

## Permissive vs Strict

The `policy` field controls the default behavior:

| Mode | Behavior |
|---|---|
| `permissive` | All hosts are allowed. This is the default. |
| `strict` | Only hosts in the allow list are reachable. All other requests are denied with a `407` response. |

```yaml
network:
  policy: strict
  allow:
    - api.github.com
    - "*.anthropic.com"
```

In permissive mode, the allow list is ignored. All traffic passes through.

## Allow List Mechanics

The allow list is a set of host patterns. Each pattern follows the same matching rules as credential host patterns:

- **Exact match.** `api.github.com` matches only `api.github.com`.
- **Wildcard.** `*.github.com` matches any subdomain: `api.github.com`, `raw.githubusercontent.com` does not match (different base domain), but `foo.bar.github.com` does.
- **Port-specific.** `api.example.com:8080` matches only that port. Patterns without a port match only ports 80 and 443.

When a client sends a CONNECT request, gatekeeper extracts the host and port and checks them against the allow list. If no pattern matches, the tunnel is refused.

## Grant Hosts Are Auto-Allowed

When callers pass grant names to `SetNetworkPolicy`, gatekeeper expands each grant to its known host patterns and adds them to the allow list automatically. This is used by moat's daemon layer, which passes per-run grants when registering runs.

For example, the `github` grant expands to:

- `github.com`
- `api.github.com`
- `*.githubusercontent.com`
- `*.github.com`

In standalone mode (`gatekeeper.yaml`), grant expansion does not apply — only the explicit `allow` list is used. Add credential hosts to the allow list manually when using strict mode.

## Interaction with Credential Injection

Network policy and credential injection are independent checks that run in sequence:

1. **Network policy** runs first. If the host is denied, the request is blocked with a `407` response. No credential lookup occurs.
2. **Credential injection** runs second, only for allowed requests. The proxy matches the host against credential patterns and injects headers.

This ordering has a security property: credentials are never sent to unauthorized hosts. Even if a credential pattern matches a host that is blocked by network policy, the credential is never injected because the request never reaches the injection step.

## Per-Path Rules

When gatekeeper has path-level rules (configured via `RequestChecker`), it evaluates them on the inner HTTP request after TLS interception — not on the CONNECT tunnel. The CONNECT request only carries the host, not the path. Gatekeeper intercepts the tunnel, reads the plaintext request, and then checks `method` and `path` against the rules.

> **Note:** Per-path rules require TLS interception (a CA must be configured). Without interception, only host-level allow/deny applies. Gatekeeper logs a warning if path rules are configured but the CA is missing.

## Host Gateway Policy

When a request targets a host gateway address (synthetic hostname or loopback), gatekeeper applies a separate check: the destination port must be in the run's `AllowedHostPorts` list. This prevents containers from reaching arbitrary services on the host machine. See [Host Gateway](./07-host-gateway.md) for details.

## Blocked Response Format

Blocked requests receive a `407 Proxy Authentication Required` response with a `Proxy-Authenticate: Moat-Policy` header and a plaintext body explaining which host was denied. The `X-Moat-Blocked` header indicates the denial reason (`request-rule` for network policy, `host-service` for host gateway blocks).
