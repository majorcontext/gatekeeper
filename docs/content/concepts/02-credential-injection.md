---
title: "Injection"
description: "How Gatekeeper matches hostnames, injects authentication headers, and handles multiple credentials per host."
keywords: ["gatekeeper", "credential injection", "host matching", "authorization headers"]
---

# Credential Injection

Gatekeeper injects authentication headers into proxied HTTP requests based on hostname matching. Clients never handle raw credentials — they send requests through the proxy, which resolves the correct credential and sets the appropriate header before forwarding to the upstream server.

## Host Matching

Each credential is configured with a `host` pattern. When gatekeeper intercepts a request, it looks up credentials for the target hostname, stripping any port from the request host unconditionally before comparing — there is no notion of a default or matched port in credential lookup.

Matching rules:

| Pattern | Matches | Does Not Match |
|---|---|---|
| `api.github.com` | `api.github.com`, `api.github.com:443` (port stripped before comparison) | `github.com`, `foo.api.github.com` |
| `*.github.com` | `api.github.com`, `foo.bar.github.com` | `github.com` |

A `host` pattern cannot contain a port — `credentials[].host` is validated and any value containing `:` is rejected (silently dropped, logged at debug level), so a pattern like `api.example.com:8080` can never be configured. This differs from network policy's `allow` patterns, which do support an explicit port and default unported patterns to matching only ports 80 and 443 — that port-aware matching is specific to network policy and does not apply to credential host matching. See [Network Policy](./04-network-policy.md).

Host comparison is case-insensitive. `API.GitHub.com` matches `api.github.com`.

## Header Injection

The default injection header is `Authorization`. Override it with the `header` field:

```yaml
credentials:
  - host: api.example.com
    header: x-api-key
    source:
      type: env
      var: EXAMPLE_API_KEY
```

Gatekeeper injects credentials in two modes:

1. **Placeholder replacement.** If the client sends a request with the target header already set (e.g., a stub `Authorization` value), gatekeeper replaces it with the real credential. This lets the client choose which credential to use when multiple grants target the same host.

2. **Auto-injection.** If the client sends no matching header, gatekeeper injects the credential unconditionally. When multiple credentials share the same header name for a host, the `claude` grant is deprioritized — it is only injected when the client explicitly sends a placeholder.

## Grant Names

The `grant` field is an optional label that identifies a credential for logging and MCP relay matching. Grant names appear in canonical log lines and OpenTelemetry span attributes.

```yaml
credentials:
  - host: api.github.com
    grant: github
    source:
      type: env
      var: GITHUB_TOKEN
```

Built-in grant names (`github`, `anthropic`, `openai`, `aws`, and others) map to predefined host patterns. These mappings are used by network policy to auto-allow hosts for configured grants.

## Prefix and Format

For `Authorization` headers, gatekeeper ensures the value includes an auth scheme prefix. The behavior depends on configuration:

- **No prefix, no format.** Gatekeeper auto-detects the scheme from known token prefixes. GitHub `ghp_` and `ghs_` tokens get `token` scheme. GitHub `gho_` and `github_pat_` tokens get `Bearer`. Everything else defaults to `Bearer`.
- **Explicit prefix.** The `prefix` value is prepended with a space: `prefix: "token"` produces `token sk-xxxx`.
- **Basic format.** Set `format: basic` to produce HTTP Basic authentication. The `prefix` field becomes the username: `Basic base64(prefix:value)`.

```yaml
# HTTP Basic auth for git smart HTTP
credentials:
  - host: github.com
    format: basic
    prefix: x-access-token
    grant: github
    source:
      type: env
      var: GITHUB_TOKEN
```

## Multiple Credentials Per Host

A host can have multiple credential entries with different header names. All matching credentials are injected:

```yaml
credentials:
  - host: api.anthropic.com
    header: x-api-key
    grant: anthropic
    source:
      type: env
      var: ANTHROPIC_API_KEY
  - host: api.anthropic.com
    header: anthropic-beta
    source:
      type: static
      value: "prompt-caching-2024-07-31"
```

When multiple credentials share the same header name, placeholder replacement takes priority. If no placeholder matched, auto-injection picks the non-`claude` grant to avoid overriding explicit OAuth flows.

## Credential Stripping

Gatekeeper removes `Proxy-Authorization` and `Proxy-Connection` headers from all forwarded requests. These are hop-by-hop headers used between the client and the proxy — they must never reach the upstream server. Injected credential headers (like `Authorization`) are also redacted in log output to prevent credential leakage.
