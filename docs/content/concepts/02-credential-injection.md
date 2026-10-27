---
title: "Injection"
description: "How Gatekeeper matches hostnames, injects authentication headers, and handles multiple credentials per host."
keywords: ["gatekeeper", "credential injection", "host matching", "authorization headers"]
---

# Credential injection

Gatekeeper injects authentication headers into proxied HTTP requests based on hostname matching. Clients never handle raw credentials — they send requests through the proxy, which resolves the correct credential and sets the appropriate header before forwarding to the upstream server.

## Host matching

Each credential is configured with a `host` pattern. When gatekeeper intercepts a request, it looks up credentials for the target hostname, stripping any port from the request host unconditionally before comparing — there is no notion of a default or matched port in credential lookup.

Matching rules:

| Pattern | Matches | Does Not Match |
|---|---|---|
| `api.github.com` | `api.github.com`, `api.github.com:443` (port stripped before comparison) | `github.com`, `foo.api.github.com` |
| `*.github.com` | `api.github.com`, `foo.bar.github.com` | `github.com` |
| `pr-*.example.com` | `pr-6301.example.com` | `pr-.example.com`, `pr-1.x.example.com`, `xpr-1.example.com`, `example.com` |

A prefix pattern, such as `pr-*.example.com`, matches one label: the prefix, at least one more character, then exactly the rest of the pattern. The `*` must end the first label, the prefix cannot be empty, and the rest needs two labels. Any other `*` placement fails config load. When several patterns match, an exact host wins over a prefix pattern, and a prefix pattern wins over a `*.` pattern.

A `host` pattern cannot contain a port — `credentials[].host` is validated and any value containing `:` is rejected (silently dropped, logged at debug level), so a pattern like `api.example.com:8080` can never be configured. This differs from network policy's `allow` patterns, which do support an explicit port and default unported patterns to matching only ports 80 and 443 — that port-aware matching is specific to network policy and does not apply to credential host matching. See [Network Policy](./04-network-policy.md).

Host comparison is case-insensitive. `API.GitHub.com` matches `api.github.com`.

Before it matches, gatekeeper puts the host of a proxy request (the CONNECT target, or the host of an absolute-form URL) in the form the upstream connection dials, so that matching and dialing use one name:

- A non-ASCII host is mapped to its ASCII (`xn--`) form with the IDNA lookup mapping that `net/http` applies when it dials. `pr-1。evil.example.com` (U+3002) becomes `pr-1.evil.example.com` and so does not match `pr-*.example.com`.
- One trailing dot is dropped, so `api.github.com.` matches the same patterns as `api.github.com`.
- A host with an empty label (`a..example.com`, `.example.com`) or a name IDNA rejects is refused with `400`.
- A host that ends in a number but is not a canonical dotted-quad IPv4 address (`0177.0.0.1`, `127.1`, `0x7f.1`, `2130706433`) is refused with `400`: libc reads each as an IPv4 address, so it must not pass as a DNS name. Host patterns with that shape are rejected, as are bracketed patterns that are not IP literals.
- An IP key (`::1`, `[::1]:8080`, `127.0.0.1`) matches by parsed address and port, so `127.0.0.1` also matches `[::ffff:127.0.0.1]` and `[0:0:0:0:0:0:0:1]` matches `[::1]`.
- An IP literal is an address, not a name. A `*.` or prefix pattern never matches one (a `*.0.2.1` pattern does not match `192.0.2.1`); only an exact IP host key does. An IPv6 literal is put in its canonical text form, and one with a zone (`[::1%25eth0]`) is refused with `400`: a zone is free text that the dial ignores for an IPv4-mapped address, so `[::ffff:192.0.2.1%25x.example.com]` would otherwise look like a host under `example.com`.

Host patterns follow the same rules: write an internationalized name in its `xn--` form, and do not end a pattern with a dot or leave an empty label. Config load rejects both, and so does `ValidateHostPattern`.

## Header injection

The configured `header` is the credential output header. Credential-scoped `add_headers` appends comma-separated tokens to request headers, trims token edges, compares without case, and uses `, ` between additions. It cannot target the credential output header. Legacy `AddExtraHeader` still permits that collision. `remove_headers` suppresses a legacy extra header unless credential injection writes that same header.

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

## Request matching

Add `match` to any credential source to select it by request header, path, and method. Header presence, a matching path prefix, and a matching method are combined with AND. Multiple path prefixes and methods are combined with OR.

```yaml
credentials:
  - host: api.anthropic.com
    header: Authorization
    match: {header: x-api-key, paths: [/v1/messages], methods: [POST]}
    remove_headers: [x-api-key]
    add_headers:
      anthropic-beta: oauth-2025-04-20
    source:
      type: static
      value: test-token
```

Gatekeeper applies its existing exact and wildcard host precedence. Within the selected host key, it tries matched credentials in registration order. The first matching credential wins, regardless of source type. If none matches, unmatched credentials follow their existing behavior. Gatekeeper removes the selecting header unless the selected credential writes that header.

Gatekeeper applies `remove_headers` after credential injection and before `add_headers`. It preserves injected credential headers. `add_headers` therefore wins when a name appears in both lists. These transforms apply when Gatekeeper injects the credential that declares them.

Config validation rejects identical matches and a match fully covered by an earlier match. It allows partial overlap. Two unmatched `token-exchange` credentials on one host remain invalid.

## Plain HTTP

Gatekeeper does not inject credentials into plain-HTTP requests by default. If a request to an `http://` URL matches a credential, gatekeeper answers `403`, logs a warning with the host only, and does not forward the request. The same rule covers token substitution and `/relay/` targets with an `http://` URL.

To permit injection for one credential, for example toward an in-cluster service, set `allow_insecure: true` on it. See [credentials[].allow_insecure](../reference/02-config-file.md#credentialsallow_insecure). HTTPS and CONNECT-intercepted traffic is not affected, and neither are gatekeeper's own requests such as token-exchange `endpoint` calls.

## Grant names

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

## Prefix and format

For `Authorization` headers, the behavior depends on configuration:

- **No prefix, no format.** Gatekeeper auto-detects the scheme from known token prefixes. GitHub `ghp_` and `ghs_` tokens get `token` scheme. GitHub `gho_` and `github_pat_` tokens get `Bearer`. Everything else defaults to `Bearer`.
- **Explicit prefix.** The `prefix` value is prepended with a space: `prefix: "token"` produces `token sk-xxxx`.
- **Basic format.** Set `format: basic` to produce HTTP Basic authentication. The `prefix` field becomes the username: `Basic base64(prefix:value)`.
- **Raw format.** Set `format: raw` to inject the value exactly as resolved, with no prefix or scheme detection. Do not set `prefix` with this format. This supports APIs such as Cloudflare Access, which requires the JSON service-token object as the complete `Authorization` value.

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

```yaml
credentials:
  # Cloudflare Access service token, injected verbatim
  - host: api.example.com
    format: raw
    source:
      type: env
      var: CLOUDFLARE_ACCESS_AUTHORIZATION
```

## Multiple credentials per host

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

## Credential stripping

Gatekeeper removes `Proxy-Authorization` and `Proxy-Connection` headers from all forwarded requests. These are hop-by-hop headers used between the client and the proxy — they must never reach the upstream server. Injected credential headers (like `Authorization`) are also redacted in log output to prevent credential leakage.
