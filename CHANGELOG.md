# Changelog

Gatekeeper is a standalone credential-injecting TLS-intercepting proxy. It transparently injects authentication headers into proxied HTTPS requests based on hostname matching, with support for multiple credential backends and automatic token refresh.

Gatekeeper is pre-1.0. The configuration schema and credential source interface may change between minor versions.

## v0.4.2 — 2026-04-20

### Fixed

- **`Proxy-Authenticate` header on 407 responses** — all proxy authentication failures now include `Proxy-Authenticate: Basic realm="gatekeeper"` as required by RFC 7235; fixes git/libcurl which only retries with credentials after receiving a challenge header ([#8](https://github.com/majorcontext/gatekeeper/pull/8))

## v0.4.1 — 2026-04-20

### Fixed

- **HTTP client/server timeout defaults** — added explicit timeouts to all HTTP clients and transports across the codebase; Go's `net/http` defaults to zero timeouts, which can cause goroutine hangs on unresponsive upstreams ([#7](https://github.com/majorcontext/gatekeeper/pull/7))
  - GitHub App credential source: 30s client timeout
  - MCP relay client: 10s TLS handshake, 30s response header, 90s idle connection
  - CONNECT interception transport: 10s TLS handshake, 30s response header
  - Non-CONNECT HTTP forwarding: replaced `http.DefaultTransport` with configured transport (10s TLS handshake, 30s response header, 90s idle)
  - Relay client: 10s TLS handshake
  - Library server (`proxy.Server`): 120s idle timeout

## v0.4.0 — 2026-04-20

v0.4 adds GitHub App installation tokens as a credential source with automatic background refresh. Tokens are generated from an RSA private key via RS256 JWT signing and exchanged for short-lived installation access tokens through GitHub's API. A new `RefreshingSource` interface enables any credential source to opt into background refresh — the proxy always holds a valid token without restarts.

### Added

- **GitHub App credential source** — new `github-app` source type generates short-lived GitHub App installation tokens from an RSA private key; supports both file path and environment variable for key configuration ([#5](https://github.com/majorcontext/gatekeeper/pull/5))
- **`RefreshingSource` interface** — credential sources that implement `TTL()` automatically get background refresh at 75% of TTL with exponential backoff and jitter on failure ([#5](https://github.com/majorcontext/gatekeeper/pull/5))
- **Lenient RSA key parsing** — accepts PKCS#1 keys with inconsistent CRT parameters (common with keys used in OpenSSL-based runtimes like Node.js) by falling back to N/E/D-only signing ([#5](https://github.com/majorcontext/gatekeeper/pull/5))
- **Example config** — `examples/gatekeeper-github-app.yaml` demonstrates GitHub App credential source configuration ([#5](https://github.com/majorcontext/gatekeeper/pull/5))

## v0.3.0 — 2026-04-20

### Added

- **OpenTelemetry integration** — distributed traces, request metrics, and slog-to-OTel logs bridge; configured entirely via standard `OTEL_*` environment variables with no YAML knobs ([#4](https://github.com/majorcontext/gatekeeper/pull/4))

## v0.2.0 — 2026-04-20

### Fixed

- **Host-gateway traffic handling** — sync host-gateway credential matching and loopback equivalence logic from moat ([#1](https://github.com/majorcontext/gatekeeper/pull/1))

## v0.1.0 — 2026-04-20

Initial extraction from [majorcontext/moat](https://github.com/majorcontext/moat). Includes the core TLS-intercepting proxy, credential injection (env, static, AWS Secrets Manager), network policy, MCP relay, and LLM policy evaluation.
