# Changelog

Gatekeeper is a standalone credential-injecting TLS-intercepting proxy. It transparently injects authentication headers into proxied HTTPS requests based on hostname matching, with support for multiple credential backends and automatic token refresh.

Gatekeeper is pre-1.0. The configuration schema and credential source interface may change between minor versions.

## v0.9.1 — 2026-04-26

### Fixed

- **Increased response header timeout from 30s to 5m** — LLM inference (especially extended thinking models like Claude 3.7 Sonnet) can take well over 30 seconds before the first response byte; the previous 30s `ResponseHeaderTimeout` caused read timeouts on slow-to-start completions; the new 5-minute default covers extended thinking while still catching genuinely dead connections; applies to all transport paths (CONNECT interception, HTTP relay, MCP relay)

## v0.9.0 — 2026-04-22

### Added

- **WebSocket support through TLS interception** — WebSocket upgrades (101 Switching Protocols) now work through CONNECT+TLS intercepted connections; credentials are injected on the upgrade request, then the proxy switches to bidirectional byte tunneling for WebSocket frames ([#22](https://github.com/majorcontext/gatekeeper/pull/22))

### Changed

- **Refactored `handleConnectWithInterception`** — replaced the manual `http.ReadRequest` → `transport.RoundTrip` → `resp.Write` loop with `httputil.ReverseProxy` served via a single-connection `http.Server`; all existing behaviors (credential injection, network/Keep policy, LLM gateway policy, response transformers, canonical logging) are preserved through `Rewrite`, `ModifyResponse`, and `ErrorHandler` hooks ([#22](https://github.com/majorcontext/gatekeeper/pull/22))
- **Extracted `evaluateAndReplaceLLMResponse`** — LLM gateway policy evaluation logic moved from inline in the request loop to a standalone method for readability ([#22](https://github.com/majorcontext/gatekeeper/pull/22))

## v0.8.0 — 2026-04-22

### Added

- **GCP Secret Manager credential source** — new `gcp-secretmanager` source type fetches secrets from Google Cloud Secret Manager; requires `project` and `secret` fields; optional `version` field defaults to `"latest"`; authenticates via Application Default Credentials (ADC); uses the same testability pattern as the AWS source (interface-based client for mock injection) ([#20](https://github.com/majorcontext/gatekeeper/pull/20))

### Changed

- **`SourceConfig` struct** — added `Project` and `Version` fields for the GCP Secret Manager source; all existing source types reject these as extraneous fields ([#20](https://github.com/majorcontext/gatekeeper/pull/20))

## v0.7.0 — 2026-04-22

v0.7 improves cross-service observability and eliminates redundant credential fetches.

### Added

- **X-Request-Id forwarding to STS** — the `TokenExchangeSource` now accepts a `requestID` parameter on `Exchange` and `Resolve`; when non-empty, it is forwarded as `X-Request-Id` to the STS endpoint, enabling end-to-end request correlation across proxy → STS → upstream ([#17](https://github.com/majorcontext/gatekeeper/pull/17))
- **X-Request-Id forwarding in MCP relay** — MCP relay requests now include the proxy-generated `X-Request-Id` header when the upstream request doesn't already carry one, correlating relay traffic with the originating proxy request ([#17](https://github.com/majorcontext/gatekeeper/pull/17))

### Changed

- **`TokenExchangeSource.Exchange` signature** — added `requestID string` parameter; callers must pass `""` when no request ID is available ([#17](https://github.com/majorcontext/gatekeeper/pull/17))
- **`TokenExchangeSource.Resolve` signature** — added `requestID string` parameter; the winning singleflight goroutine's request ID is forwarded to the STS call ([#17](https://github.com/majorcontext/gatekeeper/pull/17))

### Fixed

- **Deduplicated credential sources sharing the same config** — when multiple credential entries share the same `SourceConfig` (e.g., `api.github.com` and `github.com` both using the same `github-app`), a single fetch is now made at startup and a single background refresh goroutine is registered; the token is applied to all hosts that share the source; deduplication is generic across all source types via the comparable `SourceConfig` struct ([#18](https://github.com/majorcontext/gatekeeper/pull/18))
- **`refreshInterval` simplified** — replaced manual min-floor with `max()` builtin ([#18](https://github.com/majorcontext/gatekeeper/pull/18))

## v0.6.1 — 2026-04-21

### Added

- **Build version in startup log and OTel resource** — `cmd/gatekeeper` now has a `version` variable set via `-ldflags -X main.version=<tag>` at build time (defaults to `"dev"`); the version appears in the `"gatekeeper listening"` startup log line and as `service.version` on all OTel spans, metrics, and logs ([#15](https://github.com/majorcontext/gatekeeper/pull/15))
- **`VERSION` Docker build arg** — the Dockerfile accepts a `VERSION` build arg passed through to `-ldflags`; the release workflow passes the git tag automatically ([#15](https://github.com/majorcontext/gatekeeper/pull/15))

### Changed

- **`gatekeeper.New()` signature** — added `version string` parameter; callers must pass the build version (or `""` if unknown); this replaces the previously exported `Server.Version` field to prevent data races on concurrent access ([#15](https://github.com/majorcontext/gatekeeper/pull/15))

## v0.6.0 — 2026-04-21

v0.6 adds canonical log lines and request ID tracking. Every proxied request now emits a single wide structured log entry at completion with all context (method, host, path, status, duration, credential injection, policy decisions, sizes) and a unique K-sortable request ID.

### Added

- **Canonical log lines** — one wide structured `slog` entry per request at completion containing `http_method`, `http_host`, `http_path`, `http_status`, `duration_ms`, `proxy_type`, `credential_injected`, `injected_headers`, `grants`, `denied`, `deny_reason`, `request_size`, `response_size`, and `error`; dynamic log levels (ERROR for 5xx/transport, WARN for denials/4xx, INFO otherwise) ([#14](https://github.com/majorcontext/gatekeeper/pull/14))
- **Request ID tracking** — every request gets a unique `req_`-prefixed [TypeID](https://github.com/jetify-com/typeid) (UUIDv7-based, K-sortable); extracted from the caller's `X-Request-Id` header if present, otherwise generated; stored in request context, logged in canonical log lines as `request_id`, attached to OTel spans, and echoed back in the `X-Request-Id` response header ([#14](https://github.com/majorcontext/gatekeeper/pull/14))
- **`RequestIDFromContext` exported function** — extract the request ID from a `context.Context` for downstream consumers (e.g., moat's daemon layer) ([#14](https://github.com/majorcontext/gatekeeper/pull/14))

### Changed

- **`RequestLogData` struct-based API** — `logRequest` refactored from 11 positional parameters to a `RequestLogData` struct; new fields: `RequestID`, `Host`, `Path`, `RequestType`, `RequestSize`, `ResponseSize`, `Grants`, `Denied`, `DenyReason` ([#14](https://github.com/majorcontext/gatekeeper/pull/14))
- **`injectCredentials` returns `credentialInjectionResult`** — new return type bundles `InjectedHeaders` and `Grants` (grant names) together, replacing the bare `map[string]bool` return ([#14](https://github.com/majorcontext/gatekeeper/pull/14))
- **OTel span enrichment** — `request.complete` span events now include `request_id`, `grants`, `denied`, `deny_reason`, and `proxy.request.type` attributes ([#14](https://github.com/majorcontext/gatekeeper/pull/14))
- **Deterministic field ordering** — `grants` and `injected_headers` are sorted before logging and OTel emission, making grep-based queries stable regardless of map iteration order ([#14](https://github.com/majorcontext/gatekeeper/pull/14))

## v0.5.2 — 2026-04-21

### Added

- **`actor_token_from: proxy-auth-password`** — new token-exchange config option forwards the proxy auth password as the RFC 8693 `actor_token` parameter to the STS, enabling server-side validation that the caller owns the claimed subject identity; requires `subject_from: proxy-auth`; gatekeeper rejects requests without a password when this option is configured ([#13](https://github.com/majorcontext/gatekeeper/pull/13))
- **`actor_token_type` config field** — configurable actor token type URI for token-exchange sources; defaults to `urn:ietf:params:oauth:token-type:access_token`; set to `urn:ietf:params:oauth:token-type:jwt` or other RFC 8693 type URIs if the STS requires it ([#13](https://github.com/majorcontext/gatekeeper/pull/13))

### Changed

- **Delegated auth when `actor_token_from` is configured** — when any credential uses `actor_token_from`, the proxy skips its static `auth_token` check, delegating caller authentication to the STS; enables per-user proxy passwords where each user's API key is forwarded as the actor token and validated server-side ([#13](https://github.com/majorcontext/gatekeeper/pull/13))
- **`TokenExchangeSource.Exchange` signature** — changed from variadic `Exchange(ctx, subject, opts ...ExchangeOptions)` to explicit `Exchange(ctx, subject, actorToken string)` for consistency with `Resolve`; `ExchangeOptions` type removed ([#13](https://github.com/majorcontext/gatekeeper/pull/13))
- **`TokenExchangeSource.Resolve` signature** — added `actorToken string` parameter; callers must pass `""` when no actor token is needed ([#13](https://github.com/majorcontext/gatekeeper/pull/13))

## v0.5.1 — 2026-04-21

### Changed

- **Resolver-to-static credential fallback** — when a `CredentialResolver` (e.g., `token-exchange`) and a static credential (e.g., `github-app`) are both registered for the same host, the resolver runs first; if it returns no credentials (no subject identity found), the static credential is used as a fallback; enables the pattern "per-user OAuth via token-exchange, with a bot identity fallback" ([#12](https://github.com/majorcontext/gatekeeper/pull/12))

## v0.5.0 — 2026-04-21

v0.5 adds RFC 8693 OAuth 2.0 Token Exchange as a credential source. Multiple callers with different user identities can route requests through a single shared gatekeeper instance — each receives user-scoped credentials resolved dynamically via an external Security Token Service (STS).

### Added

- **`token-exchange` credential source** — new source type implements RFC 8693 token exchange; gatekeeper extracts a subject identity from either a configurable request header (`subject_header`) or the proxy authentication username (`subject_from: proxy-auth`), calls an external STS to exchange it for an access token, and injects the token upstream ([#11](https://github.com/majorcontext/gatekeeper/pull/11))
- **`subject_from: proxy-auth`** — extract subject identity from the `Proxy-Authorization` Basic auth username (`HTTP_PROXY=http://alice%40example.com:<token>@host:port`), enabling token exchange for clients that can only configure `HTTP_PROXY` and cannot set custom request headers ([#11](https://github.com/majorcontext/gatekeeper/pull/11))
- **`CredentialResolver` function type** — per-request dynamic credential resolution in the proxy core; resolvers receive both the proxy-level request (with `Proxy-Authorization`) and the inner application request, enabling identity extraction from either layer ([#11](https://github.com/majorcontext/gatekeeper/pull/11))
- **Per-subject token caching** — exchanged tokens are cached by subject with TTL from the STS `expires_in` response (default 5 minutes); concurrent cache misses for the same subject are coalesced via `singleflight` ([#11](https://github.com/majorcontext/gatekeeper/pull/11))
- **`format: basic` on token-exchange credentials** — the `format`/`prefix` fields now work on token-exchange sources; exchanged tokens are encoded as `Authorization: Basic base64(prefix:token)` for endpoints that require HTTP Basic auth (e.g., `github.com` git smart HTTP with `x-access-token` as the username) ([#11](https://github.com/majorcontext/gatekeeper/pull/11))
- **STS endpoint implementer guide** — `docs/token-exchange-endpoint.md` documents the exact wire format, authentication, caching semantics, and error handling contract for building compatible STS endpoints ([#11](https://github.com/majorcontext/gatekeeper/pull/11))

## v0.4.4 — 2026-04-20

### Added

- **`format: basic` credential option** — new `format` field on credential config supports HTTP Basic authentication encoding; when set to `"basic"`, the `prefix` field becomes the Basic auth username and the credential value becomes the password (`Authorization: Basic base64(prefix:value)`); required for `github.com` git smart HTTP which accepts `x-access-token` as the username ([#10](https://github.com/majorcontext/gatekeeper/pull/10))

## v0.4.3 — 2026-04-20

### Changed

- **Docker multi-arch build uses cross-compilation** — pin builder stage to native platform and use Go's `GOOS`/`GOARCH` instead of QEMU emulation; reduces release build time from ~14 minutes to ~2-3 minutes ([#9](https://github.com/majorcontext/gatekeeper/pull/9))

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
