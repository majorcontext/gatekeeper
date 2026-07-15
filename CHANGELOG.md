# Changelog

Gatekeeper is a standalone credential-injecting TLS-intercepting proxy. It transparently injects authentication headers into proxied HTTPS requests based on hostname matching, with support for multiple credential backends and automatic token refresh.

Gatekeeper is pre-1.0. The configuration schema and credential source interface may change between minor versions.

## v0.17.3 — 2026-07-15

### Changed

- **Postgres data-plane failures now leave a legible server-side trail** — the client always receives the same generic `FATAL: could not authenticate to upstream database` for any failure past the run-token boundary, by design (the underlying error could echo the upstream server's identifiers), but two gaps meant the operator had no better signal server-side either. First, when the upstream (Neon) rejected a connection with a Postgres wire `ErrorResponse` — an IP-allowlist denial, `28P01 invalid_password`, or anything else — gatekeeper collapsed it to either the bare `errUpstreamAuthFailed` sentinel or `"upstream error (SQLSTATE %s)"`, discarding the upstream server's own `Message` entirely; an IP-allowlist rejection and a bad password were indistinguishable in the log, and the message text (the most useful part of any Postgres error) never appeared at all. `upstreamErrorResponse` now folds the upstream's `Severity`, `Code`, and `Message` — the upstream *server's* own error fields, never a credential — into the error text at every point gatekeeper reads an `ErrorResponse` from the upstream (`authenticateSCRAM`, `collectPostAuthFrames`), so the existing DEBUG `postgres upstream connection failed` line now carries the real reason. Authentication-failure SQLSTATEs (`28P01`, `28000`) still wrap `errUpstreamAuthFailed` via `%w`, so `connectWithRetry`'s `errors.Is` check and its invalidate-cached-password-and-retry-once behavior are unaffected — only the message the sentinel carries got richer. That log line also gained a `stage` attribute naming which of three failure boundaries the error came from — `resolve` (the credential resolver, e.g. the Neon API, failed before the proxy reached the upstream: missing project, wrong scope, API error), `upstream_auth` (the upstream server rejected the presented credential), and `upstream_connect` (a dial/TLS/SCRAM/protocol failure reaching the upstream) — so a resolution failure, an auth rejection, and a network/TLS failure are each independently filterable rather than collapsed together. Each stage is classified from a wrapped sentinel via `errors.Is` (`errResolvePassword`, `errUpstreamAuthFailed`), not a string prefix; only `errUpstreamAuthFailed` drives `connectWithRetry`'s invalidate-and-retry, so a resolver failure never needlessly invalidates a cached password. Second, a client whose run token failed to authenticate produced zero log output server-side — the `handleConn` boundary just sent `28P01` and returned; a failed connection there was invisible to any dashboard or log search. It now logs a `WARN`-level `postgres run-token authentication failed` line (visible without enabling DEBUG) naming the client address and the SNI host — never the token itself, not even a prefix. Between this and the network-policy denial (already logged at `WARN` via the policy logger), the run-token, network-policy, credential-resolution, and upstream-connect boundaries are now each independently identifiable in the logs

### Fixed

- **A portless `network.allow` pattern denied every Postgres data-plane connection under strict policy — including the shipped example** — `hostPattern.port == 0` (an unspecified pattern port) is documented and enforced by `matchesPattern` as "match only ports 80 and 443," an HTTP-scheme assumption. The Postgres data plane's policy check (`serveAuthenticated`, `proxy/postgres.go`) called that same HTTP-oriented `matchHost`/`checkNetworkPolicy` with the literal Postgres port (5432), so a pattern like `*.neon.tech` — which matches neither 80 nor 443 — could never match a live Postgres connection: every connection was denied with `FATAL: connection not allowed by network policy` (SQLSTATE 28000), regardless of how the allow list was written. This left the network-policy matcher inconsistent with the credential-resolver matcher for the identical connection: `postgresResolverFromEntries` already defaults an unspecified pattern port to 5432 when matching Postgres credential resolvers, so a host could be accepted for credential resolution and simultaneously rejected by policy. `examples/gatekeeper-postgres.yaml` and `docs/content/guides/13-postgres-neon.md` both document exactly this configuration (`policy: strict` + `allow: ["*.neon.tech"]`), so the shipped example was broken as written. Fixed by giving the Postgres data plane its own matcher, `matchHostPostgres` (`proxy/postgres.go`), and a corresponding `Proxy.checkNetworkPolicyPostgres` — both mirror the existing HTTP-facing functions exactly, but apply the same port-0-defaults-to-5432 override `postgresResolverFromEntries` already uses, so the two matchers can no longer disagree about the same connection. `matchHost`, `matchesPattern`, `checkNetworkPolicy`, and `checkNetworkPolicyForRequest` — the shared matcher and its HTTP/CONNECT callers — are untouched: a portless allow pattern still means "ports 80 and 443 only" for HTTP traffic, and an allow pattern pinned to an explicit non-5432 port still denies Postgres connections, exactly as before

## v0.17.2 — 2026-07-15

### Added

- **Eight new deployment and how-to guides** — the docs audit found the guide catalog stopped at reference material for several features with real setup friction. New task-oriented walkthroughs, each verified against code (all YAML parse-checked through `gatekeeper.LoadConfig`, Go snippets compile-checked, and the container guide exercised live against the published image): deploying behind a TCP load balancer with PROXY protocol (GCP `proxyHeader: PROXY_V1` backend config, gatekeeper-first rollout ordering, client-IP-forgery caveats); running the `ghcr.io/majorcontext/gatekeeper` container image (config/CA mounting, client wiring, and why in-container Docker healthchecks can't work on the distroless image — it has no shell); the Postgres data plane with Neon end-to-end (account- vs project-scoped API keys, the libpq `host=`/`hostaddr=` split for local testing without DNS); host command credentials with worked 1Password and `pass` examples; GCP service account tokens (including the precise key-rotation semantics: only the Google token endpoint rejecting a JWT drops the cached key, and only in Secret Manager mode — a downstream 401 rides out the TTL); MCP relay setup (honest about MCP having no `gatekeeper.yaml` surface — it's Go-library-only via `RunContextData`); the full credential lifecycle (startup fetch, 75%-of-TTL refresh whose backoff jitter applies after the 60s cap so waits can reach ~75s, token-exchange's 1-minute cache, 401/403 eviction); and the three Keep policy scopes (`http`, `mcp-<server>`, `llm-gateway`), including that `mcp-*` denials set no `X-Moat-Blocked` header unlike the other two scopes

### Changed

- **Docs corpus now complies with its own style guide** — a compliance sweep nobody had run found `concepts/` and `guides/` used Title Case headings throughout while `getting-started/` and `reference/` were sentence case per `docs/STYLE-GUIDE.md`; 106 headings across 18 files converted, plus scattered terminology and abbreviation-order fixes. Systemic gaps flagged for a policy call rather than fixed: first-use abbreviation expansion is ignored corpus-wide, guide files use `--` where the rest of the corpus uses em dashes (new guides written to the em-dash convention), and frontmatter title casing is uncodified

### Fixed

- **Gatekeeper's own OTel diagnostics no longer feed back into the failing OTel log-export pipeline** — `configureLogging` fans every slog record out to `otelslog.NewHandler("gatekeeper")` unconditionally: the bridge's `Enabled` defers entirely to the OTel logger, not the console handler's configured level, so nothing before v0.17.0's DEBUG demotion (and nothing since) kept the bridge from seeing a record just because it was noisy. That meant `logOTelError` ([#47](https://github.com/majorcontext/gatekeeper/pull/47))'s own DEBUG record on a failed export was itself enqueued right back into the OTel log-export pipeline that had just failed: failed export → DEBUG diagnostic → diagnostic fanned out to the bridge → re-enqueued for the next export → that export fails too, now carrying the diagnostic → another diagnostic logged → re-enqueued again, and so on for as long as the collector stays unreachable. Bounded — one record per export attempt, and the batch queue drops on overflow rather than growing without limit — but a genuine feedback loop, not merely repeated independent failures. `gatekeeper.OTelDiagnosticKey` is a new exported marker attribute; `logOTelError` tags its DEBUG record with it, and `configureLogging`'s otelslog bridge handler is now wrapped in a filter that drops any record carrying the marker before forwarding — the console/file handler is unaffected and still logs every record, marked or not, at its configured level. Diagnostics about the OTel pipeline itself are now visible locally but never re-enter the pipeline they're reporting on ([#48](https://github.com/majorcontext/gatekeeper/issues/48))

## v0.17.1 — 2026-07-15

### Fixed

- **Getting-started docs no longer fail as written; reference docs catch up to shipped behavior** — a docs-correctness audit reproduced two getting-started failures live against a built binary. Quick start's `cd examples && ./gen-ca.sh` step left the working directory inside `examples/`, so the following step's `ca_cert: examples/ca.crt` resolved to the nonexistent `examples/examples/ca.crt`; the guide now writes `gatekeeper.yaml` with CA paths relative to `examples/`. The installation guide's "verify" step, `gatekeeper --config /dev/null`, was documented as exiting with a config error — an empty YAML file actually unmarshals to a valid zero-value config, so the binary started and blocked forever instead of exiting; the verify step now uses a command that actually exits. `examples/gen-ca.sh` itself is rewritten to use an explicit OpenSSL config file instead of `-addext`, since Homebrew OpenSSL 1.1.1 folded a duplicate `basicConstraints` extension onto the certificate (Go rejected the result with `x509: certificate contains duplicate extension with OID "2.5.29.19"`) and macOS LibreSSL 3.3.6 emitted EC parameters Go's `x509.ParseCertificate` rejected with `x509: invalid ECDSA parameters` — both toolchains now produce a certificate Go accepts. Reference and concept docs are corrected to match code: LLM-policy denials return HTTP 400, not 200; a credential's `grant: claude` gets tie-break treatment during header injection (auto-injection prefers a non-`claude` grant, placeholder selection prefers `claude`) rather than being purely cosmetic as documented; token-exchange cache TTL is hard-capped at 1 minute, not defaulted to 5 minutes when `expires_in` is absent; credential host matching strips the port unconditionally with no 80/443 default (that semantics belongs to network policy, a separate matcher, and the port-bearing example host in the old doc could not actually be configured as a credential key); and MCP SSE responses are streamed through a 4096-byte read loop with a flush after every chunk, not `io.Copy`. Newly documented: HTTP-scope Keep policy enforcement (403 with `X-Moat-Blocked: keep-policy`, distinct from network-policy's 407 denials), 401/403-triggered credential invalidation and its 10s per-key re-exchange cooldown, the `OTEL_SDK_DISABLED` env var, and daemon mode's token-embedded MCP relay path (`/mcp/{token}/{server-name}`)

## v0.17.0 — 2026-07-14

### Added

- **`network.proxy_protocol` recovers the real client IP behind a TCP load balancer** — when gatekeeper runs behind a TCP-terminating load balancer (e.g. GCP's global TCP Proxy LB), the load balancer terminates the client TCP connection and dials gatekeeper from its own front-end IP range (GCP: `35.191.0.0/16`), so the `client_ip` request-log attribute always showed the load balancer's hop, never the actual client, no matter how faithfully client addresses were captured elsewhere. When `network.proxy_protocol` is set to `true` (default `false`), the proxy listener is wrapped with [`github.com/pires/go-proxyproto`](https://github.com/pires/go-proxyproto) and parses a leading PROXY protocol v1/v2 header — as prepended by the load balancer — using its advertised source address as the accepted connection's remote address before `http.Server` (and therefore every request-logging path, including CONNECT-intercepted inner requests, which log from the outer tunnel-opening request's address) ever sees it. The connection policy is pinned to fail-open (`USE`, not go-proxyproto's spec-conformant `REQUIRE` default): a connection that opens with no PROXY header, or that doesn't send one within a 10s read timeout, falls back to the raw TCP peer address instead of being rejected, so load balancer health checks and direct probes of the port keep working exactly as before. Because the header is honored from any peer, a client that can reach the listener directly (bypassing the load balancer) can forge its own logged `client_ip` by prepending a PROXY header — enable this only when the port is reachable solely through the load balancer, and never use `client_ip` for security decisions. The postgres data-plane listener is unaffected; it is a separate listener and port. A connection that opens with something that looks like a PROXY header but fails to parse (a malformed v1 line, a truncated v2 binary header, and so on) is still dropped, but now logs a single DEBUG line naming the raw peer address and the parse error, rather than vanishing without a trace ([#46](https://github.com/majorcontext/gatekeeper/pull/46))

### Fixed

- **OTel export failures no longer drown the request log when no collector is reachable** — `cmd/gatekeeper` unconditionally created OTLP HTTP exporters and registered them as global providers, and never installed an OTel error handler. The OTel SDK's default handler routes SDK/export errors through the standard library `log` package, which gatekeeper's `slog.SetDefault` call rewires to the configured slog handler at INFO level (documented `log/slog` behavior) — so every failed export attempt logged an INFO line, once per batch interval, with no backoff: `{"level":"INFO","msg":"Post \"https://localhost:4318/v1/logs\": dial tcp [::1]:4318: connect: connection refused"}`. Two changes: the standard `OTEL_SDK_DISABLED=true` env var now suppresses OTel entirely (no exporters, no providers, no OTel-related log lines), and a dedicated error handler now logs export/SDK failures at DEBUG instead of the SDK default, so they're observable with debug logging on but no longer flood the default `info` level. Default behavior (no env vars set) is unchanged — exporters still target the standard OTLP endpoint and traces/metrics/logs still flow when a collector is present ([#47](https://github.com/majorcontext/gatekeeper/pull/47))

## v0.16.0 — 2026-07-13

### Added

- **Client addresses are now captured on every request path** — gatekeeper runs as a standalone service that remote clients connect to over the network, so a proxy-auth token or run ID alone doesn't tell an operator which network peer actually sent a request; nothing in the audit trail recorded it. `RequestLogData` gains a `ClientAddr` field (the listener-observed `ip:port`), populated on plain HTTP requests (`r.RemoteAddr`), intercepted CONNECT traffic (attributed to the client that opened the tunnel — not the hijacked, TLS-terminated connection carrying the individual inner requests, which has no meaningful remote address of its own), the `/relay/{name}` and `/mcp/{server}` relay paths (`r.RemoteAddr`; both previously emitted no canonical log line at all — the "relay" and "mcp" `RequestType` values existed only in the field's doc comment, unused, until this change wired up minimal completion logging for them), and postgres data-plane connections (the client `net.Conn`'s `RemoteAddr()`, since libpq speaks no HTTP). The canonical log line emits a corresponding `client_ip` attribute — the host portion of `ClientAddr` split via `net.SplitHostPort`, falling back to the raw value if it carries no port — following the same non-empty-gated style as `run_id` and `user_id` ([#45](https://github.com/majorcontext/gatekeeper/pull/45))
- **The new relay/MCP canonical log lines now carry precise stream semantics and complete policy coverage** — `Err` on a streamed `/relay/{name}` or `/mcp/{server}` log line means exactly one thing: the upstream failed while the client was still connected; a client canceling mid-stream no longer escalates the line to ERROR, and `ResponseSize` is the actual bytes delivered to the client rather than the upstream `Content-Length` (which is `-1` for a stream). An unknown-relay-name or unknown-MCP-server 404 is a client/config mistake, not a failure, and logs at WARN purely from its status code. `handleMCPRelay`'s Keep-policy block — invalid-JSON fail-closed denial, evaluation errors, policy-deny, and redaction failures — previously only recorded a policy-log entry; every exit there now also emits a canonical request log line (`Denied`, `DenyReason`) so MCP tool-call denials show up in the same audit trail as every other request. Finally, streamed responses proxied through the OTel-wrapped standalone server now actually flush per chunk: `statusRecorder` didn't implement `http.Flusher`, so the relay and MCP streaming loops' `w.(http.Flusher)` check silently failed in production and SSE responses sat buffered in `net/http` until the stream ended ([#45](https://github.com/majorcontext/gatekeeper/pull/45))

## v0.15.3 — 2026-07-13

### Fixed

- **Post-release fixes to the v0.15.2 host-key lookup** — a review of the shipped lookup surfaced four defects, all fixed here. *Request logs no longer capture resolver-consumed subject headers*: v0.15.2's plain-HTTP handler snapshotted request headers for logging before the credential resolver ran, so a subject-identity token the resolver removes (e.g. a token-exchange subject header) was written verbatim to request logs; the forwarded-request snapshot now happens after resolution, and policy-denial and resolution-failure logs — which by design run before any resolver — redact the headers a matching resolver declared at registration. *Outranked resolvers with declared side effects no longer stall requests*: when a better-matched static credential decides a request, v0.15.2 still ran the wildcard-matched resolver synchronously and discarded its result — an unrelated IdP outage added a full STS timeout to every request on the static-credential host. Resolvers registered through the new `SetCredentialResolverWithStripHeaders` declare the request headers they remove; when outranked, the proxy skips such a resolver and strips the declared headers itself (the built-in token-exchange wiring declares its `subject_header`). Resolvers registered through the unchanged `SetCredentialResolver` API keep the v0.15.2 behavior — they still run when outranked, with credentials discarded and errors non-fatal — because the proxy cannot know what request-mutating side effects an undeclared resolver has, and silently skipping one could leak the very headers it strips. *Port-pinned keys fire regardless of how the client or config spells the target*: the plain-HTTP path passed the request host with a port only when the client literally included one, and the relay path passed the target URL's host verbatim, so a `:80`/`:443`-pinned key matched only when the port was written out; both paths now make the scheme-default port explicit before lookup, and a bracketed portless IPv6 lookup host (`[::1]`) matches keys stored in canonical form (`::1`). *In-map and cross-map ranking share one specificity comparator*: verbatim beats case-fold and a port-pinned key beats a port-less one in every tier, cross-map included, so the two selection paths cannot disagree (port-pinned keys remain expressible only via embedder-built `RunContextData` maps and direct map construction — the credential setters reject `:` in hosts) ([#44](https://github.com/majorcontext/gatekeeper/pull/44))

## v0.15.2 — 2026-07-13

### Fixed

- **Wildcard credential hosts now actually match subdomains** — every host-keyed lookup resolved the request host by exact string key (with only a host:port-stripping fallback), so an entry whose `host` was a wildcard like `*.box.example.com` only ever matched a request whose host was the literal string `*.box.example.com` — it never fired for a real subdomain such as `alpha.box.example.com`. The failure was silent: registration succeeded, wildcard semantics are documented for network allow patterns (which use a separate matcher), and an operator configuring a wildcard credential host simply got no injection and no error. All host-keyed lookups now share one matcher: after the exact-key lookups miss, wildcard keys are matched against the port-stripped request host using the same suffix rule as allow patterns — `*.example.com` matches any subdomain at any depth (`api.example.com`, `a.b.example.com`) but never the apex `example.com` itself. This covers static credentials, dynamic credential resolvers, per-run `RunContextData` credentials (the moat daemon path), extra headers, remove-headers, token substitutions, and response transformers, so a wildcard host key behaves consistently across every feature that accepts one. Precedence is deterministic: an exact key beats a wildcard key, and between wildcards a longer domain part wins (a port suffix does not count toward specificity), then a port-pinned key beats a port-less one — including across maps, so a resolver registered under `*.example.com` shadows neither a static credential configured for `api.example.com` specifically nor one under `*.api.example.com`; a resolver outranked this way still runs for its request-mutating side effects (e.g. stripping subject-identity headers), its result and any error simply do not decide the injected credential. Exact matching is case-insensitive for both port-less and port-bearing keys (a mixed-case request host cannot skip its exact entry and fall through to a wildcard); within the case-insensitive tier a key matching the full `host:port` beats one matching only the bare host — the same order as the case-sensitive lookups, so request-host casing cannot flip which credential is sent — and any remaining tie between case-variant keys goes to the lexicographically smallest key rather than depending on map iteration order. Empty entries keep their historical, per-map semantics: an empty credentials entry falls through to the next tier (`len>0` gating, as before this release), while an explicit empty or nil entry in the companion maps (extra headers, remove-headers, token substitutions, response transformers) — and a nil entry planted by `SetCredentialResolver(host, nil)` — still matches and terminates the lookup, so opt-outs for a specific `host:port` keep suppressing broader keys, including wildcards. Within the case-insensitive tier and across maps, a verbatim-cased key outranks a case-fold match, so a resolver registered under a case-variant of a host cannot shadow a static credential registered under the host's exact casing. Port-pinned keys (`*.internal.example.com:8443`; the credential setters reject `:` in hosts, but such keys arise via embedder-built `RunContextData` maps and the substitution/remove-header setters, which do not validate hosts) match subdomains on exactly that port, and the CONNECT-interception and plain-HTTP paths now pass the port-bearing request target to every host-keyed lookup so those keys actually fire there. Plain-HTTP requests are also checked against network policy *before* credential resolution — matching the interception path — so a policy-denied client can no longer trigger a resolver's external side effects (e.g. token-exchange round trips against an IdP) for fabricated wildcard-matched hosts, and receives the policy denial rather than a resolver error. Motivating case: injecting a Cloudflare Access service token across dynamically-created per-host subdomains under a `*.box.<domain>` wildcard ([#43](https://github.com/majorcontext/gatekeeper/pull/43))

## v0.15.1 — 2026-07-09

### Fixed

- **A client placeholder no longer selects the wrong credential, and the canonical log line no longer over-reports grants** — `injectCredentials`' placeholder pass tested `req.Header.Get(c.Name)` *after* earlier iterations had already written that header, so when several credentials for a host shared a header name and the client sent a placeholder for it, every same-named credential passed the "client sent this" check. Three consequences: the last credential in config order silently won the wire regardless of which grant the placeholder meant to select; `Grants` recorded every same-named credential as injected, so audit logs named credentials that never left the proxy; and `Injected` (used for cache invalidation since v0.15.0) listed credentials the destination never saw. Client-sent headers are now sampled once, before any injection, and exactly one credential is chosen per header name by a tie-break that does not depend on config order. **Behavior change:** the two selection paths break the tie in opposite directions — auto-injection still prefers a non-`claude` grant, while placeholder selection now prefers `claude`, since the claude grant is Claude Code's OAuth flow and a client that explicitly sends the header is asking for exactly it. Previously a placeholder could never reliably select it ([#40](https://github.com/majorcontext/gatekeeper/issues/40))

## v0.15.0 — 2026-07-09

### Added

- **`process` credential source** — run a host command (`sh -c`) and use its stdout as the credential value; any helper that prints a credential works (OS keychain CLIs, `pass`, 1Password's `op`, AWS `credential_process` helpers). Implements `RefreshingSource`: when the output is AWS `credential_process`-format JSON (exact-case `Version`/`AccessKeyId`/`Expiration` keys, so unrelated JSON can't hijack the schedule), the credential refreshes on the embedded `Expiration`, and already-expired output fails the fetch (engaging retry backoff) instead of installing credentials that would 401; other output reports a configurable `ttl` (default 5m; gatekeeper re-fetches at the standard 75%-of-TTL schedule). Header-invalid control characters are stripped from the output, with a warning (count only, never the value) when non-whitespace control bytes were present; stderr is included (truncated) in fetch errors for diagnosability, stdout never; the command string is config-owned and must not be accepted from untrusted config by embedding operators ([#38](https://github.com/majorcontext/gatekeeper/pull/38))

### Fixed

- **Token-exchange credentials no longer serve a rotated token until its advertised expiry** — `TokenExchangeSource.Resolve` cached each exchanged token for the full `expires_in` returned by the STS, with no invalidation path. When an STS reports the remaining lifetime of the underlying credential (e.g. a GitHub user-to-server token, ~8h), a credential that was revoked, rotated, or re-authorized upstream kept being injected for the rest of that window: every request failed with a `403` from the destination, and the only remediation was restarting the process to flush the in-memory cache. Two changes bound this. First, cache TTL is now capped at 1 minute regardless of the advertised `expires_in` — a long `expires_in` only means the token *may* live that long, not that it stays valid, and `Resolve` is singleflighted so the extra exchanges coalesce. Second, a `401` or `403` from the destination now drops the cache entry for that `(subject, actor)` so the next request exchanges afresh; the failed request is **not** retried (its body is already consumed, and requests like a git push are not idempotent). Because gatekeeper sees only a status code — a GitHub `403` covers "re-authorize the app", secondary rate limits, and plain permission denials alike — evictions are rate-limited to one per key per 10 seconds, so a client looping on a failing request cannot drive one STS exchange per request. An `Invalidate` hook on `proxy.CredentialHeader` carries this signal; it is nil for credentials with no cache behind them, and only the credential actually injected into the rejected request is evicted — when several credentials for a host share a header name, the ones that lost de-duplication keep their cache entries. Note that `expires_in` values above the cap no longer reduce STS request volume ([#39](https://github.com/majorcontext/gatekeeper/pull/39))

## v0.14.1 — 2026-06-23

### Fixed

- **Streamed responses are no longer buffered during capture** — the response-body log sampler did a blocking read of up to `MaxBodySize` (8 KB) before forwarding, so any incrementally-produced text response (Server-Sent Events, `application/x-ndjson`, chunked JSON, …) had its status line and every chunk — including the keepalive pings an upstream sends during a long time-to-first-token — withheld from the client until 8 KB accumulated, or until the stream ended for responses under 8 KB. The client received nothing, tripped its first-byte timeout, and retried in a loop; most visibly on large or cache-cold LLM streaming requests (e.g. `/v1/messages`), which worked when sent directly (un-proxied). The sampler now captures text responses lazily via a non-blocking tee instead of a blocking read-ahead, so a slow or streamed response (SSE, ndjson, chunked JSON) is forwarded immediately rather than withheld. The canonical log line for a text response is now written when the body completes rather than when its headers arrive; non-text and non-streaming responses are unchanged. This does **not** apply to hosts with an `llm-gateway` Keep engine: response-policy evaluation reads the full body before forwarding, so streams on those hosts are still buffered end-to-end ([#37](https://github.com/majorcontext/gatekeeper/pull/37))

## v0.14.0 — 2026-06-23

### Added

- **HTTP/2 and gRPC support through TLS interception** — the CONNECT interception path now negotiates HTTP/2 via ALPN (`h2` advertised first, `http/1.1` as fallback); when a client negotiates h2 (e.g., a gRPC client), the inner `http.Server` handles the connection with `http2.ConfigureServer` for correct h2 framing, and the upstream transport switches to `http2.Transport` so requests are forwarded over h2 end-to-end; credential injection (arbitrary headers such as `x-modal-token-id` / `x-modal-token-secret`) works identically on h2 connections; HTTP/1.1 clients are unaffected — `http.Transport` is used unchanged when h2 is not negotiated ([#34](https://github.com/majorcontext/gatekeeper/pull/34))

## v0.13.0 — 2026-06-18

### Added

- **HTTP request body inspection in Keep policies** — http-scope Keep rules can now reference `params.body` to match on request body content (e.g. `params.body.model == 'gpt-4'`); the proxy buffers and JSON-parses the body, evaluates the rule, then restores `req.Body` so the upstream request is unchanged; zero overhead when no rule inspects the body (`RequiresBody` is false and the body is never touched); fail-closed: non-JSON content with a payload, malformed JSON, duplicate JSON keys, or bodies exceeding 10 MB are denied (403, `X-Moat-Blocked: keep-policy`); bodyless and empty requests pass through with `params.body == null` ([#33](https://github.com/majorcontext/gatekeeper/pull/33))

### Changed

- **`keep` upgraded v0.3.0 → v0.5.0** — `SafeEvaluate`, `Engine.Evaluate`, `llm.EvaluateResponse`, and `llm.EvaluateStream` now take a leading `context.Context`; all call sites in `proxy.go`, `mcp.go`, and `llmpolicy.go` updated to thread the request context through ([#33](https://github.com/majorcontext/gatekeeper/pull/33))

## v0.12.0 — 2026-06-12

### Added

- **Postgres data plane** — an optional second listener (`postgres.port`/`postgres.host`) speaks the Postgres wire protocol so a client reaches a managed database without holding its password. The client connects with the real database hostname and presents its run token as the Postgres password; gatekeeper terminates TLS with a CA-minted certificate, reads the target endpoint from TLS SNI, validates the token against the per-run context (constant-time, the same model as the HTTP plane), resolves the real upstream password, completes SCRAM-SHA-256 with the upstream, and relays protocol messages in both directions. A credential's new `postgres` block selects the resolver: `neon` mints per-branch passwords from the Neon API (the credential `source` supplies the API key; passwords are cached with a TTL and re-resolved on rotation or after expiry; set `project` for project-scoped API keys, which cannot enumerate projects) or `static` (the source supplies a fixed password, for non-Neon servers). Upstream TLS is verified with no plaintext fallback; no API key, branch password, or run token appears in logs or client-facing errors; network policy is enforced on the SNI host before any upstream dial; the listener requires a configured CA and drains active connections within the shutdown deadline. Protocol framing uses `github.com/jackc/pgx/v5/pgproto3`; upstream SCRAM uses `github.com/xdg-go/scram` ([#30](https://github.com/majorcontext/gatekeeper/pull/30))

### Changed

- **Canonical request log** — postgres connections are logged with `proxy_type=postgres`; per-message counts go in new `request_messages`/`response_messages` fields (the byte-valued `request_size`/`response_size` stay unset for postgres), `user_id` carries the Postgres role, and denied connections carry a non-zero `http_status` (403 policy/credential, 502 upstream) ([#30](https://github.com/majorcontext/gatekeeper/pull/30))

## v0.11.0 — 2026-06-10

### Added

- **GCP service account credential source** — new `gcp-service-account` source type mints short-lived OAuth2 access tokens from a service account key JSON: gatekeeper signs an RS256 JWT assertion with the key and exchanges it at the key's `token_uri` via the jwt-bearer grant; the key JSON can come from GCP Secret Manager (`secret`/`project`/`version`), a file (`private_key_path`), or an environment variable (`private_key_env`); optional `scopes` field takes a space-separated scope list and defaults to `cloud-platform`; implements `RefreshingSource`, so tokens hot-swap at 75% of their ~1-hour TTL; an assertion rejection (400/401/403) drops the cached key and re-reads it from the key source on the next refresh, picking up key rotation without a restart; `token_uri` must be https (loopback hosts excepted, for emulators) ([#27](https://github.com/majorcontext/gatekeeper/pull/27))

### Changed

- **`SourceConfig` struct** — added `Scopes` field for the GCP service account source; all other source types reject it as extraneous; the struct now documents that it must remain comparable because it keys the source-deduplication maps ([#27](https://github.com/majorcontext/gatekeeper/pull/27))
- **Shared token-source helpers** — `github-app`, `token-exchange`, and the new source now share `signRS256JWT` (RS256 JWT signing), `readTokenResponse` (bounded response read with truncated error bodies), and `readKeyMaterial` (path/env key loading) instead of maintaining per-source copies; no behavior change ([#27](https://github.com/majorcontext/gatekeeper/pull/27))

### Fixed

- **Validation gaps** — `env` and `static` sources now reject an extraneous `region` field, and `token-exchange` rejects an extraneous `scopes` field, matching the strict-validation contract of all other source types ([#27](https://github.com/majorcontext/gatekeeper/pull/27))

## v0.10.0 — 2026-05-11

### Added

- **`capture_headers` log config** — new `log.capture_headers` field captures specified request headers as structured attributes in the canonical `"request"` log entry; matched headers are stripped before forwarding upstream; header names are logged as lowercase with hyphens converted to underscores (e.g., `X-Workspace-Slug` → `x_workspace_slug`); values are truncated at 256 characters; sensitive headers (`Authorization`, `Proxy-Authorization`, `Cookie`) are rejected at startup; max 10 headers allowed
- **User ID in canonical request log** — the proxy auth username (from `HTTP_PROXY=http://user:token@host`) is now logged as `user_id` in the canonical request log entry and included in OTel span attributes

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
