# WebSocket Support via ReverseProxy Refactor

**Date:** 2026-04-22
**Status:** Approved
**Scope:** `proxy/proxy.go` — `handleConnectWithInterception`

## Problem

Gatekeeper's TLS interception path manually reads HTTP requests in a loop (`http.ReadRequest` → `transport.RoundTrip` → `resp.Write`). After a WebSocket upgrade (HTTP 101 Switching Protocols), the client sends binary WebSocket frames which `http.ReadRequest` cannot parse, causing `"malformed HTTP request"` errors and connection drops.

## Solution

Replace the manual request loop in `handleConnectWithInterception` with an `http.Server` serving on the client-side TLS connection, using `httputil.ReverseProxy` as the handler. Go 1.25's `ReverseProxy` natively handles WebSocket upgrades — it detects `Upgrade` headers, preserves them through hop-by-hop removal, hijacks both sides on a `101` response, and does bidirectional `io.Copy`.

## Architecture

```
Client ←TLS→ http.Server(tlsClientConn) → ReverseProxy → upstream
```

### Flow

1. CONNECT arrives, proxy hijacks, sends `200 Connection Established` (unchanged)
2. TLS handshake with client using generated cert (unchanged)
3. **New:** Create a single-connection `http.Server` with `httputil.ReverseProxy` as handler
4. `http.Server.Serve()` manages the request loop (replaces manual `for` + `http.ReadRequest`)
5. For normal HTTP: `ReverseProxy` forwards via `Transport.RoundTrip`, credential injection in `Rewrite`
6. For WebSocket: `ReverseProxy` detects `101`, hijacks, bidirectional copy — no custom code needed

### Feature Mapping

Every feature in the current manual loop maps to a `ReverseProxy` hook:

| Feature | Current location | New location |
|---|---|---|
| Network policy check | Loop body | Wrapping handler (before ReverseProxy) |
| Keep HTTP policy | Loop body | Wrapping handler (before ReverseProxy) |
| Credential injection (`injectCredentials`) | Loop body | `Rewrite` on `ProxyRequest.Out` |
| MCP credential injection | Loop body | `Rewrite` |
| Extra headers / remove headers | Loop body | `Rewrite` |
| Token substitution | Loop body | `Rewrite` |
| Request ID generation | Loop body | `Rewrite` |
| Host gateway IP rewrite | Loop body, modifies dial target | `Rewrite` (rewrite URL host) or custom `Transport.DialContext` |
| Proxy-Authorization stripping | Loop body | `Rewrite` (read from `ProxyRequest.In` before hop-by-hop removal) |
| Credential resolver (token-exchange) | Loop body | `Rewrite` (read subject from `In.Header`, resolve, set on `Out`) |
| LLM gateway policy | Loop body, post-response | `ModifyResponse` |
| Response transformers | Loop body, post-response | `ModifyResponse` |
| Body capture for logging | Loop body | `ModifyResponse` (response) and `Rewrite` (request) |
| Canonical log line | Loop body | `ModifyResponse` + `ErrorHandler` |
| OTel span/metrics | Loop body via callbacks | Wrapping handler or `ModifyResponse` |
| Transport error → 502 | Loop body | `ErrorHandler` |
| WebSocket upgrade | **Not supported** | Built-in `ReverseProxy.handleUpgradeResponse` |

### Key Design Decisions

**Proxy-Authorization before hop-by-hop removal:** `ReverseProxy` strips hop-by-hop headers (including `Proxy-Authorization`) before calling `Rewrite`. For `subject_from: proxy-auth` token exchange, the subject identity must be extracted from `ProxyRequest.In` (which preserves original headers) rather than `ProxyRequest.Out`.

**Single-connection http.Server:** The `http.Server` serves on a `net.Listener` wrapping the single TLS connection. When the connection closes, `Serve` returns. This replaces the manual `for` loop and gets HTTP keepalive, pipelining, and protocol upgrade handling from the stdlib.

**Per-connection transport:** The `http.Transport` is created per-CONNECT connection (same as today). `ForceAttemptHTTP2` remains disabled — the intercepted connection reads HTTP/1.1.

**No behavioral changes:** All external APIs (`Proxy`, `RunContextData`, config) remain identical. This is purely an internal refactor of one function.

### Handling Policy Denials in Rewrite

The current loop writes error responses (407, 403, 502) directly to the TLS connection and continues the loop. With `ReverseProxy`, the `Rewrite` function cannot write responses directly. Two options:

**Option A — Wrapping handler:** A handler that runs policy checks before delegating to `ReverseProxy`. On denial, it writes the error response itself and does not call `ReverseProxy.ServeHTTP`. This is the cleanest approach.

**Option B — Rewrite sets a sentinel, ErrorHandler acts on it.** `Rewrite` stores a denial in the request context, `ModifyResponse` or a custom `RoundTripper` wrapper checks for it. More complex, less readable.

**Decision:** Option A. The wrapping handler pattern is idiomatic and keeps policy logic separate from forwarding logic.

```go
func (p *Proxy) interceptHandler(host string, rc *RunContextData, transport *http.Transport) http.Handler {
    rp := &httputil.ReverseProxy{
        Rewrite:        p.rewriteIntercepted(host, rc),
        Transport:      transport,
        ModifyResponse: p.modifyInterceptedResponse(host, rc),
        ErrorHandler:   p.interceptErrorHandler(host, rc),
    }
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Network policy, Keep HTTP policy checks here
        // On denial: write error response, return
        // On allow: rp.ServeHTTP(w, r)
    })
}
```

## Testing Strategy

Tests are written first (TDD) against the current code to establish behavioral baselines, then the refactor must keep them passing.

### New tests to add before refactor

1. **Normal HTTPS through interception** — credential injection verified on upstream request
2. **WebSocket upgrade through interception** — upgrade succeeds, bidirectional frame exchange works (will fail against current code, pass after refactor)
3. **Multi-request keepalive** — multiple requests over single CONNECT tunnel
4. **Network policy denial on inner request** — 407 returned, connection stays alive
5. **Transport error** — unreachable upstream, 502 returned, canonical log line emitted
6. **Credential resolver via CONNECT** — token-exchange with `subject_from: proxy-auth`
7. **Host gateway through interception** — gateway hostname rewritten to actual IP

### Existing tests that must keep passing

All tests in `proxy/proxy_test.go`, particularly:
- `TestProxy_CanonicalLogLine_ConnectTransportError`
- `TestProxy_CanonicalLogLine_ConnectBlocked`
- All credential injection, policy, and logging tests

## Implementation Plan

### Phase 1: Test baseline (TDD)
Write the new tests listed above against the current code. All should pass except the WebSocket test.

### Phase 2: Extract helpers
Extract the inline policy/credential/logging logic from the current loop into named methods that can be called from both the old loop and the new handler. This is a refactor-only step — no behavioral changes.

### Phase 3: Build the ReverseProxy handler
Implement `interceptHandler` with `Rewrite`, `ModifyResponse`, `ErrorHandler`, and the wrapping handler for policy checks. Wire it into `handleConnectWithInterception` replacing the manual loop.

### Phase 4: WebSocket test passes
The WebSocket upgrade test should now pass with zero additional code.

### Phase 5: Verify and clean up
Run full test suite, remove dead code from the old loop, verify OTel instrumentation.

## Out of Scope

- Changing the non-interception tunnel path (`handleConnectTunnel`)
- Changing the HTTP relay path (`handleHTTP`)
- Changing the MCP relay handler
- Config schema changes
- New config options for WebSocket-specific behavior
