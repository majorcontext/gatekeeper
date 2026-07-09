# AGENTS.md

Instructions for AI coding agents working in this repository.

## Project Overview

Gatekeeper is a standalone credential-injecting TLS-intercepting proxy. It transparently injects authentication headers (tokens, API keys) into proxied HTTPS requests based on hostname matching. Clients never see raw credentials — they route traffic through the proxy, which handles credential resolution, injection, and TLS interception.

Key capabilities:

- **Credential injection** — Resolve credentials from environment variables, static values, host command output, AWS Secrets Manager, GCP Secret Manager, GCP service account keys, GitHub App keys, or RFC 8693 token exchange, then inject them as HTTP headers for matching hosts
- **Postgres data plane** — Credential-injecting Postgres proxy on a second listener: routes by TLS SNI, authenticates clients with their run token (sent as the Postgres password inside gatekeeper's TLS), and resolves per-branch Neon passwords (or a static password) on the fly so no database secret lives in the sandbox
- **TLS interception** — MITM proxy with per-host certificate generation from a configured CA
- **MCP relay** — Forward Model Context Protocol requests with credential injection and SSE streaming
- **Network policy** — Allow/deny traffic by host pattern
- **LLM policy** — Evaluate Anthropic API responses against Keep policy rules
- **Host gateway** — Route synthetic container hostnames to the actual host IP
- **OpenTelemetry** — Distributed traces, request metrics, and slog-to-OTel logs bridge; configured entirely via standard `OTEL_*` environment variables

## Architecture

```
proxy/              Core TLS-intercepting proxy engine
  proxy.go            Main proxy: CONNECT handling, TLS interception, credential injection
  ca.go              CA certificate loading and per-host cert generation
  hosts.go           Hostname matching (glob patterns, port stripping)
  mcp.go             MCP relay handler (SSE streaming, tool credential injection)
  llmpolicy.go       LLM response policy evaluation via Keep
  relay.go           HTTP relay for non-CONNECT requests
  postgres.go        Postgres data-plane listener (TLS termination, run-token auth, SCRAM upstream, message relay)
  otel.go            OpenTelemetry handler wrapper, metrics instruments, span helpers
  server.go          Proxy server lifecycle (start/stop/listen)

gatekeeper.go       Standalone server wiring (config → proxy + credential sources)
config.go           YAML config parsing (proxy, TLS, credentials, network, log)
config_credential.go  Credential source resolution (maps source config to backends)

credentialsource/   Pluggable credential backends
  source.go           Source interface (CredentialSource, RefreshingSource)
  env.go             Environment variable source
  static.go          Literal value source
  process.go         Host command (credential_process-style) source
  awssecretsmanager.go  AWS Secrets Manager source
  gcpsecretmanager.go   GCP Secret Manager source
  gcpserviceaccount.go  GCP service account OAuth2 token source
  githubapp.go       GitHub App installation token source
  tokenexchange.go   RFC 8693 token exchange source
  neon.go            Neon endpoint parsing + per-branch Postgres password resolver

cmd/gatekeeper/     CLI entry point (--config flag)

examples/           Sample config, CA generation script, and test harness
```

### Key Types

- **`proxy.Proxy`** — The core proxy. Handles HTTP CONNECT, TLS interception, credential injection, network policy, and request logging.
- **`proxy.RunContextData`** — Per-caller credential and policy context. Holds credentials, network policy, MCP servers, host gateway config, and Keep engines for a single caller.
- **`proxy.ContextResolver`** — Function type (`func(token string) (*RunContextData, bool)`) that resolves a proxy auth token to per-caller context. Standalone mode uses a single static context; moat's daemon maps each registered run to its own scoped context.
- **`proxy.PostgresServer`** — The client-facing Postgres listener. Terminates client TLS with a CA-minted cert for the SNI host, authenticates the run token sent as the Postgres password, resolves the upstream password, completes SCRAM-SHA-256 upstream, and relays pgproto3 messages in both directions.
- **`proxy.PostgresCredentialResolver`** — Interface resolving an upstream Postgres password for a (host, user, database) tuple at connection time. Implemented by `credentialsource.NeonResolver` (per-branch passwords via the Neon API, cached with TTL) and `proxy.StaticPostgresResolver` (a fixed password).
- **`gatekeeper.Server`** — Standalone server that loads config, resolves credential sources, and wires up the proxy.

### How Credential Injection Works

1. Client sends `CONNECT host:443` through the proxy (via `HTTP_PROXY` env var)
2. Proxy establishes TLS with the client using a dynamically-generated certificate for that host
3. Proxy reads the plaintext HTTP request from the client
4. `RunContextData.Credentials` is checked — if a credential matches the request host, the configured header (default: `Authorization`) is injected
5. Proxy forwards the request to the real server over a separate TLS connection
6. Response streams back to the client

### Host Gateway

The `HostGateway` field in `RunContextData` maps a synthetic hostname (used inside containers) to the host machine's IP. When `HostGatewayIP` resolves to a loopback address, the proxy also matches `localhost`/`127.0.0.1`/`::1` as equivalent — so credentials configured for the gateway hostname also apply to direct loopback connections.

### OpenTelemetry Instrumentation

OTel integration uses a callback-based architecture — the proxy core (`proxy/proxy.go`) has no OTel imports. Instrumentation is layered on externally:

- **`proxy.OTelHandler`** wraps the proxy as HTTP middleware, creating root spans and recording request duration/count metrics. Its `statusRecorder` implements `http.Hijacker` so CONNECT requests still work after hijack.
- **Request/policy loggers** (set in `gatekeeper.go`) attach span events and record credential injection/policy denial metrics via exported functions `proxy.RecordCredentialInjection` and `proxy.RecordPolicyDenial`.
- **slog bridge** — `gatekeeper.go` uses a `multiHandler` to fan out log records to both the configured slog handler and `otelslog.NewHandler`, correlating logs with trace context.
- **Provider setup** — `cmd/gatekeeper/main.go` creates OTLP HTTP exporters for traces, metrics, and logs, registering them as global providers. All configuration is via standard `OTEL_*` env vars (no YAML knobs).

## Development Commands

```bash
# Build
go build ./...

# Run tests (includes race detector)
go test -race ./...

# Run a single test
go test -race -run TestName ./proxy/

# Vet
go vet ./...

# Build the binary
go build -o gatekeeper ./cmd/gatekeeper/
```

## Testing

Always work test-first. Write the test, run it and confirm it fails, then write the implementation and confirm it passes. This holds even for small bug fixes where the fix looks obvious — a test written after the fix can pass without ever having demonstrated the bug. The failing run is the evidence that the test is testing something.

- **Confirm the test fails for the right reason.** Prefer a failure that demonstrates the defect over one that is merely a compile error. If asserting against a not-yet-existing constant would only produce `undefined: X`, pin the expected value in the test instead, so it compiles and fails on behavior. A red state of `cached TTL = 7h56m12s, want <= 1m0s` names the bug; `undefined: maxTokenTTL` does not.
- **If you wrote the fix first, back it out.** `git checkout -- <file>`, write the test, watch it fail, then re-apply.
- **When a clean red is impossible** — adding a new struct field or method makes the compile error unavoidable — mutation-check afterward: neuter the implementation (make the new method a no-op), confirm the test fails, restore. This catches tests that pass vacuously.
- **Regression tests should encode the incident.** Name the real values from the bug report in the test, so the failure output reads like the original symptom.

## Code Style

- Follow standard Go conventions and `go fmt` formatting
- Use `go vet` to catch common issues
- No `internal/` packages — this is a library module meant to be imported

## Git Commits

- Use [Conventional Commits](https://www.conventionalcommits.org/) format: `type(scope): description`
  - Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `build`, `ci`, `perf`
  - Scope is optional but encouraged (e.g., `feat(proxy): add header injection`)
- Do not include `Co-Authored-By` lines for AI agents in commit messages

## Security Considerations

This proxy handles sensitive credentials. When making changes:

- Never log credential values (tokens, keys, secrets) — log host/grant names only
- Credentials must not appear in error messages returned to clients
- The CA private key must stay in memory only — never written to temp files
- Validate that TLS interception cannot be bypassed (e.g., via malformed CONNECT requests)
- Host matching must be exact or use explicit glob patterns — no accidental wildcard leaks
- Auth token comparison must be constant-time to prevent timing attacks

## Relationship to Moat

This module (`github.com/majorcontext/gatekeeper`) was extracted from moat's `internal/proxy/` package. Moat imports gatekeeper as a dependency and provides the daemon layer (per-run registration, token-scoped contexts, Unix socket management API). Gatekeeper has no knowledge of moat — it's a general-purpose credential-injecting proxy.

## Creating Pull Requests

- Use `gh pr create` with default flags only (no `--base`, `--head`, etc.)
- If `gh pr create` fails, report the error to the operator immediately
- Do not attempt to work around failures by adding flags or changing configuration
