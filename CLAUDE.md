# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Gatekeeper is a standalone credential-injecting TLS-intercepting proxy. It transparently injects authentication headers (tokens, API keys) into proxied HTTPS requests based on hostname matching. Clients never see raw credentials — they route traffic through the proxy, which handles credential resolution, injection, and TLS interception.

Key capabilities:

- **Credential injection** — Resolve credentials from environment variables, static values, or AWS Secrets Manager, then inject them as HTTP headers for matching hosts
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
  otel.go            OpenTelemetry handler wrapper, metrics instruments, span helpers
  server.go          Proxy server lifecycle (start/stop/listen)

gatekeeper.go       Standalone server wiring (config → proxy + credential sources)
config.go           YAML config parsing (proxy, TLS, credentials, network, log)
config_credential.go  Credential source resolution (env, static, AWS Secrets Manager)

credentialsource/   Pluggable credential backends
  source.go           Source interface
  env.go             Environment variable source
  static.go          Literal value source
  awssecretsmanager.go  AWS Secrets Manager source

cmd/gatekeeper/     CLI entry point (--config flag)

examples/           Sample config, CA generation script, and test harness
```

### Key Types

- **`proxy.Proxy`** — The core proxy. Handles HTTP CONNECT, TLS interception, credential injection, network policy, and request logging.
- **`proxy.RunContextData`** — Per-caller credential and policy context. Holds credentials, network policy, MCP servers, host gateway config, and Keep engines for a single caller.
- **`proxy.ContextResolver`** — Function type (`func(token string) (*RunContextData, bool)`) that resolves a proxy auth token to per-caller context. Standalone mode uses a single static context; moat's daemon maps each registered run to its own scoped context.
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

Key env vars for deployment:
- `OTEL_EXPORTER_OTLP_ENDPOINT` — Collector endpoint (e.g., `https://host.betterstackdata.com`)
- `OTEL_EXPORTER_OTLP_HEADERS` — Auth headers (e.g., `Authorization=Bearer <token>`)
- `OTEL_RESOURCE_ATTRIBUTES` — Resource tags (e.g., `deployment.environment.name=production`)

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

## Code Style

- Follow standard Go conventions and `go fmt` formatting
- Use `go vet` to catch common issues
- No `internal/` packages — this is a library module meant to be imported

## Git Commits

- Use [Conventional Commits](https://www.conventionalcommits.org/) format: `type(scope): description`
  - Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `build`, `ci`, `perf`
  - Scope is optional but encouraged (e.g., `feat(proxy): add header injection`)
- Do not include `Co-Authored-By` lines for Claude in commit messages

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
