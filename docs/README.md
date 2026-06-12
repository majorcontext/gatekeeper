# Gatekeeper Documentation

## Contents

### Getting Started

- [Introduction](./content/getting-started/01-introduction.md) — What Gatekeeper does, key capabilities, the CONNECT flow
- [Installation](./content/getting-started/02-installation.md) — Install via go install, build from source, or Docker
- [Quick Start](./content/getting-started/03-quick-start.md) — Inject your first credential in five minutes

### Concepts

- [TLS Interception](./content/concepts/01-tls-interception.md) — Why MITM is necessary, per-host certificate generation, CA trust
- [Credential Injection](./content/concepts/02-credential-injection.md) — Host matching, header injection, grant names, prefix/format options
- [Credential Sources](./content/concepts/03-credential-sources.md) — Source interface, static vs dynamic, background refresh, deduplication
- [Network Policy](./content/concepts/04-network-policy.md) — Permissive vs strict modes, allow lists, blocked response format
- [MCP Relay](./content/concepts/05-mcp-relay.md) — MCP request proxying, SSE streaming, tool credential injection
- [Observability](./content/concepts/06-observability.md) — OTel instrumentation, canonical log lines, request ID tracking
- [Host Gateway](./content/concepts/07-host-gateway.md) — Synthetic hostname mapping, loopback equivalence, port-based access control
- [Postgres Data Plane](./content/concepts/08-postgres-data-plane.md) — Postgres wire-protocol proxying, SNI routing, run-token auth, Neon per-branch password resolution

### Guides

- [CA Setup](./content/guides/01-ca-setup.md) — Generate a CA certificate and trust it on your system
- [Environment Credentials](./content/guides/02-environment-credentials.md) — Inject credentials from environment variables
- [AWS Secrets Manager](./content/guides/03-aws-secrets-manager.md) — Fetch credentials from AWS Secrets Manager
- [GCP Secret Manager](./content/guides/04-gcp-secret-manager.md) — Fetch credentials from Google Cloud Secret Manager
- [GitHub App Tokens](./content/guides/05-github-app-tokens.md) — Auto-refreshing short-lived GitHub installation tokens
- [Token Exchange](./content/guides/06-token-exchange.md) — Per-user credential resolution via RFC 8693
- [Network Lockdown](./content/guides/07-network-lockdown.md) — Restrict proxy traffic to specific hosts
- [OpenTelemetry](./content/guides/08-opentelemetry.md) — Distributed tracing, metrics, and logs
- [Go Library](./content/guides/09-go-library.md) — Embed the proxy engine in a custom Go application
- [WebSocket Support](./content/guides/10-websockets.md) — WebSocket upgrades through TLS interception

### Reference

- [CLI](./content/reference/01-cli.md) — Command-line flags, exit codes, signals, health endpoint
- [Config File](./content/reference/02-config-file.md) — Complete gatekeeper.yaml schema reference
- [Credential Sources](./content/reference/03-credential-sources.md) — Per-source-type field reference
- [Environment Variables](./content/reference/04-environment.md) — OTEL_*, AWS, GCP, and proxy environment variables
- [LLM Policy](./content/reference/05-llm-policy.md) — Keep integration for Anthropic API response evaluation

---

## Directory Structure

```
docs/
  README.md                     # This file
  STYLE-GUIDE.md                # Writing guidelines
  content/                      # User-facing documentation
    getting-started/
    concepts/
    guides/
    reference/
```

## Frontmatter Schema

Each documentation file includes YAML frontmatter:

```yaml
---
title: "Page Title"
description: "Brief description for SEO and previews"
keywords: ["gatekeeper", "keyword1", "keyword2"]
---
```

The following are inferred from the file path:
- **slug** — From filename (e.g., `01-introduction.md` → `introduction`)
- **section** — From parent directory (e.g., `getting-started/`)
- **order** — From numeric prefix (e.g., `01-`, `02-`)
- **prev/next** — From adjacent files in the same directory

## Writing Guidelines

See [STYLE-GUIDE.md](./STYLE-GUIDE.md) for voice, tone, and formatting conventions.

Summary:
1. **Be objective** — State facts, avoid hyperbole
2. **Be respectful** — Don't disparage other tools
3. **Be factual** — Make specific, verifiable claims
4. **Be practical** — Lead with examples, explain after
5. **Test examples** — All code examples should work as written
