---
title: "Introduction"
description: "Overview of Gatekeeper, a standalone credential-injecting TLS-intercepting proxy that transparently injects authentication headers into HTTPS requests."
keywords: ["gatekeeper", "proxy", "credential injection", "TLS interception"]
---

# Introduction

Gatekeeper is a standalone credential-injecting TLS-intercepting proxy. It sits between HTTP clients and upstream servers, transparently injecting authentication headers into proxied HTTPS requests based on hostname matching. Clients route traffic through the proxy and never handle raw credentials directly.

## Key capabilities

- **Credential injection** — Resolve credentials from environment variables, static values, AWS Secrets Manager, GCP Secret Manager, or GitHub App tokens, then inject them as HTTP headers for matching hosts.
- **TLS interception** — Man-in-the-middle proxy with per-host certificate generation from a configured CA. The proxy terminates TLS, reads plaintext requests, injects credentials, and forwards to the real server.
- **Multiple credential sources** — Pluggable backend system. Environment variables and static values for development. AWS Secrets Manager, GCP Secret Manager, and GitHub App tokens for production. RFC 8693 token exchange for multi-user deployments.
- **Network policy** — Allow or deny traffic by host pattern. `permissive` mode allows all traffic. `strict` mode denies all traffic except explicitly allowed hosts.
- **MCP relay** — Forward Model Context Protocol requests to upstream servers with credential injection and SSE streaming.
- **Observability** — OpenTelemetry traces, metrics, and logs. Canonical log lines per request. Configured entirely via standard `OTEL_*` environment variables.

## How it works

Gatekeeper operates as an HTTP CONNECT proxy. The credential injection flow has five steps:

1. Client sends `CONNECT host:443` through the proxy (typically via the `HTTP_PROXY` environment variable).
2. Proxy establishes TLS with the client using a dynamically-generated certificate for that host, signed by the configured CA.
3. Proxy reads the plaintext HTTP request from the client.
4. If a credential matches the request host, the proxy injects the configured header (default: `Authorization`).
5. Proxy forwards the request to the real server over a separate TLS connection and streams the response back to the client.

The client must trust the proxy's CA certificate. Generate one with the included `examples/gen-ca.sh` script or provide an existing CA.

## Credential source types

| Source | Type value | Use case |
|---|---|---|
| Environment variable | `env` | Local development, CI |
| Static value | `static` | Fixed API keys |
| AWS Secrets Manager | `aws-secretsmanager` | AWS-hosted credentials |
| GCP Secret Manager | `gcp-secretmanager` | GCP-hosted credentials |
| GCP service account | `gcp-service-account` | Short-lived GCP access tokens with auto-refresh |
| GitHub App | `github-app` | Short-lived installation tokens with auto-refresh |
| Token exchange | `token-exchange` | Multi-user OAuth via RFC 8693 STS |

## Relationship to Moat

Gatekeeper is a general-purpose proxy with no knowledge of Moat. It was extracted from Moat's internal proxy package into a standalone Go module (`github.com/majorcontext/gatekeeper`).

Moat imports Gatekeeper as a library dependency and adds a daemon layer on top: per-run registration, token-scoped credential contexts, and Unix socket management. Gatekeeper handles the proxy mechanics. Moat handles the multi-tenant orchestration.
