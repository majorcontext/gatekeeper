---
title: "Observability"
description: "How Gatekeeper produces structured logs, distributed traces, and request metrics via OpenTelemetry."
keywords: ["gatekeeper", "observability", "OpenTelemetry", "metrics", "logging"]
---

# Observability

Gatekeeper produces structured logs, distributed traces, and request metrics via OpenTelemetry. The proxy core has no direct OTel dependency — instrumentation is layered on externally through callbacks and HTTP middleware.

## Callback-Based Architecture

The `proxy` package defines two callback types for instrumentation:

- **`RequestLogger`** — called once per completed request with a `RequestLogData` struct containing method, host, path, status code, duration, injected headers, grant names, denial info, and request context.
- **`PolicyLogger`** — called on each policy denial with scope, operation, rule, and message.

The `gatekeeper` package (standalone server wiring) sets these callbacks at startup. The callbacks write canonical log lines, enrich OTel spans, and record metrics. This design keeps `proxy/proxy.go` free of OTel imports.

## OTelHandler Middleware

`proxy.OTelHandler` wraps the proxy's `http.Handler` with OpenTelemetry tracing and metrics:

```go
s.proxyServer = &http.Server{
    Handler: proxy.OTelHandler(&healthHandler{next: s.proxy}),
}
```

For each request, the handler:

1. Classifies the request type: `connect`, `mcp`, `relay`, or `http`.
2. Starts a root span with `SpanKindServer` and the span name `proxy.request`, `proxy.mcp`, `proxy.relay`, or `proxy.http`.
3. Sets span attributes: `http.request.method`, `server.address`, `proxy.request.type`.
4. Wraps the `ResponseWriter` with a `statusRecorder` that captures the HTTP status code.
5. After the handler returns, records `proxy.request.duration` (histogram) and `proxy.request.count` (counter) with method, server address, request type, and status code as attributes.

The `statusRecorder` implements `http.Hijacker` by delegating to the underlying writer. This is critical — CONNECT requests call `Hijack()` to take over the raw connection, and the OTel wrapper must not break this.

## Canonical Log Lines

Gatekeeper emits one wide structured log entry per request at completion. Each log line contains all request context in a single record:

| Field | Description |
|---|---|
| `request_id` | Unique identifier (TypeID with `req` prefix) |
| `http_method` | Request method |
| `http_host` | Target hostname |
| `http_path` | Request path |
| `http_status` | Response status code |
| `duration_ms` | Request duration in milliseconds |
| `proxy_type` | Request classification (`http`, `connect`, `mcp`, `relay`) |
| `credential_injected` | Whether any credential was injected |
| `injected_headers` | Comma-separated list of injected header names |
| `grants` | Comma-separated list of grant names used |
| `denied` | Whether the request was denied by policy |
| `deny_reason` | Denial reason (e.g., `Host not in allow list: example.com`) |
| `run_id` | Per-run identifier (daemon mode) |
| `user_id` | User ID from proxy auth username |

Log level is determined by outcome: `ERROR` for server errors or transport failures, `WARN` for policy denials or client errors, `INFO` for successful requests.

## Client IP Attribution Behind a Load Balancer

By default, `client_ip` comes from the raw TCP peer address of the proxy listener's accepted connection. That's accurate for a directly-exposed listener, but not for one that sits behind a TCP-terminating load balancer (e.g. GCP's global TCP Proxy load balancer) — every connection appears to originate from the load balancer's own front-end range (`35.191.0.0/16` for GCP), not the real client.

Setting `network.proxy_protocol: true` wraps the proxy listener with PROXY protocol v1/v2 parsing. When the load balancer prepends a PROXY header, gatekeeper uses its advertised source address as the connection's client address instead of the TCP peer, flowing through to `client_ip` on every request path, including CONNECT-intercepted inner requests. Connections opened without a header — load balancer health checks, direct probes of the port — fall back to the raw TCP peer address rather than being rejected.

Because the header is honored from any peer that can reach the listener, only enable `proxy_protocol` when the port is reachable solely through the load balancer, and never use `client_ip` for security decisions — it's a logging convenience, not an authenticated identity.

## Request ID Tracking

Every request receives a unique identifier. Gatekeeper checks for an `X-Request-Id` header from the caller. If present, it is reused. Otherwise, gatekeeper generates a TypeID with a `req` prefix (e.g., `req_01h455vb4pex5vsknk084sn02q`).

The request ID is:

- Set on the response via `X-Request-Id` header.
- Propagated to upstream servers via `X-Request-Id` on the forwarded request.
- Stored in the request context for extraction by loggers and span enrichment.
- Included in canonical log lines and OTel span events.

## slog-to-OTel Bridge

Gatekeeper uses a `multiHandler` to fan out every slog record to two destinations:

1. The configured slog handler (JSON or text, writing to stderr/stdout/file).
2. An `otelslog.NewHandler("gatekeeper")` that converts slog records to OTel log records, correlating them with the active trace context.

This ensures that all structured logs — not just request logs — appear in the OTel log pipeline with correct trace and span IDs.

## Metrics

Four metrics instruments are registered under the `gatekeeper` meter:

| Metric | Type | Description |
|---|---|---|
| `proxy.request.duration` | Float64 Histogram (seconds) | Duration of proxy requests |
| `proxy.request.count` | Int64 Counter | Total number of proxy requests |
| `proxy.credential.injections` | Int64 Counter | Credential injections by host and header |
| `proxy.policy.denials` | Int64 Counter | Policy denials by scope and rule |

## Configuration

OTel is configured entirely via standard `OTEL_*` environment variables. There are no YAML knobs for tracing, metrics, or logs. The CLI entry point (`cmd/gatekeeper/main.go`) always creates OTLP HTTP exporters for traces, metrics, and logs and registers them as global providers. When no `OTEL_EXPORTER_OTLP_ENDPOINT` is set, exporters default to `localhost:4318` — gatekeeper will attempt to connect to a local collector even with no `OTEL_*` variables configured.
