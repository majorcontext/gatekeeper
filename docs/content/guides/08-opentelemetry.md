---
title: "OpenTelemetry"
description: "Configure Gatekeeper to emit traces, metrics, and logs via OpenTelemetry using standard OTEL environment variables."
keywords: ["gatekeeper", "OpenTelemetry", "tracing", "metrics", "observability"]
---

# OpenTelemetry

Gatekeeper emits traces, metrics, and logs via OpenTelemetry. Configuration uses standard `OTEL_*` environment variables -- no YAML knobs required.

## Prerequisites

- A working gatekeeper configuration
- An OpenTelemetry collector or compatible backend (Jaeger, Grafana, Honeycomb, etc.)

## Configuration

Set OTEL environment variables before starting gatekeeper:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:4318"
export OTEL_SERVICE_NAME="gatekeeper"
gatekeeper --config gatekeeper.yaml
```

For authenticated endpoints:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT="https://your-collector:4318"
export OTEL_EXPORTER_OTLP_HEADERS="Authorization=Bearer <token>"
```

Gatekeeper creates OTLP HTTP exporters for traces, metrics, and logs and registers them as global providers.

## Traces

Every proxy request creates a span. Span names reflect the request type:

| Request Type  | Span Name       |
|---------------|-----------------|
| CONNECT       | `proxy.request` |
| MCP relay     | `proxy.mcp`     |
| HTTP relay    | `proxy.relay`   |
| Plain HTTP    | `proxy.http`    |

Each span includes attributes:

- `http.request.method` — request method
- `server.address` — target host
- `proxy.request.type` — one of `connect`, `mcp`, `relay`, `http`
- `http.response.status_code` — response status (not set for hijacked CONNECT connections)

A `request.complete` event is added to each span with detailed context: `request_id`, `duration_ms`, `credential_injected`, `injected_headers`, `grants`, `denied`, and `deny_reason`.

## Metrics

Four instruments are registered under the `gatekeeper` meter:

| Metric                        | Type          | Description                  | Attributes                                           |
|-------------------------------|---------------|------------------------------|------------------------------------------------------|
| `proxy.request.duration`      | Histogram (s) | Request duration in seconds  | `http.request.method`, `server.address`, `proxy.request.type`, `http.response.status_code` |
| `proxy.request.count`         | Counter       | Total proxy requests         | Same as above                                        |
| `proxy.credential.injections` | Counter       | Credential injection count   | `server.address`, `proxy.credential.header`          |
| `proxy.policy.denials`        | Counter       | Policy denial count          | `proxy.policy.scope`, `proxy.policy.rule`            |

## Logs

Gatekeeper bridges `slog` output to OTel via `otelslog`. Structured log records are sent to both the configured slog handler (text/JSON to stderr) and the OTel log exporter. Log records carry trace context for correlation.

## Local Collector Example

Run a local OpenTelemetry Collector with Jaeger:

```bash
docker run -d --name jaeger \
  -p 4318:4318 \
  -p 16686:16686 \
  jaegertracing/all-in-one:latest
```

Start gatekeeper pointing to the local collector:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:4318"
export OTEL_SERVICE_NAME="gatekeeper"
gatekeeper --config gatekeeper.yaml
```

Make a request through the proxy, then open `http://localhost:16686` to view traces.

## Verification

After sending requests through the proxy, confirm traces and metrics are arriving at the collector. In Jaeger, search for service `gatekeeper` and look for `proxy.request` spans with `credential_injected=true` events.

## Next Steps

- [Go Library](./09-go-library.md) — embed gatekeeper in a Go application with custom instrumentation
