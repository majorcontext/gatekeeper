# OpenTelemetry Integration Design

## Overview

Add OpenTelemetry (OTel) instrumentation to gatekeeper for production operational visibility, debugging, and correlated observability across traces, metrics, and logs.

## Requirements

- **Motivation:** Production dashboards/alerting (primary), debugging request flows (secondary), clean integration surface for library consumers like moat (tertiary).
- **Backend:** OTLP to a collector (backend-agnostic).
- **Configuration:** OTel SDK standard `OTEL_*` environment variables only. No YAML config changes.
- **Signals:** Traces, metrics, and slog-to-OTel logs bridge.
- **Span granularity:** Coarse-grained. One root span per request; phases recorded as span events and attributes, not child spans.
- **Provider model:** Global OTel providers (`otel.GetTracerProvider()`, `otel.GetMeterProvider()`). Library consumers set up providers before creating the proxy; gatekeeper picks them up automatically.
- **Activation:** Always on. When no exporter is configured, the OTel SDK's no-op providers handle it with negligible overhead.

## Architecture: Callback-Based Instrumentation

Gatekeeper already uses a callback pattern for observability (`RequestLogger`, `PolicyLogger`). The OTel integration extends this pattern rather than adding OTel imports to the proxy core.

**Layers:**

1. **Handler wrapper** (`proxy/otel.go`) — Creates the root span and records request-level metrics.
2. **Callbacks** (`gatekeeper.go`) — `RequestLogger` and `PolicyLogger` implementations attach span events and record callback-level metrics.
3. **slog bridge** (`gatekeeper.go`) — Wraps the slog handler so all log records carry trace context and are exported via the LoggerProvider.
4. **Provider init** (`cmd/gatekeeper/main.go`) — Initializes TracerProvider, MeterProvider, LoggerProvider with OTLP exporters and registers them as globals.

The proxy core (`proxy/proxy.go`) gets one change: a `Ctx context.Context` field added to `RequestLogData` and `PolicyLogData` so callbacks can access the active span.

## Section 1: OTel Provider Initialization

In `cmd/gatekeeper/main.go`, before `gatekeeper.New()`:

- **TracerProvider** — OTLP HTTP exporter, configured via `OTEL_*` env vars. Parent-based always-on sampler (overridable via `OTEL_TRACES_SAMPLER`).
- **MeterProvider** — OTLP HTTP exporter, periodic reader (default 30s, overridable via `OTEL_METRIC_EXPORT_INTERVAL`).
- **LoggerProvider** — OTLP HTTP exporter for the slog bridge.
- All three registered as globals via `otel.SetTracerProvider()`, `otel.SetMeterProvider()`, `global.SetLoggerProvider()`.
- **Shutdown** — `shutdownOTel(ctx)` deferred in `main()`, calls `Shutdown()` on all three providers.
- **Resource** — `service.name=gatekeeper` as fallback (overridable via `OTEL_SERVICE_NAME`).

**Library consumers (moat):** Set up their own providers before creating the proxy. Gatekeeper uses globals, so it inherits whatever the consumer configured.

## Section 2: Traces

### Root span via handler wrapper

A new file `proxy/otel.go` provides:

```go
func OTelHandler(next http.Handler) http.Handler
```

Wraps the proxy handler. Per request:

1. Starts a single span named by request type: `"proxy.request"` (CONNECT), `"proxy.http"` (plain HTTP), `"proxy.relay"` (relay), `"proxy.mcp"` (MCP).
2. Sets standard attributes: `http.request.method`, `url.full` (credential values redacted), `server.address`, `http.response.status_code`.
3. Stores the span in request context for callbacks.
4. On completion, sets span status (OK/Error) and ends the span.

### Span events via callbacks

- **RequestLogger** — Adds `"request.complete"` event with attributes: `duration_ms`, `credential_injected` (bool), `injected_headers` (header names only, not values), `run_id`. Errors recorded via `span.RecordError()`.
- **PolicyLogger** — Adds `"policy.denial"` event with attributes: `scope`, `operation`, `rule`, `message`.

### Context bridging

Add `Ctx context.Context` to `RequestLogData` and `PolicyLogData`. The proxy already has request context at both `logRequest` and `logPolicy` call sites. Callbacks extract the span via `trace.SpanFromContext(data.Ctx)`.

### What is not a span

TLS cert generation, individual credential lookups, header manipulation, Keep engine evaluation. These stay uninstrumented. Targeted span events can be added later if debugging needs grow.

## Section 3: Metrics

All instruments defined in `proxy/otel.go`, created from `otel.GetMeterProvider().Meter("gatekeeper")`. The instruments are exported (package-level vars or an accessor struct) so that `gatekeeper.go` can record callback-level metrics. The handler wrapper records request-level metrics directly.

### Request metrics (handler wrapper)

| Metric | Type | Attributes |
|---|---|---|
| `proxy.request.duration` | Histogram (ms) | `http.request.method`, `server.address`, `http.response.status_code`, `proxy.request.type` |
| `proxy.request.count` | Counter | Same as duration |

### Credential metrics (RequestLogger callback)

| Metric | Type | Attributes |
|---|---|---|
| `proxy.credential.injections` | Counter | `server.address`, `proxy.credential.header` |

### Policy metrics (PolicyLogger callback)

| Metric | Type | Attributes |
|---|---|---|
| `proxy.policy.denials` | Counter | `proxy.policy.scope`, `proxy.policy.rule` |

### Cardinality decisions

- No per-credential-grant cardinality (grant names could proliferate).
- No request/response body size histograms (add later if needed).
- No TLS cert generation metrics (fast and cached).
- Attribute naming follows OTel semantic conventions where applicable, `proxy.*` namespace for gatekeeper-specific attributes.

## Section 4: slog-to-OTel Logs Bridge

**Integration point:** `configureLogging` in `gatekeeper.go`.

Current flow:
1. Create base `slog.Handler` (text or JSON, with level filter).
2. Set as default.

New flow:
1. Create base handler as today.
2. Wrap: `bridged := otelslog.NewHandler("gatekeeper", otelslog.WithHandler(baseHandler))`.
3. Set default: `slog.SetDefault(slog.New(bridged))`.

Every `slog.*` call throughout gatekeeper automatically gets trace correlation. Logs emitted within a span carry that span's trace ID, enabling log-to-trace navigation in backends like Grafana.

**Library consumers:** Moat configures its own slog default. Standalone `configureLogging` is only called by `cmd/gatekeeper/main.go`, so moat's logging is unaffected.

**No exporter configured:** LoggerProvider defaults to no-op; bridge adds negligible overhead, logs flow to base handler as normal.

## Section 5: File Changes

### New file

- **`proxy/otel.go`** — `OTelHandler` wrapper, metric instrument definitions, tracer/meter initialization from globals.

### Modified files

- **`cmd/gatekeeper/main.go`** — Initialize TracerProvider, MeterProvider, LoggerProvider with OTLP exporters. Register as globals. Defer `shutdownOTel()`. Set resource with `service.name=gatekeeper` fallback.
- **`gatekeeper.go`** — `configureLogging` wraps slog handler with `otelslog.NewHandler`. Standalone server wraps handler chain: `healthHandler` -> `OTelHandler` -> `proxy`. RequestLogger and PolicyLogger callbacks extract span from context, attach events, record metrics.
- **`proxy/proxy.go`** — Add `Ctx context.Context` to `RequestLogData` and `PolicyLogData`. Pass request context at existing `logRequest` and `logPolicy` call sites.

### New dependencies (go.mod)

```
go.opentelemetry.io/otel
go.opentelemetry.io/otel/sdk
go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp
go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp
go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp
go.opentelemetry.io/contrib/bridges/otelslog
```

### Not changed

- `config.go` — No YAML changes.
- `proxy/mcp.go`, `proxy/relay.go`, `proxy/ca.go` — No direct changes; instrumented via callbacks and handler wrapper.
- No new public interfaces or API beyond the `Ctx` field addition.

## Section 6: Testing

- **`OTelHandler` unit tests** — In-memory span exporter. Verify span attributes, events, and status for CONNECT, HTTP, relay, and MCP request types.
- **Callback tests** — Verify RequestLogger and PolicyLogger correctly attach span events when context carries an active span. Verify metrics recorded via in-memory metric reader.
- **Existing tests** — Continue to pass unchanged. The `Ctx` field is optional; nil context is safe.

## Security

- Credential values are never recorded in span attributes, events, or metrics. Only header names (e.g., `"authorization"`) appear.
- `url.full` attribute redacts query parameters that might contain tokens.
- The OTLP exporter endpoint is operator-controlled via `OTEL_EXPORTER_OTLP_ENDPOINT`. Operators are responsible for securing the collector connection.
