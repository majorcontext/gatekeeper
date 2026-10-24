---
title: "Observability"
description: "How Gatekeeper produces structured logs, distributed traces, and request metrics via OpenTelemetry."
keywords: ["gatekeeper", "observability", "OpenTelemetry", "metrics", "logging"]
---

# Observability

Gatekeeper produces structured logs, distributed traces, and request metrics via OpenTelemetry. The proxy core has no direct OTel dependency — instrumentation is layered on externally through callbacks and HTTP middleware.

## Callback-based architecture

The `proxy` package exposes two callbacks for instrumentation:

- **`SetLogger` callback** — called once per completed request with a `RequestLogData` struct containing method, host, path, status code, duration, injected headers, grant names, denial info, and request context.
- **`SetPolicyLogger` callback** — called on each policy denial with scope, operation, rule, and message.

The `gatekeeper` package (standalone server wiring) sets these callbacks at startup. The callbacks write canonical log lines, enrich OTel spans, and record metrics. This design keeps every non-test `proxy/` file except `otel.go` free of OTel imports.

## OTelHandler middleware

`proxy.NewOTelHandler` wraps the proxy's `http.Handler` with OpenTelemetry tracing and metrics:

```go
s.proxyServer = &http.Server{
    Handler: otelHandler, // proxy.NewOTelHandler(&healthHandler{next: s.proxy}, proxy.OTelOptions{})
}
```

`OTelOptions` takes optional tracer and meter providers that default to the global ones. If an instrument cannot be created, the handler still works with it disabled and the call returns an error.

For each request, the handler:

1. Classifies the request type: `connect`, `mcp`, `relay`, or `http`.
2. Starts a root span with `SpanKindServer` and the span name `proxy.request`, `proxy.mcp`, `proxy.relay`, or `proxy.http`.
3. Sets span attributes: `http.request.method`, `server.address`, `proxy.request.type`.
4. Wraps the `ResponseWriter` with a `statusRecorder` that captures the HTTP status code.
5. After the handler returns, records `proxy.request.duration` (histogram) and `proxy.request.count` (counter) with method, server address, request type, and status code as attributes.

The `statusRecorder` implements `http.Hijacker` by delegating to the underlying writer. This is critical — CONNECT requests call `Hijack()` to take over the raw connection, and the OTel wrapper must not break this.

`NewOTelHandler` wraps only the HTTP proxy listener. The Postgres data-plane listener (see [Postgres Data Plane](./08-postgres-data-plane.md)) is a separate `net.Listener` that this middleware never sees, so it produces no `proxy.request`-family spans or `proxy.request.duration`/`proxy.request.count` metrics — `postgres` connections are observable only through the canonical log line below.

## Canonical log lines

Gatekeeper emits one wide structured log entry per request at completion. Each log line contains all request context in a single record:

| Field | Description |
|---|---|
| `request_id` | Unique identifier (TypeID with `req` prefix) |
| `http_method` | Request method |
| `http_host` | Target hostname |
| `http_path` | Request path |
| `http_status` | Response status code |
| `duration_ms` | Request duration in milliseconds |
| `proxy_type` | Request classification (`http`, `connect`, `mcp`, `relay`, `postgres`) |
| `credential_injected` | Whether any credential was injected |
| `injected_headers` | Comma-separated list of injected header names |
| `grants` | Comma-separated list of grant names used |
| `denied` | Whether the request was denied by policy |
| `deny_reason` | Denial reason (e.g., `Host not in allow list: example.com`) |
| `request_size` | Content-Length of the request body, when known. Omitted (not zero) when unknown — always omitted for postgres connections, which report size in `request_messages` instead. |
| `response_size` | Bytes delivered to the client (streaming paths) or response Content-Length, when known. Omitted when unknown — always omitted for postgres connections. |
| `request_messages` | Postgres protocol messages relayed client→upstream. Present only for postgres connections. |
| `response_messages` | Postgres protocol messages relayed upstream→client. Present only for postgres connections. |
| `error` | Error message, when the request ended in an error |
| `run_id` | Per-run identifier (daemon mode) |
| `user_id` | User ID from proxy auth username. When a token-exchange credential rule configures `bot_subject` (see [Token Exchange: Bot/service fallback](../guides/06-token-exchange.md#botservice-fallback)), a request using that sentinel value logs it here verbatim (e.g. `user_id="-"`) -- read that as "bot/service traffic," not a real per-user identity. |
| `application_name` | Postgres connections only: the client's `application_name` startup parameter, sanitized and length-bounded. A correlation slug the client sets, not a trusted identity — see [Postgres Data Plane](./08-postgres-data-plane.md#tracing-a-connection-to-its-origin). Omitted when the client didn't set one. |

Log level is determined by outcome: `ERROR` for server errors or transport failures, `WARN` for policy denials or client errors, `INFO` for successful requests.

## Model exchange log

`log.model_exchange` logs each inference request to a listed host as one OpenTelemetry GenAI event, `gen_ai.client.inference.operation.details` (conventions status Development). It is off by default. Only OpenAI Responses (`.../responses`) and Anthropic Messages (`.../v1/messages`) requests are logged, on the CONNECT interception, plain HTTP, and `/relay/` paths. On a WebSocket upgrade, each call (a client message and the server events up to its terminal event) is one event. A WebSocket that negotiates an extension (`Sec-WebSocket-Extensions`) is not logged.

The metadata uses `gen_ai.*` names. The bodies are the raw wire bytes under `gatekeeper.*` keys, not the normalized `gen_ai.input.messages` and `gen_ai.output.messages`: gatekeeper sees provider JSON and logs it exactly.

| Field | Source |
|---|---|
| `gen_ai.operation.name` | `chat` |
| `gen_ai.provider.name` | `openai` or `anthropic`, from the path |
| `gen_ai.request.model` | `model` of the request body |
| `gen_ai.response.id` | the response object; set on every event, including each WebSocket call |
| `gen_ai.response.finish_reasons` | the incomplete reason, the Anthropic `stop_reason`, `stop` for a completed call, or `error` for a failure or HTTP 400 and up |
| `gen_ai.conversation.id` | the `Session_id` request header; absent when the request has none |
| `server.address`, `url.path`, `http.request.method`, `http.response.status_code`, `error.type` | the request and response |
| `span.trace_id`, `span.span_id` | the `traceparent` and `tracestate` of the request; the event joins that trace |
| `gatekeeper.exchange.id` | the `X-Request-Id`, which is `request_id` of the canonical log line |
| `gatekeeper.request.body`, `gatekeeper.response.body` | the bodies |
| `gatekeeper.usage` | the raw usage JSON of the response; a stream gives the first and the last usage |
| `gatekeeper.terminal.type` | type of the terminal event |
| `gatekeeper.ttfb_ms`, `gatekeeper.duration_ms` | request start to response headers, and to body close |
| `gatekeeper.transport`, `gatekeeper.conn_id`, `gatekeeper.msg_seq` | WebSocket calls |
| `gatekeeper.user_id` | the proxy-auth user |
| `gatekeeper.request.truncated`, `gatekeeper.response.truncated` | a cut body: held back at the 32 MiB capture limit or by the 256 MiB body budget, or not decodable; for the response, also a body closed before its end |
| `gatekeeper.error` | transport or body-read error |

A body over 16 KiB is split into `gatekeeper.exchange.body` events with `gatekeeper.exchange.id`, `gatekeeper.exchange.part`, `gatekeeper.exchange.chunk_index` from 1, and `gatekeeper.exchange.chunk_count`; the main event then has no body, and `gatekeeper.request.parts` or `gatekeeper.response.parts` gives the count. Join the chunks in `chunk_index` order.

### Credentials

Gatekeeper logs no request or response header. The request body is copied from the client before credential injection and token substitution. Gatekeeper replaces each injected credential value with `[REDACTED]` in the response body, the error, and the path. When an injected value is under 8 bytes, gatekeeper cannot redact it safely and replaces the response body, the error, and the path with a placeholder. When a body is cut at the capture limit, gatekeeper also drops the last bytes the longest injected value could span. A client or tool that puts a secret in a body, or an upstream that returns one in another spelling, is not redacted.

### Cost

The proxy copies the bytes it forwards and forwards them without delay. One goroutine writes the events. A full queue (256 exchanges), 256 MiB of held bodies when the exchange starts, or a closed log skips the exchange and increments `proxy.exchange_log.dropped`. A budget that fills during a capture cuts the body instead. With the log off, a request costs one nil check.

## Client IP attribution behind a load balancer

By default, `client_ip` comes from the raw TCP peer address of the accepted connection. That's accurate for a directly-exposed listener, but not for one that sits behind a TCP-terminating load balancer (e.g. GCP's global TCP Proxy load balancer) — every connection appears to originate from the load balancer's own front-end range (`35.191.0.0/16` for GCP), not the real client.

PROXY protocol support is configured per listener: `proxy.proxy_protocol: true` wraps the HTTP/CONNECT proxy listener, and `postgres.proxy_protocol: true` wraps the [Postgres data-plane listener](./08-postgres-data-plane.md) — both parse PROXY protocol v1/v2 through the same shared logic. When the load balancer prepends a PROXY header, gatekeeper uses its advertised source address as the connection's client address instead of the TCP peer. On the HTTP listener this flows through to `client_ip` on every request path, including CONNECT-intercepted inner requests. On the Postgres listener it flows through to `client_ip` on the canonical log line and to the `client_addr` field on a failed run-token-authentication log line; the PROXY header is always the first bytes on the wire, so it's parsed before the client's `SSLRequest` and the TLS handshake. Connections opened without a header — load balancer health checks, direct probes of the port — fall back to the raw TCP peer address rather than being rejected, on either listener.

Because the header is honored from any peer that can reach the listener, only enable `proxy_protocol` on a listener whose port is reachable solely through the load balancer, and never use `client_ip` for security decisions — it's a logging convenience, not an authenticated identity. See [Deploying behind a TCP load balancer](../guides/11-load-balancer-proxy-protocol.md) for the full setup, including the Postgres listener.

## Request ID tracking

Every request receives a unique identifier. Gatekeeper checks for an `X-Request-Id` header from the caller. If present, it is reused. Otherwise, gatekeeper generates a TypeID with a `req` prefix (e.g., `req_01h455vb4pex5vsknk084sn02q`).

The request ID is:

- Set on the response via `X-Request-Id` header.
- Propagated to upstream servers via `X-Request-Id` on the forwarded request.
- Stored in the request context for extraction by loggers and span enrichment.
- Included in canonical log lines and OTel span events.

## slog-to-OTel bridge

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
