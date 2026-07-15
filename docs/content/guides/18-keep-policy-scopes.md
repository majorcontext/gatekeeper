---
title: "Keep Policy Scopes"
description: "The three Keep policy scopes gatekeeper evaluates — http, mcp-<server>, and llm-gateway — and how to read their denial logs."
keywords: ["gatekeeper", "Keep", "policy", "scopes", "http", "mcp", "llm-gateway"]
---

# Keep policy scopes

Gatekeeper evaluates [Keep](https://github.com/majorcontext/keep) policy engines at three distinct points in the request lifecycle, keyed by three distinct scope names: `http`, `mcp-<server-name>`, and `llm-gateway`. They inspect different things, deny in different ways, and fail closed under different conditions. This guide is for two audiences: embedders (like moat) wiring engines into `RunContextData.KeepEngines`, and operators reading policy denial logs and trying to tell which layer produced them.

> **Note:** None of this is configurable in `gatekeeper.yaml`. `KeepEngines` is a field on `RunContextData` — a Go-library type — populated by whatever constructs the struct returned from a `ContextResolver`. Standalone gatekeeper never sets it; this feature exists only for embedders. See [Go Library Usage](./09-go-library.md).

## The KeepEngines map

```go
type RunContextData struct {
    // ...
    KeepEngines map[string]*keeplib.Engine
    // ...
}
```

There is no setter method — an embedder populates the map directly when building the `RunContextData` it returns from its `ContextResolver`. The map is keyed by scope name, and gatekeeper looks up exactly three keys:

| Key | Looked up | Evaluates |
|---|---|---|
| `"http"` | On every intercepted HTTPS request, after network policy allows it | The request itself (method, host, path, body) |
| `"mcp-" + serverName` | On `POST` requests to `/mcp/{serverName}` whose body is a `tools/call` | The tool name and arguments |
| `"llm-gateway"` | On `200` responses from `api.anthropic.com` | The response body (JSON or SSE) |

A run with no entry for a given key simply skips that check — Keep evaluation is opt-in per scope, not a blanket policy. A run can set only `"llm-gateway"`, only `"mcp-github"`, all three, or none.

## `http` scope

Runs after [network policy](../concepts/04-network-policy.md) allows a request, on the plaintext request produced by TLS interception. Unlike network policy, it can inspect the request body, not just the host.

**Denial:** `403 Forbidden`, header `X-Moat-Blocked: keep-policy`, `Content-Type: text/plain`, a plaintext body naming the host (and, for evaluation-error denials, a generic "policy evaluation error" — the specific evaluator error is not echoed to the client).

**Fail-closed conditions.** The engine's rules determine whether a body is needed at all (`eng.RequiresBody("http")`); when it is, gatekeeper reads and parses it before evaluation, and any of the following denies the request rather than passing it through unevaluated:

- `Content-Encoding` is set on the request (e.g., `gzip`) — the body is not decompressed here, so a compressed body can't be inspected and is denied outright. This differs from the `llm-gateway` scope below, which does decompress gzip responses.
- `Content-Type` is not `application/json` or does not end in `+json`.
- The body exceeds 10 MiB (10,485,760 bytes).
- The body is not valid JSON.
- The body has duplicate keys in a JSON object at any nesting depth (e.g., two `"model"` keys) — rejected because `encoding/json` silently keeps the last value, but a downstream parser that keeps the first would see a different value than the one the policy evaluated, a bypass vector.

A `nil` or zero-`Content-Length` body, or a body that is empty/whitespace after trimming, is treated as body-less rather than a failure — path-only rules still apply, body rules just don't match.

## `mcp-<server-name>` scope

Evaluated inside the [MCP relay](./16-mcp-relay.md) handler, before the request is forwarded to the real MCP server, and only for a `tools/call` method with a non-empty tool name. Requests for other MCP methods (`tools/list`, `initialize`, etc.) are not evaluated even when an engine is configured.

**Decisions:**

- `Deny` — the request is blocked with `403 Forbidden` and a plaintext body. If the engine set a message, it's appended to the client-facing response.
- `Redact` — the engine's mutation rules rewrite the tool call's `arguments`, the request body is re-encoded with the mutated arguments, and the modified request is forwarded. A failure at any step of re-encoding (unmarshal, missing `params` map, marshal) denies with `403` rather than forwarding a partially-mutated or original body.
- Anything else (allow) — forwarded unchanged.

**Fail-closed condition:** once an engine is configured for a server, *every* request body to that server must parse as JSON, not just `tools/call` bodies — gatekeeper reads and unmarshals the body before it can even check the method name, and denies with `403` if that unmarshal fails. Only a body that does parse as JSON goes on to the method check above, where non-`tools/call` requests (and `tools/call` requests with an empty tool name) pass through without Keep evaluation.

> **Note:** This scope does not set `X-Moat-Blocked`. All of its denial responses use a plain `http.Error` call with no policy header, unlike the `http` and `llm-gateway` scopes below. Don't rely on the header's presence to detect an MCP-scope denial in logs or client-side handling — use the response body and the `mcp.tool_call` operation in the policy log instead (see [Observability](#observability)).

## `llm-gateway` scope

Evaluated on the response side, inside `ModifyResponse`, and gated on two hardcoded conditions: the response status must be exactly `200`, and the request host must be exactly `api.anthropic.com` (a literal string comparison, not a configurable pattern). A non-200 response, or a response from any other host, is never evaluated even when `KeepEngines["llm-gateway"]` is set.

**Denial:** `400 Bad Request` (not `403` — this scope replaces the response body rather than blocking a forward-in-progress), `Content-Type: application/json`, header `X-Moat-Blocked: llm-policy`, JSON body:

```json
{
  "type": "error",
  "error": {
    "type": "policy_denied",
    "message": "Policy denied: rule-name. Human-readable message."
  }
}
```

This matches the error shape Keep's own LLM gateway uses, so a client like Claude Code handles a gatekeeper denial the same way it handles a Keep-gateway denial.

**Fail-closed conditions:**

- The response body exceeds 10 MiB (10,485,760 bytes) — denied with rule `size-limit` before evaluation runs.
- The body can't be read from the upstream connection — rule `read-error`.
- The body is `Content-Encoding: gzip` and decompression fails — rule `evaluation-error`. Unlike the `http` scope, a gzip-compressed body here *is* decompressed and evaluated on success; Claude Code sends `Accept-Encoding: gzip`, and Go's transport does not auto-decompress a response the client explicitly asked to receive compressed, so gatekeeper does it itself before evaluation.
- The response is SSE (`Content-Type: text/event-stream`) and the stream fails to parse — rule `evaluation-error`. SSE events are read up to and including `message_stop`; anything after that (pings, keepalives) is not policy-relevant and isn't parsed.
- The Keep evaluation call itself errors — rule `evaluation-error`.

A `Deny` decision from the engine uses the rule and message the engine returned, tagged with operation `llm.tool_use` in the policy log (see below).

This scope is documented in full in [LLM policy](../reference/05-llm-policy.md), including the codec and evaluation-flow details this guide doesn't repeat.

## Observability

Every denial across all three scopes calls the same policy logger, configured once via `Proxy.SetPolicyLogger`. Gatekeeper's own standalone binary wires it to a `slog.Warn` call with exactly five fields:

| Field | Description |
|---|---|
| `run_id` | The run's ID from `RunContextData`, empty in standalone mode |
| `scope` | `"http"`, `"mcp-<server-name>"`, or `"llm-gateway"` (also `"network"` for network-policy denials, which are a separate layer — see [Network Policy](../concepts/04-network-policy.md)) |
| `operation` | See the table below |
| `rule` | The Keep rule name that triggered the denial, or an internal reason like `evaluation-error`/`size-limit`/`read-error` for a fail-closed denial that never reached rule evaluation |
| `message` | Human-readable detail from the engine or the fail-closed condition |

This logger fires only on denials — there is no corresponding "allow" log line from this path. Allowed requests still appear in the canonical per-request log (`RequestLogData`), which is a separate log stream covering every request regardless of policy outcome.

### scope / operation combinations

| scope | operation | rule examples |
|---|---|---|
| `network` | `http.request` / `http.connect` | (empty — network policy denials carry no rule name) |
| `http` | `http.request` | Keep rule name, or `body-inspection-error` / `evaluation-error` |
| `mcp-<server-name>` | `mcp.tool_call` | Keep rule name, or `evaluation-error` / `redaction-error` |
| `llm-gateway` | `llm.tool_use` | Keep rule name |
| `llm-gateway` | `llm.read_error` | `read-error` |
| `llm-gateway` | `llm.response_too_large` | `size-limit` |

### OTel signals

Each denial also, when a trace context is present, adds a `policy.denial` span event (attributes: `scope`, `operation`, `rule`, `message`) and increments the `proxy.policy.denials` counter with `proxy.policy.scope` and `proxy.policy.rule` attributes. See [OpenTelemetry](./08-opentelemetry.md).

### X-Moat-Blocked header values

| Value | Scope/layer | Status |
|---|---|---|
| `request-rule` | Network policy | `407` |
| `host-service` | Host gateway | `407` |
| `keep-policy` | `http` scope | `403` |
| `llm-policy` | `llm-gateway` scope | `400` |
| *(none)* | `mcp-<server-name>` scope | `403` |

## Next steps

- [LLM policy](../reference/05-llm-policy.md) — full reference for the `llm-gateway` scope
- [Network Policy](../concepts/04-network-policy.md) — how the `http` scope relates to host/path-level network policy
- [MCP Relay Setup](./16-mcp-relay.md) — configuring the servers that the `mcp-<server-name>` scope evaluates
