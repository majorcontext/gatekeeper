---
title: "LLM policy"
description: "Reference for Gatekeeper's LLM policy evaluation, which evaluates Anthropic API responses against Keep policy rules."
keywords: ["gatekeeper", "LLM policy", "Keep", "policy evaluation", "Anthropic"]
---

# LLM policy

Gatekeeper evaluates Anthropic API responses against [Keep](https://github.com/majorcontext/keep) policy rules. Denied responses are blocked before reaching the client.

## Overview

LLM policy evaluation is configured through `RunContextData.KeepEngines` — a map of hostnames to Keep engine instances. When a proxied response matches a host with a Keep engine, gatekeeper buffers the response body, evaluates it against the engine's rules, and either forwards or blocks the response.

This feature is primarily used through moat's configuration layer, which compiles Keep rule files into engines and attaches them to per-run context. Standalone gatekeeper does not expose Keep configuration in `gatekeeper.yaml`.

---

## Evaluation flow

1. The proxy intercepts an HTTPS response from a host that has a Keep engine configured (e.g., `api.anthropic.com`).
2. The response body is buffered up to 10 MB (`maxLLMResponseSize`). Responses exceeding this limit are denied (fail-closed).
3. If the response is gzip-compressed, it is decompressed for evaluation.
4. The response is evaluated based on its `Content-Type`:
   - **JSON responses** — Parsed and evaluated via `llm.EvaluateResponse`.
   - **SSE streaming responses** (`text/event-stream`) — SSE events are parsed, evaluated via `llm.EvaluateStream`, and the (possibly redacted) events are forwarded.
5. If the policy denies the response, a JSON error body is returned to the client.

---

## Fail-closed behavior

All evaluation errors result in denial:

- Gzip decompression failures
- SSE parse errors
- Keep evaluation errors
- Response bodies exceeding 10 MB

---

## Denied response format

When a response is denied, the client receives an HTTP 200 with a JSON body matching the Keep LLM gateway format:

```json
{
  "type": "error",
  "error": {
    "type": "policy_denied",
    "message": "Policy denied: rule-name. Human-readable message."
  }
}
```

---

## Observability

Policy denials are logged at `warn` level with fields:

| Field | Description |
|-------|-------------|
| `run_id` | Run ID from per-run context |
| `scope` | Policy scope (e.g., `"llm"`) |
| `operation` | Operation type |
| `rule` | Rule name that triggered the denial |
| `message` | Human-readable denial message |

Policy denials are also recorded as OTel span events (`policy.denial`) and increment the `proxy.policy.denials` counter with `proxy.policy.scope` and `proxy.policy.rule` attributes.

---

## Codec

Gatekeeper uses the Anthropic codec (`anthropic.NewCodec()`) for parsing API responses. The codec is stateless and shared across all requests.
