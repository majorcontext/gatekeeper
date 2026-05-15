---
title: "MCP Relay"
description: "How Gatekeeper relays Model Context Protocol requests to remote MCP servers with credential injection and SSE streaming."
keywords: ["gatekeeper", "MCP relay", "model context protocol", "SSE streaming"]
---

# MCP Relay

Gatekeeper relays Model Context Protocol (MCP) requests to remote MCP servers with credential injection. MCP clients that cannot route traffic through an HTTP proxy connect to gatekeeper's relay endpoint directly, and gatekeeper forwards requests to the real MCP server with authentication headers attached.

## What MCP Relay Does

MCP servers often require authentication — an API key, OAuth token, or other credential. The MCP relay solves two problems:

1. **Credential injection for MCP.** The client sends requests to gatekeeper without credentials. Gatekeeper looks up the configured grant for the target MCP server and injects the real credential before forwarding.
2. **Proxy bypass.** Some MCP clients do not respect `HTTP_PROXY` settings. The relay endpoint (`/mcp/{server-name}`) accepts direct HTTP connections, eliminating the need for proxy-aware clients.

## Request Flow

A relay request follows this path:

1. The client sends a request to `http://proxy-host:port/mcp/{server-name}[/path]`.
2. Gatekeeper matches `{server-name}` against configured `MCPServerConfig` entries.
3. Gatekeeper builds the target URL from the server's configured `URL` field, preserving any sub-path and query string from the original request.
4. If the server has an `Auth` config, gatekeeper resolves the credential by grant name and injects it into the forwarded request header.
5. Gatekeeper forwards the request to the real MCP server and streams the response back to the client.

```yaml
# MCP server configuration (set via MCPServerConfig)
# name: context7
# url: https://mcp.context7.com/mcp
# auth:
#   grant: mcp-context7
#   header: Authorization
```

A request to `/mcp/context7/v1/endpoint` forwards to `https://mcp.context7.com/mcp/v1/endpoint` with the `Authorization` header set to the resolved credential.

## SSE Streaming

MCP uses Server-Sent Events (SSE) for streaming responses. Gatekeeper supports this by flushing response data incrementally:

- After writing response headers, gatekeeper calls `Flush()` on the `http.ResponseWriter` if it implements `http.Flusher`.
- The response body is streamed with `io.Copy`, delivering events to the client as they arrive from the upstream server.

The relay HTTP client has no client-level timeout — MCP SSE streams are long-lived connections that may remain open indefinitely.

## Credential Injection Modes

MCP credential injection works in two modes:

**Relay mode.** Requests to `/mcp/{server-name}` are proxied directly. Gatekeeper resolves the credential by grant name from `RunContextData.Credentials` (daemon mode) or the `CredentialStore` (standalone mode) and sets the header on the outgoing request.

**Stub replacement mode.** When an MCP client sends a request through the CONNECT proxy (not the relay endpoint) to an MCP server URL, gatekeeper checks if the authentication header contains a stub value (`moat-stub-{grant}`). If it matches, the stub is replaced with the real credential. Non-stub values are left unchanged — the client may already have a valid credential.

For OAuth grants (grant names starting with `oauth:`), the credential value is automatically prefixed with `Bearer `.

## Keep Policy Evaluation

When a Keep policy engine is configured for an MCP server (keyed as `mcp-{server-name}`), gatekeeper evaluates `tools/call` requests before forwarding:

- The request body is parsed as JSON to extract the method, tool name, and arguments.
- If the Keep engine returns `Deny`, the request is blocked with a `403` response.
- If the engine returns `Redact`, tool arguments are mutated according to the policy's mutation rules, and the modified request is forwarded.
- Non-JSON request bodies are denied (fail-closed) when a policy is configured.

## Error Handling

- Unknown server name: `404` with a message listing available server count.
- Credential resolution failure: `500` with the grant name and a suggested `moat grant` command.
- Upstream connection failure: `502` with the target URL and error details.
