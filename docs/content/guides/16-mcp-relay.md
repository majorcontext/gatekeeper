---
title: "MCP Relay Setup"
description: "Configure gatekeeper's MCP relay end-to-end using the Go library, since MCP servers are not configurable in gatekeeper.yaml."
keywords: ["gatekeeper", "MCP relay", "model context protocol", "Go library", "SSE streaming"]
---

# MCP relay setup

Relay Model Context Protocol (MCP) requests to remote MCP servers with credential injection. This guide walks through configuring the relay end-to-end. For how the relay works internally — request flow, SSE mechanics, the two credential-injection modes — see [MCP Relay](../concepts/05-mcp-relay.md).

> **Note:** MCP servers are not configurable in `gatekeeper.yaml`. `MCPServerConfig` is a Go-library type, set via `Proxy.SetMCPServers` or `RunContextData.MCPServers` — there is no `mcp:` section in the standalone config file. This is how [moat](https://github.com/majorcontext/moat)'s daemon layer wires up MCP servers per run. This guide shows the Go-library path, which is the only path that exists.

## Prerequisites

- Go 1.25+
- Familiarity with embedding gatekeeper as a library ([Go Library Usage](./09-go-library.md))

## Minimal setup

Create a proxy, register an MCP server, and supply a credential store that resolves grants to values:

```go
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/majorcontext/gatekeeper/proxy"
)

// credStore looks up MCP grant credentials by name.
type credStore struct {
	tokens map[string]string
}

func (s *credStore) GetToken(grant string) (string, error) {
	token, ok := s.tokens[grant]
	if !ok {
		return "", fmt.Errorf("no credential for grant %q", grant)
	}
	return token, nil
}

func main() {
	p := proxy.NewProxy()

	p.SetCredentialStore(&credStore{
		tokens: map[string]string{
			"mcp-context7": "real-api-key-123",
		},
	})

	p.SetMCPServers([]proxy.MCPServerConfig{
		{
			Name: "context7",
			URL:  "https://mcp.context7.com/mcp",
			Auth: &proxy.MCPAuthConfig{
				Grant:  "mcp-context7",
				Header: "Authorization",
			},
		},
	})

	log.Fatal(http.ListenAndServe("127.0.0.1:9080", p))
}
```

`SetCredentialStore` and `SetMCPServers` are the standalone/single-run fallback: the proxy checks `RunContextData` first (daemon mode) and falls back to these proxy-level values when no per-run context is set. `proxy.Proxy` implements `http.Handler`, so this needs no CA and no TLS interception — the relay endpoint is a plain HTTP handler on the proxy's own listener.

## Sending a request

An MCP client sends requests directly to the relay endpoint, bypassing `HTTP_PROXY`:

```bash
curl -X POST http://127.0.0.1:9080/mcp/context7/v1/endpoint \
  -H "Content-Type: application/json" \
  -d '{"method": "tools/list"}'
```

Gatekeeper:

1. Matches `context7` against the configured `MCPServerConfig` entries.
2. Builds the target URL from the server's `URL` field, appending any path after `/mcp/context7` (here, `/v1/endpoint`) and preserving the query string.
3. Resolves the credential for grant `mcp-context7` — first from `RunContextData.Credentials` (daemon mode), then from the `CredentialStore` — and sets it on the configured `Auth.Header`.
4. Forwards the request to `https://mcp.context7.com/mcp/v1/endpoint` and streams the response back.

Path building trims exactly the `/mcp/{server-name}` prefix and appends what remains to the server's configured URL path (trimming a trailing slash first), so `/mcp/context7` (no sub-path) forwards to the bare `https://mcp.context7.com/mcp`.

## Multi-tenant setup (RunContextData)

For a daemon that scopes MCP servers and credentials per caller, populate `RunContextData.MCPServers` and `RunContextData.Credentials` (or `RunContextData.CredStore`) inside a `ContextResolver` instead of calling `SetMCPServers`/`SetCredentialStore` on the proxy directly:

```go
p.SetContextResolver(func(token string) (*proxy.RunContextData, bool) {
	run, ok := registry.Get(token)
	if !ok {
		return nil, false
	}
	return &proxy.RunContextData{
		RunID: run.ID,
		MCPServers: []proxy.MCPServerConfig{
			{
				Name: "context7",
				URL:  "https://mcp.context7.com/mcp",
				Auth: &proxy.MCPAuthConfig{
					Grant:  "mcp-context7",
					Header: "Authorization",
				},
			},
		},
		Credentials: map[string][]proxy.CredentialHeader{
			"mcp.context7.com": {
				{Name: "Authorization", Value: "Bearer " + run.Context7Key, Grant: "mcp-context7"},
			},
		},
	}, true
})
```

Each run's `MCPServers` list and credentials are isolated — `getMCPServersForRequest` reads `RunContextData.MCPServers` when a `ContextResolver` resolved the run, and only falls back to the proxy-level list set by `SetMCPServers` when no run context is present. See [Go Library Usage](./09-go-library.md#custom-contextresolver) for the full `ContextResolver` pattern.

### Daemon-mode direct access

When a `ContextResolver` is set, gatekeeper also serves `/mcp/{token}/{server-name}[/path]` for clients that connect directly (not through the proxy mechanism) and therefore cannot send a `Proxy-Authorization` header. The run's proxy auth token is embedded in the URL instead; gatekeeper extracts it, resolves the run, strips the token from the path, and dispatches to the same relay handling described above. Standalone gatekeeper (no `ContextResolver`) never serves this form — see [MCP Relay](../concepts/05-mcp-relay.md#daemon-mode-token-embedded-path) for the full mechanics.

## Credential injection modes

The relay endpoint above is one of two ways credentials reach an MCP server.

**Relay mode** (`/mcp/{server-name}`, shown above): the client talks to gatekeeper's relay endpoint directly. Gatekeeper resolves the grant and sets the header on the outgoing request unconditionally.

**Stub-replacement mode**: when an MCP client instead routes through the CONNECT proxy (`HTTP_PROXY`) to an MCP server's real hostname, gatekeeper inspects the configured `Auth.Header` on the intercepted request. If its value exactly matches `moat-stub-{grant}`, gatekeeper replaces it with the real credential; any other value (including a credential the client already holds) is left untouched. This mode requires a CA — TLS interception is what lets gatekeeper read and rewrite the header. See [CA Setup](./01-ca-setup.md).

```bash
# Client sends a stub value through the CONNECT proxy:
curl --cacert ca.crt --proxy http://127.0.0.1:9080 \
  -H "Authorization: moat-stub-mcp-context7" \
  https://mcp.context7.com/mcp/v1/endpoint
```

Gatekeeper matches the request host against a configured server's `URL` host, sees the stub value, and swaps in the real credential before forwarding.

### oauth: grant prefix

When a grant name starts with `oauth:` (e.g., `oauth:notion`), gatekeeper prepends `Bearer ` to the resolved credential value automatically, in both modes. Grants that don't start with `oauth:` are injected as-is — set `Header` to `Authorization` and give the credential value its own scheme prefix if one is needed.

## SSE streaming

MCP responses that use Server-Sent Events stream through the relay as they arrive: gatekeeper reads the upstream body in 4096-byte chunks and flushes the `http.ResponseWriter` after each one, rather than buffering the full response. The relay's HTTP client has no client-level timeout, since MCP SSE connections may stay open indefinitely.

## Error handling

| Status | Cause |
|--------|-------|
| `400` | Direct daemon-mode request (`/mcp/{token}/{server}`) with no server name after the token |
| `401` | Direct daemon-mode request with an unrecognized proxy auth token |
| `404` | `{server-name}` doesn't match any configured `MCPServerConfig` |
| `403` | A `mcp-{server-name}` Keep policy denied the request, or the request body failed fail-closed inspection (non-JSON, or a redaction step failed) — see [Keep Policy Scopes](./18-keep-policy-scopes.md) |
| `500` | The server's configured `URL` failed to parse, reading the request body for Keep evaluation failed, the credential for the grant resolved empty, or building the outgoing request failed |
| `502` | Gatekeeper reached out to the real MCP server and the connection failed |

The `404` and `500` bodies include diagnostic detail (available server count, the grant name, a suggested `moat grant` command) meant for an operator or coding agent reading the response, not for display to an end user.

## Next steps

- [Keep Policy Scopes](./18-keep-policy-scopes.md) — evaluate `tools/call` requests against policy before forwarding
- [Credential Caching, Refresh, and Invalidation](./17-credential-lifecycle.md) — how the grants referenced here are resolved and rotated
