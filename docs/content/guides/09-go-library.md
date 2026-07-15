---
title: "Go Library"
description: "Import Gatekeeper as a Go module to embed the credential-injecting proxy in a custom application."
keywords: ["gatekeeper", "Go library", "embedding", "proxy API"]
---

# Go Library Usage

Import gatekeeper as a Go module to embed the proxy in a custom application. This is how [moat](https://github.com/majorcontext/moat) integrates gatekeeper -- importing the proxy engine and adding per-run credential scoping via a daemon layer.

## Prerequisites

- Go 1.25+

## Install

```bash
go get github.com/majorcontext/gatekeeper/proxy
```

## Basic Setup

Create a proxy, load a CA, and set credentials:

```go
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/majorcontext/gatekeeper/proxy"
)

func main() {
	// Load CA for TLS interception.
	certPEM, err := os.ReadFile("ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	keyPEM, err := os.ReadFile("ca.key")
	if err != nil {
		log.Fatal(err)
	}
	ca, err := proxy.LoadCA(certPEM, keyPEM)
	if err != nil {
		log.Fatal(err)
	}

	// Create proxy and configure it.
	p := proxy.NewProxy()
	p.SetCA(ca)
	p.SetCredentialWithGrant("api.github.com", "Authorization", "Bearer ghp_xxxx", "github")
	p.SetNetworkPolicy("strict", []string{"api.github.com"}, nil)

	// Start HTTP server.
	log.Fatal(http.ListenAndServe("127.0.0.1:9080", p))
}
```

`proxy.Proxy` implements `http.Handler`. Serve it with any `http.Server` or wrap it with middleware.

## Key API

| Method                       | Description                                          |
|------------------------------|------------------------------------------------------|
| `NewProxy()`                 | Create a new proxy instance                          |
| `SetCA(ca)`                  | Set the CA for TLS interception                      |
| `SetCredentialWithGrant(host, header, value, grant)` | Set a static credential for a host  |
| `SetCredentialResolver(host, resolver)`               | Set a dynamic per-request resolver  |
| `SetCredentialResolverWithStripHeaders(host, resolver, headers...)` | Set a dynamic resolver that also removes request headers it consumes; prefer this over `SetCredentialResolver` when the resolver reads a subject-identity or other header that must not reach the upstream, since the proxy strips those headers even when a better-matched static credential skips calling the resolver |
| `SetNetworkPolicy(policy, allows, grants)`            | Configure network allow/deny        |
| `SetAuthToken(token)`        | Require proxy authentication                         |
| `SetContextResolver(fn)`     | Map proxy auth tokens to per-caller contexts         |

## Custom ContextResolver

For multi-tenant setups, use a `ContextResolver` to map proxy auth tokens to per-caller credential sets:

```go
p := proxy.NewProxy()
p.SetCA(ca)

p.SetContextResolver(func(token string) (*proxy.RunContextData, bool) {
	// Look up caller by their proxy auth token.
	run, ok := registry.Get(token)
	if !ok {
		return nil, false
	}
	// AllowedHosts is []proxy.HostPattern — build it from raw strings
	// via proxy.ParseHostPattern.
	allowedHosts := make([]proxy.HostPattern, len(run.AllowedHosts))
	for i, h := range run.AllowedHosts {
		allowedHosts[i] = proxy.ParseHostPattern(h)
	}
	return &proxy.RunContextData{
		RunID: run.ID,
		Credentials: map[string][]proxy.CredentialHeader{
			"api.github.com": {
				{Name: "Authorization", Value: "Bearer " + run.GitHubToken, Grant: "github"},
			},
		},
		Policy:       "strict",
		AllowedHosts: allowedHosts,
	}, true
})
```

Each caller authenticates via `Proxy-Authorization` (or the username/password in `HTTP_PROXY`). The resolver returns per-caller credentials, network policy, and MCP server configuration.

## How Moat Uses Gatekeeper

Moat imports `github.com/majorcontext/gatekeeper/proxy` and layers a daemon on top:

1. A management API (Unix socket) accepts run registrations with per-run credentials and policies.
2. Each registration generates a unique proxy auth token.
3. The `ContextResolver` maps tokens to `RunContextData` containing that run's scoped credentials and network policy.
4. The proxy itself is shared across all runs -- credential isolation is handled entirely by the resolver.

Gatekeeper has no knowledge of moat. It exposes the `ContextResolver` hook and `RunContextData` struct; moat provides the implementation.

## OTel Middleware

Wrap the proxy with `OTelHandler` for OpenTelemetry instrumentation:

```go
handler := proxy.OTelHandler(p)
log.Fatal(http.ListenAndServe("127.0.0.1:9080", handler))
```

This adds request spans, duration histograms, and request counters. See [OpenTelemetry](./08-opentelemetry.md) for details on emitted signals.

## Next Steps

- [WebSocket Support](./10-websockets.md) — WebSocket upgrades through the proxy
