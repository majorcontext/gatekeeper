---
title: "Go Library"
description: "Import Gatekeeper as a Go module to embed the credential-injecting proxy in a custom application."
keywords: ["gatekeeper", "Go library", "embedding", "proxy API"]
---

# Go library usage

Import gatekeeper as a Go module to embed the proxy in a custom application. This is how [moat](https://github.com/majorcontext/moat) integrates gatekeeper -- importing the proxy engine and adding per-run credential scoping via a daemon layer.

## Prerequisites

- Go 1.27.3+

## Install

```bash
go get github.com/majorcontext/gatekeeper/proxy
```

## Basic setup

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
	if err := p.SetNetworkPolicy("strict", []string{"api.github.com"}, nil); err != nil {
		log.Fatal(err)
	}

	// Start HTTP server.
	log.Fatal(http.ListenAndServe("127.0.0.1:9080", p))
}
```

`proxy.Proxy` implements `http.Handler`. Serve it with any `http.Server` or wrap it with middleware.

`http.Server.Shutdown` does not close CONNECT tunnels or intercepted connections, because the proxy hijacks them. Call `Proxy.CloseConnections(ctx)` after `Shutdown`, or at the same time:

```go
srv := &http.Server{Addr: "127.0.0.1:9080", Handler: p}
go srv.ListenAndServe()

// On shutdown:
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()
_ = srv.Shutdown(ctx)
_ = p.CloseConnections(ctx)
```

`CloseConnections` closes the open tunnels and waits for them to exit until `ctx` ends, then returns `ctx.Err()` if any remain. It is safe to call more than once. It is permanent: the `Proxy` refuses every later CONNECT, so create a new `Proxy` to serve again. `proxy.Server.Stop` and the standalone server's `Stop` do this for you.

## Key API

| Method                       | Description                                          |
|------------------------------|------------------------------------------------------|
| `NewProxy()`                 | Create a new proxy instance                          |
| `SetCA(ca)`                  | Set the CA for TLS interception                      |
| `SetCredentialWithGrant(host, header, value, grant)` | Set a static credential for a host |
| `SetCredentialEntry(credential)` | Register a static credential with request matching and header transforms |
| `SetCredentialResolverEntry(credential, stripHeaders...)` | Register a credential model with its runtime resolver and policy fields |
| `SetCredentialResolver(host, resolver)` | Set a dynamic per-request resolver |
| `SetCredentialResolverWithStripHeaders(host, resolver, headers...)` | Set a dynamic resolver that also removes request headers it consumes; prefer this over `SetCredentialResolver` when the resolver reads a subject-identity or other header that must not reach the upstream, since the proxy strips those headers even when a better-matched static credential skips calling the resolver |
| `SetNetworkPolicy(policy, allows, grants)`            | Configure network allow/deny; returns an error unless `policy` is `permissive`, `strict`, or empty |
| `SetDelegateAuth(true)`      | Delegate password checks to resolvers; returns an error, and the proxy refuses every request, until `SetAuthToken` sets a token |
| `CloseConnections(ctx)`      | Close open CONNECT tunnels and refuse new ones; call on shutdown |
| `SetAuthToken(token)`        | Require proxy authentication                         |
| `SetContextResolver(fn)`     | Map proxy auth tokens to per-caller contexts         |

`proxy.Credential` is the shared model for YAML, static registration, resolver registration, and `RunContextData.Credentials`. `proxy.CredentialHeader` is an alias for the same type. A credential can select and transform a request:

```go
p.SetCredentialEntry(proxy.Credential{
	Host: "api.anthropic.com",
	Header: "Authorization",
	Value: "Bearer test-token",
	Grant: "workload",
	Match: &proxy.RequestMatch{Header: "x-api-key", Paths: []string{"/v1/messages"}, Methods: []string{"POST"}},
	SetHeaders: map[string]string{"anthropic-beta": "oauth-2025-04-20"},
	RemoveHeaders: []string{"x-api-key"},
})
```

Use `SetCredentialResolverEntry` for a per-request resolver. Set its callback on `Credential.Resolver` before registration. The first matching credential wins in registration order. `SetMatchedCredentialResolver` remains available with its existing resolver-ranking behavior.

## Custom context resolver

For multi-tenant setups, use a context resolver to map proxy auth tokens to per-caller credential sets:

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

## How Moat uses Gatekeeper

Moat imports `github.com/majorcontext/gatekeeper/proxy` and layers a daemon on top:

1. A management API (Unix socket) accepts run registrations with per-run credentials and policies.
2. Each registration generates a unique proxy auth token.
3. The context resolver maps tokens to `RunContextData` containing that run's scoped credentials and network policy.
4. The proxy itself is shared across all runs -- credential isolation is handled entirely by the resolver.

Gatekeeper has no knowledge of moat. It exposes the `SetContextResolver` hook and `RunContextData` struct; moat provides the implementation.

## Branding

Blocked responses, relay errors, MCP stub values, and a newly generated CA are neutral by default: blocked bodies start with `gatekeeper:`, the MCP stub prefix is `gatekeeper-stub-`, the CA subject is `Gatekeeper CA`, and `Proxy-Authenticate` uses the `Gatekeeper-Policy` scheme. Every blocked response (network policy, host service, Keep `http` and MCP scopes, LLM policy, cleartext-injection refusal) carries `X-Gatekeeper-Blocked` and the alias `X-Moat-Blocked` with the same value.

An embedder phrases these differently with `Proxy.SetBranding(proxy.Branding{...})` (`Name`, `ErrorPrefix`, `PolicyScheme`, `MCPStubPrefix`, `NetworkHint`, `HostHint`, `GrantHint`) and `proxy.NewCAWithSubject(dir, organization, commonName)`. A CA loaded from disk keeps its own subject.

## OTel middleware

Wrap the proxy with `NewOTelHandler` for OpenTelemetry instrumentation:

```go
handler, err := proxy.NewOTelHandler(p, proxy.OTelOptions{})
if err != nil {
	log.Printf("some otel instruments are disabled: %v", err)
}
log.Fatal(http.ListenAndServe("127.0.0.1:9080", handler))
```

This adds request spans, duration histograms, and request counters. `OTelOptions` takes an optional `TracerProvider` and `MeterProvider`; a nil provider uses the global one. If an instrument cannot be created, the handler still works with that instrument disabled and the error names it. `proxy.RecordCredentialInjection` and `proxy.RecordPolicyDenial` always use the global providers.

## Embedding the standalone server

`gatekeeper.New(ctx, cfg, gatekeeper.Options{Version: v, Logger: logger})` never changes process-global state. It logs through `Options.Logger`, or `slog.Default()` when nil. The `log.level`, `log.format`, and `log.output` config keys apply only to the `gatekeeper` binary, which builds the logger from them and installs it with `slog.SetDefault`. The `proxy` and `credentialsource` packages log through the global `slog` default. See [OpenTelemetry](./08-opentelemetry.md) for details on emitted signals.

## Next steps

- [WebSocket Support](./10-websockets.md) — WebSocket upgrades through the proxy
