---
title: "WebSockets"
description: "WebSocket connections work through Gatekeeper with credential injection on the HTTP upgrade request and transparent frame tunneling."
keywords: ["gatekeeper", "WebSocket", "upgrade request", "bidirectional tunneling"]
---

# WebSocket Support

WebSocket connections work through gatekeeper with no special configuration. The proxy intercepts the TLS connection, injects credentials on the HTTP upgrade request, and then tunnels the bidirectional WebSocket frames transparently.

## How It Works

1. The client sends `CONNECT host:443` through the proxy.
2. Gatekeeper terminates TLS and reads the plaintext HTTP request.
3. The client sends an HTTP `Upgrade: websocket` request.
4. Gatekeeper injects credentials into the upgrade request headers (e.g., `Authorization`), just like any other request.
5. The upgrade request is forwarded to the upstream server via a `ReverseProxy`.
6. The Go standard library's `httputil.ReverseProxy` detects the `101 Switching Protocols` response and initiates bidirectional tunneling.
7. After the upgrade, WebSocket frames flow between client and server without further proxy intervention.

## Configuration

No additional configuration is needed. Any credential configured for a host applies to WebSocket upgrade requests to that host:

```yaml
proxy:
  host: 127.0.0.1
  port: 9080

tls:
  ca_cert: ca.crt
  ca_key: ca.key

credentials:
  - host: ws.example.com
    header: Authorization
    grant: ws-api
    source:
      type: env
      var: WS_API_TOKEN

network:
  policy: permissive

log:
  level: info
  format: text
```

## Verification

Connect a WebSocket client through the proxy:

```bash
export HTTPS_PROXY=http://127.0.0.1:9080
wscat -c wss://ws.example.com/socket --ca ca.crt
```

The proxy log shows the CONNECT tunnel and credential injection on the upgrade request:

```text
level=INFO msg=request http_method=CONNECT http_host=ws.example.com:443 credential_injected=true
```

After the upgrade completes, the proxy tunnels frames bidirectionally until either side closes the connection.

## Limitations

- Credentials are injected only on the initial HTTP upgrade request. Subsequent WebSocket frames pass through unmodified.
- The proxy does not inspect or modify WebSocket frame content.
- Connection lifetime is bounded by the proxy's idle timeout and the underlying TCP keepalive settings.

## Next Steps

- [Network Lockdown](./07-network-lockdown.md) — restrict which WebSocket hosts the proxy can reach
- [OpenTelemetry](./08-opentelemetry.md) — trace WebSocket CONNECT tunnels
