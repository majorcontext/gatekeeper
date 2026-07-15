---
title: "Deploying Behind a TCP Load Balancer"
description: "Recover the real client IP when gatekeeper runs behind a TCP-terminating load balancer, using PROXY protocol v1/v2."
keywords: ["gatekeeper", "load balancer", "PROXY protocol", "GCP", "client IP"]
---

# Deploying behind a TCP load balancer

Recover the real client IP when gatekeeper runs behind a TCP-terminating load balancer, such as GCP's global TCP Proxy load balancer. Without this, every request's `client_ip` log attribute shows the load balancer's hop instead of the actual client.

## Prerequisites

- A working gatekeeper deployment (see [Config file](../reference/02-config-file.md))
- A TCP-terminating load balancer in front of gatekeeper that supports PROXY protocol v1/v2 (for example, GCP's global TCP Proxy load balancer)
- `gcloud` configured against the target GCP project, if following the GCP walkthrough below

## Why client_ip shows the load balancer

A TCP-terminating load balancer ends the client's TCP connection at its own edge and opens a new connection to gatekeeper from its own front-end IP range. GCP's global TCP Proxy load balancer dials backends from `35.191.0.0/16`. By default, gatekeeper reads `client_ip` from the raw TCP peer address of the accepted connection — so every request logs the load balancer's address, never the real client, no matter which host actually opened the connection.

## How it works

1. The client connects to the load balancer's public IP.
2. The load balancer terminates that connection and opens a new TCP connection to gatekeeper, prepending a PROXY protocol v1 or v2 header that names the original client address.
3. When `network.proxy_protocol: true`, gatekeeper wraps its proxy listener with PROXY protocol parsing. On each accepted connection, it reads the leading header (if present) and substitutes the header's advertised source address for the raw TCP peer address.
4. That substituted address flows through to the `client_ip` request-log attribute on every request path, including CONNECT-intercepted TLS traffic.
5. A connection that opens without a PROXY header — or that doesn't send one within a 10-second read timeout — falls back to the raw TCP peer address instead of being rejected. This fail-open behavior keeps load balancer health checks and direct probes of the port working.

## Enabling proxy_protocol

Set `network.proxy_protocol: true` in gatekeeper.yaml:

```yaml
proxy:
  host: 0.0.0.0
  port: 9080

tls:
  ca_cert: ca.crt
  ca_key: ca.key

credentials:
  - host: api.github.com
    header: Authorization
    grant: github
    source:
      type: env
      var: GITHUB_TOKEN

network:
  policy: permissive
  proxy_protocol: true

log:
  level: info
  format: text
```

`proxy.host` is bound to `0.0.0.0` here because the listener must be reachable from the load balancer, which is not running on the same host. See [Security Requirement](#security-requirement) below before deploying this configuration.

## Configuring the GCP backend service

Enabling `proxy_protocol` on gatekeeper is only half the change — the load balancer must also be told to send the header. For a global TCP Proxy load balancer, this is the backend service's `proxyHeader` field.

Update an existing backend service:

```bash
gcloud compute backend-services update gatekeeper-backend \
  --global \
  --proxy-header=PROXY_V1
```

Or set it at creation time:

```bash
gcloud compute health-checks create http gatekeeper-health-check \
  --port=9080 \
  --request-path=/healthz

gcloud compute backend-services create gatekeeper-backend \
  --global \
  --protocol=TCP \
  --health-checks=gatekeeper-health-check \
  --proxy-header=PROXY_V1

gcloud compute backend-services add-backend gatekeeper-backend \
  --global \
  --instance-group=gatekeeper-ig \
  --instance-group-zone=us-central1-a
```

`--proxy-header` accepts `NONE` (default) or `PROXY_V1`. Gatekeeper's PROXY protocol parser handles both v1 (text) and v2 (binary) headers, but GCP's global TCP Proxy load balancer sends v1.

## Safe rollout ordering

Deploy in this order to avoid an outage:

1. **Enable `network.proxy_protocol: true` on gatekeeper first, and deploy it.** Because the listener fails open, connections without a PROXY header — which is every connection at this point, since the load balancer isn't sending one yet — fall back to the raw TCP peer address exactly as before. `/healthz` stays green throughout.
2. **Confirm gatekeeper is healthy and serving traffic** with `proxy_protocol` enabled but no header arriving yet.
3. **Update the backend service's `proxyHeader` to `PROXY_V1`.** Once the load balancer starts sending headers, gatekeeper parses them and `client_ip` starts reflecting real clients.

Reversing this order — turning on `proxyHeader: PROXY_V1` before gatekeeper understands it — sends a raw PROXY header into a listener that doesn't parse it. Gatekeeper would treat the header bytes as the start of an HTTP request or TLS handshake and reject the connection, which is why gatekeeper goes first.

## Security requirement

> **Warning:** `network.proxy_protocol` trusts the PROXY header from any peer that can reach the listener. A client that connects directly to gatekeeper's port — bypassing the load balancer — can prepend its own PROXY header and forge its logged `client_ip`.

Only enable `proxy_protocol` when the port is reachable solely through the load balancer, and never use `client_ip` for security decisions — it's a logging convenience, not an authenticated identity. Restrict direct access to the port with a firewall rule that allows only the load balancer's and health check's source ranges:

```bash
gcloud compute firewall-rules create allow-gatekeeper-lb \
  --network=default \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:9080 \
  --source-ranges=130.211.0.0/22,35.191.0.0/16 \
  --target-tags=gatekeeper
```

The Postgres data-plane listener does not parse PROXY protocol headers — it is a separate listener and port, unaffected by this setting.

## Verification

Before enabling `proxy_protocol`, the canonical log line shows the load balancer's address as `client_ip`:

```text
level=INFO msg=request http_host=api.github.com client_ip=35.191.12.34 credential_injected=true
```

After enabling `network.proxy_protocol: true` on gatekeeper and `--proxy-header=PROXY_V1` on the backend service, the same request logs the real client:

```text
level=INFO msg=request http_host=api.github.com client_ip=203.0.113.7 credential_injected=true
```

A connection whose PROXY header fails to parse — a malformed v1 line or truncated v2 binary header — is dropped, and gatekeeper logs one line at `DEBUG`:

```text
level=DEBUG msg="dropping connection: malformed PROXY protocol header" peer=35.191.12.34:51422 err="proxyproto: ..."
```

## Health check notes

Gatekeeper's fail-open policy means the load balancer's HTTP health check against `/healthz` keeps working whether or not it carries a PROXY header: a probe that includes one is parsed normally, and a probe that doesn't falls back to the raw TCP peer address. Neither case is rejected, so flipping `proxy_protocol` on and off does not require a matching change to the health check configuration.

## Next steps

- [Observability](../concepts/06-observability.md) — how `client_ip` and other request attributes flow into logs, traces, and metrics
- [Config file](../reference/02-config-file.md) — full `network.proxy_protocol` field reference
- [OpenTelemetry](./08-opentelemetry.md) — correlate `client_ip` with traces and metrics
