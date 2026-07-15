---
title: "Deploying Behind a TCP Load Balancer"
description: "Recover the real client IP when gatekeeper runs behind a TCP-terminating load balancer, using PROXY protocol v1/v2."
keywords: ["gatekeeper", "load balancer", "PROXY protocol", "GCP", "client IP", "Postgres"]
---

# Deploying behind a TCP load balancer

Recover the real client IP when gatekeeper runs behind a TCP-terminating load balancer, such as GCP's global TCP Proxy load balancer. Without this, every request's `client_ip` log attribute shows the load balancer's hop instead of the actual client.

PROXY protocol support is configured per listener: `proxy.proxy_protocol` for the HTTP/CONNECT listener, and `postgres.proxy_protocol` for the [Postgres data-plane listener](../concepts/08-postgres-data-plane.md) (if configured). They are independent toggles — enabling one does not enable the other — because the two listeners are commonly fronted by different load balancers, or only one of them is exposed publicly at all. Everything below applies identically to both; the config examples call out where the field name differs.

## Prerequisites

- A working gatekeeper deployment (see [Config file](../reference/02-config-file.md))
- A TCP-terminating load balancer in front of the listener you're enabling this for, supporting PROXY protocol v1/v2 (for example, GCP's global TCP Proxy load balancer)
- `gcloud` configured against the target GCP project, if following the GCP walkthrough below

## Why client_ip shows the load balancer

A TCP-terminating load balancer ends the client's TCP connection at its own edge and opens a new connection to gatekeeper from its own front-end IP range. GCP's global TCP Proxy load balancer dials backends from `35.191.0.0/16`. By default, gatekeeper reads `client_ip` from the raw TCP peer address of the accepted connection — so every request logs the load balancer's address, never the real client, no matter which host actually opened the connection.

## How it works

1. The client connects to the load balancer's public IP.
2. The load balancer terminates that connection and opens a new TCP connection to gatekeeper, prepending a PROXY protocol v1 or v2 header that names the original client address.
3. When `proxy.proxy_protocol: true` (HTTP/CONNECT listener) or `postgres.proxy_protocol: true` (Postgres listener) is set, gatekeeper wraps that listener with PROXY protocol parsing. On each accepted connection, it reads the leading header (if present) and substitutes the header's advertised source address for the raw TCP peer address. Both listeners share the exact same parsing logic — fail-open policy, timeout, and malformed-header handling are identical.
4. That substituted address flows through to the `client_ip` request-log attribute on every request path — including CONNECT-intercepted TLS traffic on the HTTP listener, and the canonical log line and the run-token-authentication-failure log line on the Postgres listener. On the Postgres listener, the PROXY header is always the very first bytes on the wire, so it's parsed before the client's `SSLRequest` and the TLS handshake that follows it.
5. A connection that opens without a PROXY header — or that doesn't send one within a 10-second read timeout — falls back to the raw TCP peer address instead of being rejected. This fail-open behavior keeps load balancer health checks and direct probes of the port working.

## Enabling proxy_protocol

Set `proxy.proxy_protocol: true` in gatekeeper.yaml for the HTTP/CONNECT listener:

```yaml
proxy:
  host: 0.0.0.0
  port: 9080
  proxy_protocol: true

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

log:
  level: info
  format: text
```

`proxy.host` is bound to `0.0.0.0` here because the listener must be reachable from the load balancer, which is not running on the same host. See [Security Requirement](#security-requirement) below before deploying this configuration.

If gatekeeper's Postgres data-plane listener is also fronted by a TCP-terminating load balancer, enable it there independently with `postgres.proxy_protocol: true`:

```yaml
postgres:
  host: 0.0.0.0
  port: 5432
  proxy_protocol: true
```

## Configuring the GCP backend service

Enabling `proxy_protocol` on gatekeeper is only half the change — the load balancer must also be told to send the header. For a global TCP Proxy load balancer, this is the backend service's `proxyHeader` field. Configure this on whichever backend service fronts the listener you enabled — the HTTP/CONNECT port, the Postgres port, or both, if both are load-balanced.

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

The Postgres listener's backend service follows the same pattern, just pointed at the Postgres port (5432 by default) with a TCP health check instead of an HTTP one against `/healthz` — the Postgres listener has no HTTP health endpoint; a bare TCP connect check is sufficient, since the listener always answers the Postgres `SSLRequest` preamble.

## Safe rollout ordering

Deploy in this order to avoid an outage, for each listener you're enabling:

1. **Enable `proxy_protocol: true` (`proxy.proxy_protocol` or `postgres.proxy_protocol`) on gatekeeper first, and deploy it.** Because the listener fails open, connections without a PROXY header — which is every connection at this point, since the load balancer isn't sending one yet — fall back to the raw TCP peer address exactly as before. `/healthz` (HTTP listener) or a plain TCP connect (Postgres listener) stays green throughout.
2. **Confirm gatekeeper is healthy and serving traffic** with `proxy_protocol` enabled but no header arriving yet.
3. **Update the backend service's `proxyHeader` to `PROXY_V1`.** Once the load balancer starts sending headers, gatekeeper parses them and `client_ip` starts reflecting real clients.

Reversing this order — turning on `proxyHeader: PROXY_V1` before gatekeeper understands it — sends a raw PROXY header into a listener that doesn't parse it. On the HTTP listener, gatekeeper would treat the header bytes as the start of an HTTP request and reject the connection; on the Postgres listener, it would corrupt the `SSLRequest` preamble and the connection would be dropped. Either way, gatekeeper goes first.

If both listeners are load-balanced, roll them out independently, one at a time — enabling `proxy.proxy_protocol` has no effect on the Postgres listener's behavior, and vice versa.

## Security requirement

> **Warning:** `proxy_protocol` trusts the PROXY header from any peer that can reach the listener. A client that connects directly to gatekeeper's port — bypassing the load balancer — can prepend its own PROXY header and forge its logged `client_ip`.

Only enable `proxy_protocol` on a listener when its port is reachable solely through the load balancer, and never use `client_ip` for security decisions — it's a logging convenience, not an authenticated identity. Restrict direct access to the port with a firewall rule that allows only the load balancer's and health check's source ranges:

```bash
gcloud compute firewall-rules create allow-gatekeeper-lb \
  --network=default \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:9080,tcp:5432 \
  --source-ranges=130.211.0.0/22,35.191.0.0/16 \
  --target-tags=gatekeeper
```

Adjust the `tcp:` ports to whichever listeners you've fronted with the load balancer — omit 5432 if the Postgres listener isn't load-balanced (or isn't configured at all).

## Verification

Before enabling `proxy_protocol`, the canonical log line shows the load balancer's address as `client_ip`:

```text
level=INFO msg=request http_host=api.github.com client_ip=35.191.12.34 credential_injected=true
```

After enabling `proxy.proxy_protocol: true` on gatekeeper and `--proxy-header=PROXY_V1` on the backend service, the same request logs the real client:

```text
level=INFO msg=request http_host=api.github.com client_ip=203.0.113.7 credential_injected=true
```

The Postgres listener's canonical log line behaves the same way once `postgres.proxy_protocol: true` is set and the fronting load balancer sends the header:

```text
level=INFO msg=request proxy_type=postgres client_ip=203.0.113.7 credential_injected=true
```

A connection whose PROXY header fails to parse — a malformed v1 line or truncated v2 binary header — is dropped, and gatekeeper logs one line at `DEBUG`, on either listener:

```text
level=DEBUG msg="dropping connection: malformed PROXY protocol header" peer=35.191.12.34:51422 err="proxyproto: ..."
```

## Health check notes

Gatekeeper's fail-open policy means a load balancer health check keeps working whether or not it carries a PROXY header: a probe that includes one is parsed normally, and a probe that doesn't falls back to the raw TCP peer address. Neither case is rejected, so flipping `proxy_protocol` on and off does not require a matching change to the health check configuration. This holds for both the HTTP listener's `/healthz` endpoint and a bare TCP connect check against the Postgres listener.

## Next steps

- [Postgres data plane](../concepts/08-postgres-data-plane.md) — how the Postgres listener authenticates clients and resolves upstream credentials
- [Observability](../concepts/06-observability.md) — how `client_ip` and other request attributes flow into logs, traces, and metrics
- [Config file](../reference/02-config-file.md) — full `proxy.proxy_protocol` and `postgres.proxy_protocol` field reference
- [OpenTelemetry](./08-opentelemetry.md) — correlate `client_ip` with traces and metrics
