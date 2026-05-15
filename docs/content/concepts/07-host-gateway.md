---
title: "Host Gateway"
description: "How Gatekeeper maps synthetic hostnames to host machine IPs, enabling containers to reach host services with credential injection."
keywords: ["gatekeeper", "host gateway", "container networking", "loopback equivalence"]
---

# Host Gateway

Gatekeeper's host gateway maps a synthetic hostname (used inside containers) to the host machine's IP address. This enables containers to reach services running on the host while maintaining credential injection and network policy enforcement.

## What Host Gateway Solves

Containers cannot reliably address the host machine. Docker provides `host.docker.internal`, but this is not universal — it resolves differently across platforms and may not exist in all runtimes. The host gateway gives each run a consistent hostname that resolves to the host machine's actual IP, allowing gatekeeper to intercept, authorize, and forward the traffic.

The `RunContextData` struct carries two fields for this:

| Field | Purpose |
|---|---|
| `HostGateway` | The synthetic hostname the container uses (e.g., `moat-host-gateway`) |
| `HostGatewayIP` | The actual IP address to forward traffic to |

When a CONNECT request targets the gateway hostname, gatekeeper rewrites the dial address from the synthetic hostname to `HostGatewayIP` before establishing the upstream connection.

## Synthetic Hostname Mapping

The container's `/etc/hosts` file maps the synthetic hostname to the proxy's IP. When the container connects to `moat-host-gateway:8080`, the request routes to gatekeeper. Gatekeeper recognizes the hostname as a gateway address, applies network policy, and dials the real host IP.

```bash
# Inside the container
curl http://moat-host-gateway:8080/api/data
```

Gatekeeper intercepts this as a CONNECT (for HTTPS) or plain HTTP request, checks that port 8080 is in `AllowedHostPorts`, and forwards to `{HostGatewayIP}:8080`.

## Loopback Equivalence

When `HostGatewayIP` resolves to a loopback address (`127.0.0.1`, `::1`), gatekeeper treats `localhost`, `127.0.0.1`, and `::1` as equivalent to the gateway hostname. This prevents a bypass: without this equivalence, a container can connect directly to `localhost` or `127.0.0.1` to skip network policy that only checks the gateway hostname.

The equivalence check follows this logic:

1. If `HostGatewayIP` is set, parse it and check `IsLoopback()`.
2. If `HostGatewayIP` is empty, check whether `HostGateway` itself is a loopback IP.
3. If `HostGateway` is a non-IP hostname (synthetic), assume loopback — synthetic hostnames are injected into container `/etc/hosts` pointing at the host, which is loopback from the proxy's perspective.

When loopback equivalence is active, credentials configured for the gateway hostname also match requests to `localhost`, `127.0.0.1`, and `::1`.

## Port-Based Access Control

Host gateway traffic is not governed by the standard allow/deny list. Instead, each destination port must be explicitly listed in `AllowedHostPorts`. A request to `moat-host-gateway:3000` is allowed only if port 3000 appears in the run's allowed ports.

This is a security boundary. Without port restrictions, a container can reach any service on the host — databases, admin interfaces, other proxies. The port allowlist limits exposure to explicitly configured services.

The `AllowedHostPorts` field in `RunContextData` lists the permitted ports. This is configured programmatically — not through `gatekeeper.yaml`. Moat sets this field when registering runs.

Requests to unlisted ports receive a `407` response with an `X-Moat-Blocked: host-service` header and a message indicating which port was denied and how to allow it.

## Credential Matching Across Gateway and Loopback

Credentials configured for the gateway hostname apply to all equivalent addresses when loopback equivalence is active. If a credential targets `moat-host-gateway` and the gateway routes to loopback, that credential also applies to requests targeting `localhost`, `127.0.0.1`, or `::1` on an allowed port.

The proxy resolves credentials by host after rewriting the dial address but before forwarding. The hostname used for credential lookup is the original hostname from the client's request (the gateway hostname or loopback alias), not the rewritten `HostGatewayIP`.
