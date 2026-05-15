---
title: "TLS Interception"
description: "How Gatekeeper terminates TLS connections, generates per-host certificates, and enables credential injection into HTTPS requests."
keywords: ["gatekeeper", "TLS interception", "MITM proxy", "certificate generation"]
---

# TLS Interception

Gatekeeper is a TLS-intercepting proxy. It terminates the client's TLS connection, reads the plaintext HTTP request, injects credentials, and forwards the request to the real server over a separate TLS connection. This is a man-in-the-middle architecture — the client must trust gatekeeper's CA certificate.

This page explains why TLS interception is necessary and how the certificate chain works.

## Why MITM Is Necessary

HTTP proxies see CONNECT tunnels as opaque byte streams. Without interception, the proxy knows the destination host but cannot read or modify the encrypted HTTP request inside the tunnel. Credential injection requires access to the plaintext request headers — so gatekeeper must terminate the client's TLS, read the request, inject headers, and re-encrypt for the upstream server.

## The CONNECT Flow

When a client sends an HTTPS request through gatekeeper, the flow has five stages:

1. **CONNECT request.** The client sends `CONNECT api.github.com:443 HTTP/1.1` to the proxy.
2. **Network policy check.** Gatekeeper evaluates the target host against allow/deny rules. If denied, a `407` response is returned immediately.
3. **Tunnel establishment.** Gatekeeper responds with `HTTP/1.1 200 Connection Established` and hijacks the raw TCP connection.
4. **TLS handshake with the client.** Gatekeeper generates a certificate for `api.github.com` signed by its CA, then performs a TLS handshake as the server. The client validates the certificate against the CA it trusts.
5. **Request interception.** Gatekeeper reads the plaintext HTTP request, injects credential headers, opens a separate TLS connection to the real `api.github.com`, and forwards the request.

```text
Client                    Gatekeeper                   api.github.com
  |--- CONNECT :443 ------->|                               |
  |<-- 200 Connected --------|                               |
  |--- TLS handshake ------->| (CA-signed cert)              |
  |--- GET /repos (plain) -->|                               |
  |                          |-- inject Authorization ------>|
  |                          |--- TLS handshake ------------>|
  |                          |--- GET /repos (encrypted) --->|
  |                          |<-- 200 OK --------------------|
  |<-- 200 OK ---------------|                               |
```

## Two Separate TLS Connections

The proxy maintains two independent TLS sessions per intercepted request:

| Connection | Endpoint | Certificate |
|---|---|---|
| Client-side | Client to gatekeeper | Dynamically generated, signed by gatekeeper's CA |
| Server-side | Gatekeeper to origin | Origin server's real certificate, verified against system roots |

These connections use independent keys and cipher suites. The client never sees the origin server's certificate — it only sees gatekeeper's generated certificate.

## Per-Host Certificate Generation

When gatekeeper intercepts a CONNECT tunnel for a host, `CA.GenerateCert` creates a certificate on the fly:

- The certificate's `CommonName` and SAN (Subject Alternative Name) match the target host.
- IP addresses are added as IP SANs; hostnames as DNS SANs.
- Each certificate is signed by gatekeeper's CA private key.
- Generated certificates are cached in memory by hostname to avoid repeated key generation.
- Leaf certificates are valid for one year. The CA certificate is valid for ten years.

The CA supports RSA, EC, and Ed25519 private keys via PKCS1, PKCS8, and SEC 1 formats.

## Why the Client Must Trust the CA

The dynamically generated certificates are not signed by a public CA. Clients reject them unless they explicitly trust gatekeeper's CA certificate. In container environments, the CA certificate is mounted into the container's trust store (e.g., `/etc/ssl/certs/`). Without this, every HTTPS request through the proxy fails with a certificate verification error.

> **Note:** Applications with certificate pinning will fail even with the CA trusted. This is expected — interception requires replacing the origin certificate.

## Non-CONNECT Relay Path

Plain HTTP requests (no TLS) bypass the interception flow entirely. Gatekeeper reads the request directly, injects credentials, and forwards it using a standard `http.Transport`. No certificate generation occurs.

The relay path (`/relay/{name}/{path}`) handles a special case: when the target host is in `NO_PROXY` (e.g., a host-side service reachable at the same address as the proxy), direct connections bypass the proxy. The relay endpoint accepts direct HTTP requests, injects credentials, and forwards to the configured target URL.

## Without a CA

When no CA is configured, gatekeeper cannot perform TLS interception. CONNECT tunnels pass through as opaque TCP streams — the proxy relays bytes without reading them. Credential injection is impossible for HTTPS traffic in this mode. Per-path network rules also cannot be enforced, since the proxy cannot see the HTTP request inside the encrypted tunnel.
