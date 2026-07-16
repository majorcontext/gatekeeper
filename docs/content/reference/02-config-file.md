---
title: "Config file"
description: "Complete reference for gatekeeper.yaml fields including proxy, TLS, credentials, network policy, and logging configuration."
keywords: ["gatekeeper", "config file", "YAML", "configuration reference"]
---

# Config file

gatekeeper.yaml defines proxy settings, TLS configuration, credentials, network policy, and logging.

## Top-level structure

```yaml
proxy:
  host: 127.0.0.1
  port: 8080
  auth_token: my-secret-token

tls:
  ca_cert: ca.pem
  ca_key: ca-key.pem

postgres:
  host: 127.0.0.1
  port: 5432

credentials:
  - host: api.github.com
    source:
      type: env
      var: GITHUB_TOKEN

network:
  policy: strict
  allow:
    - "*.github.com"

log:
  level: info
  format: json
  output: stderr
```

PROXY protocol (recovering the real client IP behind a TCP load balancer) is configured per listener: `proxy.proxy_protocol` for the HTTP/CONNECT listener, `postgres.proxy_protocol` for the Postgres data-plane listener. See [proxy.proxy_protocol](#proxyproxy_protocol) and [postgres.proxy_protocol](#postgresproxy_protocol) below.

| Section | Description |
|---------|-------------|
| `proxy` | Proxy listener address and authentication |
| `tls` | CA certificate for TLS interception |
| `postgres` | Postgres data-plane listener (optional) |
| `credentials` | Credential injection rules |
| `network` | Network access policy |
| `log` | Logging configuration |

---

## proxy

Configures the proxy listener.

### proxy.port

TCP port the proxy listens on.

```yaml
proxy:
  port: 8080
```

- **Type:** `int`
- **Required:** No
- **Default:** `0` (random available port)

If this equals `postgres.port` (and `proxy.host` equals `postgres.host`, after defaults), the two listeners collapse onto one shared physical listener instead of binding separately — see [Sharing one listener with the HTTP proxy](#sharing-one-listener-with-the-http-proxy) under `postgres` below. There is no separate flag for this: setting both ports the same **is** the declaration.

### proxy.host

Bind address for the proxy listener.

```yaml
proxy:
  host: 0.0.0.0
```

- **Type:** `string`
- **Required:** No
- **Default:** `"127.0.0.1"`

Binding to `127.0.0.1` prevents accidental exposure on all interfaces. Set to `0.0.0.0` when the proxy must be reachable from containers via a gateway IP.

### proxy.auth_token

Static token clients must provide via `Proxy-Authorization` header to access the proxy.

```yaml
proxy:
  auth_token: my-secret-token
```

- **Type:** `string`
- **Required:** No
- **Default:** — (no authentication required)

When set, clients authenticate by including the token in the proxy URL:

```bash
export HTTP_PROXY=http://user:my-secret-token@127.0.0.1:8080
```

The username portion is ignored. The token comparison is constant-time to prevent timing attacks.

### proxy.proxy_protocol

Parse PROXY protocol v1/v2 headers on the HTTP/CONNECT proxy listener to recover the real client address behind a TCP-terminating load balancer.

```yaml
proxy:
  proxy_protocol: true
```

- **Type:** `bool`
- **Required:** No
- **Default:** `false`

When enabled, each inbound connection to the proxy listener is checked for a leading PROXY protocol header — as prepended by a TCP load balancer such as GCP's global TCP Proxy load balancer — and, if present, the header's advertised source address replaces the raw TCP peer address as the connection's client address. This flows through to the `client_ip` request-log attribute on every request path, including CONNECT-intercepted TLS traffic.

Connections that open without a PROXY header, or that don't send one within a 10s read timeout, fall back to the raw TCP peer address instead of being rejected (fail-open), so load balancer health checks and direct probes of the port keep working.

Because the header is honored from any peer, a client that can reach the listener directly (bypassing the load balancer) can forge its logged `client_ip` by prepending its own PROXY header. Only enable this when the port is reachable solely through the load balancer, and never use `client_ip` for security decisions.

The Postgres data-plane listener has its own, independent toggle — see [postgres.proxy_protocol](#postgresproxy_protocol).

---

## tls

Configures the CA certificate used for TLS interception. Without a CA, CONNECT tunnels pass through without credential injection.

### tls.ca_cert

File path to the PEM-encoded CA certificate.

```yaml
tls:
  ca_cert: /etc/gatekeeper/ca.pem
```

- **Type:** `string`
- **Required:** No (but required for HTTPS credential injection)
- **Default:** —

### tls.ca_key

File path to the PEM-encoded CA private key.

```yaml
tls:
  ca_key: /etc/gatekeeper/ca-key.pem
```

- **Type:** `string`
- **Required:** No (but required for HTTPS credential injection)
- **Default:** —

Both `ca_cert` and `ca_key` must be set together. The proxy uses this CA to dynamically generate per-host certificates for TLS interception. Clients must trust this CA certificate.

---

## postgres

Configures the Postgres data-plane listener. Omit this section to run the HTTP proxy alone. When present, it requires a configured CA (`tls.ca_cert` and `tls.ca_key`); Gatekeeper refuses to start otherwise. See [Postgres Data Plane](../concepts/08-postgres-data-plane.md).

```yaml
postgres:
  host: 127.0.0.1
  port: 5432
```

### postgres.port

TCP port the Postgres listener binds to.

```yaml
postgres:
  port: 5432
```

- **Type:** `integer`
- **Required:** Yes (when the `postgres` section is present)
- **Default:** —

### postgres.host

Address the Postgres listener binds to.

```yaml
postgres:
  host: 0.0.0.0
```

- **Type:** `string`
- **Required:** No
- **Default:** the `proxy.host` value

### postgres.proxy_protocol

Parse PROXY protocol v1/v2 headers on the Postgres data-plane listener to recover the real client address behind a TCP-terminating load balancer, mirroring [proxy.proxy_protocol](#proxyproxy_protocol) for this listener.

```yaml
postgres:
  proxy_protocol: true
```

- **Type:** `bool`
- **Required:** No
- **Default:** `false`

Semantics are identical to `proxy.proxy_protocol`, applied to this listener instead: each inbound connection is checked for a leading PROXY protocol header, and, if present, the header's advertised source address replaces the raw TCP peer address as the connection's client address (the `client_ip` request-log attribute and the `client_addr` field on a failed run-token authentication log line). Connections that open without a header, or that don't send one within a 10s read timeout, fall back to the raw TCP peer address instead of being rejected (fail-open). The PROXY header is always the first bytes on the wire, so it is parsed before the client's `SSLRequest` and the TLS handshake.

Because the header is honored from any peer, only enable this when the Postgres port is reachable solely through the load balancer, and never use `client_ip` for security decisions.

This is a separate toggle from `proxy.proxy_protocol` — enabling one does not enable the other, since the two listeners are typically fronted by different load balancers (or only one of them is exposed at all). **Exception:** when `postgres.port` equals `proxy.port` (see below), the two settings must agree.

### Sharing one listener with the HTTP proxy

When `postgres.port` equals `proxy.port` — and `proxy.host` and `postgres.host` are the same string, after their defaults are applied — gatekeeper multiplexes both planes onto **one** real listener instead of binding two. (The host comparison is a literal string match, not address resolution: `proxy.host: localhost` and `postgres.host: 127.0.0.1` are treated as *different* and rejected as an ambiguous bind rather than guessed to be equivalent.) Each accepted connection is classified by its first bytes: a recognized Postgres startup signature (`SSLRequest`, `GSSENCRequest`, or the v3 `StartupMessage`) routes to the Postgres data plane, and everything else — HTTP methods, the h2 preface — routes to the HTTP/CONNECT plane, unchanged. There is no dedicated config flag for this; the port equality itself is the trigger.

```yaml
proxy:
  host: 0.0.0.0
  port: 5432

postgres:
  port: 5432 # same host (defaulted from proxy.host) and same port as above -> shared listener
```

Gatekeeper refuses to start, with a fatal, descriptive error, in two situations once the ports are equal:

- **Different hosts.** `postgres.port == proxy.port` but the two configs' hosts (after defaults) don't match — there's only one socket to bind, and which address to use is ambiguous.
- **Mismatched `proxy_protocol`.** `postgres.proxy_protocol != proxy.proxy_protocol` — a single shared listener can only have one PROXY protocol setting. `proxy.proxy_protocol` is the setting actually applied; set both fields (or leave `postgres.proxy_protocol` unset, which mirrors `proxy.proxy_protocol`'s own default of `false`) so they agree.

Port `0` (letting the OS assign an ephemeral port) never triggers multiplexing on its own, even if both `proxy.port` and `postgres.port` are left unset — two independent ephemeral-port binds are not "the same port." Multiplexing requires an explicit, matching, non-zero port on both listeners.

If `postgres` isn't configured at all, or the two ports differ, gatekeeper binds two listeners exactly as it always has. See [Deploying behind a TCP load balancer](../guides/11-load-balancer-proxy-protocol.md#single-load-balancer-one-shared-port) for the full walkthrough, including PROXY protocol and health checks on the shared listener.

---

## credentials

A list of credential injection rules. Each entry maps a hostname to a credential source and the HTTP header to inject.

```yaml
credentials:
  - host: api.github.com
    header: Authorization
    prefix: Bearer
    grant: github
    source:
      type: env
      var: GITHUB_TOKEN
```

### credentials[].host

Hostname or glob pattern to match for credential injection.

```yaml
credentials:
  - host: api.github.com
```

- **Type:** `string`
- **Required:** Yes
- **Default:** —

Supports glob patterns (`*.github.com`). Port numbers are stripped before matching — `api.github.com:443` matches a rule for `api.github.com`.

### credentials[].header

HTTP header name to inject the credential into.

```yaml
credentials:
  - host: api.anthropic.com
    header: x-api-key
```

- **Type:** `string`
- **Required:** No
- **Default:** `"Authorization"`

### credentials[].prefix

Auth scheme prefix prepended to the credential value.

```yaml
credentials:
  - host: api.github.com
    prefix: "token"
```

- **Type:** `string`
- **Required:** No
- **Default:** — (auto-detected for `Authorization` header)

When the header is `Authorization` and no prefix is set, gatekeeper auto-detects the scheme from known token formats:

| Token prefix | Scheme |
|-------------|--------|
| `ghp_`, `ghs_` | `token` |
| `gho_`, `github_pat_` | `Bearer` |
| All others | `Bearer` |

If the credential value already contains a scheme (e.g., `Bearer xxx`), it is used as-is.

When `format` is `"basic"`, the `prefix` field is used as the Basic auth username instead.

### credentials[].format

Auth format for the `Authorization` header.

```yaml
credentials:
  - host: github.com
    format: basic
    prefix: x-access-token
```

- **Type:** `string`
- **Required:** No
- **Default:** — (scheme prefix mode)
- **Valid values:** `""`, `"basic"`

When set to `"basic"`, the credential is encoded as HTTP Basic authentication: `Authorization: Basic base64(prefix:value)`. The `prefix` field becomes the username and the credential value becomes the password. Only supported with the `Authorization` header.

### credentials[].grant

Label for logging and metrics.

```yaml
credentials:
  - host: api.github.com
    grant: github
```

- **Type:** `string`
- **Required:** No
- **Default:** —

Grant names appear in the `grants` field of canonical request log lines and in OTel span attributes.

Grant names normally have no effect on which credential is injected. The one exception: when multiple credentials targeting the same host share a header name, gatekeeper breaks the tie by grant name. If the client sent a placeholder value in that header, the credential with `grant: claude` wins (letting the client explicitly opt into that grant). Otherwise, for unprompted auto-injection, a non-`claude` grant wins over `claude`, so `claude` is only injected when the client explicitly requests it via a placeholder. This tie-break only matters when two or more credentials collide on the same host and header; with no collision, `grant` is purely a logging label.

### credentials[].source

Determines where the credential value comes from. See [Credential sources](./03-credential-sources.md) for all source types and their fields.

```yaml
credentials:
  - host: api.github.com
    source:
      type: env
      var: GITHUB_TOKEN
```

- **Type:** `object`
- **Required:** Yes
- **Default:** —

The `type` field selects the credential source. Each type accepts different fields. Extraneous fields for the selected type cause a validation error.

### credentials[].postgres

Marks a credential as a Postgres data-plane credential and selects how the upstream password is resolved. Requires the [`postgres`](#postgres) listener section. A credential with a `postgres` block injects database passwords on the Postgres listener instead of HTTP headers; the `header`, `prefix`, and `format` fields do not apply.

```yaml
credentials:
  - host: "*.neon.tech"
    postgres:
      resolver: neon
      project: falling-river-38863773
    source:
      type: env
      var: NEON_API_KEY
    grant: neon-databases
```

- **Type:** `object`
- **Required:** No
- **Default:** —

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `resolver` | `string` | Yes | `neon` (the source supplies a Neon API key; per-branch passwords are minted from the Neon API) or `static` (the source supplies a fixed password; works with any Postgres server, not just Neon). |
| `project` | `string` | No | Neon project ID. Required for project-scoped Neon API keys, which cannot list projects; omit it for account-scoped keys. |

See [Postgres Data Plane](../concepts/08-postgres-data-plane.md) for how resolution works.

---

## network

Configures network access policy for proxied requests.

### network.policy

Network policy mode.

```yaml
network:
  policy: strict
```

- **Type:** `string`
- **Required:** No
- **Default:** `"permissive"`
- **Valid values:** `"permissive"`, `"strict"`

| Policy | Behavior |
|--------|----------|
| `permissive` | All hosts allowed. `allow` list is ignored. |
| `strict` | Only hosts matching `allow` patterns are permitted. All other requests are denied. |

### network.allow

List of hostname glob patterns permitted under `strict` policy.

```yaml
network:
  policy: strict
  allow:
    - api.github.com
    - "*.anthropic.com"
    - "registry.npmjs.org"
```

- **Type:** `[]string`
- **Required:** No (only meaningful with `policy: strict`)
- **Default:** `[]`

Patterns support glob syntax. Port numbers are stripped before matching.

---

## log

Configures structured logging.

### log.level

Minimum log level.

```yaml
log:
  level: debug
```

- **Type:** `string`
- **Required:** No
- **Default:** `"info"`
- **Valid values:** `"debug"`, `"info"`, `"warn"`, `"error"`

### log.format

Log output format.

```yaml
log:
  format: json
```

- **Type:** `string`
- **Required:** No
- **Default:** `"text"`
- **Valid values:** `"json"`, `"text"`

### log.output

Log output destination.

```yaml
log:
  output: /var/log/gatekeeper.log
```

- **Type:** `string`
- **Required:** No
- **Default:** `"stderr"`
- **Valid values:** `"stderr"`, `"stdout"`, or a file path

When set to a file path, gatekeeper opens the file in append mode (creating it if needed) and closes it on shutdown.

### log.capture_headers

Request headers to capture in log output and strip before forwarding to the upstream server.

```yaml
log:
  capture_headers:
    - X-Request-Id
    - X-Correlation-Id
```

- **Type:** `[]string`
- **Required:** No
- **Default:** `[]`

Captured header values are included as structured log attributes (lowercased, hyphens replaced with underscores). Values longer than 256 characters are truncated at a valid UTF-8 boundary. The headers are removed from the request before it is forwarded upstream.
