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

| Section | Description |
|---------|-------------|
| `proxy` | Proxy listener address and authentication |
| `tls` | CA certificate for TLS interception |
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
    prefix: "token "
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

Label for logging and metrics. Does not affect credential injection behavior.

```yaml
credentials:
  - host: api.github.com
    grant: github
```

- **Type:** `string`
- **Required:** No
- **Default:** —

Grant names appear in the `grants` field of canonical request log lines and in OTel span attributes.

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

The `type` field selects the source backend. Each type accepts different fields. Extraneous fields for the selected type cause a validation error.

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
