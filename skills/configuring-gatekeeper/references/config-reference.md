# Config reference

Complete `gatekeeper.yaml` schema. Pass it with `--config` (or set
`GATEKEEPER_CONFIG`).

## Top level

```yaml
proxy:        { ... }   # required: listener + optional client auth
tls:          { ... }   # CA for TLS interception (required for interception + Postgres)
credentials:  [ ... ]   # what to inject and where
network:      { ... }   # egress policy
log:          { ... }   # logging
postgres:     { ... }   # optional: Postgres data-plane listener
```

## proxy

| Field        | Required | Default | Description                                              |
|--------------|----------|---------|----------------------------------------------------------|
| `host`       | yes      | —       | Bind address. `127.0.0.1` for local; `0.0.0.0` to accept clients on other hosts. |
| `port`       | yes      | —       | Listener port, e.g. `9080`.                              |
| `auth_token` | no       | —       | Token clients must present via `Proxy-Authorization`. Also used as the Postgres password on the data plane. Constant-time compared. |

## tls

| Field     | Required | Default | Description                          |
|-----------|----------|---------|--------------------------------------|
| `ca_cert` | yes\*    | —       | Path to the CA certificate (PEM).    |
| `ca_key`  | yes\*    | —       | Path to the CA private key (PEM).    |

\* Required for TLS interception and for the Postgres data plane. See
[ca-setup.md](ca-setup.md).

## credentials[]

| Field      | Required | Default         | Description                                              |
|------------|----------|-----------------|----------------------------------------------------------|
| `host`     | yes      | —               | Target host; matched **exactly**, port-insensitive. Not a wildcard — use `network.allow`/postgres for globs. |
| `header`   | no       | `Authorization` | Header to inject.                                         |
| `prefix`   | no       | auto-detected   | **Authorization only.** Scheme word (`Bearer`, `token`); or Basic username when `format: basic`. Ignored for other headers (value injected verbatim). |
| `format`   | no       | `""`            | **Authorization only.** `""` (prefix scheme) or `basic` (HTTP Basic). Any other header with `format: basic` is a config error. |
| `grant`    | no       | —               | Label for logs only. Never the secret.                   |
| `source`   | yes      | —               | Credential source — see [credential-sources.md](credential-sources.md). |
| `postgres` | no       | —               | Postgres resolver config — see [postgres-data-plane.md](postgres-data-plane.md). |

## network

| Field    | Required | Default      | Description                                       |
|----------|----------|--------------|---------------------------------------------------|
| `policy` | no       | `permissive` | `permissive` (allow all) or `strict` (deny all).  |
| `allow`  | no       | —            | Host patterns allowed under `strict`.             |

See [network-policy.md](network-policy.md).

## log

| Field             | Required | Default  | Description                                                  |
|-------------------|----------|----------|-------------------------------------------------------------|
| `level`           | no       | `info`   | `debug`, `info`, `warn`, `error`.                            |
| `format`          | no       | `text`   | `text` or `json`.                                            |
| `output`          | no       | `stderr` | `stderr`, `stdout`, or a file path.                          |
| `capture_headers` | no       | —        | Request headers to log and strip before forwarding.         |

## postgres

| Field  | Required | Default        | Description                                  |
|--------|----------|----------------|----------------------------------------------|
| `port` | yes      | —              | Postgres listener port, e.g. `5432`.         |
| `host` | no       | the proxy host | Bind address for the Postgres listener.      |

Omit the whole `postgres` block to disable the data plane. See
[postgres-data-plane.md](postgres-data-plane.md).

## CLI and environment

- `gatekeeper --config <path>` — start the proxy. If `--config` is omitted,
  `GATEKEEPER_CONFIG` is used; if neither is set, it errors.
- Health check: `GET /healthz` on the proxy port → `{"status":"ok"}`.
- Signals: `SIGTERM`/`SIGINT` trigger graceful shutdown (5s timeout).
- Exit codes: `0` clean shutdown; `1` startup error.
- **OpenTelemetry**: configured entirely via standard `OTEL_*` env vars (e.g.
  `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`). No YAML knobs.
