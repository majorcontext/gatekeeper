---
title: "Postgres Data Plane with Neon"
description: "Run gatekeeper's Postgres listener against a Neon project so clients connect with a run token instead of a database password."
keywords: ["gatekeeper", "postgres", "neon", "database proxy", "credential injection"]
---

# Postgres data plane with Neon

Run gatekeeper's Postgres listener against a Neon project. Clients connect with their run token in place of the database password; gatekeeper resolves the real per-branch password from the Neon API and completes the upstream connection.

See [Postgres Data Plane](../concepts/08-postgres-data-plane.md) for how the listener works internally.

## Prerequisites

- CA certificate generated ([CA Setup](./01-ca-setup.md)) — the Postgres listener requires it for TLS termination
- A Neon API key ([neon.tech/docs/manage/api-keys](https://neon.tech/docs/manage/api-keys))
- A Neon project with at least one branch and compute endpoint

## Configuration

Add a `postgres` listener block and a credential with a `postgres` resolver to `gatekeeper.yaml`:

```yaml
proxy:
  host: 127.0.0.1
  port: 9080
  auth_token: local-test-token

postgres:
  port: 5432
  host: 127.0.0.1

tls:
  ca_cert: ca.crt
  ca_key: ca.key

credentials:
  - host: "*.neon.tech"
    grant: neon-databases
    postgres:
      resolver: neon
    source:
      type: env
      var: NEON_API_KEY

network:
  policy: strict
  allow:
    - "*.neon.tech"

log:
  level: info
  format: text
```

| Field             | Required | Description                                                             |
|-------------------|----------|---------------------------------------------------------------------------|
| `postgres.port`   | Yes      | Port for the Postgres-protocol listener                                   |
| `postgres.host`   | No       | Bind address. Defaults to the same host as `proxy.host`                   |
| `credentials[].postgres.resolver` | Yes | `neon` or `static`                                        |
| `credentials[].postgres.project`  | No  | Neon project ID; required for project-scoped API keys                |

Omit the top-level `postgres` block to run gatekeeper without the data plane. A `postgres` credential entry bypasses the `header`/`prefix`/`format` fields used for HTTP credential injection — the listener authenticates with SCRAM-SHA-256, not an HTTP header.

Gatekeeper refuses to start if `postgres` is configured without `tls.ca_cert` and `tls.ca_key`: the listener terminates client TLS with a CA-minted certificate for the connection's SNI hostname, so there is no way to run it without a CA.

## Account-scoped vs. project-scoped API keys

Gatekeeper locates the project and branch that own a Neon endpoint before it can fetch that branch's password. How it does this depends on the API key's scope:

- **Account-scoped key** — Gatekeeper lists the key's projects (`GET /api/v2/projects`) and searches each project's endpoints for a match. No further configuration needed.
- **Project-scoped key** — Neon's project-scoped keys cannot call `/api/v2/projects`; a listing attempt is rejected. Set `project` on the credential's `postgres` block so gatekeeper queries that project directly instead of enumerating:

```yaml
credentials:
  - host: "*.neon.tech"
    grant: neon-databases
    postgres:
      resolver: neon
      project: falling-river-38863773
    source:
      type: env
      var: NEON_API_KEY
```

With an account-scoped key and more than 99 projects, the project listing is not paginated — gatekeeper logs a warning and returns an error naming the endpoint if it isn't found on the first page. Setting `project` avoids the enumeration (and the pagination limit) entirely, so it's the better choice even for account-scoped keys once you know which project a credential targets.

## How clients connect

The client's Postgres password is gatekeeper's run token — the same token used for `Proxy-Authorization` on the HTTP plane. In standalone mode that's the static `proxy.auth_token`; nothing else about the connection string changes from a direct Neon connection except the password value.

`sslmode=require` is mandatory. The run token is read only inside gatekeeper's TLS tunnel — a plaintext connection is refused before any credential is requested — so a client that skips TLS never gets to authenticate.

```bash
PGPASSWORD=local-test-token psql \
  "host=ep-cool-darkness-123456.us-east-2.aws.neon.tech \
   dbname=neondb user=neondb_owner sslmode=require"
```

For this to reach gatekeeper instead of Neon directly, `ep-cool-darkness-123456.us-east-2.aws.neon.tech` must resolve to the host running gatekeeper. Arranging that DNS is outside gatekeeper's scope — an embedder typically does it per run. See the local-testing trick below if you don't want to touch DNS.

## Local testing without DNS

libpq accepts `host` and `hostaddr` as separate connection parameters. When both are set, `hostaddr` is used for the actual TCP connection — no DNS lookup occurs — while `host` still supplies the TLS Server Name Indication and the value checked during certificate verification.

Gatekeeper's Postgres listener routes entirely on SNI, so this combination points the TCP connection at gatekeeper without editing `/etc/hosts` or resolvers, while still handing gatekeeper the real Neon endpoint hostname to route on:

```bash
PGPASSWORD=local-test-token psql \
  "host=ep-cool-darkness-123456.us-east-2.aws.neon.tech \
   hostaddr=127.0.0.1 \
   dbname=neondb user=neondb_owner sslmode=require"
```

`host` never touches DNS here — it only sets SNI — so this works even for endpoint hostnames that don't resolve from your machine at all.

## Tracing a connection to its origin

Set `application_name` to identify which caller opened a given connection in gatekeeper's logs:

```bash
PGAPPNAME=box-abc123 PGPASSWORD=local-test-token psql \
  "host=ep-cool-darkness-123456.us-east-2.aws.neon.tech \
   dbname=neondb user=neondb_owner sslmode=require"
```

Gatekeeper captures it (sanitized) as `application_name` on the canonical log line, alongside the authenticated `run_id`. It's forwarded upstream unchanged too, so it also shows up in Neon's `pg_stat_activity` — but unlike `run_id`, it's client-set and not authenticated. See [Tracing a connection to its origin](../concepts/08-postgres-data-plane.md#tracing-a-connection-to-its-origin).

## Static resolver alternative

For a non-Neon Postgres server, or to pin a single fixed password instead of calling the Neon API, use `resolver: static`. The source supplies the password directly and gatekeeper fetches it once at startup:

```yaml
credentials:
  - host: db.internal
    grant: internal-db
    postgres:
      resolver: static
    source:
      type: env
      var: DB_PASSWORD
```

`static` does not re-fetch: rotating the password requires a restart, the same limitation as the `env`/`static`/secret-manager sources on the HTTP plane.

## Verification

Start gatekeeper:

```bash
gatekeeper --config gatekeeper.yaml
```

Connect with `psql` (adjust `host`/`hostaddr`/`dbname`/`user` for your project):

```bash
PGPASSWORD=local-test-token psql \
  "host=ep-cool-darkness-123456.us-east-2.aws.neon.tech \
   hostaddr=127.0.0.1 \
   dbname=neondb user=neondb_owner sslmode=require" \
  -c "select 1"
```

The proxy log confirms the connection and credential resolution:

```text
level=INFO msg=request http_method=STARTUP http_host=ep-cool-darkness-123456.us-east-2.aws.neon.tech proxy_type=postgres user_id=neondb_owner credential_injected=true grants=postgres:ep-cool-darkness-123456.us-east-2.aws.neon.tech request_messages=4 response_messages=6
```

> **Note:** Some Neon projects restrict access with an IP allowlist. If gatekeeper's egress IP isn't allowlisted, the upstream connection fails and the client sees a generic `could not authenticate to upstream database` error — identical to what a genuinely wrong password produces, since gatekeeper never echoes upstream failure detail to the client. Check the debug log (`postgres upstream connection failed`, logged with host and user but never the password) and the project's IP Allow settings in the Neon console.

## Next steps

- [Postgres Data Plane](../concepts/08-postgres-data-plane.md) — connection lifecycle, SNI routing, and security properties
- [Network Lockdown](./07-network-lockdown.md) — restrict proxy traffic to specific hosts
