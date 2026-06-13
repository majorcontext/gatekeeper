# Postgres data plane (Neon)

Gatekeeper can run a **second listener that speaks the Postgres wire protocol**,
letting a client connect to a database with *only a run token* — no database
password ever enters the sandbox.

How it works: the client connects to the real database hostname and sends its
run token (or the proxy `auth_token`) **as the Postgres password**. Gatekeeper
terminates TLS with a CA-minted cert, reads the target endpoint from the **TLS
SNI**, resolves the real password, completes SCRAM-SHA-256 upstream, and relays
the connection.

```
client ──TLS(token as password)──▶ gatekeeper ──TLS(SCRAM, real password)──▶ Neon
         SNI: ep-...neon.tech                    resolved per-branch via Neon API
```

## Requirements (read first)

- **A CA is mandatory** (`tls.ca_cert` + `tls.ca_key`) — Gatekeeper errors at
  startup without it. See [ca-setup.md](ca-setup.md).
- **`sslmode=require`** on the client — the token is only read inside the TLS
  tunnel; plaintext connections are refused.
- **DNS routing is the embedder's job.** The target endpoint travels in the SNI,
  so `*.neon.tech` must resolve to Gatekeeper inside the client's network. For
  local testing, add the endpoint to `/etc/hosts` pointing at `127.0.0.1`.
- The v1 data plane is a **blind relay routed solely on SNI** — no SQL-level
  inspection.

## Config

```yaml
proxy:
  host: 127.0.0.1
  port: 9080
  auth_token: local-test-token   # client presents this as the Postgres password

postgres:                        # omit this block to disable the data plane
  host: 127.0.0.1                # optional; defaults to the proxy host
  port: 5432

tls:
  ca_cert: ca.crt
  ca_key: ca.key

credentials:
  - host: "*.neon.tech"
    postgres:
      resolver: neon
      # project: falling-river-38863773   # only for project-scoped Neon keys
    source:
      type: env
      var: NEON_API_KEY
    grant: neon-databases

network:
  policy: strict
  allow:
    - "*.neon.tech"
```

## Resolvers

- **`neon`** — the `source` supplies a **Neon API key**; Gatekeeper mints
  per-branch passwords from the Neon API and caches them with a TTL.
  - An **account-scoped** key needs no `project` — Gatekeeper discovers which
    project owns an endpoint.
  - A **project-scoped** key (least privilege) cannot list projects — set
    `postgres.project` to the project ID so Gatekeeper queries it directly.
- **`static`** — the `source` supplies a fixed password directly. For non-Neon
  Postgres or testing:

  ```yaml
  - host: "db.internal"
    postgres:
      resolver: static
    source:
      type: env
      var: DB_PASSWORD
    grant: internal-db
  ```

## Connect

Once DNS routes the endpoint to Gatekeeper, connect with the run token as the
password:

```bash
PGPASSWORD=<run-token> psql \
  "host=ep-cool-darkness-123456.us-east-2.aws.neon.tech \
   dbname=neondb user=neondb_owner sslmode=require"
```

The token travels as a cleartext password but only inside Gatekeeper's own TLS
tunnel — the same trust model as `Proxy-Authorization` on the HTTP plane. An
embedder (e.g. Moat) typically sets `PGPASSWORD` in the container so the token
never appears in the agent's command line.
