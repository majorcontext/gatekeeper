# Postgres Data Plane with Neon Credential Resolution

**Date:** 2026-06-11
**Status:** Validated design, not yet implemented

## Motivation

Today a sandboxed agent that needs Postgres holds real secrets: a Neon
connection URL and a proxy password. An agent that reads its own environment
can exfiltrate both and connect to Neon from anywhere; an IP allowlist is the
only backstop.

This design removes every database secret from the sandbox. The agent holds
only its per-run gatekeeper token — useless outside the sandbox, dead when the
run ends, and worthless against Neon directly. The Neon API key and all branch
passwords live only in gatekeeper's memory on the host. Every database
connection flows through one audited, policy-enforced chokepoint.

Residual risk: an agent can still read data through the proxy — that is its
job — so exfiltration over *allowed* channels remains. The strict network
allowlist bounds that.

## Goals

- Agents connect to arbitrary Neon projects and branches, including branches
  created mid-run, with no pre-enumeration and no secrets in the sandbox.
- The data plane composes with the existing control plane: agents manage
  projects and branches through the Neon MCP server (via the MCP relay, which
  injects the Neon API key), then connect to the resulting endpoints over
  Postgres. Both planes share one secret: the Neon API key.
- Per-run context scoping, network policy, and audit logging work exactly as
  they do for the HTTP plane.

## How Existing Postgres Proxies Inform This Design

Every Postgres proxy answers two questions: **routing** (which upstream?) and
**auth substitution** (client proves a weak identity to the proxy; the proxy
proves the real identity upstream). pgbouncer routes by database name from a
static config — it cannot reach arbitrary targets. Neon's own proxy routes by
**TLS SNI**: the endpoint ID rides in the hostname. Cloud SQL Auth Proxy uses
one local port per instance. Arbitrary targets require the target to travel on
the connection itself, which means SNI.

Gatekeeper already owns the key asset for SNI routing: a trusted CA that mints
per-host certificates (`proxy/ca.go`). This design replays the HTTPS MITM
story for the Postgres wire protocol.

## Connection Lifecycle

```
agent: psql postgres://app_rw@ep-foo-123.us-east-2.aws.neon.tech/appdb
        (PGPASSWORD=<run-token>, container DNS resolves *.neon.tech
         to gatekeeper)
```

1. Client sends `SSLRequest`; gatekeeper replies `'S'` and completes a TLS
   handshake with a certificate minted from the existing `proxy.CA` for the
   SNI hostname.
2. Client sends `StartupMessage` (user, database).
3. Gatekeeper sends `AuthenticationCleartextPassword`; the client replies with
   its run token. Cleartext is deliberate: gatekeeper needs the token value to
   resolve run context, and gatekeeper's own TLS protects it in transit — the
   same reasoning as `Proxy-Authorization` on the HTTP plane.
4. Token → `ContextResolver` → `RunContextData`. An unknown token, or an SNI
   host that fails network policy, yields an auth error and a closed
   connection. Policy is checked before any upstream dial.
5. The Neon resolver maps (endpoint, role, database) to a password via the
   Neon API, with a TTL cache.
6. Gatekeeper dials the real endpoint, verifies its TLS certificate, replays
   the `StartupMessage`, and completes SCRAM-SHA-256 with the real password.
7. Upstream's `AuthenticationOk` and parameter statuses flow to the client
   verbatim. From here the proxy is a blind byte relay in both directions —
   no query parsing in v1.
8. On close, one audit entry records run ID, endpoint, role, database,
   duration, and bytes in each direction (`RequestType: "postgres"`).

If the client skips `SSLRequest`, gatekeeper refuses before requesting auth,
so the run token never crosses the wire bare.

## Components

1. **`proxy/postgres.go`** — listener and per-connection state machine
   (handshake → resolve → upstream auth → relay). Lives in `proxy/` to reuse
   `CA`, `ContextResolver`, host patterns, and network policy. Its
   `net.Listener` starts alongside the HTTP listener in `proxy/server.go`.

2. **Protocol layer** — `github.com/jackc/pgx/v5/pgproto3` for wire framing
   on both sides, and `github.com/xdg-go/scram` for the upstream SCRAM
   client. Nothing security-critical is hand-rolled.

3. **`proxy.PostgresCredentialResolver`** — the parameterized analog of
   `CredentialResolver`:

   ```go
   type PostgresCredentialResolver interface {
       ResolvePassword(ctx context.Context, host, user, database string) (string, error)
   }
   ```

   Wired into `RunContextData` as
   `PostgresResolvers map[string]PostgresCredentialResolver` (host pattern →
   resolver), so moat's per-run scoping works unchanged.

4. **`credentialsource/neon.go`** — parses the endpoint ID from the SNI
   hostname, maps endpoint → project/branch through the Neon API, fetches
   `GET /projects/{id}/connection_uri?branch_id&role_name&database_name`, and
   extracts the password. The API key is itself a `CredentialSource`, so it
   can come from env, AWS Secrets Manager, or GCP Secret Manager. Cache keyed
   on (endpoint, role, database) with TTL; an upstream auth failure
   invalidates the entry and retries once, since passwords rotate on branch
   reset.

A `static` resolver (fixed password for one host) covers non-Neon Postgres
and most tests.

## Config

```yaml
postgres:
  port: 5432

credentials:
  - host: "*.neon.tech"
    postgres:                # presence marks a postgres credential
      resolver: neon
    source:                  # existing SourceConfig; supplies the API key
      type: env
      var: NEON_API_KEY
    grant: neon-databases
```

## Error Handling

- Every client-facing failure is a Postgres `ErrorResponse` (severity FATAL,
  SQLSTATE `28P01` for auth failures) with a generic message. Neon API
  errors, resolver details, and upstream auth failures never reach the
  client; full detail goes to slog with host and grant names only.
- Resolver calls and the upstream dial are each bounded by a timeout
  (following `connectTunnelDialTimeout`).

## Security

- Run-token comparison uses the same constant-time path as the HTTP plane.
- Client auth happens only inside gatekeeper's TLS.
- Upstream TLS verifies real certificates (honoring `SetUpstreamCAs`); there
  is no plaintext-upstream fallback.
- Neon API responses contain passwords; they live only in the in-memory
  cache, and never appear in logs or errors.
- The SNI hostname is checked against network policy before any upstream
  dial.

## Testing

pgproto3 implements both sides of the protocol, so tests spin up a fake
Postgres server demanding SCRAM and connect a real pgx client through
gatekeeper — full handshake round trips with no Docker. A fake Neon API
(`httptest.Server`) covers resolver mapping, caching, and rotation retry.
Table tests cover endpoint-ID parsing and policy denials. Everything runs
under `-race`.

## Out of Scope (v1)

- Query-level inspection or logging (the relay is blind after auth; the
  design admits adding it later without restructuring)
- Connection pooling
- Startup-parameter routing fallback for clients without SNI support
  (libpq ≥ 14 sends SNI)
