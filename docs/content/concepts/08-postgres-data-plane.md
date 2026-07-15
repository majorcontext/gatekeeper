---
title: "Postgres Data Plane"
description: "How Gatekeeper proxies the Postgres wire protocol, authenticating clients with a run token and resolving per-branch Neon database passwords so no database secret reaches the client."
keywords: ["gatekeeper", "postgres", "neon", "SCRAM", "credential injection", "database proxy"]
---

# Postgres data plane

Gatekeeper runs a second listener that speaks the Postgres wire protocol. A client connects to it with the real database hostname and an authentication token in place of the database password. Gatekeeper resolves the real password, authenticates upstream, and relays the connection. The database password never reaches the client.

This is a genuinely separate listener from the HTTP/CONNECT proxy — except when `postgres.port` is configured to the same value as `proxy.port`, in which case gatekeeper multiplexes both planes onto one shared listener, classifying each connection by its first bytes. See [Sharing one listener with the HTTP proxy](../reference/02-config-file.md#sharing-one-listener-with-the-http-proxy) in the config reference.

This mirrors the HTTP credential-injection plane: the client presents a weak identity (its run token), and Gatekeeper substitutes the real credential before talking to the upstream. The two planes share configuration, network policy, per-run context scoping, and audit logging.

## What it solves

A client that connects to a managed Postgres database directly holds a connection string with an embedded password. A process that reads its own environment can copy that string and connect from anywhere; a network allowlist is the only remaining control.

The data plane removes the database password from the client. The client holds only its Gatekeeper run token, which is scoped to a single run and is rejected outside Gatekeeper. The Neon API key and the per-branch database passwords stay in Gatekeeper's memory on the host. Every database connection passes through one audited, policy-enforced listener.

A client can still read data through the proxy — that is the point of the connection — so exfiltration over an allowed connection remains possible. The strict network policy bounds which hosts a client may reach.

## Routing by SNI

The target endpoint travels in the connection's TLS Server Name Indication (SNI) field. Gatekeeper reads the SNI hostname during the TLS handshake, mints a certificate for it from the configured CA, and uses it to select the credential and dial the upstream.

Routing by SNI is what allows a single listener to reach arbitrary endpoints — including database branches created after Gatekeeper started — without enumerating them in configuration. The embedder arranges DNS so the database hostname resolves to Gatekeeper inside the client's environment; that DNS configuration is outside Gatekeeper's scope.

## Connection lifecycle

1. The client sends an `SSLRequest`. Gatekeeper replies `S` and completes a TLS handshake using a certificate minted from the configured CA for the SNI hostname. A client that skips the `SSLRequest` is refused before any credential is requested, so the run token never crosses the wire unencrypted.
2. The client sends a `StartupMessage` carrying the user (role) and database.
3. Gatekeeper requests `AuthenticationCleartextPassword`. The client sends its run token. Cleartext is deliberate: Gatekeeper needs the token value to resolve the run context, and its own TLS protects the token in transit — the same model as `Proxy-Authorization` on the HTTP plane.
4. Gatekeeper resolves the token to a run context. An unknown token, or an SNI host that fails network policy, produces a fatal error and closes the connection. Network policy is checked before any upstream dial.
5. The configured resolver maps `(endpoint, role, database)` to the real password.
6. Gatekeeper dials the real endpoint, verifies its TLS certificate, replays the startup parameters, and completes SCRAM-SHA-256 with the real password.
7. The upstream's `AuthenticationOk` and parameter status messages flow to the client. From here Gatekeeper relays protocol messages in both directions without inspecting them.
8. On close, Gatekeeper writes one audit entry recording the run ID, endpoint, role, database, duration, and message counts in each direction, with `proxy_type` set to `postgres`.

Startup parameters are forwarded to the upstream with `replication` and `options` removed. `replication` would request a WAL-streaming session, and `options` sets server-side parameters at startup; neither is forwarded.

## Resolvers

A credential with a `postgres` block selects how the upstream password is resolved.

- **`neon`** — The credential source supplies a Neon API key. Gatekeeper parses the endpoint ID from the SNI hostname, maps it to a project and branch through the Neon API, fetches the branch's connection URI, and extracts the password. Passwords are cached with a TTL. An upstream authentication failure invalidates the cached entry and retries once, since Neon rotates passwords on branch reset. An account-scoped API key discovers an endpoint's project by listing projects; a project-scoped key cannot list projects, so set `project` on the credential to its project ID.
- **`static`** — The credential source supplies a fixed password directly. This covers non-Neon Postgres servers and testing.

The API key is itself a credential source, so it can come from an environment variable, AWS Secrets Manager, or GCP Secret Manager. See [Credential Sources](./03-credential-sources.md).

## Tracing a connection to its origin

The audit entry's `run_id` is the trusted identity: it comes from the authenticated run token, so a client cannot forge it. But `run_id` alone doesn't say *which* connection within a run produced a given log line — a single run can open many Postgres connections over its lifetime.

Clients can additionally set the standard Postgres `application_name` startup parameter (via `PGAPPNAME`, a driver's `application_name=` connection option, or `libpq`'s `application_name` keyword) to a short slug identifying the connection's origin, e.g. a box or worker ID. Gatekeeper captures it into the canonical log line as `application_name` (see [Canonical log lines](./06-observability.md#canonical-log-lines)) — sanitized (control characters stripped) and length-bounded before logging, the Postgres analogue of the HTTP [`capture_headers`](./06-observability.md#canonical-log-lines) feature. The raw value is still forwarded upstream unchanged, so it also surfaces in Neon's own `pg_stat_activity`, giving the same slug on both sides of the proxy.

Unlike `run_id`, `application_name` is not authenticated: the client sets it, so treat it as a correlation hint for debugging, not as proof of origin.

## Security properties

- Run-token comparison uses the same constant-time path as the HTTP plane.
- The client's token is read only inside Gatekeeper's TLS tunnel.
- Upstream TLS verifies the real server certificate; there is no plaintext-upstream fallback.
- Neon API responses contain passwords. They live only in the in-memory cache and never appear in logs or in errors returned to the client.
- Client-facing failures are Postgres `ErrorResponse` messages with generic text. Neon API errors, resolver details, and upstream authentication failures are logged with host and grant names only, never credential values.
- The SNI hostname is checked against network policy before any upstream dial.
- A Postgres listener requires a configured CA. Gatekeeper refuses to start a listener without `tls.ca_cert` and `tls.ca_key`.

## Scope

The relay forwards protocol messages without parsing them. It does not inspect or log SQL, pool connections, or route by startup parameter as a fallback for clients that omit SNI. The relay clears the handshake timeout once a connection is established and sets TCP keep-alives, so long-running queries and idle sessions are not bounded by the handshake deadline.
