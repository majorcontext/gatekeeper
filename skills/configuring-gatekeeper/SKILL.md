---
name: configuring-gatekeeper
description: >-
  Set up, configure, and run Gatekeeper — a credential-injecting,
  TLS-intercepting proxy. Use when writing or editing gatekeeper.yaml,
  generating the CA certificate, choosing a credential source (env var, static
  value, AWS Secrets Manager, GCP Secret Manager, GCP service account, GitHub
  App, or RFC 8693 token exchange), injecting auth headers
  (Authorization/Bearer/Basic) for specific hosts, locking down network egress
  with allow lists, or wiring up a Postgres/Neon data plane. Also use when
  pointing a client (curl, git, Node, opencode) through the proxy, or when a
  request isn't getting its credential injected, TLS verification fails, or you
  need a copy-paste starter config.
license: MIT
compatibility: >-
  Requires the gatekeeper binary (built with Go 1.25+) and openssl for CA
  generation. Cloud sources need the matching provider credentials (AWS/GCP
  ADC, a GitHub App key, a Neon API key, etc.).
metadata:
  author: majorcontext
  repository: https://github.com/majorcontext/gatekeeper
  version: "1.0"
---

# Configuring Gatekeeper

Gatekeeper is a proxy that **injects credentials into HTTPS traffic so clients
never hold raw secrets**. A client routes traffic through Gatekeeper (via
`HTTPS_PROXY`); Gatekeeper terminates TLS with a CA it controls, injects the
matching credential as an HTTP header, and forwards the request upstream.

This skill gets you from nothing to a working, verified proxy, then routes you
to the right reference for each credential source and feature.

## Quick start (3 steps, ~2 minutes)

This injects a GitHub token from an environment variable into requests to
`api.github.com`. Adapt the host/source from there.

**1. Generate a CA** (Gatekeeper signs per-host certs with it):

```bash
# In the gatekeeper repo:
cd examples && ./gen-ca.sh        # writes ca.crt + ca.key
# Or anywhere, with openssl directly — see references/ca-setup.md
```

**2. Write `gatekeeper.yaml`** (copy `assets/gatekeeper.starter.yaml` from this
skill, or start from this minimum):

```yaml
proxy:
  host: 127.0.0.1
  port: 9080

tls:
  ca_cert: ca.crt
  ca_key: ca.key

credentials:
  - host: api.github.com
    grant: github            # label for logs only — never the secret
    source:
      type: env
      var: GITHUB_TOKEN      # bare token; auth scheme auto-detected

network:
  policy: permissive

log:
  level: info
  format: text
```

**3. Run and verify:**

```bash
export GITHUB_TOKEN=ghp_xxx
gatekeeper --config gatekeeper.yaml          # or: go run ./cmd/gatekeeper --config gatekeeper.yaml

# In another terminal — no token on the command line:
curl --proxy http://127.0.0.1:9080 --cacert ca.crt https://api.github.com/user
```

A `200` with your user JSON means injection worked. The proxy log shows
`credential_injected=true grants=github`. Health check: `curl
http://127.0.0.1:9080/healthz` → `{"status":"ok"}`.

## Mental model

1. Client sends `CONNECT host:443` to the proxy (set by `HTTPS_PROXY`).
2. Proxy terminates TLS with a cert minted on the fly from your CA — so the
   client **must trust `ca.crt`** (that's the `--cacert` flag above).
3. Proxy reads the plaintext request and checks `credentials[]` for a `host`
   match. On a match it injects the resolved credential as `header` (default
   `Authorization`). If the client already sent that header (a placeholder), the
   proxy **replaces** its value. Multiple entries with different headers on one
   host are all injected.
4. Proxy forwards upstream over a *separate* real TLS connection and streams
   the response back.

Three facts that explain most problems:

- **The client must trust the CA**, or TLS fails. There is no bypass.
- **Host matching is exact or explicit glob** (`*.example.com`). `*.foo.com`
  does **not** match `foo.com` or `a-b.foo.com` (single labels). No accidental
  wildcards.
- **Secrets only ever appear in config/sources**, never in client commands and
  never in logs (`grant` is logged, the value is not).

## Choose a credential source

| `source.type`         | Use when…                                                        |
|-----------------------|------------------------------------------------------------------|
| `env`                 | The secret is already in an environment variable. Simplest.      |
| `static`              | You have a literal value (testing, a fixed API key).             |
| `aws-secretsmanager`  | The secret lives in AWS Secrets Manager.                         |
| `gcp-secretmanager`   | The secret lives in GCP Secret Manager.                          |
| `gcp-service-account` | You need a short-lived GCP OAuth token (e.g. Vertex AI).         |
| `github-app`          | You want auto-refreshing GitHub App installation tokens.         |
| `token-exchange`      | Per-caller identities via an RFC 8693 STS (multi-tenant).        |

Full YAML for every type, plus header/prefix/format and host-matching rules:
**[references/credential-sources.md](references/credential-sources.md)**.

## Task router

| Goal                                                  | Read                                                   |
|-------------------------------------------------------|--------------------------------------------------------|
| Pick/configure a credential source                    | [references/credential-sources.md](references/credential-sources.md) |
| Generate or trust the CA cert                         | [references/ca-setup.md](references/ca-setup.md)       |
| Restrict which hosts the proxy will reach             | [references/network-policy.md](references/network-policy.md) |
| Connect to Postgres/Neon with only a token            | [references/postgres-data-plane.md](references/postgres-data-plane.md) |
| Look up any config field, default, or env var         | [references/config-reference.md](references/config-reference.md) |
| Start from a template                                 | [assets/gatekeeper.starter.yaml](assets/gatekeeper.starter.yaml) |

## Point a client at the proxy

The client needs two things: the proxy address and trust for the CA.

```bash
# curl
curl --proxy http://127.0.0.1:9080 --cacert ca.crt https://api.github.com/user

# Any tool honoring proxy env vars
export HTTPS_PROXY=http://127.0.0.1:9080

# Node / opencode
export HTTPS_PROXY=http://127.0.0.1:9080
export NODE_EXTRA_CA_CERTS=$PWD/ca.crt

# git over HTTPS (note: github.com push needs HTTP Basic — see credential-sources.md)
git -c http.proxy=http://127.0.0.1:9080 -c http.sslCAInfo=$PWD/ca.crt clone https://github.com/owner/repo
```

**If `proxy.auth_token` is set**, clients must authenticate via
`Proxy-Authorization`. The username is ignored unless you use token-exchange
with `subject_from: proxy-auth`:

```bash
curl --proxy http://127.0.0.1:9080 --proxy-user "client:$AUTH_TOKEN" \
  --cacert ca.crt https://api.github.com/user
```

## Run in production (Docker)

The published image runs the same way — mount the config and CA, pass `--config`:

```bash
docker run -d --name gatekeeper --network host \
  -v /etc/gatekeeper:/etc/gatekeeper:ro \
  ghcr.io/majorcontext/gatekeeper:<tag> \
  --config /etc/gatekeeper/gatekeeper.yaml
```

Bind to `0.0.0.0` (not `127.0.0.1`) when clients are on other hosts. Configure
OpenTelemetry with `OTEL_*` env vars on the container. Secrets typically come
from a `*-secretmanager` source so nothing sensitive sits in the config file.

## Troubleshoot

| Symptom                                            | Likely cause / fix                                                                 |
|----------------------------------------------------|------------------------------------------------------------------------------------|
| TLS / certificate verification error on the client | Client doesn't trust the CA. Pass `--cacert ca.crt` / set `NODE_EXTRA_CA_CERTS`.   |
| `credential_injected=false` in the log             | `host` didn't match. Check exact host vs glob; `*.x.com` ≠ `x.com`. See network ref.|
| Request blocked / not forwarded                    | `network.policy: strict` without the host in `allow`. See network-policy.md.        |
| `git push` to github.com rejected                  | Needs HTTP Basic with user `x-access-token`: set `format: basic`, `prefix: x-access-token`. |
| Startup error about CA                              | Postgres data plane (and TLS interception) requires `tls.ca_cert` + `tls.ca_key`.  |
| Secret value appears nowhere                        | Correct — Gatekeeper never logs secret values, only `grant` names.                 |

Exit code `0` = clean shutdown (SIGTERM/SIGINT); `1` = startup error (bad
config, credential fetch failure, bind failure). Full CLI/env details:
[references/config-reference.md](references/config-reference.md).
