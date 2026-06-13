# Credential sources

Each entry in `credentials[]` matches a `host` and injects a resolved secret as
an HTTP header. The shape is always:

```yaml
credentials:
  - host: api.example.com     # exact host or glob (*.example.com)
    header: Authorization     # optional; default "Authorization"
    prefix: Bearer            # optional; auth scheme — auto-detected if omitted
    format: ""                # optional; "" (prefix scheme) or "basic" (HTTP Basic)
    grant: my-api             # optional; label for logs only (never the secret)
    source:
      type: env               # the source type — see below
      # ...type-specific fields
```

## Header, prefix, and format

- **`header`** — which header to set. Default `Authorization`. Use e.g.
  `x-api-key`, `Api-Token`, or `x-cal-secret-key` for key-in-header APIs.
- **`prefix`** and **`format` apply only to the `Authorization` header.** For
  `Authorization`, `prefix` is the scheme word prepended to the value (`Bearer`,
  `token`, `Token`, …); if omitted, Gatekeeper auto-detects it from the token
  shape. Set it explicitly when auto-detection would be wrong.
- **For any other header, the resolved value is injected verbatim** — `prefix`
  and `format` are ignored. So for `header: x-api-key`, store the *complete*
  value in the source. (To inject a bare value with no scheme on an
  `Authorization` header, set `prefix: ""`.)

```yaml
# Bearer scheme on Authorization (this is also the auto-detected default)
- host: api.openai.com
  prefix: Bearer
  source: { type: env, var: OPENAI_API_KEY }

# Custom header — value injected exactly as resolved, no prefix logic
- host: api.example.com
  header: x-api-key
  source: { type: env, var: EXAMPLE_API_KEY }
```

- **`format: basic`** — encode as HTTP Basic: `Authorization: Basic
  base64(prefix:value)`, where `prefix` is the **username**. Required for `git`
  push/clone to `github.com` (username `x-access-token`). `format: basic` is only
  valid with the `Authorization` header — any other header is a config error.

```yaml
# git over HTTPS to github.com
- host: github.com
  grant: github-git
  format: basic
  prefix: x-access-token
  source:
    type: env
    var: GITHUB_TOKEN
```

## Injecting several headers into one host

List multiple `credentials[]` entries with the **same `host` but different
`header` names** — Gatekeeper injects all of them. Useful for APIs that need a
pair of headers (e.g. Cloudflare Access client id + secret):

```yaml
- host: api.example.com
  header: X-Client-Id
  source: { type: env, var: CLIENT_ID }
- host: api.example.com
  header: X-Client-Secret
  source: { type: env, var: CLIENT_SECRET }
```

## Placeholder replacement and choosing among credentials

If the client already sends a header that a credential targets, Gatekeeper
**replaces** that header's value with the resolved secret. This is how clients
that insist on sending *some* token work: send any placeholder (e.g.
`Authorization: Bearer placeholder`) and the proxy swaps in the real value.

It also lets you register **several credentials on the same host and header**:
the client picks one by sending that header as a placeholder. With no
placeholder, Gatekeeper auto-injects one of them. Order your entries so the
intended default comes first.

## Host matching rules

- Matching is **exact** or an **explicit glob**. `*.example.com` is a
  `.example.com` suffix match: it matches `api.example.com` and any deeper
  subdomain, but **not** bare `example.com`. The suffix requires a dot boundary,
  so `*.aiplatform.googleapis.com` does **not** match
  `us-central1-aiplatform.googleapis.com` (it ends in `-aiplatform…`, not
  `.aiplatform…`). Add such regional hosts as their own entries.
- Ports are stripped before matching.
- Identical `source` blocks across entries are **deduplicated** — they share one
  resolved token and one refresh loop. Safe to list many hosts for one secret.

---

## env — environment variable

```yaml
source:
  type: env
  var: GITHUB_TOKEN
```

Resolved once at startup. The value is the full credential (Gatekeeper adds the
scheme prefix unless the value already looks complete).

## static — literal value

```yaml
source:
  type: static
  value: "Bearer sk-ant-..."
```

For testing or fixed keys. Prefer a secret manager for anything real.

## aws-secretsmanager — AWS Secrets Manager

```yaml
source:
  type: aws-secretsmanager
  secret: prod/api-key      # secret name or ARN
  region: us-east-1
```

Uses the standard AWS SDK credential chain (env, profile, IAM role). Fetched
once at startup; restart to pick up rotation.

## gcp-secretmanager — GCP Secret Manager

```yaml
source:
  type: gcp-secretmanager
  project: my-gcp-project
  secret: github-token
  version: "latest"         # optional; default "latest", or pin "3"
```

Needs Application Default Credentials (`gcloud auth application-default login`
or a service-account key) and `roles/secretmanager.secretAccessor` on the
secret. Fetched once at startup (10s timeout); restart to pick up rotation.

## gcp-service-account — short-lived GCP OAuth token

Mints a GCP OAuth2 access token from a service-account key and injects it as
`Authorization: Bearer ...`. Tokens auto-refresh. Ideal for Vertex AI.

```yaml
source:
  type: gcp-service-account
  private_key_path: vertex-sa.json   # key JSON from `gcloud iam service-accounts keys create`
  # private_key_env: SA_KEY_JSON     # alternative: read the JSON from an env var
  # scopes: https://www.googleapis.com/auth/cloud-platform   # space-separated; this is the default
```

The secret may instead live in GCP Secret Manager — set `secret`, `project`,
and `version` instead of `private_key_path`. Clients send any placeholder
`Authorization` header; the proxy replaces it.

> Regional Vertex hosts (e.g. `us-central1-aiplatform.googleapis.com`) are not
> subdomains of `aiplatform.googleapis.com`. Add each as its own credential
> entry; identical sources are deduplicated, so they share one token.

## github-app — auto-refreshing installation tokens

```yaml
source:
  type: github-app
  app_id: "12345"
  installation_id: "67890"
  private_key_path: ./github-app-key.pem   # or private_key_env: APP_KEY_PEM
```

Generates short-lived installation tokens from the App private key and refreshes
in the background at ~75% of TTL. Setup: create a GitHub App, install it, then
download the private key from the App settings page.

## token-exchange — per-caller identity (RFC 8693)

For multi-tenant setups where each caller has a distinct identity. Gatekeeper
calls your Security Token Service (STS) to exchange a subject identity for an
upstream token, caching per subject. **You implement the STS;** Gatekeeper is
the client.

```yaml
source:
  type: token-exchange
  endpoint: https://sts.example.com/token
  client_id: gk-client
  client_secret_env: STS_CLIENT_SECRET   # or client_secret: <literal>
  subject_header: X-Gatekeeper-Subject   # OR subject_from: proxy-auth (mutually exclusive)
  resource: https://api.github.com       # optional target resource URI
  # actor_token_from: proxy-auth-password  # forward proxy-auth password as RFC 8693 actor_token
```

Two ways to supply the subject:

- **`subject_header`** — read from a request header (stripped before forwarding).
  Client sends `-H "X-Gatekeeper-Subject: alice@example.com"`.
- **`subject_from: proxy-auth`** — read from the proxy-auth username. Client uses
  `HTTP_PROXY=http://alice%40example.com:pass@127.0.0.1:9080` (`@` → `%40`).

By default subjects are self-asserted. Set `actor_token_from:
proxy-auth-password` so the STS can verify the caller (it then requires Basic
proxy auth with a non-empty password). Tokens cache by `(subject, actor)`;
`expires_in` from the STS controls TTL (default 300s). For the full STS request/
response contract and an implementation checklist, see the repo's
`docs/content/guides/06-token-exchange.md`.

---

## Postgres / Neon

Postgres credentials use a different `source` + `postgres.resolver` pairing —
see **[postgres-data-plane.md](postgres-data-plane.md)**.
