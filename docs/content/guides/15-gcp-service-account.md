---
title: "GCP Service Account Tokens"
description: "Mint short-lived GCP OAuth2 access tokens from a service account key and inject them into requests to Google APIs, with automatic background refresh."
keywords: ["gatekeeper", "GCP", "service account", "OAuth2", "credential source"]
---

# GCP service account tokens

Mint short-lived OAuth2 access tokens from a GCP service account key and inject them into requests to Google APIs. Tokens refresh automatically in the background before they expire.

Unlike [GCP Secret Manager](./04-gcp-secret-manager.md), which fetches a literal secret value once, this source holds a service account key and continuously exchanges it for fresh access tokens — the credential injected into requests is never the key itself.

## Prerequisites

- CA certificate generated ([CA Setup](./01-ca-setup.md))
- A GCP service account with the IAM role(s) needed for the target API
- The service account's key JSON (`gcloud iam service-accounts keys create key.json --iam-account=...@...iam.gserviceaccount.com`), or that key JSON stored in GCP Secret Manager

## Key location modes

The service account key JSON can come from exactly one of three places:

| Field              | Where the key lives                                    |
|---------------------|---------------------------------------------------------|
| `private_key_path`  | A file on disk, read once at startup                    |
| `private_key_env`   | An environment variable, read once at startup           |
| `secret` + `project` | GCP Secret Manager, read lazily on first use and re-read on key rotation |

Set exactly one. `secret` also requires `project` (the GCP project containing the secret); `project` and `version` are only valid alongside `secret`.

### File or environment variable

```yaml
credentials:
  - host: storage.googleapis.com
    grant: gcs
    source:
      type: gcp-service-account
      private_key_path: ./gcs-uploader-key.json
```

```yaml
source:
  type: gcp-service-account
  private_key_env: GCS_SERVICE_ACCOUNT_KEY
```

```bash
export GCS_SERVICE_ACCOUNT_KEY="$(cat gcs-uploader-key.json)"
```

With either mode, the key is read once at startup and held in memory for the life of the process. It is not re-read — rotating the key file or environment variable requires a restart.

### GCP Secret Manager

```yaml
credentials:
  - host: storage.googleapis.com
    grant: gcs
    source:
      type: gcp-service-account
      project: my-gcp-project
      secret: gcs-uploader-key
```

The secret's payload must be the full service account key JSON. Reading it uses Application Default Credentials, same as the [GCP Secret Manager source](./04-gcp-secret-manager.md) directly. Unlike the file/env modes, this mode re-reads the secret when the key is rotated — see [Key Rotation](#key-rotation) below.

## Scopes

```yaml
source:
  type: gcp-service-account
  private_key_path: ./key.json
  scopes: https://www.googleapis.com/auth/devstorage.read_write
```

`scopes` is a space-separated list of OAuth scope URIs requested when minting the token. It defaults to `https://www.googleapis.com/auth/cloud-platform`, which is broad — most Google Cloud APIs accept it, but scope the token down to what the target host actually needs when you know it (e.g. `devstorage.read_write` for Cloud Storage rather than the blanket `cloud-platform` scope).

## How the token mint and refresh work

Gatekeeper signs a JWT asserting the service account's identity (`iss`, requested `scope`, the token endpoint as `aud`) with the key's RSA private key, and exchanges it at the key's `token_uri` (from the key JSON, defaulting to `https://oauth2.googleapis.com/token`) for an access token using the `urn:ietf:params:oauth:grant-type:jwt-bearer` grant. The response's `expires_in` sets the token's TTL.

Background refresh follows the same schedule as every other refreshing source in gatekeeper: **75% of TTL, floored at 30 seconds**. For a typical one-hour Google access token, that's a refresh roughly every 45 minutes. Refresh is atomic — requests see either the old token or the new one, never a partial state.

## Key rotation

When the token endpoint rejects the signed JWT with `400`, `401`, or `403`, that's a strong signal the key itself is stale (rotated or revoked, not just an expired token — tokens don't get JWT-assertion errors, keys do). Gatekeeper responds differently depending on where the key came from:

- **`secret` mode.** The cached parsed key is dropped. The next fetch attempt re-reads the key JSON from Secret Manager, so a key rotated there is picked up without a gatekeeper restart.
- **`private_key_path` / `private_key_env` mode.** There is no backing source to re-read from — the key was loaded once from a file or environment variable at startup — so this drop-and-retry has no effect. Rotating a file- or env-sourced key requires a restart.

> **Note:** This key-drop is scoped to the *token endpoint* rejecting the signing key — it does not react to the *target API* (e.g. `storage.googleapis.com`) returning 401/403 for an otherwise-valid token. Gatekeeper's proxy-level "evict a credential when the destination rejects it" mechanism ([Credential invalidation](../reference/03-credential-sources.md#credential-invalidation)) is wired up for `token-exchange` credentials only; a `gcp-service-account` token that a Google API rejects is not proactively evicted — the background refresh loop replaces it on its normal 75%-of-TTL schedule regardless.

## Worked example: Cloud Storage

```yaml
proxy:
  host: 127.0.0.1
  port: 9080

tls:
  ca_cert: ca.crt
  ca_key: ca.key

credentials:
  - host: storage.googleapis.com
    header: Authorization
    grant: gcs
    source:
      type: gcp-service-account
      project: my-gcp-project
      secret: gcs-uploader-key
      scopes: https://www.googleapis.com/auth/devstorage.read_write

network:
  policy: permissive

log:
  level: info
  format: text
```

## IAM setup

- The service account needs whatever IAM role the target API requires — for example `roles/storage.objectAdmin` for read/write access to Cloud Storage objects. Grant the narrowest role that covers the request pattern.
- If the key comes from Secret Manager (`secret` + `project`), the principal running gatekeeper additionally needs `roles/secretmanager.secretAccessor` on that secret — the same permission described in the [GCP Secret Manager guide](./04-gcp-secret-manager.md#iam-permissions).
- The key JSON itself grants whatever the service account can do — treat it as a credential. Prefer Secret Manager over a key file on disk where practical, since Secret Manager access is itself auditable and revocable without rotating the key.

## Start the proxy

```bash
gatekeeper --config gatekeeper.yaml
```

If the key JSON is malformed, missing required fields, or ADC is not configured for Secret Manager access, gatekeeper exits with an error at startup.

## Verification

```bash
curl --cacert ca.crt --proxy http://127.0.0.1:9080 \
  https://storage.googleapis.com/storage/v1/b/my-bucket/o
```

The proxy log confirms credential injection:

```text
level=INFO msg=request http_host=storage.googleapis.com credential_injected=true grants=gcs
```

At debug level, refresh events appear:

```text
level=DEBUG msg="credential refreshed" host=storage.googleapis.com grant=gcs ttl=1h0m0s
```

## Next steps

- [GCP Secret Manager](./04-gcp-secret-manager.md) — fetch a literal secret value instead of minting OAuth2 tokens
- [Network Lockdown](./07-network-lockdown.md) — restrict proxy traffic to specific hosts
