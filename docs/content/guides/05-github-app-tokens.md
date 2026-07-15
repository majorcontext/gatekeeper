---
title: "GitHub App Tokens"
description: "Generate short-lived GitHub installation tokens from a GitHub App private key with automatic background refresh."
keywords: ["gatekeeper", "GitHub App", "installation tokens", "auto-refresh"]
---

# GitHub App tokens

Generate short-lived GitHub installation tokens from a GitHub App private key. Tokens refresh automatically in the background.

## Prerequisites

- CA certificate generated ([CA Setup](./01-ca-setup.md))
- A GitHub App created with the required permissions
- The App's private key (PEM file), downloaded from the App settings page
- The installation ID (visible in the App's installation URL: `https://github.com/settings/installations/{id}`)

## Configuration

Add a `github-app` credential source to `gatekeeper.yaml`:

```yaml
proxy:
  host: 127.0.0.1
  port: 9080

tls:
  ca_cert: ca.crt
  ca_key: ca.key

credentials:
  - host: api.github.com
    header: Authorization
    grant: github
    source:
      type: github-app
      app_id: "12345"
      installation_id: "67890"
      private_key_path: ./github-app-key.pem

network:
  policy: permissive

log:
  level: info
  format: text
```

| Field              | Required | Description                                          |
|--------------------|----------|------------------------------------------------------|
| `app_id`           | Yes      | GitHub App ID (from App settings)                    |
| `installation_id`  | Yes      | Installation ID for the target org/account           |
| `private_key_path` | One of   | Path to the PEM private key file                     |
| `private_key_env`  | One of   | Environment variable containing the PEM private key  |

Set either `private_key_path` or `private_key_env`, not both.

### Private key via environment variable

For environments where files are not practical (containers, CI):

```yaml
source:
  type: github-app
  app_id: "12345"
  installation_id: "67890"
  private_key_env: GITHUB_APP_PRIVATE_KEY
```

```bash
export GITHUB_APP_PRIVATE_KEY="$(cat github-app-key.pem)"
```

## Auto-refresh behavior

GitHub installation tokens expire after one hour. Gatekeeper refreshes them automatically:

1. At startup, gatekeeper generates a JWT signed with the App private key and exchanges it for an installation token via the GitHub API.
2. A background goroutine re-fetches the token at 75% of TTL (roughly every 45 minutes).
3. If a refresh fails, gatekeeper retries with exponential backoff (1s to 60s) until it succeeds.
4. Token rotation is atomic -- requests always see either the old or new token, never a partial state.

When multiple credential entries share the same `github-app` source (e.g., `api.github.com` and `github.com`), a single refresh goroutine updates all of them.

## Start the proxy

```bash
gatekeeper --config gatekeeper.yaml
```

## Verification

```bash
curl --cacert ca.crt --proxy http://127.0.0.1:9080 https://api.github.com/installation/repositories
```

A successful response confirms the installation token was generated and injected. The proxy log shows:

```text
level=INFO msg=request http_host=api.github.com credential_injected=true grants=github
```

At debug level, refresh events appear:

```text
level=DEBUG msg="credential refreshed" host=api.github.com grant=github ttl=1h0m0s
```

See [`examples/gatekeeper-github-app.yaml`](https://github.com/majorcontext/gatekeeper/blob/main/examples/gatekeeper-github-app.yaml) for a complete working example.

## Next steps

- [Token Exchange](./06-token-exchange.md) — per-user credential resolution via RFC 8693
- [Network Lockdown](./07-network-lockdown.md) — restrict proxy traffic to specific hosts
