---
title: "Credential sources"
description: "Reference for all credential source types including env, static, AWS Secrets Manager, GCP Secret Manager, GitHub App, and token exchange."
keywords: ["gatekeeper", "credential sources", "source types", "configuration reference"]
---

# Credential sources

Each credential entry in gatekeeper.yaml includes a `source` block that determines where the credential value comes from.

## Source types overview

| Type | Description | Refresh |
|------|-------------|---------|
| `env` | Read from an environment variable | No |
| `static` | Literal inline value | No |
| `aws-secretsmanager` | Fetch from AWS Secrets Manager | No |
| `gcp-secretmanager` | Fetch from GCP Secret Manager | No |
| `github-app` | Generate GitHub App installation token | Yes (auto-refresh before expiry) |
| `token-exchange` | RFC 8693 token exchange | Yes (per-request, cached with TTL) |

Sources marked **Refresh: Yes** implement background credential refresh. Gatekeeper re-fetches the credential at 75% of the token's TTL (minimum 30 seconds) and hot-swaps it on the proxy without downtime.
Sources marked **Refresh: Yes** have credentials that expire. `github-app` implements background credential refresh — gatekeeper re-fetches at 75% of TTL (minimum 30 seconds) and hot-swaps without downtime. `token-exchange` uses per-request lazy caching: on cache miss, gatekeeper calls the STS and caches the result for the token's TTL.
---

## env

Read the credential value from an environment variable at startup.

```yaml
credentials:
  - host: api.github.com
    source:
      type: env
      var: GITHUB_TOKEN
```

### var

Name of the environment variable to read.

- **Type:** `string`
- **Required:** Yes
- **Default:** —

The variable must be set and non-empty at startup. If unset, gatekeeper exits with an error.

---

## static

Use a literal value defined inline in the config file.

```yaml
credentials:
  - host: api.example.com
    header: x-api-key
    source:
      type: static
      value: sk-xxxx
```

### value

The credential value.

- **Type:** `string`
- **Required:** Yes
- **Default:** —

> **Note:** Avoid committing secrets in config files. Prefer `env` or a secret manager source for production deployments.

---

## aws-secretsmanager

Fetch the credential from AWS Secrets Manager at startup. Uses the AWS SDK default credential chain (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, IAM roles, etc.).

```yaml
credentials:
  - host: api.example.com
    source:
      type: aws-secretsmanager
      secret: my-app/api-key
      region: us-east-1
```

### secret

AWS Secrets Manager secret ID or ARN.

- **Type:** `string`
- **Required:** Yes
- **Default:** —

### region

AWS region for the Secrets Manager client.

- **Type:** `string`
- **Required:** No
- **Default:** — (uses `AWS_REGION` or `AWS_DEFAULT_REGION` from the environment)

---

## gcp-secretmanager

Fetch the credential from GCP Secret Manager at startup. Uses Application Default Credentials (`GOOGLE_APPLICATION_CREDENTIALS`, metadata server, etc.).

```yaml
credentials:
  - host: api.example.com
    source:
      type: gcp-secretmanager
      project: my-gcp-project
      secret: api-key
      version: latest
```

### project

GCP project ID containing the secret.

- **Type:** `string`
- **Required:** Yes
- **Default:** —

### secret

Secret name within the project.

- **Type:** `string`
- **Required:** Yes
- **Default:** —

### version

Secret version to access.

- **Type:** `string`
- **Required:** No
- **Default:** `"latest"`

The underlying gRPC connection is closed on gatekeeper shutdown.

---

## github-app

Generate short-lived GitHub App installation access tokens. Tokens refresh automatically in the background before expiry.

```yaml
credentials:
  - host: api.github.com
    grant: github
    source:
      type: github-app
      app_id: "12345"
      installation_id: "67890"
      private_key_path: /etc/gatekeeper/github-app.pem
```

### app_id

GitHub App ID.

- **Type:** `string`
- **Required:** Yes
- **Default:** —

### installation_id

GitHub App installation ID.

- **Type:** `string`
- **Required:** Yes
- **Default:** —

### private_key_path

File path to the PEM-encoded RSA private key for the GitHub App.

- **Type:** `string`
- **Required:** One of `private_key_path` or `private_key_env` is required
- **Default:** —

Mutually exclusive with `private_key_env`. Supports both PKCS#1 (`RSA PRIVATE KEY`) and PKCS#8 (`PRIVATE KEY`) PEM formats.

### private_key_env

Name of an environment variable containing the PEM-encoded RSA private key.

- **Type:** `string`
- **Required:** One of `private_key_path` or `private_key_env` is required
- **Default:** —

Mutually exclusive with `private_key_path`. The environment variable must be set and non-empty at startup.

When multiple credentials share the same `github-app` source config (e.g., `api.github.com` and `github.com`), gatekeeper deduplicates them into a single token fetch and a single background refresh goroutine.

---

## token-exchange

Exchange a per-request subject token for an access token via RFC 8693 (OAuth 2.0 Token Exchange). Unlike other sources, `token-exchange` resolves credentials dynamically per request rather than at startup.

```yaml
credentials:
  - host: api.github.com
    grant: github
    source:
      type: token-exchange
      endpoint: https://sts.example.com/token
      client_id: gatekeeper
      client_secret_env: STS_CLIENT_SECRET
      subject_header: X-Subject-Token
      resource: https://api.github.com
```

### endpoint

STS token endpoint URL.

- **Type:** `string`
- **Required:** Yes
- **Default:** —

### client_id

OAuth client ID for authenticating to the STS via HTTP Basic auth.

- **Type:** `string`
- **Required:** Yes
- **Default:** —

### client_secret

OAuth client secret. Sent as the Basic auth password to the STS endpoint.

- **Type:** `string`
- **Required:** One of `client_secret` or `client_secret_env` is required
- **Default:** —

Mutually exclusive with `client_secret_env`.

### client_secret_env

Name of an environment variable containing the OAuth client secret.

- **Type:** `string`
- **Required:** One of `client_secret` or `client_secret_env` is required
- **Default:** —

Mutually exclusive with `client_secret`. The environment variable must be set and non-empty at startup.

### subject_header

HTTP request header containing the subject token. The header is stripped from the request before forwarding.

- **Type:** `string`
- **Required:** One of `subject_header` or `subject_from` is required
- **Default:** —

Mutually exclusive with `subject_from`.

### subject_from

Alternative subject token extraction method.

- **Type:** `string`
- **Required:** One of `subject_header` or `subject_from` is required
- **Default:** —
- **Valid values:** `"proxy-auth"`

When set to `"proxy-auth"`, the subject token is extracted from the username in the `Proxy-Authorization` Basic auth header.

Mutually exclusive with `subject_header`.

### subject_token_type

OAuth token type URI for the subject token.

- **Type:** `string`
- **Required:** No
- **Default:** `"urn:ietf:params:oauth:token-type:access_token"`

### resource

Target resource URI included in the token exchange request.

- **Type:** `string`
- **Required:** No
- **Default:** —

### actor_token_from

Source for the optional RFC 8693 actor token.

- **Type:** `string`
- **Required:** No
- **Default:** — (no actor token)
- **Valid values:** `"proxy-auth-password"`

When set to `"proxy-auth-password"`, the actor token is extracted from the password in the `Proxy-Authorization` Basic auth header. Requires `subject_from: proxy-auth`.

When `actor_token_from` is configured, gatekeeper sets delegate auth mode — the static `auth_token` check is skipped and each caller's identity is validated by the STS instead.

### actor_token_type

OAuth token type URI for the actor token.

- **Type:** `string`
- **Required:** No
- **Default:** `"urn:ietf:params:oauth:token-type:access_token"`

Exchanged tokens are cached per subject (and actor, if present) using the TTL from the STS `expires_in` response field. If the STS does not return `expires_in`, a default TTL of 5 minutes is used. Concurrent requests for the same subject are coalesced into a single STS call.
