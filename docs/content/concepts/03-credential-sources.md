---
title: "Credential Sources"
description: "How Gatekeeper resolves credentials from pluggable backends including environment variables, secret managers, and token exchange."
keywords: ["gatekeeper", "credential sources", "background refresh", "credential resolver"]
---

# Credential Sources

Gatekeeper resolves credentials from pluggable backends called **credential sources**. Each source implements a single method — `Fetch` — that returns a credential value. Sources range from simple (read an environment variable) to complex (exchange tokens with an external STS).

## The Source Interface

All credential sources implement `CredentialSource`:

```go
type CredentialSource interface {
    Fetch(ctx context.Context) (string, error)
    Type() string
}
```

`Fetch` retrieves the current credential value. It accepts a context for cancellation and timeout — gatekeeper enforces a 10-second timeout on all startup fetches. `Type` returns a string identifier for logging (e.g., `"env"`, `"aws-secretsmanager"`).

## Static vs Dynamic Sources

**Static sources** return the same value on every call. They are fetched once at startup and cached:

| Source | Config | Behavior |
|---|---|---|
| `env` | `var: GITHUB_TOKEN` | Reads the environment variable at startup |
| `static` | `value: "sk-xxxx"` | Returns the literal value |

**Dynamic sources** fetch from external systems and may return different values over time:

| Source | Config | Behavior |
|---|---|---|
| `aws-secretsmanager` | `secret: my-secret`, `region: us-east-1` | Fetches from AWS Secrets Manager |
| `gcp-secretmanager` | `secret: my-secret`, `project: my-project` | Fetches from GCP Secret Manager |
| `github-app` | `app_id`, `installation_id`, private key | Generates GitHub App installation tokens |

## RefreshingSource and Background Refresh

Sources whose credentials expire implement `RefreshingSource`:

```go
type RefreshingSource interface {
    CredentialSource
    TTL() time.Duration
}
```

`TTL` returns the duration until the most recently fetched credential expires. Gatekeeper uses this to schedule background refresh:

- **Refresh interval.** 75% of TTL, with a floor of 30 seconds. A token with a 60-minute TTL refreshes every 45 minutes.
- **Failure backoff.** On fetch failure, gatekeeper retries with exponential backoff starting at 1 second, doubling each attempt, capped at 60 seconds. A random jitter (up to 25% of the backoff) is added to prevent thundering herds.
- **Hot-swap.** Refreshed credentials are applied to the proxy immediately via `SetCredentialWithGrant`. In-flight requests use the previous value; subsequent requests use the new one.

The `github-app` source is a `RefreshingSource`. GitHub App installation tokens expire after one hour, so gatekeeper refreshes them every 45 minutes.

## Source Deduplication

When multiple credential entries share the same `SourceConfig` (identical `type`, `var`, `secret`, etc.), gatekeeper fetches the credential once and applies it to all matching hosts. A single background refresh goroutine updates every host that shares the source.

```yaml
credentials:
  - host: api.github.com
    grant: github
    source:
      type: github-app
      app_id: "12345"
      installation_id: "67890"
      private_key_path: ./key.pem
  - host: github.com
    grant: github
    format: basic
    prefix: x-access-token
    source:
      type: github-app
      app_id: "12345"
      installation_id: "67890"
      private_key_path: ./key.pem
```

Both entries share the same `github-app` source. Gatekeeper makes one API call to GitHub, generates one installation token, and applies it to both `api.github.com` (as `Bearer`) and `github.com` (as `Basic x-access-token:token`).

## CredentialResolver for Dynamic Resolution

Some credential flows require per-request context — for example, RFC 8693 token exchange, where the proxy exchanges a caller's identity token for a scoped access token. These flows use `CredentialResolver` instead of `CredentialSource`:

```go
type CredentialResolver func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]credentialHeader, error)
```

Unlike static sources (fetched once at startup), resolvers are called on every request. They receive both the proxy-level request (`proxyReq`, carrying `Proxy-Authorization`) and the application-level request (`innerReq`, which the resolver may inspect and modify). This enables patterns like extracting a subject identity header from the request, exchanging it for an access token, and stripping the identity header before forwarding.

The `token-exchange` source type creates a `CredentialResolver`. All other source types create a `CredentialSource`.

## Error Handling

Credential source errors at startup are fatal — gatekeeper refuses to start if any `Fetch` call fails. This fail-fast behavior prevents the proxy from running without required credentials.

During background refresh, errors are logged and retried with backoff. The previous credential value remains in use until a successful refresh replaces it.
