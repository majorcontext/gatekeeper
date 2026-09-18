---
title: "Credential Caching, Refresh, and Invalidation"
description: "How gatekeeper fetches, caches, refreshes, and evicts credentials across their lifecycle, from startup through 401/403-triggered invalidation."
keywords: ["gatekeeper", "credential refresh", "credential caching", "invalidation", "backoff", "token exchange"]
---

# Credential caching, refresh, and invalidation

Credentials move through several distinct lifecycle stages depending on source type: a one-time fetch at startup, a background refresh loop, a per-request cache, or an eviction triggered by an upstream rejection. This guide consolidates the timing and failure behavior of each stage in one place. For the source types themselves, see [Credential Sources](../reference/03-credential-sources.md) (reference) and [Sources](../concepts/03-credential-sources.md) (concepts); for token exchange specifically, see [Token Exchange](./06-token-exchange.md).

## Prerequisites

- A working gatekeeper configuration with at least one credential ([CA Setup](./01-ca-setup.md))

## Lifecycle overview

| Stage | Applies to | Trigger | Behavior |
|-------|-----------|---------|----------|
| Startup fetch | All sources | Server startup | Single `Fetch`, 10s timeout, failure is fatal |
| Background refresh | `RefreshingSource` (`process`, `github-app`, `gcp-service-account`) | Timer at 75% of TTL, floor 30s | Hot-swaps the credential; failures retry with backoff |
| Per-request cache | `token-exchange` | Cache miss on incoming request | Exchanges with the STS, caches up to 1 minute, coalesced via singleflight |
| Invalidation | Sources with an `Invalidate` hook (`token-exchange`) | Upstream `401`/`403` on an injected credential | Drops the cache entry so the next request re-resolves; rate-limited to one eviction per key per 10s |

## Startup: fetch once, fail fast

Every credential in `gatekeeper.yaml` is fetched once when the server starts, with a 10-second timeout per fetch. If any `Fetch` call fails or times out, gatekeeper refuses to start:

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

If the GitHub App's private key file is missing or the installation token request fails, the process exits with an error naming the host — it does not start with a missing credential and fail requests later. `static` and `env` sources resolve instantly; `aws-secretsmanager`, `gcp-secretmanager`, `process`, `github-app`, and `gcp-service-account` all make a network or subprocess call during this window, so a slow or unreachable backend delays startup up to the 10s timeout per credential.

Credentials that share an identical `source` block (same type and fields) are deduplicated: one `Fetch`, applied to every host that references it. See [Source Deduplication](../concepts/03-credential-sources.md#source-deduplication).

## Background refresh

Sources whose credentials expire implement `RefreshingSource`, adding a `TTL() time.Duration` method to `CredentialSource`. Gatekeeper schedules a background refresh goroutine per unique source:

- **Refresh interval:** 75% of the reported TTL, floored at 30 seconds. A GitHub App installation token (1-hour TTL) refreshes every 45 minutes. A `process` source with no expiry-aware output and the default 5-minute `ttl` refreshes every 3m45s.
- **Hot-swap:** the refreshed value replaces the credential on the proxy immediately (`SetCredentialWithGrant`) for every host sharing that source. In-flight requests already holding the old value are unaffected; the next request picks up the new one.
- **Failure backoff:** on a failed refresh, gatekeeper retries starting at 1 second, doubling on each subsequent failure, capped at 60 seconds. A random jitter of up to 25% of the (already-capped) backoff is added on top, so a run of consecutive failures can wait up to ~75 seconds between attempts, not a strict 60s ceiling. The previous credential value stays in use throughout — a failed refresh never blanks a working credential.

```yaml
credentials:
  - host: api.example.com
    header: x-api-key
    grant: helper
    source:
      type: process
      command: "op read op://vault/example/api-key"
      ttl: 10m
```

With `ttl: 10m` and no expiry-aware JSON output, this refreshes every 7m30s; a failing `op` invocation (an expired session, say) retries at 1s, 2s, 4s... up to the ~60-75s ceiling until the helper succeeds again.

### gcp-service-account and github-app: two different rotation behaviors

Both are `RefreshingSource`s with a one-hour token TTL, but they react differently to a rejection:

- **github-app** parses `expires_at` from each GitHub API response and schedules the next refresh from it. There is no key-rotation-specific handling beyond the standard backoff — a rejected JWT (e.g., the App's private key was revoked) simply keeps failing and retrying.
- **gcp-service-account** additionally detects a rejected assertion — but only in Secret Manager mode (`secret` + `project`): if the GCP token endpoint returns `400`, `401`, or `403` for the signed JWT, gatekeeper drops its in-memory copy of the parsed service account key and re-reads it from Secret Manager on the next attempt, picking up a rotated key without a restart as long as the *new* key was already written there. Keys loaded from a file (`private_key_path`) or environment variable (`private_key_env`) have no backing source to re-read — rotating them requires a restart. A `429` or `5xx` from the token endpoint is treated as transient and does not drop the cached key. See [GCP Service Account Tokens](./15-gcp-service-account.md) for the full rotation semantics.

This distinction only matters when the key itself rotates (e.g., a new GCP service account key replaces the old one in Secret Manager); for both sources, an expired *token* is handled by the ordinary refresh-before-expiry schedule, not by this fallback path.

## Per-request caching: token exchange

`token-exchange` does not fit the fetch-once/refresh-on-a-timer model above — it resolves a credential per request, scoped to the caller's identity, and has its own cache:

- Tokens are cached per `(subject_token, actor_token)` pair.
- Cache TTL is the STS's `expires_in`, **capped at 1 minute** regardless of what the STS advertises. If `expires_in` is `0` or omitted, the 1-minute cap is used directly.
- Concurrent requests for the same subject are coalesced into a single STS call via singleflight — the 1-minute cap does not mean an STS call every minute per active subject, it means at most one exchange per subject per minute even under concurrent load.
- There is no proactive refresh: a cache miss (first request, or the entry aged out) triggers a synchronous exchange on that request's path.

See [Token Exchange: Caching Behavior](./06-token-exchange.md#caching-behavior) for the full mechanics and the reasoning behind the 1-minute cap.

## Invalidation on 401/403

When the destination rejects a forwarded request with `401 Unauthorized` or `403 Forbidden`, gatekeeper evicts every credential that was injected into that specific request — not every credential configured for the host, only the ones this request actually used. The next request re-resolves rather than replaying a credential the destination just refused.

This is evict-only: the failed request itself is never retried. Its body may have already been consumed by the time the response arrives, and the operations that surface this (a `git push`, an API mutation) are frequently not safe to replay automatically.

Only sources that expose an `Invalidate` hook participate. Concretely, that means `token-exchange` today — eviction drops the cached token for that `(subject_token, actor_token)` pair. Static sources (`env`, `static`) and sources fetched once at startup with no cache to drop have no `Invalidate` hook and are unaffected by a 401/403; the value simply stays as configured until the process restarts or a background refresh (for `RefreshingSource`s) replaces it on its own schedule.

Evictions are rate-limited to one per cache key per 10 seconds. A client looping on a request that fails for a reason unrelated to a stale credential (a secondary rate limit, a permissions gap) triggers at most one eviction, and therefore at most one extra STS call, per 10-second window — not one per failed request. The trade-off: a genuinely rotated credential can take up to 10 seconds after the first eviction to be picked up, since evictions inside the cooldown are no-ops.

A `5xx` response is left alone entirely — it says nothing about whether the injected credential is valid.

## Summary table

| Source type | Startup fetch | Background refresh | Per-request cache | Participates in 401/403 invalidation |
|---|---|---|---|---|
| `env`, `static` | Yes | No | No | No |
| `aws-secretsmanager`, `gcp-secretmanager` | Yes | No | No | No |
| `process` | Yes | Yes (75% of TTL, floor 30s) | No | No |
| `github-app` | Yes | Yes (75% of TTL, floor 30s) | No | No |
| `gcp-service-account` | Yes | Yes (75% of TTL, floor 30s); Secret Manager mode also drops the cached key on assertion rejection | No | No |
| `token-exchange` | No (resolved per request) | No | Yes (STS `expires_in`, capped at 1 minute) | Yes (10s cooldown per subject/actor key) |

## Next steps

- [Credential Sources](../reference/03-credential-sources.md) — field-by-field reference for every source type
- [Token Exchange](./06-token-exchange.md) — configuring the per-request resolver and its STS contract
- [MCP Relay Setup](./16-mcp-relay.md) — credentials referenced by MCP server grants follow the same lifecycle
