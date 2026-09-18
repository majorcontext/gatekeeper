---
title: "Token Exchange"
description: "Resolve per-user credentials dynamically by calling an external Security Token Service using RFC 8693 token exchange."
keywords: ["gatekeeper", "token exchange", "RFC 8693", "STS", "OAuth"]
---

# Token exchange (RFC 8693)

Resolve per-user credentials dynamically by calling an external Security Token Service (STS). Multiple callers with different identities share a single gatekeeper instance. Each request triggers a token exchange -- or uses a cached token -- scoped to the caller's identity.

This guide covers gatekeeper configuration and the STS endpoint contract. Implement the STS endpoint yourself; gatekeeper is the client.

## Prerequisites

- CA certificate generated ([CA Setup](./01-ca-setup.md))
- An STS endpoint that implements RFC 8693 token exchange (see [STS Endpoint Requirements](#sts-endpoint-requirements) below)
- Client credentials (`client_id` and `client_secret`) for authenticating gatekeeper to the STS

## How it works

1. A request arrives at gatekeeper with a subject identity (via header or proxy auth username).
2. Gatekeeper checks its cache for a valid token for that subject.
3. On cache miss, gatekeeper sends an RFC 8693 `POST` to the STS with the subject token, client credentials, and optional resource/actor parameters.
4. The STS returns an `access_token` (and optional `expires_in`).
5. Gatekeeper caches the token and injects it into the upstream request.

## Subject identity modes

Gatekeeper extracts the subject identity from one of two sources. The two modes are mutually exclusive.

### Mode 1: Subject from request header

The subject identity is read from a named HTTP header on each request. Gatekeeper strips the header before forwarding upstream.

```yaml
credentials:
  - host: api.github.com
    grant: github
    prefix: Bearer
    source:
      type: token-exchange
      endpoint: https://sts.example.com/token
      client_id: gk-client
      client_secret_env: STS_CLIENT_SECRET
      subject_header: X-Gatekeeper-Subject
      resource: https://api.github.com
```

The client includes the subject in each request:

```bash
curl --proxy http://127.0.0.1:9080 --cacert ca.crt \
  -H "X-Gatekeeper-Subject: alice@example.com" \
  https://api.github.com/user
```

### Mode 2: Subject from proxy auth

The subject identity is extracted from the username in proxy authentication credentials. No request headers are modified.

```yaml
credentials:
  - host: api.github.com
    grant: github
    prefix: Bearer
    source:
      type: token-exchange
      endpoint: https://sts.example.com/token
      client_id: gk-client
      client_secret_env: STS_CLIENT_SECRET
      subject_from: proxy-auth
      resource: https://api.github.com
```

The client encodes the subject in the proxy URL. Percent-encode `@` as `%40`:

```bash
export HTTP_PROXY="http://alice%40example.com:proxypass@127.0.0.1:9080"
curl --cacert ca.crt https://api.github.com/user
```

## Configuration reference

| Field                | Required       | Default                                                | Description                                              |
|----------------------|----------------|--------------------------------------------------------|----------------------------------------------------------|
| `endpoint`           | Yes            | --                                                     | STS token endpoint URL                                   |
| `client_id`          | Yes            | --                                                     | OAuth client ID for HTTP Basic auth to STS               |
| `client_secret`      | One of         | --                                                     | Client secret (literal value)                            |
| `client_secret_env`  | One of         | --                                                     | Environment variable containing the client secret        |
| `subject_header`     | One of         | --                                                     | Request header to extract subject from (stripped before forwarding) |
| `subject_from`       | One of         | --                                                     | Set to `proxy-auth` to extract subject from proxy auth username |
| `subject_token_type` | No             | `urn:ietf:params:oauth:token-type:access_token`        | Token type URI for the subject token                     |
| `resource`           | No             | --                                                     | Target resource URI sent to the STS                      |
| `actor_token_from`   | No             | --                                                     | Set to `proxy-auth-password` to forward the proxy auth password as actor token |
| `actor_token_type`   | No             | `urn:ietf:params:oauth:token-type:access_token`        | Token type URI for the actor token                       |
| `cache_ttl`          | No             | `1m`                                                   | Cache ceiling as a Go duration; `"0"` disables caching   |
| `bot_subject`        | No             | `""` (disabled)                                        | A sentinel subject value that falls through to the next credential rule instead of an STS exchange -- see [Bot/service fallback](#botservice-fallback) below |

## Bot/service fallback

An empty subject already falls through to the next matching credential rule for a host instead of calling the STS -- `getCredentialsForRequest` (`proxy/proxy.go`) treats a resolver's `(nil, nil)` return as "try the next rule," which is how a per-host `github-app` (bot) credential is meant to take over when there is no per-user identity for the STS to exchange. This is what makes the common two-rule pattern work: a `token-exchange` rule for real users, then a `github-app` rule beneath it as the bot fallback.

A caller building the proxy-auth URL with `undici`'s `ProxyAgent` (Node.js) cannot express that fallback cleanly: undici only sends `Proxy-Authorization` when the proxy URL's username is non-empty (`username && password`, no password-only branch) -- an empty-username proxy URL, the natural way to say "no subject, use the bot," silently sends no proxy auth at all, which most gatekeeper deployments require.

`bot_subject` gives the same fallthrough behavior a **non-empty**, dedicated sentinel value, so a caller can encode "use the bot" as an ordinary (non-empty) proxy-auth username:

```yaml
credentials:
  - host: api.github.com
    grant: github-user
    source:
      type: token-exchange
      endpoint: https://sts.example.com/token
      client_id: gk-client
      client_secret_env: STS_CLIENT_SECRET
      subject_from: proxy-auth
      bot_subject: "-"
      resource: https://api.github.com

  - host: api.github.com
    grant: github-bot
    source:
      type: github-app
      app_id: "123456"
      installation_id: "789012"
      private_key_env: GITHUB_APP_PRIVATE_KEY
```

```bash
# Real user: subject_from proxy-auth reads "alice@example.com" and exchanges it.
HTTP_PROXY="http://alice%40example.com:ak_alice_xxxxx@127.0.0.1:9080"

# Bot/service traffic: the sentinel subject skips the STS and falls through
# to the github-app rule above, with a non-empty proxy-auth username the
# whole way -- undici's Proxy-Authorization check passes.
HTTP_PROXY="http://-:proxy-token@127.0.0.1:9080"
```

`bot_subject` is unset by default, so this is opt-in and fully backward compatible: a config written before this field existed keeps exchanging every non-empty subject exactly as before. When set, pick a value that can never collide with a real subject your deployment could see -- `"-"` is a safe default because no CF-Access email, GitHub username, or similar identity string is ever a bare hyphen.

**`bot_subject` requires `subject_from: proxy-auth` and gatekeeper enforces that, not merely documents it.** Setting `bot_subject` on a `subject_header`-mode source is a config-load error (`"bot_subject requires subject_from 'proxy-auth'"`). This is not incidental: `subject_header` mode reads a caller-controlled, self-asserted request header with nothing authenticating it, unlike `subject_from: proxy-auth`. Without this restriction, any caller could simply send the configured sentinel value in that header to skip the STS and fall through to the credential below -- typically broader, e.g. a `github-app` bot rule -- bypassing per-subject authentication for the host entirely. The check is enforced twice: once at config load (rejecting the combination outright) and once again at request time (the fallthrough only ever fires when the resolver is actually in `proxy-auth` mode), so the property holds even for a resolver constructed outside the normal config-loading path.

The sentinel subject is exactly what shows up as `user_id` on the [canonical log line](../concepts/06-observability.md#canonical-log-lines), since `user_id` is populated from the same proxy-auth username the resolver reads. That's a strict readability improvement over the empty-subject case: `user_id="-"` reads unambiguously as "bot/service traffic," where an absent `user_id` field (the empty-subject case) gives no positive signal at all.

## Actor token forwarding

By default, subject identities are self-asserted -- any caller can claim any identity. In shared environments, use **actor token forwarding** to let the STS verify caller identity.

Configure gatekeeper to forward the proxy auth password as the RFC 8693 `actor_token`:

```yaml
credentials:
  - host: api.github.com
    grant: github
    prefix: Bearer
    source:
      type: token-exchange
      endpoint: https://sts.example.com/token
      client_id: gk-client
      client_secret_env: STS_CLIENT_SECRET
      subject_from: proxy-auth
      actor_token_from: proxy-auth-password
      resource: https://api.github.com
```

Each caller uses a unique API key as the proxy auth password:

```bash
HTTP_PROXY=http://alice%40example.com:ak_alice_xxxxx@127.0.0.1:9080
```

Gatekeeper sends both `subject_token=alice@example.com` and `actor_token=ak_alice_xxxxx` to the STS. The STS validates that the API key belongs to Alice before issuing tokens.

When `actor_token_from` is configured on any credential, gatekeeper requires all clients to provide Basic proxy auth with a non-empty password. The password is not checked against a static value -- it is forwarded to the STS.

## Caching behavior

Gatekeeper caches tokens per `(subject_token, actor_token)` pair by default:

- `cache_ttl` sets the cache ceiling as a Go duration. It defaults to `1m`, values above `1m` are capped at `1m`, and `"0"` disables caching.
- If `expires_in` is returned by the STS, the token is cached until the earlier of that expiry and `cache_ttl`.
- If `expires_in` is `0` or omitted, `cache_ttl` is used.
- Concurrent requests for the same subject are coalesced into a single STS call via singleflight, including when caching is disabled.
- Expired entries are evicted lazily on the next exchange.
- There is no proactive refresh. When a cached token expires, the next request triggers a new exchange.
- When the destination rejects an injected credential with `401` or `403`, the cache entry is dropped so the next request exchanges afresh. The failed request is **not** retried. Evictions are rate-limited to one per key per 10 seconds.

The default cap exists because a long `expires_in` only means the token *may* live that long, not that it stays valid. The upstream credential behind the exchange can be revoked, rotated, or re-authorized at any moment, and gatekeeper has no way to learn of it. Honoring a multi-hour `expires_in` meant a rotated credential kept being injected — and kept being rejected — for hours. Set `cache_ttl: "0"` when the STS dynamically selects mutable backing state that can change while `(subject_token, actor_token)` remains constant, such as a subscription account selected for a long-running client.

With the default, an `expires_in` above 60 seconds does not reduce STS request volume. With caching disabled, size the STS for one exchange per request (simultaneous requests for the same key are still coalesced).

## STS endpoint requirements

Gatekeeper sends a `POST` with `Content-Type: application/x-www-form-urlencoded` and HTTP Basic authentication.

### Request format

```http
POST /token HTTP/1.1
Host: sts.example.com
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token=alice%40example.com&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&resource=https%3A%2F%2Fapi.github.com
```

### Success response (HTTP 200)

```json
{
  "access_token": "gho_exchanged_abc123",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

| Field               | Type   | Required | Description                                          |
|---------------------|--------|----------|------------------------------------------------------|
| `access_token`      | string | Yes      | The token gatekeeper injects upstream                |
| `issued_token_type` | string | No       | Token type URI of the issued token                   |
| `token_type`        | string | No       | Informational; gatekeeper uses its own prefix config |
| `expires_in`        | int    | No       | TTL in seconds, capped at 60. Defaults to the cap if omitted |

`access_token` must be non-empty. Gatekeeper treats an empty value as an error.

### Error response (non-200)

Gatekeeper treats any non-200 status as a failure and returns HTTP 502 to the client. Use standard OAuth error format:

```json
{
  "error": "invalid_grant",
  "error_description": "Subject token is expired or revoked"
}
```

> **Note:** Do not echo `actor_token` in error responses. Gatekeeper logs up to 200 bytes of STS error bodies, so sensitive values would appear in proxy logs.

## Implementation checklist

- [ ] Accept `POST` with `Content-Type: application/x-www-form-urlencoded`
- [ ] Validate HTTP Basic auth credentials (`client_id` / `client_secret`)
- [ ] Validate `grant_type` is exactly `urn:ietf:params:oauth:grant-type:token-exchange`
- [ ] Extract `subject_token` -- the user/caller identity
- [ ] Read `resource` if present -- the target API
- [ ] Look up or mint an access token for the given subject and resource
- [ ] Return JSON with a non-empty `access_token`
- [ ] Set `expires_in` to enable caching (values above 60s are capped)
- [ ] Return non-200 for invalid/expired/unknown subjects
- [ ] Handle concurrent requests (idempotency or internal locking)
- [ ] *(Optional)* Validate `actor_token` against `subject_token` to prevent impersonation

## Testing

Test your STS endpoint with curl:

```bash
curl -X POST https://sts.example.com/token \
  -u "gk-client:your-secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=alice&subject_token_type=urn:ietf:params:oauth:token-type:access_token&resource=https://api.github.com"
```

Then test through the proxy:

```bash
curl --cacert ca.crt --proxy http://127.0.0.1:9080 \
  -H "X-Gatekeeper-Subject: alice" \
  https://api.github.com/user
```

The proxy log shows credential injection with the grant name.

## Next steps

- [Network Lockdown](./07-network-lockdown.md) — combine token exchange with strict network policy
- [OpenTelemetry](./08-opentelemetry.md) — trace token exchange calls end-to-end
- [STS Endpoint Implementation Notes](../../token-exchange-endpoint.md) — the full wire contract and implementation checklist for building an STS endpoint
