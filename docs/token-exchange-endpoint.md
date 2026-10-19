# Implementing an RFC 8693 Token Exchange Endpoint for Gatekeeper

This document is the STS-implementer contract: authentication, wire format, and caching semantics for the endpoint gatekeeper calls. For configuring gatekeeper itself as the token-exchange client — subject/actor modes, YAML fields, actor-token forwarding — see the [Token Exchange guide](content/guides/06-token-exchange.md).

## Context

Gatekeeper is a credential-injecting TLS proxy. It can be configured with a `token-exchange` credential source that dynamically resolves per-user OAuth tokens by calling an external Security Token Service (STS) endpoint using the [RFC 8693 OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) protocol.

Multiple callers with different user identities route requests through a single shared gatekeeper instance. When a request arrives with a subject identity — either via a custom header or extracted from the proxy authentication username — gatekeeper calls your STS endpoint to exchange that subject token for an access token scoped to the target API. The exchanged token is injected into the upstream request.

Your job is to implement the STS endpoint that gatekeeper calls.

## What Gatekeeper Sends

Gatekeeper sends a `POST` request to your endpoint with:

### Authentication

HTTP Basic authentication using the configured `client_id` and `client_secret`:

```
Authorization: Basic base64(client_id:client_secret)
```

### Request Body

`Content-Type: application/x-www-form-urlencoded` with the following parameters:

| Parameter            | Value                                                              | Always present |
|----------------------|--------------------------------------------------------------------|----------------|
| `grant_type`         | `urn:ietf:params:oauth:grant-type:token-exchange`                  | Yes            |
| `subject_token`      | The subject identity (e.g., `usr_alice` or `alice@example.com`)    | Yes            |
| `subject_token_type` | A token type URI (default: `urn:ietf:params:oauth:token-type:access_token`) | Yes  |
| `resource`           | Target resource URI (e.g., `https://api.github.com`)               | Only if configured |
| `actor_token`        | Caller proof token (the proxy auth password, which is the shared proxy token)                 | Only if `actor_token_from` is configured |
| `actor_token_type`   | Token type URI (default: `urn:ietf:params:oauth:token-type:access_token`; configurable via `actor_token_type`) | Only if `actor_token` is present |

### Example Request

```http
POST /token HTTP/1.1
Host: sts.example.com
Authorization: Basic <base64(client_id:client_secret)>
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&subject_token=usr_alice&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&resource=https%3A%2F%2Fapi.github.com
```

## What Gatekeeper Expects Back

### Success (HTTP 200)

A JSON response per [RFC 8693 §2.2.1](https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.1):

```json
{
  "access_token": "gho_exchanged_abc123",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

| Field               | Type   | Required | Description                                                      |
|---------------------|--------|----------|------------------------------------------------------------------|
| `access_token`      | string | **Yes**  | The token gatekeeper injects into the upstream request            |
| `issued_token_type` | string | No       | Token type URI of the issued token                                |
| `token_type`        | string | No       | How the token should be used (informational; gatekeeper uses its own prefix config) |
| `expires_in`        | int    | No       | TTL in seconds. Gatekeeper caches the token per subject until expiry, capped at 1 minute. If omitted, the cap is used. |
| `gatekeeper_upgrade` | object | No      | An upgrade hint; see [Upgrade hints](#upgrade-hints). |

**Important:** `access_token` must be non-empty. Gatekeeper treats an empty `access_token` as an error.

### Decline (HTTP 400)

An STS that has no token for this subject, but wants the request to go out with the host's configured static credential, declines. The response is an [RFC 6749 §5.2](https://datatracker.ietf.org/doc/html/rfc6749#section-5.2) error with `invalid_target` ([RFC 8693 §2.2.2](https://datatracker.ietf.org/doc/html/rfc8693#section-2.2.2): unwilling to issue a token for the target) and the extension parameter `gatekeeper_fallback`:

```json
{
  "error": "invalid_target",
  "error_description": "no grant for this target; use the configured default",
  "gatekeeper_fallback": "default",
  "gatekeeper_upgrade": {"route": "gcp", "entitlements": ["gcp-deploy-dev"]}
}
```

Gatekeeper then injects the static credentials configured for the same host, as it does for an empty or `bot_subject` subject. With no static credential for the host, the client's own headers go upstream unchanged. A decline is cached like a token, for 1 minute, so a host with a static default does not call the STS on every request. A `401`, `403`, or `429` from the destination drops the cached decline, so a credential the STS starts issuing applies to the client's retry.

Only `invalid_target` with `gatekeeper_fallback: "default"` is a decline. A bare `invalid_target`, which also reports a target the STS does not know, fails the request. An STS that returns a decline to an older gatekeeper fails the request the same way.

### Upgrade hints

A success or a decline may carry `gatekeeper_upgrade`: an object whose values are strings or arrays of strings, saying what the subject could request beyond the credential it got. When the destination answers `401` or `403`, gatekeeper sends it to the client as the `X-Gatekeeper-Upgrade` header, an [RFC 9651](https://datatracker.ietf.org/doc/html/rfc9651) dictionary of inner lists with sorted members:

```
X-Gatekeeper-Upgrade: entitlements=("gcp-deploy-dev"), route=("gcp")
```

Gatekeeper removes any `X-Gatekeeper-Upgrade` header or trailer the destination sends, so the client can trust its origin. When the host's resolver declined, the decline's hint is sent; otherwise the hint of the first injected credential that has one. A member whose key is not a lowercase RFC 9651 key, or with a value that is not printable ASCII, is dropped, and a serialized hint over 1024 bytes is dropped whole. A `gatekeeper_upgrade` of any other shape, including a `null` value or array element, is ignored; it never fails the exchange.

### No credential for the subject (HTTP 404)

Answer `404` when the subject has no credential for the target, for example a user who has not connected the account the route needs. On a rule with `static_fallback: explicit`, gatekeeper refuses the request with `403` and `X-Gatekeeper-Blocked: credential-required`, and appends your `error_description` to the message the client sees. Keep the description to printable ASCII, 200 bytes or fewer, with no secrets; gatekeeper drops one with any other character and cuts a longer one. Gatekeeper does not cache a `404`, so a credential the user connects applies to the next request. On any other rule, a `404` fails the request with `502`, as before.

### Error (any other non-200 status)

Gatekeeper treats any other non-200 HTTP response as a failure. It reads up to 200 bytes of the response body for error logging. The request that triggered the exchange receives an HTTP 502 Bad Gateway response from the proxy.

**Important:** Do not echo request parameters (especially `actor_token`) in error response bodies. Gatekeeper includes the STS error body in log messages, so sensitive values like the caller's API key would appear in proxy logs.

Use standard OAuth error responses for debugging clarity:

```json
{
  "error": "invalid_grant",
  "error_description": "Subject token is expired or revoked"
}
```

## Caching Behavior

Gatekeeper caches tokens per `(subject_token, actor_token)` pair within each credential source instance:

- If `expires_in` is provided, the token is cached until expiry, capped at 1 minute. No refresh is attempted — when the cache entry expires, the next request triggers a new exchange.
- If `expires_in` is `0` or omitted, the cap is used.
- A decline is cached for the cap, with its upgrade hint. The destination statuses that drop a token drop a decline too, under the same per-key rate limit.
- There is no proactive refresh or sliding window. Expired entries are replaced on the next request.
- A `401`, `403`, or `429` from the destination drops the cache entry, so the next request exchanges afresh. A `429` may signal an exhausted backing credential even when its token remains valid. Evictions are rate-limited to one per key per 10 seconds.
- Concurrent requests that share a cache-miss key are coalesced with `singleflight.Group` — only one exchange call reaches your endpoint per key at a time; the other callers block on the same in-flight call and share its result. You do not need your own request-level locking or idempotency handling to survive a burst of simultaneous requests for the same subject, though duplicate exchanges can still happen across separate cache keys (e.g. different actor tokens) or after a cache entry has expired and a new one hasn't populated yet.

The cap bounds how long a rotated or revoked upstream credential keeps being injected. Because of it, an `expires_in` above 60 seconds does not reduce STS request volume — size the endpoint for roughly one exchange per subject per minute.

## Gatekeeper Configuration Reference

The gatekeeper YAML config for a token-exchange credential looks like:

```yaml
# Mode 1: Subject from a custom request header
credentials:
  - host: api.github.com
    grant: github
    prefix: Bearer
    source:
      type: token-exchange
      endpoint: https://sts.example.com/token
      client_id: gk-client
      client_secret_env: STS_CLIENT_SECRET
      subject_header: X-Gatekeeper-Subject    # extract subject from this request header
      resource: https://api.github.com

# Mode 2: Subject from proxy authentication username
credentials:
  - host: api.github.com
    grant: github
    prefix: Bearer
    source:
      type: token-exchange
      endpoint: https://sts.example.com/token
      client_id: gk-client
      client_secret_env: STS_CLIENT_SECRET
      subject_from: proxy-auth                # extract subject from Proxy-Authorization username
      resource: https://api.github.com
```

**`subject_header`** — The subject identity is read from the named HTTP header on each request. Gatekeeper strips the header before forwarding upstream. Use this when callers can set custom headers.

**`subject_from: proxy-auth`** — The subject identity is extracted from the username in the client's proxy authentication credentials (`HTTP_PROXY=http://alice%40example.com:<token>@proxy:port`). The `@` in email addresses is percent-encoded as `%40` in the URL. No request headers are modified. Use this when callers cannot set custom headers (e.g., tools that only configure `HTTP_PROXY`).

The two options are mutually exclusive — set one or the other, not both.

With `subject_from: proxy-auth`, a config may also set `bot_subject` to a sentinel value (e.g. `"-"`) that never reaches this endpoint at all — gatekeeper matches it before ever building the exchange request and falls through to the next credential rule for the host instead. Your STS implementation never sees that value as a `subject_token`; see [Token Exchange: Bot/service fallback](content/guides/06-token-exchange.md#botservice-fallback) for the client-side config.

## Verifying the Gatekeeper Caller

By default, subject identities are self-asserted — any caller can claim to be any user via the subject header or proxy auth username. This is acceptable when callers are isolated (separate containers with pre-configured `HTTP_PROXY` values), but in shared environments you may want the STS to verify that the request came through an authorized gatekeeper client. This does not stop an authorized client from claiming another subject.

The recommended pattern uses the proxy auth **password** as a proof token. With `subject_from: proxy-auth`, gatekeeper extracts the username as the subject, and the password reaches the STS as the RFC 8693 `actor_token` parameter (requires gatekeeper configuration to forward it -- see below). Gatekeeper requires `proxy.auth_token` or `proxy.auth_token_env` in this mode and rejects any other password with `407`, so the `actor_token` is the shared proxy token.

### Example: the shared proxy token as the actor token

The client configures:

```
HTTP_PROXY=http://alice%40example.com:shared-proxy-token@proxy:port
```

Gatekeeper sends the STS:

```
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=alice@example.com
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&actor_token=shared-proxy-token
&actor_token_type=urn:ietf:params:oauth:token-type:access_token
&resource=https://api.github.com
```

The STS implementation:

```python
def handle_token_exchange(request):
    # Validate gatekeeper client credentials (unchanged)
    if not verify_basic_auth(request, CLIENT_ID, CLIENT_SECRET):
        return error_response(401, "unauthorized")

    subject = request.form["subject_token"]      # alice@example.com
    actor   = request.form.get("actor_token")     # shared-proxy-token

    # Verify the caller holds the shared proxy token
    if not verify_proxy_token(actor):
        return error_response(403, "invalid_grant",
            "actor_token is not the gatekeeper proxy token")

    # Issue scoped token as before
    token = mint_token_for(subject, request.form.get("resource"))
    return {"access_token": token, "expires_in": 3600}
```

The actor token proves the caller reached gatekeeper with its shared token. It does not bind a subject to one caller: gatekeeper has no per-caller password mode.

### Gatekeeper Configuration

To enable actor token forwarding, add `actor_token_from: proxy-auth-password` to the token-exchange source config. This requires `subject_from: proxy-auth`. When `actor_token_from` is configured, gatekeeper rejects requests that do not include a proxy auth password — the STS is never called without an actor token.

```yaml
proxy:
  auth_token_env: GATEKEEPER_PROXY_AUTH_TOKEN

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

When `actor_token_from` is not set, the proxy auth password is ignored and no `actor_token` parameter is sent to the STS.

By default, `actor_token_type` is `urn:ietf:params:oauth:token-type:access_token`. To override (e.g., if your actor tokens are JWTs), set `actor_token_type` in the source config.

**Important:** `actor_token_from` requires `proxy.auth_token` or `proxy.auth_token_env`; gatekeeper fails at config load without one. Gatekeeper requires clients to provide Basic proxy auth with a non-empty password, and rejects a password that does not equal the shared token with `407` before it reaches your endpoint. The `actor_token` your endpoint receives is therefore that shared token. If your config mixes `actor_token_from` credentials with non-token-exchange credentials, use `network.policy: strict` with a tight `allow` list to restrict which hosts the proxy can reach.

## Implementation Checklist

- [ ] Accept `POST` with `Content-Type: application/x-www-form-urlencoded`
- [ ] Validate HTTP Basic auth credentials (`client_id` / `client_secret`)
- [ ] Validate `grant_type` is exactly `urn:ietf:params:oauth:grant-type:token-exchange`
- [ ] Extract `subject_token` — this identifies the user/caller to resolve credentials for
- [ ] Read `resource` if present — this identifies the target API the token will be used against
- [ ] Look up or mint an access token for the given subject and resource
- [ ] Return a JSON response with at minimum `access_token` (non-empty string)
- [ ] Set `expires_in` to enable client-side caching (gatekeeper caps it at 60s)
- [ ] Return non-200 with an error body for invalid/expired/unknown subjects
- [ ] Handle concurrent requests for the same subject (idempotency or internal locking)
- [ ] *(Optional)* Validate `actor_token` as the gatekeeper proxy token (see [Verifying the Gatekeeper Caller](#verifying-the-gatekeeper-caller))

## Testing

You can test your endpoint against gatekeeper's token exchange client directly. The end-to-end integration test in `gatekeeper_test.go` (`TestHTTPSTokenExchangeEndToEnd`) demonstrates the complete flow with a mock STS — use it as a reference for the exact wire format. For the proxy-auth subject mode, see `TestHTTPSTokenExchangeProxyAuthSubject`.

Manual test with curl:

```bash
curl -X POST https://sts.example.com/token \
  -u "<client_id>:<client_secret>" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=usr_alice&subject_token_type=urn:ietf:params:oauth:token-type:access_token&resource=https://api.github.com"
```

Expected response:

```json
{
  "access_token": "<token-for-usr_alice-scoped-to-api.github.com>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 3600
}
```
