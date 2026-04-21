# Implementing an RFC 8693 Token Exchange Endpoint for Gatekeeper

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
| `actor_token`        | Caller proof token (e.g., the proxy auth password)                 | Only if `actor_token_from` is configured |
| `actor_token_type`   | `urn:ietf:params:oauth:token-type:access_token`                    | Only if `actor_token` is present |

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
| `expires_in`        | int    | No       | TTL in seconds. Gatekeeper caches the token per subject until expiry. If omitted, the token is not cached (re-exchanged on every request). |

**Important:** `access_token` must be non-empty. Gatekeeper treats an empty `access_token` as an error.

### Error (any non-200 status)

Gatekeeper treats any non-200 HTTP response as a failure. It reads up to 200 bytes of the response body for error logging. The request that triggered the exchange receives an HTTP 502 Bad Gateway response from the proxy.

Use standard OAuth error responses for debugging clarity:

```json
{
  "error": "invalid_grant",
  "error_description": "Subject token is expired or revoked"
}
```

## Caching Behavior

Gatekeeper caches tokens per `(subject_token, actor_token, endpoint)` tuple:

- If `expires_in` is provided, the token is cached until expiry. No refresh is attempted — when the cache entry expires, the next request triggers a new exchange.
- If `expires_in` is `0` or omitted, a default TTL of 5 minutes is applied.
- There is no proactive refresh or sliding window. Expired entries are replaced on the next request.

For high-throughput scenarios, set `expires_in` to a reasonable TTL (e.g., 3600 for one hour) to avoid per-request STS calls.

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

## Preventing Subject Impersonation

By default, subject identities are self-asserted — any caller can claim to be any user via the subject header or proxy auth username. This is acceptable when callers are isolated (separate containers with pre-configured `HTTP_PROXY` values), but in shared environments you may want the STS to verify the caller's identity.

The recommended pattern uses the proxy auth **password** as a per-user proof token. With `subject_from: proxy-auth`, gatekeeper extracts the username as the subject, but the password is also available to the STS via the RFC 8693 `actor_token` parameter (requires gatekeeper configuration to forward it — see below). The STS validates that the password belongs to the claimed subject before issuing tokens.

### Example: per-user API keys as proof tokens

Each user receives a unique API key. The client configures:

```
HTTP_PROXY=http://alice%40example.com:ak_alice_xxxxx@proxy:port
```

Gatekeeper sends the STS:

```
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=alice@example.com
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&actor_token=ak_alice_xxxxx
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
    actor   = request.form.get("actor_token")     # ak_alice_xxxxx

    # Verify the actor token belongs to this subject
    if not verify_api_key(subject, actor):
        return error_response(403, "invalid_grant",
            "actor_token does not match subject")

    # Issue scoped token as before
    token = mint_token_for(subject, request.form.get("resource"))
    return {"access_token": token, "expires_in": 3600}
```

Without a valid API key for `alice@example.com`, another user cannot exchange tokens on Alice's behalf — even if they control the proxy auth username.

### Gatekeeper Configuration

To enable actor token forwarding, add `actor_token_from: proxy-auth-password` to the token-exchange source config. This requires `subject_from: proxy-auth`.

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

When `actor_token_from` is not set, the proxy auth password is ignored and no `actor_token` parameter is sent to the STS.

## Implementation Checklist

- [ ] Accept `POST` with `Content-Type: application/x-www-form-urlencoded`
- [ ] Validate HTTP Basic auth credentials (`client_id` / `client_secret`)
- [ ] Validate `grant_type` is exactly `urn:ietf:params:oauth:grant-type:token-exchange`
- [ ] Extract `subject_token` — this identifies the user/caller to resolve credentials for
- [ ] Read `resource` if present — this identifies the target API the token will be used against
- [ ] Look up or mint an access token for the given subject and resource
- [ ] Return a JSON response with at minimum `access_token` (non-empty string)
- [ ] Set `expires_in` to enable client-side caching and reduce request volume
- [ ] Return non-200 with an error body for invalid/expired/unknown subjects
- [ ] Handle concurrent requests for the same subject (idempotency or internal locking)
- [ ] *(Optional)* Validate `actor_token` against `subject_token` to prevent impersonation (see [Preventing Subject Impersonation](#preventing-subject-impersonation))

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
