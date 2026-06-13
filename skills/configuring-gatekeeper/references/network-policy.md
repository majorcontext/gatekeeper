# Network policy

Control which hosts the proxy will forward traffic to. This is egress
lockdown — independent of credential injection. A host can be allowed without a
credential, and a credential entry does not implicitly allow a host under a
strict policy.

```yaml
network:
  policy: strict        # "permissive" (default) or "strict"
  allow:
    - "api.github.com"
    - "*.anthropic.com"
```

## Policies

- **`permissive`** — forward to any host. Credentials are still injected where
  they match. Good for development.
- **`strict`** — deny everything except hosts in `allow`. Anything not listed is
  refused. Use in production / sandboxes for true egress control.

## Allow-list patterns

Unlike credential hosts (which are matched exactly), network policy supports
globs:

- Exact host: `api.github.com`.
- Glob: `*.anthropic.com` matches `api.anthropic.com` and any subdomain at any
  depth (e.g. `a-b.anthropic.com`, `x.y.anthropic.com`) — it's a `.anthropic.com`
  suffix match — but **not** the bare `anthropic.com`.
- Ports: a pattern without an explicit port matches only the standard ports 80
  and 443. For a non-standard port, include it in the pattern (`host:8443`).
- Add regional/multi-label hosts explicitly (e.g.
  `us-central1-aiplatform.googleapis.com` alongside `aiplatform.googleapis.com`).

## Common pattern: lock down to exactly what you inject

Under `strict`, list every host that has a credential entry, plus any host the
client legitimately needs without a credential:

```yaml
credentials:
  - host: api.github.com
    source: { type: env, var: GITHUB_TOKEN }
  - host: aiplatform.googleapis.com
    source: { type: gcp-service-account, private_key_path: vertex-sa.json }

network:
  policy: strict
  allow:
    - api.github.com
    - aiplatform.googleapis.com
```

If a request is silently not forwarded, check the log for a policy denial and
confirm the host (and its exact label structure) is in `allow`.

## localhost and the host gateway

When a host-gateway hostname resolves to a loopback address, the proxy also
treats `localhost` / `127.0.0.1` / `::1` as equivalent — so credentials and
allow rules configured for the gateway hostname also apply to direct loopback
connections. (Host-gateway mapping is set by the embedder, e.g. Moat, not in
standalone YAML.)
