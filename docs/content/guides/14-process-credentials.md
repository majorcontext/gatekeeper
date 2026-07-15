---
title: "Host Command Credentials (process source)"
description: "Run a host command and inject its output as a credential, so gatekeeper can use any secret manager that has a CLI."
keywords: ["gatekeeper", "process source", "credential_process", "1Password", "pass", "credential source"]
---

# Host command credentials (process source)

Run a host command and use its trimmed stdout as the credential value. The `process` source is the escape hatch for secret managers gatekeeper has no dedicated integration for: any CLI that prints a credential — a password manager, an OS keychain tool, a corporate credential helper — can back a grant without writing Go code.

## When to use it

Use `process` when the credential lives behind a command-line tool rather than an API gatekeeper speaks natively (AWS Secrets Manager, GCP Secret Manager, GitHub Apps). This covers bring-your-own secret managers: 1Password, `pass`, a Vault CLI wrapper, or an internal `credential_process`-style helper.

If the backend has a stable HTTP API, prefer a dedicated source ([AWS Secrets Manager](./03-aws-secrets-manager.md), [GCP Secret Manager](./04-gcp-secret-manager.md)) — those fetch over HTTPS directly instead of shelling out.

## Prerequisites

- CA certificate generated ([CA Setup](./01-ca-setup.md))
- A command, runnable by the user gatekeeper runs as, that prints a credential to stdout and exits 0

## Configuration

Add a `process` credential source to `gatekeeper.yaml`:

```yaml
proxy:
  host: 127.0.0.1
  port: 9080

tls:
  ca_cert: ca.crt
  ca_key: ca.key

credentials:
  - host: api.example.com
    header: x-api-key
    grant: example-api
    source:
      type: process
      command: "op read op://vault/example/api-key"
      ttl: 10m

network:
  policy: permissive

log:
  level: info
  format: text
```

| Field     | Required | Default | Description                                                        |
|-----------|----------|---------|----------------------------------------------------------------------|
| `command` | Yes      | --      | Shell command, run with `sh -c`. Trimmed stdout becomes the credential |
| `ttl`     | No       | `5m`    | Refresh interval when the output carries no expiry (Go duration string) |

## Worked example: 1Password CLI

Store the credential in a 1Password vault, then reference it by its `op://` path:

```yaml
credentials:
  - host: api.github.com
    grant: github
    source:
      type: process
      command: "op read op://Engineering/github-pat/credential"
```

`op` must be signed in (`op signin`) in whatever session gatekeeper's process inherits, or configured with a service account token via its own environment variable — gatekeeper only runs the command, it does not manage `op`'s auth state.

## Worked example: pass

[`pass`](https://www.passwordstore.org/) prints the decrypted secret to stdout:

```yaml
credentials:
  - host: api.example.com
    header: x-api-key
    grant: example-api
    source:
      type: process
      command: "pass show api/example-api-key"
```

`pass` shells out to GPG, so gatekeeper's process needs access to the same `gpg-agent` (and cached passphrase, or an unattended key) that an interactive `pass show` would need. A command that blocks on a passphrase prompt blocks the credential fetch — and, on a refresh, the background refresh goroutine — until it times out.

## Refresh semantics

`process` implements background refresh the same way [GitHub App tokens](./05-github-app-tokens.md) do: gatekeeper re-runs the command at 75% of the credential's TTL (floored at 30 seconds) and hot-swaps the value without downtime.

How the TTL is determined depends on the command's output:

- **Expiry-aware.** If stdout is JSON matching the AWS `credential_process` shape — exact-case `Version`, `AccessKeyId`, and `Expiration` (RFC 3339) keys — gatekeeper reads `Expiration` and schedules the refresh from it. The configured `ttl` is ignored in this case. The JSON is passed through verbatim as the credential value; gatekeeper does not extract `AccessKeyId` or any other field for you.
- **Plain string or other JSON.** Anything else — a bare token, an API key, JSON without that exact key set — is treated as an opaque value with no expiry, and the configured `ttl` (default 5 minutes) sets the refresh interval.

```bash
# Expiry-aware: gatekeeper schedules refresh from "Expiration", ignores ttl.
{"Version":1,"AccessKeyId":"...","SecretAccessKey":"...","Expiration":"2026-07-13T18:00:00Z"}

# Opaque: gatekeeper refreshes every ttl (or every 5m by default).
ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

## Failure behavior

**At startup**, a failing command fails gatekeeper's startup: the credential is fetched once before the proxy begins serving, and a non-zero exit or empty output is a fatal configuration error.

**On refresh**, a failing command does not take gatekeeper down or drop the previously-injected credential — the last good value stays in place while the refresh loop retries with exponential backoff (starting at 1 second, capped at 60 seconds, with jitter).

A few specific failure modes:

- **Non-zero exit.** The fetch fails; stderr (truncated to 256 bytes) is included in the error so a diagnosable failure — an expired SSO session, a locked keychain — shows up in logs. Stdout is never included, since it may hold a partial credential.
- **Empty output.** Treated as an error even on exit 0.
- **Already-expired `Expiration`.** If the sniffed `credential_process` JSON reports an `Expiration` already in the past, the fetch fails instead of installing a credential that would be rejected upstream on first use.
- **Control characters in output.** Bytes invalid in HTTP header values (RFC 7230) are stripped automatically. If any non-whitespace control byte was present, gatekeeper logs a warning with a count — never the value — so a helper emitting garbage is diagnosable without exposing the credential.

## Security notes

> **Warning:** The command runs on the host with gatekeeper's own OS privileges, not the client's. Only configure commands from config files you trust — an embedder that lets an untrusted party supply `gatekeeper.yaml` (or just the `command` field) is granting that party arbitrary code execution as the gatekeeper process.

- Don't echo secrets to logs. Gatekeeper never logs the fetched value, but a command that itself writes the credential to stderr (for debugging) will have that stderr echoed into gatekeeper's error log on failure — keep debug output out of commands used as credential sources.
- Prefer a command that reads from an already-unlocked store over one that prompts interactively. A prompt blocks the calling goroutine, and on a background refresh, there's no terminal attached to answer it.

## Next steps

- [GitHub App Tokens](./05-github-app-tokens.md) — a source with the same 75%-of-TTL refresh model, built in
- [Network Lockdown](./07-network-lockdown.md) — restrict proxy traffic to specific hosts
