# Gatekeeper

A credential-injecting TLS-intercepting proxy. Route HTTPS traffic through Gatekeeper and it transparently injects authentication headers based on hostname matching. Clients never see raw credentials.

```bash
# Start the proxy
gatekeeper --config gatekeeper.yaml

# In another terminal — credential injected automatically
curl --proxy http://127.0.0.1:9080 --cacert ca.crt https://api.github.com/user
```

No `GITHUB_TOKEN` in the command. No secrets in environment variables. The token is resolved from the configured source and injected at the network layer.

Gatekeeper also runs an optional [Postgres data plane](#postgres-data-plane) — connect to Neon databases with only a run token, never a database password.

## Installation

```bash
go install github.com/majorcontext/gatekeeper/cmd/gatekeeper@latest
```

**Requires:** Go 1.25+

## How it works

1. Client sends `CONNECT host:443` through the proxy
2. Proxy terminates TLS using a dynamically-generated certificate for that host
3. Proxy reads the plaintext request, injects the matching credential as an HTTP header
4. Request is forwarded to the real server over a separate TLS connection
5. Response streams back to the client

The proxy needs a CA certificate to sign per-host certificates. Generate one with the included script:

```bash
cd examples && ./gen-ca.sh
```

## Configuration

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
      type: env
      var: GITHUB_TOKEN

network:
  policy: permissive

log:
  level: info
  format: text
```

## Credential sources

### Environment variable

```yaml
source:
  type: env
  var: GITHUB_TOKEN
```

### Static value

```yaml
source:
  type: static
  value: "Bearer sk-..."
```

### Process

Runs a host command and uses its stdout as the credential. If the output is AWS `credential_process`-format JSON with an `Expiration`, the credential refreshes automatically on that expiry.

```yaml
source:
  type: process
  command: "op read op://vault/example/api-key"
```

### AWS Secrets Manager

```yaml
source:
  type: aws-secretsmanager
  secret: prod/api-key
  region: us-east-1
```

### GitHub App

Generates short-lived installation tokens from a GitHub App private key. Tokens refresh automatically in the background at 75% of TTL.

```yaml
source:
  type: github-app
  app_id: "12345"
  installation_id: "67890"
  private_key_path: ./key.pem       # or use private_key_env
```

See [`examples/gatekeeper-github-app.yaml`](examples/gatekeeper-github-app.yaml) for a complete example.

## Network policy

Control which hosts the proxy will forward traffic to:

```yaml
network:
  policy: strict       # deny all except explicitly allowed
  allow:
    - "api.github.com"
    - "*.anthropic.com"
```

Policies: `permissive` (allow all), `strict` (deny all, allow listed).

## Postgres data plane

Gatekeeper can run a second listener that speaks the Postgres wire protocol, letting a sandboxed client connect to arbitrary Neon databases without any database secret ever entering the sandbox. The only credential the client holds is a run-scoped token, which is useless outside Gatekeeper.

The client connects to the real Neon hostname and presents its run token (or the proxy's `auth_token`) as the Postgres password. Gatekeeper terminates TLS with a CA-minted certificate, reads the target endpoint from the TLS SNI, resolves the real per-branch password from the Neon API on the fly, completes SCRAM-SHA-256 with the upstream server, and relays the connection. The run token travels as a cleartext password, but only inside Gatekeeper's own TLS tunnel — the same trust model as `Proxy-Authorization` on the HTTP plane.

```
client ──TLS(token as password)──▶ gatekeeper ──TLS(SCRAM, real password)──▶ Neon
         SNI: ep-...neon.tech                    resolved via Neon API
```

**Routing is by SNI.** The target endpoint travels in the TLS SNI field, so the embedder must arrange DNS inside the container so `*.neon.tech` resolves to Gatekeeper. That DNS plumbing is outside Gatekeeper's scope — it's the embedder's responsibility (e.g. [Moat](https://github.com/majorcontext/moat) handles it). The v1 data plane is a blind message relay: it routes on SNI only and does no SQL-level inspection.

A Postgres listener **requires a CA** (`tls.ca_cert` and `tls.ca_key`) for TLS termination — Gatekeeper errors at startup otherwise.

Two resolvers are available:

- **`neon`** — the source supplies a Neon API key; per-branch passwords are minted from the Neon API and cached with a TTL. With an account-scoped key, Gatekeeper discovers an endpoint's project automatically; with a project-scoped key (which can't list projects), set `project:` on the credential to its project ID.
- **`static`** — the source supplies a fixed password directly (for non-Neon Postgres or testing).

```yaml
postgres:
  host: 127.0.0.1      # optional, defaults to the proxy host
  port: 5432

tls:
  ca_cert: ca.crt
  ca_key: ca.key

credentials:
  - host: "*.neon.tech"
    postgres:
      resolver: neon
    source:
      type: env
      var: NEON_API_KEY
    grant: neon-databases
```

Once DNS routes `*.neon.tech` to Gatekeeper, connect with the run token as the password:

```bash
PGPASSWORD=<run-token> psql \
  "host=ep-cool-darkness-123456.us-east-2.aws.neon.tech dbname=neondb user=neondb_owner sslmode=require"
```

Moat sets `PGPASSWORD` in the container so the token never appears in the agent's command line. See [`examples/gatekeeper-postgres.yaml`](examples/gatekeeper-postgres.yaml) for a complete example.

## Observability

Gatekeeper supports OpenTelemetry for traces, metrics, and logs. No YAML configuration needed — use standard `OTEL_*` environment variables:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=https://your-collector:4318
export OTEL_EXPORTER_OTLP_HEADERS="Authorization=Bearer <token>"
gatekeeper --config gatekeeper.yaml
```

## Library usage

Gatekeeper is a Go module. Import the proxy engine directly for custom integrations:

```go
import (
    "github.com/majorcontext/gatekeeper/proxy"
)

ca, _ := proxy.LoadCA(certPEM, keyPEM)

p := proxy.NewProxy()
p.SetCA(ca)
p.SetCredentialWithGrant("api.github.com", "Authorization", "Bearer xxx", "github")
```

[Moat](https://github.com/majorcontext/moat) uses Gatekeeper this way — importing the proxy and adding per-run credential scoping via a daemon layer.

## Development

```bash
go build ./...           # build
go test -race ./...      # test
go vet ./...             # lint
```

## License

MIT — see [LICENSE](LICENSE).
