# Gatekeeper

A credential-injecting TLS-intercepting proxy. Route HTTPS traffic through Gatekeeper and it transparently injects authentication headers based on hostname matching. Clients never see raw credentials.

Full documentation: [docs/README.md](docs/README.md).

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

Or pull the published Docker image:

```bash
docker pull ghcr.io/majorcontext/gatekeeper:latest

docker run --rm -v ./gatekeeper.yaml:/etc/gatekeeper/gatekeeper.yaml \
  ghcr.io/majorcontext/gatekeeper --config /etc/gatekeeper/gatekeeper.yaml
```

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
  # proxy_protocol: true  # behind a TCP-terminating LB, recover the real client_ip

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

## PROXY protocol (client IP behind a load balancer)

Behind a TCP-terminating load balancer (e.g. GCP's global TCP Proxy LB), every connection's peer address is the load balancer's, not the real client. PROXY protocol parsing recovers the real client address, and it's configured per listener: `proxy.proxy_protocol: true` for the HTTP/CONNECT listener, and `postgres.proxy_protocol: true` for the Postgres data-plane listener. Each parses a PROXY protocol v1/v2 header from the LB and uses its advertised source as the `client_ip` recorded in request logs. Both are fail-open (headerless connections, like LB health checks, fall back to the raw peer address) and should only be enabled when that listener's port is reachable solely through the load balancer, since the header is otherwise forgeable by any direct client. See [Deploying behind a TCP load balancer](docs/content/guides/11-load-balancer-proxy-protocol.md).

**Single-port multiplexing:** if `postgres.port` equals `proxy.port` (same host), gatekeeper serves both planes on one shared listener instead of binding two, classifying each connection by its first bytes (Postgres startup signatures vs. everything else). There's no flag — the matching ports are the trigger. This lets one load balancer front both planes with a single backend service and health check. See [Single load balancer, one shared port](docs/content/guides/11-load-balancer-proxy-protocol.md#single-load-balancer-one-shared-port).

## MCP relay

For MCP clients that can't route through `HTTP_PROXY`, Gatekeeper relays Model Context Protocol requests directly, injecting credentials and streaming SSE responses:

```
POST http://127.0.0.1:9080/mcp/context7/v1/endpoint
```

Gatekeeper resolves the credential configured for the `context7` MCP server and injects it before forwarding to the real server. MCP servers are registered via `MCPServerConfig` in the Go library — not exposed in `gatekeeper.yaml` — which is how [Moat](https://github.com/majorcontext/moat)'s daemon layer wires it up per run.

## LLM policy

Gatekeeper can evaluate Anthropic API responses against [Keep](https://github.com/majorcontext/keep) policy rules before they reach the client, blocking a response that violates a rule instead of forwarding it. Like MCP relay, this is configured via `RunContextData.KeepEngines` in the Go library, not `gatekeeper.yaml` — it's primarily used through Moat's daemon layer.

## Host gateway

A synthetic hostname used inside a sandboxed container can be mapped to the real host machine's IP, so containers reach host services without relying on `host.docker.internal`:

```
container ──▶ moat-host-gateway:8080 ──▶ gatekeeper ──▶ {HostGatewayIP}:8080
```

Set via `RunContextData.HostGateway`/`HostGatewayIP` in the Go library. Destination ports must be explicitly listed in `AllowedHostPorts` — traffic to unlisted ports is denied.

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

**Tracing a connection:** the Postgres request log records the authenticated `run_id` alongside the client-set `application_name` startup parameter (set via `PGAPPNAME` or a driver's connection option), sanitized and length-bounded. `run_id` is the trusted identity; `application_name` is a correlation slug for telling apart multiple connections within one run, and it's forwarded upstream unchanged so it also shows up in Neon's own `pg_stat_activity`.

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
