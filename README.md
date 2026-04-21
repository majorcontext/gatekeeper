# Gatekeeper

A credential-injecting TLS-intercepting proxy. Route HTTPS traffic through Gatekeeper and it transparently injects authentication headers based on hostname matching. Clients never see raw credentials.

```bash
# Start the proxy
gatekeeper --config gatekeeper.yaml

# In another terminal — credential injected automatically
curl --proxy http://127.0.0.1:9080 --cacert ca.crt https://api.github.com/user
```

No `GITHUB_TOKEN` in the command. No secrets in environment variables. The token is resolved from the configured source and injected at the network layer.

## Installation

```bash
go install github.com/majorcontext/gatekeeper/cmd/gatekeeper@latest
```

**Requires:** Go 1.23+

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

Policies: `permissive` (allow all, deny listed), `strict` (deny all, allow listed).

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

