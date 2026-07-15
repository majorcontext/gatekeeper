---
title: "Running the Container Image"
description: "Pull and run the published gatekeeper container image, mount config and CA material, and wire clients to trust the proxy."
keywords: ["gatekeeper", "Docker", "container", "ghcr.io", "deployment"]
---

# Running the container image

Gatekeeper publishes a multi-arch container image to `ghcr.io/majorcontext/gatekeeper` on every `v*` tag (`.github/workflows/release.yml`), built for `linux/amd64` and `linux/arm64` from `cmd/gatekeeper/Dockerfile`. The image is `gcr.io/distroless/static-debian12` with a single static binary at `/gatekeeper` — no shell, no package manager, no other executables.

## Prerequisites

- Docker (or another OCI-compatible runtime)
- A CA certificate and key for TLS interception ([CA Setup](./01-ca-setup.md))
- A gatekeeper.yaml config file ([Config file](../reference/02-config-file.md))

## Pulling the image

Pull by version tag:

```bash
docker pull ghcr.io/majorcontext/gatekeeper:0.17.0
```

Or pin to an immutable digest for reproducible deployments:

```bash
docker pull ghcr.io/majorcontext/gatekeeper@sha256:1238110cc242a14719182f695c785d298e5a841ecec33f68dc70f88af57192b3
```

A tag like `0.17.0` can be reassigned to a different digest if the release is ever rebuilt; a digest cannot. Use the tag for local development and the digest when the deployment pipeline needs to guarantee exactly which image is running. `major.minor` tags (`0.17`) and a `latest` tag are also published, alongside `sha-<short-sha>` tags for every build.

## Mounting config and CA material

The image ships no config and no CA — both must be mounted read-only at container start. The binary reads its config path from `--config` or the `GATEKEEPER_CONFIG` environment variable; the Dockerfile's `ENTRYPOINT` is `["/gatekeeper"]` with no default arguments, so one of the two must be supplied.

Write a config that references the mounted paths:

```yaml
proxy:
  host: 0.0.0.0
  port: 9080

tls:
  ca_cert: /etc/gatekeeper/ca.crt
  ca_key: /etc/gatekeeper/ca.key

credentials:
  - host: api.github.com
    header: Authorization
    grant: github
    source:
      type: env
      var: GITHUB_TOKEN

log:
  level: info
  format: text
```

`proxy.host` is `0.0.0.0` because the proxy listens inside the container's own network namespace — binding to `127.0.0.1` would make it unreachable from outside the container even with the port published.

## Running the container

```bash
docker run -d --name gatekeeper \
  -p 127.0.0.1:9080:9080 \
  -v "$(pwd)/gatekeeper.yaml:/etc/gatekeeper/gatekeeper.yaml:ro" \
  -v "$(pwd)/ca.crt:/etc/gatekeeper/ca.crt:ro" \
  -v "$(pwd)/ca.key:/etc/gatekeeper/ca.key:ro" \
  -e GATEKEEPER_CONFIG=/etc/gatekeeper/gatekeeper.yaml \
  -e GITHUB_TOKEN \
  ghcr.io/majorcontext/gatekeeper:0.17.0
```

`-p 127.0.0.1:9080:9080` publishes the proxy port to the host's loopback interface only. Widen this (or route it through a load balancer — see [Deploying Behind a TCP Load Balancer](./11-load-balancer-proxy-protocol.md)) only once the port's exposure is deliberate.

## Wiring clients

Clients reach the proxy the same way they would a non-containerized gatekeeper: set `HTTPS_PROXY` and trust the CA certificate.

```bash
export HTTPS_PROXY=http://127.0.0.1:9080
curl --cacert ca.crt https://api.github.com/user
```

See [CA Setup](./01-ca-setup.md#per-tool-trust) for trusting the CA in the system store, Node.js, Python, and Go, instead of passing it per-command.

## Verification

Pulling `0.17.0` and running it with a scratch config (reusing `examples/ca.crt` and `examples/ca.key`) confirms the full flow:

```bash
$ curl -s http://127.0.0.1:9080/healthz
{"status":"ok"}

$ curl --cacert ca.crt --proxy http://127.0.0.1:9080 https://httpbin.org/headers
{
  "headers": {
    "Accept": "*/*",
    "Accept-Encoding": "gzip",
    "Authorization": "Bearer test-token-xxxx",
    "Host": "httpbin.org",
    "User-Agent": "curl/8.7.1",
    "X-Amzn-Trace-Id": "Root=1-..."
  }
}
```

The container's log line confirms the injection:

```text
time=2026-07-15T12:46:19.438Z level=INFO msg=request request_id=req_01kxjwz81jf7mt3v9jnfss33pa http_method=GET http_host=httpbin.org http_path=/headers http_status=200 proxy_type=connect client_ip=172.17.0.1 credential_injected=true injected_headers=authorization grants=test
```

`client_ip` shows the Docker bridge network's gateway address (`172.17.0.1`), not a real external client — expected for a container reached directly from the host. Behind a load balancer, see [Deploying Behind a TCP Load Balancer](./11-load-balancer-proxy-protocol.md) to recover the actual client address.

## Health checks

`/healthz` is served on the proxy port and returns `{"status":"ok"}` with HTTP 200 for any `GET` request, unauthenticated. It's suitable for a container orchestrator's liveness or readiness probe.

> **Note:** The image has no shell and no `curl`/`wget` binary, so a Docker `HEALTHCHECK` instruction or a Compose `healthcheck.test` — both of which exec a command *inside* the container — cannot invoke `curl` the way a typical image's health check does. Attempting it fails with `executable file not found in $PATH`. Probe `/healthz` from outside the container instead: an orchestrator's HTTP-based probe (Kubernetes `livenessProbe`/`readinessProbe` with `httpGet`, which the kubelet performs from outside the container) or an external monitoring check against the published port both work without needing a shell inside the image.

```yaml
# Kubernetes probe example -- httpGet runs from the kubelet, not inside the container.
livenessProbe:
  httpGet:
    path: /healthz
    port: 9080
  initialDelaySeconds: 2
  periodSeconds: 10
```

## Exposing the Postgres data-plane port

The optional Postgres data-plane listener ([Postgres Data Plane](../concepts/08-postgres-data-plane.md)) is a second, separate listener. Publish its port alongside the proxy port and add a `postgres` section to the config:

```yaml
postgres:
  host: 0.0.0.0
  port: 5432
```

```bash
docker run -d --name gatekeeper \
  -p 127.0.0.1:9080:9080 \
  -p 127.0.0.1:5432:5432 \
  -v "$(pwd)/gatekeeper.yaml:/etc/gatekeeper/gatekeeper.yaml:ro" \
  -v "$(pwd)/ca.crt:/etc/gatekeeper/ca.crt:ro" \
  -v "$(pwd)/ca.key:/etc/gatekeeper/ca.key:ro" \
  -e GATEKEEPER_CONFIG=/etc/gatekeeper/gatekeeper.yaml \
  ghcr.io/majorcontext/gatekeeper:0.17.0
```

The `postgres` section requires `tls.ca_cert` and `tls.ca_key` — gatekeeper refuses to start without them.

## Environment variables that matter in containers

| Variable | Description |
|---|---|
| `GATEKEEPER_CONFIG` | Path to gatekeeper.yaml inside the container. Required unless `--config` is passed as the container command instead. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP collector endpoint. Defaults to `localhost:4318` if unset — inside a container, `localhost` is the container's own network namespace, not the host, so gatekeeper attempts (and, absent a collector, fails to reach) a collector inside the container unless this is set to a reachable address. |
| `OTEL_SDK_DISABLED` | Set to `true` to skip OTel exporter setup entirely. Useful when no collector is reachable from the container and the resulting DEBUG-level connection-refused log lines aren't wanted. |
| Any credential source env var (e.g. `GITHUB_TOKEN`) | Referenced by `source.var` in credential config entries; pass with `-e VAR` or `-e VAR=value`. |

`SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt` is already set in the image by the `distroless/static-debian12` base and points Go's HTTP client at the base image's system root CAs — relevant to credential sources that call out over HTTPS (AWS Secrets Manager, GCP Secret Manager, token exchange, GitHub App installation tokens). It does not need to be set or changed for gatekeeper's own interception CA, which is configured separately via `tls.ca_cert`/`tls.ca_key`.

## Compose example

```yaml
services:
  gatekeeper:
    image: ghcr.io/majorcontext/gatekeeper:0.17.0
    ports:
      - "127.0.0.1:9080:9080"
    volumes:
      - ./gatekeeper.yaml:/etc/gatekeeper/gatekeeper.yaml:ro
      - ./ca.crt:/etc/gatekeeper/ca.crt:ro
      - ./ca.key:/etc/gatekeeper/ca.key:ro
    environment:
      GATEKEEPER_CONFIG: /etc/gatekeeper/gatekeeper.yaml
      GITHUB_TOKEN: ${GITHUB_TOKEN}
      OTEL_SDK_DISABLED: "true"
    restart: unless-stopped
```

## Next steps

- [Deploying Behind a TCP Load Balancer](./11-load-balancer-proxy-protocol.md) — recover real client IPs when the container sits behind a TCP-terminating load balancer
- [OpenTelemetry](./08-opentelemetry.md) — point the container at a collector instead of disabling the SDK
- [Postgres Data Plane](../concepts/08-postgres-data-plane.md) — how the optional Postgres listener resolves upstream passwords
