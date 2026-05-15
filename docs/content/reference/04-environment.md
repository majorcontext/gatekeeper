---
title: "Environment variables"
description: "Reference for all environment variables that Gatekeeper reads, including AWS, GCP, OpenTelemetry, and client-side proxy variables."
keywords: ["gatekeeper", "environment variables", "OTEL", "AWS", "configuration"]
---

# Environment variables

Environment variables that gatekeeper reads or that affect its behavior.

## Gatekeeper variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GATEKEEPER_CONFIG` | Path to `gatekeeper.yaml`. Used when `--config` flag is not provided. | — |

---

## Credential source variables

These variables are referenced by credential source configs in `gatekeeper.yaml`. They are not read directly by gatekeeper itself — they are read when the corresponding source type is configured.

| Variable | Used by | Description |
|----------|---------|-------------|
| _name from `source.var`_ | `env` source | The credential value. Must be set and non-empty. |
| _name from `source.private_key_env`_ | `github-app` source | PEM-encoded RSA private key for GitHub App authentication. |
| _name from `source.client_secret_env`_ | `token-exchange` source | OAuth client secret for the STS endpoint. |

---

## AWS variables

Used by the `aws-secretsmanager` credential source via the AWS SDK default credential chain.

| Variable | Description |
|----------|-------------|
| `AWS_ACCESS_KEY_ID` | AWS access key ID |
| `AWS_SECRET_ACCESS_KEY` | AWS secret access key |
| `AWS_SESSION_TOKEN` | AWS session token (for temporary credentials) |
| `AWS_REGION` | Default AWS region |
| `AWS_DEFAULT_REGION` | Fallback AWS region (used if `AWS_REGION` is unset) |
| `AWS_PROFILE` | Named profile from `~/.aws/credentials` |

The `region` field in the source config takes precedence over these environment variables.

---

## GCP variables

Used by the `gcp-secretmanager` credential source via Application Default Credentials.

| Variable | Description |
|----------|-------------|
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to a service account key JSON file |

When unset, the GCP SDK uses the metadata server (on GCE/GKE) or gcloud application-default credentials.

---

## OpenTelemetry variables

Gatekeeper initializes OTLP HTTP exporters for traces, metrics, and logs. All configuration uses standard OpenTelemetry environment variables. When no `OTEL_EXPORTER_OTLP_ENDPOINT` is set, the exporters default to `localhost:4318` (OTLP/HTTP).

| Variable | Description |
|----------|-------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Base URL for the OTLP collector (e.g., `http://localhost:4318`) |
| `OTEL_EXPORTER_OTLP_HEADERS` | Headers for OTLP requests (e.g., `Authorization=Bearer token`) |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | Protocol (`http/protobuf` is used by default) |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | Override endpoint for traces only |
| `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | Override endpoint for metrics only |
| `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` | Override endpoint for logs only |
| `OTEL_RESOURCE_ATTRIBUTES` | Additional resource attributes (e.g., `deployment.environment=production`) |
| `OTEL_SERVICE_NAME` | Override the service name (default: `gatekeeper`) |

Gatekeeper registers the following OTel resource attributes at startup:

| Attribute | Value |
|-----------|-------|
| `service.name` | `gatekeeper` |
| `service.version` | Build version (from `-ldflags -X main.version`) |

### Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `proxy.request.duration` | Histogram (seconds) | Duration of proxy requests |
| `proxy.request.count` | Counter | Total number of proxy requests |
| `proxy.credential.injections` | Counter | Total number of credential injections |
| `proxy.policy.denials` | Counter | Total number of policy denials |

---

## Client-side variables

These variables are set on the client side (inside the container), not on the gatekeeper process. They direct HTTP traffic through the proxy.

| Variable | Description |
|----------|-------------|
| `HTTP_PROXY` | Proxy URL for HTTP requests (e.g., `http://127.0.0.1:8080`) |
| `HTTPS_PROXY` | Proxy URL for HTTPS requests (e.g., `http://127.0.0.1:8080`) |
| `NO_PROXY` | Comma-separated list of hosts that bypass the proxy |

When `proxy.auth_token` is configured, include the token in the proxy URL:

```bash
export HTTPS_PROXY=http://user:my-secret-token@127.0.0.1:8080
```
