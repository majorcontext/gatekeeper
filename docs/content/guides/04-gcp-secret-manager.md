---
title: "GCP Secret Manager"
description: "Fetch a credential from Google Cloud Secret Manager at proxy startup and inject it into HTTPS requests."
keywords: ["gatekeeper", "GCP Secret Manager", "credential source", "cloud secrets"]
---

# GCP Secret Manager Credentials

Fetch a credential from Google Cloud Secret Manager at proxy startup and inject it into HTTPS requests.

## Prerequisites

- CA certificate generated ([CA Setup](./01-ca-setup.md))
- GCP Application Default Credentials configured (`gcloud auth application-default login` or a service account key)
- A secret stored in GCP Secret Manager containing the credential value

## IAM Permissions

The service account or principal running gatekeeper needs the `Secret Manager Secret Accessor` role (`roles/secretmanager.secretAccessor`) on the target secret.

## Configuration

Add a `gcp-secretmanager` credential source to `gatekeeper.yaml`:

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
      type: gcp-secretmanager
      project: my-gcp-project
      secret: github-token

network:
  policy: permissive

log:
  level: info
  format: text
```

| Field     | Required | Default    | Description                              |
|-----------|----------|------------|------------------------------------------|
| `project` | Yes      | --         | GCP project ID                           |
| `secret`  | Yes      | --         | Secret name in Secret Manager            |
| `version` | No       | `"latest"` | Secret version (e.g., `"1"`, `"latest"`) |

Gatekeeper constructs the resource name `projects/{project}/secrets/{secret}/versions/{version}` and fetches the payload at startup with a 10-second timeout.

## Pin a Specific Version

To pin to a specific secret version instead of `latest`:

```yaml
source:
  type: gcp-secretmanager
  project: my-gcp-project
  secret: github-token
  version: "3"
```

## Start the Proxy

```bash
gatekeeper --config gatekeeper.yaml
```

If ADC is not configured or the secret does not exist, gatekeeper exits with an error at startup.

## Verification

```bash
curl --cacert ca.crt --proxy http://127.0.0.1:9080 https://api.github.com/user
```

The proxy log confirms credential injection:

```text
level=INFO msg=request http_host=api.github.com credential_injected=true grants=github
```

> **Note:** Gatekeeper fetches the secret once at startup. To pick up a rotated secret, restart the proxy.

## Next Steps

- [GitHub App Tokens](./05-github-app-tokens.md) — auto-refreshing short-lived tokens
- [Network Lockdown](./07-network-lockdown.md) — restrict proxy traffic to specific hosts
