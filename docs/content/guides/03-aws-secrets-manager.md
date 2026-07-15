---
title: "AWS Secrets Manager"
description: "Fetch a credential from AWS Secrets Manager at proxy startup and inject it into HTTPS requests."
keywords: ["gatekeeper", "AWS Secrets Manager", "credential source", "cloud secrets"]
---

# AWS Secrets Manager credentials

Fetch a credential from AWS Secrets Manager at proxy startup and inject it into HTTPS requests.

## Prerequisites

- CA certificate generated ([CA Setup](./01-ca-setup.md))
- AWS credentials configured (environment variables, IAM role, or `~/.aws/credentials`)
- A secret stored in AWS Secrets Manager containing the credential value as a plaintext string

## IAM permissions

The IAM principal running gatekeeper needs:

```json
{
  "Effect": "Allow",
  "Action": "secretsmanager:GetSecretValue",
  "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/github-token-*"
}
```

Scope the `Resource` to the specific secret ARN.

## Configuration

Add an `aws-secretsmanager` credential source to `gatekeeper.yaml`:

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
      type: aws-secretsmanager
      secret: prod/github-token
      region: us-east-1

network:
  policy: permissive

log:
  level: info
  format: text
```

| Field    | Required | Description                                      |
|----------|----------|--------------------------------------------------|
| `secret` | Yes      | Secret name or ARN in AWS Secrets Manager        |
| `region` | No       | AWS region. Falls back to SDK default if omitted |

The secret value must be a plaintext string (not binary). Gatekeeper fetches it once at startup with a 10-second timeout.

## Start the proxy

```bash
gatekeeper --config gatekeeper.yaml
```

If AWS credentials are missing or the secret does not exist, gatekeeper exits with an error at startup.

## Verification

```bash
curl --cacert ca.crt --proxy http://127.0.0.1:9080 https://api.github.com/user
```

The proxy log confirms credential injection:

```text
level=INFO msg=request http_host=api.github.com credential_injected=true grants=github
```

> **Note:** Gatekeeper fetches the secret once at startup. To pick up a rotated secret, restart the proxy.

## Next steps

- [GCP Secret Manager](./04-gcp-secret-manager.md) — use GCP instead of AWS
- [Network Lockdown](./07-network-lockdown.md) — restrict proxy traffic to specific hosts
