---
title: "CLI"
description: "Reference for the gatekeeper command-line interface, including flags, exit codes, signals, and health check endpoint."
keywords: ["gatekeeper", "CLI", "command line", "flags", "configuration"]
---

# CLI

The `gatekeeper` command starts a credential-injecting TLS-intercepting proxy.

## Usage

```bash
gatekeeper --config gatekeeper.yaml
```

## Flags

### --config

Path to the gatekeeper configuration file.

```bash
gatekeeper --config /etc/gatekeeper/gatekeeper.yaml
```

- **Type:** `string`
- **Required:** Yes (unless `GATEKEEPER_CONFIG` is set)
- **Default:** —

If `--config` is not provided, gatekeeper reads the `GATEKEEPER_CONFIG` environment variable. If neither is set, gatekeeper exits with an error.

---

## Build version

The binary version is set at build time via `-ldflags`:

```bash
go build -ldflags "-X main.version=1.2.3" -o gatekeeper ./cmd/gatekeeper/
```

When unset, the version defaults to `"dev"`. The version appears in the startup log line and is registered as the `service.version` OpenTelemetry resource attribute.

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Clean shutdown (SIGTERM or SIGINT received) |
| `1`  | Startup error (missing config, invalid config, credential fetch failure, listener bind failure, or OTel initialization failure) |

---

## Signals

Gatekeeper listens for `SIGTERM` and `SIGINT`. On receipt, it gracefully shuts down the HTTP server (5-second timeout), cancels background credential refresh goroutines, closes credential source connections, and flushes OpenTelemetry providers.

---

## Health check

The proxy exposes a health endpoint on the proxy port:

```bash
curl http://127.0.0.1:8080/healthz
```

```json
{"status":"ok"}
```
