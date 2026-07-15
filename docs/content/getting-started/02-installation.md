---
title: "Installation"
description: "Install Gatekeeper via go install, build from source, or pull the Docker image."
keywords: ["gatekeeper", "installation", "go install", "docker"]
---

# Installation

## Requirements

- Go 1.25 or later

## go install

```bash
go install github.com/majorcontext/gatekeeper/cmd/gatekeeper@latest
```

This places the `gatekeeper` binary in `$GOPATH/bin`.

## Build from source

```bash
git clone https://github.com/majorcontext/gatekeeper.git
cd gatekeeper
go build -o gatekeeper ./cmd/gatekeeper/
```

Set the version at build time with linker flags:

```bash
go build -ldflags "-X main.version=v0.10.0" -o gatekeeper ./cmd/gatekeeper/
```

## Docker

```bash
docker pull ghcr.io/majorcontext/gatekeeper:latest
```

Run with a config file mounted:

```bash
docker run --rm -v ./gatekeeper.yaml:/etc/gatekeeper/gatekeeper.yaml \
  ghcr.io/majorcontext/gatekeeper --config /etc/gatekeeper/gatekeeper.yaml
```

## Verify

```bash
gatekeeper
```

Gatekeeper requires a config file and refuses to start without one. With no `--config` flag and no `GATEKEEPER_CONFIG` environment variable set, the binary exits immediately:

```text
error: --config or GATEKEEPER_CONFIG required
```

An exit status of `1` with this message confirms the binary is installed and runs.
