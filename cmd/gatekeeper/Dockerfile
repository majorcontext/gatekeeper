FROM --platform=$BUILDPLATFORM golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS builder
ARG TARGETOS TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-X main.version=${VERSION}" -o /gatekeeper ./cmd/gatekeeper

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /gatekeeper /gatekeeper
EXPOSE 9080
ENTRYPOINT ["/gatekeeper"]
