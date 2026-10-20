FROM --platform=$BUILDPLATFORM golang:1.27.3-bookworm@sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110 AS builder
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
