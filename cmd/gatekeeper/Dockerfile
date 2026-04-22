FROM --platform=$BUILDPLATFORM golang:1.25 AS builder
ARG TARGETOS TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-X main.version=${VERSION}" -o /gatekeeper ./cmd/gatekeeper

FROM gcr.io/distroless/static-debian12
COPY --from=builder /gatekeeper /gatekeeper
EXPOSE 9080
ENTRYPOINT ["/gatekeeper"]
