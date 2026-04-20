# OpenTelemetry Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add OpenTelemetry traces, metrics, and slog-to-OTel logs bridge to gatekeeper using the existing callback-based architecture.

**Architecture:** A handler wrapper (`proxy/otel.go`) creates root spans and records request metrics. The existing `RequestLogger` and `PolicyLogger` callbacks attach span events and record callback-level metrics. Provider initialization lives in `cmd/gatekeeper/main.go`; the slog bridge is wired in `gatekeeper.go`. The proxy core only changes to pass `context.Context` through the log data structs.

**Tech Stack:** `go.opentelemetry.io/otel` SDK, OTLP HTTP exporters (trace, metric, log), `go.opentelemetry.io/contrib/bridges/otelslog`

---

## File Structure

| File | Role | Action |
|---|---|---|
| `proxy/otel.go` | OTelHandler wrapper, metric instruments, tracer/meter accessors | Create |
| `proxy/otel_test.go` | Tests for OTelHandler (spans, metrics, status capture) | Create |
| `proxy/proxy.go` | Add `Ctx context.Context` to `RequestLogData` and `PolicyLogData`; pass ctx at call sites | Modify |
| `gatekeeper.go` | slog bridge in `configureLogging`, OTel callbacks, handler chain wiring | Modify |
| `gatekeeper_test.go` | Tests for OTel callbacks (span events, metrics) | Modify |
| `cmd/gatekeeper/main.go` | Provider init, shutdown, resource | Modify |

---

### Task 1: Add `Ctx` field to log data structs

**Files:**
- Modify: `proxy/proxy.go:96-124` (data structs)
- Modify: `proxy/proxy.go:212` (logRequest helper)
- Modify: `proxy/proxy.go:398-415` (logPolicy helper)

- [ ] **Step 1: Add `Ctx` field to `RequestLogData`**

In `proxy/proxy.go`, add `Ctx context.Context` to the `RequestLogData` struct (after `RunID`):

```go
type RequestLogData struct {
	Method          string
	URL             string
	StatusCode      int
	Duration        time.Duration
	Err             error
	RequestHeaders  http.Header
	ResponseHeaders http.Header
	RequestBody     []byte
	ResponseBody    []byte
	AuthInjected    bool
	InjectedHeaders map[string]bool
	RunID           string
	Ctx             context.Context
}
```

- [ ] **Step 2: Add `Ctx` field to `PolicyLogData`**

In the same file, add `Ctx context.Context` to `PolicyLogData` (after `Message`):

```go
type PolicyLogData struct {
	RunID     string
	Scope     string
	Operation string
	Rule      string
	Message   string
	Ctx       context.Context
}
```

- [ ] **Step 3: Pass context in `logRequest`**

Update the `logRequest` helper to accept and pass through context. Change the signature and body:

```go
func (p *Proxy) logRequest(ctxReq *http.Request, method, url string, statusCode int, duration time.Duration, err error, reqHeaders, respHeaders http.Header, reqBody, respBody []byte, injectedHeaders map[string]bool) {
	if p.logger == nil {
		return
	}
	var runID string
	var reqCtx context.Context
	if ctxReq != nil {
		reqCtx = ctxReq.Context()
		if rc := getRunContext(ctxReq); rc != nil {
			runID = rc.RunID
		}
	}
	p.logger(RequestLogData{
		Method:          method,
		URL:             url,
		StatusCode:      statusCode,
		Duration:        duration,
		Err:             err,
		RequestHeaders:  reqHeaders,
		ResponseHeaders: respHeaders,
		RequestBody:     reqBody,
		ResponseBody:    respBody,
		AuthInjected:    len(injectedHeaders) > 0,
		InjectedHeaders: injectedHeaders,
		RunID:           runID,
		Ctx:             reqCtx,
	})
}
```

- [ ] **Step 4: Pass context in `logPolicy`**

Update the `logPolicy` helper to pass through context:

```go
func (p *Proxy) logPolicy(ctxReq *http.Request, scope, operation, rule, message string) {
	if p.policyLogger == nil {
		return
	}
	var runID string
	var reqCtx context.Context
	if ctxReq != nil {
		reqCtx = ctxReq.Context()
		if rc := getRunContext(ctxReq); rc != nil {
			runID = rc.RunID
		}
	}
	p.policyLogger(PolicyLogData{
		RunID:     runID,
		Scope:     scope,
		Operation: operation,
		Rule:      rule,
		Message:   message,
		Ctx:       reqCtx,
	})
}
```

- [ ] **Step 5: Run existing tests**

Run: `cd /Users/andybons/dev/gatekeeper && go test -race ./...`
Expected: All existing tests pass. The `Ctx` field is zero-valued (`nil`) in test code that doesn't set it, which is safe.

- [ ] **Step 6: Commit**

```bash
git add proxy/proxy.go
git commit -m "feat(proxy): add Ctx field to RequestLogData and PolicyLogData"
```

---

### Task 2: Create `proxy/otel.go` — handler wrapper and metric instruments

**Files:**
- Create: `proxy/otel.go`

- [ ] **Step 1: Create `proxy/otel.go` with metric instruments**

```go
package proxy

import (
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

var (
	tracer          = otel.Tracer("gatekeeper")
	meter           = otel.Meter("gatekeeper")
	requestDuration metric.Float64Histogram
	requestCount    metric.Int64Counter
	credInjections  metric.Int64Counter
	policyDenials   metric.Int64Counter
)

func init() {
	var err error
	requestDuration, err = meter.Float64Histogram("proxy.request.duration",
		metric.WithDescription("Duration of proxy requests in milliseconds"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		otel.Handle(err)
	}
	requestCount, err = meter.Int64Counter("proxy.request.count",
		metric.WithDescription("Total number of proxy requests"),
	)
	if err != nil {
		otel.Handle(err)
	}
	credInjections, err = meter.Int64Counter("proxy.credential.injections",
		metric.WithDescription("Number of credential injections"),
	)
	if err != nil {
		otel.Handle(err)
	}
	policyDenials, err = meter.Int64Counter("proxy.policy.denials",
		metric.WithDescription("Number of policy denials"),
	)
	if err != nil {
		otel.Handle(err)
	}
}

// RecordCredentialInjection records a credential injection metric.
func RecordCredentialInjection(ctx context.Context, host, headerName string) {
	credInjections.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("server.address", host),
			attribute.String("proxy.credential.header", strings.ToLower(headerName)),
		),
	)
}

// RecordPolicyDenial records a policy denial metric.
func RecordPolicyDenial(ctx context.Context, scope, rule string) {
	policyDenials.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("proxy.policy.scope", scope),
			attribute.String("proxy.policy.rule", rule),
		),
	)
}

// statusRecorder wraps http.ResponseWriter to capture the status code.
// It also implements http.Hijacker so CONNECT handling works.
type statusRecorder struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (sr *statusRecorder) WriteHeader(code int) {
	if !sr.written {
		sr.statusCode = code
		sr.written = true
	}
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := sr.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("upstream ResponseWriter does not implement http.Hijacker")
}

func requestType(r *http.Request) string {
	if r.Method == http.MethodConnect {
		return "connect"
	}
	if r.URL.Host == "" && strings.HasPrefix(r.URL.Path, "/mcp/") {
		return "mcp"
	}
	if r.URL.Host == "" && strings.HasPrefix(r.URL.Path, "/relay/") {
		return "relay"
	}
	return "http"
}

func spanName(rt string) string {
	switch rt {
	case "connect":
		return "proxy.request"
	case "mcp":
		return "proxy.mcp"
	case "relay":
		return "proxy.relay"
	default:
		return "proxy.http"
	}
}

// OTelHandler wraps an http.Handler with OpenTelemetry tracing and metrics.
func OTelHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt := requestType(r)
		ctx, span := tracer.Start(r.Context(), spanName(rt),
			trace.WithSpanKind(trace.SpanKindServer),
		)
		defer span.End()

		host := r.Host
		if r.URL.Host != "" {
			host = r.URL.Host
		}

		span.SetAttributes(
			attribute.String("http.request.method", r.Method),
			attribute.String("server.address", host),
			attribute.String("proxy.request.type", rt),
		)

		sr := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		start := time.Now()

		next.ServeHTTP(sr, r.WithContext(ctx))

		durationMs := float64(time.Since(start).Milliseconds())

		span.SetAttributes(
			attribute.Int("http.response.status_code", sr.statusCode),
		)

		if sr.statusCode >= 400 {
			span.SetStatus(codes.Error, http.StatusText(sr.statusCode))
		} else {
			span.SetStatus(codes.Ok, "")
		}

		attrs := metric.WithAttributes(
			attribute.String("http.request.method", r.Method),
			attribute.String("server.address", host),
			attribute.Int("http.response.status_code", sr.statusCode),
			attribute.String("proxy.request.type", rt),
		)
		requestDuration.Record(ctx, durationMs, attrs)
		requestCount.Add(ctx, 1, attrs)
	})
}
```

Note: this file needs `"bufio"`, `"context"`, `"fmt"`, and `"net"` imports for the `statusRecorder.Hijack` method. Add them to the import block:

```go
import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)
```

- [ ] **Step 2: Add OTel dependencies to go.mod**

Run:
```bash
cd /Users/andybons/dev/gatekeeper && go get go.opentelemetry.io/otel go.opentelemetry.io/otel/sdk go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp go.opentelemetry.io/contrib/bridges/otelslog
```

Then run:
```bash
cd /Users/andybons/dev/gatekeeper && go mod tidy
```

- [ ] **Step 3: Verify it compiles**

Run: `cd /Users/andybons/dev/gatekeeper && go build ./...`
Expected: Build succeeds with no errors.

- [ ] **Step 4: Commit**

```bash
git add proxy/otel.go go.mod go.sum
git commit -m "feat(proxy): add OTel handler wrapper and metric instruments"
```

---

### Task 3: Test `OTelHandler` — spans and metrics

**Files:**
- Create: `proxy/otel_test.go`

- [ ] **Step 1: Write test for span creation on HTTP request**

```go
package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func setupTestOTel(t *testing.T) (*tracetest.InMemoryExporter, *sdkmetric.ManualReader) {
	t.Helper()

	spanExporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(spanExporter))
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { tp.Shutdown(context.Background()) })

	metricReader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(metricReader))
	otel.SetMeterProvider(mp)
	t.Cleanup(func() { mp.Shutdown(context.Background()) })

	// Re-initialize instruments with the new provider.
	// The init() func ran with the global no-op; we need fresh instruments.
	reinitMetrics()

	return spanExporter, metricReader
}

// reinitMetrics re-creates the package-level metric instruments from the
// current global MeterProvider so tests using a ManualReader see data.
func reinitMetrics() {
	m := otel.Meter("gatekeeper")
	var err error
	requestDuration, err = m.Float64Histogram("proxy.request.duration",
		metric.WithDescription("Duration of proxy requests in milliseconds"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		otel.Handle(err)
	}
	requestCount, err = m.Int64Counter("proxy.request.count",
		metric.WithDescription("Total number of proxy requests"),
	)
	if err != nil {
		otel.Handle(err)
	}
	credInjections, err = m.Int64Counter("proxy.credential.injections",
		metric.WithDescription("Number of credential injections"),
	)
	if err != nil {
		otel.Handle(err)
	}
	policyDenials, err = m.Int64Counter("proxy.policy.denials",
		metric.WithDescription("Number of policy denials"),
	)
	if err != nil {
		otel.Handle(err)
	}
}

func TestOTelHandler_CreatesSpanForHTTPRequest(t *testing.T) {
	spanExporter, _ := setupTestOTel(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	p := NewProxy()
	handler := OTelHandler(p)
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	spans := spanExporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least one span")
	}

	span := spans[0]
	if span.Name != "proxy.http" {
		t.Errorf("span name = %q, want %q", span.Name, "proxy.http")
	}

	var foundMethod, foundType bool
	for _, attr := range span.Attributes {
		if attr.Key == "http.request.method" && attr.Value.AsString() == "GET" {
			foundMethod = true
		}
		if attr.Key == "proxy.request.type" && attr.Value.AsString() == "http" {
			foundType = true
		}
	}
	if !foundMethod {
		t.Error("missing http.request.method=GET attribute")
	}
	if !foundType {
		t.Error("missing proxy.request.type=http attribute")
	}
}
```

- [ ] **Step 2: Write test for request metrics**

Add to `proxy/otel_test.go`:

```go
func TestOTelHandler_RecordsMetrics(t *testing.T) {
	_, metricReader := setupTestOTel(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	p := NewProxy()
	handler := OTelHandler(p)
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	var rm metricdata.ResourceMetrics
	if err := metricReader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collecting metrics: %v", err)
	}

	var foundCount, foundDuration bool
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch m.Name {
			case "proxy.request.count":
				foundCount = true
			case "proxy.request.duration":
				foundDuration = true
			}
		}
	}
	if !foundCount {
		t.Error("missing proxy.request.count metric")
	}
	if !foundDuration {
		t.Error("missing proxy.request.duration metric")
	}
}
```

- [ ] **Step 3: Write test for error status code span**

Add to `proxy/otel_test.go`:

```go
func TestOTelHandler_SetsErrorStatusOnFailure(t *testing.T) {
	spanExporter, _ := setupTestOTel(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer backend.Close()

	p := NewProxy()
	handler := OTelHandler(p)
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	spans := spanExporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least one span")
	}

	span := spans[0]
	if span.Status.Code != codes.Error {
		t.Errorf("span status = %v, want Error", span.Status.Code)
	}
}

- [ ] **Step 4: Write test for `requestType` classification**

Add to `proxy/otel_test.go`:

```go
func TestRequestType(t *testing.T) {
	tests := []struct {
		name   string
		method string
		host   string
		path   string
		want   string
	}{
		{"CONNECT", "CONNECT", "example.com:443", "", "connect"},
		{"HTTP GET", "GET", "example.com", "/foo", "http"},
		{"MCP relay", "POST", "", "/mcp/server/path", "mcp"},
		{"Relay", "POST", "", "/relay/target", "relay"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, "http://proxy/", nil)
			r.URL.Host = tt.host
			r.URL.Path = tt.path
			if got := requestType(r); got != tt.want {
				t.Errorf("requestType() = %q, want %q", got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 5: Run tests**

Run: `cd /Users/andybons/dev/gatekeeper && go test -race ./proxy/ -run TestOTel -v`
Expected: All four tests pass.

Also run: `cd /Users/andybons/dev/gatekeeper && go test -race ./...`
Expected: All existing tests still pass.

- [ ] **Step 6: Commit**

```bash
git add proxy/otel_test.go
git commit -m "test(proxy): add OTelHandler span and metric tests"
```

---

### Task 4: Wire OTel handler and callbacks in `gatekeeper.go`

**Files:**
- Modify: `gatekeeper.go:32-72` (configureLogging)
- Modify: `gatekeeper.go:148-167` (RequestLogger callback)
- Modify: `gatekeeper.go:292-338` (Start method, handler chain)

- [ ] **Step 1: Add slog bridge to `configureLogging`**

Update `configureLogging` in `gatekeeper.go` to wrap the slog handler with the OTel bridge. Add the import for `"go.opentelemetry.io/contrib/bridges/otelslog"` and update the function:

```go
func configureLogging(cfg LogConfig) (func(), error) {
	var level slog.Level
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	var (
		w       *os.File
		cleanup func()
	)
	switch strings.ToLower(cfg.Output) {
	case "", "stderr":
		w = os.Stderr
	case "stdout":
		w = os.Stdout
	default:
		f, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("opening log output %q: %w", cfg.Output, err)
		}
		w = f
		cleanup = func() { f.Close() }
	}

	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if strings.ToLower(cfg.Format) == "json" {
		handler = slog.NewJSONHandler(w, opts)
	} else {
		handler = slog.NewTextHandler(w, opts)
	}

	handler = otelslog.NewHandler("gatekeeper", otelslog.WithHandler(handler))
	slog.SetDefault(slog.New(handler))
	return cleanup, nil
}
```

- [ ] **Step 2: Update RequestLogger callback to attach span events**

Replace the existing `p.SetLogger(...)` block in `gatekeeper.go` `New()` with:

```go
	p.SetLogger(func(data proxy.RequestLogData) {
		attrs := []slog.Attr{
			slog.String("method", data.Method),
			slog.String("url", data.URL),
			slog.Int("status", data.StatusCode),
			slog.String("duration", data.Duration.Round(time.Millisecond).String()),
		}
		if data.AuthInjected {
			attrs = append(attrs, slog.Bool("credential_injected", true))
		}
		if data.Err != nil {
			attrs = append(attrs, slog.String("error", data.Err.Error()))
		}
		args := make([]any, len(attrs))
		for i, a := range attrs {
			args[i] = a
		}
		slog.Info("request", args...)

		if data.Ctx != nil {
			span := trace.SpanFromContext(data.Ctx)
			if span.SpanContext().IsValid() {
				spanAttrs := []attribute.KeyValue{
					attribute.Float64("duration_ms", float64(data.Duration.Milliseconds())),
					attribute.Bool("credential_injected", data.AuthInjected),
				}
				if data.RunID != "" {
					spanAttrs = append(spanAttrs, attribute.String("run_id", data.RunID))
				}
				var headerNames []string
				for name := range data.InjectedHeaders {
					headerNames = append(headerNames, name)
				}
				if len(headerNames) > 0 {
					spanAttrs = append(spanAttrs, attribute.StringSlice("injected_headers", headerNames))
				}
				span.AddEvent("request.complete", trace.WithAttributes(spanAttrs...))
				if data.Err != nil {
					span.RecordError(data.Err)
				}

				if data.AuthInjected {
					host := data.URL
					if u, err := url.Parse(data.URL); err == nil {
						host = u.Hostname()
					}
					for name := range data.InjectedHeaders {
						proxy.RecordCredentialInjection(data.Ctx, host, name)
					}
				}
			}
		}
	})
```

Add imports to `gatekeeper.go`:
```go
"net/url"

"go.opentelemetry.io/contrib/bridges/otelslog"
"go.opentelemetry.io/otel/attribute"
"go.opentelemetry.io/otel/trace"
```

- [ ] **Step 3: Add PolicyLogger callback with span events**

After the `p.SetLogger(...)` block, add a policy logger. This goes right before the `// Optional defense-in-depth` comment in `New()`:

```go
	p.SetPolicyLogger(func(data proxy.PolicyLogData) {
		slog.Warn("policy denial",
			"run_id", data.RunID,
			"scope", data.Scope,
			"operation", data.Operation,
			"rule", data.Rule,
			"message", data.Message,
		)

		if data.Ctx != nil {
			span := trace.SpanFromContext(data.Ctx)
			if span.SpanContext().IsValid() {
				span.AddEvent("policy.denial", trace.WithAttributes(
					attribute.String("scope", data.Scope),
					attribute.String("operation", data.Operation),
					attribute.String("rule", data.Rule),
					attribute.String("message", data.Message),
				))
				proxy.RecordPolicyDenial(data.Ctx, data.Scope, data.Rule)
			}
		}
	})
```

- [ ] **Step 4: Wrap handler chain with OTelHandler**

In `gatekeeper.go`, update the `Start` method to wrap the handler chain. Change the `http.Server` initialization:

```go
	s.proxyServer = &http.Server{
		Handler:           proxy.OTelHandler(&healthHandler{next: s.proxy}),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
```

- [ ] **Step 5: Run tests**

Run: `cd /Users/andybons/dev/gatekeeper && go build ./...`
Expected: Build succeeds.

Run: `cd /Users/andybons/dev/gatekeeper && go test -race ./...`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
git add gatekeeper.go
git commit -m "feat: wire OTel handler, slog bridge, and callback instrumentation"
```

---

### Task 5: Provider initialization in `cmd/gatekeeper/main.go`

**Files:**
- Modify: `cmd/gatekeeper/main.go`

- [ ] **Step 1: Add OTel provider initialization**

Replace the entire contents of `cmd/gatekeeper/main.go` with:

```go
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/majorcontext/gatekeeper"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

func initOTel(ctx context.Context) (shutdown func(context.Context) error, err error) {
	var shutdownFuncs []func(context.Context) error

	shutdown = func(ctx context.Context) error {
		var errs []error
		for _, fn := range shutdownFuncs {
			if e := fn(ctx); e != nil {
				errs = append(errs, e)
			}
		}
		return errors.Join(errs...)
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("gatekeeper"),
		),
	)
	if err != nil {
		return shutdown, fmt.Errorf("creating otel resource: %w", err)
	}

	traceExporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return shutdown, fmt.Errorf("creating trace exporter: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExporter),
		sdktrace.WithResource(res),
	)
	shutdownFuncs = append(shutdownFuncs, tp.Shutdown)
	otel.SetTracerProvider(tp)

	metricExporter, err := otlpmetrichttp.New(ctx)
	if err != nil {
		return shutdown, fmt.Errorf("creating metric exporter: %w", err)
	}
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter)),
		sdkmetric.WithResource(res),
	)
	shutdownFuncs = append(shutdownFuncs, mp.Shutdown)
	otel.SetMeterProvider(mp)

	logExporter, err := otlploghttp.New(ctx)
	if err != nil {
		return shutdown, fmt.Errorf("creating log exporter: %w", err)
	}
	lp := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(logExporter)),
		sdklog.WithResource(res),
	)
	shutdownFuncs = append(shutdownFuncs, lp.Shutdown)
	global.SetLoggerProvider(lp)

	return shutdown, nil
}

func main() {
	configPath := flag.String("config", "", "path to gatekeeper.yaml")
	flag.Parse()

	if *configPath == "" {
		*configPath = os.Getenv("GATEKEEPER_CONFIG")
	}
	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "error: --config or GATEKEEPER_CONFIG required")
		os.Exit(1)
	}

	cfg, err := gatekeeper.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	otelShutdown, err := initOTel(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error initializing otel: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := otelShutdown(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "error shutting down otel: %v\n", err)
		}
	}()

	srv, err := gatekeeper.New(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating server: %v\n", err)
		os.Exit(1)
	}

	if err := srv.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
```

- [ ] **Step 2: Verify build**

Run: `cd /Users/andybons/dev/gatekeeper && go build ./...`
Expected: Compiles successfully.

Run: `cd /Users/andybons/dev/gatekeeper && go vet ./...`
Expected: No issues.

- [ ] **Step 3: Commit**

```bash
git add cmd/gatekeeper/main.go go.mod go.sum
git commit -m "feat: add OTel provider initialization with OTLP exporters"
```

---

### Task 6: Integration test for OTel callbacks

**Files:**
- Modify: `gatekeeper_test.go` (or create if no OTel-specific tests exist there)

- [ ] **Step 1: Check existing test file**

Read `gatekeeper_test.go` to understand the test patterns used.

- [ ] **Step 2: Write integration test for RequestLogger span event**

Add a test that verifies the full flow: HTTP request → OTelHandler span → RequestLogger callback → span event. Since `healthHandler` is unexported, this test lives in `gatekeeper_test.go` (same package):

```go
func TestOTelSpanEventsViaHTTPRequest(t *testing.T) {
	spanExporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(spanExporter))
	otel.SetTracerProvider(tp)
	defer tp.Shutdown(context.Background())

	metricReader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(metricReader))
	otel.SetMeterProvider(mp)
	defer mp.Shutdown(context.Background())

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfgYAML := fmt.Sprintf(`
proxy:
  port: 0
log:
  level: error
`)
	cfgPath := filepath.Join(t.TempDir(), "gatekeeper.yaml")
	os.WriteFile(cfgPath, []byte(cfgYAML), 0644)

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	srv, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	// Use the OTel-wrapped handler directly
	handler := proxy.OTelHandler(&healthHandler{next: srv.proxy})
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(t, proxyServer.URL)),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	tp.ForceFlush(context.Background())

	spans := spanExporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least one span")
	}

	foundComplete := false
	for _, s := range spans {
		for _, e := range s.Events {
			if e.Name == "request.complete" {
				foundComplete = true
			}
		}
	}
	if !foundComplete {
		t.Error("expected request.complete span event")
	}
}
```

Imports for `gatekeeper_test.go`:

```go
import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/majorcontext/gatekeeper/proxy"

	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse URL %q: %v", rawURL, err)
	}
	return u
}
```

- [ ] **Step 3: Run tests**

Run: `cd /Users/andybons/dev/gatekeeper && go test -race ./... -v`
Expected: All tests pass including the new OTel integration test.

- [ ] **Step 4: Commit**

```bash
git add gatekeeper_test.go
git commit -m "test: add OTel integration test for span events via HTTP flow"
```

---

### Task 7: Final verification

**Files:** None (verification only)

- [ ] **Step 1: Run full test suite with race detector**

Run: `cd /Users/andybons/dev/gatekeeper && go test -race ./...`
Expected: All tests pass, no race conditions.

- [ ] **Step 2: Run vet**

Run: `cd /Users/andybons/dev/gatekeeper && go vet ./...`
Expected: No issues.

- [ ] **Step 3: Build the binary**

Run: `cd /Users/andybons/dev/gatekeeper && go build -o gatekeeper ./cmd/gatekeeper/`
Expected: Binary builds successfully.

- [ ] **Step 4: Clean up binary**

Run: `rm /Users/andybons/dev/gatekeeper/gatekeeper`

- [ ] **Step 5: Run `go mod tidy`**

Run: `cd /Users/andybons/dev/gatekeeper && go mod tidy`
Expected: No changes (deps already clean), or minor cleanup.

- [ ] **Step 6: Commit if go.mod/go.sum changed**

```bash
git add go.mod go.sum
git commit -m "chore: tidy go modules"
```
