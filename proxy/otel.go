package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/trace"
)

// OTelOptions selects the OpenTelemetry providers for NewOTelHandler. A nil
// provider falls back to the corresponding global provider.
type OTelOptions struct {
	TracerProvider trace.TracerProvider
	MeterProvider  metric.MeterProvider
}

type otelInstruments struct {
	tracer          trace.Tracer
	requestDuration metric.Float64Histogram
	requestCount    metric.Int64Counter
	credInjections  metric.Int64Counter
	policyDenials   metric.Int64Counter
}

// otelScope selects which instruments newOTelInstruments creates.
type otelScope int

const (
	scopeRequest otelScope = iota // handler: spans, request duration and count
	scopeRecord                   // Record* functions: injection and denial counters
)

// newOTelInstruments never returns nil. An instrument that cannot be created
// is a no-op, and the joined creation errors are returned.
func newOTelInstruments(opts OTelOptions, scope otelScope) (*otelInstruments, error) {
	tp := opts.TracerProvider
	if tp == nil {
		tp = otel.GetTracerProvider()
	}
	mp := opts.MeterProvider
	if mp == nil {
		mp = otel.GetMeterProvider()
	}
	meter := mp.Meter("gatekeeper")
	fallback := noop.NewMeterProvider().Meter("gatekeeper")
	in := &otelInstruments{tracer: tp.Tracer("gatekeeper")}

	var errs []error
	counter := func(name, desc string) metric.Int64Counter {
		c, err := meter.Int64Counter(name, metric.WithDescription(desc))
		if err != nil {
			errs = append(errs, fmt.Errorf("creating %s: %w", name, err))
			c, _ = fallback.Int64Counter(name)
		}
		return c
	}
	if scope == scopeRecord {
		in.credInjections = counter("proxy.credential.injections", "Total number of credential injections")
		in.policyDenials = counter("proxy.policy.denials", "Total number of policy denials")
		return in, errors.Join(errs...)
	}
	h, err := meter.Float64Histogram("proxy.request.duration",
		metric.WithDescription("Duration of proxy requests"),
		metric.WithUnit("s"),
	)
	if err != nil {
		errs = append(errs, fmt.Errorf("creating proxy.request.duration: %w", err))
		h, _ = fallback.Float64Histogram("proxy.request.duration")
	}
	in.requestDuration = h
	in.requestCount = counter("proxy.request.count", "Total number of proxy requests")
	return in, errors.Join(errs...)
}

// globalInstruments back RecordCredentialInjection and RecordPolicyDenial,
// which always use the global providers.
var globalInstruments = sync.OnceValue(func() *otelInstruments {
	in, err := newOTelInstruments(OTelOptions{}, scopeRecord)
	if err != nil {
		slog.Warn("otel instruments unavailable", "error", err)
	}
	return in
})

// RecordCredentialInjection increments the credential injection counter
// with the server address and injected header name as attributes.
func RecordCredentialInjection(ctx context.Context, host, headerName string) {
	globalInstruments().credInjections.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("server.address", host),
			attribute.String("proxy.credential.header", headerName),
		),
	)
}

// RecordPolicyDenial increments the policy denial counter
// with the policy scope and rule as attributes.
func RecordPolicyDenial(ctx context.Context, scope, rule string) {
	globalInstruments().policyDenials.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("proxy.policy.scope", scope),
			attribute.String("proxy.policy.rule", rule),
		),
	)
}

// statusRecorder wraps http.ResponseWriter to capture the status code.
// It also implements http.Hijacker by delegating to the underlying writer,
// which is required for CONNECT handling.
type statusRecorder struct {
	http.ResponseWriter
	statusCode int
	written    bool
	hijacked   bool
}

func (sr *statusRecorder) WriteHeader(code int) {
	if !sr.written {
		sr.statusCode = code
		sr.written = true
	}
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *statusRecorder) Write(b []byte) (int, error) {
	if !sr.written {
		sr.statusCode = http.StatusOK
		sr.written = true
	}
	return sr.ResponseWriter.Write(b)
}

// Hijack implements http.Hijacker by delegating to the underlying ResponseWriter.
// This is critical for CONNECT requests where the proxy calls w.(http.Hijacker).Hijack()
// to take over the connection.
func (sr *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := sr.ResponseWriter.(http.Hijacker); ok {
		sr.hijacked = true
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")
}

// Flush implements http.Flusher by delegating to the underlying
// ResponseWriter when it implements http.Flusher, and is a no-op otherwise.
// The relay and MCP relay streaming loops (proxy/relay.go, proxy/mcp.go)
// type-assert w.(http.Flusher) after every chunk to push partial responses
// (SSE, ndjson) onto the wire immediately instead of waiting in net/http's
// internal buffer. Without this method the assertion always failed once the
// standalone server wrapped the proxy in OTelHandler, silently disabling
// per-chunk flushing in production — invisible in tests that exercise
// streaming directly against httptest.ResponseRecorder, which implements
// Flush itself.
//
// No response path needs flushing suppressed here: the only other special
// case this wrapper handles is Hijack (CONNECT), which hands the raw
// connection to the caller and is never followed by further Write/Flush
// calls through this ResponseWriter, so there is no risk of a stray Flush
// after hijack.
func (sr *statusRecorder) Flush() {
	if f, ok := sr.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// requestType returns a classification string for the request.
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

// spanName maps a request type to a span name.
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

// NewOTelHandler wraps an http.Handler with OpenTelemetry tracing and
// metrics. If an instrument cannot be created, the handler still works with
// that instrument disabled and the error reports which ones failed.
func NewOTelHandler(next http.Handler, opts OTelOptions) (http.Handler, error) {
	in, err := newOTelInstruments(opts, scopeRequest)
	return in.handler(next), err
}

func (in *otelInstruments) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt := requestType(r)
		ctx, span := in.tracer.Start(r.Context(), spanName(rt),
			trace.WithSpanKind(trace.SpanKindServer),
		)
		defer span.End()

		// Determine server address from the request.
		serverAddr := r.Host
		if r.URL.Host != "" {
			serverAddr = r.URL.Host
		}

		span.SetAttributes(
			attribute.String("http.request.method", r.Method),
			attribute.String("server.address", serverAddr),
			attribute.String("proxy.request.type", rt),
		)

		sr := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		start := time.Now()

		next.ServeHTTP(sr, r.WithContext(ctx))

		duration := time.Since(start).Seconds()

		// After Hijack(), the status code is meaningless — the proxy
		// wrote directly to the raw connection, bypassing ResponseWriter.
		if !sr.hijacked {
			span.SetAttributes(
				attribute.Int("http.response.status_code", sr.statusCode),
			)
			if sr.statusCode >= 400 {
				span.SetStatus(codes.Error, http.StatusText(sr.statusCode))
			} else {
				span.SetStatus(codes.Ok, "")
			}
		}

		metricAttrs := []attribute.KeyValue{
			attribute.String("http.request.method", r.Method),
			attribute.String("server.address", serverAddr),
			attribute.String("proxy.request.type", rt),
		}
		if !sr.hijacked {
			metricAttrs = append(metricAttrs, attribute.Int("http.response.status_code", sr.statusCode))
		}
		attrs := metric.WithAttributes(metricAttrs...)
		in.requestDuration.Record(ctx, duration, attrs)
		in.requestCount.Add(ctx, 1, attrs)
	})
}
