package proxy

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
		metric.WithDescription("Duration of proxy requests"),
		metric.WithUnit("s"),
	)
	if err != nil {
		panic(fmt.Sprintf("failed to create request duration histogram: %v", err))
	}

	requestCount, err = meter.Int64Counter("proxy.request.count",
		metric.WithDescription("Total number of proxy requests"),
	)
	if err != nil {
		panic(fmt.Sprintf("failed to create request count counter: %v", err))
	}

	credInjections, err = meter.Int64Counter("proxy.credential.injections",
		metric.WithDescription("Total number of credential injections"),
	)
	if err != nil {
		panic(fmt.Sprintf("failed to create credential injections counter: %v", err))
	}

	policyDenials, err = meter.Int64Counter("proxy.policy.denials",
		metric.WithDescription("Total number of policy denials"),
	)
	if err != nil {
		panic(fmt.Sprintf("failed to create policy denials counter: %v", err))
	}
}

// RecordCredentialInjection increments the credential injection counter
// with the server address and injected header name as attributes.
func RecordCredentialInjection(ctx context.Context, host, headerName string) {
	credInjections.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("server.address", host),
			attribute.String("proxy.credential.header", headerName),
		),
	)
}

// RecordPolicyDenial increments the policy denial counter
// with the policy scope and rule as attributes.
func RecordPolicyDenial(ctx context.Context, scope, rule string) {
	policyDenials.Add(ctx, 1,
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

// OTelHandler wraps an http.Handler with OpenTelemetry tracing and metrics.
func OTelHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt := requestType(r)
		ctx, span := tracer.Start(r.Context(), spanName(rt),
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
		requestDuration.Record(ctx, duration, attrs)
		requestCount.Add(ctx, 1, attrs)
	})
}
