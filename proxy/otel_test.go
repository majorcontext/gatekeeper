package proxy

import (
	"context"
	"io"
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

// reinitMetrics re-creates all metric instruments from a fresh meter.
// This is needed because init() runs before tests can swap in a real
// MeterProvider via otel.SetMeterProvider.
func reinitMetrics() {
	m := otel.Meter("gatekeeper")
	var err error
	requestDuration, err = m.Float64Histogram("proxy.request.duration",
		metric.WithDescription("Duration of proxy requests"),
		metric.WithUnit("s"),
	)
	if err != nil {
		panic(err)
	}
	requestCount, err = m.Int64Counter("proxy.request.count",
		metric.WithDescription("Total number of proxy requests"),
	)
	if err != nil {
		panic(err)
	}
	credInjections, err = m.Int64Counter("proxy.credential.injections",
		metric.WithDescription("Total number of credential injections"),
	)
	if err != nil {
		panic(err)
	}
	policyDenials, err = m.Int64Counter("proxy.policy.denials",
		metric.WithDescription("Total number of policy denials"),
	)
	if err != nil {
		panic(err)
	}
}

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

	// Re-create instruments so they use the new real MeterProvider
	// instead of the no-op one from init().
	reinitMetrics()

	// Also re-create the tracer so spans go to the new provider.
	tracer = otel.Tracer("gatekeeper")

	return spanExporter, metricReader
}

// TestOTelHandler_CreatesSpanForHTTPRequest verifies that the OTelHandler
// creates a span with the expected name and attributes for an HTTP request
// proxied through the handler.
func TestOTelHandler_CreatesSpanForHTTPRequest(t *testing.T) {
	spanExporter, _ := setupTestOTel(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()
	wrapped := OTelHandler(p)
	proxyServer := httptest.NewServer(wrapped)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	spans := spanExporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least one span, got none")
	}

	var found bool
	for _, s := range spans {
		if s.Name == "proxy.http" {
			found = true
			// Check attributes.
			attrs := make(map[string]interface{})
			for _, a := range s.Attributes {
				attrs[string(a.Key)] = a.Value.AsInterface()
			}
			if attrs["http.request.method"] != "GET" {
				t.Errorf("http.request.method = %v, want GET", attrs["http.request.method"])
			}
			if attrs["proxy.request.type"] != "http" {
				t.Errorf("proxy.request.type = %v, want http", attrs["proxy.request.type"])
			}
			break
		}
	}
	if !found {
		t.Errorf("no span with name 'proxy.http' found; spans: %v", spanNames(spans))
	}
}

// TestOTelHandler_RecordsMetrics verifies that the OTelHandler records
// proxy.request.count and proxy.request.duration metrics.
func TestOTelHandler_RecordsMetrics(t *testing.T) {
	_, metricReader := setupTestOTel(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()
	wrapped := OTelHandler(p)
	proxyServer := httptest.NewServer(wrapped)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	var rm metricdata.ResourceMetrics
	if err := metricReader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collecting metrics: %v", err)
	}

	metricNames := collectMetricNames(rm)
	if _, ok := metricNames["proxy.request.count"]; !ok {
		t.Errorf("proxy.request.count metric not found; got: %v", metricNames)
	}
	if _, ok := metricNames["proxy.request.duration"]; !ok {
		t.Errorf("proxy.request.duration metric not found; got: %v", metricNames)
	}
}

// TestOTelHandler_SetsErrorStatusOnFailure verifies that the OTelHandler sets
// span status to Error when the backend returns a 502 status code.
func TestOTelHandler_SetsErrorStatusOnFailure(t *testing.T) {
	spanExporter, _ := setupTestOTel(t)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("bad gateway"))
	}))
	defer backend.Close()

	p := NewProxy()
	wrapped := OTelHandler(p)
	proxyServer := httptest.NewServer(wrapped)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	spans := spanExporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least one span, got none")
	}

	var found bool
	for _, s := range spans {
		if s.Name == "proxy.http" {
			found = true
			if s.Status.Code != codes.Error {
				t.Errorf("span status code = %v, want %v (Error)", s.Status.Code, codes.Error)
			}
			break
		}
	}
	if !found {
		t.Errorf("no span with name 'proxy.http' found; spans: %v", spanNames(spans))
	}
}

// TestRequestType is a table-driven test for the requestType() function.
func TestRequestType(t *testing.T) {
	tests := []struct {
		name   string
		method string
		host   string
		path   string
		want   string
	}{
		{
			name:   "CONNECT is connect",
			method: http.MethodConnect,
			host:   "example.com:443",
			path:   "",
			want:   "connect",
		},
		{
			name:   "GET with host is http",
			method: http.MethodGet,
			host:   "example.com",
			path:   "/foo",
			want:   "http",
		},
		{
			name:   "POST to /mcp/ with empty host is mcp",
			method: http.MethodPost,
			host:   "",
			path:   "/mcp/some-server",
			want:   "mcp",
		},
		{
			name:   "POST to /relay/ with empty host is relay",
			method: http.MethodPost,
			host:   "",
			path:   "/relay/some-server",
			want:   "relay",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Method: tt.method,
				URL:    mustParseURL("http://" + tt.host + tt.path),
			}
			// For cases where host should be empty, clear it.
			if tt.host == "" {
				req.URL.Host = ""
			}
			got := requestType(req)
			if got != tt.want {
				t.Errorf("requestType() = %q, want %q", got, tt.want)
			}
		})
	}
}

// spanNames returns the names of all spans for diagnostic output.
func spanNames(spans tracetest.SpanStubs) []string {
	names := make([]string, len(spans))
	for i, s := range spans {
		names[i] = s.Name
	}
	return names
}

// collectMetricNames extracts all metric names from ResourceMetrics.
func collectMetricNames(rm metricdata.ResourceMetrics) map[string]bool {
	names := make(map[string]bool)
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			names[m.Name] = true
		}
	}
	return names
}
