package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/majorcontext/gatekeeper"
)

// ── multiHandler (slog fan-out) ───────────────────────────────────────────────

// TestMultiHandler_WithAttrs verifies that WithAttrs propagates to all child
// handlers, exercising the previously uncovered branch.
func TestMultiHandler_WithAttrs(t *testing.T) {
	h1 := slog.NewTextHandler(io.Discard, nil)
	h2 := slog.NewTextHandler(io.Discard, nil)
	mh := newMultiHandler(h1, h2)

	derived := mh.WithAttrs([]slog.Attr{slog.String("k", "v")})
	if derived == nil {
		t.Fatal("WithAttrs returned nil")
	}
	// Derived handler should still respond to Enabled.
	if !derived.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("derived handler Enabled(Info) = false, want true")
	}
}

// TestMultiHandler_WithGroup verifies that WithGroup propagates to all child
// handlers.
func TestMultiHandler_WithGroup(t *testing.T) {
	h1 := slog.NewTextHandler(io.Discard, nil)
	mh := newMultiHandler(h1)

	derived := mh.WithGroup("mygroup")
	if derived == nil {
		t.Fatal("WithGroup returned nil")
	}
	if !derived.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("derived handler Enabled(Info) = false, want true")
	}
}

// fakeSlogHandler is a minimal slog.Handler that records every record it
// receives, for observing what actually reaches a handler in tests.
type fakeSlogHandler struct {
	records []slog.Record
}

func (f *fakeSlogHandler) Enabled(context.Context, slog.Level) bool { return true }

func (f *fakeSlogHandler) Handle(_ context.Context, r slog.Record) error {
	f.records = append(f.records, r)
	return nil
}

func (f *fakeSlogHandler) WithAttrs([]slog.Attr) slog.Handler { return f }
func (f *fakeSlogHandler) WithGroup(string) slog.Handler      { return f }

// TestOTelDiagnosticFilter_KeepsBridgeOutOfLoop encodes the fix for #48:
// gatekeeper's own OTel diagnostics (logOTelError's DEBUG record on a
// failed export) must never reach the otelslog bridge handler, or the
// diagnostic itself gets enqueued into the same failing OTel log-export
// pipeline — producing another diagnostic on the next failed attempt, and
// so on indefinitely while a collector is unreachable. The console handler
// must still see every record, marked or not.
func TestOTelDiagnosticFilter_KeepsBridgeOutOfLoop(t *testing.T) {
	var console, bridge fakeSlogHandler
	handler := newMultiHandler(&console, newOTelDiagnosticFilter(&bridge))
	logger := slog.New(handler)

	logger.Debug("otel error", "error", "dial tcp [::1]:4318: connect: connection refused", otelDiagnosticKey, true)
	logger.Info("normal request", "host", "example.com")
	// A record carrying the key set to false is not a diagnostic and must
	// still reach the bridge — the filter keys off the value, not mere
	// presence of the attribute.
	logger.Info("opted-in request", "host", "example.com", otelDiagnosticKey, false)

	if got := len(console.records); got != 3 {
		t.Fatalf("console handler received %d records, want 3 (all records)", got)
	}
	if got := len(bridge.records); got != 2 {
		t.Fatalf("bridge handler received %d records, want 2 (only the true-marked diagnostic is filtered out)", got)
	}
	if got := bridge.records[0].Message; got != "normal request" {
		t.Errorf("bridge handler's first surviving record = %q, want %q", got, "normal request")
	}
	if got := bridge.records[1].Message; got != "opted-in request" {
		t.Errorf("bridge handler's second surviving record = %q, want %q (key=false must pass through)", got, "opted-in request")
	}
}

func TestNewLogger_FileOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gk.log")
	logger, closeLog, err := newLogger(gatekeeper.LogConfig{Level: "info", Format: "json", Output: path})
	if err != nil {
		t.Fatalf("newLogger: %v", err)
	}
	logger.Info("request", "http_status", 200)
	logger.Debug("hidden")
	closeLog()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("log file mode = %o, want 600", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &rec); err != nil {
		t.Fatalf("log output is not one JSON line: %q: %v", data, err)
	}
	if rec["level"] != "INFO" || rec["msg"] != "request" || rec["http_status"] != float64(200) || len(rec) != 4 {
		t.Errorf("log record = %v, want time, level=INFO, msg=request, http_status=200", rec)
	}
}

func TestNewServer_ClosesLogFileWhenNewFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gk.log")
	cfg := &gatekeeper.Config{
		Proxy:    gatekeeper.ProxyConfig{Port: 0, Host: "127.0.0.1"},
		Postgres: &gatekeeper.PostgresConfig{Port: 5433},
		Log:      gatekeeper.LogConfig{Output: path},
	}
	before := openFDs(t)
	if _, _, err := newServer(context.Background(), cfg); err == nil {
		t.Fatal("newServer succeeded, want error for postgres without a CA")
	}
	if after := openFDs(t); after != before {
		t.Errorf("open file descriptors = %d after failed newServer, want %d", after, before)
	}
}

func openFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Skipf("no /dev/fd: %v", err)
	}
	return len(entries)
}

func TestNewServer_CanonicalRequestLine(t *testing.T) {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer backend.Close()

	path := filepath.Join(t.TempDir(), "gk.log")
	cfg := &gatekeeper.Config{
		Proxy:   gatekeeper.ProxyConfig{Port: 0, Host: "127.0.0.1"},
		Network: gatekeeper.NetworkConfig{Policy: "permissive"},
		Log:     gatekeeper.LogConfig{Format: "json", Output: path},
	}
	srv, closeLog, err := newServer(context.Background(), cfg)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan error, 1)
	go func() { started <- srv.Start(ctx) }()
	for srv.ProxyAddr() == "" {
		select {
		case err := <-started:
			t.Fatalf("Start returned early: %v", err)
		default:
			runtime.Gosched()
		}
	}

	proxyURL, _ := url.Parse("http://" + srv.ProxyAddr())
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(backend.URL + "/probe")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	cancel()
	if err := <-started; err != nil {
		t.Fatalf("Start: %v", err)
	}
	closeLog()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("non-JSON log line %q: %v", line, err)
		}
		if rec["msg"] != "request" {
			continue
		}
		found = true
		if rec["level"] != "WARN" || rec["http_method"] != "GET" || rec["http_path"] != "/probe" ||
			rec["http_status"] != float64(http.StatusTeapot) || rec["proxy_type"] != "http" || rec["request_id"] == "" {
			t.Errorf("canonical line = %v", rec)
		}
	}
	if !found {
		t.Errorf("no canonical request line in %q", data)
	}
}
