package gatekeeper

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/majorcontext/gatekeeper/proxy"
)

func TestRequestLogUpstreamAuthCode(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"detail":{"code":"token_expired","message":"secret"}}`))
	}))
	defer backend.Close()
	var logs bytes.Buffer
	s := &Server{proxy: proxy.NewProxy(), cfg: &Config{}, logger: slog.New(slog.NewJSONHandler(&logs, nil))}
	if err := s.proxy.AddRelay("test", backend.URL); err != nil {
		t.Fatal(err)
	}
	s.installRequestLogger()
	s.proxy.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/relay/test/", nil))
	if !strings.Contains(logs.String(), `"upstream_auth_code":"token_expired"`) {
		t.Fatalf("canonical log missing code: %s", logs.String())
	}
	if strings.Contains(logs.String(), "secret") {
		t.Fatalf("canonical log leaked body: %s", logs.String())
	}
}
