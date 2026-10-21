package gatekeeper

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/majorcontext/gatekeeper/credentialsource"
)

// flakySource fails its first failures fetches, as the GKE metadata server
// does for the first seconds of a new Pod.
type flakySource struct {
	failures int // -1 fails every fetch

	mu    sync.Mutex
	times []time.Time
}

func (s *flakySource) Fetch(ctx context.Context) (string, error) {
	s.mu.Lock()
	s.times = append(s.times, time.Now())
	n := len(s.times)
	s.mu.Unlock()
	if s.failures < 0 || n <= s.failures {
		return "", errors.New("metadata server not ready: connection refused")
	}
	return "ya29.adc", nil
}

func (s *flakySource) Type() string { return "flaky" }

func (s *flakySource) fetchTimes() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Time(nil), s.times...)
}

// retryingFlakySource asks for a startup retry window, as the ADC
// gcp-service-account source does.
type retryingFlakySource struct {
	*flakySource
	window time.Duration
}

func (s retryingFlakySource) StartupRetryWindow() time.Duration { return s.window }

func loadFlakyCredential(t *testing.T, src credentialsource.CredentialSource) (*Server, error) {
	t.Helper()
	srv, err := New(context.Background(), &Config{Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	srv.resolveSource = func(SourceConfig) (credentialsource.CredentialSource, error) { return src, nil }
	cfg := &Config{Credentials: []CredentialConfig{{
		Host: "127.0.0.1", Grant: "gcs", AllowInsecure: true,
		Source: SourceConfig{Type: "gcp-service-account", ADC: true},
	}}}
	return srv, srv.loadCredentials(context.Background(), cfg)
}

func TestLoadCredentials_StartupRetryWindowRetriesWithBackoff(t *testing.T) {
	port := startEchoBackend(t)
	synctest.Test(t, func(t *testing.T) {
		src := &flakySource{failures: 3}
		srv, err := loadFlakyCredential(t, retryingFlakySource{src, 30 * time.Second})
		if err != nil {
			t.Fatalf("loadCredentials with 3 failures inside a 30s retry window: %v", err)
		}

		times := src.fetchTimes()
		if len(times) != 4 {
			t.Fatalf("fetches = %d, want 4 (3 failures, then a success)", len(times))
		}
		floor := time.Second
		for i := 1; i < len(times); i++ {
			if g := times[i].Sub(times[i-1]); g < floor || g >= floor*5/4 {
				t.Errorf("wait after failure %d = %v, want [%v, %v)", i, g, floor, floor*5/4)
			}
			floor = 2 * times[i].Sub(times[i-1])
		}

		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:"+port+"/", nil)
		rec := httptest.NewRecorder()
		srv.proxy.ServeHTTP(rec, req)
		if got, _, _ := strings.Cut(rec.Body.String(), "|"); got != "Bearer ya29.adc" {
			t.Errorf("Authorization injected = %q, want %q", got, "Bearer ya29.adc")
		}
	})
}

func TestLoadCredentials_StartupRetryWindowIsBounded(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		src := &flakySource{failures: -1}
		start := time.Now()
		_, err := loadFlakyCredential(t, retryingFlakySource{src, 30 * time.Second})
		if err == nil {
			t.Fatal("loadCredentials with a source that always fails = nil error, want an error")
		}
		if !strings.Contains(err.Error(), "connection refused") {
			t.Errorf("error = %q, want the last fetch error", err)
		}
		if n := len(src.fetchTimes()); n < 2 {
			t.Errorf("fetches = %d, want retries inside the window", n)
		}
		if elapsed := time.Since(start); elapsed > 30*time.Second {
			t.Errorf("loadCredentials gave up after %v, want at most the 30s window", elapsed)
		}
	})
}

// TestLoadCredentials_NoStartupRetryWithoutWindow pins the key path: a
// source without a retry window fails startup on its first fetch error.
func TestLoadCredentials_NoStartupRetryWithoutWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		src := &flakySource{failures: 1}
		_, err := loadFlakyCredential(t, src)
		if err == nil {
			t.Fatal("loadCredentials after one fetch failure = nil error, want an error")
		}
		if n := len(src.fetchTimes()); n != 1 {
			t.Errorf("fetches = %d, want 1 (no retry)", n)
		}
	})
}
