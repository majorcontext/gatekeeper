package gatekeeper

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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
		srv, err := loadFlakyCredential(t, retryingFlakySource{src, 30 * time.Second})
		if err != nil {
			t.Fatalf("loadCredentials with a source that always fails = %v, want nil", err)
		}
		if len(srv.pendingRefreshes) != 1 || !srv.pendingRefreshes[0].failed {
			t.Errorf("pendingRefreshes = %+v, want the failed credential queued for background retry", srv.pendingRefreshes)
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
// source without a retry window makes one startup fetch, then retries in the
// background.
func TestLoadCredentials_NoStartupRetryWithoutWindow(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		src := &flakySource{failures: 1}
		if _, err := loadFlakyCredential(t, src); err != nil {
			t.Fatalf("loadCredentials after one fetch failure = %v, want nil", err)
		}
		if n := len(src.fetchTimes()); n != 1 {
			t.Errorf("fetches = %d, want 1 (no retry)", n)
		}
	})
}

// ambientFlakySource fails its first fetch like flakySource and reports the
// startup retry window of the source that a config resolves to.
type ambientFlakySource struct {
	*flakySource
	resolved credentialsource.CredentialSource
}

func (s ambientFlakySource) StartupRetryWindow() time.Duration {
	if r, ok := s.resolved.(startupRetrier); ok {
		return r.StartupRetryWindow()
	}
	return 0
}

// TestLoadCredentials_AmbientCredentialSourcesRetryAtStartup pins which
// sources survive a metadata server that refuses the first fetch of a new
// Pod: a source that authenticates with ambient cloud credentials retries,
// and a source with a configured key does not.
func TestLoadCredentials_AmbientCredentialSourcesRetryAtStartup(t *testing.T) {
	keyJSON := testGCPSAKeyJSON(t)
	adcFile := filepath.Join(t.TempDir(), "adc.json")
	if err := os.WriteFile(adcFile, keyJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", adcFile)
	t.Setenv("TEST_GCP_SA_KEY", string(keyJSON))

	tests := []struct {
		name      string
		cfg       SourceConfig
		wantRetry bool
	}{
		{"gcp-secretmanager", SourceConfig{Type: "gcp-secretmanager", Project: "my-project", Secret: "api-key"}, true},
		{"gcp-service-account with secret", SourceConfig{Type: "gcp-service-account", Project: "my-project", Secret: "sa-key"}, true},
		{"gcp-service-account with adc", SourceConfig{Type: "gcp-service-account", ADC: true}, true},
		{"aws-secretsmanager", SourceConfig{Type: "aws-secretsmanager", Secret: "api-key", Region: "us-east-1"}, true},
		{"gcp-service-account with private_key_env", SourceConfig{Type: "gcp-service-account", PrivateKeyEnv: "TEST_GCP_SA_KEY"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolved, err := resolveSource(tt.cfg)
			if err != nil {
				t.Fatalf("resolveSource(%+v): %v", tt.cfg, err)
			}
			if c, ok := resolved.(io.Closer); ok {
				t.Cleanup(func() { c.Close() })
			}
			synctest.Test(t, func(t *testing.T) {
				flaky := &flakySource{failures: 1}
				srv, err := loadFlakyCredential(t, ambientFlakySource{flaky, resolved})
				if err != nil {
					t.Fatalf("loadCredentials after one failed %s fetch: %v", tt.name, err)
				}
				if got := len(srv.pendingRefreshes) == 0; got != tt.wantRetry {
					t.Errorf("%s: startup retry succeeded = %v, want %v", tt.name, got, tt.wantRetry)
				}
			})
		})
	}
}

type vendorSource struct {
	token string
	err   atomic.Pointer[error]
}

func (s *vendorSource) Fetch(context.Context) (string, error) {
	if e := s.err.Load(); e != nil {
		return "", *e
	}
	return s.token, nil
}

func (s *vendorSource) Type() string { return "vendor" }

func TestLoadCredentials_FailedFetchDoesNotBlockStartup(t *testing.T) {
	port := startEchoBackend(t)
	synctest.Test(t, func(t *testing.T) {
		bad := failingVendor()
		srv := vendorServer(t, map[string]*vendorSource{"good-key": {token: "good-token"}, "vendor-key": bad})
		cfg := &Config{Credentials: []CredentialConfig{
			{Host: "127.0.0.1", Grant: "good", AllowInsecure: true, Source: SourceConfig{Type: "vendor", Secret: "good-key"}, Match: &MatchConfig{Header: "X-Route", Paths: []string{"/good"}}},
			{Host: "127.0.0.1", Grant: "vendor", AllowInsecure: true, Source: SourceConfig{Type: "vendor", Secret: "vendor-key"}, Match: &MatchConfig{Header: "X-Route", Paths: []string{"/vendor"}}},
		}}
		if err := srv.loadCredentials(context.Background(), cfg); err != nil {
			t.Fatalf("loadCredentials with one deleted secret = %v, want nil", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		for _, pr := range srv.pendingRefreshes {
			srv.startPending(ctx, pr)
		}
		defer func() {
			cancel()
			srv.refreshWG.Wait()
		}()

		get := func(path string) (int, string) {
			req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:"+port+path, nil)
			req.Header.Set("X-Route", "x")
			rec := httptest.NewRecorder()
			srv.proxy.ServeHTTP(rec, req)
			auth, _, _ := strings.Cut(rec.Body.String(), "|")
			return rec.Code, auth
		}
		if code, auth := get("/good"); code != http.StatusOK || auth != "Bearer good-token" {
			t.Fatalf("/good with the vendor secret deleted = %d %q, want 200 with the good credential", code, auth)
		}
		if code, _ := get("/vendor"); code != http.StatusForbidden {
			t.Fatalf("/vendor with the secret deleted = %d, want 403", code)
		}

		bad.err.Store(nil)
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if code, auth := get("/vendor"); code != http.StatusOK || auth != "Bearer vendor-token" {
			t.Errorf("/vendor after the secret is restored = %d %q, want 200 with the vendor credential", code, auth)
		}
	})
}

func vendorServer(t *testing.T, srcs map[string]*vendorSource) *Server {
	t.Helper()
	srv := newBareServer(t)
	srv.resolveSource = func(sc SourceConfig) (credentialsource.CredentialSource, error) {
		return srcs[sc.Secret], nil
	}
	return srv
}

func failingVendor() *vendorSource {
	v := &vendorSource{token: "vendor-token"}
	e := errors.New("secretmanager: rpc error: code = NotFound desc = secret was deleted")
	v.err.Store(&e)
	return v
}

func TestLoadCredentials_FailedExactHostIsNotServedByWildcard(t *testing.T) {
	srv := vendorServer(t, map[string]*vendorSource{"wild": {token: "wildcard-token"}, "exact": failingVendor()})
	cfg := &Config{Credentials: []CredentialConfig{
		{Host: "api.example.com", Grant: "exact", AllowInsecure: true, Source: SourceConfig{Type: "vendor", Secret: "exact"}},
		{Host: "*.example.com", Grant: "wild", AllowInsecure: true, Source: SourceConfig{Type: "vendor", Secret: "wild"}},
	}}
	if err := srv.loadCredentials(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/", nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	srv.proxy.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status for the host with the deleted secret = %d, want 403 (never another credential)", rec.Code)
	}
}

func TestLoadCredentials_NeonSharingAFailedSourceKeepsItsResolver(t *testing.T) {
	srv := vendorServer(t, map[string]*vendorSource{"shared": failingVendor()})
	shared := SourceConfig{Type: "vendor", Secret: "shared"}
	cfg := &Config{Credentials: []CredentialConfig{
		{Host: "db.example.com", Grant: "db", Source: shared, Postgres: &PostgresCredentialConfig{Resolver: "static"}},
		{Host: "*.neon.tech", Grant: "neon", Source: shared, Postgres: &PostgresCredentialConfig{Resolver: "neon", Project: "p"}},
	}}
	if err := srv.loadCredentials(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if len(srv.pendingRefreshes) != 1 || len(srv.pendingRefreshes[0].creds) != 1 || srv.pendingRefreshes[0].creds[0].Host != "db.example.com" {
		t.Errorf("pendingRefreshes = %+v, want only the static db.example.com queued for recovery", srv.pendingRefreshes)
	}
}

func TestLoadCredentials_RecoveredNarrowRuleKeepsItsPrecedence(t *testing.T) {
	port := startEchoBackend(t)
	synctest.Test(t, func(t *testing.T) {
		narrow := failingVendor()
		srv := vendorServer(t, map[string]*vendorSource{"narrow": narrow, "broad": {token: "broad-token"}})
		cfg := &Config{Credentials: []CredentialConfig{
			{Host: "127.0.0.1", Grant: "narrow", AllowInsecure: true, Source: SourceConfig{Type: "vendor", Secret: "narrow"}, Match: &MatchConfig{Header: "X-Route", Paths: []string{"/v1/admin"}}},
			{Host: "127.0.0.1", Grant: "broad", AllowInsecure: true, Source: SourceConfig{Type: "vendor", Secret: "broad"}, Match: &MatchConfig{Header: "X-Route", Paths: []string{"/v1"}}},
		}}
		if err := srv.loadCredentials(context.Background(), cfg); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		for _, pr := range srv.pendingRefreshes {
			srv.startPending(ctx, pr)
		}
		defer func() {
			cancel()
			srv.refreshWG.Wait()
		}()
		get := func(path string) (int, string) {
			req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:"+port+path, nil)
			req.Header.Set("X-Route", "x")
			rec := httptest.NewRecorder()
			srv.proxy.ServeHTTP(rec, req)
			auth, _, _ := strings.Cut(rec.Body.String(), "|")
			return rec.Code, auth
		}
		if code, _ := get("/v1/admin/x"); code != http.StatusForbidden {
			t.Errorf("/v1/admin/x before recovery = %d, want 403", code)
		}
		narrow.err.Store(nil)
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if code, auth := get("/v1/admin/x"); code != http.StatusOK || auth != "Bearer vendor-token" {
			t.Errorf("/v1/admin/x after recovery = %d %q, want 200 with the narrow credential", code, auth)
		}
		if code, auth := get("/v1/other"); code != http.StatusOK || auth != "Bearer broad-token" {
			t.Errorf("/v1/other = %d %q, want 200 with the broad credential", code, auth)
		}
	})
}

func TestLoadCredentials_CanceledContextFailsEvenWhenEveryFetchSucceeds(t *testing.T) {
	srv := newBareServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := &Config{Credentials: []CredentialConfig{{Host: "api.example.com", Grant: "a", Source: SourceConfig{Type: "static", Value: "tok"}}}}
	if err := srv.loadCredentials(ctx, cfg); !errors.Is(err, context.Canceled) {
		t.Errorf("loadCredentials with a canceled context = %v, want context.Canceled", err)
	}
}
