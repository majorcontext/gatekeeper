package credentialsource

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const metadataTokenPath = "/computeMetadata/v1/instance/service-accounts/default/token"

// metadataToken is one response from the fake metadata token endpoint.
type metadataToken struct {
	value     string
	expiresIn int
}

// fakeMetadataServer serves the GCE metadata token endpoint and points
// Application Default Credentials at it. GCE_METADATA_HOST makes the
// metadata client report that it runs on GCE without a probe; an empty
// HOME and GOOGLE_APPLICATION_CREDENTIALS keep ADC from finding a
// credentials file first. Each request gets the next token in tokens, and
// the last token repeats. The returned function lists the scopes query
// parameter of each request.
func fakeMetadataServer(t *testing.T, tokens ...metadataToken) (requestScopes func() []string) {
	t.Helper()
	var (
		mu     sync.Mutex
		scopes []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != metadataTokenPath || r.Header.Get("Metadata-Flavor") != "Google" {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		scopes = append(scopes, r.URL.Query().Get("scopes"))
		tok := tokens[min(len(scopes), len(tokens))-1]
		mu.Unlock()
		w.Header().Set("Metadata-Flavor", "Google")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": tok.value,
			"expires_in":   tok.expiresIn,
			"token_type":   "Bearer",
		})
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	t.Setenv("GCE_METADATA_HOST", u.Host)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("HOME", t.TempDir())
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), scopes...)
	}
}

func TestGCPDefaultCredentialsSource_MetadataTokenWithScopes(t *testing.T) {
	requestScopes := fakeMetadataServer(t, metadataToken{"ya29.adc", 3600})

	src := NewGCPDefaultCredentialsSource("https://www.googleapis.com/auth/devstorage.read_write https://www.googleapis.com/auth/pubsub", "")
	if src.Type() != "gcp-service-account" {
		t.Errorf("Type() = %q, want gcp-service-account", src.Type())
	}
	if ttl := src.TTL(); ttl != 0 {
		t.Errorf("TTL before Fetch = %v, want 0", ttl)
	}

	token, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if token != "ya29.adc" {
		t.Errorf("token = %q, want ya29.adc", token)
	}
	want := "https://www.googleapis.com/auth/devstorage.read_write,https://www.googleapis.com/auth/pubsub"
	if got := requestScopes(); len(got) != 1 || got[0] != want {
		t.Errorf("metadata token requests asked for scopes %q, want [%q]", got, want)
	}
	if ttl := src.TTL(); ttl < 59*time.Minute || ttl > time.Hour {
		t.Errorf("TTL = %v, want ~1h", ttl)
	}
}

func TestGCPDefaultCredentialsSource_DefaultScope(t *testing.T) {
	requestScopes := fakeMetadataServer(t, metadataToken{"ya29.adc", 3600})

	if _, err := NewGCPDefaultCredentialsSource("", "").Fetch(context.Background()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got := requestScopes(); len(got) != 1 || got[0] != gcpDefaultScope {
		t.Errorf("metadata token requests asked for scopes %q, want [%q]", got, gcpDefaultScope)
	}
}

// TestGCPDefaultCredentialsSource_RefreshesNearExpiry shows that a Fetch
// after the token nears expiry returns a new token and a new TTL, so the
// gatekeeper refresh loop, which fetches at 75% of TTL, swaps in fresh
// tokens.
func TestGCPDefaultCredentialsSource_RefreshesNearExpiry(t *testing.T) {
	requestScopes := fakeMetadataServer(t,
		metadataToken{"ya29.first", 120},
		metadataToken{"ya29.second", 3600},
	)
	src := NewGCPDefaultCredentialsSource("https://www.googleapis.com/auth/pubsub", "")

	first, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("first Fetch: %v", err)
	}
	if ttl := src.TTL(); first != "ya29.first" || ttl > 2*time.Minute || ttl < time.Minute {
		t.Fatalf("first Fetch = %q with TTL %v, want ya29.first with TTL ~2m", first, ttl)
	}

	second, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("second Fetch: %v", err)
	}
	if ttl := src.TTL(); second != "ya29.second" || ttl < 59*time.Minute {
		t.Errorf("second Fetch = %q with TTL %v, want ya29.second with TTL ~1h", second, ttl)
	}
	if got := requestScopes(); len(got) != 2 || got[1] != "https://www.googleapis.com/auth/pubsub" {
		t.Errorf("metadata token requests asked for scopes %q, want two requests for pubsub", got)
	}
}

func TestGCPDefaultCredentialsSource_MetadataError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	t.Setenv("GCE_METADATA_HOST", u.Host)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("HOME", t.TempDir())

	src := NewGCPDefaultCredentialsSource("", "")
	if _, err := src.Fetch(context.Background()); err == nil {
		t.Fatal("Fetch with a metadata server that answers 404 = nil error, want an error")
	}
	if ttl := src.TTL(); ttl != 0 {
		t.Errorf("TTL after a failed Fetch = %v, want 0", ttl)
	}
}

func TestGCPDefaultCredentialsSource_StartupRetryWindow(t *testing.T) {
	if w := NewGCPDefaultCredentialsSource("", "").StartupRetryWindow(); w <= 0 {
		t.Errorf("StartupRetryWindow() = %v, want a positive window", w)
	}
}

// fakeIAMCredentials serves the IAM Credentials generateAccessToken method.
// Each call returns the next token in tokens; the last repeats.
type fakeIAMCredentials struct {
	t      *testing.T
	status int
	tokens []string

	mu   sync.Mutex
	reqs []iamRequest
}

type iamRequest struct {
	path          string
	authorization string
	scope         []string
	lifetime      string
}

func (f *fakeIAMCredentials) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Scope    []string `json:"scope"`
		Lifetime string   `json:"lifetime"`
	}
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.reqs = append(f.reqs, iamRequest{
		path:          r.URL.EscapedPath(),
		authorization: r.Header.Get("Authorization"),
		scope:         body.Scope,
		lifetime:      body.Lifetime,
	})
	n := len(f.reqs)
	f.mu.Unlock()
	if f.status != 0 {
		http.Error(w, `{"error":{"code":403,"message":"Permission 'iam.serviceAccounts.getAccessToken' denied"}}`, f.status)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{
		"accessToken": f.tokens[min(n, len(f.tokens))-1],
		"expireTime":  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
}

func (f *fakeIAMCredentials) requests() []iamRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]iamRequest(nil), f.reqs...)
}

func TestGCPDefaultCredentialsSource_Impersonation(t *testing.T) {
	requestScopes := fakeMetadataServer(t, metadataToken{"ya29.base", 3600})
	iam := &fakeIAMCredentials{t: t, tokens: []string{"ya29.impersonated-1", "ya29.impersonated-2"}}
	iamSrv := httptest.NewServer(iam)
	t.Cleanup(iamSrv.Close)

	src := NewGCPDefaultCredentialsSource("https://www.googleapis.com/auth/devstorage.read_write https://www.googleapis.com/auth/pubsub", "uploader@my-project.iam.gserviceaccount.com")
	src.iamURL = iamSrv.URL

	for i, want := range []string{"ya29.impersonated-1", "ya29.impersonated-2"} {
		token, err := src.Fetch(context.Background())
		if err != nil {
			t.Fatalf("Fetch %d: %v", i+1, err)
		}
		if token != want {
			t.Errorf("Fetch %d = %q, want %q", i+1, token, want)
		}
		if ttl := src.TTL(); ttl < 59*time.Minute || ttl > time.Hour {
			t.Errorf("TTL after Fetch %d = %v, want ~1h", i+1, ttl)
		}
	}

	reqs := iam.requests()
	if len(reqs) != 2 {
		t.Fatalf("generateAccessToken calls = %d, want 2 (one per Fetch)", len(reqs))
	}
	for _, r := range reqs {
		if want := "/v1/projects/-/serviceAccounts/uploader@my-project.iam.gserviceaccount.com:generateAccessToken"; r.path != want {
			t.Errorf("generateAccessToken path = %q, want %q", r.path, want)
		}
		if r.authorization != "Bearer ya29.base" {
			t.Errorf("generateAccessToken Authorization = %q, want the ADC token", r.authorization)
		}
		if want := []string{"https://www.googleapis.com/auth/devstorage.read_write", "https://www.googleapis.com/auth/pubsub"}; strings.Join(r.scope, " ") != strings.Join(want, " ") {
			t.Errorf("generateAccessToken scope = %q, want %q", r.scope, want)
		}
		if r.lifetime != "3600s" {
			t.Errorf("generateAccessToken lifetime = %q, want 3600s", r.lifetime)
		}
	}
	// The ADC token only calls the IAM Credentials API, so it carries the
	// cloud-platform scope, not the rule's scopes.
	if got := requestScopes(); len(got) == 0 || got[0] != gcpDefaultScope {
		t.Errorf("metadata token requests asked for scopes %q, want %q", got, gcpDefaultScope)
	}
}

func TestGCPDefaultCredentialsSource_ImpersonationDenied(t *testing.T) {
	fakeMetadataServer(t, metadataToken{"ya29.base", 3600})
	iamSrv := httptest.NewServer(&fakeIAMCredentials{t: t, status: http.StatusForbidden})
	t.Cleanup(iamSrv.Close)

	src := NewGCPDefaultCredentialsSource("", "uploader@my-project.iam.gserviceaccount.com")
	src.iamURL = iamSrv.URL

	_, err := src.Fetch(context.Background())
	if err == nil {
		t.Fatal("Fetch with a 403 from generateAccessToken = nil error, want an error")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error = %q, want it to name the 403", err)
	}
	if strings.Contains(err.Error(), "ya29.base") {
		t.Errorf("error = %q contains the ADC token", err)
	}
}
