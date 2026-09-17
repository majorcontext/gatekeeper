package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func withBundleContext(req *http.Request, bundles ...CredentialBundle) *http.Request {
	rc := &RunContextData{CredentialBundles: bundles}
	return req.WithContext(context.WithValue(req.Context(), runContextKey, rc))
}

func collectLogs(p *Proxy) (*sync.Mutex, *[]RequestLogData) {
	var mu sync.Mutex
	var logged []RequestLogData
	p.SetLogger(func(d RequestLogData) {
		mu.Lock()
		defer mu.Unlock()
		logged = append(logged, d)
	})
	return &mu, &logged
}

// A denied bundle is the single most important thing in this feature to have a
// record of: reaching it means something tried to send a subscription
// placeholder somewhere it is not allowed to go. The CONNECT and relay paths
// log it; the plain-HTTP forward path dropped it silently, so a denial over
// http:// left no trace in the request log at all.
func TestHandleHTTP_DeniedBundleIsLogged(t *testing.T) {
	p := NewProxy()
	mu, logged := collectLogs(p)

	// Plain HTTP against a bundle that requires TLS: the placeholder makes the
	// request a candidate, and the scope check then fails closed.
	req := httptest.NewRequest("POST", "http://chatgpt.com/backend-api/codex/responses", nil)
	req.Header.Set("Authorization", "Bearer fake-access")
	req.Header.Set("ChatGPT-Account-ID", "fake-account")
	rec := httptest.NewRecorder()
	p.handleHTTP(rec, withBundleContext(req, codexTestBundle()))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(*logged) != 1 {
		t.Fatalf("logged %d entries, want exactly 1 — a denied credential bundle must be recorded", len(*logged))
	}
	entry := (*logged)[0]
	if !entry.Denied {
		t.Error("Denied = false, want true — this is a policy decision, not a client error")
	}
	if entry.DenyReason == "" {
		t.Error("DenyReason is empty, want the bundle mismatch reason")
	}
	if entry.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want 403", entry.StatusCode)
	}
	if entry.Host != "chatgpt.com" {
		t.Errorf("Host = %q, want chatgpt.com", entry.Host)
	}
	// The log must retain what the client sent, never the real credential.
	for name, values := range entry.RequestHeaders {
		for _, v := range values {
			if strings.Contains(v, "real-access") || strings.Contains(v, "real-account") {
				t.Errorf("log leaked a real credential in %s: %q", name, v)
			}
		}
	}
}

// Companion: an allowed bundle is injected and forwarded, and the log records
// the request without the real values. Without this the test above would pass
// on a proxy that denied everything.
func TestHandleHTTP_AllowedBundleIsInjectedAndLogged(t *testing.T) {
	var gotAuth, gotAccount string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAccount = r.Header.Get("ChatGPT-Account-ID")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	bundle := codexTestBundle()
	// Point the scope at the test backend so the request is actually forwarded.
	bundle.Scope.RequireTLS = false
	bundle.Scope.Origins = []string{backend.URL}

	p := NewProxy()
	mu, logged := collectLogs(p)

	req := httptest.NewRequest("POST", backend.URL+"/backend-api/codex/responses", nil)
	req.Header.Set("Authorization", "Bearer fake-access")
	req.Header.Set("ChatGPT-Account-ID", "fake-account")
	rec := httptest.NewRecorder()
	p.handleHTTP(rec, withBundleContext(req, bundle))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if gotAuth != "Bearer real-access" || gotAccount != "real-account" {
		t.Fatalf("upstream got auth=%q account=%q, want the real pair", gotAuth, gotAccount)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(*logged) != 1 {
		t.Fatalf("logged %d entries, want exactly 1", len(*logged))
	}
	if (*logged)[0].Denied {
		t.Error("Denied = true on an allowed request")
	}
	for name, values := range (*logged)[0].RequestHeaders {
		for _, v := range values {
			if strings.Contains(v, "real-access") || strings.Contains(v, "real-account") {
				t.Errorf("log leaked a real credential in %s: %q", name, v)
			}
		}
	}
}

// A request carrying no placeholder must be untouched by the bundle machinery,
// whatever else is configured — otherwise ordinary traffic to the same host
// starts getting 403s.
func TestHandleHTTP_UnrelatedRequestIsUnaffectedByBundles(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	p := NewProxy()
	req := httptest.NewRequest("GET", backend.URL+"/健/other", nil)
	rec := httptest.NewRecorder()
	p.handleHTTP(rec, withBundleContext(req, codexTestBundle()))

	if rec.Code == http.StatusForbidden {
		t.Fatalf("a request with no bundle placeholder was denied: %q", rec.Body.String())
	}
}

// Grants feed the request log. A bundle and a static credential that both fire
// for one host must not produce the same grant twice.
func TestMergeCredentialInjectionResults_DeduplicatesGrants(t *testing.T) {
	a := credentialInjectionResult{
		InjectedHeaders: map[string]bool{"authorization": true},
		Grants:          []string{"codex"},
	}
	b := credentialInjectionResult{
		InjectedHeaders: map[string]bool{"x-api-key": true},
		Grants:          []string{"codex", "other"},
	}
	got := mergeCredentialInjectionResults(a, b)
	seen := map[string]int{}
	for _, g := range got.Grants {
		seen[g]++
	}
	if seen["codex"] != 1 {
		t.Errorf("Grants = %v, want codex exactly once", got.Grants)
	}
	if seen["other"] != 1 {
		t.Errorf("Grants = %v, want other preserved", got.Grants)
	}
}

// The relay path forwards on behalf of a caller that cannot use CONNECT, and
// injects credentials exactly as the other paths do. A scoped bundle has to
// apply there too, or a relay becomes a way around the scope.
func TestRelay_CredentialBundleIsScoped(t *testing.T) {
	var gotAuth, gotAccount string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAccount = r.Header.Get("ChatGPT-Account-ID")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	newRelay := func(t *testing.T, scope CredentialScope) (*Proxy, *sync.Mutex, *[]RequestLogData) {
		t.Helper()
		p := NewProxy()
		if err := p.AddRelay("codex", backend.URL); err != nil {
			t.Fatalf("AddRelay: %v", err)
		}
		mu, logged := collectLogs(p)
		return p, mu, logged
	}

	t.Run("in scope injects the real pair", func(t *testing.T) {
		bundle := codexTestBundle()
		bundle.Scope = CredentialScope{
			Origins:      []string{backend.URL},
			Methods:      []string{"POST"},
			PathPrefixes: []string{"/backend-api/codex"},
		}
		p, _, _ := newRelay(t, bundle.Scope)

		req := httptest.NewRequest("POST", "/relay/codex/backend-api/codex/responses", nil)
		req.Header.Set("Authorization", "Bearer fake-access")
		req.Header.Set("ChatGPT-Account-ID", "fake-account")
		rec := httptest.NewRecorder()
		p.handleRelay(rec, withBundleContext(req, bundle))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (%q)", rec.Code, rec.Body.String())
		}
		if gotAuth != "Bearer real-access" || gotAccount != "real-account" {
			t.Fatalf("upstream got auth=%q account=%q, want the real pair", gotAuth, gotAccount)
		}
	})

	// Companion: the same relay, the same placeholders, a path the bundle does
	// not cover. Nothing may be injected, and the denial must be logged.
	t.Run("out of scope is denied and logged", func(t *testing.T) {
		gotAuth, gotAccount = "", ""
		bundle := codexTestBundle()
		bundle.Scope = CredentialScope{
			Origins:      []string{backend.URL},
			Methods:      []string{"POST"},
			PathPrefixes: []string{"/backend-api/codex"},
		}
		p, mu, logged := newRelay(t, bundle.Scope)

		req := httptest.NewRequest("POST", "/relay/codex/backend-api/other", nil)
		req.Header.Set("Authorization", "Bearer fake-access")
		req.Header.Set("ChatGPT-Account-ID", "fake-account")
		rec := httptest.NewRecorder()
		p.handleRelay(rec, withBundleContext(req, bundle))

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
		if gotAuth != "" || gotAccount != "" {
			t.Fatalf("upstream was reached with auth=%q account=%q; nothing should have been forwarded", gotAuth, gotAccount)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(*logged) != 1 || !(*logged)[0].Denied {
			t.Fatalf("logged %+v, want one entry marked denied", *logged)
		}
	})
}

// The TLS-interception path is how moat's containers actually reach ChatGPT.
// It applies bundles before ReverseProxy so a mismatch never reaches upstream,
// which is different plumbing from the other two paths and needs its own test.
func TestIntercept_CredentialBundleIsScoped(t *testing.T) {
	var gotAuth, gotAccount string
	var reached atomic.Bool
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
		gotAuth = r.Header.Get("Authorization")
		gotAccount = r.Header.Get("ChatGPT-Account-ID")
		_, _ = w.Write([]byte("ok"))
	}))

	bundle := codexTestBundle()
	bundle.Scope = CredentialScope{
		RequireTLS:   true,
		Origins:      []string{"https://" + mustParseURL(setup.Backend.URL).Host},
		Methods:      []string{"POST"},
		PathPrefixes: []string{"/backend-api/codex"},
	}
	setup.Proxy.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token != "bundletest" {
			return nil, false
		}
		return &RunContextData{Policy: "permissive", CredentialBundles: []CredentialBundle{bundle}}, true
	})
	// A context resolver turns on proxy auth, so the tunnel needs the run token.
	setup.Client.Transport.(*http.Transport).ProxyConnectHeader = http.Header{
		"Proxy-Authorization": {"Basic " + basicAuth("moat", "bundletest")},
	}

	post := func(t *testing.T, path string) *http.Response {
		t.Helper()
		req, err := http.NewRequest("POST", setup.Backend.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer fake-access")
		req.Header.Set("ChatGPT-Account-ID", "fake-account")
		resp, err := setup.Client.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp
	}

	t.Run("in scope injects the real pair", func(t *testing.T) {
		resp := post(t, "/backend-api/codex/responses")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		if gotAuth != "Bearer real-access" || gotAccount != "real-account" {
			t.Fatalf("upstream got auth=%q account=%q, want the real pair", gotAuth, gotAccount)
		}
	})

	t.Run("adjacent path is denied before reaching upstream", func(t *testing.T) {
		reached.Store(false)
		resp := post(t, "/backend-api/codexevil/responses")
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
		if resp.Header.Get("X-Moat-Blocked") != "credential-bundle" {
			t.Errorf("X-Moat-Blocked = %q, want credential-bundle", resp.Header.Get("X-Moat-Blocked"))
		}
		if reached.Load() {
			t.Error("upstream was contacted for a denied request")
		}
	})
}
