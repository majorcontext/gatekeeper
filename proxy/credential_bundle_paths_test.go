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
	return withRunContext(req, &RunContextData{CredentialBundles: bundles})
}

func withRunContext(req *http.Request, rc *RunContextData) *http.Request {
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

// A scope mismatch must stay visible even though it no longer blocks: it means
// a bundle's scope disagrees with where its client actually goes, and without a
// record that is invisible rather than merely non-fatal.
func TestHandleHTTP_SkippedBundleIsRecorded(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	bundle := codexTestBundle()
	bundle.Scope = CredentialScope{Origins: []string{backend.URL}, Methods: []string{"POST"}, PathPrefixes: []string{"/backend-api/codex"}}

	p := NewProxy()
	var policy []PolicyLogData
	p.SetPolicyLogger(func(d PolicyLogData) { policy = append(policy, d) })

	req := httptest.NewRequest("POST", backend.URL+"/elsewhere", nil)
	req.Header.Set("Authorization", "Bearer fake-access")
	req.Header.Set("ChatGPT-Account-ID", "fake-account")
	p.handleHTTP(httptest.NewRecorder(), withBundleContext(req, bundle))

	if len(policy) != 1 || policy[0].Scope != "credential-bundle" || policy[0].Message == "" {
		t.Fatalf("policy log = %+v, want one credential-bundle entry with a reason", policy)
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
	t.Run("out of scope receives no credential", func(t *testing.T) {
		gotAuth, gotAccount = "", ""
		bundle := codexTestBundle()
		bundle.Scope = CredentialScope{
			Origins:      []string{backend.URL},
			Methods:      []string{"POST"},
			PathPrefixes: []string{"/backend-api/codex"},
		}
		p, _, _ := newRelay(t, bundle.Scope)

		req := httptest.NewRequest("POST", "/relay/codex/backend-api/other", nil)
		req.Header.Set("Authorization", "Bearer fake-access")
		req.Header.Set("ChatGPT-Account-ID", "fake-account")
		rec := httptest.NewRecorder()
		p.handleRelay(rec, withBundleContext(req, bundle))

		if rec.Code == http.StatusForbidden {
			t.Fatalf("out-of-scope relay request was blocked: %q", rec.Body.String())
		}
		// Forwarded, but carrying the client's own placeholders — never the bundle.
		if gotAuth != "Bearer fake-access" || gotAccount != "fake-account" {
			t.Fatalf("bundle leaked off-scope: auth=%q account=%q", gotAuth, gotAccount)
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

	// An adjacent path must not receive the credential. It is still forwarded —
	// the boundary is what gets injected, not what gets through.
	t.Run("adjacent path receives no credential", func(t *testing.T) {
		gotAuth, gotAccount = "", ""
		resp := post(t, "/backend-api/codexevil/responses")
		if resp.StatusCode == http.StatusForbidden {
			t.Fatal("status = 403, want the request forwarded without injection")
		}
		if gotAuth != "Bearer fake-access" || gotAccount != "fake-account" {
			t.Fatalf("bundle leaked to an adjacent path: auth=%q account=%q", gotAuth, gotAccount)
		}
	})
}

// A bundle is atomic and narrowly scoped. An ordinary host-wide credential on
// one of its header names must not overwrite it: the request would go upstream
// with one half of the bundle and one half of something else, and the log would
// report both grants as injected when only the last one survived.
func TestHandleHTTP_BundleHeaderSurvivesCollidingHostCredential(t *testing.T) {
	var gotAuth, gotAccount string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAccount = r.Header.Get("ChatGPT-Account-ID")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	bundle := codexTestBundle()
	bundle.Scope = CredentialScope{
		Origins:      []string{backend.URL},
		Methods:      []string{"POST"},
		PathPrefixes: []string{"/backend-api/codex"},
	}
	host := mustParseURL(backend.URL).Hostname()

	p := NewProxy()
	mu, logged := collectLogs(p)

	req := httptest.NewRequest("POST", backend.URL+"/backend-api/codex/responses", nil)
	req.Header.Set("Authorization", "Bearer fake-access")
	req.Header.Set("ChatGPT-Account-ID", "fake-account")
	rec := httptest.NewRecorder()
	// The same host also carries an ordinary Authorization credential.
	p.handleHTTP(rec, withRunContext(req, &RunContextData{
		CredentialBundles: []CredentialBundle{bundle},
		Credentials: map[string][]credentialHeader{
			host: {{Name: "Authorization", Value: "Bearer host-wide-token", Grant: "other"}},
		},
	}))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%q)", rec.Code, rec.Body.String())
	}
	if gotAuth != "Bearer real-access" {
		t.Errorf("Authorization = %q, want the bundle's value — a host credential overwrote an atomic replacement", gotAuth)
	}
	if gotAccount != "real-account" {
		t.Errorf("ChatGPT-Account-ID = %q, want the bundle's value", gotAccount)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(*logged) != 1 {
		t.Fatalf("logged %d entries, want 1", len(*logged))
	}
	for _, g := range (*logged)[0].Grants {
		if g == "other" {
			t.Errorf("Grants = %v, want no 'other' — that credential never reached the wire", (*logged)[0].Grants)
		}
	}
}

// Companion: reserving the bundle's header must not disturb how the host's
// other credentials are chosen. The client asked for a credential (the bundle's
// placeholder), so the "client sent nothing, inject everything" fallback must
// stay off for the remaining headers.
func TestHandleHTTP_BundleDoesNotTriggerAutoInjectionOfOtherHeaders(t *testing.T) {
	var gotAPIKey string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAPIKey = r.Header.Get("X-Api-Key")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	bundle := codexTestBundle()
	bundle.Scope = CredentialScope{
		Origins:      []string{backend.URL},
		Methods:      []string{"POST"},
		PathPrefixes: []string{"/backend-api/codex"},
	}
	host := mustParseURL(backend.URL).Hostname()

	p := NewProxy()

	req := httptest.NewRequest("POST", backend.URL+"/backend-api/codex/responses", nil)
	req.Header.Set("Authorization", "Bearer fake-access")
	req.Header.Set("ChatGPT-Account-ID", "fake-account")
	rec := httptest.NewRecorder()
	p.handleHTTP(rec, withRunContext(req, &RunContextData{
		CredentialBundles: []CredentialBundle{bundle},
		Credentials: map[string][]credentialHeader{
			host: {
				{Name: "Authorization", Value: "Bearer host-wide-token", Grant: "other"},
				{Name: "X-Api-Key", Value: "host-api-key", Grant: "other"},
			},
		},
	}))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%q)", rec.Code, rec.Body.String())
	}
	if gotAPIKey != "" {
		t.Errorf("X-Api-Key = %q, want empty — the client sent a placeholder, so nothing should auto-inject", gotAPIKey)
	}
}

// The MCP relay resolves its target from the registered server list, not from a
// bundle's scope, so it must never inject one — that would apply a scope to a
// destination it was never written for. It records the near miss and forwards
// the request, which then fails upstream on its own merits.
func TestMCPRelay_RecordsButDoesNotInjectBundlePlaceholders(t *testing.T) {
	var reached atomic.Bool
	var gotAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	p := NewProxy()
	var policy []PolicyLogData
	p.SetPolicyLogger(func(d PolicyLogData) { policy = append(policy, d) })
	rc := &RunContextData{
		CredentialBundles: []CredentialBundle{codexTestBundle()},
		MCPServers:        []MCPServerConfig{{Name: "srv", URL: backend.URL}},
	}

	req := httptest.NewRequest("POST", "/mcp/srv", nil)
	req.Header.Set("Authorization", "Bearer fake-access")
	rec := httptest.NewRecorder()
	p.handleMCPRelay(rec, withRunContext(req, rc))

	if rec.Code == http.StatusForbidden {
		t.Fatalf("the MCP relay blocked a request carrying a placeholder: %q", rec.Body.String())
	}
	if !reached.Load() {
		t.Error("the MCP server was not contacted")
	}
	// The one thing that must never happen here: the real value reaching a
	// relay target, which no bundle scope describes.
	if strings.Contains(gotAuth, "real-access") {
		t.Fatalf("the real bundle value reached an MCP server: %q", gotAuth)
	}
	if len(policy) != 1 || policy[0].Operation != "mcp.request" {
		t.Fatalf("policy log = %+v, want one mcp.request entry", policy)
	}
}

// Companion: ordinary MCP traffic is untouched by the presence of a bundle, or
// the guard above would break every MCP server on a run that also uses one.
func TestMCPRelay_UnrelatedRequestIsUnaffectedByBundles(t *testing.T) {
	var reached atomic.Bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	p := NewProxy()
	rc := &RunContextData{
		CredentialBundles: []CredentialBundle{codexTestBundle()},
		MCPServers:        []MCPServerConfig{{Name: "srv", URL: backend.URL}},
	}

	req := httptest.NewRequest("POST", "/mcp/srv", nil)
	rec := httptest.NewRecorder()
	p.handleMCPRelay(rec, withRunContext(req, rc))

	if rec.Code == http.StatusForbidden {
		t.Fatalf("an MCP request carrying no placeholder was denied: %q", rec.Body.String())
	}
	if !reached.Load() {
		t.Error("the MCP server was not contacted")
	}
}

// A bundle grants a capability for an exact request shape. A request outside
// that shape must simply not receive it — not be blocked.
//
// Refusing looks protective and is not: the placeholder is synthetic, so
// forwarding it grants nothing and the upstream answers as it would for any
// bad credential. What refusing does do is convert every route the scope does
// not name into a hard client failure. Codex's own `codex_apps` connector hits
// `/backend-api/MCP` with the same placeholder; under a 403 it failed at
// startup with "credential bundle rejected", which reads as a proxy bug rather
// than as the absence of a credential it was never granted.
func TestOutOfScopeBundleRequestIsForwardedNotBlocked(t *testing.T) {
	var gotAuth, gotAccount, gotPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotAccount = r.Header.Get("ChatGPT-Account-ID")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	bundle := codexTestBundle()
	bundle.Scope = CredentialScope{
		Origins:      []string{backend.URL},
		Methods:      []string{"POST"},
		PathPrefixes: []string{"/backend-api/codex"},
	}

	p := NewProxy()
	var policy []PolicyLogData
	p.SetPolicyLogger(func(d PolicyLogData) { policy = append(policy, d) })

	// The route Codex's apps connector actually uses.
	req := httptest.NewRequest("POST", backend.URL+"/backend-api/MCP", nil)
	req.Header.Set("Authorization", "Bearer fake-access")
	req.Header.Set("ChatGPT-Account-ID", "fake-account")
	rec := httptest.NewRecorder()
	p.handleHTTP(rec, withBundleContext(req, bundle))

	if rec.Code == http.StatusForbidden {
		t.Fatalf("out-of-scope request was blocked: %q", rec.Body.String())
	}
	if gotPath != "/backend-api/MCP" {
		t.Fatalf("upstream never saw the request (path %q)", gotPath)
	}
	// Nothing from the bundle may be injected — that is the actual boundary.
	if gotAuth != "Bearer fake-access" || gotAccount != "fake-account" {
		t.Fatalf("bundle leaked off-scope: auth=%q account=%q", gotAuth, gotAccount)
	}
	// The near miss still has to be observable, or a mis-scoped bundle becomes
	// invisible instead of merely non-fatal.
	if len(policy) != 1 || policy[0].Scope != "credential-bundle" {
		t.Fatalf("policy log = %+v, want one credential-bundle entry", policy)
	}
}

// Companion: in-scope still injects, so the test above cannot pass on a proxy
// that has stopped applying bundles altogether.
func TestInScopeBundleStillInjectsAfterDegrade(t *testing.T) {
	var gotAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	bundle := codexTestBundle()
	bundle.Scope = CredentialScope{
		Origins:      []string{backend.URL},
		Methods:      []string{"POST"},
		PathPrefixes: []string{"/backend-api/codex"},
	}

	p := NewProxy()
	req := httptest.NewRequest("POST", backend.URL+"/backend-api/codex/responses", nil)
	req.Header.Set("Authorization", "Bearer fake-access")
	req.Header.Set("ChatGPT-Account-ID", "fake-account")
	rec := httptest.NewRecorder()
	p.handleHTTP(rec, withBundleContext(req, bundle))

	if gotAuth != "Bearer real-access" {
		t.Fatalf("in-scope Authorization = %q, want the real value", gotAuth)
	}
}

// A skipped bundle is not a denial and must not be reported as one.
//
// Every PolicyLogData reaching gatekeeper.go's sink is warned as "policy
// denial" and counted by RecordPolicyDenial. Before bundles degraded rather
// than blocked, that was sound — every caller was a real refusal. Routing a
// harmless out-of-scope forward through the same channel would page whoever
// alerts on the denial rate: the same "looks like a proxy fault" outcome this
// behavior exists to avoid, moved from the client to the operator.
func TestSkippedBundleIsNotReportedAsADenial(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	bundle := codexTestBundle()
	bundle.Scope = CredentialScope{Origins: []string{backend.URL}, Methods: []string{"POST"}, PathPrefixes: []string{"/backend-api/codex"}}

	p := NewProxy()
	var policy []PolicyLogData
	p.SetPolicyLogger(func(d PolicyLogData) { policy = append(policy, d) })

	req := httptest.NewRequest("POST", backend.URL+"/backend-api/MCP", nil)
	req.Header.Set("Authorization", "Bearer fake-access")
	req.Header.Set("ChatGPT-Account-ID", "fake-account")
	p.handleHTTP(httptest.NewRecorder(), withBundleContext(req, bundle))

	if len(policy) != 1 {
		t.Fatalf("policy log = %+v, want exactly one entry", policy)
	}
	if policy[0].Blocking {
		t.Error("a skipped bundle was reported as Blocking; it would be counted as a policy denial")
	}
}

// Companion: an actual refusal must still be Blocking, or the flag above
// could be satisfied by never marking anything as a denial again.
func TestNetworkPolicyDenialIsStillBlocking(t *testing.T) {
	p := NewProxy()
	var policy []PolicyLogData
	p.SetPolicyLogger(func(d PolicyLogData) { policy = append(policy, d) })

	req := httptest.NewRequest("GET", "http://blocked.example/x", nil)
	rec := httptest.NewRecorder()
	p.handleHTTP(rec, withRunContext(req, &RunContextData{Policy: "strict"}))

	if len(policy) == 0 {
		t.Fatal("a network-policy denial produced no policy log entry")
	}
	if !policy[0].Blocking {
		t.Errorf("network denial Blocking = false, want true: %+v", policy[0])
	}
}
