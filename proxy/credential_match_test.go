package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
)

type matchRow struct {
	name       string
	only       string   // restrict to one path: "relay"
	apiLead    bool     // register the api resolver first, with no path restriction
	static     bool     // static x-api-key credential on the host
	staticAuth bool     // static Authorization credential on the host
	apiMode    string   // api resolver behavior: "" credential, "nil" returns nil, "decline", "explicit"
	relayBase  string   // base path on the relay target URL
	apiPaths   []string // overrides the api rule's paths
	method     string
	path       string
	headers    map[string]string

	wantAuth   string
	wantAPIKey string
}

func matchRows() []matchRow {
	return []matchRow{
		{
			name: "subscription_by_authorization", method: "POST", path: "/v1/messages",
			headers:  map[string]string{"Authorization": "Bearer placeholder"},
			wantAuth: "Bearer sub",
		},
		{
			name: "api_by_x_api_key_selecting_header_stripped", method: "POST", path: "/v1/messages",
			headers:  map[string]string{"x-api-key": "placeholder"},
			wantAuth: "Bearer api",
		},
		{
			name: "admin_get_on_organizations", method: "GET", path: "/v1/organizations/usage_report/messages",
			headers:  map[string]string{"x-api-key": "p"},
			wantAuth: "Bearer admin",
		},
		{
			name: "admin_post_matches_nothing", static: true, method: "POST", path: "/v1/organizations/x",
			headers:    map[string]string{"x-api-key": "p"},
			wantAPIKey: "static-key",
		},
		{
			name: "first_match_wins_in_registration_order", apiLead: true, method: "GET", path: "/v1/organizations/usage_report/messages",
			headers:  map[string]string{"x-api-key": "p"},
			wantAuth: "Bearer api",
		},
		{
			name: "relay_matches_target_path", only: "relay", method: "POST", path: "/v1/messages",
			headers:  map[string]string{"x-api-key": "p"},
			wantAuth: "Bearer api",
		},
		{
			name: "resolver_returns_nothing_strips_selecting_header", apiMode: "nil", method: "POST", path: "/v1/messages",
			headers: map[string]string{"x-api-key": "placeholder"},
		},
		{
			name: "relay_matches_full_upstream_path", only: "relay", relayBase: "/api", apiPaths: []string{"/api/v1/messages"}, method: "POST", path: "/v1/messages",
			headers:  map[string]string{"x-api-key": "p"},
			wantAuth: "Bearer api",
		},
		{
			name: "relay_root_path_matches_slash", only: "relay", apiPaths: []string{"/"}, method: "POST", path: "",
			headers:  map[string]string{"x-api-key": "p"},
			wantAuth: "Bearer api",
		},
		{
			name: "selecting_header_does_not_request_same_name_static", static: true, method: "POST", path: "/v1/messages",
			headers:  map[string]string{"x-api-key": "placeholder"},
			wantAuth: "Bearer api",
		},
		{
			name: "decline_falls_back_to_same_name_static", apiMode: "decline", static: true, method: "POST", path: "/v1/messages",
			headers:    map[string]string{"x-api-key": "placeholder"},
			wantAPIKey: "static-key",
		},
		{
			name: "explicit_only_decline_falls_back_to_same_name_static", apiMode: "explicit", static: true, method: "POST", path: "/v1/messages",
			headers:    map[string]string{"x-api-key": "placeholder"},
			wantAPIKey: "static-key",
		},
		{
			name: "decline_strips_selecting_header", apiMode: "decline", staticAuth: true, method: "POST", path: "/v1/messages",
			headers:  map[string]string{"x-api-key": "placeholder"},
			wantAuth: "Bearer static",
		},
	}
}

func matchProxy(row matchRow, host string) *Proxy {
	p := NewProxy()
	if row.static {
		p.SetInsecureCredentialWithGrant(host, "x-api-key", "static-key", "anthropic")
	}
	if row.staticAuth {
		p.SetInsecureCredentialWithGrant(host, "Authorization", "Bearer static", "bot")
	}
	tagged := func(tag string) CredentialResolver {
		return func(context.Context, *http.Request, *http.Request, string) ([]CredentialHeader, error) {
			if tag == "api" && row.apiMode == "nil" {
				return nil, nil
			}
			if tag == "api" && row.apiMode == "explicit" {
				return nil, &ResolverDeclined{ExplicitOnly: true}
			}
			if tag == "api" && row.apiMode == "decline" {
				return nil, &ResolverDeclined{}
			}
			return []CredentialHeader{{Name: "Authorization", Value: "Bearer " + tag, AllowInsecure: true}}, nil
		}
	}
	admin := RequestMatch{Header: "x-api-key", Paths: []string{"/v1/organizations/"}, Methods: []string{"GET"}}
	api := RequestMatch{Header: "x-api-key", Paths: []string{"/v1/messages"}}
	if row.apiPaths != nil {
		api.Paths = row.apiPaths
	}
	if row.apiLead {
		api.Paths = nil
		p.SetMatchedCredentialResolver(host, api, tagged("api"))
		p.SetMatchedCredentialResolver(host, admin, tagged("admin"))
	} else {
		p.SetMatchedCredentialResolver(host, admin, tagged("admin"))
		p.SetMatchedCredentialResolver(host, api, tagged("api"))
	}
	p.SetMatchedCredentialResolver(host, RequestMatch{Header: "Authorization"}, tagged("sub"))
	return p
}

func TestRunContextCredentialResolverIsInvoked(t *testing.T) {
	for _, tt := range []struct {
		name  string
		match *RequestMatch
	}{
		{name: "unmatched credential"},
		{name: "matched credential", match: &RequestMatch{Header: "x-select"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := NewProxy()
			called := false
			credential := CredentialHeader{
				Name: "Authorization", Grant: "runtime", Match: tt.match, AllowInsecure: true,
				Resolver: func(context.Context, *http.Request, *http.Request, string) ([]CredentialHeader, error) {
					called = true
					return []CredentialHeader{{Name: "Authorization", Value: "Bearer runtime", Grant: "runtime", AllowInsecure: true}}, nil
				},
			}
			req := httptest.NewRequest("POST", "http://api.example.com/v1/messages", nil)
			if tt.match != nil {
				req.Header.Set("x-select", "yes")
			}
			req = withRunContext(req, &RunContextData{Credentials: map[string][]CredentialHeader{"api.example.com": {credential}}})
			resolved, err := p.getCredentialsForRequest(req, req, "api.example.com", "/v1/messages")
			if err != nil {
				t.Fatal(err)
			}
			if !called || len(resolved.creds) != 1 || resolved.creds[0].Value != "Bearer runtime" {
				t.Fatalf("resolver called=%t credentials=%+v", called, resolved.creds)
			}
		})
	}
}

func TestRunContextCredentialResolverErrorFailsClosed(t *testing.T) {
	p := NewProxy()
	credential := CredentialHeader{
		Name: "Authorization", Match: &RequestMatch{Header: "x-select"},
		Resolver: func(context.Context, *http.Request, *http.Request, string) ([]CredentialHeader, error) {
			return nil, errors.New("source unavailable")
		},
	}
	req := httptest.NewRequest("POST", "http://api.example.com/v1/messages", nil)
	req.Header.Set("x-select", "yes")
	req = withRunContext(req, &RunContextData{Credentials: map[string][]CredentialHeader{
		"api.example.com": {credential, {Name: "x-api-key", Value: "static", Grant: "legacy"}},
	}})
	_, err := p.getCredentialsForRequest(req, req, "api.example.com", "/v1/messages")
	if err == nil || err.Error() != "source unavailable" {
		t.Fatalf("error = %v, want selected resolver error", err)
	}
}

func TestRunContextDataUsesCredentialMatchAndTransforms(t *testing.T) {
	p := NewProxy()
	ctx := context.WithValue(context.Background(), runContextKey, &RunContextData{Credentials: map[string][]CredentialHeader{
		"api.example.com": {
			{Name: "Authorization", Value: "Bearer first", Match: &RequestMatch{Header: "x-api-key", Paths: []string{"/v1"}}, SetHeaders: map[string]string{"anthropic-beta": "oauth-2025-04-20"}, RemoveHeaders: []string{"x-client"}},
			{Name: "Authorization", Value: "Bearer second", Match: &RequestMatch{Header: "x-api-key"}},
		},
	}})
	req := httptest.NewRequest("POST", "http://api.example.com/v1/messages", nil).WithContext(ctx)
	req.Header.Set("x-api-key", "placeholder")
	req.Header.Set("x-client", "remove")
	resolved, err := p.getCredentialsForRequest(req, req, "api.example.com", "/v1/messages")
	if err != nil {
		t.Fatal(err)
	}
	out := req.Clone(req.Context())
	p.prepareOutbound(req, out, outboundPrep{creds: resolved.creds, host: "api.example.com", lookupHost: "api.example.com", path: "/v1/messages"})
	if got := out.Header.Get("Authorization"); got != "Bearer first" {
		t.Errorf("Authorization = %q, want first matched credential", got)
	}
	if out.Header.Get("x-api-key") != "" || out.Header.Get("x-client") != "" {
		t.Errorf("request headers after transform = %v", out.Header)
	}
	if got := out.Header.Get("anthropic-beta"); got != "oauth-2025-04-20" {
		t.Errorf("set header = %q, want configured value", got)
	}
}

func TestSetCredentialEntryRejectsInvalidTransformHeader(t *testing.T) {
	p := NewProxy()
	err := p.SetCredentialEntry(Credential{Host: "api.example.com", Header: "Authorization", Value: "Bearer test", SetHeaders: map[string]string{"X Bad": "value"}})
	if err == nil || !strings.Contains(err.Error(), "set_headers") {
		t.Fatalf("error = %v, want set_headers validation", err)
	}
}

func TestCredentialResolverPolicyDoesNotMutateResolverResults(t *testing.T) {
	shared := []CredentialHeader{{Name: "resolver-header", Value: "Bearer value", Grant: "resolver"}}
	policy := CredentialHeader{
		Name: "Authorization", Grant: "policy", Match: &RequestMatch{Header: "x-select"},
		SetHeaders: map[string]string{"anthropic-beta": "oauth-2025-04-20"},
	}
	resolve := credentialResolverWithPolicy(policy, func(context.Context, *http.Request, *http.Request, string) ([]CredentialHeader, error) {
		return shared, nil
	})
	resolved, err := resolve(context.Background(), nil, nil, "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if shared[0].Name != "resolver-header" || shared[0].Grant != "resolver" || shared[0].Match != nil || shared[0].SetHeaders != nil {
		t.Fatalf("resolver-owned result changed: %+v", shared[0])
	}
	if resolved[0].Name != "Authorization" || resolved[0].Grant != "policy" || resolved[0].Match != policy.Match || resolved[0].SetHeaders["anthropic-beta"] == "" {
		t.Fatalf("credential policy not applied: %+v", resolved[0])
	}
}

func TestCredentialResolverEntryAppliesCredentialPolicy(t *testing.T) {
	p := NewProxy()
	policy := CredentialHeader{
		Host: "api.example.com", Header: "Authorization", Name: "Authorization", Grant: "workload",
		Match:         &RequestMatch{Header: "x-api-key", Paths: []string{"/v1/messages"}},
		SetHeaders:    map[string]string{"anthropic-beta": "oauth-2025-04-20"},
		RemoveHeaders: []string{"x-client"}, AllowInsecure: true,
		Resolver: func(context.Context, *http.Request, *http.Request, string) ([]CredentialHeader, error) {
			return []CredentialHeader{{Value: "Bearer dynamic"}}, nil
		},
	}
	if err := p.SetCredentialResolverEntry(policy); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "http://api.example.com/v1/messages", nil)
	req.Header.Set("x-api-key", "selector")
	req.Header.Set("x-client", "remove")
	resolved, err := p.getCredentialsForRequest(req, req, "api.example.com", "/v1/messages")
	if err != nil {
		t.Fatal(err)
	}
	out := req.Clone(req.Context())
	result := p.prepareOutbound(req, out, outboundPrep{creds: resolved.creds, host: "api.example.com", lookupHost: "api.example.com", path: "/v1/messages"})
	if got := out.Header.Get("Authorization"); got != "Bearer dynamic" {
		t.Errorf("Authorization = %q, want resolver value", got)
	}
	if out.Header.Get("x-api-key") != "" || out.Header.Get("x-client") != "" {
		t.Errorf("request headers after transform = %v", out.Header)
	}
	if got := out.Header.Get("anthropic-beta"); got != "oauth-2025-04-20" {
		t.Errorf("set header = %q, want configured value", got)
	}
	if !slices.Contains(result.Grants, "workload") {
		t.Errorf("grants = %v, want workload", result.Grants)
	}
}

func TestMatchedCredentialEntryRefreshReplacesInPlace(t *testing.T) {
	p := NewProxy()
	policy := CredentialHeader{Host: "api.example.com", Name: "Authorization", Value: "Bearer old", Grant: "workload", Match: &RequestMatch{Header: "x-api-key"}}
	if err := p.SetCredentialEntry(policy); err != nil {
		t.Fatal(err)
	}
	p.SetMatchedCredentialResolver("api.example.com", *policy.Match, func(context.Context, *http.Request, *http.Request, string) ([]CredentialHeader, error) {
		return []CredentialHeader{{Name: "Authorization", Value: "Bearer later"}}, nil
	})
	policy.Value = "Bearer refreshed"
	if err := p.SetCredentialEntry(policy); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "http://api.example.com/v1/messages", nil)
	req.Header.Set("x-api-key", "selector")
	resolved, err := p.getCredentialsForRequest(req, req, "api.example.com", "/v1/messages")
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved.creds) != 1 || resolved.creds[0].Value != "Bearer refreshed" {
		t.Fatalf("selected credentials = %+v, want refreshed first entry", resolved.creds)
	}
}

func TestMatchedCredentialEntryPrecedesLaterResolver(t *testing.T) {
	p := NewProxy()
	match := &RequestMatch{Header: "x-api-key", Paths: []string{"/v1/"}, Methods: []string{"POST"}}
	if err := p.SetCredentialEntry(CredentialHeader{
		Host: "api.example.com", Name: "Authorization", Value: "Bearer first", Match: match,
		SetHeaders:    map[string]string{"anthropic-beta": "oauth-2025-04-20"},
		RemoveHeaders: []string{"x-client"},
	}); err != nil {
		t.Fatal(err)
	}
	p.SetMatchedCredentialResolver("api.example.com", *match, func(context.Context, *http.Request, *http.Request, string) ([]CredentialHeader, error) {
		return []CredentialHeader{{Name: "Authorization", Value: "Bearer second"}}, nil
	})
	req := httptest.NewRequest("POST", "http://api.example.com/v1/messages", nil)
	req.Header.Set("x-api-key", "placeholder")
	req.Header.Set("x-client", "remove")
	resolved, err := p.getCredentialsForRequest(req, req, "api.example.com", "/v1/messages")
	if err != nil {
		t.Fatal(err)
	}
	out := req.Clone(req.Context())
	p.prepareOutbound(req, out, outboundPrep{creds: resolved.creds, host: "api.example.com", lookupHost: "api.example.com", path: "/v1/messages"})
	if got := out.Header.Get("Authorization"); got != "Bearer first" {
		t.Errorf("Authorization = %q, want first registered matched credential", got)
	}
	if got := out.Header.Get("x-api-key"); got != "" {
		t.Errorf("selector header = %q, want empty", got)
	}
	if got := out.Header.Get("x-client"); got != "" {
		t.Errorf("removed header = %q, want empty", got)
	}
	if got := out.Header.Get("anthropic-beta"); got != "oauth-2025-04-20" {
		t.Errorf("set header = %q, want configured value", got)
	}
}

func outgoingHeaders(t *testing.T, p *Proxy, req *http.Request, host, path string) http.Header {
	t.Helper()
	resolved, err := p.getCredentialsForRequest(req, req, host, path)
	if err != nil {
		t.Fatal(err)
	}
	out := req.Clone(req.Context())
	p.prepareOutbound(req, out, outboundPrep{creds: resolved.creds, host: host, lookupHost: host, path: path})
	return out.Header
}

func TestCredentialSelectionMatchesRunContextAndRegistration(t *testing.T) {
	tests := []struct {
		name          string
		matchedHost   string
		matched       CredentialHeader
		unmatchedHost string
		unmatched     CredentialHeader
		path          string
		headers       map[string]string
		want          map[string]string
	}{
		{
			name:          "matched resolver excludes requested unmatched static credential",
			matchedHost:   "api.example.com",
			matched:       CredentialHeader{Name: "Authorization", Value: "Bearer matched", Grant: "matched", Match: &RequestMatch{Header: "x-select", Paths: []string{"/v1"}}},
			unmatchedHost: "api.example.com",
			unmatched:     CredentialHeader{Name: "x-api-key", Value: "unmatched", Grant: "static"},
			path:          "/v1/messages", headers: map[string]string{"x-select": "select", "x-api-key": "placeholder"},
			want: map[string]string{"Authorization": "Bearer matched", "x-select": "", "x-api-key": "placeholder"},
		},
		{
			name:          "nonmatching exact rule falls back to wildcard unmatched credential",
			matchedHost:   "api.example.com",
			matched:       CredentialHeader{Name: "Authorization", Value: "Bearer matched", Grant: "matched", Match: &RequestMatch{Header: "x-select", Paths: []string{"/admin"}}},
			unmatchedHost: "*.example.com",
			unmatched:     CredentialHeader{Name: "x-api-key", Value: "wildcard", Grant: "wildcard"},
			path:          "/v1/messages", headers: map[string]string{"x-api-key": "placeholder"},
			want: map[string]string{"Authorization": "", "x-api-key": "wildcard"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registered := NewProxy()
			matched := tt.matched
			matched.Host = tt.matchedHost
			unmatched := tt.unmatched
			unmatched.Host = tt.unmatchedHost
			if err := registered.SetCredentialEntry(matched); err != nil {
				t.Fatal(err)
			}
			if err := registered.SetCredentialEntry(unmatched); err != nil {
				t.Fatal(err)
			}
			newRequest := func() *http.Request {
				req := httptest.NewRequest("POST", "http://api.example.com"+tt.path, nil)
				for name, value := range tt.headers {
					req.Header.Set(name, value)
				}
				return req
			}
			registeredHeaders := outgoingHeaders(t, registered, newRequest(), "api.example.com", tt.path)
			contextProxy := NewProxy()
			credentials := make(map[string][]CredentialHeader)
			credentials[tt.matchedHost] = append(credentials[tt.matchedHost], matched)
			credentials[tt.unmatchedHost] = append(credentials[tt.unmatchedHost], unmatched)
			ctxReq := newRequest().WithContext(context.WithValue(context.Background(), runContextKey, &RunContextData{Credentials: credentials}))
			contextHeaders := outgoingHeaders(t, contextProxy, ctxReq, "api.example.com", tt.path)
			for name, want := range tt.want {
				if got := registeredHeaders.Get(name); got != want {
					t.Errorf("registered %s = %q, want %q", name, got, want)
				}
				if got := contextHeaders.Get(name); got != want {
					t.Errorf("RunContextData %s = %q, want %q", name, got, want)
				}
			}
		})
	}
}

func TestMatchedCredentialErrorDoesNotFallBackToUnmatched(t *testing.T) {
	p := NewProxy()
	p.SetInsecureCredentialWithGrant("api.example.com", "x-api-key", "static", "legacy")
	if err := p.SetCredentialResolverEntry(CredentialHeader{
		Host:  "api.example.com",
		Match: &RequestMatch{Header: "x-api-key"},
		Resolver: func(context.Context, *http.Request, *http.Request, string) ([]CredentialHeader, error) {
			return nil, errors.New("source unavailable")
		},
	}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "http://api.example.com/v1/messages", nil)
	req.Header.Set("x-api-key", "selector")
	_, err := p.getCredentialsForRequest(req, req, "api.example.com", "/v1/messages")
	if err == nil || err.Error() != "source unavailable" {
		t.Fatalf("error = %v, want selected source error", err)
	}
}

func TestMatchedResolvers(t *testing.T) {
	for _, row := range matchRows() {
		check := func(t *testing.T, status int, seen *seenRequest) {
			t.Helper()
			if status != http.StatusOK {
				t.Fatalf("status = %d, want 200", status)
			}
			if seen == nil {
				t.Fatal("request never reached upstream")
			}
			if seen.auth != row.wantAuth || seen.apiKey != row.wantAPIKey {
				t.Errorf("upstream Authorization, X-Api-Key = %q, %q; want %q, %q", seen.auth, seen.apiKey, row.wantAuth, row.wantAPIKey)
			}
		}
		if row.only == "" {
			t.Run("http-cleartext/"+row.name, func(t *testing.T) {
				up, seen := requiredUpstream(t, false)
				redirectHTTPTransport(t, up.Listener.Addr().String())
				p := matchProxy(row, "api.anthropic.com")
				req := httptest.NewRequest(row.method, "http://api.anthropic.com:8080"+row.path, nil)
				for k, v := range row.headers {
					req.Header.Set(k, v)
				}
				rec := httptest.NewRecorder()
				p.ServeHTTP(rec, req)
				check(t, rec.Code, seen.Load())
			})
			t.Run("connect-intercept/"+row.name, func(t *testing.T) {
				up, seen := requiredUpstream(t, true)
				p := matchProxy(row, mustParseURL(up.URL).Hostname())
				ca := contractCA(t)
				upstreamCAs := x509.NewCertPool()
				upstreamCAs.AddCert(up.Certificate())
				p.SetCA(ca)
				p.SetUpstreamCAs(upstreamCAs)
				proxySrv := httptest.NewServer(p)
				t.Cleanup(proxySrv.Close)
				clientCAs := x509.NewCertPool()
				clientCAs.AppendCertsFromPEM(ca.certPEM)
				proxyURL, _ := url.Parse(proxySrv.URL)
				client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: clientCAs}}}
				t.Cleanup(client.CloseIdleConnections)
				req, _ := http.NewRequest(row.method, up.URL+row.path, nil)
				for k, v := range row.headers {
					req.Header.Set(k, v)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("request: %v", err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				check(t, resp.StatusCode, seen.Load())
			})
		}
		if row.only == "" || row.only == "relay" {
			t.Run("relay/"+row.name, func(t *testing.T) {
				up, seen := requiredUpstream(t, false)
				p := matchProxy(row, mustParseURL(up.URL).Hostname())
				if err := p.AddRelay("anthropic", up.URL+row.relayBase); err != nil {
					t.Fatal(err)
				}
				req := httptest.NewRequest(row.method, "/relay/anthropic"+row.path, nil)
				for k, v := range row.headers {
					req.Header.Set(k, v)
				}
				rec := httptest.NewRecorder()
				p.handleRelay(rec, req)
				check(t, rec.Code, seen.Load())
			})
		}
	}
}

// A declared resolver outranked by an exact-host static credential is skipped;
// the client's selecting header must still be removed.
func TestMatchedResolvers_OutrankedStripsSelectingHeader(t *testing.T) {
	p := NewProxy()
	p.SetInsecureCredentialWithGrant("api.example.com", "Authorization", "Bearer static", "bot")
	p.SetMatchedCredentialResolver("*.example.com", RequestMatch{Header: "x-api-key"}, func(context.Context, *http.Request, *http.Request, string) ([]CredentialHeader, error) {
		t.Error("outranked resolver ran")
		return nil, nil
	})
	req := httptest.NewRequest("POST", "http://api.example.com/v1/messages", nil)
	req.Header.Set("x-api-key", "placeholder")
	if _, err := p.getCredentialsForRequest(req, req, "api.example.com", "/v1/messages"); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("x-api-key"); got != "" {
		t.Errorf("x-api-key = %q, want it stripped", got)
	}
}

// A nil resolver or an empty match registered ahead of a real rule must not
// shadow it.
func TestSetMatchedCredentialResolver_IgnoresDegenerateEntries(t *testing.T) {
	p := NewProxy()
	p.SetMatchedCredentialResolver("api.example.com", RequestMatch{Header: "x-api-key"}, nil)
	p.SetMatchedCredentialResolver("api.example.com", RequestMatch{}, func(context.Context, *http.Request, *http.Request, string) ([]CredentialHeader, error) {
		return []CredentialHeader{{Name: "Authorization", Value: "Bearer shadow"}}, nil
	})
	p.SetMatchedCredentialResolver("api.example.com", RequestMatch{Header: "x-api-key"}, func(context.Context, *http.Request, *http.Request, string) ([]CredentialHeader, error) {
		return []CredentialHeader{{Name: "Authorization", Value: "Bearer real"}}, nil
	})
	req := httptest.NewRequest("POST", "http://api.example.com/v1/messages", nil)
	req.Header.Set("x-api-key", "placeholder")
	got, err := p.getCredentialsForRequest(req, req, "api.example.com", "/v1/messages")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.creds) != 1 || got.creds[0].Value != "Bearer real" {
		t.Errorf("creds = %+v, want the real rule's Bearer real", got.creds)
	}
}

// A request that carries the subject headers of two rules and selects one
// must not forward the other rule's subject header.
func TestMatchedResolvers_StripsEveryRulesSubjectHeader(t *testing.T) {
	for _, outranked := range []bool{false, true} {
		name := "resolved"
		if outranked {
			name = "outranked"
		}
		t.Run(name, func(t *testing.T) {
			p := NewProxy()
			host := "api.example.com"
			if outranked {
				p.SetInsecureCredentialWithGrant(host, "Authorization", "Bearer static", "bot")
				host = "*.example.com"
			}
			consume := func(h string) CredentialResolver {
				return func(_ context.Context, _, inner *http.Request, _ string) ([]CredentialHeader, error) {
					inner.Header.Del(h)
					return []CredentialHeader{{Name: "Authorization", Value: "Bearer " + h}}, nil
				}
			}
			p.SetMatchedCredentialResolver(host, RequestMatch{Header: "X-Subject-A"}, consume("X-Subject-A"), "X-Subject-A")
			p.SetMatchedCredentialResolver(host, RequestMatch{Header: "X-Subject-B"}, consume("X-Subject-B"), "X-Subject-B")
			req := httptest.NewRequest("POST", "http://api.example.com/v1/messages", nil)
			req.Header.Set("X-Subject-A", "a")
			req.Header.Set("X-Subject-B", "b")
			if _, err := p.getCredentialsForRequest(req, req, "api.example.com", "/v1/messages"); err != nil {
				t.Fatal(err)
			}
			for _, h := range []string{"X-Subject-A", "X-Subject-B"} {
				if got := req.Header.Get(h); got != "" {
					t.Errorf("%s = %q, want it stripped", h, got)
				}
			}
		})
	}
}
