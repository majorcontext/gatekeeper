package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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
