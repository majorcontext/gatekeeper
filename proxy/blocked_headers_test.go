package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	keeplib "github.com/majorcontext/keep"
)

func TestBlockedResponses_AllKindsCarryBothHeaders(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(backend.Close)
	host, _, _ := strings.Cut(strings.TrimPrefix(backend.URL, "http://"), ":")

	mcpDeny := func(t *testing.T, body string) *httptest.ResponseRecorder {
		eng, err := keeplib.LoadFromBytes([]byte(mcpDenyAllRules))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { eng.Close() })
		p := &Proxy{mcpServers: []MCPServerConfig{{Name: "keep-test", URL: backend.URL}}}
		req := httptest.NewRequest(http.MethodPost, "/mcp/keep-test", strings.NewReader(body))
		rc := &RunContextData{KeepEngines: map[string]*keeplib.Engine{"mcp-keep-test": eng}, MCPServers: p.mcpServers}
		req = req.WithContext(context.WithValue(req.Context(), runContextKey, rc))
		rec := httptest.NewRecorder()
		p.handleMCPRelay(rec, req)
		return rec
	}

	cases := []struct {
		name string
		do   func(t *testing.T) http.Header
		want string
	}{
		{"network policy", func(t *testing.T) http.Header {
			p := NewProxy()
			p.SetNetworkPolicy("strict", nil, nil)
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, httptest.NewRequest("GET", "http://blocked.example/", nil))
			return rec.Header()
		}, "request-rule"},
		{"mcp invalid json", func(t *testing.T) http.Header { return mcpDeny(t, "not json").Header() }, "mcp-policy"},
		{"mcp tool denied", func(t *testing.T) http.Header {
			return mcpDeny(t, `{"method":"tools/call","params":{"name":"x","arguments":{}}}`).Header()
		}, "mcp-policy"},
		{"cleartext http", func(t *testing.T) http.Header {
			p := NewProxy()
			p.SetCredentialWithGrant(host, "Authorization", "Bearer s", "g")
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, httptest.NewRequest("GET", backend.URL, nil))
			return rec.Header()
		}, "cleartext-credential"},
		{"cleartext relay", func(t *testing.T) http.Header {
			p := NewProxy()
			if err := p.AddRelay("svc", backend.URL); err != nil {
				t.Fatal(err)
			}
			p.SetCredentialWithGrant(host, "Authorization", "Bearer s", "g")
			rec := httptest.NewRecorder()
			p.handleRelay(rec, httptest.NewRequest("GET", "/relay/svc/x", nil))
			return rec.Header()
		}, "cleartext-credential"},
		{"cleartext mcp", func(t *testing.T) http.Header {
			p := &Proxy{
				credStore:  &mockCredentialStore{tokens: map[string]string{"mcp-svc": "s"}},
				mcpServers: []MCPServerConfig{{Name: "svc", URL: backend.URL, Auth: &MCPAuthConfig{Grant: "mcp-svc", Header: "API_KEY"}}},
			}
			rec := httptest.NewRecorder()
			p.handleMCPRelay(rec, httptest.NewRequest("POST", "/mcp/svc", nil))
			return rec.Header()
		}, "cleartext-credential"},
		{"credential required", func(t *testing.T) http.Header {
			p := NewProxy()
			p.SetCredentialResolver(host, func(context.Context, *http.Request, *http.Request, string) ([]CredentialHeader, error) {
				return nil, &ResolverDeclined{ExplicitOnly: true, Grant: "claude-code-user"}
			})
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, httptest.NewRequest("GET", backend.URL, nil))
			return rec.Header()
		}, "credential-required"},
		{"host service", func(t *testing.T) http.Header {
			p := NewProxy()
			p.SetContextResolver(func(token string) (*RunContextData, bool) {
				return &RunContextData{Policy: "permissive", HostGateway: "host.internal", HostGatewayIP: "127.0.0.1"}, token == "tok"
			})
			req := httptest.NewRequest("GET", "http://127.0.0.1:8080/", nil)
			req.Header.Set("Proxy-Authorization", "Bearer tok")
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)
			return rec.Header()
		}, "host-service"},
		{"keep policy", func(t *testing.T) http.Header {
			eng, err := keeplib.LoadFromBytes([]byte(httpBodyRules))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { eng.Close() })
			setup := newInterceptTestSetup(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			setup.Proxy.SetContextResolver(func(token string) (*RunContextData, bool) {
				return &RunContextData{Policy: "permissive", KeepEngines: map[string]*keeplib.Engine{"http": eng}}, token == "tok"
			})
			proxyURL := mustParseURL(setup.ProxyServer.URL)
			proxyURL.User = url.UserPassword("alice", "tok")
			clientCAs := x509.NewCertPool()
			clientCAs.AppendCertsFromPEM(setup.CA.certPEM)
			client := &http.Client{Transport: &http.Transport{
				Proxy:           http.ProxyURL(proxyURL),
				TLSClientConfig: &tls.Config{RootCAs: clientCAs},
			}}
			resp, err := client.Post(setup.Backend.URL+"/v1/messages", "application/json", strings.NewReader(`{"model":"gpt-4"}`))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			return resp.Header
		}, "keep-policy"},
		{"llm policy", func(t *testing.T) http.Header {
			eng, err := keeplib.LoadFromBytes([]byte(llmGatewayDenyEditPolicy))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(eng.Close)
			body := `{"content":[{"type":"tool_use","id":"t1","name":"Edit","input":{"file_path":"/foo"}}],"stop_reason":"tool_use"}`
			client, backendURL := newAnthropicInterceptSetup(t, eng, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, body)
			}))
			resp, err := client.Post(backendURL+"/v1/messages", "application/json", strings.NewReader(`{"model":"claude-opus-4-5"}`))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			return resp.Header
		}, "llm-policy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := tc.do(t)
			if got := h.Get("X-Gatekeeper-Blocked"); got != tc.want {
				t.Errorf("X-Gatekeeper-Blocked = %q, want %q", got, tc.want)
			}
			if got := h.Get("X-Moat-Blocked"); got != tc.want {
				t.Errorf("X-Moat-Blocked = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCleartextRefusal_UsesBrandPrefix(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(backend.Close)
	host, _, _ := strings.Cut(strings.TrimPrefix(backend.URL, "http://"), ":")
	p := NewProxy()
	p.SetBranding(Branding{Name: "Acme"})
	p.SetCredentialWithGrant(host, "Authorization", "Bearer s", "g")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("GET", backend.URL, nil))
	if body := rec.Body.String(); !strings.HasPrefix(body, "Acme: ") {
		t.Errorf("body = %q, want Acme prefix", body)
	}
}
