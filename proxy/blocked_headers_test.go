package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
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
		do   func(t *testing.T) *httptest.ResponseRecorder
		want string
	}{
		{"network policy", func(t *testing.T) *httptest.ResponseRecorder {
			p := NewProxy()
			p.SetNetworkPolicy("strict", nil, nil)
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, httptest.NewRequest("GET", "http://blocked.example/", nil))
			return rec
		}, "request-rule"},
		{"mcp invalid json", func(t *testing.T) *httptest.ResponseRecorder { return mcpDeny(t, "not json") }, "mcp-policy"},
		{"mcp tool denied", func(t *testing.T) *httptest.ResponseRecorder {
			return mcpDeny(t, `{"method":"tools/call","params":{"name":"x","arguments":{}}}`)
		}, "mcp-policy"},
		{"cleartext http", func(t *testing.T) *httptest.ResponseRecorder {
			p := NewProxy()
			p.SetCredentialWithGrant(host, "Authorization", "Bearer s", "g")
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, httptest.NewRequest("GET", backend.URL, nil))
			return rec
		}, "cleartext-credential"},
		{"cleartext relay", func(t *testing.T) *httptest.ResponseRecorder {
			p := NewProxy()
			if err := p.AddRelay("svc", backend.URL); err != nil {
				t.Fatal(err)
			}
			p.SetCredentialWithGrant(host, "Authorization", "Bearer s", "g")
			rec := httptest.NewRecorder()
			p.handleRelay(rec, httptest.NewRequest("GET", "/relay/svc/x", nil))
			return rec
		}, "cleartext-credential"},
		{"cleartext mcp", func(t *testing.T) *httptest.ResponseRecorder {
			p := &Proxy{
				credStore:  &mockCredentialStore{tokens: map[string]string{"mcp-svc": "s"}},
				mcpServers: []MCPServerConfig{{Name: "svc", URL: backend.URL, Auth: &MCPAuthConfig{Grant: "mcp-svc", Header: "API_KEY"}}},
			}
			rec := httptest.NewRecorder()
			p.handleMCPRelay(rec, httptest.NewRequest("POST", "/mcp/svc", nil))
			return rec
		}, "cleartext-credential"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := tc.do(t).Header()
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
