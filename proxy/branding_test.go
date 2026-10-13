package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func blockedRecorder(t *testing.T, p *Proxy) *httptest.ResponseRecorder {
	t.Helper()
	p.SetNetworkPolicy("strict", nil, nil)
	req := httptest.NewRequest("GET", "http://blocked.example/", nil)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", rec.Code)
	}
	return rec
}

func TestBlockedResponse_NeutralByDefaultWithAliasHeader(t *testing.T) {
	rec := blockedRecorder(t, NewProxy())
	h := rec.Header()
	if got := h.Get("X-Gatekeeper-Blocked"); got != "request-rule" {
		t.Errorf("X-Gatekeeper-Blocked = %q, want request-rule", got)
	}
	if h.Get("X-Moat-Blocked") != h.Get("X-Gatekeeper-Blocked") {
		t.Errorf("X-Moat-Blocked = %q, want alias of X-Gatekeeper-Blocked", h.Get("X-Moat-Blocked"))
	}
	for name, vals := range h {
		if strings.Contains(strings.ToLower(name+strings.Join(vals, ",")), "moat") && name != "X-Moat-Blocked" {
			t.Errorf("header %s=%v names moat", name, vals)
		}
	}
	if body := rec.Body.String(); strings.Contains(strings.ToLower(body), "moat") || !strings.HasPrefix(body, "gatekeeper: request blocked") {
		t.Errorf("body = %q, want neutral gatekeeper text", body)
	}
}

func TestBlockedResponse_BrandingOptionRestoresHints(t *testing.T) {
	p := NewProxy()
	p.SetBranding(Branding{Name: "Moat", NetworkHint: "Add it to network.rules in moat.yaml."})
	body := blockedRecorder(t, p).Body.String()
	if !strings.HasPrefix(body, "Moat: request blocked") || !strings.Contains(body, "network.rules in moat.yaml") {
		t.Errorf("body = %q, want moat hint", body)
	}
}

func TestMCPStubPrefix(t *testing.T) {
	cases := []struct {
		name, prefix, stub string
		injected           bool
	}{
		{"default prefix", "", "gatekeeper-stub-mcp-x", true},
		{"default ignores moat prefix", "", "moat-stub-mcp-x", false},
		{"option prefix", "moat-stub-", "moat-stub-mcp-x", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(r.Header.Get("API_KEY")))
			}))
			defer backend.Close()
			p := &Proxy{
				credStore: &mockCredentialStore{tokens: map[string]string{"mcp-x": "real"}},
				mcpServers: []MCPServerConfig{{Name: "x", URL: backend.URL,
					Auth: &MCPAuthConfig{AllowInsecure: true, Grant: "mcp-x", Header: "API_KEY"}}},
			}
			p.SetBranding(Branding{MCPStubPrefix: tc.prefix})
			req := httptest.NewRequest("GET", backend.URL, nil)
			req.Header.Set("API_KEY", tc.stub)
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)
			want := tc.stub
			if tc.injected {
				want = "real"
			}
			if rec.Body.String() != want {
				t.Errorf("backend saw %q, want %q", rec.Body.String(), want)
			}
		})
	}
}

func TestNewCA_SubjectNeutralByDefaultAndOverridable(t *testing.T) {
	ca, err := NewCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got := ca.cert.Subject.CommonName; got != "Gatekeeper CA" {
		t.Errorf("CommonName = %q, want Gatekeeper CA", got)
	}
	ca, err = NewCAWithSubject(t.TempDir(), "Moat", "Moat CA")
	if err != nil {
		t.Fatal(err)
	}
	if got := ca.cert.Subject.CommonName; got != "Moat CA" {
		t.Errorf("CommonName = %q, want Moat CA", got)
	}
}
