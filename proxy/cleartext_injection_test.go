package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const cleartextSecret = "s3cr3t-token"

func cleartextProxyKinds() map[string]func(p *Proxy, k hostKeys) *RunContextData {
	return map[string]func(p *Proxy, k hostKeys) *RunContextData{
		"proxy-level credential": func(p *Proxy, k hostKeys) *RunContextData {
			p.SetCredentialWithGrant(k.h, "Authorization", "Bearer "+cleartextSecret, "g")
			return nil
		},
		"run context credential": func(p *Proxy, k hostKeys) *RunContextData {
			return &RunContextData{Policy: "permissive", Credentials: map[string][]CredentialHeader{k.h: authCred("Bearer "+cleartextSecret, "g")}}
		},
		"resolver credential": func(p *Proxy, k hostKeys) *RunContextData {
			p.SetCredentialResolver(k.h, func(context.Context, *http.Request, *http.Request, string) ([]CredentialHeader, error) {
				return authCred("Bearer "+cleartextSecret, "g"), nil
			})
			return nil
		},
		"token substitution": func(p *Proxy, k hostKeys) *RunContextData {
			p.SetTokenSubstitution(k.h, "placeholder", cleartextSecret)
			return nil
		},
	}
}

func serveCleartext(t *testing.T, setup func(p *Proxy, k hostKeys) *RunContextData) (*httptest.ResponseRecorder, <-chan wireRequest) {
	t.Helper()
	up, got := newContractUpstream(t, false)
	redirectHTTPTransport(t, up.Listener.Addr().String())
	k := hostKeys{h: "api.example.com", hp: "api.example.com:8080"}
	p := NewProxy()
	rc := setup(p, k)
	if rc != nil {
		p.SetContextResolver(func(token string) (*RunContextData, bool) { return rc, token == "run-token" })
	}
	req := httptest.NewRequest("GET", "http://"+k.hp+"/api/placeholder", nil)
	if rc != nil {
		req.Header.Set("Proxy-Authorization", "Bearer run-token")
	}
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	return rec, got
}

func TestCleartextInjectionRefusedByDefault(t *testing.T) {
	for name, setup := range cleartextProxyKinds() {
		t.Run(name, func(t *testing.T) {
			rec, got := serveCleartext(t, setup)
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
			}
			select {
			case w := <-got:
				t.Fatalf("request reached upstream over plain HTTP with headers %v path %q", w.flat(), w.path)
			default:
			}
			body := rec.Body.String()
			for _, want := range []string{"api.example.com", "allow_insecure"} {
				if !strings.Contains(body, want) {
					t.Errorf("body %q does not mention %q", body, want)
				}
			}
			if strings.Contains(body, cleartextSecret) {
				t.Errorf("body leaks the credential: %q", body)
			}
		})
	}
}

func TestCleartextInjectionOptIn(t *testing.T) {
	kinds := map[string]struct {
		setup func(p *Proxy, k hostKeys) *RunContextData
		check func(t *testing.T, w wireRequest)
	}{
		"proxy-level credential": {
			setup: func(p *Proxy, k hostKeys) *RunContextData {
				p.SetInsecureCredentialWithGrant(k.h, "Authorization", "Bearer "+cleartextSecret, "g")
				return nil
			},
			check: wantAuth("Bearer " + cleartextSecret),
		},
		"run context credential": {
			setup: func(p *Proxy, k hostKeys) *RunContextData {
				c := cred("Authorization", "Bearer "+cleartextSecret, "g")
				c.AllowInsecure = true
				return &RunContextData{Policy: "permissive", Credentials: map[string][]CredentialHeader{k.h: {c}}}
			},
			check: wantAuth("Bearer " + cleartextSecret),
		},
		"token substitution": {
			setup: func(p *Proxy, k hostKeys) *RunContextData {
				p.SetInsecureTokenSubstitution(k.h, "placeholder", cleartextSecret)
				return nil
			},
			check: func(t *testing.T, w wireRequest) {
				if w.path != "/api/"+cleartextSecret {
					t.Errorf("upstream path = %q, want the real token substituted", w.path)
				}
			},
		},
	}
	for name, k := range kinds {
		t.Run(name, func(t *testing.T) {
			rec, got := serveCleartext(t, k.setup)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			k.check(t, <-got)
		})
	}
}

func wantAuth(v string) func(*testing.T, wireRequest) {
	return func(t *testing.T, w wireRequest) {
		t.Helper()
		if g := w.header.Get("Authorization"); g != v {
			t.Errorf("upstream Authorization = %q, want %q", g, v)
		}
	}
}

func TestCleartextInjectionMixedCredentialsRefused(t *testing.T) {
	rec, got := serveCleartext(t, func(p *Proxy, k hostKeys) *RunContextData {
		p.SetInsecureCredentialWithGrant(k.h, "X-Api-Key", "k", "a")
		p.SetCredentialWithGrant(k.h, "Authorization", "Bearer "+cleartextSecret, "b")
		return nil
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if len(got) != 0 {
		t.Error("request reached upstream with one credential lacking opt-in")
	}
}

func TestCleartextRelayRefusedByDefault(t *testing.T) {
	for _, optIn := range []bool{false, true} {
		var gotAuth string
		reached := false
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			gotAuth = r.Header.Get("Authorization")
		}))
		t.Cleanup(backend.Close)

		p := NewProxy()
		if err := p.AddRelay("svc", backend.URL); err != nil {
			t.Fatal(err)
		}
		host, _, _ := strings.Cut(strings.TrimPrefix(backend.URL, "http://"), ":")
		if optIn {
			p.SetInsecureCredentialWithGrant(host, "Authorization", "Bearer "+cleartextSecret, "g")
		} else {
			p.SetCredentialWithGrant(host, "Authorization", "Bearer "+cleartextSecret, "g")
		}
		rec := httptest.NewRecorder()
		p.handleRelay(rec, httptest.NewRequest("GET", "/relay/svc/x", nil))

		if optIn {
			if rec.Code != http.StatusOK || gotAuth != "Bearer "+cleartextSecret {
				t.Errorf("opt-in: status %d, Authorization %q; want injected", rec.Code, gotAuth)
			}
			continue
		}
		if rec.Code != http.StatusForbidden || reached {
			t.Errorf("default: status %d, reached upstream %v; want 403 and no upstream call", rec.Code, reached)
		}
		if strings.Contains(rec.Body.String(), cleartextSecret) {
			t.Errorf("body leaks the credential: %q", rec.Body.String())
		}
	}
}

func TestCleartextMCPRefusedByDefault(t *testing.T) {
	for _, optIn := range []bool{false, true} {
		var gotKey string
		reached := false
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			gotKey = r.Header.Get("API_KEY")
		}))
		t.Cleanup(backend.Close)

		p := &Proxy{
			credStore:  &mockCredentialStore{tokens: map[string]string{"mcp-svc": cleartextSecret}},
			mcpServers: []MCPServerConfig{{Name: "svc", URL: backend.URL, Auth: &MCPAuthConfig{Grant: "mcp-svc", Header: "API_KEY", AllowInsecure: optIn}}},
		}

		rec := httptest.NewRecorder()
		p.handleMCPRelay(rec, httptest.NewRequest("POST", "/mcp/svc", nil))
		if optIn {
			if rec.Code != http.StatusOK || gotKey != cleartextSecret {
				t.Errorf("relay opt-in: status %d, API_KEY %q; want injected", rec.Code, gotKey)
			}
		} else if rec.Code != http.StatusForbidden || reached {
			t.Errorf("relay default: status %d, reached upstream %v; want 403 and no upstream call", rec.Code, reached)
		}

		reached, gotKey = false, ""
		req := httptest.NewRequest("GET", backend.URL, nil)
		req.Header.Set("API_KEY", "gatekeeper-stub-mcp-svc")
		p.ServeHTTP(httptest.NewRecorder(), req)
		if want := map[bool]string{false: "gatekeeper-stub-mcp-svc", true: cleartextSecret}[optIn]; gotKey != want {
			t.Errorf("stub path (opt-in %v): upstream API_KEY = %q, want %q", optIn, gotKey, want)
		}
	}
}
