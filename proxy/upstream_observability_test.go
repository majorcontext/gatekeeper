package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestUpstreamUnauthorizedCode(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{`{"detail":{"code":"invalid_token","message":"secret value"}}`, "invalid_token"},
		{`{"error":{"code":"expired_token"}}`, "expired_token"},
		{`{"detail":"Not authenticated","error":{"code":"token_expired"}}`, "token_expired"},
		{`{"detail":{"code":"invalid_token"},"error":"Not authenticated"}`, "invalid_token"},
		{`{"detail":{"code":42},"error":{"code":"token_expired"}}`, "token_expired"},
		{`{"detail":{"code":"invalid_token"},"error":{"code":42}}`, "invalid_token"},
		{`{"detail":{"code":"invalid_token"},"error":{"code":"token_expired"}}`, "invalid_token"},
		{`{"error":{"code":"Bearer secret"}}`, ""},
		{`{"error":{"code":42}}`, ""},
	} {
		t.Run(tc.body, func(t *testing.T) {
			resp := &http.Response{StatusCode: 401, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(tc.body))}
			body := captureUpstreamAuthCode(resp, &http.Request{URL: &url.URL{}})
			_, _ = io.Copy(io.Discard, resp.Body)
			if got := upstreamAuthCode(body, nil, nil, false); got != tc.want {
				t.Errorf("code = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestUpstreamUnauthorizedCredentialOverlap(t *testing.T) {
	basic := "Basic " + basicAuth("user", "secret_token")
	for _, tc := range []struct {
		name, code string
		headers    http.Header
		injected   []CredentialHeader
		want       string
	}{
		{"credential", "secret_token", nil, []CredentialHeader{{Value: "secret_token"}}, ""},
		{"authorization", "secret_token", http.Header{"Authorization": {"Bearer sec"}}, nil, ""},
		{"short credential", "secret_token", nil, []CredentialHeader{{Value: "sec"}}, ""},
		{"custom header", "secret_token", http.Header{"X-Custom-Key": {"sec"}}, nil, ""},
		{"injected language", "secret_token", http.Header{"Accept-Language": {"sec"}}, []CredentialHeader{{Name: "Accept-Language", Value: "sec"}}, ""},
		{"header syntax", "invalid_token", http.Header{"Authorization": {"token abc123"}}, []CredentialHeader{{Name: "Authorization", Value: "token abc123"}}, "invalid_token"},
		{"custom basic injected", "secret_token", nil, []CredentialHeader{{Name: "X-Custom-Key", Value: basic}}, ""},
		{"custom basic outbound", "secret_token", http.Header{"X-Custom-Key": {basic}}, nil, ""},
		{"custom basic partial", "bad_key_abcdef12", http.Header{"X-Custom-Key": {"Basic " + basicAuth("user", "abcdef12_more")}}, nil, ""},
		{"mixed case nested basic", "secret_token", http.Header{"X-Custom-Key": {"bEaReR bAsIc " + basicAuth("user", "secret_token")}}, nil, ""},
		{"nested basic with extension", "secret_token", http.Header{"X-Custom-Key": {"Bearer Basic " + basicAuth("user", "secret_token") + " extension"}}, nil, ""},
		{"token nested basic", "secret_token", http.Header{"X-Custom-Key": {"token Basic " + basicAuth("user", "secret_token")}}, nil, ""},
		{"arbitrary mixed case nested basic with extension", "secret_token", nil, []CredentialHeader{{Name: "X-Key", Value: "custom prefix bAsIc " + basicAuth("user", "secret_token") + " extension"}}, ""},
		{"partial injected", "bad_key_abcdef12", nil, []CredentialHeader{{Name: "X-Key", Value: "abcdef12_more"}}, ""},
		{"partial outbound", "bad_key_abcdef12", http.Header{"X-Key": {"abcdef12_more"}}, nil, ""},
		{"seven shared characters", "bad_key_abcdef1", http.Header{"X-Key": {"abcdef12_more"}}, nil, "bad_key_abcdef1"},
		{"oversized credential", "invalid_token", http.Header{"X-Key": {strings.Repeat("z", MaxBodySize+1)}}, nil, ""},
		{"short header", "token_expired", http.Header{"Accept-Language": {"en"}}, nil, ""},
		{"case insensitive injected", "secret_token", nil, []CredentialHeader{{Name: "X-Key", Value: "SECRET_TOKEN"}}, ""},
		{"case insensitive basic decoded", "secret_token", http.Header{"X-Key": {"Basic " + basicAuth("user", "SECRET_TOKEN")}}, nil, ""},
		{"case insensitive fragment header", "bad_key_abcdef12", http.Header{"X-Key": {"ABCDEF12_more"}}, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{StatusCode: 401, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"error":{"code":"` + tc.code + `"}}`))}
			body := captureUpstreamAuthCode(resp, &http.Request{URL: &url.URL{}})
			_, _ = io.Copy(io.Discard, resp.Body)
			if got := upstreamAuthCode(body, tc.headers, tc.injected, false); got != tc.want {
				t.Fatalf("code = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestUpstreamUnauthorizedCaptureStreamsUnchanged(t *testing.T) {
	body := `{"detail":{"code":"token_expired"}}`
	resp := &http.Response{StatusCode: 401, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
	captured := captureUpstreamAuthCode(resp, &http.Request{URL: &url.URL{}})
	if len(captured.Captured()) != 0 {
		t.Fatal("capture read ahead")
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil || string(got) != body {
		t.Fatalf("body = %q, error = %v", got, err)
	}
	if got := upstreamAuthCode(captured, nil, nil, false); got != "token_expired" {
		t.Fatalf("code = %q", got)
	}
}

func TestUpstreamUnauthorizedSecretsNotLogged(t *testing.T) {
	for _, path := range []string{"http", "connect"} {
		for _, kind := range []string{"basic", "nested-basic", "substitution"} {
			t.Run(path+"/"+kind, func(t *testing.T) {
				const secret = "secret_token"
				seen := make(chan string, 1)
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if kind != "substitution" {
						seen <- r.Header.Get("Authorization")
					} else {
						seen <- r.URL.Path
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = io.WriteString(w, `{"error":{"code":"secret_token"}}`)
				})
				var p *Proxy
				var backendURL, host string
				var request func(string) (*http.Response, error)
				if path == "connect" {
					setup := newInterceptTestSetup(t, handler)
					p, backendURL, host, request = setup.Proxy, setup.Backend.URL, setup.BackendHost, setup.Client.Get
				} else {
					backend := httptest.NewServer(handler)
					t.Cleanup(backend.Close)
					p, backendURL = NewProxy(), backend.URL
					host = mustParseURL(backend.URL).Hostname()
					server := httptest.NewServer(p)
					t.Cleanup(server.Close)
					client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustParseURL(server.URL))}}
					request = client.Get
				}
				if kind != "substitution" {
					value := "Basic " + basicAuth("user", secret)
					if kind == "nested-basic" {
						value = "custom bAsIc " + basicAuth("user", secret) + " extension"
					}
					if path == "http" {
						p.SetInsecureCredentialWithGrant(host, "Authorization", value, "example")
					} else {
						p.SetCredentialWithGrant(host, "Authorization", value, "example")
					}
				} else if path == "http" {
					p.SetInsecureTokenSubstitution(host, "placeholder", secret)
				} else {
					p.SetTokenSubstitution(host, "placeholder", secret)
				}
				wait := captureLog(t, p)
				resp, err := request(backendURL + "/placeholder")
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				got := <-seen
				if kind == "basic" && got != "Basic "+basicAuth("user", secret) {
					t.Fatalf("upstream auth = %q", got)
				}
				if kind == "nested-basic" && got != "custom bAsIc "+basicAuth("user", secret)+" extension" {
					t.Fatalf("upstream auth = %q", got)
				}
				if kind == "substitution" && got != "/"+secret {
					t.Fatalf("upstream path = %q", got)
				}
				if log := wait(); log.UpstreamAuthCode != "" {
					t.Fatalf("upstream auth code leaked secret: %q", log.UpstreamAuthCode)
				}
			})
		}
	}
}

func TestMCPRawOAuthBasicCredentialRedactsUpstreamCode(t *testing.T) {
	const secret = "secret_token"
	raw := "Basic " + basicAuth("user", secret)
	seen := make(chan string, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("X-Custom-Key")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"code":"secret_token"}}`)
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetMCPServers([]MCPServerConfig{{Name: "test", URL: backend.URL, Auth: &MCPAuthConfig{Grant: "oauth:test", Header: "X-Custom-Key", AllowInsecure: true}}})
	p.SetCredentialStore(&mockCredentialStore{tokens: map[string]string{"oauth:test": raw}})
	var logged RequestLogData
	p.SetLogger(func(d RequestLogData) { logged = d })
	response := httptest.NewRecorder()
	p.ServeHTTP(response, httptest.NewRequest("POST", "/mcp/test", nil))
	if response.Code != http.StatusUnauthorized || logged.StatusCode != http.StatusUnauthorized {
		t.Fatalf("response status = %d, logged status = %d", response.Code, logged.StatusCode)
	}
	if got := <-seen; got != "Bearer "+raw {
		t.Fatalf("upstream header = %q, want %q", got, "Bearer "+raw)
	}
	if logged.UpstreamAuthCode != "" {
		t.Fatalf("upstream auth code leaked secret: %q", logged.UpstreamAuthCode)
	}
}

func TestMCPInjectedHeaderRedactsUpstreamCode(t *testing.T) {
	for _, tc := range []struct{ name, grant, credential, code, want string }{
		{"fragment", "mcp-test", "abcdef12_more", "bad_key_abcdef12", "abcdef12_more"},
		{"oauth nested basic", "oauth:test", "Basic " + basicAuth("user", "secret_token"), "secret_token", "Bearer Basic " + basicAuth("user", "secret_token")},
	} {
		for _, path := range []string{"http", "connect"} {
			t.Run(tc.name+"/"+path, func(t *testing.T) {
				seen := make(chan string, 1)
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					seen <- r.Header.Get("Accept-Language")
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = io.WriteString(w, `{"error":{"code":"`+tc.code+`"}}`)
				})
				var p *Proxy
				var backendURL string
				var client *http.Client
				if path == "connect" {
					setup := newInterceptTestSetup(t, handler)
					p, backendURL, client = setup.Proxy, setup.Backend.URL, setup.Client
				} else {
					backend := httptest.NewServer(handler)
					t.Cleanup(backend.Close)
					p, backendURL = NewProxy(), backend.URL
					server := httptest.NewServer(p)
					t.Cleanup(server.Close)
					client = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustParseURL(server.URL))}}
				}
				p.SetMCPServers([]MCPServerConfig{{Name: "test", URL: backendURL, Auth: &MCPAuthConfig{Grant: tc.grant, Header: "Accept-Language", AllowInsecure: true}}})
				p.SetCredentialStore(&mockCredentialStore{tokens: map[string]string{tc.grant: tc.credential}})
				wait := captureLog(t, p)
				req, err := http.NewRequest("GET", backendURL+"/resource", nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Accept-Language", "gatekeeper-stub-"+tc.grant)
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if got := <-seen; got != tc.want {
					t.Fatalf("upstream header = %q", got)
				}
				if data := wait(); data.UpstreamAuthCode != "" {
					t.Fatalf("code leaked credential fragment: %q", data.UpstreamAuthCode)
				}
			})
		}
	}
}

func TestInterceptUnauthorizedCodePreservesBody(t *testing.T) {
	const body = `{"error":{"code":"token_expired","message":"try again"}}`
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, body)
	}))
	wait := captureLog(t, setup.Proxy)
	resp, err := setup.Client.Get(setup.Backend.URL + "/resource")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(got) != body {
		t.Fatalf("body = %q, err = %v", got, err)
	}
	if data := wait(); data.UpstreamAuthCode != "token_expired" {
		t.Fatalf("code = %q", data.UpstreamAuthCode)
	}
}

func TestUserinfoUpstreamAuthCodeSuppressed(t *testing.T) {
	for _, path := range []string{"relay", "mcp", "http"} {
		t.Run(path, func(t *testing.T) {
			seen := make(chan bool, 1)
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				user, pass, ok := r.BasicAuth()
				seen <- ok && user == "user" && pass == "secret_token"
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, `{"error":{"code":"secret_token"}}`)
			}))
			defer backend.Close()
			u := mustParseURL(backend.URL)
			u.User = url.UserPassword("user", "secret_token")
			p := NewProxy()
			if path == "relay" {
				if err := p.AddRelay("test", u.String()); err != nil {
					t.Fatal(err)
				}
			} else if path == "mcp" {
				p.SetMCPServers([]MCPServerConfig{{Name: "test", URL: u.String()}})
			}
			var logged RequestLogData
			p.SetLogger(func(d RequestLogData) { logged = d })
			requestPath := "/relay/test/"
			if path == "mcp" {
				requestPath = "/mcp/test"
			} else if path == "http" {
				requestPath = u.String()
			}
			p.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", requestPath, nil))
			if path != "http" && !<-seen {
				t.Fatal("upstream did not receive expected Basic credentials")
			}
			if path == "http" && logged.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d", logged.StatusCode)
			}
			if logged.UpstreamAuthCode != "" {
				t.Fatal("upstream auth code exposed userinfo")
			}
		})
	}
}

func TestInterceptTransformedUnauthorizedOmitsAuthCode(t *testing.T) {
	const body = `{"error":{"code":"token_expired"}}`
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, body)
	}))
	setup.Proxy.AddResponseTransformer(setup.BackendHost, func(_, value any) (any, bool) {
		resp := value.(*http.Response)
		resp.StatusCode = http.StatusOK
		resp.Status = "200 OK"
		return resp, true
	})
	wait := captureLog(t, setup.Proxy)
	resp, err := setup.Client.Get(setup.Backend.URL + "/resource")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(got) != body || resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %q, err = %v", resp.StatusCode, got, err)
	}
	if data := wait(); data.StatusCode != http.StatusOK || data.UpstreamAuthCode != "" {
		t.Fatalf("logged status %d with code %q", data.StatusCode, data.UpstreamAuthCode)
	}
}

func TestQueryCredentialUpstreamAuthCodeSuppressed(t *testing.T) {
	for _, path := range []string{"http", "relay", "mcp", "connect"} {
		t.Run(path, func(t *testing.T) {
			seen := make(chan string, 1)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.URL.Query().Get("api_key")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, `{"error":{"code":"secret_token"}}`)
			})
			var p *Proxy
			var backendURL string
			var client *http.Client
			if path == "connect" {
				setup := newInterceptTestSetup(t, handler)
				p, backendURL, client = setup.Proxy, setup.Backend.URL, setup.Client
			} else {
				backend := httptest.NewServer(handler)
				t.Cleanup(backend.Close)
				p, backendURL = NewProxy(), backend.URL
			}
			wait := captureLog(t, p)
			if path == "connect" {
				resp, err := client.Get(backendURL + "/resource?api_key=secret_token")
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			} else {
				target := backendURL + "/resource?api_key=secret_token"
				if path == "relay" {
					if err := p.AddRelay("test", backendURL); err != nil {
						t.Fatal(err)
					}
					target = "/relay/test/resource?api_key=secret_token"
				} else if path == "mcp" {
					p.SetMCPServers([]MCPServerConfig{{Name: "test", URL: backendURL}})
					target = "/mcp/test/resource?api_key=secret_token"
				}
				p.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", target, nil))
			}
			if got := <-seen; got != "secret_token" {
				t.Fatal("upstream query did not carry credential")
			}
			if data := wait(); data.UpstreamAuthCode != "" {
				t.Fatal("upstream auth code exposed query credential")
			}
		})
	}
}
