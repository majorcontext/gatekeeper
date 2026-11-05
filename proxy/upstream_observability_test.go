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
		{`{"detail":{"code":"token_expired"}}`, "token_expired"},
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

func TestUpstreamUnauthorizedRedactsCredentialCode(t *testing.T) {
	resp := &http.Response{StatusCode: 401, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"error":{"code":"secret_token"}}`))}
	body := captureUpstreamAuthCode(resp, &http.Request{URL: &url.URL{}})
	_, _ = io.Copy(io.Discard, resp.Body)
	if got := upstreamAuthCode(body, nil, []CredentialHeader{{Value: "secret_token"}}, false); got != "" {
		t.Fatalf("credential logged: %s", got)
	}
	if got := upstreamAuthCode(body, http.Header{"Authorization": {"Bearer sec"}}, nil, false); got != "" {
		t.Fatalf("header credential logged: %s", got)
	}
	if got := upstreamAuthCode(body, nil, []CredentialHeader{{Value: "sec"}}, false); got != "" {
		t.Fatalf("short credential logged: %s", got)
	}
	if got := upstreamAuthCode(body, http.Header{"X-Custom-Key": {"sec"}}, nil, false); got != "" {
		t.Fatalf("custom header credential logged: %s", got)
	}
	if got := upstreamAuthCode(body, http.Header{"Accept-Language": {"sec"}}, []CredentialHeader{{Name: "Accept-Language", Value: "sec"}}, false); got != "" {
		t.Fatalf("injected language header credential logged: %s", got)
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

func TestRelayUnauthorizedCodeInRequestLog(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"detail":{"code":"token_expired"}}`)
	}))
	defer backend.Close()
	p := NewProxy()
	if err := p.AddRelay("test", backend.URL); err != nil {
		t.Fatal(err)
	}
	var logged RequestLogData
	p.SetLogger(func(d RequestLogData) { logged = d })
	r := httptest.NewRequest("GET", "/relay/test/", nil)
	p.ServeHTTP(httptest.NewRecorder(), r)
	if logged.UpstreamAuthCode != "token_expired" {
		t.Fatalf("upstream auth code = %q", logged.UpstreamAuthCode)
	}
}

func TestUpstreamUnauthorizedSecretsNotLogged(t *testing.T) {
	for _, path := range []string{"http", "connect"} {
		for _, kind := range []string{"basic", "substitution"} {
			t.Run(path+"/"+kind, func(t *testing.T) {
				const secret = "secret_token"
				seen := make(chan string, 1)
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if kind == "basic" {
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
				if kind == "basic" {
					value := "Basic " + basicAuth("user", secret)
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

func TestUpstreamUnauthorizedCodeIgnoresHeaderSyntax(t *testing.T) {
	for _, tc := range []struct {
		name        string
		code        string
		headers     http.Header
		credentials []CredentialHeader
	}{
		{"token scheme", "invalid_token", http.Header{"Authorization": {"token abc123"}}, []CredentialHeader{{Name: "Authorization", Value: "token abc123"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{StatusCode: 401, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"error":{"code":"` + tc.code + `"}}`))}
			body := captureUpstreamAuthCode(resp, &http.Request{URL: &url.URL{}})
			_, _ = io.Copy(io.Discard, resp.Body)
			if got := upstreamAuthCode(body, tc.headers, tc.credentials, false); got != tc.code {
				t.Fatalf("code = %q, want %q", got, tc.code)
			}
		})
	}
}

func TestMCPUnauthorizedCodeRedactsInjectedLanguageHeader(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Language") != "sec" {
			t.Errorf("upstream credential = %q", r.Header.Get("Accept-Language"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"code":"secret_token"}}`)
	}))
	defer backend.Close()
	p := &Proxy{credStore: &mockCredentialStore{tokens: map[string]string{"mcp-test": "sec"}}, mcpServers: []MCPServerConfig{{Name: "test", URL: backend.URL, Auth: &MCPAuthConfig{Grant: "mcp-test", Header: "Accept-Language", AllowInsecure: true}}}}
	var logged RequestLogData
	p.SetLogger(func(d RequestLogData) { logged = d })
	p.handleMCPRelay(httptest.NewRecorder(), httptest.NewRequest("POST", "/mcp/test", nil))
	if logged.UpstreamAuthCode != "" {
		t.Fatalf("code leaked credential: %q", logged.UpstreamAuthCode)
	}
}

func TestUpstreamUnauthorizedPartialCredentialRedaction(t *testing.T) {
	basic := "Basic " + basicAuth("user", "secret_token")
	for _, tc := range []struct {
		name, code string
		headers    http.Header
		injected   []CredentialHeader
		want       string
	}{
		{"custom basic injected", "secret_token", nil, []CredentialHeader{{Name: "X-Custom-Key", Value: basic}}, ""},
		{"custom basic outbound", "secret_token", http.Header{"X-Custom-Key": {basic}}, nil, ""},
		{"custom basic partial", "bad_key_abcdef12", http.Header{"X-Custom-Key": {"Basic " + basicAuth("user", "abcdef12_more")}}, nil, ""},
		{"partial injected", "bad_key_abcdef12", nil, []CredentialHeader{{Name: "X-Key", Value: "abcdef12_more"}}, ""},
		{"partial outbound", "bad_key_abcdef12", http.Header{"X-Key": {"abcdef12_more"}}, nil, ""},
		{"seven shared characters", "bad_key_abcdef1", http.Header{"X-Key": {"abcdef12_more"}}, nil, "bad_key_abcdef1"},
		{"oversized credential", "invalid_token", http.Header{"X-Key": {strings.Repeat("z", MaxBodySize+1)}}, nil, ""},
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

func TestMCPInjectedHeaderRedactsUpstreamCode(t *testing.T) {
	for _, path := range []string{"http", "connect"} {
		t.Run(path, func(t *testing.T) {
			seen := make(chan string, 1)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Header.Get("Accept-Language")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, `{"error":{"code":"bad_key_abcdef12"}}`)
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
			p.SetMCPServers([]MCPServerConfig{{Name: "test", URL: backendURL, Auth: &MCPAuthConfig{Grant: "mcp-test", Header: "Accept-Language", AllowInsecure: true}}})
			p.SetCredentialStore(&mockCredentialStore{tokens: map[string]string{"mcp-test": "abcdef12_more"}})
			wait := captureLog(t, p)
			req, err := http.NewRequest("GET", backendURL+"/resource", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Accept-Language", "gatekeeper-stub-mcp-test")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if got := <-seen; got != "abcdef12_more" {
				t.Fatalf("upstream header = %q", got)
			}
			if data := wait(); data.UpstreamAuthCode != "" {
				t.Fatalf("code leaked credential fragment: %q", data.UpstreamAuthCode)
			}
		})
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

func TestUpstreamUnauthorizedCodeSuppressesShortHeader(t *testing.T) {
	resp := &http.Response{StatusCode: 401, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"error":{"code":"token_expired"}}`))}
	body := captureUpstreamAuthCode(resp, &http.Request{URL: &url.URL{}})
	_, _ = io.Copy(io.Discard, resp.Body)
	if got := upstreamAuthCode(body, http.Header{"Accept-Language": {"en"}}, nil, false); got != "" {
		t.Fatalf("code = %q, want omission for overlapping header", got)
	}
}

func TestUserinfoUpstreamAuthCodeSuppressed(t *testing.T) {
	for _, path := range []string{"relay", "mcp"} {
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
			} else {
				p.SetMCPServers([]MCPServerConfig{{Name: "test", URL: u.String()}})
			}
			var logged RequestLogData
			p.SetLogger(func(d RequestLogData) { logged = d })
			requestPath := "/relay/test/"
			if path == "mcp" {
				requestPath = "/mcp/test"
			}
			p.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", requestPath, nil))
			if !<-seen {
				t.Fatal("upstream did not receive expected Basic credentials")
			}
			if logged.UpstreamAuthCode != "" {
				t.Fatal("upstream auth code exposed userinfo")
			}
		})
	}
}

func TestPlainHTTPUserinfoUpstreamAuthCodeSuppressed(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"code":"secret_token"}}`)
	}))
	defer backend.Close()
	u := mustParseURL(backend.URL)
	u.User = url.UserPassword("user", "secret_token")
	p := NewProxy()
	var logged RequestLogData
	p.SetLogger(func(d RequestLogData) { logged = d })
	p.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", u.String(), nil))
	if logged.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d", logged.StatusCode)
	}
	if logged.UpstreamAuthCode != "" {
		t.Fatal("upstream auth code exposed userinfo")
	}
}
