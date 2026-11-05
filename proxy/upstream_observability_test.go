package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
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
			body := captureUpstreamAuthCode(resp)
			_, _ = io.Copy(io.Discard, resp.Body)
			if got := upstreamAuthCode(body, nil, nil, false); got != tc.want {
				t.Errorf("code = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestUpstreamUnauthorizedRedactsCredentialCode(t *testing.T) {
	resp := &http.Response{StatusCode: 401, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"error":{"code":"secret_token"}}`))}
	body := captureUpstreamAuthCode(resp)
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
}

func TestUpstreamUnauthorizedCaptureStreamsUnchanged(t *testing.T) {
	body := `{"detail":{"code":"token_expired"}}`
	resp := &http.Response{StatusCode: 401, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
	captured := captureUpstreamAuthCode(resp)
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
