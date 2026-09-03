package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A host can carry both a resolver and a static credential on DIFFERENT
// headers, each serving a different client. On api.anthropic.com the boxes
// deployment runs a token exchange for Claude Code's subscription on
// Authorization alongside an app's API key on x-api-key.
//
// Each client sends its own header as a placeholder, which is how
// injectCredentials tells them apart. Before these credentials were merged the
// resolver's result replaced the static one outright, so the app's placeholder
// went upstream unreplaced and Anthropic answered "invalid x-api-key".
func TestProxy_ResolverAndStaticOnDifferentHeaders(t *testing.T) {
	var gotAuth, gotAPIKey string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAPIKey = r.Header.Get("x-api-key")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetCredentialWithGrant("127.0.0.1", "x-api-key", "real-api-key", "app")
	p.SetCredentialResolverWithStripHeaders("127.0.0.1",
		func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]credentialHeader, error) {
			return []credentialHeader{{Name: "Authorization", Value: "Bearer resolved", Grant: "subscription"}}, nil
		})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustParseURL(proxyServer.URL))}}

	send := func(header, value string) {
		t.Helper()
		gotAuth, gotAPIKey = "", ""
		req, _ := http.NewRequest("GET", backend.URL, nil)
		req.Header.Set(header, value)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request with %s: %v", header, err)
		}
		resp.Body.Close()
	}

	send("x-api-key", "placeholder")
	if gotAPIKey != "real-api-key" {
		t.Errorf("x-api-key = %q, want the static credential", gotAPIKey)
	}
	if gotAuth != "" {
		t.Errorf("Authorization = %q, want none: this client asked for x-api-key", gotAuth)
	}

	send("Authorization", "placeholder")
	if gotAuth != "Bearer resolved" {
		t.Errorf("Authorization = %q, want the resolver's credential", gotAuth)
	}
	if gotAPIKey != "" {
		t.Errorf("x-api-key = %q, want none: this client asked for Authorization", gotAPIKey)
	}
}

// A static credential sharing the resolver's header stays dropped: on
// api.github.com the token exchange and the GitHub App key both target
// Authorization, and the exchange must keep winning it.
func TestProxy_ResolverStillWinsItsOwnHeader(t *testing.T) {
	var gotAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetCredentialWithGrant("127.0.0.1", "Authorization", "Bearer static-fallback", "app-fallback")
	p.SetCredentialResolverWithStripHeaders("127.0.0.1",
		func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]credentialHeader, error) {
			return []credentialHeader{{Name: "Authorization", Value: "Bearer resolved", Grant: "subscription"}}, nil
		})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustParseURL(proxyServer.URL))}}
	req, _ := http.NewRequest("GET", backend.URL, nil)
	req.Header.Set("Authorization", "placeholder")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if gotAuth != "Bearer resolved" {
		t.Errorf("Authorization = %q, want the resolver's credential to win its own header", gotAuth)
	}
}

// A request carrying neither header must not collect both credentials.
// injectCredentials auto-injects every credential it is given when a client
// sends none of their headers, so a merge that ignored what the client asked
// for would attach the resolver's per-user token to requests that never
// wanted it.
func TestProxy_NoPlaceholderDoesNotFanOutCredentials(t *testing.T) {
	var gotAuth, gotAPIKey string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAPIKey = r.Header.Get("x-api-key")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetCredentialWithGrant("127.0.0.1", "x-api-key", "real-api-key", "app")
	p.SetCredentialResolverWithStripHeaders("127.0.0.1",
		func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]credentialHeader, error) {
			return []credentialHeader{{Name: "Authorization", Value: "Bearer resolved", Grant: "subscription"}}, nil
		})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustParseURL(proxyServer.URL))}}
	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if gotAPIKey != "" {
		t.Errorf("x-api-key = %q, want none: the client asked for no credential", gotAPIKey)
	}
	if gotAuth != "Bearer resolved" {
		t.Errorf("Authorization = %q, want the resolver's credential, matching the behaviour before static merging", gotAuth)
	}
}
