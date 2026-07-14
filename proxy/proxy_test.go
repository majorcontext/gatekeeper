package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestProxy_ForwardsRequests(t *testing.T) {
	// Create a test backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	// Create proxy
	p := NewProxy()

	// Create proxy server
	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	// Make request through proxy
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "backend response" {
		t.Errorf("body = %q, want %q", string(body), "backend response")
	}
}

func TestProxy_InjectsAuthHeader(t *testing.T) {
	var receivedAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetCredential("127.0.0.1", "Bearer test-token")

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	req, _ := http.NewRequest("GET", backend.URL, nil)
	req.Header.Set("Authorization", "placeholder")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if receivedAuth != "Bearer test-token" {
		t.Errorf("Authorization = %q, want %q", receivedAuth, "Bearer test-token")
	}
}

func TestProxy_AuthTokenRequired(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetAuthToken("secret-token-123")

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	// Request without auth should fail
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("status = %d, want %d (Proxy Auth Required)", resp.StatusCode, http.StatusProxyAuthRequired)
	}
	if got := resp.Header.Get("Proxy-Authenticate"); got != `Basic realm="gatekeeper"` {
		t.Errorf("Proxy-Authenticate = %q, want %q", got, `Basic realm="gatekeeper"`)
	}
}

func TestProxy_AuthTokenValidBasicAuth(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetAuthToken("secret-token-123")

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	// Request with valid Basic auth (username:token format) should succeed
	proxyURL := mustParseURL(proxyServer.URL)
	proxyURL.User = url.UserPassword("moat", "secret-token-123")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "backend response" {
		t.Errorf("body = %q, want %q", string(body), "backend response")
	}
}

func TestProxy_AuthTokenInvalidToken(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetAuthToken("secret-token-123")

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	// Request with wrong token should fail
	proxyURL := mustParseURL(proxyServer.URL)
	proxyURL.User = url.UserPassword("moat", "wrong-token")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("status = %d, want %d (Proxy Auth Required)", resp.StatusCode, http.StatusProxyAuthRequired)
	}
	if got := resp.Header.Get("Proxy-Authenticate"); got != `Basic realm="gatekeeper"` {
		t.Errorf("Proxy-Authenticate = %q, want %q", got, `Basic realm="gatekeeper"`)
	}
}

func TestProxy_DelegateAuthSkipsStaticCheck(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetAuthToken("static-token")
	p.SetDelegateAuth(true)

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	// With delegateAuth, a different password should pass the static check.
	proxyURL := mustParseURL(proxyServer.URL)
	proxyURL.User = url.UserPassword("alice", "per-user-api-key")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d; delegateAuth should skip static authToken check", resp.StatusCode, http.StatusOK)
	}
}

func TestProxy_DelegateAuthBlocksAnonymous(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	tests := []struct {
		name      string
		authToken string
	}{
		{"with auth_token", "static-token"},
		{"without auth_token", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewProxy()
			if tt.authToken != "" {
				p.SetAuthToken(tt.authToken)
			}
			p.SetDelegateAuth(true)

			proxyServer := httptest.NewServer(p)
			defer proxyServer.Close()

			client := &http.Client{
				Transport: &http.Transport{
					Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
				},
			}

			resp, err := client.Get(backend.URL)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			resp.Body.Close()

			if resp.StatusCode != http.StatusProxyAuthRequired {
				t.Errorf("status = %d, want %d; delegateAuth should require proxy auth credentials", resp.StatusCode, http.StatusProxyAuthRequired)
			}
		})
	}
}

func TestProxy_DelegateAuthBlocksEmptyPassword(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetDelegateAuth(true)

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	// Basic auth with empty password ("alice:") should be rejected.
	proxyURL := mustParseURL(proxyServer.URL)
	proxyURL.User = url.UserPassword("alice", "")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("status = %d, want %d; delegateAuth should reject empty password", resp.StatusCode, http.StatusProxyAuthRequired)
	}
}

func TestProxy_DelegateAuthRejectsBearerAuth(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetDelegateAuth(true)

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			ProxyConnectHeader: http.Header{
				"Proxy-Authorization": {"Bearer some-token"},
			},
			TLSClientConfig: backend.Client().Transport.(*http.Transport).TLSClientConfig,
		},
	}

	_, err := client.Get(backend.URL)
	if err == nil {
		t.Fatal("expected error for Bearer auth with delegateAuth, got nil")
	}
	if !strings.Contains(err.Error(), "Proxy Authentication Required") {
		t.Errorf("error = %v, want to contain 'Proxy Authentication Required'", err)
	}
}

func TestProxy_NetworkPolicyPermissive(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetNetworkPolicy("permissive", []string{}, []string{})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestProxy_NetworkPolicyStrictBlocked(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	p := NewProxy()
	// Set strict policy with no allowed hosts
	p.SetNetworkPolicy("strict", []string{}, []string{})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusProxyAuthRequired)
	}

	if resp.Header.Get("X-Moat-Blocked") != "request-rule" {
		t.Errorf("X-Moat-Blocked header missing or wrong")
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "blocked by network policy") {
		t.Errorf("response body should mention network policy blocking")
	}
}

func TestProxy_NetworkPolicyStrictAllowed(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	// Extract port from backend URL to allow it
	backendURL := mustParseURL(backend.URL)
	allowPattern := "127.0.0.1:" + backendURL.Port()

	p := NewProxy()
	// Allow localhost/127.0.0.1 with the specific port
	p.SetNetworkPolicy("strict", []string{allowPattern}, []string{})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "backend response" {
		t.Errorf("body = %q, want %q", string(body), "backend response")
	}
}

func TestProxy_NetworkPolicyWithGrants(t *testing.T) {
	p := NewProxy()
	// Set policy with github grant
	p.SetNetworkPolicy("strict", []string{}, []string{"github"})

	// Should allow github.com (port 443)
	if !p.checkNetworkPolicy("github.com", 443) {
		t.Errorf("github.com:443 should be allowed with github grant")
	}

	// Should allow api.github.com (port 443)
	if !p.checkNetworkPolicy("api.github.com", 443) {
		t.Errorf("api.github.com:443 should be allowed with github grant")
	}

	// Should allow wildcard match for githubusercontent.com
	if !p.checkNetworkPolicy("raw.githubusercontent.com", 443) {
		t.Errorf("raw.githubusercontent.com:443 should be allowed with github grant (wildcard)")
	}

	// Should block non-github hosts
	if p.checkNetworkPolicy("example.com", 443) {
		t.Errorf("example.com:443 should be blocked")
	}
}

func TestProxy_NetworkPolicyMixedAllowsAndGrants(t *testing.T) {
	p := NewProxy()
	// Combine explicit allows and grants
	p.SetNetworkPolicy("strict", []string{"api.example.com"}, []string{"github"})

	// Should allow explicit pattern
	if !p.checkNetworkPolicy("api.example.com", 443) {
		t.Errorf("api.example.com:443 should be allowed (explicit)")
	}

	// Should allow github from grant
	if !p.checkNetworkPolicy("github.com", 443) {
		t.Errorf("github.com:443 should be allowed (grant)")
	}

	// Should block others
	if p.checkNetworkPolicy("evil.com", 443) {
		t.Errorf("evil.com:443 should be blocked")
	}
}

func TestProxy_NetworkPolicyLogging(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetNetworkPolicy("strict", []string{}, []string{}) // Block everything

	var loggedMethod string
	var loggedStatus int

	p.SetLogger(func(data RequestLogData) {
		loggedMethod = data.Method
		loggedStatus = data.StatusCode
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if loggedStatus != http.StatusProxyAuthRequired {
		t.Errorf("logged status = %d, want %d", loggedStatus, http.StatusProxyAuthRequired)
	}

	if loggedMethod != "GET" {
		t.Errorf("logged method = %q, want GET", loggedMethod)
	}
}

func TestProxy_CanonicalLogLine_SuccessfulRequest(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "7")
		w.Write([]byte("ok body"))
	}))
	defer backend.Close()

	backendURL := mustParseURL(backend.URL)
	host := backendURL.Hostname()

	p := NewProxy()
	p.SetCredentialWithGrant(host, "Authorization", "Bearer test-token", "myservice")

	var logged RequestLogData
	p.SetLogger(func(data RequestLogData) {
		logged = data
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	req, _ := http.NewRequest("GET", backend.URL+"/api/v1/test", nil)
	req.Header.Set("Authorization", "placeholder")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if logged.Method != "GET" {
		t.Errorf("Method = %q, want GET", logged.Method)
	}
	if logged.Host != host {
		t.Errorf("Host = %q, want %q", logged.Host, host)
	}
	if logged.Path != "/api/v1/test" {
		t.Errorf("Path = %q, want /api/v1/test", logged.Path)
	}
	if logged.RequestType != "http" {
		t.Errorf("RequestType = %q, want http", logged.RequestType)
	}
	if logged.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", logged.StatusCode, http.StatusOK)
	}
	if logged.Duration <= 0 {
		t.Error("Duration should be positive")
	}
	if !logged.AuthInjected {
		t.Error("AuthInjected should be true")
	}
	if !logged.InjectedHeaders["authorization"] {
		t.Errorf("InjectedHeaders = %v, want authorization key", logged.InjectedHeaders)
	}
	if len(logged.Grants) != 1 || logged.Grants[0] != "myservice" {
		t.Errorf("Grants = %v, want [myservice]", logged.Grants)
	}
	if logged.Denied {
		t.Error("Denied should be false for allowed request")
	}
	if logged.Err != nil {
		t.Errorf("Err = %v, want nil", logged.Err)
	}
	if logged.ResponseSize != 7 {
		t.Errorf("ResponseSize = %d, want 7", logged.ResponseSize)
	}
}

func TestProxy_CanonicalLogLine_PolicyDenied(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("should not reach"))
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetNetworkPolicy("strict", []string{}, nil)

	var logged RequestLogData
	p.SetLogger(func(data RequestLogData) {
		logged = data
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	backendURL := mustParseURL(backend.URL)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if logged.Method != "GET" {
		t.Errorf("Method = %q, want GET", logged.Method)
	}
	if logged.Host != backendURL.Hostname() {
		t.Errorf("Host = %q, want %q", logged.Host, backendURL.Hostname())
	}
	if logged.RequestType != "http" {
		t.Errorf("RequestType = %q, want http", logged.RequestType)
	}
	if logged.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("StatusCode = %d, want %d", logged.StatusCode, http.StatusProxyAuthRequired)
	}
	if !logged.Denied {
		t.Error("Denied should be true for blocked request")
	}
	if logged.DenyReason == "" {
		t.Error("DenyReason should be set for blocked request")
	}
	if !strings.Contains(logged.DenyReason, backendURL.Hostname()) {
		t.Errorf("DenyReason = %q, should contain host %q", logged.DenyReason, backendURL.Hostname())
	}
	if logged.AuthInjected {
		t.Error("AuthInjected should be false for blocked request")
	}
	if logged.ResponseSize != -1 {
		t.Errorf("ResponseSize = %d, want -1 (no response)", logged.ResponseSize)
	}
}

func TestProxy_CanonicalLogLine_UpstreamError(t *testing.T) {
	p := NewProxy()

	var logged RequestLogData
	p.SetLogger(func(data RequestLogData) {
		logged = data
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	// Point at a port nothing is listening on.
	resp, err := client.Get("http://127.0.0.1:1/nope")
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	resp.Body.Close()

	if logged.Method != "GET" {
		t.Errorf("Method = %q, want GET", logged.Method)
	}
	if logged.Host != "127.0.0.1" {
		t.Errorf("Host = %q, want 127.0.0.1", logged.Host)
	}
	if logged.Path != "/nope" {
		t.Errorf("Path = %q, want /nope", logged.Path)
	}
	if logged.RequestType != "http" {
		t.Errorf("RequestType = %q, want http", logged.RequestType)
	}
	if logged.Err == nil {
		t.Error("Err should be set for upstream failure")
	}
	if logged.ResponseSize != -1 {
		t.Errorf("ResponseSize = %d, want -1 (no response)", logged.ResponseSize)
	}
}

func TestProxy_CanonicalLogLine_MultipleGrants(t *testing.T) {
	var receivedAuth, receivedAPIKey string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedAPIKey = r.Header.Get("x-api-key")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	backendURL := mustParseURL(backend.URL)
	host := backendURL.Hostname()

	p := NewProxy()
	p.SetCredentialWithGrant(host, "Authorization", "Bearer token1", "github")
	p.SetCredentialWithGrant(host, "x-api-key", "sk-ant-key", "anthropic")

	var logged RequestLogData
	p.SetLogger(func(data RequestLogData) {
		logged = data
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	resp, err := client.Get(backend.URL + "/multi")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if receivedAuth != "Bearer token1" {
		t.Errorf("Authorization = %q, want Bearer token1", receivedAuth)
	}
	if receivedAPIKey != "sk-ant-key" {
		t.Errorf("x-api-key = %q, want sk-ant-key", receivedAPIKey)
	}

	if !logged.AuthInjected {
		t.Error("AuthInjected should be true")
	}
	if len(logged.Grants) != 2 {
		t.Errorf("Grants = %v, want 2 entries", logged.Grants)
	}

	grantSet := make(map[string]bool)
	for _, g := range logged.Grants {
		grantSet[g] = true
	}
	if !grantSet["github"] || !grantSet["anthropic"] {
		t.Errorf("Grants = %v, want github and anthropic", logged.Grants)
	}

	if !logged.InjectedHeaders["authorization"] || !logged.InjectedHeaders["x-api-key"] {
		t.Errorf("InjectedHeaders = %v, want authorization and x-api-key", logged.InjectedHeaders)
	}
}

func TestProxy_CanonicalLogLine_ConnectBlocked(t *testing.T) {
	p := NewProxy()
	p.SetNetworkPolicy("strict", []string{}, nil)

	var logged RequestLogData
	p.SetLogger(func(data RequestLogData) {
		logged = data
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	// Issue a CONNECT through the proxy to a blocked host.
	conn, err := net.Dial("tcp", proxyServer.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	_, _ = fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if logged.Method != "CONNECT" {
		t.Errorf("Method = %q, want CONNECT", logged.Method)
	}
	if logged.Host != "example.com" {
		t.Errorf("Host = %q, want example.com", logged.Host)
	}
	if logged.RequestType != "connect" {
		t.Errorf("RequestType = %q, want connect", logged.RequestType)
	}
	if logged.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("StatusCode = %d, want %d", logged.StatusCode, http.StatusProxyAuthRequired)
	}
	if !logged.Denied {
		t.Error("Denied should be true")
	}
	if logged.DenyReason == "" {
		t.Error("DenyReason should be set")
	}
	if !strings.Contains(logged.DenyReason, "example.com") {
		t.Errorf("DenyReason = %q, should mention example.com", logged.DenyReason)
	}
	if logged.RequestSize != -1 {
		t.Errorf("RequestSize = %d, want -1", logged.RequestSize)
	}
	if logged.ResponseSize != -1 {
		t.Errorf("ResponseSize = %d, want -1", logged.ResponseSize)
	}
}

func TestProxy_CanonicalLogLine_ConnectTransportError(t *testing.T) {
	ca, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}

	p := NewProxy()
	p.SetCA(ca)

	var logged RequestLogData
	var logOnce sync.Once
	p.SetLogger(func(data RequestLogData) {
		logOnce.Do(func() { logged = data })
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	// Configure client to trust our test CA.
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(ca.certPEM)

	proxyURL := mustParseURL(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
			},
		},
	}

	// CONNECT to a port nothing listens on — the proxy intercepts TLS,
	// then transport.RoundTrip fails upstream. The proxy writes a 502
	// back over the intercepted TLS connection.
	resp, err := client.Get("https://127.0.0.1:1/nope")
	if err != nil {
		t.Fatalf("request through proxy: %v", err)
	}
	resp.Body.Close()

	if logged.Method != "GET" {
		t.Errorf("Method = %q, want GET", logged.Method)
	}
	if logged.Host != "127.0.0.1" {
		t.Errorf("Host = %q, want 127.0.0.1", logged.Host)
	}
	if logged.RequestType != "connect" {
		t.Errorf("RequestType = %q, want connect", logged.RequestType)
	}
	if logged.StatusCode != http.StatusBadGateway {
		t.Errorf("StatusCode = %d, want %d", logged.StatusCode, http.StatusBadGateway)
	}
	if logged.Err == nil {
		t.Error("Err should be set for transport failure")
	}
}

func TestProxy_CanonicalLogLine_NoCredentials(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()

	var logged RequestLogData
	p.SetLogger(func(data RequestLogData) {
		logged = data
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	resp, err := client.Get(backend.URL + "/plain")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if logged.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", logged.StatusCode)
	}
	if logged.AuthInjected {
		t.Error("AuthInjected should be false when no credentials configured")
	}
	if len(logged.Grants) != 0 {
		t.Errorf("Grants = %v, want empty", logged.Grants)
	}
	if len(logged.InjectedHeaders) > 0 {
		t.Errorf("InjectedHeaders = %v, want empty", logged.InjectedHeaders)
	}
	if logged.Denied {
		t.Error("Denied should be false")
	}
}

func TestProxy_RequestID_Generated(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()

	var logged RequestLogData
	p.SetLogger(func(data RequestLogData) {
		logged = data
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	resp, err := client.Get(backend.URL + "/test")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if logged.RequestID == "" {
		t.Fatal("RequestID should be generated when X-Request-Id is not set")
	}
	if !strings.HasPrefix(logged.RequestID, "req_") {
		t.Errorf("RequestID = %q, want prefix req_", logged.RequestID)
	}
	if respID := resp.Header.Get("X-Request-Id"); respID != logged.RequestID {
		t.Errorf("response X-Request-Id = %q, want %q", respID, logged.RequestID)
	}
}

func TestProxy_RequestID_FromHeader(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()

	var logged RequestLogData
	p.SetLogger(func(data RequestLogData) {
		logged = data
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	req, _ := http.NewRequest("GET", backend.URL+"/test", nil)
	req.Header.Set("X-Request-Id", "req_caller-provided-id")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if logged.RequestID != "req_caller-provided-id" {
		t.Errorf("RequestID = %q, want %q", logged.RequestID, "req_caller-provided-id")
	}
	if respID := resp.Header.Get("X-Request-Id"); respID != "req_caller-provided-id" {
		t.Errorf("response X-Request-Id = %q, want %q", respID, "req_caller-provided-id")
	}
}

func TestProxy_RequestID_Unique(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()

	var ids []string
	var mu sync.Mutex
	p.SetLogger(func(data RequestLogData) {
		mu.Lock()
		ids = append(ids, data.RequestID)
		mu.Unlock()
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	for i := 0; i < 10; i++ {
		resp, err := client.Get(backend.URL + "/test")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
	}

	seen := make(map[string]bool)
	for _, id := range ids {
		if seen[id] {
			t.Errorf("duplicate RequestID: %s", id)
		}
		seen[id] = true
	}
}

func TestProxy_RequestID_ForwardedToUpstream(t *testing.T) {
	var upstreamReqID string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamReqID = r.Header.Get("X-Request-Id")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()

	var logged RequestLogData
	p.SetLogger(func(data RequestLogData) {
		logged = data
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	resp, err := client.Get(backend.URL + "/test")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if upstreamReqID == "" {
		t.Fatal("upstream did not receive X-Request-Id header")
	}
	if upstreamReqID != logged.RequestID {
		t.Errorf("upstream X-Request-Id = %q, want %q (logged)", upstreamReqID, logged.RequestID)
	}
}

func TestProxy_RequestID_PreservesClientHeader(t *testing.T) {
	var upstreamReqID string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamReqID = r.Header.Get("X-Request-Id")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	req, _ := http.NewRequest("GET", backend.URL+"/test", nil)
	req.Header.Set("X-Request-Id", "client-provided-id")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if upstreamReqID != "client-provided-id" {
		t.Errorf("upstream X-Request-Id = %q, want %q", upstreamReqID, "client-provided-id")
	}
}

func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func basicAuth(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

// TestProxy_SetCredentialHeader tests custom header injection (e.g., x-api-key for Anthropic).
func TestProxy_SetCredentialHeader(t *testing.T) {
	var receivedHeader string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("x-api-key")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetCredentialHeader("127.0.0.1", "x-api-key", "sk-ant-test-key")

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	req, _ := http.NewRequest("GET", backend.URL, nil)
	req.Header.Set("x-api-key", "placeholder")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if receivedHeader != "sk-ant-test-key" {
		t.Errorf("x-api-key = %q, want %q", receivedHeader, "sk-ant-test-key")
	}
}

// TestProxy_SetCredential_UsesAuthorizationHeader verifies SetCredential uses Authorization header.
func TestProxy_SetCredential_UsesAuthorizationHeader(t *testing.T) {
	p := NewProxy()
	p.SetCredential("api.example.com", "Bearer token123")

	creds := p.getCredentials("api.example.com")
	if len(creds) == 0 {
		t.Fatal("expected credential to be set")
	}
	cred := creds[0]
	if cred.Name != "Authorization" {
		t.Errorf("header name = %q, want %q", cred.Name, "Authorization")
	}
	if cred.Value != "Bearer token123" {
		t.Errorf("header value = %q, want %q", cred.Value, "Bearer token123")
	}
}

// TestProxy_GetCredentials_WildcardKey verifies that a credential registered
// under a wildcard host key like "*.box.example.com" matches real subdomains
// using the same suffix rule as network allow patterns: any subdomain at any
// depth matches, but the apex domain does not. Exact keys take precedence
// over wildcard keys.
func TestProxy_GetCredentials_WildcardKey(t *testing.T) {
	p := NewProxy()
	p.SetCredentialWithGrant("*.box.example.com", "Cf-Access-Client-Id", "client-id-123", "cloudflare-access")

	tests := []struct {
		name      string
		host      string
		wantMatch bool
	}{
		{"single-label subdomain", "alpha.box.example.com", true},
		{"subdomain with port", "alpha.box.example.com:443", true},
		{"deep subdomain", "a.b.box.example.com", true},
		{"apex does not match", "box.example.com", false},
		{"unrelated host", "evil-box.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds := p.getCredentials(tt.host)
			if tt.wantMatch {
				if len(creds) != 1 {
					t.Fatalf("getCredentials(%q) returned %d credentials, want 1", tt.host, len(creds))
				}
				if creds[0].Grant != "cloudflare-access" {
					t.Errorf("grant = %q, want %q", creds[0].Grant, "cloudflare-access")
				}
			} else if len(creds) != 0 {
				t.Errorf("getCredentials(%q) returned %d credentials, want 0", tt.host, len(creds))
			}
		})
	}

	t.Run("most specific wildcard wins when keys overlap", func(t *testing.T) {
		p := NewProxy()
		p.SetCredentialWithGrant("*.example.com", "Authorization", "Bearer broad-token", "broad-grant")
		p.SetCredentialWithGrant("*.box.example.com", "Authorization", "Bearer narrow-token", "narrow-grant")
		// Map iteration order is randomized per range statement, so a
		// first-match implementation picks each key about half the time.
		// Repeat the lookup so a non-deterministic pick cannot pass by luck.
		for i := range 100 {
			creds := p.getCredentials("alpha.box.example.com")
			if len(creds) != 1 {
				t.Fatalf("getCredentials returned %d credentials, want 1", len(creds))
			}
			if creds[0].Grant != "narrow-grant" {
				t.Fatalf("iteration %d: grant = %q, want %q (most specific wildcard must win)", i, creds[0].Grant, "narrow-grant")
			}
		}
	})

	t.Run("exact key takes precedence", func(t *testing.T) {
		p.SetCredentialWithGrant("exact.box.example.com", "Authorization", "Bearer exact-token", "exact-grant")
		creds := p.getCredentials("exact.box.example.com")
		if len(creds) != 1 {
			t.Fatalf("getCredentials returned %d credentials, want 1", len(creds))
		}
		if creds[0].Grant != "exact-grant" {
			t.Errorf("grant = %q, want %q (exact key must win over wildcard)", creds[0].Grant, "exact-grant")
		}
	})
}

// TestProxy_GetCredentialResolver_WildcardKey verifies that a credential
// resolver registered under a wildcard host key matches real subdomains with
// the same rules as static credentials: any-depth subdomains match, the apex
// does not, and an exact key takes precedence over a wildcard key.
func TestProxy_GetCredentialResolver_WildcardKey(t *testing.T) {
	grantResolver := func(grant string) CredentialResolver {
		return func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]credentialHeader, error) {
			return []credentialHeader{{Name: "Authorization", Value: "Bearer " + grant, Grant: grant}}, nil
		}
	}
	p := NewProxy()
	p.SetCredentialResolver("*.box.example.com", grantResolver("wildcard-grant"))
	p.SetCredentialResolver("exact.box.example.com", grantResolver("exact-grant"))

	resolve := func(t *testing.T, host string) []credentialHeader {
		t.Helper()
		r := p.getCredentialResolver(host)
		if r == nil {
			return nil
		}
		req := httptest.NewRequest("GET", "https://"+host+"/", nil)
		creds, err := r(context.Background(), req, req, host)
		if err != nil {
			t.Fatalf("resolver(%q): %v", host, err)
		}
		return creds
	}

	tests := []struct {
		name      string
		host      string
		wantGrant string // "" means no resolver must match
	}{
		{"single-label subdomain", "alpha.box.example.com", "wildcard-grant"},
		{"subdomain with port", "alpha.box.example.com:443", "wildcard-grant"},
		{"deep subdomain", "a.b.box.example.com", "wildcard-grant"},
		{"apex does not match", "box.example.com", ""},
		{"unrelated host", "evil-box.example.com", ""},
		{"exact key takes precedence", "exact.box.example.com", "exact-grant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds := resolve(t, tt.host)
			if tt.wantGrant == "" {
				if creds != nil {
					t.Fatalf("getCredentialResolver(%q) matched grant %q, want no match", tt.host, creds[0].Grant)
				}
				return
			}
			if len(creds) != 1 || creds[0].Grant != tt.wantGrant {
				t.Fatalf("getCredentialResolver(%q) = %v, want grant %q", tt.host, creds, tt.wantGrant)
			}
		})
	}
}

// TestProxy_GetCredentialsForRequest_RunContextWildcardKey verifies that
// wildcard credential host keys work in RunContextData mode (per-run
// credentials), not just in the proxy-level credentials map.
func TestProxy_GetCredentialsForRequest_RunContextWildcardKey(t *testing.T) {
	p := NewProxy()
	rc := &RunContextData{
		Credentials: map[string][]credentialHeader{
			"*.box.example.com": {{Name: "Cf-Access-Client-Id", Value: "client-id-123", Grant: "cloudflare-access"}},
		},
	}
	req := httptest.NewRequest("GET", "https://alpha.box.example.com/", nil)
	req = req.WithContext(context.WithValue(req.Context(), runContextKey, rc))

	creds, err := p.getCredentialsForRequest(req, req, "alpha.box.example.com")
	if err != nil {
		t.Fatalf("getCredentialsForRequest: %v", err)
	}
	if len(creds) != 1 || creds[0].Grant != "cloudflare-access" {
		t.Fatalf("getCredentialsForRequest(alpha.box.example.com) = %v, want cloudflare-access credential", creds)
	}

	apexCreds, err := p.getCredentialsForRequest(req, req, "box.example.com")
	if err != nil {
		t.Fatalf("getCredentialsForRequest(apex): %v", err)
	}
	if len(apexCreds) != 0 {
		t.Fatalf("getCredentialsForRequest(box.example.com) = %v, want none (apex excluded)", apexCreds)
	}
}

// TestProxy_GetCredentialsForRequest_ExactStaticBeatsWildcardResolver verifies
// cross-map precedence: an exact-keyed static credential wins over a
// wildcard-keyed resolver for the same host, while the resolver still serves
// hosts with no exact static entry.
func TestProxy_GetCredentialsForRequest_ExactStaticBeatsWildcardResolver(t *testing.T) {
	p := NewProxy()
	p.SetCredentialWithGrant("api.example.com", "Authorization", "Bearer static-token", "static-grant")
	p.SetCredentialResolver("*.example.com", func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]credentialHeader, error) {
		return []credentialHeader{{Name: "Authorization", Value: "Bearer resolver-token", Grant: "resolver-grant"}}, nil
	})
	req := httptest.NewRequest("GET", "https://api.example.com/", nil)

	creds, err := p.getCredentialsForRequest(req, req, "api.example.com")
	if err != nil {
		t.Fatalf("getCredentialsForRequest: %v", err)
	}
	if len(creds) != 1 || creds[0].Grant != "static-grant" {
		t.Fatalf("getCredentialsForRequest(api.example.com) grant = %v, want static-grant (exact static must beat wildcard resolver)", creds)
	}

	creds, err = p.getCredentialsForRequest(req, req, "other.example.com")
	if err != nil {
		t.Fatalf("getCredentialsForRequest(other): %v", err)
	}
	if len(creds) != 1 || creds[0].Grant != "resolver-grant" {
		t.Fatalf("getCredentialsForRequest(other.example.com) grant = %v, want resolver-grant", creds)
	}
}

// TestProxy_GetCredentials_MixedCaseHost verifies that a mixed-case request
// host still resolves its exact-keyed credential in preference to a wildcard
// key: exact matching must be as case-insensitive as wildcard matching, or
// the documented exact-over-wildcard precedence inverts for such hosts.
func TestProxy_GetCredentials_MixedCaseHost(t *testing.T) {
	p := NewProxy()
	p.SetCredentialWithGrant("special.box.example.com", "Authorization", "Bearer exact-token", "exact-grant")
	p.SetCredentialWithGrant("*.box.example.com", "Authorization", "Bearer wild-token", "wild-grant")

	creds := p.getCredentials("Special.box.example.com")
	if len(creds) != 1 {
		t.Fatalf("getCredentials returned %d credentials, want 1", len(creds))
	}
	if creds[0].Grant != "exact-grant" {
		t.Fatalf("grant = %q, want %q (case-variant host must still hit the exact key)", creds[0].Grant, "exact-grant")
	}
}

// TestProxy_GetCredentials_CaseVariantKeysDeterministic verifies that when
// the same host is (unusually) registered under two different casings, a
// third-casing request resolves to a deterministic winner — the
// lexicographically smallest key — rather than whichever key Go's randomized
// map iteration reaches first.
func TestProxy_GetCredentials_CaseVariantKeysDeterministic(t *testing.T) {
	p := NewProxy()
	p.SetCredentialWithGrant("API.example.com", "Authorization", "Bearer upper-token", "upper-grant")
	p.SetCredentialWithGrant("api.example.com", "Authorization", "Bearer lower-token", "lower-grant")

	// Map iteration order is randomized per range statement; repeat the
	// lookup so a first-match implementation cannot pass by luck.
	for i := range 100 {
		creds := p.getCredentials("Api.example.com")
		if len(creds) != 1 {
			t.Fatalf("getCredentials returned %d credentials, want 1", len(creds))
		}
		if creds[0].Grant != "upper-grant" {
			t.Fatalf("iteration %d: grant = %q, want %q (lexicographically smallest case-variant key must win)", i, creds[0].Grant, "upper-grant")
		}
	}
}

// TestProxy_GetCredentialsForRequest_MoreSpecificWildcardStaticBeatsResolver
// verifies cross-map wildcard specificity: when a static credential and a
// resolver both match via wildcard keys, the more specific (longer) key wins
// regardless of which map it lives in.
func TestProxy_GetCredentialsForRequest_MoreSpecificWildcardStaticBeatsResolver(t *testing.T) {
	p := NewProxy()
	p.SetCredentialWithGrant("*.api.example.com", "Authorization", "Bearer static-token", "static-grant")
	p.SetCredentialResolver("*.example.com", func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]credentialHeader, error) {
		return []credentialHeader{{Name: "Authorization", Value: "Bearer resolver-token", Grant: "resolver-grant"}}, nil
	})
	req := httptest.NewRequest("GET", "https://svc.api.example.com/", nil)

	creds, err := p.getCredentialsForRequest(req, req, "svc.api.example.com")
	if err != nil {
		t.Fatalf("getCredentialsForRequest: %v", err)
	}
	if len(creds) != 1 || creds[0].Grant != "static-grant" {
		t.Fatalf("grant = %v, want static-grant (*.api.example.com static must beat *.example.com resolver)", creds)
	}
}

// TestProxy_GetCredentialsForRequest_EmptyExactEntryFallsThrough verifies
// that a present-but-empty entry in an embedder-supplied RunContextData
// credentials map does not shadow a populated bare-host entry — matching the
// pre-refactor len>0 gating.
func TestProxy_GetCredentialsForRequest_EmptyExactEntryFallsThrough(t *testing.T) {
	p := NewProxy()
	rc := &RunContextData{
		Credentials: map[string][]credentialHeader{
			"api.example.com:443": {},
			"api.example.com":     {{Name: "Authorization", Value: "Bearer tok", Grant: "the-grant"}},
		},
	}
	req := httptest.NewRequest("GET", "https://api.example.com/", nil)
	req = req.WithContext(context.WithValue(req.Context(), runContextKey, rc))

	creds, err := p.getCredentialsForRequest(req, req, "api.example.com:443")
	if err != nil {
		t.Fatalf("getCredentialsForRequest: %v", err)
	}
	if len(creds) != 1 || creds[0].Grant != "the-grant" {
		t.Fatalf("creds = %v, want the-grant credential (empty exact entry must not shadow bare-host entry)", creds)
	}
}

// TestProxy_GetCredentials_WildcardKeyWithPort verifies that a wildcard key
// carrying a port matches subdomains on exactly that port and nothing else.
// The credential setters reject keys containing ":" (isValidHost), so such
// keys arise via embedder-supplied RunContextData maps — the lookup is
// exercised through that path.
func TestProxy_GetCredentials_WildcardKeyWithPort(t *testing.T) {
	p := NewProxy()
	rc := &RunContextData{
		Credentials: map[string][]credentialHeader{
			"*.internal.example.com:8443": {{Name: "Authorization", Value: "Bearer tok", Grant: "port-grant"}},
		},
	}
	lookup := func(t *testing.T, host string) []credentialHeader {
		t.Helper()
		req := httptest.NewRequest("GET", "https://"+host+"/", nil)
		req = req.WithContext(context.WithValue(req.Context(), runContextKey, rc))
		creds, err := p.getCredentialsForRequest(req, req, host)
		if err != nil {
			t.Fatalf("getCredentialsForRequest(%q): %v", host, err)
		}
		return creds
	}

	if creds := lookup(t, "svc.internal.example.com:8443"); len(creds) != 1 || creds[0].Grant != "port-grant" {
		t.Errorf("lookup(svc.internal.example.com:8443) = %v, want port-grant credential", creds)
	}
	if creds := lookup(t, "svc.internal.example.com:9999"); len(creds) != 0 {
		t.Errorf("lookup(svc.internal.example.com:9999) = %v, want none (port must match)", creds)
	}
	if creds := lookup(t, "svc.internal.example.com"); len(creds) != 0 {
		t.Errorf("lookup(svc.internal.example.com) = %v, want none (port must match)", creds)
	}
	if creds := lookup(t, "internal.example.com:8443"); len(creds) != 0 {
		t.Errorf("lookup(internal.example.com:8443) = %v, want none (apex excluded)", creds)
	}
}

// TestProxy_GetCredentials_CaseVariantWildcardKeysDeterministic verifies the
// wildcard tier's tie-break: equal-length wildcard keys (only possible as
// case-variants of each other) resolve to the lexicographically smallest key
// rather than random map iteration order.
func TestProxy_GetCredentials_CaseVariantWildcardKeysDeterministic(t *testing.T) {
	p := NewProxy()
	p.SetCredentialWithGrant("*.API.example.com", "Authorization", "Bearer upper", "upper-grant")
	p.SetCredentialWithGrant("*.api.example.com", "Authorization", "Bearer lower", "lower-grant")

	for i := range 100 {
		creds := p.getCredentials("svc.api.example.com")
		if len(creds) != 1 {
			t.Fatalf("getCredentials returned %d credentials, want 1", len(creds))
		}
		if creds[0].Grant != "upper-grant" {
			t.Fatalf("iteration %d: grant = %q, want %q (lexicographically smallest wildcard key must win)", i, creds[0].Grant, "upper-grant")
		}
	}
}

// TestProxy_GetCredentialsForRequest_StaticReadAfterResolverMiss verifies
// that when a resolver returns nil, the static-credential fallback reads the
// map fresh rather than a snapshot taken before the resolver ran — a token
// refresh landing during a slow resolver call must not be missed.
func TestProxy_GetCredentialsForRequest_StaticReadAfterResolverMiss(t *testing.T) {
	p := NewProxy()
	p.SetCredentialResolver("api.example.com", func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]credentialHeader, error) {
		p.SetCredentialWithGrant("api.example.com", "Authorization", "Bearer refreshed", "refreshed-grant")
		return nil, nil
	})
	req := httptest.NewRequest("GET", "https://api.example.com/", nil)

	creds, err := p.getCredentialsForRequest(req, req, "api.example.com")
	if err != nil {
		t.Fatalf("getCredentialsForRequest: %v", err)
	}
	if len(creds) != 1 || creds[0].Grant != "refreshed-grant" {
		t.Fatalf("creds = %v, want refreshed-grant (static fallback must read fresh after resolver miss)", creds)
	}
}

// TestProxy_HostKeyedMaps_WildcardKey verifies that the companion host-keyed
// maps — extra headers, remove-headers, token substitutions, and response
// transformers — honor wildcard host keys the same way credentials do, in
// both the proxy-level maps and RunContextData.
func TestProxy_HostKeyedMaps_WildcardKey(t *testing.T) {
	const host = "alpha.box.example.com"
	noop := ResponseTransformer(func(req, resp any) (any, bool) { return resp, false })

	p := NewProxy()
	p.AddExtraHeader("*.box.example.com", "X-Api-Version", "2024-01-01")
	p.RemoveRequestHeader("*.box.example.com", "X-Internal")
	p.SetTokenSubstitution("*.box.example.com", "PLACEHOLDER", "real-token")
	p.AddResponseTransformer("*.box.example.com", noop)

	if got := p.getExtraHeaders(host); len(got) != 1 || got[0].Name != "X-Api-Version" {
		t.Errorf("getExtraHeaders(%q) = %v, want X-Api-Version header", host, got)
	}
	if got := p.getRemoveHeaders(host); len(got) != 1 || got[0] != "X-Internal" {
		t.Errorf("getRemoveHeaders(%q) = %v, want [X-Internal]", host, got)
	}
	if sub := p.getTokenSubstitution(host); sub == nil || sub.placeholder != "PLACEHOLDER" {
		t.Errorf("getTokenSubstitution(%q) = %v, want PLACEHOLDER substitution", host, sub)
	}
	if got := p.getResponseTransformers(host); len(got) != 1 {
		t.Errorf("getResponseTransformers(%q) returned %d transformers, want 1", host, len(got))
	}

	rc := &RunContextData{
		ExtraHeaders:         map[string][]extraHeader{"*.box.example.com": {{Name: "X-Rc-Version", Value: "v1"}}},
		RemoveHeaders:        map[string][]string{"*.box.example.com": {"X-Rc-Internal"}},
		TokenSubstitutions:   map[string]*tokenSubstitution{"*.box.example.com": {placeholder: "RC-PLACEHOLDER", realToken: "rc-token"}},
		ResponseTransformers: map[string][]ResponseTransformer{"*.box.example.com": {noop}},
	}
	req := httptest.NewRequest("GET", "https://"+host+"/", nil)
	req = req.WithContext(context.WithValue(req.Context(), runContextKey, rc))

	if got := p.getExtraHeadersForRequest(req, host); len(got) != 1 || got[0].Name != "X-Rc-Version" {
		t.Errorf("getExtraHeadersForRequest(%q) = %v, want X-Rc-Version header", host, got)
	}
	if got := p.getRemoveHeadersForRequest(req, host); len(got) != 1 || got[0] != "X-Rc-Internal" {
		t.Errorf("getRemoveHeadersForRequest(%q) = %v, want [X-Rc-Internal]", host, got)
	}
	if sub := p.getTokenSubstitutionForRequest(req, host); sub == nil || sub.placeholder != "RC-PLACEHOLDER" {
		t.Errorf("getTokenSubstitutionForRequest(%q) = %v, want RC-PLACEHOLDER substitution", host, sub)
	}
	if got := p.getResponseTransformersForRequest(req, host); len(got) != 1 {
		t.Errorf("getResponseTransformersForRequest(%q) returned %d transformers, want 1", host, len(got))
	}
}

// TestProxy_ExtraHeaders_MergesWithExisting verifies that extra headers are
// merged with client-sent headers rather than replacing them.
func TestProxy_ExtraHeaders_MergesWithExisting(t *testing.T) {
	var receivedBeta string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBeta = r.Header.Get("anthropic-beta")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()
	p.AddExtraHeader("127.0.0.1", "anthropic-beta", "oauth-2025-04-20")

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	req, _ := http.NewRequest("GET", backend.URL, nil)
	req.Header.Set("anthropic-beta", "prompt-caching-2024-07-31")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	want := "prompt-caching-2024-07-31,oauth-2025-04-20"
	if receivedBeta != want {
		t.Errorf("anthropic-beta = %q, want %q", receivedBeta, want)
	}
}

// TestProxy_ExtraHeaders_SetsWhenAbsent verifies that extra headers are set
// when the client doesn't send them.
func TestProxy_ExtraHeaders_SetsWhenAbsent(t *testing.T) {
	var receivedBeta string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBeta = r.Header.Get("anthropic-beta")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()
	p.AddExtraHeader("127.0.0.1", "anthropic-beta", "oauth-2025-04-20")

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if receivedBeta != "oauth-2025-04-20" {
		t.Errorf("anthropic-beta = %q, want %q", receivedBeta, "oauth-2025-04-20")
	}
}

// TestProxy_RemoveRequestHeader verifies that client-sent headers can be
// stripped before forwarding.
func TestProxy_RemoveRequestHeader(t *testing.T) {
	var receivedAPIKey string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAPIKey = r.Header.Get("x-api-key")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetCredential("127.0.0.1", "Bearer real-token")
	p.RemoveRequestHeader("127.0.0.1", "x-api-key")

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	req, _ := http.NewRequest("GET", backend.URL, nil)
	req.Header.Set("x-api-key", "stale-placeholder")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if receivedAPIKey != "" {
		t.Errorf("x-api-key should be stripped, got %q", receivedAPIKey)
	}
}

// TestIsTextContentType verifies content type detection for body capture.
func TestIsTextContentType(t *testing.T) {
	tests := []struct {
		contentType string
		want        bool
	}{
		{"text/plain", true},
		{"text/html", true},
		{"application/json", true},
		{"application/xml", true},
		{"application/x-www-form-urlencoded", true},
		{"text/javascript", true},
		{"application/javascript", true},
		{"image/png", false},
		{"image/jpeg", false},
		{"application/octet-stream", false},
		{"application/pdf", false},
		{"video/mp4", false},
		{"", false},
		{"TEXT/PLAIN", true},       // case insensitive
		{"Application/JSON", true}, // case insensitive
	}

	for _, tt := range tests {
		t.Run(tt.contentType, func(t *testing.T) {
			got := isTextContentType(tt.contentType)
			if got != tt.want {
				t.Errorf("isTextContentType(%q) = %v, want %v", tt.contentType, got, tt.want)
			}
		})
	}
}

// TestCaptureBody_TruncatesLargeBody verifies body capture truncation at MaxBodySize
// while still forwarding the full body.
func TestCaptureBody_TruncatesLargeBody(t *testing.T) {
	// Create a body larger than MaxBodySize (8KB)
	largeBody := strings.Repeat("x", MaxBodySize+1000)
	body := io.NopCloser(strings.NewReader(largeBody))

	captured, newBody := captureBody(body, "application/json")

	// Captured portion should be truncated to MaxBodySize
	if len(captured) != MaxBodySize {
		t.Errorf("captured length = %d, want %d", len(captured), MaxBodySize)
	}

	// Full body should still be readable and contain ALL original data
	fullData, err := io.ReadAll(newBody)
	if err != nil {
		t.Fatalf("reading new body: %v", err)
	}
	if len(fullData) != len(largeBody) {
		t.Errorf("full body length = %d, want %d", len(fullData), len(largeBody))
	}
}

// TestCaptureBody_StreamsVeryLargeBody verifies bodies much larger than MaxBodySize
// are fully forwarded (not truncated).
func TestCaptureBody_StreamsVeryLargeBody(t *testing.T) {
	// Create a body much larger than MaxBodySize (e.g., 100KB)
	veryLargeBody := strings.Repeat("y", 100*1024)
	body := io.NopCloser(strings.NewReader(veryLargeBody))

	captured, newBody := captureBody(body, "application/json")

	// Captured should still be truncated to MaxBodySize
	if len(captured) != MaxBodySize {
		t.Errorf("captured length = %d, want %d", len(captured), MaxBodySize)
	}

	// But full body must be fully forwarded
	fullData, err := io.ReadAll(newBody)
	if err != nil {
		t.Fatalf("reading new body: %v", err)
	}
	if len(fullData) != len(veryLargeBody) {
		t.Errorf("full body length = %d, want %d (body was truncated!)", len(fullData), len(veryLargeBody))
	}

	// Close should work
	if err := newBody.Close(); err != nil {
		t.Errorf("close error: %v", err)
	}
}

// TestCaptureBody_SkipsBinaryContent verifies binary content types are not captured.
func TestCaptureBody_SkipsBinaryContent(t *testing.T) {
	originalData := []byte{0x89, 0x50, 0x4E, 0x47} // PNG magic bytes
	body := io.NopCloser(bytes.NewReader(originalData))

	captured, newBody := captureBody(body, "image/png")

	// Should not capture binary content
	if captured != nil {
		t.Errorf("captured = %v, want nil for binary content", captured)
	}

	// Body should be returned unchanged
	data, err := io.ReadAll(newBody)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if !bytes.Equal(data, originalData) {
		t.Errorf("body data changed for binary content")
	}
}

// TestCaptureBody_NilBody verifies nil body handling.
func TestCaptureBody_NilBody(t *testing.T) {
	captured, newBody := captureBody(nil, "application/json")

	if captured != nil {
		t.Errorf("captured = %v, want nil", captured)
	}
	if newBody != nil {
		t.Errorf("newBody = %v, want nil", newBody)
	}
}

// blockingBody delivers one initial chunk, then blocks on Read until released.
// It mimics a streaming upstream that has emitted an early chunk (status line,
// first record, keepalive ping) but not yet MaxBodySize bytes of body — e.g.
// during a long time-to-first-token.
type blockingBody struct {
	first   []byte
	sent    bool
	release chan struct{}
}

func (b *blockingBody) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		return copy(p, b.first), nil
	}
	<-b.release
	return 0, io.EOF
}

func (b *blockingBody) Close() error { return nil }

// TestCapturingBody_StreamsAndCaptures verifies the full body passes through
// while a bounded sample is captured, and onClose fires exactly once with it.
func TestCapturingBody_StreamsAndCaptures(t *testing.T) {
	full := strings.Repeat("a", MaxBodySize+500)
	var got []byte
	var calls int
	cb := newCapturingBody(io.NopCloser(strings.NewReader(full)), MaxBodySize, func(c []byte) {
		calls++
		got = c
	})

	streamed, err := io.ReadAll(cb)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(streamed) != full {
		t.Errorf("streamed %d bytes, want %d (body must pass through in full)", len(streamed), len(full))
	}

	if err := cb.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := cb.Close(); err != nil { // second close must not re-fire onClose
		t.Fatalf("second close: %v", err)
	}
	if calls != 1 {
		t.Errorf("onClose called %d times, want 1", calls)
	}
	if len(got) != MaxBodySize {
		t.Errorf("captured %d bytes, want %d (bounded sample)", len(got), MaxBodySize)
	}
}

// TestCapturingBody_NeverBlocksOnSlowStream is the regression guard for the
// first-byte-timeout bug: a streamed body that delivers one record then blocks
// must not trigger a read-ahead. capturingBody reads only what the consumer
// requests, so the first record is available immediately — regardless of content
// type. This uses a non-SSE stream (application/x-ndjson) to show the fix is not
// keyed on a media-type allowlist.
func TestCapturingBody_NeverBlocksOnSlowStream(t *testing.T) {
	first := []byte(`{"chunk":1}` + "\n")
	body := &blockingBody{first: first, release: make(chan struct{})}
	defer close(body.release)
	cb := newCapturingBody(body, MaxBodySize, nil)

	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := cb.Read(buf)
		done <- buf[:n]
	}()

	select {
	case got := <-done:
		if !bytes.Equal(got, first) {
			t.Errorf("first read = %q, want %q", got, first)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("capturingBody.Read blocked instead of returning the available record")
	}

	if !bytes.Equal(cb.Captured(), first) {
		t.Errorf("captured = %q, want %q", cb.Captured(), first)
	}
}

// TestFilterHeaders_RedactsInjectedCredential verifies credential redaction.
func TestFilterHeaders_RedactsInjectedCredential(t *testing.T) {
	headers := http.Header{
		"Authorization": []string{"Bearer secret-token"},
		"Content-Type":  []string{"application/json"},
		"Accept":        []string{"*/*"},
	}

	// When auth was injected, Authorization should be redacted
	filtered := FilterHeaders(headers, map[string]bool{"authorization": true})

	if filtered["Authorization"] != "[REDACTED]" {
		t.Errorf("Authorization = %q, want %q", filtered["Authorization"], "[REDACTED]")
	}
	if filtered["Content-Type"] != "application/json" {
		t.Errorf("Content-Type = %q, want %q", filtered["Content-Type"], "application/json")
	}
}

// TestFilterHeaders_PreservesNonInjectedCredential verifies non-injected headers are preserved.
func TestFilterHeaders_PreservesNonInjectedCredential(t *testing.T) {
	headers := http.Header{
		"Authorization": []string{"Bearer user-token"},
		"Content-Type":  []string{"application/json"},
	}

	// When auth was NOT injected, Authorization should be preserved
	filtered := FilterHeaders(headers, nil)

	if filtered["Authorization"] != "Bearer user-token" {
		t.Errorf("Authorization = %q, want %q", filtered["Authorization"], "Bearer user-token")
	}
}

// TestFilterHeaders_RedactsCustomHeader verifies custom header redaction (like x-api-key).
func TestFilterHeaders_RedactsCustomHeader(t *testing.T) {
	headers := http.Header{
		"X-Api-Key":    []string{"sk-ant-secret"},
		"Content-Type": []string{"application/json"},
	}

	// When custom header was injected, it should be redacted
	filtered := FilterHeaders(headers, map[string]bool{"x-api-key": true})

	if filtered["X-Api-Key"] != "[REDACTED]" {
		t.Errorf("X-Api-Key = %q, want %q", filtered["X-Api-Key"], "[REDACTED]")
	}
}

// TestFilterHeaders_FiltersProxyHeaders verifies proxy headers are always filtered out.
func TestFilterHeaders_FiltersProxyHeaders(t *testing.T) {
	headers := http.Header{
		"Proxy-Authorization": []string{"Basic secret"},
		"Proxy-Connection":    []string{"keep-alive"},
		"Content-Type":        []string{"application/json"},
	}

	filtered := FilterHeaders(headers, nil)

	if _, exists := filtered["Proxy-Authorization"]; exists {
		t.Error("Proxy-Authorization should be filtered out")
	}
	if _, exists := filtered["Proxy-Connection"]; exists {
		t.Error("Proxy-Connection should be filtered out")
	}
	if filtered["Content-Type"] != "application/json" {
		t.Errorf("Content-Type = %q, want %q", filtered["Content-Type"], "application/json")
	}
}

// TestFilterHeaders_JoinsMultipleValues verifies multi-value headers are joined.
func TestFilterHeaders_JoinsMultipleValues(t *testing.T) {
	headers := http.Header{
		"Accept": []string{"text/html", "application/json", "*/*"},
	}

	filtered := FilterHeaders(headers, nil)

	expected := "text/html, application/json, */*"
	if filtered["Accept"] != expected {
		t.Errorf("Accept = %q, want %q", filtered["Accept"], expected)
	}
}

// TestFilterHeaders_NilHeaders verifies nil header handling.
func TestFilterHeaders_NilHeaders(t *testing.T) {
	filtered := FilterHeaders(nil, nil)

	if filtered != nil {
		t.Errorf("filtered = %v, want nil", filtered)
	}
}

// TestApplyTokenSubstitution_URLPath verifies token substitution in URL paths.
func TestApplyTokenSubstitution_URLPath(t *testing.T) {
	p := NewProxy()
	sub := &tokenSubstitution{
		placeholder: "moat-proxy-injected",
		realToken:   "123456:ABC-DEF",
	}

	req := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Scheme: "https",
			Host:   "api.telegram.org",
			Path:   "/botmoat-proxy-injected/getMe",
		},
		Header: make(http.Header),
	}

	p.applyTokenSubstitution(req, sub)

	wantPath := "/bot123456:ABC-DEF/getMe"
	if req.URL.Path != wantPath {
		t.Errorf("URL.Path = %q, want %q", req.URL.Path, wantPath)
	}
}

// TestApplyTokenSubstitution_RawPath verifies token substitution in RawPath when set.
func TestApplyTokenSubstitution_RawPath(t *testing.T) {
	p := NewProxy()
	sub := &tokenSubstitution{
		placeholder: "moat-abc123",
		realToken:   "123456:ABC-DEF",
	}

	req := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Scheme:  "https",
			Host:    "api.telegram.org",
			Path:    "/botmoat-abc123/getMe",
			RawPath: "/botmoat-abc123/getMe",
		},
		Header: make(http.Header),
	}

	p.applyTokenSubstitution(req, sub)

	wantPath := "/bot123456:ABC-DEF/getMe"
	if req.URL.Path != wantPath {
		t.Errorf("URL.Path = %q, want %q", req.URL.Path, wantPath)
	}
	if req.URL.RawPath != wantPath {
		t.Errorf("URL.RawPath = %q, want %q", req.URL.RawPath, wantPath)
	}
}

// TestApplyTokenSubstitution_URLPathAndBody verifies substitution in both URL and body.
func TestApplyTokenSubstitution_URLPathAndBody(t *testing.T) {
	p := NewProxy()
	sub := &tokenSubstitution{
		placeholder: "moat-proxy-injected",
		realToken:   "real-token-value",
	}

	body := `{"token": "moat-proxy-injected"}`
	req := &http.Request{
		Method: "POST",
		URL: &url.URL{
			Scheme: "https",
			Host:   "api.example.com",
			Path:   "/v1/moat-proxy-injected/action",
		},
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}

	p.applyTokenSubstitution(req, sub)

	if req.URL.Path != "/v1/real-token-value/action" {
		t.Errorf("URL.Path = %q, want %q", req.URL.Path, "/v1/real-token-value/action")
	}

	gotBody, _ := io.ReadAll(req.Body)
	wantBody := `{"token": "real-token-value"}`
	if string(gotBody) != wantBody {
		t.Errorf("Body = %q, want %q", string(gotBody), wantBody)
	}
}

// TestProxy_ContextResolver verifies that a context resolver can look up per-run data by token.
func TestProxy_ContextResolver(t *testing.T) {
	p := NewProxy()

	contexts := map[string]*RunContextData{
		"token_a": {
			Credentials: map[string][]credentialHeader{
				"api.github.com": {{Name: "Authorization", Value: "token aaa"}},
			},
		},
	}
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		rc, ok := contexts[token]
		return rc, ok
	})

	rc, ok := p.ResolveContext("token_a")
	if !ok {
		t.Fatal("expected to resolve token_a")
	}
	if rc.Credentials["api.github.com"][0].Value != "token aaa" {
		t.Error("wrong credential value")
	}

	_, ok = p.ResolveContext("invalid")
	if ok {
		t.Error("expected invalid token to fail")
	}
}

// TestProxy_ContextResolverNilFallback verifies that ResolveContext returns false
// when no resolver is set.
func TestProxy_ContextResolverNilFallback(t *testing.T) {
	p := NewProxy()
	// No resolver set
	_, ok := p.ResolveContext("any")
	if ok {
		t.Error("expected nil resolver to return false")
	}
}

// TestApplyTokenSubstitution_NoMatch verifies no modification when placeholder is absent.
func TestApplyTokenSubstitution_NoMatch(t *testing.T) {
	p := NewProxy()
	sub := &tokenSubstitution{
		placeholder: "moat-proxy-injected",
		realToken:   "real-token",
	}

	req := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Scheme: "https",
			Host:   "api.example.com",
			Path:   "/v1/something-else/action",
		},
		Header: make(http.Header),
	}

	p.applyTokenSubstitution(req, sub)

	if req.URL.Path != "/v1/something-else/action" {
		t.Errorf("URL.Path should be unchanged, got %q", req.URL.Path)
	}
}

// TestProxy_PerContextHTTPRequest verifies that per-run context data is used
// to inject credentials when a ContextResolver is set.
func TestProxy_PerContextHTTPRequest(t *testing.T) {
	// Start a target HTTP server that echoes the Authorization header
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Header.Get("Authorization")))
	}))
	defer target.Close()

	p := NewProxy()

	targetURL := mustParseURL(target.URL)
	h := targetURL.Hostname()

	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "test_token" {
			return &RunContextData{
				Credentials: map[string][]credentialHeader{
					h: {{Name: "Authorization", Value: "Bearer injected"}},
				},
				Policy: "permissive",
			}, true
		}
		return nil, false
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, _ := http.NewRequest("GET", target.URL+"/test", nil)
	req.Header.Set("Proxy-Authorization", "Bearer test_token")
	req.Header.Set("Authorization", "placeholder")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "Bearer injected" {
		t.Errorf("expected 'Bearer injected', got %q", string(body))
	}
}

// TestProxy_PerContextRejectsInvalidToken verifies that an invalid proxy token
// is rejected with 407 when a ContextResolver is set.
func TestProxy_PerContextRejectsInvalidToken(t *testing.T) {
	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		return nil, false
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("Proxy-Authorization", "Bearer bad_token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("expected 407, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Proxy-Authenticate"); got != `Basic realm="gatekeeper"` {
		t.Errorf("Proxy-Authenticate = %q, want %q", got, `Basic realm="gatekeeper"`)
	}
}

// TestProxy_PerContextRejectsMissingToken verifies that a request without a
// Proxy-Authorization header is rejected when a ContextResolver is set.
func TestProxy_PerContextRejectsMissingToken(t *testing.T) {
	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		return &RunContextData{Policy: "permissive"}, true
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	// No Proxy-Authorization header set
	resp, err := client.Get("http://example.com/test")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("expected 407, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Proxy-Authenticate"); got != `Basic realm="gatekeeper"` {
		t.Errorf("Proxy-Authenticate = %q, want %q", got, `Basic realm="gatekeeper"`)
	}
}

// TestProxy_PerContextNetworkPolicy verifies that per-run network policy
// from RunContextData is applied correctly.
func TestProxy_PerContextNetworkPolicy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	backendURL := mustParseURL(backend.URL)

	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "strict_run" {
			return &RunContextData{
				Policy:       "strict",
				AllowedHosts: []hostPattern{}, // allow nothing
			}, true
		}
		return nil, false
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, _ := http.NewRequest("GET", backend.URL, nil)
	req.Header.Set("Proxy-Authorization", "Bearer strict_run")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Should be blocked since the host is not in the allow list
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("expected 407 (blocked by policy), got %d", resp.StatusCode)
	}

	// Verify the blocked header
	if resp.Header.Get("X-Moat-Blocked") != "request-rule" {
		t.Errorf("expected X-Moat-Blocked header, got %q", resp.Header.Get("X-Moat-Blocked"))
	}

	// Now test with a permissive context
	p2 := NewProxy()
	p2.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "permissive_run" {
			return &RunContextData{
				Credentials: map[string][]credentialHeader{
					backendURL.Hostname(): {{Name: "Authorization", Value: "Bearer ctx-token"}},
				},
				Policy: "permissive",
			}, true
		}
		return nil, false
	})

	proxyServer2 := httptest.NewServer(p2)
	defer proxyServer2.Close()

	proxyURL2 := mustParseURL(proxyServer2.URL)
	client2 := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL2)}}

	req2, _ := http.NewRequest("GET", backend.URL, nil)
	req2.Header.Set("Proxy-Authorization", "Bearer permissive_run")
	resp2, err := client2.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}
}

// TestProxy_PerContextExtraHeaders verifies that extra headers from
// RunContextData are injected.
func TestProxy_PerContextExtraHeaders(t *testing.T) {
	var receivedBeta string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBeta = r.Header.Get("anthropic-beta")
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	backendURL := mustParseURL(backend.URL)
	h := backendURL.Hostname()

	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "extra_run" {
			return &RunContextData{
				ExtraHeaders: map[string][]extraHeader{
					h: {{Name: "anthropic-beta", Value: "oauth-2025-04-20"}},
				},
				Policy: "permissive",
			}, true
		}
		return nil, false
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, _ := http.NewRequest("GET", backend.URL, nil)
	req.Header.Set("Proxy-Authorization", "Bearer extra_run")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if receivedBeta != "oauth-2025-04-20" {
		t.Errorf("anthropic-beta = %q, want %q", receivedBeta, "oauth-2025-04-20")
	}
}

// TestProxy_PerContextRemoveHeaders verifies that remove headers from
// RunContextData are applied.
func TestProxy_PerContextRemoveHeaders(t *testing.T) {
	var receivedKey string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedKey = r.Header.Get("x-api-key")
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	backendURL := mustParseURL(backend.URL)
	h := backendURL.Hostname()

	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "remove_run" {
			return &RunContextData{
				RemoveHeaders: map[string][]string{
					h: {"x-api-key"},
				},
				Policy: "permissive",
			}, true
		}
		return nil, false
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, _ := http.NewRequest("GET", backend.URL, nil)
	req.Header.Set("Proxy-Authorization", "Bearer remove_run")
	req.Header.Set("x-api-key", "should-be-removed")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if receivedKey != "" {
		t.Errorf("x-api-key should be removed, got %q", receivedKey)
	}
}

// TestProxy_RemoveHeaderSkipsInjectedCredential verifies that RemoveRequestHeader
// does not strip the credential header the proxy just injected. This prevents a
// conflict when both "claude" (OAuth, removes x-api-key) and "anthropic" (API key,
// injects x-api-key) grants target the same host.
func TestProxy_RemoveHeaderSkipsInjectedCredential(t *testing.T) {
	var receivedKey string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedKey = r.Header.Get("x-api-key")
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	backendURL := mustParseURL(backend.URL)
	h := backendURL.Hostname()

	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "multi_grant_run" {
			return &RunContextData{
				// "anthropic" grant won the credential slot with x-api-key
				Credentials: map[string][]credentialHeader{
					h: {{Name: "x-api-key", Value: "sk-ant-real-key", Grant: "anthropic"}},
				},
				// "claude" grant registered remove x-api-key (for OAuth)
				RemoveHeaders: map[string][]string{
					h: {"x-api-key"},
				},
				Policy: "permissive",
			}, true
		}
		return nil, false
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, _ := http.NewRequest("GET", backend.URL, nil)
	req.Header.Set("Proxy-Authorization", "Bearer multi_grant_run")
	// Client sends a placeholder (like Claude Code would with ANTHROPIC_API_KEY env)
	req.Header.Set("x-api-key", "placeholder-value")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if receivedKey != "sk-ant-real-key" {
		t.Errorf("x-api-key should be the injected credential, got %q", receivedKey)
	}
}

// TestProxy_DualCredentialClientChooses verifies that when both "claude" (OAuth)
// and "anthropic" (API key) grants are active for the same host, the proxy
// replaces whichever header the client actually sends. The client's choice of
// auth scheme determines which credential is injected.
func TestProxy_DualCredentialClientChooses(t *testing.T) {
	var receivedAuth, receivedKey string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedKey = r.Header.Get("x-api-key")
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	backendURL := mustParseURL(backend.URL)
	h := backendURL.Hostname()

	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "dual_cred" {
			return &RunContextData{
				Credentials: map[string][]credentialHeader{
					h: {
						{Name: "Authorization", Value: "Bearer oauth-token", Grant: "claude"},
						{Name: "x-api-key", Value: "sk-ant-real-key", Grant: "anthropic"},
					},
				},
				// Claude OAuth registers RemoveRequestHeader("x-api-key")
				RemoveHeaders: map[string][]string{
					h: {"x-api-key"},
				},
				Policy: "permissive",
			}, true
		}
		return nil, false
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	// Test 1: Client sends x-api-key → anthropic credential injected
	receivedAuth = ""
	receivedKey = ""
	req, _ := http.NewRequest("GET", backend.URL, nil)
	req.Header.Set("Proxy-Authorization", "Bearer dual_cred")
	req.Header.Set("x-api-key", "placeholder")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if receivedKey != "sk-ant-real-key" {
		t.Errorf("test 1: x-api-key should be real key, got %q", receivedKey)
	}
	if receivedAuth != "" {
		t.Errorf("test 1: Authorization should be empty (client didn't send it), got %q", receivedAuth)
	}

	// Test 2: Client sends Authorization → claude credential injected
	receivedAuth = ""
	receivedKey = ""
	req, _ = http.NewRequest("GET", backend.URL, nil)
	req.Header.Set("Proxy-Authorization", "Bearer dual_cred")
	req.Header.Set("Authorization", "Bearer placeholder")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if receivedAuth != "Bearer oauth-token" {
		t.Errorf("test 2: Authorization should be OAuth token, got %q", receivedAuth)
	}
	// x-api-key was not sent and not injected (first-pass only matched Authorization)
	if receivedKey != "" {
		t.Errorf("test 2: x-api-key should be empty (removed by RemoveHeaders), got %q", receivedKey)
	}

	// Test 3: Client sends both → both replaced
	receivedAuth = ""
	receivedKey = ""
	req, _ = http.NewRequest("GET", backend.URL, nil)
	req.Header.Set("Proxy-Authorization", "Bearer dual_cred")
	req.Header.Set("Authorization", "Bearer placeholder")
	req.Header.Set("x-api-key", "placeholder")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if receivedAuth != "Bearer oauth-token" {
		t.Errorf("test 3: Authorization should be OAuth token, got %q", receivedAuth)
	}
	if receivedKey != "sk-ant-real-key" {
		t.Errorf("test 3: x-api-key should be real key, got %q", receivedKey)
	}

	// Test 4: Client sends no placeholder → both auto-injected (different header names)
	receivedAuth = ""
	receivedKey = ""
	req, _ = http.NewRequest("GET", backend.URL, nil)
	req.Header.Set("Proxy-Authorization", "Bearer dual_cred")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// Both credentials have different header names, so both are auto-injected.
	// The "claude" grant gets Authorization, "anthropic" gets x-api-key.
	if receivedAuth != "Bearer oauth-token" {
		t.Errorf("test 4: Authorization should be OAuth token (auto-injected), got %q", receivedAuth)
	}
	if receivedKey != "sk-ant-real-key" {
		t.Errorf("test 4: x-api-key should be real key (auto-injected, protected from RemoveHeaders), got %q", receivedKey)
	}
}

// TestProxy_DualCredentialSameHeaderPreference verifies that when multiple
// credentials share the same header name and no placeholder is sent, the
// proxy prefers the non-"claude" grant for auto-injection.
func TestProxy_DualCredentialSameHeaderPreference(t *testing.T) {
	var receivedAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	backendURL := mustParseURL(backend.URL)
	h := backendURL.Hostname()

	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "same_header" {
			return &RunContextData{
				Credentials: map[string][]credentialHeader{
					h: {
						{Name: "Authorization", Value: "Bearer oauth-token", Grant: "claude"},
						{Name: "Authorization", Value: "Bearer api-key-token", Grant: "anthropic"},
					},
				},
				Policy: "permissive",
			}, true
		}
		return nil, false
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	// No placeholder — auto-inject should prefer "anthropic" over "claude"
	req, _ := http.NewRequest("GET", backend.URL, nil)
	req.Header.Set("Proxy-Authorization", "Bearer same_header")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if receivedAuth != "Bearer api-key-token" {
		t.Errorf("Authorization = %q, want %q (anthropic preferred over claude)", receivedAuth, "Bearer api-key-token")
	}
}

// TestProxy_PerContextTokenSubstitution verifies that token substitution from
// RunContextData is applied.
func TestProxy_PerContextTokenSubstitution(t *testing.T) {
	var receivedAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	backendURL := mustParseURL(backend.URL)
	h := backendURL.Hostname()

	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "sub_run" {
			return &RunContextData{
				TokenSubstitutions: map[string]*tokenSubstitution{
					h: {placeholder: "PLACEHOLDER", realToken: "real-secret"},
				},
				Policy: "permissive",
			}, true
		}
		return nil, false
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, _ := http.NewRequest("GET", backend.URL, nil)
	req.Header.Set("Proxy-Authorization", "Bearer sub_run")
	req.Header.Set("Authorization", "Bearer PLACEHOLDER")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if receivedAuth != "Bearer real-secret" {
		t.Errorf("Authorization = %q, want %q", receivedAuth, "Bearer real-secret")
	}
}

// TestProxy_PerContextBasicAuth verifies that Basic auth format works with
// context resolver (e.g., from HTTP_PROXY=http://moat:token@host).
func TestProxy_PerContextBasicAuth(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Header.Get("Authorization")))
	}))
	defer backend.Close()

	backendURL := mustParseURL(backend.URL)
	h := backendURL.Hostname()

	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "basic_token" {
			return &RunContextData{
				Credentials: map[string][]credentialHeader{
					h: {{Name: "Authorization", Value: "Bearer injected-via-basic"}},
				},
				Policy: "permissive",
			}, true
		}
		return nil, false
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)
	proxyURL.User = url.UserPassword("moat", "basic_token")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, _ := http.NewRequest("GET", backend.URL, nil)
	req.Header.Set("Authorization", "placeholder")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "Bearer injected-via-basic" {
		t.Errorf("expected 'Bearer injected-via-basic', got %q", string(body))
	}
}

// TestProxy_PerContextIsolation verifies that different tokens get different
// credentials injected - requests are isolated per-run.
func TestProxy_PerContextIsolation(t *testing.T) {
	var mu sync.Mutex
	received := make(map[string]string)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received[r.URL.Path] = r.Header.Get("Authorization")
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	backendURL := mustParseURL(backend.URL)
	h := backendURL.Hostname()

	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		switch token {
		case "run_a":
			return &RunContextData{
				Credentials: map[string][]credentialHeader{
					h: {{Name: "Authorization", Value: "Bearer token-A"}},
				},
				Policy: "permissive",
			}, true
		case "run_b":
			return &RunContextData{
				Credentials: map[string][]credentialHeader{
					h: {{Name: "Authorization", Value: "Bearer token-B"}},
				},
				Policy: "permissive",
			}, true
		}
		return nil, false
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	// Request with token A
	reqA, _ := http.NewRequest("GET", backend.URL+"/path-a", nil)
	reqA.Header.Set("Proxy-Authorization", "Bearer run_a")
	reqA.Header.Set("Authorization", "placeholder")
	respA, err := client.Do(reqA)
	if err != nil {
		t.Fatal(err)
	}
	respA.Body.Close()

	// Request with token B
	reqB, _ := http.NewRequest("GET", backend.URL+"/path-b", nil)
	reqB.Header.Set("Proxy-Authorization", "Bearer run_b")
	reqB.Header.Set("Authorization", "placeholder")
	respB, err := client.Do(reqB)
	if err != nil {
		t.Fatal(err)
	}
	respB.Body.Close()

	mu.Lock()
	defer mu.Unlock()

	if received["/path-a"] != "Bearer token-A" {
		t.Errorf("path-a got %q, want %q", received["/path-a"], "Bearer token-A")
	}
	if received["/path-b"] != "Bearer token-B" {
		t.Errorf("path-b got %q, want %q", received["/path-b"], "Bearer token-B")
	}
}

// TestProxy_LegacyModeUnchanged verifies that when no ContextResolver is set,
// the proxy injects credentials when the client sends a matching placeholder header.
func TestProxy_LegacyModeUnchanged(t *testing.T) {
	var receivedAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetCredential("127.0.0.1", "Bearer legacy-token")
	// No ContextResolver set - should work with placeholder header

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	req, _ := http.NewRequest("GET", backend.URL, nil)
	req.Header.Set("Authorization", "placeholder")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if receivedAuth != "Bearer legacy-token" {
		t.Errorf("Authorization = %q, want %q", receivedAuth, "Bearer legacy-token")
	}
}

// TestProxy_AutoInjectWithoutPlaceholder verifies that credentials are
// auto-injected when the client doesn't send a placeholder header.
// This ensures transparent auth for tools like curl, git, npm, etc.
func TestProxy_AutoInjectWithoutPlaceholder(t *testing.T) {
	var receivedAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetCredential("127.0.0.1", "Bearer secret-token")

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	// No Authorization header sent — credential should be auto-injected
	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if receivedAuth != "Bearer secret-token" {
		t.Errorf("Authorization = %q, want %q (auto-injected)", receivedAuth, "Bearer secret-token")
	}
}

// TestProxy_ConnectPreCheckSkipsPathRules verifies that CONNECT requests are not
// evaluated against per-path deny rules. The CONNECT tunnel must be allowed at
// the host level so TLS interception can apply path rules to inner HTTP requests.
func TestProxy_ConnectPreCheckSkipsPathRules(t *testing.T) {
	p := NewProxy()
	// Set up strict policy with a RequestChecker that denies everything.
	// Without the CONNECT guard, the checker would block the tunnel itself.
	checker := func(host string, port int, method, path string) bool {
		if host == "httpbin.org" {
			return false // deny all
		}
		return false // strict: deny unknown hosts too
	}
	p.SetNetworkPolicyWithRules("strict", []string{"httpbin.org"}, nil, checker, nil)

	req, _ := http.NewRequest("CONNECT", "http://httpbin.org:443", nil)

	// CONNECT pre-check should allow the tunnel (host is in allow list).
	if !p.checkNetworkPolicyForRequest(req, "httpbin.org", 443, "CONNECT", "") {
		t.Error("CONNECT to httpbin.org:443 should be allowed at tunnel stage despite deny-all checker")
	}

	// A subsequent inner GET should be denied by the checker.
	getReq, _ := http.NewRequest("GET", "http://httpbin.org/anything", nil)
	if p.checkNetworkPolicyForRequest(getReq, "httpbin.org", 443, "GET", "/anything") {
		t.Error("GET /anything should be denied by deny-all checker")
	}

	// Unlisted host should still be blocked under strict policy.
	connectReq2, _ := http.NewRequest("CONNECT", "http://example.com:443", nil)
	if p.checkNetworkPolicyForRequest(connectReq2, "example.com", 443, "CONNECT", "") {
		t.Error("CONNECT to unlisted host example.com should be blocked under strict policy")
	}
}

// TestProxy_SetNetworkPolicyClearsCheckers verifies that SetNetworkPolicy
// clears any previously set request checkers to prevent stale rules.
func TestProxy_SetNetworkPolicyClearsCheckers(t *testing.T) {
	p := NewProxy()

	// First set a deny-all checker via SetNetworkPolicyWithRules.
	checker := func(host string, port int, method, path string) bool {
		return false
	}
	p.SetNetworkPolicyWithRules("strict", []string{"example.com"}, nil, checker, nil)

	// Now switch to plain SetNetworkPolicy — checkers should be cleared.
	p.SetNetworkPolicy("strict", []string{"example.com"}, nil)

	// Without the fix, stale checker would cause GET to be denied.
	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	if !p.checkNetworkPolicyForRequest(req, "example.com", 443, "GET", "/test") {
		t.Error("GET /test should be allowed after SetNetworkPolicy clears checkers")
	}
}

func TestProxy_HasPathRulesForHost(t *testing.T) {
	p := NewProxy()
	pathChecker := func(host string, port int) bool {
		return host == "api.github.com"
	}
	p.SetNetworkPolicyWithRules("strict", []string{"api.github.com", "example.com"}, nil, nil, pathChecker)

	req, _ := http.NewRequest("GET", "http://api.github.com/repos/foo", nil)

	// Host with per-path rules.
	if !p.hasPathRulesForHost(req, "api.github.com", 443) {
		t.Error("api.github.com should have path rules")
	}

	// Host-only entry (no rules).
	if p.hasPathRulesForHost(req, "example.com", 443) {
		t.Error("example.com should not have path rules")
	}

	// Unlisted host.
	if p.hasPathRulesForHost(req, "evil.com", 443) {
		t.Error("unlisted host should not have path rules")
	}
}

// TestProxy_HostGatewayBlocked verifies that requests to the host gateway
// address are blocked by default, even in permissive mode.
func TestProxy_HostGatewayBlocked(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	backendURL := mustParseURL(backend.URL)
	backendHost := backendURL.Hostname()
	backendPort, _ := strconv.Atoi(backendURL.Port())

	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "gw_run" {
			return &RunContextData{
				Policy:      "permissive",
				HostGateway: backendHost,
			}, true
		}
		return nil, false
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, _ := http.NewRequest("GET", backend.URL, nil)
	req.Header.Set("Proxy-Authorization", "Bearer gw_run")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("expected 407 (blocked), got %d", resp.StatusCode)
	}

	if resp.Header.Get("X-Moat-Blocked") != "host-service" {
		t.Errorf("expected X-Moat-Blocked=host-service, got %q", resp.Header.Get("X-Moat-Blocked"))
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), strconv.Itoa(backendPort)) {
		t.Errorf("expected body to mention port %d, got %q", backendPort, string(body))
	}
}

// TestProxy_HostGatewayAllowedPort verifies that requests to the host gateway
// on an explicitly allowed port are permitted.
func TestProxy_HostGatewayAllowedPort(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	backendURL := mustParseURL(backend.URL)
	backendHost := backendURL.Hostname()
	backendPort, _ := strconv.Atoi(backendURL.Port())

	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "gw_allowed" {
			return &RunContextData{
				Policy:           "permissive",
				HostGateway:      backendHost,
				AllowedHostPorts: []int{backendPort},
			}, true
		}
		return nil, false
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, _ := http.NewRequest("GET", backend.URL, nil)
	req.Header.Set("Proxy-Authorization", "Bearer gw_allowed")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// TestProxy_HostGatewayStrictModeAlsoBlocks verifies that the host gateway
// check takes precedence over strict mode AllowedHosts — even if the host is
// in AllowedHosts, it is still blocked unless AllowedHostPorts permits the port.
func TestProxy_HostGatewayStrictModeAlsoBlocks(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	backendURL := mustParseURL(backend.URL)
	backendHost := backendURL.Hostname()

	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "strict_gw" {
			return &RunContextData{
				Policy:      "strict",
				HostGateway: backendHost,
				AllowedHosts: []hostPattern{
					{host: backendHost, port: 0}, // wildcard port
				},
			}, true
		}
		return nil, false
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, _ := http.NewRequest("GET", backend.URL, nil)
	req.Header.Set("Proxy-Authorization", "Bearer strict_gw")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("expected 407 (blocked by host gateway), got %d", resp.StatusCode)
	}

	if resp.Header.Get("X-Moat-Blocked") != "host-service" {
		t.Errorf("expected X-Moat-Blocked=host-service, got %q", resp.Header.Get("X-Moat-Blocked"))
	}
}

// TestProxy_NonHostGatewayUnaffected verifies that requests to non-host-gateway
// addresses are unaffected by the host gateway blocking logic.
func TestProxy_NonHostGatewayUnaffected(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "other_run" {
			return &RunContextData{
				Policy:      "permissive",
				HostGateway: "10.254.254.254", // some other address
			}, true
		}
		return nil, false
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, _ := http.NewRequest("GET", backend.URL, nil)
	req.Header.Set("Proxy-Authorization", "Bearer other_run")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// TestProxy_HostGatewayNoContext verifies that without RunContextData (legacy mode),
// no host gateway blocking is applied.
func TestProxy_HostGatewayNoContext(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()
	// No context resolver set — legacy mode

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, _ := http.NewRequest("GET", backend.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// TestProxy_HostGatewayBlockedCONNECT verifies that CONNECT requests to the host
// gateway are blocked with the host-specific 407 response.
func TestProxy_HostGatewayBlockedCONNECT(t *testing.T) {
	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "test_run" {
			return &RunContextData{
				Policy:      "permissive",
				HostGateway: "host.docker.internal",
			}, true
		}
		return nil, false
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)

	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT host.docker.internal:443 HTTP/1.1\r\n")
	fmt.Fprintf(conn, "Host: host.docker.internal:443\r\n")
	fmt.Fprintf(conn, "Proxy-Authorization: Bearer test_run\r\n")
	fmt.Fprintf(conn, "\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("expected 407, got %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Moat-Blocked") != "host-service" {
		t.Errorf("expected X-Moat-Blocked: host-service, got %q", resp.Header.Get("X-Moat-Blocked"))
	}
}

// TestProxy_HostGatewayLocalhostBypass verifies that on Linux (gateway 127.0.0.1),
// requests to "localhost" are also blocked as host-gateway traffic.
func TestProxy_HostGatewayLocalhostBypass(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	backendURL := mustParseURL(backend.URL)
	backendPort, _ := strconv.Atoi(backendURL.Port())

	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "test_run" {
			return &RunContextData{
				Policy:      "permissive",
				HostGateway: "127.0.0.1", // Linux gateway
			}, true
		}
		return nil, false
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
	}}

	// Request via "localhost" — should still be blocked
	localhostURL := "http://localhost:" + strconv.Itoa(backendPort)
	req, _ := http.NewRequest("GET", localhostURL, nil)
	req.Header.Set("Proxy-Authorization", "Bearer test_run")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("expected 407 (localhost should match 127.0.0.1 gateway), got %d", resp.StatusCode)
	}
}

// TestProxy_HostGatewayLocalhostBypassCONNECT verifies that CONNECT requests to
// "localhost" are also blocked when the gateway is 127.0.0.1.
func TestProxy_HostGatewayLocalhostBypassCONNECT(t *testing.T) {
	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "test_run" {
			return &RunContextData{
				Policy:      "permissive",
				HostGateway: "127.0.0.1",
			}, true
		}
		return nil, false
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)

	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT localhost:443 HTTP/1.1\r\n")
	fmt.Fprintf(conn, "Host: localhost:443\r\n")
	fmt.Fprintf(conn, "Proxy-Authorization: Bearer test_run\r\n")
	fmt.Fprintf(conn, "\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("expected 407 (localhost CONNECT should match 127.0.0.1 gateway), got %d", resp.StatusCode)
	}
}

// TestProxy_HostGatewayMoatHost verifies that when HostGateway is "moat-host"
// (the synthetic hostname used to separate proxy access from host service access),
// requests to "moat-host" are blocked by the host-gateway check.
func TestProxy_HostGatewayMoatHost(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	backendURL := mustParseURL(backend.URL)
	backendPort, _ := strconv.Atoi(backendURL.Port())

	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "moat_host_run" {
			return &RunContextData{
				Policy:      "permissive",
				HostGateway: "moat-host",
			}, true
		}
		return nil, false
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	// Request to moat-host:<port> should be blocked
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://moat-host:%d/", backendPort), nil)
	req.Header.Set("Proxy-Authorization", "Bearer moat_host_run")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("expected 407 (blocked), got %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Moat-Blocked") != "host-service" {
		t.Errorf("expected X-Moat-Blocked=host-service, got %q", resp.Header.Get("X-Moat-Blocked"))
	}
}

// TestProxy_HostGatewayMoatHostAllowedPort verifies that requests to "moat-host"
// on an explicitly allowed port are permitted.
func TestProxy_HostGatewayMoatHostAllowedPort(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	backendURL := mustParseURL(backend.URL)
	backendPort, _ := strconv.Atoi(backendURL.Port())

	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "moat_host_allowed" {
			return &RunContextData{
				Policy:           "permissive",
				HostGateway:      "moat-host",
				HostGatewayIP:    backendURL.Hostname(), // actual IP so proxy can forward
				AllowedHostPorts: []int{backendPort},
			}, true
		}
		return nil, false
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, _ := http.NewRequest("GET", fmt.Sprintf("http://moat-host:%d/", backendPort), nil)
	req.Header.Set("Proxy-Authorization", "Bearer moat_host_allowed")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// The proxy should rewrite "moat-host" to the actual IP (HostGatewayIP)
	// and forward the request to the backend successfully.
	if resp.StatusCode == http.StatusProxyAuthRequired {
		t.Errorf("expected request to be allowed (port %d in AllowedHostPorts), got 407", backendPort)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

// TestIsHostGatewayAliases verifies that loopback aliases (localhost, ::1,
// 127.0.0.1) are treated as host-gateway when HostGateway is either the
// synthetic hostname or the legacy 127.0.0.1 form. A container that issues
// "CONNECT localhost:8080" must not slip past the host-service block by
// using a loopback alias instead of the canonical synthetic hostname.
func TestIsHostGatewayAliases(t *testing.T) {
	cases := []struct {
		name    string
		gateway string
		host    string
		want    bool
	}{
		{"synthetic matches self", "moat-host", "moat-host", true},
		{"synthetic matches localhost", "moat-host", "localhost", true},
		{"synthetic matches 127.0.0.1", "moat-host", "127.0.0.1", true},
		{"synthetic matches ::1", "moat-host", "::1", true},
		{"synthetic rejects unrelated", "moat-host", "api.example.com", false},
		{"legacy 127 matches localhost", "127.0.0.1", "localhost", true},
		{"legacy 127 matches ::1", "127.0.0.1", "::1", true},
		{"legacy 127 matches 127.0.0.1", "127.0.0.1", "127.0.0.1", true},
		{"empty gateway never matches", "", "localhost", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc := &RunContextData{HostGateway: tc.gateway}
			if got := isHostGateway(rc, tc.host); got != tc.want {
				t.Errorf("isHostGateway(gw=%q, host=%q) = %v, want %v",
					tc.gateway, tc.host, got, tc.want)
			}
		})
	}
}

// TestRewriteURLHost verifies that URL host rewriting preserves port, path,
// query, and fragment and emits a valid URL for IPv6 loopback aliases. The
// naive strings.Replace approach used prior to this helper produced
// "http://[127.0.0.1]:8080/path" — an IPv4 address inside IPv6 brackets,
// which is an invalid URL.
func TestRewriteURLHost(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		newHost string
		want    string
	}{
		{"ipv6 loopback with port", "http://[::1]:8080/path", "127.0.0.1", "http://127.0.0.1:8080/path"},
		{"ipv6 loopback no port", "http://[::1]/path", "127.0.0.1", "http://127.0.0.1/path"},
		{"synthetic hostname with port", "http://moat-host:8080/api", "127.0.0.1", "http://127.0.0.1:8080/api"},
		{"preserves query and fragment", "http://moat-host:8080/x?q=moat-host#moat-host", "127.0.0.1", "http://127.0.0.1:8080/x?q=moat-host#moat-host"},
		{"preserves https scheme", "https://moat-host/path", "127.0.0.1", "https://127.0.0.1/path"},
		{"ipv6 target host brackets correctly", "http://moat-host:8080/x", "::1", "http://[::1]:8080/x"},
		{"ipv6 target host no port brackets correctly", "http://moat-host/x", "::1", "http://[::1]/x"},
		{"malformed URL returns input", "not a url", "127.0.0.1", "not a url"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rewriteURLHost(tc.in, tc.newHost); got != tc.want {
				t.Errorf("rewriteURLHost(%q, %q) = %q, want %q", tc.in, tc.newHost, got, tc.want)
			}
		})
	}
}

// TestProxy_HostGatewayMoatHostBypassAliases verifies that when HostGateway is
// "moat-host", requests to loopback aliases (localhost, 127.0.0.1, ::1) are
// blocked as host-gateway traffic. This prevents containers from bypassing the
// host-service firewall by addressing the host via a loopback alias instead of
// the synthetic "moat-host" hostname.
func TestProxy_HostGatewayMoatHostBypassAliases(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	backendURL := mustParseURL(backend.URL)
	backendPort, _ := strconv.Atoi(backendURL.Port())

	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "moat_host_bypass" {
			return &RunContextData{
				Policy:      "permissive",
				HostGateway: "moat-host",
			}, true
		}
		return nil, false
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	// Each loopback alias should be blocked when gateway is "moat-host".
	aliases := []string{"localhost", "127.0.0.1", "::1"}
	for _, alias := range aliases {
		t.Run(alias, func(t *testing.T) {
			// Build the target URL. For IPv6 literals, wrap in brackets.
			host := alias
			if strings.Contains(alias, ":") {
				host = "[" + alias + "]"
			}
			targetURL := fmt.Sprintf("http://%s:%d/", host, backendPort)

			req, _ := http.NewRequest("GET", targetURL, nil)
			req.Header.Set("Proxy-Authorization", "Bearer moat_host_bypass")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request to %s failed: %v", alias, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusProxyAuthRequired {
				t.Errorf("expected 407 (blocked), got %d for alias %q", resp.StatusCode, alias)
			}
			if resp.Header.Get("X-Moat-Blocked") != "host-service" {
				t.Errorf("expected X-Moat-Blocked=host-service for alias %q, got %q",
					alias, resp.Header.Get("X-Moat-Blocked"))
			}
		})
	}
}

// TestProxy_HostGatewayMoatHostBypassAliasesCONNECT verifies that CONNECT
// requests to loopback aliases are also blocked when HostGateway is "moat-host".
func TestProxy_HostGatewayMoatHostBypassAliasesCONNECT(t *testing.T) {
	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "moat_host_bypass" {
			return &RunContextData{
				Policy:      "permissive",
				HostGateway: "moat-host",
			}, true
		}
		return nil, false
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)

	// Test CONNECT for each loopback alias.
	aliases := []struct {
		name string
		host string // host:port for CONNECT line
	}{
		{"localhost", "localhost:443"},
		{"127.0.0.1", "127.0.0.1:443"},
		{"::1", "[::1]:443"},
	}
	for _, tc := range aliases {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", proxyURL.Host)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\n", tc.host)
			fmt.Fprintf(conn, "Host: %s\r\n", tc.host)
			fmt.Fprintf(conn, "Proxy-Authorization: Bearer moat_host_bypass\r\n")
			fmt.Fprintf(conn, "\r\n")

			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusProxyAuthRequired {
				t.Errorf("expected 407 for CONNECT to %s, got %d", tc.host, resp.StatusCode)
			}
			if resp.Header.Get("X-Moat-Blocked") != "host-service" {
				t.Errorf("expected X-Moat-Blocked=host-service for %s, got %q",
					tc.host, resp.Header.Get("X-Moat-Blocked"))
			}
		})
	}
}

// TestProxy_HostGatewayMoatHostAllowedPortBypassAlias verifies that when a port
// is in AllowedHostPorts and HostGateway is "moat-host", a request through a
// loopback alias (e.g., localhost) is still permitted — the port allowlist
// applies to all host-gateway aliases, not just the canonical hostname.
func TestProxy_HostGatewayMoatHostAllowedPortBypassAlias(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	backendURL := mustParseURL(backend.URL)
	backendPort, _ := strconv.Atoi(backendURL.Port())

	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "allowed_alias" {
			return &RunContextData{
				Policy:           "permissive",
				HostGateway:      "moat-host",
				HostGatewayIP:    backendURL.Hostname(),
				AllowedHostPorts: []int{backendPort},
			}, true
		}
		return nil, false
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	// Request via "localhost" alias — should be allowed because port is in AllowedHostPorts.
	targetURL := fmt.Sprintf("http://localhost:%d/", backendPort)
	req, _ := http.NewRequest("GET", targetURL, nil)
	req.Header.Set("Proxy-Authorization", "Bearer allowed_alias")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 (allowed via AllowedHostPorts), got %d", resp.StatusCode)
	}
}

// TestRewriteHostPort verifies that host:port rewriting handles bracketed
// IPv6 inputs correctly and emits bracketed form when the target is IPv6.
func TestRewriteHostPort(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		newHost string
		want    string
	}{
		{"ipv6 loopback to ipv4", "[::1]:8080", "127.0.0.1", "127.0.0.1:8080"},
		{"synthetic hostname to ipv4", "moat-host:8080", "127.0.0.1", "127.0.0.1:8080"},
		{"ipv4 to ipv6 adds brackets", "moat-host:8080", "::1", "[::1]:8080"},
		{"missing port returns input unchanged", "moat-host", "127.0.0.1", "moat-host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rewriteHostPort(tc.in, tc.newHost); got != tc.want {
				t.Errorf("rewriteHostPort(%q, %q) = %q, want %q", tc.in, tc.newHost, got, tc.want)
			}
		})
	}
}

func TestProxy_CredentialResolver(t *testing.T) {
	var receivedAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetCredentialResolver("127.0.0.1", func(ctx context.Context, _, _ *http.Request, host string) ([]CredentialHeader, error) {
		return []CredentialHeader{{Name: "Authorization", Value: "Bearer dynamic-token", Grant: "test"}}, nil
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if receivedAuth != "Bearer dynamic-token" {
		t.Errorf("Authorization = %q, want %q", receivedAuth, "Bearer dynamic-token")
	}
}

func TestProxy_CredentialResolverError(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("backend should not be called when resolver fails")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetCredentialResolver("127.0.0.1", func(ctx context.Context, _, _ *http.Request, host string) ([]CredentialHeader, error) {
		return nil, fmt.Errorf("STS endpoint unreachable")
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
}

func TestProxy_ResolverFallbackToStatic(t *testing.T) {
	var receivedAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	var resolverCalled atomic.Bool
	p := NewProxy()
	p.SetCredential("127.0.0.1", "Bearer static-token")
	p.SetCredentialResolver("127.0.0.1", func(ctx context.Context, _, _ *http.Request, host string) ([]CredentialHeader, error) {
		resolverCalled.Store(true)
		return nil, nil
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	req, _ := http.NewRequest("GET", backend.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if !resolverCalled.Load() {
		t.Error("resolver should be called before falling back to static credentials")
	}
	if receivedAuth != "Bearer static-token" {
		t.Errorf("Authorization = %q, want %q", receivedAuth, "Bearer static-token")
	}
}

func TestProxy_ResolverTakesPriorityOverStatic(t *testing.T) {
	var receivedAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetCredential("127.0.0.1", "Bearer static-token")
	p.SetCredentialResolver("127.0.0.1", func(ctx context.Context, _, _ *http.Request, host string) ([]CredentialHeader, error) {
		return []CredentialHeader{{Name: "Authorization", Value: "Bearer resolver-token", Grant: "test"}}, nil
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if receivedAuth != "Bearer resolver-token" {
		t.Errorf("Authorization = %q, want %q (resolver should take priority over static)", receivedAuth, "Bearer resolver-token")
	}
}

func TestProxy_ResolverErrorDoesNotFallbackToStatic(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("backend should not be called when resolver returns an error")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetCredential("127.0.0.1", "Bearer static-token")
	p.SetCredentialResolver("127.0.0.1", func(ctx context.Context, _, _ *http.Request, host string) ([]CredentialHeader, error) {
		return nil, errors.New("sts unavailable")
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want %d (resolver error should not fall through to static)", resp.StatusCode, http.StatusBadGateway)
	}
}

func TestProxy_CredentialResolverStripsSubjectHeader(t *testing.T) {
	var receivedAuth string
	var receivedSubject string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		receivedSubject = r.Header.Get("X-Gatekeeper-Subject")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetCredentialResolver("127.0.0.1", func(ctx context.Context, _, innerReq *http.Request, host string) ([]CredentialHeader, error) {
		subject := innerReq.Header.Get("X-Gatekeeper-Subject")
		if subject == "" {
			return nil, nil
		}
		innerReq.Header.Del("X-Gatekeeper-Subject")
		return []CredentialHeader{{
			Name:  "Authorization",
			Value: "Bearer token-for-" + subject,
			Grant: "test",
		}}, nil
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	req, _ := http.NewRequest("GET", backend.URL, nil)
	req.Header.Set("X-Gatekeeper-Subject", "usr_abc123")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if receivedAuth != "Bearer token-for-usr_abc123" {
		t.Errorf("Authorization = %q, want %q", receivedAuth, "Bearer token-for-usr_abc123")
	}
	if receivedSubject != "" {
		t.Errorf("X-Gatekeeper-Subject should be stripped, got %q", receivedSubject)
	}
}

func TestProxy_CredentialResolverNoMatch(t *testing.T) {
	var receivedAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()
	// Resolver registered for a different host
	p.SetCredentialResolver("api.example.com", func(ctx context.Context, _, _ *http.Request, host string) ([]CredentialHeader, error) {
		t.Error("resolver should not be called for non-matching host")
		return nil, nil
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(mustParseURL(proxyServer.URL)),
		},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if receivedAuth != "" {
		t.Errorf("Authorization should be empty for non-matching host, got %q", receivedAuth)
	}
}

func TestExtractProxyUsername(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
	}{
		{"basic auth", "Basic " + basicAuth("alice", "secret"), "alice"},
		{"empty username", "Basic " + basicAuth("", "secret"), ""},
		{"bearer token", "Bearer some-token", ""},
		{"no header", "", ""},
		{"invalid base64", "Basic !!!invalid!!!", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", "http://example.com", nil)
			if tt.header != "" {
				r.Header.Set("Proxy-Authorization", tt.header)
			}
			got := extractProxyUsername(r)
			if got != tt.want {
				t.Errorf("extractProxyUsername() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProxy_CanonicalLogLine_UserID_ContextResolver(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "my-token" {
			return &RunContextData{Policy: "permissive"}, true
		}
		return nil, false
	})

	var logged RequestLogData
	p.SetLogger(func(data RequestLogData) {
		logged = data
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)
	proxyURL.User = url.UserPassword("alice", "my-token")

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(backend.URL + "/test")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if logged.UserID != "alice" {
		t.Errorf("UserID = %q, want %q", logged.UserID, "alice")
	}
}

func TestProxy_CanonicalLogLine_UserID_StaticAuthToken(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetAuthToken("secret-token")

	var logged RequestLogData
	p.SetLogger(func(data RequestLogData) {
		logged = data
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)
	proxyURL.User = url.UserPassword("bob", "secret-token")

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	resp, err := client.Get(backend.URL + "/test")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if logged.UserID != "bob" {
		t.Errorf("UserID = %q, want %q", logged.UserID, "bob")
	}
}

func TestProxy_CanonicalLogLine_UserID_BearerNoUsername(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "bearer-token" {
			return &RunContextData{Policy: "permissive"}, true
		}
		return nil, false
	})

	var logged RequestLogData
	p.SetLogger(func(data RequestLogData) {
		logged = data
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	proxyURL := mustParseURL(proxyServer.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, _ := http.NewRequest("GET", backend.URL+"/test", nil)
	req.Header.Set("Proxy-Authorization", "Bearer bearer-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if logged.UserID != "" {
		t.Errorf("UserID = %q, want empty (Bearer has no username)", logged.UserID)
	}
}

func TestProxy_CaptureHeaders_StrippedBeforeForwarding(t *testing.T) {
	var receivedHeaders http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetCaptureHeaders([]string{"X-Workspace-Slug", "X-Request-Source"})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustParseURL(proxyServer.URL))}}

	req, _ := http.NewRequest("GET", backend.URL+"/test", nil)
	req.Header.Set("X-Workspace-Slug", "sneaky-plum")
	req.Header.Set("X-Request-Source", "agent")
	req.Header.Set("X-Other", "keep-this")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if receivedHeaders.Get("X-Workspace-Slug") != "" {
		t.Error("X-Workspace-Slug should be stripped before forwarding")
	}
	if receivedHeaders.Get("X-Request-Source") != "" {
		t.Error("X-Request-Source should be stripped before forwarding")
	}
	if receivedHeaders.Get("X-Other") != "keep-this" {
		t.Errorf("X-Other = %q, want keep-this (non-capture headers should pass through)", receivedHeaders.Get("X-Other"))
	}
}

func TestProxy_CaptureHeaders_AvailableInLogData(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	p := NewProxy()
	p.SetCaptureHeaders([]string{"X-Workspace-Slug"})

	var logged RequestLogData
	p.SetLogger(func(data RequestLogData) {
		logged = data
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustParseURL(proxyServer.URL))}}

	req, _ := http.NewRequest("GET", backend.URL+"/test", nil)
	req.Header.Set("X-Workspace-Slug", "sneaky-plum")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	// RequestHeaders should contain the original headers (before stripping)
	if logged.RequestHeaders == nil {
		t.Fatal("RequestHeaders is nil")
	}
	if got := logged.RequestHeaders.Get("X-Workspace-Slug"); got != "sneaky-plum" {
		t.Errorf("RequestHeaders[X-Workspace-Slug] = %q, want sneaky-plum", got)
	}
}

// TestTunnel_ForwardsPlainHTTPS verifies that when the proxy has no CA
// configured, a CONNECT request is forwarded as a raw TCP tunnel without
// TLS interception.
func TestTunnel_ForwardsPlainHTTPS(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "tunneled")
	}))
	t.Cleanup(backend.Close)

	p := NewProxy()
	proxyServer := httptest.NewServer(p)
	t.Cleanup(proxyServer.Close)

	backendCAs := x509.NewCertPool()
	backendCAs.AddCert(backend.Certificate())

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(mustParseURL(proxyServer.URL)),
			TLSClientConfig: &tls.Config{RootCAs: backendCAs},
		},
	}

	resp, err := client.Get(backend.URL + "/hello")
	if err != nil {
		t.Fatalf("GET through tunnel: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "tunneled" {
		t.Errorf("body = %q, want %q", string(body), "tunneled")
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// TestTunnel_NetworkPolicyBlocked verifies that the network policy is enforced
// even when no CA is set (tunnel mode).
func TestTunnel_NetworkPolicyBlocked(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "should not reach")
	}))
	t.Cleanup(backend.Close)

	p := NewProxy()
	p.SetNetworkPolicy("strict", nil, nil)
	proxyServer := httptest.NewServer(p)
	t.Cleanup(proxyServer.Close)

	backendCAs := x509.NewCertPool()
	backendCAs.AddCert(backend.Certificate())

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(mustParseURL(proxyServer.URL)),
			TLSClientConfig: &tls.Config{RootCAs: backendCAs},
		},
	}

	resp, err := client.Get(backend.URL + "/hello")
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Errorf("expected blocked response, got 200")
	}
}

// TestTunnel_InvalidHostFormat verifies that a malformed CONNECT target
// (missing port) returns a 400 Bad Request.
func TestTunnel_InvalidHostFormat(t *testing.T) {
	p := NewProxy()
	proxyServer := httptest.NewServer(p)
	t.Cleanup(proxyServer.Close)

	conn, err := net.Dial("tcp", proxyServer.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT noporthost HTTP/1.1\r\nHost: noporthost\r\n\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// TestNewTokenSubstitution verifies the exported constructor returns a usable substitution.
func TestNewTokenSubstitution(t *testing.T) {
	sub := NewTokenSubstitution("placeholder", "real")
	if sub == nil {
		t.Fatal("NewTokenSubstitution returned nil")
	}
}

// TestProxy_GetCredentialsForRequest_CaseFoldPortBearingExactKey verifies
// that the case-insensitive exact tier also folds port-bearing keys
// (expressible in embedder-built RunContextData maps): a case-variant
// host:port must hit its exact entry, not fall through to a wildcard.
func TestProxy_GetCredentialsForRequest_CaseFoldPortBearingExactKey(t *testing.T) {
	p := NewProxy()
	rc := &RunContextData{
		Credentials: map[string][]credentialHeader{
			"internal.example.com:8443": {{Name: "Authorization", Value: "Bearer exact", Grant: "exact-grant"}},
			"*.example.com:8443":        {{Name: "Authorization", Value: "Bearer wild", Grant: "wild-grant"}},
		},
	}
	req := httptest.NewRequest("GET", "https://internal.example.com:8443/", nil)
	req = req.WithContext(context.WithValue(req.Context(), runContextKey, rc))

	creds, err := p.getCredentialsForRequest(req, req, "Internal.example.com:8443")
	if err != nil {
		t.Fatalf("getCredentialsForRequest: %v", err)
	}
	if len(creds) != 1 || creds[0].Grant != "exact-grant" {
		t.Fatalf("grant = %v, want exact-grant (case-variant host:port must hit its port-bearing exact key)", creds)
	}
}

// TestProxy_GetCredentialsForRequest_WildcardSpecificityIgnoresPort verifies
// that wildcard specificity is ranked by the domain part of the key, not raw
// byte length: a port suffix must not make a domain-broader key outrank a
// domain-narrower one, while at equal domain specificity a port-pinned key
// beats a port-less one.
func TestProxy_GetCredentialsForRequest_WildcardSpecificityIgnoresPort(t *testing.T) {
	p := NewProxy()
	rc := &RunContextData{
		Credentials: map[string][]credentialHeader{
			"*.example.com:8443": {{Name: "Authorization", Value: "Bearer broad", Grant: "broad-grant"}},
			"*.api.example.com":  {{Name: "Authorization", Value: "Bearer narrow", Grant: "narrow-grant"}},
		},
	}
	req := httptest.NewRequest("GET", "https://svc.api.example.com:8443/", nil)
	req = req.WithContext(context.WithValue(req.Context(), runContextKey, rc))

	creds, err := p.getCredentialsForRequest(req, req, "svc.api.example.com:8443")
	if err != nil {
		t.Fatalf("getCredentialsForRequest: %v", err)
	}
	if len(creds) != 1 || creds[0].Grant != "narrow-grant" {
		t.Fatalf("grant = %v, want narrow-grant (domain specificity must outrank a port suffix)", creds)
	}

	rc2 := &RunContextData{
		Credentials: map[string][]credentialHeader{
			"*.api.example.com:8443": {{Name: "Authorization", Value: "Bearer pinned", Grant: "pinned-grant"}},
			"*.api.example.com":      {{Name: "Authorization", Value: "Bearer plain", Grant: "plain-grant"}},
		},
	}
	req2 := httptest.NewRequest("GET", "https://svc.api.example.com:8443/", nil)
	req2 = req2.WithContext(context.WithValue(req2.Context(), runContextKey, rc2))

	creds, err = p.getCredentialsForRequest(req2, req2, "svc.api.example.com:8443")
	if err != nil {
		t.Fatalf("getCredentialsForRequest: %v", err)
	}
	if len(creds) != 1 || creds[0].Grant != "pinned-grant" {
		t.Fatalf("grant = %v, want pinned-grant (port-pinned key beats port-less at equal domain)", creds)
	}
}

// TestProxy_GetCredentialsForRequest_FoldTierPortPrecedence verifies that
// the case-insensitive exact tier keeps the verbatim tiers' precedence: a
// key fold-matching the full host:port beats a key fold-matching only the
// bare host, so request-host casing cannot flip which credential is sent.
func TestProxy_GetCredentialsForRequest_FoldTierPortPrecedence(t *testing.T) {
	p := NewProxy()
	rc := &RunContextData{
		Credentials: map[string][]credentialHeader{
			"API.example.com":      {{Name: "Authorization", Value: "Bearer portless", Grant: "portless-grant"}},
			"API.example.com:8443": {{Name: "Authorization", Value: "Bearer pinned", Grant: "pinned-grant"}},
		},
	}
	req := httptest.NewRequest("GET", "https://api.example.com:8443/", nil)
	req = req.WithContext(context.WithValue(req.Context(), runContextKey, rc))

	// Repeat: a map-iteration-order-dependent pick must not pass by luck.
	for i := range 100 {
		creds, err := p.getCredentialsForRequest(req, req, "api.example.com:8443")
		if err != nil {
			t.Fatalf("getCredentialsForRequest: %v", err)
		}
		if len(creds) != 1 || creds[0].Grant != "pinned-grant" {
			t.Fatalf("iteration %d: creds = %v, want pinned-grant (host:port fold match must beat bare fold match)", i, creds)
		}
	}
}

// TestProxy_HostKeyedMaps_EmptyEntryOptOut verifies presence-based exact
// matching for the companion host-keyed maps: an embedder-supplied explicit
// empty/nil entry for host:port opts that port out, suppressing both the
// bare-host entry and any wildcard entry — the pre-wildcard behavior for
// these maps, which embedders may rely on to keep secrets off specific
// ports. (Credentials keep their historical len>0 gating instead; see
// TestProxy_GetCredentialsForRequest_EmptyExactEntryFallsThrough.)
func TestProxy_HostKeyedMaps_EmptyEntryOptOut(t *testing.T) {
	const optedOut = "internal.example.com:8443"
	p := NewProxy()
	rc := &RunContextData{
		ExtraHeaders: map[string][]extraHeader{
			"internal.example.com": {{Name: "X-Secret", Value: "s3cret"}},
			optedOut:               nil,
		},
		RemoveHeaders: map[string][]string{
			"*.example.com": {"X-Strip"},
			optedOut:        nil,
		},
		TokenSubstitutions: map[string]*tokenSubstitution{
			"internal.example.com": {placeholder: "PLACEHOLDER", realToken: "real"},
			optedOut:               nil,
		},
		ResponseTransformers: map[string][]ResponseTransformer{
			"internal.example.com": {func(req, resp any) (any, bool) { return resp, false }},
			optedOut:               nil,
		},
	}
	req := httptest.NewRequest("GET", "https://"+optedOut+"/", nil)
	req = req.WithContext(context.WithValue(req.Context(), runContextKey, rc))

	if got := p.getExtraHeadersForRequest(req, optedOut); len(got) != 0 {
		t.Errorf("getExtraHeadersForRequest(%q) = %v, want none (explicit nil entry opts the port out)", optedOut, got)
	}
	if got := p.getRemoveHeadersForRequest(req, optedOut); len(got) != 0 {
		t.Errorf("getRemoveHeadersForRequest(%q) = %v, want none (explicit nil entry opts the port out)", optedOut, got)
	}
	if sub := p.getTokenSubstitutionForRequest(req, optedOut); sub != nil {
		t.Errorf("getTokenSubstitutionForRequest(%q) = %v, want nil (explicit nil entry opts the port out)", optedOut, sub)
	}
	if got := p.getResponseTransformersForRequest(req, optedOut); len(got) != 0 {
		t.Errorf("getResponseTransformersForRequest(%q) returned %d transformers, want none (explicit nil entry opts the port out)", optedOut, len(got))
	}
}

// TestProxy_GetCredentialsForRequest_NilResolverOptOut verifies that an
// explicitly-nil resolver entry disables resolution for that host — the
// pre-wildcard behavior, where the nil exact entry was found and treated as
// "no resolver" — instead of being skipped so a broader wildcard resolver
// fires for a host the embedder deliberately opted out.
func TestProxy_GetCredentialsForRequest_NilResolverOptOut(t *testing.T) {
	p := NewProxy()
	var invoked atomic.Bool
	p.SetCredentialResolver("*.example.com", func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]credentialHeader, error) {
		invoked.Store(true)
		return []credentialHeader{{Name: "Authorization", Value: "Bearer resolver-token", Grant: "resolver-grant"}}, nil
	})
	p.SetCredentialResolver("api.example.com", nil)
	p.SetCredentialWithGrant("api.example.com", "Authorization", "Bearer static-token", "static-grant")
	req := httptest.NewRequest("GET", "https://api.example.com/", nil)

	creds, err := p.getCredentialsForRequest(req, req, "api.example.com")
	if err != nil {
		t.Fatalf("getCredentialsForRequest: %v", err)
	}
	if invoked.Load() {
		t.Fatal("wildcard resolver ran for a host whose resolver was explicitly set to nil (opt-out must block broader resolvers)")
	}
	if len(creds) != 1 || creds[0].Grant != "static-grant" {
		t.Fatalf("creds = %v, want static-grant", creds)
	}

	// The wildcard resolver still serves hosts that were not opted out.
	creds, err = p.getCredentialsForRequest(req, req, "other.example.com")
	if err != nil {
		t.Fatalf("getCredentialsForRequest(other): %v", err)
	}
	if len(creds) != 1 || creds[0].Grant != "resolver-grant" {
		t.Fatalf("creds = %v, want resolver-grant", creds)
	}
}

// TestProxy_GetCredentialsForRequest_VerbatimStaticBeatsFoldResolver
// verifies cross-map rank distinguishes verbatim from case-fold exact
// matches: a static credential registered under the host's verbatim casing
// beats a resolver whose key matches only by case folding — the same order
// the tiers use inside a single map.
func TestProxy_GetCredentialsForRequest_VerbatimStaticBeatsFoldResolver(t *testing.T) {
	p := NewProxy()
	p.SetCredentialWithGrant("api.example.com", "Authorization", "Bearer static-token", "static-grant")
	p.SetCredentialResolver("API.example.com", func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]credentialHeader, error) {
		return []credentialHeader{{Name: "Authorization", Value: "Bearer resolver-token", Grant: "resolver-grant"}}, nil
	})
	req := httptest.NewRequest("GET", "https://api.example.com/", nil)

	creds, err := p.getCredentialsForRequest(req, req, "api.example.com")
	if err != nil {
		t.Fatalf("getCredentialsForRequest: %v", err)
	}
	if len(creds) != 1 || creds[0].Grant != "static-grant" {
		t.Fatalf("creds = %v, want static-grant (verbatim static must beat fold-only resolver)", creds)
	}
}

// TestProxy_HandleHTTP_PolicyCheckedBeforeResolvers verifies that plain-HTTP
// requests to policy-denied hosts are rejected before credential resolution
// runs: a wildcard-matched resolver must not perform external side effects
// (e.g. token-exchange round trips) for hosts the client may not reach, and
// the client must see the policy denial, not a resolver error.
func TestProxy_HandleHTTP_PolicyCheckedBeforeResolvers(t *testing.T) {
	p := NewProxy()
	p.SetNetworkPolicy("strict", []string{"allowed.example.com"}, nil)
	var invoked atomic.Bool
	p.SetCredentialResolver("*.example.com", func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]credentialHeader, error) {
		invoked.Store(true)
		return nil, errors.New("sts unavailable")
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(mustParseURL(proxyServer.URL))},
	}

	resp, err := client.Get("http://denied.example.com/")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("status = %d, want %d (policy denial, not a resolver error)", resp.StatusCode, http.StatusProxyAuthRequired)
	}
	if invoked.Load() {
		t.Error("resolver ran for a policy-denied host (external side effects must not be reachable through denied hosts)")
	}
}

// TestProxy_HandleHTTP_PortPinnedCredentialKey verifies the plain-HTTP path
// passes the port-bearing request host to credential lookup, so a
// port-pinned key (expressible in embedder-built maps) matches. The key is
// written directly to the map: SetCredentialWithGrant rejects ':' in hosts.
func TestProxy_HandleHTTP_PortPinnedCredentialKey(t *testing.T) {
	var receivedAuth string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()
	hostPort := mustParseURL(backend.URL).Host // "127.0.0.1:PORT"
	p.mu.Lock()
	p.credentials[hostPort] = []credentialHeader{{Name: "Authorization", Value: "Bearer port-pinned", Grant: "pinned-grant"}}
	p.mu.Unlock()

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(mustParseURL(proxyServer.URL))},
	}

	resp, err := client.Get(backend.URL + "/")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if receivedAuth != "Bearer port-pinned" {
		t.Errorf("Authorization = %q, want %q (port-pinned key must match on the plain-HTTP path)", receivedAuth, "Bearer port-pinned")
	}
}

// TestProxy_HandleHTTP_LogsExcludeResolverStrippedHeaders verifies that the
// plain-HTTP request log snapshots headers after the credential resolver has
// run, so a subject-identity token the resolver strips (e.g. a
// token-exchange subject header) never reaches the request log — credential
// values must never be logged.
func TestProxy_HandleHTTP_LogsExcludeResolverStrippedHeaders(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()
	host := mustParseURL(backend.URL).Hostname()
	p.SetCredentialResolver(host, func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]credentialHeader, error) {
		innerReq.Header.Del("X-Subject-Token")
		return []credentialHeader{{Name: "Authorization", Value: "Bearer exchanged", Grant: "exchange-grant"}}, nil
	})

	var mu sync.Mutex
	var logged []RequestLogData
	p.SetLogger(func(data RequestLogData) {
		mu.Lock()
		defer mu.Unlock()
		logged = append(logged, data)
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(mustParseURL(proxyServer.URL))},
	}

	req, _ := http.NewRequest("GET", backend.URL+"/", nil)
	req.Header.Set("X-Subject-Token", "super-secret-subject-jwt")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(logged) == 0 {
		t.Fatal("no request was logged")
	}
	for _, data := range logged {
		if got := data.RequestHeaders.Get("X-Subject-Token"); got != "" {
			t.Fatalf("request log contains X-Subject-Token = %q; resolver-stripped credentials must not be logged", got)
		}
	}
}

// TestProxy_HandleHTTP_LogsClientAddr verifies that every canonical log line
// produced by the plain-HTTP path carries the client's network address as
// seen by the listener, so operators can tell which peer sent a request
// without relying on token identity alone.
func TestProxy_HandleHTTP_LogsClientAddr(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	p := NewProxy()

	var mu sync.Mutex
	var logged []RequestLogData
	p.SetLogger(func(data RequestLogData) {
		mu.Lock()
		defer mu.Unlock()
		logged = append(logged, data)
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(mustParseURL(proxyServer.URL))},
	}

	req, _ := http.NewRequest("GET", backend.URL+"/", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(logged) == 0 {
		t.Fatal("no request was logged")
	}
	for _, data := range logged {
		if data.ClientAddr == "" {
			t.Fatalf("ClientAddr is empty, want the client's listener-observed address")
		}
		host, _, err := net.SplitHostPort(data.ClientAddr)
		if err != nil {
			t.Fatalf("ClientAddr = %q: SplitHostPort: %v", data.ClientAddr, err)
		}
		if net.ParseIP(host) == nil {
			t.Fatalf("ClientAddr host = %q, want a valid IP", host)
		}
		if host != "127.0.0.1" {
			t.Errorf("ClientAddr host = %q, want 127.0.0.1", host)
		}
	}
}

// TestProxy_GetCredentialsForRequest_BracketedIPv6Host verifies that a
// bracketed, portless IPv6 lookup host like "[::1]" matches an
// embedder-supplied key stored in canonical unbracketed form ("::1").
func TestProxy_GetCredentialsForRequest_BracketedIPv6Host(t *testing.T) {
	p := NewProxy()
	rc := &RunContextData{
		Credentials: map[string][]credentialHeader{
			"::1": {{Name: "Authorization", Value: "Bearer v6", Grant: "v6-grant"}},
		},
	}
	req := httptest.NewRequest("GET", "http://[::1]/", nil)
	req = req.WithContext(context.WithValue(req.Context(), runContextKey, rc))

	for _, host := range []string{"[::1]", "[::1]:8080"} {
		creds, err := p.getCredentialsForRequest(req, req, host)
		if err != nil {
			t.Fatalf("getCredentialsForRequest(%q): %v", host, err)
		}
		if len(creds) != 1 || creds[0].Grant != "v6-grant" {
			t.Fatalf("getCredentialsForRequest(%q) = %v, want v6-grant credential", host, creds)
		}
	}
}

// TestProxy_HandleHTTP_DefaultPortPinnedKey verifies that the plain-HTTP
// path presents a port-bearing lookup host even when the client omits the
// scheme-default port, so a key pinned to ":80" fires for
// "http://host/" and not only for "http://host:80/".
func TestProxy_HandleHTTP_DefaultPortPinnedKey(t *testing.T) {
	var mu sync.Mutex
	var receivedAuth string
	orig := httpTransport
	defer func() { httpTransport = orig }()
	httpTransport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		mu.Lock()
		receivedAuth = req.Header.Get("Authorization")
		mu.Unlock()
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("ok")),
			Request:    req,
		}, nil
	})

	p := NewProxy()
	p.mu.Lock()
	p.credentials["internal.example.com:80"] = []credentialHeader{{Name: "Authorization", Value: "Bearer default-port", Grant: "port80-grant"}}
	p.mu.Unlock()

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(mustParseURL(proxyServer.URL))},
	}

	resp, err := client.Get("http://internal.example.com/")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if receivedAuth != "Bearer default-port" {
		t.Errorf("Authorization = %q, want %q (:80-pinned key must fire when the client omits the default port)", receivedAuth, "Bearer default-port")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestProxy_HandleHTTP_PolicyAndLookupPortAgree verifies that the
// credential lookup for handleHTTP sees the same port the network-policy
// check evaluated. For an out-of-range URL port (e.g. ":99999"), the
// policy check falls back to port 80 (documented behavior), so the
// credential lookup must also resolve to ":80" — not the raw, unparseable
// URL port — or the two layers disagree about which host:port the
// request is really going to.
func TestProxy_HandleHTTP_PolicyAndLookupPortAgree(t *testing.T) {
	var mu sync.Mutex
	var receivedAuth string
	orig := httpTransport
	defer func() { httpTransport = orig }()
	httpTransport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		mu.Lock()
		receivedAuth = req.Header.Get("Authorization")
		mu.Unlock()
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("ok")),
			Request:    req,
		}, nil
	})

	p := NewProxy()
	p.mu.Lock()
	p.credentials["internal.example.com:80"] = []credentialHeader{{Name: "Authorization", Value: "Bearer port80", Grant: "port80-grant"}}
	p.mu.Unlock()

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(mustParseURL(proxyServer.URL))},
	}

	resp, err := client.Get("http://internal.example.com:99999/")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if receivedAuth != "Bearer port80" {
		t.Errorf("Authorization = %q, want %q (policy treats the unparseable port as 80, so credential lookup must agree)", receivedAuth, "Bearer port80")
	}
}

// TestProxy_GetCredentialsForRequest_OutrankedResolverNotCalled verifies
// that a resolver whose match is outranked by a static credential is not
// invoked at all — its external call (e.g. an STS round trip) must not add
// latency to requests that will use the static credential — while the
// request sanitization it declared at registration is still applied.
func TestProxy_GetCredentialsForRequest_OutrankedResolverNotCalled(t *testing.T) {
	p := NewProxy()
	p.SetCredentialWithGrant("api.example.com", "Authorization", "Bearer static-token", "static-grant")
	var invoked atomic.Bool
	p.SetCredentialResolverWithStripHeaders("*.example.com", func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]credentialHeader, error) {
		invoked.Store(true)
		return []credentialHeader{{Name: "Authorization", Value: "Bearer resolver-token", Grant: "resolver-grant"}}, nil
	}, "X-Subject-Token")

	req := httptest.NewRequest("GET", "https://api.example.com/", nil)
	req.Header.Set("X-Subject-Token", "caller-identity")

	creds, err := p.getCredentialsForRequest(req, req, "api.example.com")
	if err != nil {
		t.Fatalf("getCredentialsForRequest: %v", err)
	}
	if invoked.Load() {
		t.Fatal("outranked resolver was invoked (its external call must not stall static-credential hosts)")
	}
	if len(creds) != 1 || creds[0].Grant != "static-grant" {
		t.Fatalf("creds = %v, want static-grant", creds)
	}
	if got := req.Header.Get("X-Subject-Token"); got != "" {
		t.Fatalf("X-Subject-Token = %q, want removed (declared strip headers apply even when the resolver is skipped)", got)
	}

	// For hosts where the resolver is not outranked it runs normally.
	req2 := httptest.NewRequest("GET", "https://other.example.com/", nil)
	creds, err = p.getCredentialsForRequest(req2, req2, "other.example.com")
	if err != nil {
		t.Fatalf("getCredentialsForRequest(other): %v", err)
	}
	if !invoked.Load() {
		t.Fatal("resolver did not run for a non-outranked host")
	}
	if len(creds) != 1 || creds[0].Grant != "resolver-grant" {
		t.Fatalf("creds = %v, want resolver-grant", creds)
	}
}

// TestProxy_GetCredentialsForRequest_PortPinnedExactBeatsBareResolver
// verifies cross-map specificity within the exact tier: a port-pinned exact
// static credential outranks a bare-host resolver for a port-bearing
// request host, matching both the in-map exact ordering (host:port before
// bare) and the wildcard tier's port-pinned-beats-port-less rule.
func TestProxy_GetCredentialsForRequest_PortPinnedExactBeatsBareResolver(t *testing.T) {
	p := NewProxy()
	p.mu.Lock()
	p.credentials["api.example.com:8443"] = []credentialHeader{{Name: "Authorization", Value: "Bearer pinned", Grant: "pinned-grant"}}
	p.mu.Unlock()
	p.SetCredentialResolver("api.example.com", func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]credentialHeader, error) {
		return []credentialHeader{{Name: "Authorization", Value: "Bearer resolver", Grant: "resolver-grant"}}, nil
	})
	req := httptest.NewRequest("GET", "https://api.example.com:8443/", nil)

	creds, err := p.getCredentialsForRequest(req, req, "api.example.com:8443")
	if err != nil {
		t.Fatalf("getCredentialsForRequest: %v", err)
	}
	if len(creds) != 1 || creds[0].Grant != "pinned-grant" {
		t.Fatalf("creds = %v, want pinned-grant (port-pinned exact static must outrank bare-host resolver)", creds)
	}
}

// TestProxy_GetCredentialsForRequest_LegacyOutrankedResolverStillRuns
// verifies backward compatibility for resolvers registered through the
// original SetCredentialResolver API (no declared strip headers): when
// outranked by a static credential, such a resolver still runs — it may
// sanitize the request in ways the proxy cannot know about — its
// credentials are discarded in favor of the static ones, and its error is
// not fatal. Only resolvers registered via
// SetCredentialResolverWithStripHeaders opt into being skipped.
func TestProxy_GetCredentialsForRequest_LegacyOutrankedResolverStillRuns(t *testing.T) {
	p := NewProxy()
	p.SetCredentialWithGrant("api.example.com", "Authorization", "Bearer static-token", "static-grant")
	var invoked atomic.Bool
	p.SetCredentialResolver("*.example.com", func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]credentialHeader, error) {
		invoked.Store(true)
		innerReq.Header.Del("X-Subject-Token")
		return []credentialHeader{{Name: "Authorization", Value: "Bearer resolver-token", Grant: "resolver-grant"}}, nil
	})
	req := httptest.NewRequest("GET", "https://api.example.com/", nil)
	req.Header.Set("X-Subject-Token", "caller-identity")

	creds, err := p.getCredentialsForRequest(req, req, "api.example.com")
	if err != nil {
		t.Fatalf("getCredentialsForRequest: %v", err)
	}
	if !invoked.Load() {
		t.Fatal("legacy-registered resolver was skipped when outranked; without declared strip headers its sanitizing side effects would be lost")
	}
	if got := req.Header.Get("X-Subject-Token"); got != "" {
		t.Fatalf("X-Subject-Token = %q, want removed by the resolver", got)
	}
	if len(creds) != 1 || creds[0].Grant != "static-grant" {
		t.Fatalf("creds = %v, want static-grant (static still wins the credential)", creds)
	}

	t.Run("error is not fatal when outranked", func(t *testing.T) {
		p := NewProxy()
		p.SetCredentialWithGrant("api.example.com", "Authorization", "Bearer static-token", "static-grant")
		var errInvoked atomic.Bool
		p.SetCredentialResolver("*.example.com", func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]credentialHeader, error) {
			errInvoked.Store(true)
			return nil, errors.New("sts unavailable")
		})
		req := httptest.NewRequest("GET", "https://api.example.com/", nil)
		creds, err := p.getCredentialsForRequest(req, req, "api.example.com")
		if err != nil {
			t.Fatalf("getCredentialsForRequest: %v (outranked legacy resolver error must not fail the request)", err)
		}
		if !errInvoked.Load() {
			t.Fatal("legacy resolver was not invoked")
		}
		if len(creds) != 1 || creds[0].Grant != "static-grant" {
			t.Fatalf("creds = %v, want static-grant", creds)
		}
	})
}

// TestProxy_GetCredentialsForRequest_LegacyOutrankedStaticReadFresh verifies
// that when a legacy (undeclared) resolver is outranked and run for its side
// effects, the static credential returned reflects any refresh that landed
// while the resolver was out — not the value read before the resolver ran.
// A refreshing credential source can rotate the static token (via
// SetCredentialWithGrant) during the resolver's external call; injecting the
// pre-rotation value would send a token the upstream has already revoked.
func TestProxy_GetCredentialsForRequest_LegacyOutrankedStaticReadFresh(t *testing.T) {
	p := NewProxy()
	p.SetCredentialWithGrant("api.example.com", "Authorization", "Bearer v1", "static-grant")
	p.SetCredentialResolver("*.example.com", func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]credentialHeader, error) {
		// Simulate a refresh landing while the resolver is out: it rotates
		// the static credential in place (same grant + header upserts).
		p.SetCredentialWithGrant("api.example.com", "Authorization", "Bearer v2", "static-grant")
		return []credentialHeader{{Name: "Authorization", Value: "Bearer resolver", Grant: "resolver-grant"}}, nil
	})
	req := httptest.NewRequest("GET", "https://api.example.com/", nil)

	creds, err := p.getCredentialsForRequest(req, req, "api.example.com")
	if err != nil {
		t.Fatalf("getCredentialsForRequest: %v", err)
	}
	if len(creds) != 1 || creds[0].Value != "Bearer v2" {
		t.Fatalf("creds = %v, want single credential with value %q (fresh post-refresh read), not stale v1 or the resolver's own credential", creds, "Bearer v2")
	}
}

// TestProxy_HandleHTTP_DenialLogRedactsDeclaredHeaders verifies that
// policy-denial request logs redact the headers a matching resolver declared
// at registration: the denial happens before the resolver runs (by design),
// so the proxy must remove the declared subject-identity headers from the
// logged snapshot itself.
func TestProxy_HandleHTTP_DenialLogRedactsDeclaredHeaders(t *testing.T) {
	p := NewProxy()
	p.SetNetworkPolicy("strict", []string{"allowed.example.com"}, nil)
	p.SetCredentialResolverWithStripHeaders("*.example.com", func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]credentialHeader, error) {
		return nil, nil
	}, "X-Gatekeeper-Subject")

	var mu sync.Mutex
	var logged []RequestLogData
	p.SetLogger(func(data RequestLogData) {
		mu.Lock()
		defer mu.Unlock()
		logged = append(logged, data)
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(mustParseURL(proxyServer.URL))},
	}

	req, _ := http.NewRequest("GET", "http://denied.example.com/", nil)
	req.Header.Set("X-Gatekeeper-Subject", "subject-jwt")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(logged) == 0 {
		t.Fatal("no denial was logged")
	}
	for _, data := range logged {
		if got := data.RequestHeaders.Get("X-Gatekeeper-Subject"); got != "" {
			t.Fatalf("denial log contains X-Gatekeeper-Subject = %q; declared subject headers must be redacted from logs", got)
		}
	}
}
