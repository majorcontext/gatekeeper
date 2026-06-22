package proxy

// Black-box coverage tests for paths that were previously uncovered.
// Every test drives the proxy through its HTTP interface — no internal
// functions are called directly.

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	keeplib "github.com/majorcontext/keep"
)

// ── Tunnel (no-CA) path ──────────────────────────────────────────────────────

// TestTunnel_ForwardsPlainHTTPS verifies that when the proxy has no CA
// configured, a CONNECT request is forwarded as a raw TCP tunnel without
// TLS interception.  Credentials can still be configured but will not be
// injected (the proxy can't see the plaintext).
func TestTunnel_ForwardsPlainHTTPS(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "tunneled")
	}))
	t.Cleanup(backend.Close)

	// Proxy with no CA — uses handleConnectTunnel.
	p := NewProxy()
	proxyServer := httptest.NewServer(p)
	t.Cleanup(proxyServer.Close)

	// Client trusts the backend's self-signed cert directly (no MITM).
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

// TestTunnel_NetworkPolicyBlocked verifies that the network policy is still
// enforced even when no CA is set (tunnel mode).
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
		// Connection refused or proxy error — also acceptable as a block.
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

	// Issue a raw CONNECT with a host that has no port — SplitHostPort will fail.
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

// TestTunnel_PathRulesWarning exercises the code path where TLS interception
// is disabled (no CA) but per-path rules are configured — the proxy should
// log a warning and fall through to the tunnel handler.
func TestTunnel_PathRulesWarning(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(backend.Close)

	p := NewProxy()
	// Inject a PathRulesChecker that claims path rules exist for any host.
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		return &RunContextData{
			Policy: "permissive",
			PathRulesCheck: func(host string, port int) bool {
				return true // pretend per-path rules exist
			},
		}, true
	})

	proxyServer := httptest.NewServer(p)
	t.Cleanup(proxyServer.Close)

	backendCAs := x509.NewCertPool()
	backendCAs.AddCert(backend.Certificate())

	proxyURL := mustParseURL(proxyServer.URL)
	proxyURL.User = url.UserPassword("user", "tok")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: backendCAs},
		},
	}

	// The proxy has no CA, so it tunnels despite path rules existing.
	resp, err := client.Get(backend.URL + "/path")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	// Main assertion: we reach the backend (tunnel works) without panicking.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// ── LLM gateway policy (evaluateAndReplaceLLMResponse) ──────────────────────

const llmGatewayDenyEditPolicy = `
scope: llm-gateway
mode: enforce
rules:
  - name: deny-edit
    match:
      operation: "llm.tool_use"
      when: "params.name == 'edit'"
    action: deny
    message: "Editing blocked."
`

// newAnthropicInterceptSetup builds an intercept test setup where the backend
// acts as a fake api.anthropic.com.  The client sends requests to
// https://api.anthropic.com:<backend-port> and the proxy rewrites the upstream
// dial to 127.0.0.1:<backend-port> via the HostGateway mechanism, so the
// host check (host == "api.anthropic.com") triggers the LLM policy path.
//
// The backend port is added to AllowedHostPorts so the HostGateway policy
// permits the CONNECT (HostGateway traffic requires explicit port allow-listing).
func newAnthropicInterceptSetup(t *testing.T, llmEng *keeplib.Engine, backendHandler http.Handler) (client *http.Client, backendURL string) {
	t.Helper()

	ca, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}

	backend := httptest.NewTLSServer(backendHandler)
	t.Cleanup(backend.Close)

	upstreamCAs := x509.NewCertPool()
	upstreamCAs.AddCert(backend.Certificate())

	backendAddr := mustParseURL(backend.URL)
	backendPort := backendAddr.Port()
	backendPortInt := 0
	fmt.Sscanf(backendPort, "%d", &backendPortInt)

	p := NewProxy()
	p.SetCA(ca)
	p.SetUpstreamCAs(upstreamCAs)
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token != "llmtok" {
			return nil, false
		}
		rc := &RunContextData{
			Policy:           "permissive",
			HostGateway:      "api.anthropic.com",
			HostGatewayIP:    "127.0.0.1",
			AllowedHostPorts: []int{backendPortInt},
		}
		if llmEng != nil {
			rc.KeepEngines = map[string]*keeplib.Engine{"llm-gateway": llmEng}
		}
		return rc, true
	})

	proxyServer := httptest.NewServer(p)
	t.Cleanup(proxyServer.Close)

	clientCAs := x509.NewCertPool()
	clientCAs.AppendCertsFromPEM(ca.certPEM)

	proxyURL := mustParseURL(proxyServer.URL)
	proxyURL.User = url.UserPassword("user", "llmtok")

	client = &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: clientCAs},
		},
	}

	backendURL = "https://api.anthropic.com:" + backendPort
	return client, backendURL
}

// TestIntercept_LLMPolicy_Deny verifies that the llm-gateway Keep engine
// blocks a tool-use response from api.anthropic.com.
func TestIntercept_LLMPolicy_Deny(t *testing.T) {
	eng, err := keeplib.LoadFromBytes([]byte(llmGatewayDenyEditPolicy))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Close)

	body := `{"content":[{"type":"tool_use","id":"t1","name":"Edit","input":{"file_path":"/foo"}}],"stop_reason":"tool_use"}`

	client, backendURL := newAnthropicInterceptSetup(t, eng,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, body)
		}),
	)

	resp, err := client.Post(backendURL+"/v1/messages", "application/json",
		strings.NewReader(`{"model":"claude-opus-4-5"}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (policy denied)", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Moat-Blocked"); got != "llm-policy" {
		t.Errorf("X-Moat-Blocked = %q, want llm-policy", got)
	}
	respBody, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(respBody), "policy_denied") {
		t.Errorf("response body missing policy_denied: %s", respBody)
	}
}

// TestIntercept_LLMPolicy_Allow verifies that a non-matching response passes
// through the llm-gateway engine unchanged.
func TestIntercept_LLMPolicy_Allow(t *testing.T) {
	eng, err := keeplib.LoadFromBytes([]byte(llmGatewayDenyEditPolicy))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Close)

	allowedBody := `{"content":[{"type":"text","text":"hello"}],"stop_reason":"end_turn"}`

	client, backendURL := newAnthropicInterceptSetup(t, eng,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, allowedBody)
		}),
	)

	resp, err := client.Get(backendURL + "/v1/messages")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if string(respBody) != allowedBody {
		t.Errorf("body = %q, want %q", string(respBody), allowedBody)
	}
}

// TestIntercept_LLMPolicy_ResponseTooLarge verifies that oversized responses
// from api.anthropic.com are blocked with a size-limit error.
func TestIntercept_LLMPolicy_ResponseTooLarge(t *testing.T) {
	eng, err := keeplib.LoadFromBytes([]byte(llmGatewayDenyEditPolicy))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Close)

	// Build a body larger than maxLLMResponseSize (10 MiB).
	// Use 11 MiB of JSON-ish padding so the size check triggers.
	hugeBody := `{"content":[{"type":"text","text":"` + strings.Repeat("x", 11*1024*1024) + `"}]}`

	client, backendURL := newAnthropicInterceptSetup(t, eng,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, hugeBody)
		}),
	)

	resp, err := client.Get(backendURL + "/v1/messages")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (size-limit)", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Moat-Blocked"); got != "llm-policy" {
		t.Errorf("X-Moat-Blocked = %q, want llm-policy", got)
	}
	respBody, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(respBody), "size-limit") {
		t.Errorf("response body missing size-limit: %s", respBody)
	}
}

// TestIntercept_LLMPolicy_NoEnginePassesThrough verifies that without a
// llm-gateway engine the response is passed through unmodified, even for
// api.anthropic.com.
func TestIntercept_LLMPolicy_NoEnginePassesThrough(t *testing.T) {
	rawBody := `{"content":[{"type":"tool_use","id":"t1","name":"Edit","input":{}}],"stop_reason":"tool_use"}`

	// nil engine — no llm-gateway key in KeepEngines.
	client, backendURL := newAnthropicInterceptSetup(t, nil,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, rawBody)
		}),
	)

	resp, err := client.Get(backendURL + "/v1/messages")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if string(respBody) != rawBody {
		t.Errorf("body = %q, want %q", string(respBody), rawBody)
	}
}

// TestIntercept_LLMPolicy_DeniedLogged verifies that a denied LLM response is
// recorded in the canonical request log with Denied=true.
func TestIntercept_LLMPolicy_DeniedLogged(t *testing.T) {
	eng, err := keeplib.LoadFromBytes([]byte(llmGatewayDenyEditPolicy))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Close)

	toolBody := `{"content":[{"type":"tool_use","id":"t1","name":"Edit","input":{"file_path":"/f"}}],"stop_reason":"tool_use"}`

	// Build the setup manually so we can attach a log listener to the proxy.
	ca, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}

	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, toolBody)
	}))
	t.Cleanup(backend.Close)

	upstreamCAs := x509.NewCertPool()
	upstreamCAs.AddCert(backend.Certificate())

	backendPort := 0
	fmt.Sscanf(mustParseURL(backend.URL).Port(), "%d", &backendPort)

	p := NewProxy()
	p.SetCA(ca)
	p.SetUpstreamCAs(upstreamCAs)
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token != "logtest" {
			return nil, false
		}
		return &RunContextData{
			Policy:           "permissive",
			HostGateway:      "api.anthropic.com",
			HostGatewayIP:    "127.0.0.1",
			AllowedHostPorts: []int{backendPort},
			KeepEngines:      map[string]*keeplib.Engine{"llm-gateway": eng},
		}, true
	})

	var logged RequestLogData
	p.SetLogger(func(data RequestLogData) { logged = data })

	proxyServer := httptest.NewServer(p)
	t.Cleanup(proxyServer.Close)

	clientCAs := x509.NewCertPool()
	clientCAs.AppendCertsFromPEM(ca.certPEM)

	proxyURL := mustParseURL(proxyServer.URL)
	proxyURL.User = url.UserPassword("user", "logtest")
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: clientCAs},
		},
	}

	resp, err := client.Post(
		fmt.Sprintf("https://api.anthropic.com:%d/v1/messages", backendPort),
		"application/json",
		strings.NewReader(`{"model":"claude-opus-4-5"}`),
	)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	if !logged.Denied {
		t.Errorf("RequestLogData.Denied = false, want true")
	}
}

// ── AddResponseTransformer ───────────────────────────────────────────────────

// TestIntercept_ResponseTransformer verifies that a registered response
// transformer runs in the intercept path and can observe the response.
func TestIntercept_ResponseTransformer(t *testing.T) {
	var transformerCalled bool
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"original":true}`)
	}))

	setup.Proxy.AddResponseTransformer(setup.BackendHost, func(req, resp any) (any, bool) {
		transformerCalled = true
		// Return false — observe without modifying (no replacement).
		return resp, false
	})

	resp, err := setup.Client.Get(setup.Backend.URL + "/data")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	if !transformerCalled {
		t.Error("response transformer was not called")
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// TestIntercept_ResponseTransformer_NoMatch verifies that a transformer
// registered for a different host does not affect other hosts.
func TestIntercept_ResponseTransformer_NoMatch(t *testing.T) {
	originalBody := `{"original":true}`
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, originalBody)
	}))

	// Register transformer for a completely different host.
	setup.Proxy.AddResponseTransformer("other.example.com", func(req, resp any) (any, bool) {
		// This should never be called for requests to the backend host.
		t.Error("transformer called for wrong host")
		return resp, false
	})

	resp, err := setup.Client.Get(setup.Backend.URL + "/data")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if string(body) != originalBody {
		t.Errorf("body = %q, want %q (transformer should not apply)", string(body), originalBody)
	}
}

// ── SetTokenSubstitution (proxy-level setter) ────────────────────────────────

// TestIntercept_SetTokenSubstitution verifies that the proxy-level
// SetTokenSubstitution setter is wired into the intercept path.
func TestIntercept_SetTokenSubstitution(t *testing.T) {
	var receivedPath string
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		fmt.Fprint(w, "ok")
	}))

	// Register token substitution: placeholder in URL → real token.
	setup.Proxy.SetTokenSubstitution(setup.BackendHost, "placeholder-token", "real-secret-value")

	resp, err := setup.Client.Get(setup.Backend.URL + "/bot" + "placeholder-token" + "/getUpdates")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	if !strings.Contains(receivedPath, "real-secret-value") {
		t.Errorf("path = %q, want real-secret-value substituted", receivedPath)
	}
	if strings.Contains(receivedPath, "placeholder-token") {
		t.Errorf("path = %q, placeholder should have been replaced", receivedPath)
	}
}

// ── Exported API wrappers ────────────────────────────────────────────────────

// TestNewTokenSubstitution verifies the exported constructor returns a usable substitution.
func TestNewTokenSubstitution(t *testing.T) {
	sub := NewTokenSubstitution("placeholder", "real")
	if sub == nil {
		t.Fatal("NewTokenSubstitution returned nil")
	}
}

// TestParseHostPattern and TestMatchesHostPattern exercise the exported wrappers
// for parseHostPattern and matchesPattern.
func TestParseAndMatchHostPattern(t *testing.T) {
	cases := []struct {
		pattern string
		host    string
		port    int
		want    bool
	}{
		{"api.example.com", "api.example.com", 443, true},
		{"api.example.com", "other.example.com", 443, false},
		{"*.example.com", "sub.example.com", 443, true},
		{"*.example.com", "example.com", 443, false},
	}
	for _, tc := range cases {
		p := ParseHostPattern(tc.pattern)
		got := MatchesHostPattern(p, tc.host, tc.port)
		if got != tc.want {
			t.Errorf("MatchesHostPattern(%q, %q, %d) = %v, want %v", tc.pattern, tc.host, tc.port, got, tc.want)
		}
	}
}

// TestRegisterGrantHosts verifies that registered grant hosts are retrievable.
func TestRegisterGrantHosts(t *testing.T) {
	RegisterGrantHosts("test-grant-coverage", []string{"coverage.example.com"})
	hosts := GetHostsForGrant("test-grant-coverage")
	if len(hosts) == 0 {
		t.Fatal("GetHostsForGrant returned empty slice after RegisterGrantHosts")
	}
	if hosts[0] != "coverage.example.com" {
		t.Errorf("hosts[0] = %q, want coverage.example.com", hosts[0])
	}
}
