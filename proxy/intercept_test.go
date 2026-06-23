package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	keeplib "github.com/majorcontext/keep"
)

// captureLog installs a logger that records logged requests and returns a
// function that waits for the next one. The canonical log line for a text
// response is written when its body is closed (capture streams lazily), so
// tests must wait for it rather than read a shared variable synchronously.
func captureLog(t *testing.T, p *Proxy) func() RequestLogData {
	t.Helper()
	ch := make(chan RequestLogData, 8)
	p.SetLogger(func(d RequestLogData) { ch <- d })
	return func() RequestLogData {
		t.Helper()
		select {
		case d := <-ch:
			return d
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for canonical log line")
			return RequestLogData{}
		}
	}
}

// interceptTestSetup creates a proxy with TLS interception enabled and an HTTPS
// backend server. The proxy is configured to trust the backend's TLS cert and
// the returned client trusts the proxy's interception CA.
type interceptTestSetup struct {
	Proxy       *Proxy
	ProxyServer *httptest.Server
	Backend     *httptest.Server
	Client      *http.Client
	CA          *CA
	BackendHost string // hostname only (e.g., 127.0.0.1) — for credential and header matching
}

func newInterceptTestSetup(t *testing.T, backendHandler http.Handler) *interceptTestSetup {
	t.Helper()

	ca, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}

	backend := httptest.NewTLSServer(backendHandler)

	// Build a CA pool that trusts the backend's TLS cert.
	upstreamCAs := x509.NewCertPool()
	upstreamCAs.AddCert(backend.Certificate())

	p := NewProxy()
	p.SetCA(ca)
	p.SetUpstreamCAs(upstreamCAs)

	proxyServer := httptest.NewServer(p)

	// Client trusts the interception CA and routes through the proxy.
	clientCAs := x509.NewCertPool()
	clientCAs.AppendCertsFromPEM(ca.certPEM)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(mustParseURL(proxyServer.URL)),
			TLSClientConfig: &tls.Config{RootCAs: clientCAs},
		},
	}

	backendHostname := mustParseURL(backend.URL).Hostname()

	t.Cleanup(func() {
		proxyServer.Close()
		backend.Close()
	})

	return &interceptTestSetup{
		Proxy:       p,
		ProxyServer: proxyServer,
		Backend:     backend,
		Client:      client,
		CA:          ca,
		BackendHost: backendHostname,
	}
}

func TestIntercept_CredentialInjection(t *testing.T) {
	var receivedAuth string
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		w.Write([]byte("ok"))
	}))

	setup.Proxy.SetCredentialWithGrant(setup.BackendHost, "Authorization", "Bearer test-token-123", "test-grant")

	resp, err := setup.Client.Get(setup.Backend.URL + "/api/data")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if receivedAuth != "Bearer test-token-123" {
		t.Errorf("Authorization = %q, want %q", receivedAuth, "Bearer test-token-123")
	}
}

func TestIntercept_CredentialInjectionCanonicalLog(t *testing.T) {
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))

	setup.Proxy.SetCredentialWithGrant(setup.BackendHost, "Authorization", "Bearer granted-token", "my-grant")

	waitLog := captureLog(t, setup.Proxy)

	resp, err := setup.Client.Get(setup.Backend.URL + "/resource")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	logged := waitLog()
	if !logged.AuthInjected {
		t.Error("expected AuthInjected=true")
	}
	if len(logged.Grants) == 0 || logged.Grants[0] != "my-grant" {
		t.Errorf("Grants = %v, want [my-grant]", logged.Grants)
	}
	if logged.RequestType != "connect" {
		t.Errorf("RequestType = %q, want connect", logged.RequestType)
	}
	if logged.RequestID == "" {
		t.Error("expected non-empty RequestID")
	}
	// Verify credential value is NOT present in logged request headers.
	if v := logged.RequestHeaders.Get("Authorization"); v != "" {
		t.Errorf("logged RequestHeaders contains injected Authorization %q; credential values must not appear in logs", v)
	}
}

func TestIntercept_MultiRequestKeepalive(t *testing.T) {
	var requestCount int
	var mu sync.Mutex
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()
		w.Write([]byte("ok"))
	}))

	for i := 0; i < 5; i++ {
		resp, err := setup.Client.Get(setup.Backend.URL + "/ping")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("request %d: status = %d, want 200", i, resp.StatusCode)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if requestCount != 5 {
		t.Errorf("requestCount = %d, want 5", requestCount)
	}
}

func TestIntercept_NetworkPolicyDenial(t *testing.T) {
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("backend should not be reached on denied request")
	}))

	// Strict policy with no allows — denies everything at the inner request level.
	setup.Proxy.SetNetworkPolicy("strict", nil, nil)

	var logged RequestLogData
	setup.Proxy.SetLogger(func(data RequestLogData) {
		logged = data
	})

	// Strict policy denies the CONNECT request itself with 407.
	// Go's transport returns this as an error (non-200 CONNECT response).
	resp, err := setup.Client.Get(setup.Backend.URL + "/blocked")
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected transport error from denied CONNECT, got nil")
	}
	// Verify the error message references the 407 status text.
	if !strings.Contains(err.Error(), "407") && !strings.Contains(err.Error(), "Proxy Authentication Required") {
		t.Errorf("expected 407/Proxy Authentication Required in error, got: %v", err)
	}
	if !logged.Denied {
		t.Error("expected Denied=true in log")
	}
}

func TestIntercept_TransportError502(t *testing.T) {
	ca, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}

	p := NewProxy()
	p.SetCA(ca)

	var logged RequestLogData
	p.SetLogger(func(data RequestLogData) {
		logged = data
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(ca.certPEM)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(mustParseURL(proxyServer.URL)),
			TLSClientConfig: &tls.Config{RootCAs: caCertPool},
		},
	}

	// Connect to a port nothing listens on.
	resp, err := client.Get("https://127.0.0.1:1/nope")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
	if logged.Err == nil {
		t.Error("expected error in canonical log")
	}
	if logged.RequestType != "connect" {
		t.Errorf("RequestType = %q, want connect", logged.RequestType)
	}
}

func TestIntercept_CanonicalLogFields(t *testing.T) {
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("hello"))
	}))

	setup.Proxy.SetCredentialWithGrant(setup.BackendHost, "Authorization", "Bearer tok", "test-grant")

	waitLog := captureLog(t, setup.Proxy)

	resp, err := setup.Client.Get(setup.Backend.URL + "/some/path")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	logged := waitLog()
	if logged.Method != "GET" {
		t.Errorf("Method = %q, want GET", logged.Method)
	}
	backendHostname := mustParseURL(setup.Backend.URL).Hostname()
	if logged.Host != backendHostname {
		t.Errorf("Host = %q, want %q", logged.Host, backendHostname)
	}
	if logged.Path != "/some/path" {
		t.Errorf("Path = %q, want /some/path", logged.Path)
	}
	if logged.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", logged.StatusCode)
	}
	if logged.RequestType != "connect" {
		t.Errorf("RequestType = %q, want connect", logged.RequestType)
	}
	if !logged.AuthInjected {
		t.Error("expected AuthInjected=true")
	}
}

func TestIntercept_ExtraHeaders(t *testing.T) {
	var receivedHeaders http.Header
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.Write([]byte("ok"))
	}))

	setup.Proxy.AddExtraHeader(setup.BackendHost, "X-Custom-Header", "custom-value")

	resp, err := setup.Client.Get(setup.Backend.URL + "/test")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if receivedHeaders.Get("X-Custom-Header") != "custom-value" {
		t.Errorf("X-Custom-Header = %q, want custom-value", receivedHeaders.Get("X-Custom-Header"))
	}
}

func TestIntercept_RemoveHeaders(t *testing.T) {
	var receivedAPIKey string
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAPIKey = r.Header.Get("X-Api-Key")
		w.Write([]byte("ok"))
	}))

	setup.Proxy.RemoveRequestHeader(setup.BackendHost, "X-Api-Key")

	req, err := http.NewRequest("GET", setup.Backend.URL+"/test", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Api-Key", "stale-key")
	resp, err := setup.Client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if receivedAPIKey != "" {
		t.Errorf("X-Api-Key should be removed, got %q", receivedAPIKey)
	}
}

func TestIntercept_RequestBodyForwarded(t *testing.T) {
	var receivedBody string
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Write([]byte("ok"))
	}))

	reqBody := `{"key": "value"}`
	resp, err := setup.Client.Post(setup.Backend.URL+"/submit", "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if receivedBody != reqBody {
		t.Errorf("body = %q, want %q", receivedBody, reqBody)
	}
}

func TestIntercept_LargeResponseBody(t *testing.T) {
	// 1MB response body to verify streaming works.
	largeBody := bytes.Repeat([]byte("x"), 1<<20)
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(largeBody)
	}))

	resp, err := setup.Client.Get(setup.Backend.URL + "/large")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) != len(largeBody) {
		t.Errorf("body length = %d, want %d", len(body), len(largeBody))
	}
}

func TestIntercept_ResponseStatusCodes(t *testing.T) {
	codes := []int{200, 201, 204, 301, 400, 404, 500}

	for _, code := range codes {
		t.Run(http.StatusText(code), func(t *testing.T) {
			setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
			}))

			resp, err := setup.Client.Get(setup.Backend.URL + "/status")
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			resp.Body.Close()

			if resp.StatusCode != code {
				t.Errorf("status = %d, want %d", resp.StatusCode, code)
			}
		})
	}
}

func TestIntercept_ResponseHeaders(t *testing.T) {
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend-Header", "backend-value")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{}`))
	}))

	resp, err := setup.Client.Get(setup.Backend.URL + "/headers")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if resp.Header.Get("X-Backend-Header") != "backend-value" {
		t.Errorf("X-Backend-Header = %q, want backend-value", resp.Header.Get("X-Backend-Header"))
	}
	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", resp.Header.Get("Content-Type"))
	}
}

func TestIntercept_XRequestIdInjected(t *testing.T) {
	var receivedRequestID string
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedRequestID = r.Header.Get("X-Request-Id")
		w.Write([]byte("ok"))
	}))

	resp, err := setup.Client.Get(setup.Backend.URL + "/rid")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	if receivedRequestID == "" {
		t.Error("expected X-Request-Id to be injected")
	}
	if !strings.HasPrefix(receivedRequestID, "req_") {
		t.Errorf("X-Request-Id = %q, expected req_ prefix", receivedRequestID)
	}
}

func TestIntercept_ProxyAuthorizationStripped(t *testing.T) {
	var receivedProxyAuth string
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedProxyAuth = r.Header.Get("Proxy-Authorization")
		w.Write([]byte("ok"))
	}))

	resp, err := setup.Client.Get(setup.Backend.URL + "/strip")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	// Proxy-Authorization should be stripped before forwarding upstream.
	if receivedProxyAuth != "" {
		t.Errorf("Proxy-Authorization should be stripped, got %q", receivedProxyAuth)
	}
}

func TestIntercept_HTTPMethods(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			var receivedMethod string
			setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedMethod = r.Method
				w.Write([]byte("ok"))
			}))

			req, err := http.NewRequest(method, setup.Backend.URL+"/method", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			resp, err := setup.Client.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			resp.Body.Close()

			if receivedMethod != method {
				t.Errorf("method = %q, want %q", receivedMethod, method)
			}
		})
	}
}

func TestIntercept_WebSocketUpgrade(t *testing.T) {
	// Backend that accepts WebSocket upgrades and echoes raw bytes.
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "expected websocket upgrade", 400)
			return
		}

		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		w.WriteHeader(http.StatusSwitchingProtocols)

		hijacker, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, brw, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		brw.Flush()

		// Echo: read up to 1024 bytes, write them back.
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		conn.Write(buf[:n])
	}))
	defer backend.Close()

	ca, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}

	upstreamCAs := x509.NewCertPool()
	upstreamCAs.AddCert(backend.Certificate())

	p := NewProxy()
	p.SetCA(ca)
	p.SetUpstreamCAs(upstreamCAs)

	backendHost := mustParseURL(backend.URL).Hostname()
	p.SetCredential(backendHost, "Bearer ws-token")

	var logged RequestLogData
	p.SetLogger(func(data RequestLogData) {
		logged = data
	})

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	// Dial through the proxy using raw CONNECT.
	proxyURL := mustParseURL(proxyServer.URL)
	proxyConn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer proxyConn.Close()

	// Send CONNECT.
	backendAddr := mustParseURL(backend.URL).Host
	fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", backendAddr, backendAddr)
	br := bufio.NewReader(proxyConn)
	connectResp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if connectResp.StatusCode != 200 {
		t.Fatalf("CONNECT status = %d, want 200", connectResp.StatusCode)
	}

	// TLS handshake with the proxy's interception cert.
	clientCAs := x509.NewCertPool()
	clientCAs.AppendCertsFromPEM(ca.certPEM)
	tlsConn := tls.Client(proxyConn, &tls.Config{
		RootCAs:    clientCAs,
		ServerName: backendHost,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	defer tlsConn.Close()

	// Send WebSocket upgrade request.
	upgradeReq := "GET /ws HTTP/1.1\r\n" +
		"Host: " + backendAddr + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"
	if _, err := tlsConn.Write([]byte(upgradeReq)); err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}

	// Read the 101 response.
	tlsBr := bufio.NewReader(tlsConn)
	upgradeResp, err := http.ReadResponse(tlsBr, nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if upgradeResp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status = %d, want 101", upgradeResp.StatusCode)
	}

	// Send a raw message through the upgraded connection.
	testMsg := []byte("hello websocket")
	if _, err := tlsConn.Write(testMsg); err != nil {
		t.Fatalf("write message: %v", err)
	}

	// Read echoed message back.
	echoBuf := make([]byte, len(testMsg))
	if _, err := io.ReadFull(tlsBr, echoBuf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(echoBuf) != string(testMsg) {
		t.Errorf("echo = %q, want %q", echoBuf, testMsg)
	}

	// Verify credential was injected on the upgrade request.
	if !logged.AuthInjected {
		t.Error("expected credential injection on upgrade request")
	}
}

func TestIntercept_CaptureHeaders_StrippedBeforeForwarding(t *testing.T) {
	var receivedHeaders http.Header
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.Write([]byte("ok"))
	}))

	setup.Proxy.SetCaptureHeaders([]string{"X-Workspace-Slug", "X-Request-Source"})

	waitLog := captureLog(t, setup.Proxy)

	req, _ := http.NewRequest("GET", setup.Backend.URL+"/test", nil)
	req.Header.Set("X-Workspace-Slug", "sneaky-plum")
	req.Header.Set("X-Request-Source", "agent")
	req.Header.Set("X-Other", "keep-this")

	resp, err := setup.Client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)
	logged := waitLog()

	// Verify capture headers were stripped before forwarding.
	if receivedHeaders.Get("X-Workspace-Slug") != "" {
		t.Error("X-Workspace-Slug should be stripped before forwarding (CONNECT path)")
	}
	if receivedHeaders.Get("X-Request-Source") != "" {
		t.Error("X-Request-Source should be stripped before forwarding (CONNECT path)")
	}
	if receivedHeaders.Get("X-Other") != "keep-this" {
		t.Errorf("X-Other = %q, want keep-this (non-capture headers should pass through)", receivedHeaders.Get("X-Other"))
	}

	// Verify capture headers are preserved in log data (from pre-strip snapshot).
	if logged.RequestHeaders == nil {
		t.Fatal("RequestHeaders is nil")
	}
	if got := logged.RequestHeaders.Get("X-Workspace-Slug"); got != "sneaky-plum" {
		t.Errorf("logged RequestHeaders[X-Workspace-Slug] = %q, want sneaky-plum", got)
	}
}

func TestIntercept_CaptureHeaders_PreservesInjectedCredential(t *testing.T) {
	var receivedAPIKey string
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAPIKey = r.Header.Get("X-Api-Key")
		w.Write([]byte("ok"))
	}))

	// Configure both a credential injection and a capture header for the same header name.
	setup.Proxy.SetCredentialHeader(setup.BackendHost, "X-Api-Key", "secret-key-123")
	setup.Proxy.SetCaptureHeaders([]string{"X-Api-Key"})

	resp, err := setup.Client.Get(setup.Backend.URL + "/test")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	// The injected credential must survive the capture header stripping.
	if receivedAPIKey != "secret-key-123" {
		t.Errorf("X-Api-Key = %q, want %q (injected credential should not be stripped)", receivedAPIKey, "secret-key-123")
	}
}

// TestIntercept_HTTPBodyPolicy exercises http-scope request-body filtering
// end-to-end through TLS interception: a body rule denies a matching request
// before it reaches the backend (403 + X-Moat-Blocked), while a non-matching
// body is forwarded intact.
func TestIntercept_HTTPBodyPolicy(t *testing.T) {
	var backendHits atomic.Int32
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHits.Add(1)
		io.Copy(io.Discard, r.Body)
		w.Write([]byte("ok"))
	}))

	eng, err := keeplib.LoadFromBytes([]byte(httpBodyRules))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { eng.Close() })

	setup.Proxy.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "tok" {
			return &RunContextData{
				Policy:      "permissive",
				KeepEngines: map[string]*keeplib.Engine{"http": eng},
			}, true
		}
		return nil, false
	})

	proxyURL := mustParseURL(setup.ProxyServer.URL)
	proxyURL.User = url.UserPassword("alice", "tok")
	clientCAs := x509.NewCertPool()
	clientCAs.AppendCertsFromPEM(setup.CA.certPEM)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: clientCAs},
		},
	}

	// model == gpt-4 matches the deny rule: blocked before reaching the backend.
	denyResp, err := client.Post(setup.Backend.URL+"/v1/messages", "application/json",
		strings.NewReader(`{"model":"gpt-4"}`))
	if err != nil {
		t.Fatalf("deny request: %v", err)
	}
	denyResp.Body.Close()
	if denyResp.StatusCode != http.StatusForbidden {
		t.Errorf("denied request status = %d, want 403", denyResp.StatusCode)
	}
	if got := denyResp.Header.Get("X-Moat-Blocked"); got != "keep-policy" {
		t.Errorf("X-Moat-Blocked = %q, want keep-policy", got)
	}
	if n := backendHits.Load(); n != 0 {
		t.Errorf("backend reached %d times on denied request, want 0", n)
	}

	// A non-matching body is allowed and forwarded to the backend.
	okResp, err := client.Post(setup.Backend.URL+"/v1/messages", "application/json",
		strings.NewReader(`{"model":"claude"}`))
	if err != nil {
		t.Fatalf("allow request: %v", err)
	}
	okResp.Body.Close()
	if okResp.StatusCode != 200 {
		t.Errorf("allowed request status = %d, want 200", okResp.StatusCode)
	}
	if n := backendHits.Load(); n != 1 {
		t.Errorf("backend hits = %d, want 1", n)
	}
}

func TestIntercept_UserID_ContextResolver(t *testing.T) {
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))

	setup.Proxy.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "my-token" {
			return &RunContextData{Policy: "permissive"}, true
		}
		return nil, false
	})

	waitLog := captureLog(t, setup.Proxy)

	// Rebuild the client with proxy auth credentials (user:token).
	proxyURL := mustParseURL(setup.ProxyServer.URL)
	proxyURL.User = url.UserPassword("alice", "my-token")

	clientCAs := x509.NewCertPool()
	clientCAs.AppendCertsFromPEM(setup.CA.certPEM)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: clientCAs},
		},
	}

	resp, err := client.Get(setup.Backend.URL + "/test")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)
	logged := waitLog()

	if logged.UserID != "alice" {
		t.Errorf("UserID = %q, want %q (CONNECT path)", logged.UserID, "alice")
	}
}

// TestTunnel_PathRulesWarning exercises the code path where TLS interception
// is disabled (no CA) but per-path rules are configured — the proxy should
// fall through to the tunnel handler.
func TestTunnel_PathRulesWarning(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	t.Cleanup(backend.Close)

	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		return &RunContextData{
			Policy: "permissive",
			PathRulesCheck: func(host string, port int) bool {
				return true
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

	resp, err := client.Get(backend.URL + "/path")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

// newAnthropicInterceptSetup builds an intercept test setup where the backend
// acts as a fake api.anthropic.com. The client sends requests to
// https://api.anthropic.com:<backend-port> and the proxy rewrites the upstream
// dial to 127.0.0.1:<backend-port> via the HostGateway mechanism, so the
// host check (host == "api.anthropic.com") triggers the LLM policy path.
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

// TestIntercept_LLMPolicy_DeniedLogged verifies that a denied LLM response is
// recorded in the canonical request log with Denied=true.
func TestIntercept_LLMPolicy_DeniedLogged(t *testing.T) {
	eng, err := keeplib.LoadFromBytes([]byte(llmGatewayDenyEditPolicy))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Close)

	toolBody := `{"content":[{"type":"tool_use","id":"t1","name":"Edit","input":{"file_path":"/f"}}],"stop_reason":"tool_use"}`

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

	waitLog := captureLog(t, p)

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
	logged := waitLog()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	if !logged.Denied {
		t.Errorf("RequestLogData.Denied = false, want true")
	}
}

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

	setup.Proxy.AddResponseTransformer("other.example.com", func(req, resp any) (any, bool) {
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

// TestIntercept_SetTokenSubstitution verifies that the proxy-level
// SetTokenSubstitution setter is wired into the intercept path.
func TestIntercept_SetTokenSubstitution(t *testing.T) {
	var receivedPath string
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		fmt.Fprint(w, "ok")
	}))

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
