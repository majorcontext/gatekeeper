package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// interceptTestSetup creates a proxy with TLS interception enabled and an HTTPS
// backend server. The proxy is configured to trust the backend's TLS cert and
// the returned client trusts the proxy's interception CA.
type interceptTestSetup struct {
	Proxy           *Proxy
	ProxyServer     *httptest.Server
	Backend         *httptest.Server
	Client          *http.Client
	CA              *CA
	BackendHost     string // hostname only (e.g., 127.0.0.1) — for credential matching
	BackendHostPort string // host:port (e.g., 127.0.0.1:12345) — for extra/remove header matching
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

	backendHost := mustParseURL(backend.URL).Host     // host:port for extra header matching (uses r.Host)
	backendHostname := mustParseURL(backend.URL).Hostname() // hostname only for credential matching

	t.Cleanup(func() {
		proxyServer.Close()
		backend.Close()
	})

	return &interceptTestSetup{
		Proxy:           p,
		ProxyServer:     proxyServer,
		Backend:         backend,
		Client:          client,
		CA:              ca,
		BackendHost:     backendHostname,
		BackendHostPort: backendHost,
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

	var logged RequestLogData
	setup.Proxy.SetLogger(func(data RequestLogData) {
		logged = data
	})

	resp, err := setup.Client.Get(setup.Backend.URL + "/resource")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

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

	// The CONNECT itself will be denied before TLS interception.
	resp, err := setup.Client.Get(setup.Backend.URL + "/blocked")
	if err == nil {
		resp.Body.Close()
		// Under strict policy with no allows, CONNECT is denied with 407.
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusProxyAuthRequired)
		}
	}
	// The client may get a transport error if CONNECT is blocked.
	// Either way, the request should be denied.
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

	var logged RequestLogData
	setup.Proxy.SetLogger(func(data RequestLogData) {
		logged = data
	})

	resp, err := setup.Client.Get(setup.Backend.URL + "/some/path")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

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

	req, _ := http.NewRequest("GET", setup.Backend.URL+"/test", nil)
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

			req, _ := http.NewRequest(method, setup.Backend.URL+"/method", nil)
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
