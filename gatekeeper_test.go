package gatekeeper

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/majorcontext/gatekeeper/credentialsource"
	"github.com/majorcontext/gatekeeper/proxy"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/pires/go-proxyproto"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// startTLSBackend creates an HTTPS backend server using the provided CA.
// Returns the server (for cleanup), the port it's listening on, and the CA cert pool.
func startTLSBackend(t *testing.T, ca *proxy.CA, handler http.Handler) (srv *http.Server, port string, caCertPool *x509.CertPool) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.GenerateCert("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
	})
	srv = &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.Serve(tlsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("backend serve: %v", err)
		}
	}()
	t.Cleanup(func() { srv.Close() })

	_, port, _ = net.SplitHostPort(ln.Addr().String())
	caCertPool = x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(ca.CertPEM())
	return srv, port, caCertPool
}

// waitForProxy polls until the server's proxy is accepting connections.
func waitForProxy(t *testing.T, srv *Server, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		addr := srv.ProxyAddr()
		if addr != "" {
			conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
			if err == nil {
				conn.Close()
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("proxy did not start in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestServerStartStop(t *testing.T) {
	cfg := &Config{
		Proxy: ProxyConfig{
			Port: 0, // ephemeral
			Host: "127.0.0.1",
		},
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	waitForProxy(t, srv, 2*time.Second)

	// Canceling the context causes Start() to call Stop() internally.
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Start returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after cancel")
	}
}

func TestServerHealthEndpoint(t *testing.T) {
	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
	}
	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	resp, err := http.Get("http://" + srv.ProxyAddr() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status: %d, want 200", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"ok"`) {
		t.Errorf("healthz body = %s, want JSON with ok", body)
	}

	// Canceling the context causes Start() to call Stop() internally.
	cancel()
}

func TestStaticCredentialsNoContextResolver(t *testing.T) {
	t.Setenv("TEST_GH_TOKEN", "ghp_test_single_tenant")

	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
		Credentials: []CredentialConfig{
			{
				Host:   "api.github.com",
				Header: "Authorization",
				Grant:  "github",
				Source: SourceConfig{Type: "env", Var: "TEST_GH_TOKEN"},
			},
			{
				Host:   "api.anthropic.com",
				Header: "x-api-key",
				Source: SourceConfig{Type: "static", Value: "sk-ant-test"},
			},
		},
		Network: NetworkConfig{Policy: "permissive"},
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// No context resolver — credentials are injected for all matching requests.
	_, ok := srv.proxy.ResolveContext("any-token")
	if ok {
		t.Error("expected no context resolver in static credentials mode")
	}
}

func TestDefaultHeader(t *testing.T) {
	t.Setenv("TEST_TOKEN", "Bearer test123")

	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
		Credentials: []CredentialConfig{
			{
				Host:   "api.example.com",
				Source: SourceConfig{Type: "env", Var: "TEST_TOKEN"},
			},
		},
	}

	// Should succeed — header defaults to "Authorization" when omitted.
	_, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestMissingHost(t *testing.T) {
	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
		Credentials: []CredentialConfig{
			{
				Source: SourceConfig{Type: "static", Value: "test"},
			},
		},
	}

	_, err := New(context.Background(), cfg, "")
	if err == nil {
		t.Fatal("expected error for credential without host")
	}
	if !strings.Contains(err.Error(), "host is required") {
		t.Errorf("error = %q, want 'host is required'", err)
	}
}

func TestAuthToken(t *testing.T) {
	cfg := &Config{
		Proxy: ProxyConfig{
			Port:      0,
			Host:      "127.0.0.1",
			AuthToken: "my-secret-token",
		},
		Credentials: []CredentialConfig{
			{
				Host:   "api.example.com",
				Source: SourceConfig{Type: "static", Value: "test-cred"},
			},
		},
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := t.Context()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	// Request without auth token should be rejected.
	req, _ := http.NewRequest(http.MethodGet, "http://"+srv.ProxyAddr(), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET without auth: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("no-auth status = %d, want %d", resp.StatusCode, http.StatusProxyAuthRequired)
	}

	// Request WITH valid auth token should be accepted (not 407).
	proxyURL, _ := url.Parse("http://moat:my-secret-token@" + srv.ProxyAddr())
	authClient := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	resp2, err := authClient.Get("http://api.example.com/test")
	if err != nil {
		t.Fatalf("GET with auth: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode == http.StatusProxyAuthRequired {
		t.Error("request with valid auth token was rejected with 407")
	}
}

func TestDefaultProxyHost(t *testing.T) {
	cfg := &Config{
		Proxy: ProxyConfig{Port: 0}, // no host specified
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := t.Context()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	// Should have bound to 127.0.0.1.
	addr := srv.ProxyAddr()
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Errorf("proxy addr = %q, want 127.0.0.1:*", addr)
	}
}

func TestTLSCALoading(t *testing.T) {
	// Generate a CA and verify it's actually used for HTTPS interception
	// by sending a request through the proxy.
	dir := t.TempDir()
	ca, err := proxy.NewCA(dir)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	// Start an HTTPS backend signed by this CA.
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	backendCert, err := ca.GenerateCert("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	backendSrv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
		ReadHeaderTimeout: 5 * time.Second,
	}
	tlsLn := tls.NewListener(backendLn, &tls.Config{
		Certificates: []tls.Certificate{*backendCert},
		MinVersion:   tls.VersionTLS12,
	})
	go func() {
		if err := backendSrv.Serve(tlsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("backend serve: %v", err)
		}
	}()
	defer backendSrv.Close()
	_, backendPort, _ := net.SplitHostPort(backendLn.Addr().String())

	cfg := &Config{
		Proxy:   ProxyConfig{Port: 0, Host: "127.0.0.1"},
		TLS:     TLSConfig{CACert: filepath.Join(dir, "ca.crt"), CAKey: filepath.Join(dir, "ca.key")},
		Network: NetworkConfig{Policy: "permissive"},
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New with TLS: %v", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(ca.CertPEM())
	srv.proxy.SetUpstreamCAs(caCertPool)

	ctx := t.Context()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	// If the CA loaded correctly, the proxy can MITM-intercept HTTPS.
	proxyURL, _ := url.Parse("http://" + srv.ProxyAddr())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12},
		},
	}

	resp, err := client.Get("https://127.0.0.1:" + backendPort + "/tls-check")
	if err != nil {
		t.Fatalf("HTTPS through proxy failed (CA not loaded?): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestTLSCAMissingCert(t *testing.T) {
	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
		TLS: TLSConfig{
			CACert: "/nonexistent/ca.crt",
			CAKey:  "/nonexistent/ca.key",
		},
	}

	_, err := New(context.Background(), cfg, "")
	if err == nil {
		t.Fatal("expected error for missing CA cert")
	}
	if !strings.Contains(err.Error(), "reading CA cert") {
		t.Errorf("error = %q, want to mention 'reading CA cert'", err)
	}
}

func TestTLSCAPartialConfig(t *testing.T) {
	// Only CACert set, no CAKey — should create server without TLS (no error).
	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
		TLS: TLSConfig{
			CACert: "/some/cert.pem",
		},
	}

	_, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New with partial TLS should succeed (no interception): %v", err)
	}
}

func TestTLSCAWithECKey(t *testing.T) {
	// gen-ca.sh generates EC keys (prime256v1). Verify they load correctly.
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating EC key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test EC CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
		TLS: TLSConfig{
			CACert: certPath,
			CAKey:  keyPath,
		},
	}

	_, err = New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New with EC CA: %v", err)
	}
}

func TestHTTPSCredentialInjection(t *testing.T) {
	// End-to-end test: start gatekeeper with TLS + credential,
	// send HTTPS request through proxy, verify credential was injected.

	caDir := t.TempDir()
	ca, err := proxy.NewCA(caDir)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	var (
		gotAuth string
		authMu  sync.Mutex
	)
	_, backendPort, caCertPool := startTLSBackend(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authMu.Lock()
		gotAuth = r.Header.Get("Authorization")
		authMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))

	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
		TLS: TLSConfig{
			CACert: filepath.Join(caDir, "ca.crt"),
			CAKey:  filepath.Join(caDir, "ca.key"),
		},
		Credentials: []CredentialConfig{
			{
				Host:   "127.0.0.1",
				Header: "Authorization",
				Grant:  "test",
				Source: SourceConfig{Type: "static", Value: "Bearer secret123"},
			},
		},
		Network: NetworkConfig{Policy: "permissive"},
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// The proxy's upstream transport must trust the test CA that signed the
	// backend's cert. In production, upstream certs are signed by public CAs
	// in the system roots. In this test, the backend uses a cert from our
	// test CA.
	srv.proxy.SetUpstreamCAs(caCertPool)

	ctx := t.Context()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	proxyURL, _ := url.Parse("http://" + srv.ProxyAddr())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12},
		},
	}

	resp, err := client.Get("https://127.0.0.1:" + backendPort + "/test")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	resp.Body.Close()

	authMu.Lock()
	auth := gotAuth
	authMu.Unlock()
	if auth != "Bearer secret123" {
		t.Errorf("backend got Authorization = %q, want %q", auth, "Bearer secret123")
	}
}

func TestTLSCAInvalidPEM(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if err := os.WriteFile(certPath, []byte("not a cert"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("not a key"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
		TLS: TLSConfig{
			CACert: certPath,
			CAKey:  keyPath,
		},
	}

	_, err := New(context.Background(), cfg, "")
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
	if !strings.Contains(err.Error(), "loading CA") {
		t.Errorf("error = %q, want to mention 'loading CA'", err)
	}
}

func TestHTTPCredentialInjection(t *testing.T) {
	// End-to-end test for the plain HTTP (non-CONNECT) path.
	// The proxy intercepts HTTP requests and injects credentials directly.

	// Start an HTTP backend that echoes the Authorization header.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Header.Get("Authorization"))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)

	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
		Credentials: []CredentialConfig{
			{
				Host:   backendURL.Hostname(),
				Grant:  "test",
				Source: SourceConfig{Type: "static", Value: "Bearer http-secret"},
			},
		},
		Network: NetworkConfig{Policy: "permissive"},
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := t.Context()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	proxyURL, _ := url.Parse("http://" + srv.ProxyAddr())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}

	resp, err := client.Get(backend.URL + "/test")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if string(body) != "Bearer http-secret" {
		t.Errorf("backend got Authorization = %q, want %q", body, "Bearer http-secret")
	}
}

func TestHTTPSCustomHeaderInjection(t *testing.T) {
	// Test injection of a custom header (x-api-key) via HTTPS CONNECT path.
	caDir := t.TempDir()
	ca, err := proxy.NewCA(caDir)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	var (
		gotHeader string
		mu        sync.Mutex
	)
	_, backendPort, caCertPool := startTLSBackend(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotHeader = r.Header.Get("x-api-key")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))

	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
		TLS: TLSConfig{
			CACert: filepath.Join(caDir, "ca.crt"),
			CAKey:  filepath.Join(caDir, "ca.key"),
		},
		Credentials: []CredentialConfig{
			{
				Host:   "127.0.0.1",
				Header: "x-api-key",
				Grant:  "anthropic",
				Source: SourceConfig{Type: "static", Value: "sk-ant-test123"},
			},
		},
		Network: NetworkConfig{Policy: "permissive"},
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	srv.proxy.SetUpstreamCAs(caCertPool)

	ctx := t.Context()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	proxyURL, _ := url.Parse("http://" + srv.ProxyAddr())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12},
		},
	}

	resp, err := client.Get("https://127.0.0.1:" + backendPort + "/test")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	resp.Body.Close()

	mu.Lock()
	got := gotHeader
	mu.Unlock()
	if got != "sk-ant-test123" {
		t.Errorf("backend got x-api-key = %q, want %q", got, "sk-ant-test123")
	}
}

// captureServerLog installs a logger directly on the server's internal
// proxy, overriding the slog-wiring logger installed in New(), so tests can
// inspect RequestLogData (notably ClientAddr) without parsing log output.
func captureServerLog(t *testing.T, srv *Server) func() proxy.RequestLogData {
	t.Helper()
	ch := make(chan proxy.RequestLogData, 8)
	srv.proxy.SetLogger(func(d proxy.RequestLogData) { ch <- d })
	return func() proxy.RequestLogData {
		t.Helper()
		select {
		case d := <-ch:
			return d
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for canonical log line")
			return proxy.RequestLogData{}
		}
	}
}

// TestServerProxyProtocol_V1 reproduces the GCE deployment scenario: gatekeeper
// runs behind a GCP global TCP Proxy load balancer, which terminates the
// client TCP connection and dials gatekeeper from its own front-end IP
// (35.191.0.0/16), prepending a PROXY protocol v1 header naming the real
// client. With network.proxy_protocol enabled, the canonical log line's
// ClientAddr must reflect that real client — here a spoofed Modal egress IP,
// 100.52.56.181 — not the load balancer's peer address.
func TestServerProxyProtocol_V1(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()
	backendURL, _ := url.Parse(backend.URL)

	cfg := &Config{
		Proxy:   ProxyConfig{Port: 0, Host: "127.0.0.1"},
		Network: NetworkConfig{Policy: "permissive", ProxyProtocol: true},
	}
	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	waitLog := captureServerLog(t, srv)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	conn, err := net.Dial("tcp", srv.ProxyAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("PROXY TCP4 100.52.56.181 10.0.0.1 51234 8080\r\n")); err != nil {
		t.Fatalf("write PROXY header: %v", err)
	}

	req := fmt.Sprintf("GET %s/some/path HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", backend.URL, backendURL.Host)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	logged := waitLog()
	host, _, err := net.SplitHostPort(logged.ClientAddr)
	if err != nil {
		t.Fatalf("ClientAddr = %q: SplitHostPort: %v", logged.ClientAddr, err)
	}
	if host != "100.52.56.181" {
		t.Errorf("ClientAddr host = %q, want 100.52.56.181 (the PROXY-header source), not the LB's own peer address", host)
	}
}

// TestServerProxyProtocol_V2 is the binary-header counterpart to
// TestServerProxyProtocol_V1: the GCP LB (like most modern proxies) may send
// PROXY protocol v2 instead of the text v1 format.
func TestServerProxyProtocol_V2(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()
	backendURL, _ := url.Parse(backend.URL)

	cfg := &Config{
		Proxy:   ProxyConfig{Port: 0, Host: "127.0.0.1"},
		Network: NetworkConfig{Policy: "permissive", ProxyProtocol: true},
	}
	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	waitLog := captureServerLog(t, srv)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	conn, err := net.Dial("tcp", srv.ProxyAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	header := proxyproto.HeaderProxyFromAddrs(2,
		&net.TCPAddr{IP: net.ParseIP("100.52.56.181"), Port: 51234},
		&net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 8080},
	)
	if _, err := header.WriteTo(conn); err != nil {
		t.Fatalf("write PROXY v2 header: %v", err)
	}

	req := fmt.Sprintf("GET %s/v2/path HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", backend.URL, backendURL.Host)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	logged := waitLog()
	host, _, err := net.SplitHostPort(logged.ClientAddr)
	if err != nil {
		t.Fatalf("ClientAddr = %q: SplitHostPort: %v", logged.ClientAddr, err)
	}
	if host != "100.52.56.181" {
		t.Errorf("ClientAddr host = %q, want 100.52.56.181 (the PROXY v2-header source)", host)
	}
}

// TestServerProxyProtocol_FailSafeNoHeader verifies that a connection with no
// PROXY header still succeeds when network.proxy_protocol is enabled — the LB's
// own health checks and any direct probe of the port do not send one, and
// must not be rejected.
func TestServerProxyProtocol_FailSafeNoHeader(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "gatekeeper.log")
	cfg := &Config{
		Proxy:   ProxyConfig{Port: 0, Host: "127.0.0.1"},
		Network: NetworkConfig{Policy: "permissive", ProxyProtocol: true},
		Log:     LogConfig{Level: "debug", Output: logPath},
	}
	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	conn, err := net.Dial("tcp", srv.ProxyAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	req := "GET /healthz HTTP/1.1\r\nHost: gatekeeper\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (fail-open when no PROXY header is present); body = %s", resp.StatusCode, body)
	}

	// The headerless path is the fail-open case, not a parse failure: it must
	// stay quiet even at DEBUG, so a real LB health check never spams logs.
	logData, _ := os.ReadFile(logPath)
	if strings.Contains(string(logData), "malformed PROXY protocol header") {
		t.Errorf("expected no malformed-header log for a connection with no PROXY header at all, got: %s", logData)
	}
}

// TestServerProxyProtocol_MalformedHeader verifies that when
// network.proxy_protocol is enabled, a connection that opens with something
// that looks like a PROXY header but fails to parse (as opposed to one that
// simply lacks a header entirely — see TestServerProxyProtocol_FailSafeNoHeader,
// which must stay quiet) is dropped AND logged at DEBUG level with the real
// TCP peer address. PROXY header parsing is lazy — it happens inside the
// proxyproto.Conn on first Read, not in Accept — so without an explicit hook
// a parse failure surfaces only as an error from Conn.Read that net/http
// treats as a dead connection and closes silently, leaving the operator with
// a dropped connection and zero trace.
func TestServerProxyProtocol_MalformedHeader(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "gatekeeper.log")
	cfg := &Config{
		Proxy:   ProxyConfig{Port: 0, Host: "127.0.0.1"},
		Network: NetworkConfig{Policy: "permissive", ProxyProtocol: true},
		Log:     LogConfig{Level: "debug", Output: logPath},
	}
	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	conn, err := net.Dial("tcp", srv.ProxyAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	// The client's own local address is, from the loopback socket pair, the
	// exact address the server sees as the raw TCP peer — the value the
	// malformed-header log line is expected to carry.
	peerAddr := conn.LocalAddr().String()

	malformed := "PROXY TCP4 not-an-ip garbage\r\n"
	req := "GET /healthz HTTP/1.1\r\nHost: gatekeeper\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(malformed + req)); err != nil {
		t.Fatalf("write malformed PROXY header + request: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if n, readErr := conn.Read(buf); readErr == nil {
		t.Fatalf("expected the connection to be dropped with no HTTP response, got %d bytes: %q", n, buf[:n])
	}

	var logData []byte
	deadline := time.Now().Add(2 * time.Second)
	for {
		logData, _ = os.ReadFile(logPath)
		if strings.Contains(string(logData), "malformed PROXY protocol header") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for a malformed-header debug log line; log so far: %s", logData)
		}
		time.Sleep(10 * time.Millisecond)
	}

	logStr := string(logData)
	if !strings.Contains(logStr, "level=DEBUG") {
		t.Errorf("expected a DEBUG-level log line, got: %s", logStr)
	}
	if !strings.Contains(logStr, peerAddr) {
		t.Errorf("expected the log line to include the real peer address %q, got: %s", peerAddr, logStr)
	}
}

// TestServerProxyProtocol_DisabledDefault verifies that behavior is
// unchanged when network.proxy_protocol is left unset (the default): the
// canonical log line's ClientAddr is the raw TCP peer address, exactly as
// before this feature existed.
func TestServerProxyProtocol_DisabledDefault(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	cfg := &Config{
		Proxy:   ProxyConfig{Port: 0, Host: "127.0.0.1"},
		Network: NetworkConfig{Policy: "permissive"}, // proxy_protocol left unset
	}
	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	waitLog := captureServerLog(t, srv)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	proxyURL, _ := url.Parse("http://" + srv.ProxyAddr())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	resp, err := client.Get(backend.URL + "/plain")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	logged := waitLog()
	host, _, err := net.SplitHostPort(logged.ClientAddr)
	if err != nil {
		t.Fatalf("ClientAddr = %q: SplitHostPort: %v", logged.ClientAddr, err)
	}
	if host != "127.0.0.1" {
		t.Errorf("ClientAddr host = %q, want 127.0.0.1 (peer address; proxy_protocol disabled)", host)
	}
}

// TestServerProxyProtocol_ConnectIntercepted verifies PROXY protocol parsing
// also covers CONNECT-intercepted HTTPS traffic. Every request path
// (including intercepted inner requests) logs from the outer, tunnel-opening
// request's RemoteAddr (see proxy/proxy.go:191-196), so rewriting the
// accepted net.Conn's RemoteAddr at the listener is sufficient here too: the
// inner request's canonical log line must carry the PROXY header's source
// address.
func TestServerProxyProtocol_ConnectIntercepted(t *testing.T) {
	caDir := t.TempDir()
	ca, err := proxy.NewCA(caDir)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	_, backendPort, caCertPool := startTLSBackend(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
		TLS: TLSConfig{
			CACert: filepath.Join(caDir, "ca.crt"),
			CAKey:  filepath.Join(caDir, "ca.key"),
		},
		Network: NetworkConfig{Policy: "permissive", ProxyProtocol: true},
	}
	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.proxy.SetUpstreamCAs(caCertPool)
	waitLog := captureServerLog(t, srv)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	conn, err := net.Dial("tcp", srv.ProxyAddr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("PROXY TCP4 100.52.56.181 10.0.0.1 51234 8080\r\n")); err != nil {
		t.Fatalf("write PROXY header: %v", err)
	}

	backendAddr := "127.0.0.1:" + backendPort
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", backendAddr, backendAddr)
	connectResp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if connectResp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", connectResp.StatusCode)
	}

	tlsConn := tls.Client(conn, &tls.Config{
		RootCAs:    caCertPool,
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	defer tlsConn.Close()

	fmt.Fprintf(tlsConn, "GET /inner HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", backendAddr)
	innerResp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("read inner response: %v", err)
	}
	io.ReadAll(innerResp.Body)
	innerResp.Body.Close()
	if innerResp.StatusCode != http.StatusOK {
		t.Fatalf("inner status = %d, want 200", innerResp.StatusCode)
	}

	logged := waitLog()
	if logged.RequestType != "connect" {
		t.Fatalf("RequestType = %q, want connect", logged.RequestType)
	}
	host, _, err := net.SplitHostPort(logged.ClientAddr)
	if err != nil {
		t.Fatalf("ClientAddr = %q: SplitHostPort: %v", logged.ClientAddr, err)
	}
	if host != "100.52.56.181" {
		t.Errorf("ClientAddr host = %q, want 100.52.56.181 (PROXY-header source, carried through TLS interception)", host)
	}
}

func TestStrictNetworkPolicy(t *testing.T) {
	// Verify that strict network policy blocks requests to disallowed hosts
	// and allows requests to allowed hosts.

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)

	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
		Network: NetworkConfig{
			Policy: "strict",
			// Allow the backend host:port — httptest servers run on high ports.
			Allow: []string{backendURL.Host},
		},
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := t.Context()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	proxyURL, _ := url.Parse("http://" + srv.ProxyAddr())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}

	// Allowed host should succeed.
	resp, err := client.Get(backend.URL + "/allowed")
	if err != nil {
		t.Fatalf("GET allowed host: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("allowed host status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "ok" {
		t.Errorf("allowed host body = %q, want %q", body, "ok")
	}

	// Blocked host should fail. The proxy intentionally returns 407 (Proxy
	// Authentication Required) for network policy denials rather than 403.
	// This is by design: HTTP clients behind a proxy expect 407 for proxy-level
	// rejections, and 403 would imply the origin server denied the request.
	resp, err = client.Get("http://blocked.example.com/denied")
	if err != nil {
		t.Fatalf("GET blocked host: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("blocked host status = %d, want 407", resp.StatusCode)
	}
}

func TestMultipleCredentialsSameHost(t *testing.T) {
	// Multiple credentials for the same host (Authorization + x-api-key).
	// Both should be injected into the same request.

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Header.Get("Authorization")+"|"+r.Header.Get("x-api-key"))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)

	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
		Credentials: []CredentialConfig{
			{
				Host:   backendURL.Hostname(),
				Grant:  "github",
				Source: SourceConfig{Type: "static", Value: "Bearer gh-token"},
			},
			{
				Host:   backendURL.Hostname(),
				Header: "x-api-key",
				Grant:  "anthropic",
				Source: SourceConfig{Type: "static", Value: "sk-ant-key"},
			},
		},
		Network: NetworkConfig{Policy: "permissive"},
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := t.Context()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	proxyURL, _ := url.Parse("http://" + srv.ProxyAddr())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}

	resp, err := client.Get(backend.URL + "/test")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if string(body) != "Bearer gh-token|sk-ant-key" {
		t.Errorf("backend got %q, want %q", body, "Bearer gh-token|sk-ant-key")
	}
}

func TestAuthSchemeAutoDetectionThroughProxy(t *testing.T) {
	// Verify that a bare GitHub PAT gets "token" prefix when injected.

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Header.Get("Authorization"))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)

	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
		Credentials: []CredentialConfig{
			{
				Host:  backendURL.Hostname(),
				Grant: "github",
				// Bare GitHub classic PAT — should auto-detect "token" prefix.
				Source: SourceConfig{Type: "static", Value: "ghp_abc123def456"},
			},
		},
		Network: NetworkConfig{Policy: "permissive"},
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := t.Context()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	proxyURL, _ := url.Parse("http://" + srv.ProxyAddr())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}

	resp, err := client.Get(backend.URL + "/repos")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	want := "token ghp_abc123def456"
	if string(body) != want {
		t.Errorf("backend got Authorization = %q, want %q", body, want)
	}
}

func TestBasicFormatCredentialInjection(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Header.Get("Authorization"))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)

	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
		Credentials: []CredentialConfig{
			{
				Host:   backendURL.Hostname(),
				Grant:  "github-git",
				Format: "basic",
				Prefix: "x-access-token",
				Source: SourceConfig{Type: "static", Value: "ghs_abc123"},
			},
		},
		Network: NetworkConfig{Policy: "permissive"},
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := t.Context()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	proxyURL, _ := url.Parse("http://" + srv.ProxyAddr())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}

	resp, err := client.Get(backend.URL + "/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	want := "Basic eC1hY2Nlc3MtdG9rZW46Z2hzX2FiYzEyMw=="
	if string(body) != want {
		t.Errorf("backend got Authorization = %q, want %q", body, want)
	}
}

func TestBasicFormatHTTPSCredentialInjection(t *testing.T) {
	caDir := t.TempDir()
	ca, err := proxy.NewCA(caDir)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	var (
		gotAuth string
		authMu  sync.Mutex
	)
	_, backendPort, caCertPool := startTLSBackend(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authMu.Lock()
		gotAuth = r.Header.Get("Authorization")
		authMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))

	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
		TLS: TLSConfig{
			CACert: filepath.Join(caDir, "ca.crt"),
			CAKey:  filepath.Join(caDir, "ca.key"),
		},
		Credentials: []CredentialConfig{
			{
				Host:   "127.0.0.1",
				Grant:  "github-git",
				Format: "basic",
				Prefix: "x-access-token",
				Source: SourceConfig{Type: "static", Value: "ghs_abc123"},
			},
		},
		Network: NetworkConfig{Policy: "permissive"},
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.proxy.SetUpstreamCAs(caCertPool)

	ctx := t.Context()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	proxyURL, _ := url.Parse("http://" + srv.ProxyAddr())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12},
		},
	}

	resp, err := client.Get("https://127.0.0.1:" + backendPort + "/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	resp.Body.Close()

	authMu.Lock()
	auth := gotAuth
	authMu.Unlock()

	want := "Basic eC1hY2Nlc3MtdG9rZW46Z2hzX2FiYzEyMw=="
	if auth != want {
		t.Errorf("backend got Authorization = %q, want %q", auth, want)
	}
}

func TestBasicFormatValidation(t *testing.T) {
	t.Run("unknown format", func(t *testing.T) {
		cfg := &Config{
			Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
			Credentials: []CredentialConfig{
				{
					Host:   "github.com",
					Format: "basci",
					Source: SourceConfig{Type: "static", Value: "test"},
				},
			},
		}
		_, err := New(context.Background(), cfg, "")
		if err == nil {
			t.Fatal("expected error for unknown format")
		}
		if !strings.Contains(err.Error(), "unknown format") {
			t.Errorf("error = %q, want mention of 'unknown format'", err)
		}
	})

	t.Run("basic format with token-exchange source", func(t *testing.T) {
		t.Setenv("TEST_TE_FMT_SECRET", "s")
		cfg := &Config{
			Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
			Credentials: []CredentialConfig{
				{
					Host:   "api.github.com",
					Format: "basic",
					Prefix: "x-access-token",
					Source: SourceConfig{
						Type:            "token-exchange",
						Endpoint:        "http://sts.example.com/token",
						ClientID:        "gk",
						ClientSecretEnv: "TEST_TE_FMT_SECRET",
						SubjectHeader:   "X-Subject",
					},
				},
			},
		}
		_, err := New(context.Background(), cfg, "")
		if err != nil {
			t.Fatalf("format: basic should be accepted for token-exchange: %v", err)
		}
	})

	t.Run("basic with non-Authorization header", func(t *testing.T) {
		cfg := &Config{
			Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
			Credentials: []CredentialConfig{
				{
					Host:   "api.example.com",
					Header: "x-api-key",
					Format: "basic",
					Source: SourceConfig{Type: "static", Value: "test"},
				},
			},
		}
		_, err := New(context.Background(), cfg, "")
		if err == nil {
			t.Fatal("expected error for basic format with non-Authorization header")
		}
		if !strings.Contains(err.Error(), "only supported with the Authorization header") {
			t.Errorf("error = %q, want mention of 'only supported with the Authorization header'", err)
		}
	})
}

func TestEnsureAuthScheme(t *testing.T) {
	tests := []struct {
		name   string
		val    string
		prefix string
		format string
		want   string
	}{
		// Already prefixed — pass through unchanged.
		{name: "bearer already", val: "Bearer gho_abc", prefix: "", want: "Bearer gho_abc"},
		{name: "token already", val: "token ghp_abc", prefix: "", want: "token ghp_abc"},
		{name: "basic already", val: "Basic dXNlcjpwYXNz", prefix: "", want: "Basic dXNlcjpwYXNz"},

		// Explicit prefix overrides auto-detection.
		{name: "explicit prefix", val: "ghp_abc", prefix: "token", want: "token ghp_abc"},
		{name: "explicit Bearer", val: "sk-xxx", prefix: "Bearer", want: "Bearer sk-xxx"},
		{name: "explicit ApiKey", val: "key123", prefix: "ApiKey", want: "ApiKey key123"},
		// Explicit prefix does not double-prefix if value already has scheme.
		{name: "explicit prefix with existing scheme", val: "Bearer gho_abc", prefix: "token", want: "Bearer gho_abc"},

		// GitHub auto-detection.
		{name: "ghp classic PAT", val: "ghp_abc123", prefix: "", want: "token ghp_abc123"},
		{name: "ghs app token", val: "ghs_abc123", prefix: "", want: "token ghs_abc123"},
		{name: "gho OAuth", val: "gho_abc123", prefix: "", want: "Bearer gho_abc123"},
		{name: "github_pat fine-grained", val: "github_pat_abc123", prefix: "", want: "Bearer github_pat_abc123"},

		// Unknown tokens default to Bearer.
		{name: "unknown token", val: "sk-ant-abc123", prefix: "", want: "Bearer sk-ant-abc123"},
		{name: "opaque token", val: "abc123def456", prefix: "", want: "Bearer abc123def456"},

		// Basic format — encodes as HTTP Basic auth.
		{name: "basic format with username", val: "ghs_abc123", prefix: "x-access-token", format: "basic", want: "Basic eC1hY2Nlc3MtdG9rZW46Z2hzX2FiYzEyMw=="},
		{name: "basic format no username", val: "ghs_abc123", prefix: "", format: "basic", want: "Basic Omdoc19hYmMxMjM="},
		{name: "basic format case insensitive", val: "mytoken", prefix: "user", format: "Basic", want: "Basic dXNlcjpteXRva2Vu"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ensureAuthScheme(tt.val, tt.prefix, tt.format)
			if got != tt.want {
				t.Errorf("ensureAuthScheme(%q, %q, %q) = %q, want %q", tt.val, tt.prefix, tt.format, got, tt.want)
			}
		})
	}
}

func TestOTelSpanEventsViaHTTPRequest(t *testing.T) {
	spanExporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(spanExporter))
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { tp.Shutdown(context.Background()) })

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
	}
	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	handler := proxy.OTelHandler(&healthHandler{next: srv.proxy})
	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	proxyURL, _ := url.Parse(proxyServer.URL)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}

	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()

	tp.ForceFlush(context.Background())

	spans := spanExporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least one span")
	}

	foundComplete := false
	for _, s := range spans {
		for _, e := range s.Events {
			if e.Name == "request.complete" {
				foundComplete = true
			}
		}
	}
	if !foundComplete {
		t.Error("expected request.complete span event from RequestLogger callback")
	}
}

func TestRefreshInterval(t *testing.T) {
	tests := []struct {
		ttl  time.Duration
		want time.Duration
	}{
		{60 * time.Minute, 45 * time.Minute},
		{40 * time.Second, 30 * time.Second},
		{20 * time.Second, 30 * time.Second},
		{0, 30 * time.Second},
	}
	for _, tt := range tests {
		got := refreshInterval(tt.ttl)
		if got != tt.want {
			t.Errorf("refreshInterval(%v) = %v, want %v", tt.ttl, got, tt.want)
		}
	}
}

type mockRefreshSource struct {
	mu       sync.Mutex
	calls    int
	token    string
	ttl      time.Duration
	fetchErr error
}

func (m *mockRefreshSource) Fetch(_ context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.fetchErr != nil {
		return "", m.fetchErr
	}
	return fmt.Sprintf("%s_%d", m.token, m.calls), nil
}

func (m *mockRefreshSource) Type() string { return "mock-refresh" }

func (m *mockRefreshSource) TTL() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ttl
}

func (m *mockRefreshSource) fetchCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func TestStartCredentialRefresh_CancelStopsGoroutine(t *testing.T) {
	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
	}
	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatal(err)
	}

	mock := &mockRefreshSource{
		token: "ghs_test",
		ttl:   1 * time.Hour,
	}

	cred := CredentialConfig{
		Host:  "api.github.com",
		Grant: "github",
	}

	ctx, cancel := context.WithCancel(context.Background())
	srv.startCredentialRefresh(ctx, mock, []CredentialConfig{cred})

	// Cancel immediately — goroutine should exit without fetching.
	cancel()
	time.Sleep(50 * time.Millisecond)

	if count := mock.fetchCount(); count != 0 {
		t.Errorf("fetch called %d times after immediate cancel, want 0", count)
	}
}

func TestLoadCredentials_DedupSharedEnvSource(t *testing.T) {
	t.Setenv("GK_TEST_DEDUP_TOKEN", "ghs_shared_123")

	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
		Credentials: []CredentialConfig{
			{Host: "api.github.com", Source: SourceConfig{Type: "env", Var: "GK_TEST_DEDUP_TOKEN"}, Grant: "gh-api"},
			{Host: "github.com", Source: SourceConfig{Type: "env", Var: "GK_TEST_DEDUP_TOKEN"}, Grant: "gh-web"},
		},
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatal(err)
	}

	// Env sources don't implement RefreshingSource, so no refresh goroutines.
	if len(srv.pendingRefreshes) != 0 {
		t.Errorf("pendingRefreshes = %d, want 0 (env sources are not refreshing)", len(srv.pendingRefreshes))
	}
}

func TestLoadCredentials_DedupSharedRefreshingSource(t *testing.T) {
	mock := &mockRefreshSource{token: "ghs_shared", ttl: 1 * time.Hour}

	// Create server without credentials, then call loadCredentials with
	// the resolveSource override so we can inject a mock RefreshingSource.
	srv, err := New(context.Background(), &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	srv.resolveSource = func(_ SourceConfig) (credentialsource.CredentialSource, error) {
		return mock, nil
	}

	cfg := &Config{
		Credentials: []CredentialConfig{
			{Host: "api.github.com", Source: SourceConfig{Type: "mock"}, Grant: "gh-api"},
			{Host: "github.com", Source: SourceConfig{Type: "mock"}, Grant: "gh-web"},
		},
	}
	if err := srv.loadCredentials(context.Background(), cfg); err != nil {
		t.Fatalf("loadCredentials: %v", err)
	}

	if mock.fetchCount() != 1 {
		t.Errorf("Fetch calls = %d, want 1 (second cred should reuse cached value)", mock.fetchCount())
	}
	if len(srv.pendingRefreshes) != 1 {
		t.Fatalf("pendingRefreshes = %d, want 1", len(srv.pendingRefreshes))
	}
	if len(srv.pendingRefreshes[0].creds) != 2 {
		t.Errorf("creds in pendingRefresh = %d, want 2", len(srv.pendingRefreshes[0].creds))
	}
}

func TestHTTPSTokenExchangeEndToEnd(t *testing.T) {
	// End-to-end: TLS interception + token-exchange credential.
	// Verifies STS receives correct RFC 8693 request, backend gets
	// the exchanged token, and the subject header is stripped.

	caDir := t.TempDir()
	ca, err := proxy.NewCA(caDir)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	// Mock STS that validates the RFC 8693 request and returns an exchanged token.
	var (
		stsSubject   string
		stsResource  string
		stsGrantType string
		stsMu        sync.Mutex
	)
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "want POST", http.StatusMethodNotAllowed)
			return
		}

		user, pass, ok := r.BasicAuth()
		if !ok || user != "gk-client" || pass != "gk-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		stsMu.Lock()
		stsGrantType = r.FormValue("grant_type")
		stsSubject = r.FormValue("subject_token")
		stsResource = r.FormValue("resource")
		stsMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "exchanged-token-for-" + r.FormValue("subject_token"),
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type":        "Bearer",
			"expires_in":        3600,
		})
	}))
	defer sts.Close()

	// TLS backend that records what it received.
	var (
		backendAuth          string
		backendSubjectHeader string
		backendMu            sync.Mutex
	)
	_, backendPort, caCertPool := startTLSBackend(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendMu.Lock()
		backendAuth = r.Header.Get("Authorization")
		backendSubjectHeader = r.Header.Get("X-Gatekeeper-Subject")
		backendMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))

	t.Setenv("TEST_TE_CLIENT_SECRET", "gk-secret")

	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
		TLS: TLSConfig{
			CACert: filepath.Join(caDir, "ca.crt"),
			CAKey:  filepath.Join(caDir, "ca.key"),
		},
		Credentials: []CredentialConfig{
			{
				Host:   "127.0.0.1",
				Grant:  "github",
				Prefix: "Bearer",
				Source: SourceConfig{
					Type:            "token-exchange",
					Endpoint:        sts.URL,
					ClientID:        "gk-client",
					ClientSecretEnv: "TEST_TE_CLIENT_SECRET",
					SubjectHeader:   "X-Gatekeeper-Subject",
					Resource:        "https://api.github.com",
				},
			},
		},
		Network: NetworkConfig{Policy: "permissive"},
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.proxy.SetUpstreamCAs(caCertPool)

	ctx := t.Context()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	proxyURL, _ := url.Parse("http://" + srv.ProxyAddr())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12},
		},
	}

	req, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:"+backendPort+"/user", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Gatekeeper-Subject", "usr_alice")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// Verify STS received the correct RFC 8693 request.
	stsMu.Lock()
	gotGrantType := stsGrantType
	gotSubject := stsSubject
	gotResource := stsResource
	stsMu.Unlock()

	if gotGrantType != "urn:ietf:params:oauth:grant-type:token-exchange" {
		t.Errorf("STS grant_type = %q, want RFC 8693 grant type", gotGrantType)
	}
	if gotSubject != "usr_alice" {
		t.Errorf("STS subject_token = %q, want %q", gotSubject, "usr_alice")
	}
	if gotResource != "https://api.github.com" {
		t.Errorf("STS resource = %q, want %q", gotResource, "https://api.github.com")
	}

	// Verify backend received the exchanged token and NOT the subject header.
	backendMu.Lock()
	gotAuth := backendAuth
	gotSubjectHdr := backendSubjectHeader
	backendMu.Unlock()

	if gotAuth != "Bearer exchanged-token-for-usr_alice" {
		t.Errorf("backend Authorization = %q, want %q", gotAuth, "Bearer exchanged-token-for-usr_alice")
	}
	if gotSubjectHdr != "" {
		t.Errorf("backend still has X-Gatekeeper-Subject = %q, want stripped", gotSubjectHdr)
	}
}

func TestHTTPSTokenExchangeNoSubject(t *testing.T) {
	// When no X-Gatekeeper-Subject header is present, the resolver should
	// not call the STS and no credential should be injected.

	caDir := t.TempDir()
	ca, err := proxy.NewCA(caDir)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	stsCalled := false
	var stsMu sync.Mutex
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stsMu.Lock()
		stsCalled = true
		stsMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "should-not-appear",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer sts.Close()

	var (
		backendAuth string
		backendMu   sync.Mutex
	)
	_, backendPort, caCertPool := startTLSBackend(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendMu.Lock()
		backendAuth = r.Header.Get("Authorization")
		backendMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))

	t.Setenv("TEST_TE_SECRET_NOSUB", "secret")

	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
		TLS: TLSConfig{
			CACert: filepath.Join(caDir, "ca.crt"),
			CAKey:  filepath.Join(caDir, "ca.key"),
		},
		Credentials: []CredentialConfig{
			{
				Host:  "127.0.0.1",
				Grant: "github",
				Source: SourceConfig{
					Type:            "token-exchange",
					Endpoint:        sts.URL,
					ClientID:        "gk",
					ClientSecretEnv: "TEST_TE_SECRET_NOSUB",
					SubjectHeader:   "X-Gatekeeper-Subject",
				},
			},
		},
		Network: NetworkConfig{Policy: "permissive"},
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.proxy.SetUpstreamCAs(caCertPool)

	ctx := t.Context()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	proxyURL, _ := url.Parse("http://" + srv.ProxyAddr())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12},
		},
	}

	resp, err := client.Get("https://127.0.0.1:" + backendPort + "/user")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	stsMu.Lock()
	called := stsCalled
	stsMu.Unlock()
	if called {
		t.Error("STS should not have been called when no subject header is present")
	}

	backendMu.Lock()
	auth := backendAuth
	backendMu.Unlock()
	if auth != "" {
		t.Errorf("backend got Authorization = %q, want empty (no credential injected)", auth)
	}
}

func TestHTTPSTokenExchangeProxyAuthSubject(t *testing.T) {
	caDir := t.TempDir()
	ca, err := proxy.NewCA(caDir)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	var (
		stsSubject string
		stsMu      sync.Mutex
	)
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "want POST", http.StatusMethodNotAllowed)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "gk-client" || pass != "gk-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		stsMu.Lock()
		stsSubject = r.FormValue("subject_token")
		stsMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "exchanged-for-" + r.FormValue("subject_token"),
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type":        "Bearer",
			"expires_in":        3600,
		})
	}))
	defer sts.Close()

	var (
		backendAuth string
		backendMu   sync.Mutex
	)
	_, backendPort, caCertPool := startTLSBackend(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendMu.Lock()
		backendAuth = r.Header.Get("Authorization")
		backendMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))

	t.Setenv("TEST_TE_SECRET_PXA", "gk-secret")

	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
		TLS: TLSConfig{
			CACert: filepath.Join(caDir, "ca.crt"),
			CAKey:  filepath.Join(caDir, "ca.key"),
		},
		Credentials: []CredentialConfig{
			{
				Host:   "127.0.0.1",
				Grant:  "github",
				Prefix: "Bearer",
				Source: SourceConfig{
					Type:            "token-exchange",
					Endpoint:        sts.URL,
					ClientID:        "gk-client",
					ClientSecretEnv: "TEST_TE_SECRET_PXA",
					SubjectFrom:     "proxy-auth",
					Resource:        "https://api.github.com",
				},
			},
		},
		Network: NetworkConfig{Policy: "permissive"},
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.proxy.SetUpstreamCAs(caCertPool)

	ctx := t.Context()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	proxyURL, _ := url.Parse("http://" + srv.ProxyAddr())
	proxyURL.User = url.UserPassword("alice@example.com", "unused")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12},
		},
	}

	req, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:"+backendPort+"/user", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	stsMu.Lock()
	gotSubject := stsSubject
	stsMu.Unlock()
	if gotSubject != "alice@example.com" {
		t.Errorf("STS subject_token = %q, want %q", gotSubject, "alice@example.com")
	}

	backendMu.Lock()
	gotAuth := backendAuth
	backendMu.Unlock()
	if gotAuth != "Bearer exchanged-for-alice@example.com" {
		t.Errorf("backend Authorization = %q, want %q", gotAuth, "Bearer exchanged-for-alice@example.com")
	}
}

func TestHTTPSTokenExchangeActorToken(t *testing.T) {
	caDir := t.TempDir()
	ca, err := proxy.NewCA(caDir)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	var (
		stsSubject    string
		stsActorToken string
		stsMu         sync.Mutex
	)
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "want POST", http.StatusMethodNotAllowed)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "gk-client" || pass != "gk-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		stsMu.Lock()
		stsSubject = r.FormValue("subject_token")
		stsActorToken = r.FormValue("actor_token")
		stsMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "exchanged-for-" + r.FormValue("subject_token"),
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type":        "Bearer",
			"expires_in":        3600,
		})
	}))
	defer sts.Close()

	var (
		backendAuth string
		backendMu   sync.Mutex
	)
	_, backendPort, caCertPool := startTLSBackend(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendMu.Lock()
		backendAuth = r.Header.Get("Authorization")
		backendMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))

	t.Setenv("TEST_TE_SECRET_ACTOR", "gk-secret")

	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
		TLS: TLSConfig{
			CACert: filepath.Join(caDir, "ca.crt"),
			CAKey:  filepath.Join(caDir, "ca.key"),
		},
		Credentials: []CredentialConfig{
			{
				Host:   "127.0.0.1",
				Grant:  "github",
				Prefix: "Bearer",
				Source: SourceConfig{
					Type:            "token-exchange",
					Endpoint:        sts.URL,
					ClientID:        "gk-client",
					ClientSecretEnv: "TEST_TE_SECRET_ACTOR",
					SubjectFrom:     "proxy-auth",
					ActorTokenFrom:  "proxy-auth-password",
					Resource:        "https://api.github.com",
				},
			},
		},
		Network: NetworkConfig{Policy: "permissive"},
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.proxy.SetUpstreamCAs(caCertPool)

	ctx := t.Context()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	proxyURL, _ := url.Parse("http://" + srv.ProxyAddr())
	proxyURL.User = url.UserPassword("alice@example.com", "ak_alice_xxx")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12},
		},
	}

	req, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:"+backendPort+"/user", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	stsMu.Lock()
	gotSubject := stsSubject
	gotActor := stsActorToken
	stsMu.Unlock()
	if gotSubject != "alice@example.com" {
		t.Errorf("STS subject_token = %q, want %q", gotSubject, "alice@example.com")
	}
	if gotActor != "ak_alice_xxx" {
		t.Errorf("STS actor_token = %q, want %q", gotActor, "ak_alice_xxx")
	}

	backendMu.Lock()
	gotAuth := backendAuth
	backendMu.Unlock()
	if gotAuth != "Bearer exchanged-for-alice@example.com" {
		t.Errorf("backend Authorization = %q, want %q", gotAuth, "Bearer exchanged-for-alice@example.com")
	}
}

func TestHTTPSTokenExchangeActorTokenWithAuthToken(t *testing.T) {
	caDir := t.TempDir()
	ca, err := proxy.NewCA(caDir)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "want POST", http.StatusMethodNotAllowed)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "gk-client" || pass != "gk-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "exchanged-for-" + r.FormValue("subject_token"),
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type":        "Bearer",
			"expires_in":        3600,
		})
	}))
	defer sts.Close()

	var (
		backendAuth string
		backendMu   sync.Mutex
	)
	_, backendPort, caCertPool := startTLSBackend(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendMu.Lock()
		backendAuth = r.Header.Get("Authorization")
		backendMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))

	t.Setenv("TEST_TE_SECRET_ACTOR_AUTH", "gk-secret")

	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1", AuthToken: "static-proxy-token"},
		TLS: TLSConfig{
			CACert: filepath.Join(caDir, "ca.crt"),
			CAKey:  filepath.Join(caDir, "ca.key"),
		},
		Credentials: []CredentialConfig{
			{
				Host:   "127.0.0.1",
				Grant:  "github",
				Prefix: "Bearer",
				Source: SourceConfig{
					Type:            "token-exchange",
					Endpoint:        sts.URL,
					ClientID:        "gk-client",
					ClientSecretEnv: "TEST_TE_SECRET_ACTOR_AUTH",
					SubjectFrom:     "proxy-auth",
					ActorTokenFrom:  "proxy-auth-password",
					Resource:        "https://api.github.com",
				},
			},
		},
		Network: NetworkConfig{Policy: "permissive"},
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.proxy.SetUpstreamCAs(caCertPool)

	ctx := t.Context()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	proxyURL, _ := url.Parse("http://" + srv.ProxyAddr())
	proxyURL.User = url.UserPassword("alice@example.com", "ak_alice_xxx")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12},
		},
	}

	req, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:"+backendPort+"/user", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; auth_token + actor_token_from should delegate auth to STS", resp.StatusCode)
	}

	backendMu.Lock()
	gotAuth := backendAuth
	backendMu.Unlock()
	if gotAuth != "Bearer exchanged-for-alice@example.com" {
		t.Errorf("backend Authorization = %q, want %q", gotAuth, "Bearer exchanged-for-alice@example.com")
	}
}

func TestHTTPSTokenExchangeBasicFormat(t *testing.T) {
	caDir := t.TempDir()
	ca, err := proxy.NewCA(caDir)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "want POST", http.StatusMethodNotAllowed)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "gk-client" || pass != "gk-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "ghs_app_token_abc",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type":        "Bearer",
			"expires_in":        3600,
		})
	}))
	defer sts.Close()

	var (
		backendAuth string
		backendMu   sync.Mutex
	)
	_, backendPort, caCertPool := startTLSBackend(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendMu.Lock()
		backendAuth = r.Header.Get("Authorization")
		backendMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))

	t.Setenv("TEST_TE_SECRET_BASIC", "gk-secret")

	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
		TLS: TLSConfig{
			CACert: filepath.Join(caDir, "ca.crt"),
			CAKey:  filepath.Join(caDir, "ca.key"),
		},
		Credentials: []CredentialConfig{
			{
				Host:   "127.0.0.1",
				Grant:  "github",
				Format: "basic",
				Prefix: "x-access-token",
				Source: SourceConfig{
					Type:            "token-exchange",
					Endpoint:        sts.URL,
					ClientID:        "gk-client",
					ClientSecretEnv: "TEST_TE_SECRET_BASIC",
					SubjectHeader:   "X-Gatekeeper-Subject",
					Resource:        "https://api.github.com",
				},
			},
		},
		Network: NetworkConfig{Policy: "permissive"},
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.proxy.SetUpstreamCAs(caCertPool)

	ctx := t.Context()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	proxyURL, _ := url.Parse("http://" + srv.ProxyAddr())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12},
		},
	}

	req, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:"+backendPort+"/info/refs", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Gatekeeper-Subject", "usr_alice")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	backendMu.Lock()
	gotAuth := backendAuth
	backendMu.Unlock()

	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:ghs_app_token_abc"))
	if gotAuth != wantAuth {
		t.Errorf("backend Authorization = %q, want %q", gotAuth, wantAuth)
	}
}

func TestHTTPTokenExchangeRelay(t *testing.T) {
	// End-to-end test for token-exchange over the plain HTTP (non-CONNECT) relay
	// path. Exercises handleHTTP where proxyReq == innerReq.

	var (
		backendAuth          string
		backendSubjectHeader string
		backendMu            sync.Mutex
	)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendMu.Lock()
		backendAuth = r.Header.Get("Authorization")
		backendSubjectHeader = r.Header.Get("X-Gatekeeper-Subject")
		backendMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)

	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "want POST", http.StatusMethodNotAllowed)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "gk-client" || pass != "gk-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "exchanged-for-" + r.FormValue("subject_token"),
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type":        "Bearer",
			"expires_in":        3600,
		})
	}))
	defer sts.Close()

	t.Setenv("TEST_TE_RELAY_SECRET", "gk-secret")

	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
		Credentials: []CredentialConfig{
			{
				Host:   backendURL.Hostname(),
				Grant:  "test",
				Prefix: "Bearer",
				Source: SourceConfig{
					Type:            "token-exchange",
					Endpoint:        sts.URL,
					ClientID:        "gk-client",
					ClientSecretEnv: "TEST_TE_RELAY_SECRET",
					SubjectHeader:   "X-Gatekeeper-Subject",
				},
			},
		},
		Network: NetworkConfig{Policy: "permissive"},
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := t.Context()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	proxyURL, _ := url.Parse("http://" + srv.ProxyAddr())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}

	req, err := http.NewRequest(http.MethodGet, backend.URL+"/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Gatekeeper-Subject", "usr_bob")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	backendMu.Lock()
	gotAuth := backendAuth
	gotSubjectHdr := backendSubjectHeader
	backendMu.Unlock()

	if gotAuth != "Bearer exchanged-for-usr_bob" {
		t.Errorf("backend Authorization = %q, want %q", gotAuth, "Bearer exchanged-for-usr_bob")
	}
	if gotSubjectHdr != "" {
		t.Errorf("backend still has X-Gatekeeper-Subject = %q, want stripped", gotSubjectHdr)
	}
}

func TestHTTPTokenExchangeProxyAuthRelay(t *testing.T) {
	// End-to-end test for token-exchange with subject_from: proxy-auth over the
	// plain HTTP relay path. The Proxy-Authorization username is the subject.

	var (
		backendAuth string
		backendMu   sync.Mutex
	)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendMu.Lock()
		backendAuth = r.Header.Get("Authorization")
		backendMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)

	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "want POST", http.StatusMethodNotAllowed)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "gk-client" || pass != "gk-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "exchanged-for-" + r.FormValue("subject_token"),
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type":        "Bearer",
			"expires_in":        3600,
		})
	}))
	defer sts.Close()

	t.Setenv("TEST_TE_RELAY_PXA_SECRET", "gk-secret")

	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
		Credentials: []CredentialConfig{
			{
				Host:   backendURL.Hostname(),
				Grant:  "test",
				Prefix: "Bearer",
				Source: SourceConfig{
					Type:            "token-exchange",
					Endpoint:        sts.URL,
					ClientID:        "gk-client",
					ClientSecretEnv: "TEST_TE_RELAY_PXA_SECRET",
					SubjectFrom:     "proxy-auth",
				},
			},
		},
		Network: NetworkConfig{Policy: "permissive"},
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := t.Context()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	proxyURL, _ := url.Parse("http://" + srv.ProxyAddr())
	proxyURL.User = url.UserPassword("alice@example.com", "unused")

	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}

	resp, err := client.Get(backend.URL + "/test")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	backendMu.Lock()
	gotAuth := backendAuth
	backendMu.Unlock()

	if gotAuth != "Bearer exchanged-for-alice@example.com" {
		t.Errorf("backend Authorization = %q, want %q", gotAuth, "Bearer exchanged-for-alice@example.com")
	}
}

func TestHTTPSTokenExchangeFallbackToStatic(t *testing.T) {
	caDir := t.TempDir()
	ca, err := proxy.NewCA(caDir)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	stsCalled := false
	var stsMu sync.Mutex
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stsMu.Lock()
		stsCalled = true
		stsMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "user-oauth-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer sts.Close()

	var (
		backendAuth string
		backendMu   sync.Mutex
	)
	_, backendPort, caCertPool := startTLSBackend(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendMu.Lock()
		backendAuth = r.Header.Get("Authorization")
		backendMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))

	t.Setenv("TEST_TE_SECRET_FALLBACK", "secret")

	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
		TLS: TLSConfig{
			CACert: filepath.Join(caDir, "ca.crt"),
			CAKey:  filepath.Join(caDir, "ca.key"),
		},
		Credentials: []CredentialConfig{
			{
				Host:  "127.0.0.1",
				Grant: "github-user",
				Source: SourceConfig{
					Type:            "token-exchange",
					Endpoint:        sts.URL,
					ClientID:        "gk",
					ClientSecretEnv: "TEST_TE_SECRET_FALLBACK",
					SubjectHeader:   "X-Gatekeeper-Subject",
				},
			},
			{
				Host:   "127.0.0.1",
				Grant:  "github-bot",
				Source: SourceConfig{Type: "static", Value: "Bearer bot-fallback-token"},
			},
		},
		Network: NetworkConfig{Policy: "permissive"},
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.proxy.SetUpstreamCAs(caCertPool)

	ctx := t.Context()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	proxyURL, _ := url.Parse("http://" + srv.ProxyAddr())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12},
		},
	}

	// No subject header — resolver returns nil, falls through to static.
	resp, err := client.Get("https://127.0.0.1:" + backendPort + "/user")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	stsMu.Lock()
	called := stsCalled
	stsMu.Unlock()
	if called {
		t.Error("STS should not have been called when no subject header is present")
	}

	backendMu.Lock()
	fallbackAuth := backendAuth
	backendMu.Unlock()
	if fallbackAuth != "Bearer bot-fallback-token" {
		t.Errorf("backend Authorization = %q, want %q (static fallback)", fallbackAuth, "Bearer bot-fallback-token")
	}

	stsMu.Lock()
	stsCalled = false
	stsMu.Unlock()

	// With subject header — resolver returns credentials, static is not used.
	req, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:"+backendPort+"/user", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Gatekeeper-Subject", "usr_alice")

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET with subject: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	stsMu.Lock()
	called = stsCalled
	stsMu.Unlock()
	if !called {
		t.Error("STS should have been called when subject header is present")
	}

	backendMu.Lock()
	resolverAuth := backendAuth
	backendMu.Unlock()
	if resolverAuth != "Bearer user-oauth-token" {
		t.Errorf("backend Authorization = %q, want %q (resolver result)", resolverAuth, "Bearer user-oauth-token")
	}
}

// newTestCAConfig generates a CA on disk and returns a TLSConfig pointing at it.
func newTestCAConfig(t *testing.T) TLSConfig {
	t.Helper()
	dir := t.TempDir()
	if _, err := proxy.NewCA(dir); err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	return TLSConfig{
		CACert: filepath.Join(dir, "ca.crt"),
		CAKey:  filepath.Join(dir, "ca.key"),
	}
}

func TestServerStartsPostgresListener(t *testing.T) {
	cfg := &Config{
		Proxy:    ProxyConfig{Port: 0, Host: "127.0.0.1"},
		TLS:      newTestCAConfig(t),
		Postgres: &PostgresConfig{Port: 0},
		Credentials: []CredentialConfig{
			{
				Host:     "*.neon.tech",
				Postgres: &PostgresCredentialConfig{Resolver: "static"},
				Source:   SourceConfig{Type: "static", Value: "pw"},
			},
		},
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Start(ctx) }()

	// Poll until the postgres listener has an address.
	deadline := time.Now().Add(2 * time.Second)
	var pgAddr string
	for {
		pgAddr = srv.PostgresAddr()
		if pgAddr != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("postgres listener did not start in time")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Raw TCP dial must succeed.
	conn, err := net.DialTimeout("tcp", pgAddr, time.Second)
	if err != nil {
		t.Fatalf("dial postgres listener: %v", err)
	}
	defer conn.Close()

	// Sending an SSLRequest should get a single 'S' byte back, proving the
	// listener speaks the Postgres wire protocol and offers TLS.
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	frontend := pgproto3.NewFrontend(conn, conn)
	frontend.Send(&pgproto3.SSLRequest{})
	if err := frontend.Flush(); err != nil {
		t.Fatalf("send SSLRequest: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read SSLRequest response: %v", err)
	}
	if buf[0] != 'S' {
		t.Errorf("SSLRequest response = %q, want 'S'", buf[0])
	}
}

func TestServerPostgresStartFailureCleansUpHTTP(t *testing.T) {
	// Occupy a port so the postgres listener fails to bind to it.
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupying port: %v", err)
	}
	defer occupied.Close()
	occupiedPort := occupied.Addr().(*net.TCPAddr).Port

	cfg := &Config{
		Proxy:    ProxyConfig{Port: 0, Host: "127.0.0.1"}, // OS-assigned HTTP port
		TLS:      newTestCAConfig(t),
		Postgres: &PostgresConfig{Port: occupiedPort, Host: "127.0.0.1"},
		Credentials: []CredentialConfig{
			{
				Host:     "*.neon.tech",
				Postgres: &PostgresCredentialConfig{Resolver: "static"},
				Source:   SourceConfig{Type: "static", Value: "pw"},
			},
		},
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// On the postgres-bind-failure path, Start returns the error immediately
	// (it does not block on ctx.Done), so call it in the current goroutine.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startErr := srv.Start(ctx)
	if startErr == nil {
		t.Fatal("expected Start to fail when postgres port is occupied")
	}
	if !strings.Contains(startErr.Error(), "postgres listener") {
		t.Errorf("error = %q, want mention of 'postgres listener'", startErr)
	}

	// The HTTP listener must have been torn down — its port should no longer
	// be accepting connections. The proxy server's Shutdown closes the
	// listener, so a dial to the proxy address should fail.
	proxyAddr := srv.ProxyAddr()
	if proxyAddr == "" {
		t.Fatal("ProxyAddr is empty; HTTP listener address was never recorded")
	}
	// Give the Serve goroutine a moment to observe the closed listener.
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, dialErr := net.DialTimeout("tcp", proxyAddr, 100*time.Millisecond)
		if dialErr != nil {
			break // listener closed — leak cleaned up
		}
		conn.Close()
		if time.Now().After(deadline) {
			t.Fatalf("HTTP listener at %s still accepting after postgres failure; it leaked", proxyAddr)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestServerPostgresRequiresCA(t *testing.T) {
	cfg := &Config{
		Proxy:    ProxyConfig{Port: 0, Host: "127.0.0.1"},
		Postgres: &PostgresConfig{Port: 0},
	}

	_, err := New(context.Background(), cfg, "")
	if err == nil {
		t.Fatal("expected error for postgres listener without CA")
	}
	if !strings.Contains(err.Error(), "ca_cert") || !strings.Contains(err.Error(), "tls") {
		t.Errorf("error = %q, want mention of tls ca_cert", err)
	}
}

func TestServerPostgresUnknownResolver(t *testing.T) {
	cfg := &Config{
		Proxy:    ProxyConfig{Port: 0, Host: "127.0.0.1"},
		TLS:      newTestCAConfig(t),
		Postgres: &PostgresConfig{Port: 0},
		Credentials: []CredentialConfig{
			{
				Host:     "*.neon.tech",
				Postgres: &PostgresCredentialConfig{Resolver: "bogus"},
				Source:   SourceConfig{Type: "static", Value: "pw"},
			},
		},
	}

	_, err := New(context.Background(), cfg, "")
	if err == nil {
		t.Fatal("expected error for unknown postgres resolver")
	}
	if !strings.Contains(err.Error(), "unknown resolver") {
		t.Errorf("error = %q, want mention of 'unknown resolver'", err)
	}
}

// ── multiHandler (slog fan-out) ───────────────────────────────────────────────

// TestMultiHandler_WithAttrs verifies that WithAttrs propagates to all child
// handlers, exercising the previously uncovered branch.
func TestMultiHandler_WithAttrs(t *testing.T) {
	h1 := slog.NewTextHandler(io.Discard, nil)
	h2 := slog.NewTextHandler(io.Discard, nil)
	mh := newMultiHandler(h1, h2)

	derived := mh.WithAttrs([]slog.Attr{slog.String("k", "v")})
	if derived == nil {
		t.Fatal("WithAttrs returned nil")
	}
	// Derived handler should still respond to Enabled.
	if !derived.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("derived handler Enabled(Info) = false, want true")
	}
}

// TestMultiHandler_WithGroup verifies that WithGroup propagates to all child
// handlers.
func TestMultiHandler_WithGroup(t *testing.T) {
	h1 := slog.NewTextHandler(io.Discard, nil)
	mh := newMultiHandler(h1)

	derived := mh.WithGroup("mygroup")
	if derived == nil {
		t.Fatal("WithGroup returned nil")
	}
	if !derived.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("derived handler Enabled(Info) = false, want true")
	}
}

// fakeSlogHandler is a minimal slog.Handler that records every record it
// receives, for observing what actually reaches a handler in tests.
type fakeSlogHandler struct {
	records []slog.Record
}

func (f *fakeSlogHandler) Enabled(context.Context, slog.Level) bool { return true }

func (f *fakeSlogHandler) Handle(_ context.Context, r slog.Record) error {
	f.records = append(f.records, r)
	return nil
}

func (f *fakeSlogHandler) WithAttrs([]slog.Attr) slog.Handler { return f }
func (f *fakeSlogHandler) WithGroup(string) slog.Handler      { return f }

// TestOTelDiagnosticFilter_KeepsBridgeOutOfLoop encodes the fix for #48:
// gatekeeper's own OTel diagnostics (logOTelError's DEBUG record on a
// failed export) must never reach the otelslog bridge handler, or the
// diagnostic itself gets enqueued into the same failing OTel log-export
// pipeline — producing another diagnostic on the next failed attempt, and
// so on indefinitely while a collector is unreachable. The console handler
// must still see every record, marked or not.
func TestOTelDiagnosticFilter_KeepsBridgeOutOfLoop(t *testing.T) {
	var console, bridge fakeSlogHandler
	handler := newMultiHandler(&console, newOTelDiagnosticFilter(&bridge))
	logger := slog.New(handler)

	logger.Debug("otel error", "error", "dial tcp [::1]:4318: connect: connection refused", OTelDiagnosticKey, true)
	logger.Info("normal request", "host", "example.com")

	if got := len(console.records); got != 2 {
		t.Fatalf("console handler received %d records, want 2 (both records)", got)
	}
	if got := len(bridge.records); got != 1 {
		t.Fatalf("bridge handler received %d records, want 1 (the marked diagnostic must be filtered out)", got)
	}
	if got := bridge.records[0].Message; got != "normal request" {
		t.Errorf("bridge handler's surviving record = %q, want %q (the unmarked one)", got, "normal request")
	}
}

func TestHTTPSTokenExchangeOutrankedByStatic(t *testing.T) {
	// End-to-end wiring check for outranked resolvers: a token-exchange
	// credential under a wildcard host is outranked by a static credential
	// for the exact host. The resolver must not run (no STS round trip),
	// the static credential must be injected, and the subject header must
	// still be stripped before the request leaves the proxy — the wiring
	// declares it via SetCredentialResolverWithStripHeaders.

	caDir := t.TempDir()
	ca, err := proxy.NewCA(caDir)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	var stsCalls atomic.Int32
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stsCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "exchanged-token",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type":        "Bearer",
			"expires_in":        3600,
		})
	}))
	defer sts.Close()

	var (
		backendAuth          string
		backendSubjectHeader string
		backendMu            sync.Mutex
	)
	_, backendPort, caCertPool := startTLSBackend(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendMu.Lock()
		backendAuth = r.Header.Get("Authorization")
		backendSubjectHeader = r.Header.Get("X-Gatekeeper-Subject")
		backendMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))

	t.Setenv("TEST_TE_CLIENT_SECRET", "gk-secret")

	cfg := &Config{
		Proxy: ProxyConfig{Port: 0, Host: "127.0.0.1"},
		TLS: TLSConfig{
			CACert: filepath.Join(caDir, "ca.crt"),
			CAKey:  filepath.Join(caDir, "ca.key"),
		},
		Credentials: []CredentialConfig{
			{
				// Wildcard suffix that matches 127.0.0.1.
				Host:   "*.0.0.1",
				Grant:  "github",
				Prefix: "Bearer",
				Source: SourceConfig{
					Type:            "token-exchange",
					Endpoint:        sts.URL,
					ClientID:        "gk-client",
					ClientSecretEnv: "TEST_TE_CLIENT_SECRET",
					SubjectHeader:   "X-Gatekeeper-Subject",
				},
			},
			{
				Host:  "127.0.0.1",
				Grant: "static-grant",
				Source: SourceConfig{
					Type:  "static",
					Value: "Bearer static-token",
				},
			},
		},
		Network: NetworkConfig{Policy: "permissive"},
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.proxy.SetUpstreamCAs(caCertPool)

	ctx := t.Context()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	proxyURL, _ := url.Parse("http://" + srv.ProxyAddr())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12},
		},
	}

	req, err := http.NewRequest(http.MethodGet, "https://127.0.0.1:"+backendPort+"/user", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Gatekeeper-Subject", "usr_alice")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	if n := stsCalls.Load(); n != 0 {
		t.Errorf("STS was called %d times, want 0 (outranked resolver must not run)", n)
	}

	backendMu.Lock()
	defer backendMu.Unlock()
	if backendAuth != "Bearer static-token" {
		t.Errorf("backend Authorization = %q, want %q (exact static must win)", backendAuth, "Bearer static-token")
	}
	if backendSubjectHeader != "" {
		t.Errorf("backend received X-Gatekeeper-Subject = %q, want stripped (declared strip headers must apply when the resolver is skipped)", backendSubjectHeader)
	}
}
