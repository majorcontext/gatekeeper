package gatekeeper

// gatekeeper_multiplex_test.go tests single-port multiplexing at the
// Server/Config level: when proxy.port and postgres.port coincide (and
// their hosts and proxy_protocol settings agree), gatekeeper.Server wires
// both planes onto one shared listener (see resolveListenTopology in
// config.go and proxy.Demux in the proxy package) instead of binding two.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/majorcontext/gatekeeper/proxy"

	"github.com/jackc/pgx/v5/pgproto3"
)

// freeTCPPort returns a currently-unused TCP port on 127.0.0.1 by binding
// briefly and releasing it, so a caller can configure the SAME port number
// for two independent listeners (proxy.port == postgres.port) before either
// is bound. There is an inherent, very small TOCTOU race between releasing
// the port here and the caller binding it; this is the same technique
// TestServerPostgresStartFailureCleansUpHTTP already uses to occupy a port
// deliberately.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return port
}

// syncLogBuffer is a concurrency-safe io.Writer for capturing slog output.
type syncLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureDefaultSlog redirects the global slog default logger to a buffer
// for the duration of the test, restoring the previous default on cleanup.
// gatekeeper.Server's startup log lines (e.g. "gatekeeper listening",
// "proxy and postgres multiplexed on one listener") go through the package
// default logger, not a per-server logger, so this is the only way to
// observe them in a test.
func captureDefaultSlog(t *testing.T) *syncLogBuffer {
	t.Helper()
	buf := &syncLogBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// newMultiplexTestConfig builds a Config with proxy.port == postgres.port
// (the multiplex trigger) pointing at a fresh CA on disk, ready for
// New/Start. It returns the *proxy.CA too, so a caller can mint a backend
// certificate with it via startTLSBackend, the same pattern
// TestServerProxyProtocol_ConnectIntercepted uses.
func newMultiplexTestConfig(t *testing.T, port int, proxyProtocol bool) (*Config, *proxy.CA) {
	t.Helper()
	caDir := t.TempDir()
	ca, err := proxy.NewCA(caDir)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	cfg := &Config{
		Proxy: ProxyConfig{Port: port, Host: "127.0.0.1", ProxyProtocol: proxyProtocol},
		TLS: TLSConfig{
			CACert: filepath.Join(caDir, "ca.crt"),
			CAKey:  filepath.Join(caDir, "ca.key"),
		},
		Postgres: &PostgresConfig{
			Port:          port,
			ProxyProtocol: proxyProtocol,
		},
	}
	return cfg, ca
}

// TestServerMultiplexesOnSharedPort is the core scenario this feature
// exists for at the Server/Config level: with proxy.port == postgres.port,
// gatekeeper.Server serves both a real HTTP CONNECT request (with TLS
// interception and credential injection) and a real Postgres wire-protocol
// handshake on the SAME address, and logs the multiplex startup line
// instead of the plain "gatekeeper listening" line.
func TestServerMultiplexesOnSharedPort(t *testing.T) {
	port := freeTCPPort(t)
	cfg, ca := newMultiplexTestConfig(t, port, false)

	var backendAuth string
	var backendMu sync.Mutex
	_, backendPort, caCertPool := startTLSBackend(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendMu.Lock()
		backendAuth = r.Header.Get("Authorization")
		backendMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))

	cfg.Credentials = []CredentialConfig{
		{
			Host:   "127.0.0.1",
			Header: "Authorization",
			Source: SourceConfig{Type: "static", Value: "shared-port-token"},
		},
	}
	cfg.Network = NetworkConfig{Policy: "permissive"}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.proxy.SetUpstreamCAs(caCertPool)

	// New already installed its own slog default (via configureLogging); only
	// capture starting now so we observe Start's own log lines, not New's.
	logBuf := captureDefaultSlog(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	proxyAddr := srv.ProxyAddr()
	pgAddr := srv.PostgresAddr()
	if proxyAddr == "" || pgAddr == "" {
		t.Fatalf("ProxyAddr() = %q, PostgresAddr() = %q, want both non-empty", proxyAddr, pgAddr)
	}
	if proxyAddr != pgAddr {
		t.Fatalf("ProxyAddr() = %q, PostgresAddr() = %q, want equal — they share one listener", proxyAddr, pgAddr)
	}

	log := logBuf.String()
	if !strings.Contains(log, "proxy and postgres multiplexed on one listener") {
		t.Errorf("startup log = %q, want it to contain the multiplex log line", log)
	}
	if strings.Contains(log, "gatekeeper listening\"") {
		t.Errorf("startup log = %q, want the plain two-listener \"gatekeeper listening\" line NOT to appear when multiplexed", log)
	}

	// --- HTTP CONNECT + TLS interception + credential injection ---
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12},
		},
	}
	resp, err := client.Get("https://127.0.0.1:" + backendPort + "/data")
	if err != nil {
		t.Fatalf("GET through shared listener: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	backendMu.Lock()
	gotAuth := backendAuth
	backendMu.Unlock()
	if gotAuth != "Bearer shared-port-token" {
		t.Errorf("backend Authorization = %q, want %q", gotAuth, "Bearer shared-port-token")
	}

	// --- Postgres wire protocol on the SAME address ---
	conn, err := net.DialTimeout("tcp", pgAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial postgres on shared listener: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	fe := pgproto3.NewFrontend(conn, conn)
	fe.Send(&pgproto3.SSLRequest{})
	if err := fe.Flush(); err != nil {
		t.Fatalf("send SSLRequest: %v", err)
	}
	sslResp := make([]byte, 1)
	if _, err := io.ReadFull(conn, sslResp); err != nil {
		t.Fatalf("read SSLRequest response: %v", err)
	}
	if sslResp[0] != 'S' {
		t.Fatalf("SSLRequest response = %q, want 'S' (proving the shared listener speaks Postgres, not just HTTP)", sslResp[0])
	}
}

// TestServerMultiplexed_ProxyProtocolAdvertisedAddr verifies the PROXY
// protocol interaction on a shared listener: one shared listener has one
// PROXY protocol setting (proxy.proxy_protocol, required equal to
// postgres.proxy_protocol by resolveListenTopology), and a PROXY v1 header
// sent ahead of either plane's traffic surfaces the advertised client
// address — not the raw loopback test-dialer address — in that plane's
// canonical log line. This combines TestServerProxyProtocol_ConnectIntercepted
// and TestServerPostgresProxyProtocol onto the one shared address.
func TestServerMultiplexed_ProxyProtocolAdvertisedAddr(t *testing.T) {
	port := freeTCPPort(t)
	cfg, ca := newMultiplexTestConfig(t, port, true)

	_, backendPort, caCertPool := startTLSBackend(t, ca, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	cfg.Network = NetworkConfig{Policy: "permissive"}
	cfg.Credentials = []CredentialConfig{
		{
			Host:     "*.neon.tech",
			Postgres: &PostgresCredentialConfig{Resolver: "static"},
			Source:   SourceConfig{Type: "static", Value: "pw"},
		},
	}

	srv, err := New(context.Background(), cfg, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.proxy.SetUpstreamCAs(caCertPool)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Start(ctx) }()
	waitForProxy(t, srv, 2*time.Second)

	addr := srv.ProxyAddr()
	if addr != srv.PostgresAddr() {
		t.Fatalf("ProxyAddr() = %q, PostgresAddr() = %q, want equal", addr, srv.PostgresAddr())
	}

	proxyHeader := "PROXY TCP4 100.52.56.181 10.0.0.1 51234 443\r\n"

	t.Run("http", func(t *testing.T) {
		waitLog := captureServerLog(t, srv)

		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte(proxyHeader)); err != nil {
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

		tlsConn := tls.Client(conn, &tls.Config{RootCAs: caCertPool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
		if err := tlsConn.Handshake(); err != nil {
			t.Fatalf("TLS handshake: %v", err)
		}
		defer tlsConn.Close()

		fmt.Fprintf(tlsConn, "GET /inner HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", backendAddr)
		innerResp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
		if err != nil {
			t.Fatalf("read inner response: %v", err)
		}
		io.Copy(io.Discard, innerResp.Body)
		innerResp.Body.Close()

		logged := waitLog()
		host, _, err := net.SplitHostPort(logged.ClientAddr)
		if err != nil {
			t.Fatalf("ClientAddr = %q: SplitHostPort: %v", logged.ClientAddr, err)
		}
		if host != "100.52.56.181" {
			t.Errorf("ClientAddr host = %q, want 100.52.56.181 (PROXY-header source)", host)
		}
	})

	t.Run("postgres", func(t *testing.T) {
		waitLog := captureServerLog(t, srv)

		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))

		if _, err := conn.Write([]byte(proxyHeader)); err != nil {
			t.Fatalf("write PROXY header: %v", err)
		}

		fe := pgproto3.NewFrontend(conn, conn)
		fe.Send(&pgproto3.SSLRequest{})
		if err := fe.Flush(); err != nil {
			t.Fatalf("send SSLRequest: %v", err)
		}
		sslResp := make([]byte, 1)
		if _, err := io.ReadFull(conn, sslResp); err != nil {
			t.Fatalf("read SSLRequest response: %v", err)
		}
		if sslResp[0] != 'S' {
			t.Fatalf("SSLRequest response = %q, want 'S'", sslResp[0])
		}

		tlsConn := tls.Client(conn, &tls.Config{ServerName: "db.test.local", RootCAs: caCertPool})
		if err := tlsConn.Handshake(); err != nil {
			t.Fatalf("TLS handshake: %v", err)
		}
		defer tlsConn.Close()

		pfe := pgproto3.NewFrontend(tlsConn, tlsConn)
		pfe.Send(&pgproto3.StartupMessage{
			ProtocolVersion: pgproto3.ProtocolVersionNumber,
			Parameters:      map[string]string{"user": "app", "database": "appdb"},
		})
		if err := pfe.Flush(); err != nil {
			t.Fatalf("send startup: %v", err)
		}
		if _, err := pfe.Receive(); err != nil {
			t.Fatalf("receive auth request: %v", err)
		}
		pfe.Send(&pgproto3.PasswordMessage{Password: "any-token"})
		if err := pfe.Flush(); err != nil {
			t.Fatalf("send password: %v", err)
		}
		if _, err := pfe.Receive(); err != nil {
			t.Fatalf("receive auth result: %v", err)
		}

		logged := waitLog()
		host, _, err := net.SplitHostPort(logged.ClientAddr)
		if err != nil {
			t.Fatalf("ClientAddr = %q: SplitHostPort: %v", logged.ClientAddr, err)
		}
		if host != "100.52.56.181" {
			t.Errorf("ClientAddr host = %q, want 100.52.56.181 (PROXY-header source)", host)
		}
	})
}

// --- config validation, surfaced through New ---

// TestNewRejectsEqualPortsDifferentHosts pins the fatal, ambiguous-bind
// error at the point a real caller would hit it: New, before any listener
// is ever bound.
func TestNewRejectsEqualPortsDifferentHosts(t *testing.T) {
	cfg := &Config{
		Proxy:    ProxyConfig{Port: 5432, Host: "127.0.0.1"},
		TLS:      newTestCAConfig(t),
		Postgres: &PostgresConfig{Port: 5432, Host: "10.0.0.5"},
	}
	_, err := New(context.Background(), cfg, "")
	if err == nil {
		t.Fatal("New succeeded with equal ports but different hosts, want an error")
	}
	if !strings.Contains(err.Error(), "127.0.0.1") || !strings.Contains(err.Error(), "10.0.0.5") {
		t.Errorf("error = %q, want it to name both conflicting hosts", err)
	}
}

// TestNewRejectsMismatchedProxyProtocolOnSharedPort pins the fatal error for
// a shared listener with disagreeing PROXY protocol settings.
func TestNewRejectsMismatchedProxyProtocolOnSharedPort(t *testing.T) {
	cfg := &Config{
		Proxy:    ProxyConfig{Port: 5432, Host: "127.0.0.1", ProxyProtocol: true},
		TLS:      newTestCAConfig(t),
		Postgres: &PostgresConfig{Port: 5432, ProxyProtocol: false},
	}
	_, err := New(context.Background(), cfg, "")
	if err == nil {
		t.Fatal("New succeeded with mismatched proxy_protocol settings on a shared port, want an error")
	}
	if !strings.Contains(err.Error(), "proxy_protocol") {
		t.Errorf("error = %q, want it to mention proxy_protocol", err)
	}
}
