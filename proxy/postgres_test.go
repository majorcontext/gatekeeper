package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/majorcontext/gatekeeper/credentialsource"
)

// Compile-time check that the Neon resolver satisfies the proxy-side interface.
var _ PostgresCredentialResolver = (*credentialsource.NeonResolver)(nil)

func TestPostgresResolverLookup(t *testing.T) {
	p := NewProxy()
	neon := NewStaticPostgresResolver("neon-pass")
	other := NewStaticPostgresResolver("other-pass")
	p.SetPostgresResolver("*.neon.tech", neon)
	p.SetPostgresResolver("db.internal", other)

	tests := []struct {
		host string
		want PostgresCredentialResolver
	}{
		{"ep-foo-123.us-east-2.aws.neon.tech", neon},
		{"ep-foo.aws.neon.tech:5432", neon}, // host:port input — port is stripped before matching
		{"db.internal", other},
		{"example.com", nil},
	}
	for _, tt := range tests {
		got := p.postgresResolverForHost(nil, tt.host)
		if got != tt.want {
			t.Errorf("postgresResolverForHost(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestPostgresResolverRunContextOverridesProxy(t *testing.T) {
	p := NewProxy()
	proxyLevel := NewStaticPostgresResolver("proxy-pass")
	runLevel := NewStaticPostgresResolver("run-pass")
	p.SetPostgresResolver("*.neon.tech", proxyLevel)

	rc := &RunContextData{
		PostgresResolvers: []PostgresResolverEntry{{Pattern: "*.neon.tech", Resolver: runLevel}},
	}
	if got := p.postgresResolverForHost(rc, "ep-foo.aws.neon.tech"); got != runLevel {
		t.Errorf("run context resolver not preferred: got %v", got)
	}
	if got := p.postgresResolverForHost(rc, "db.other.com"); got != nil {
		t.Errorf("expected nil for unmatched host with run context, got %v", got)
	}
}

func TestPostgresResolverRunContextWithoutResolversBlocksProxyLevel(t *testing.T) {
	p := NewProxy()
	p.SetPostgresResolver("*.neon.tech", NewStaticPostgresResolver("proxy-pass"))

	// A run context with no Postgres resolvers means the run was granted no
	// Postgres access — it must not inherit proxy-level resolvers.
	for _, rc := range []*RunContextData{
		{},
		{PostgresResolvers: []PostgresResolverEntry{}},
	} {
		if got := p.postgresResolverForHost(rc, "ep-foo.aws.neon.tech"); got != nil {
			t.Errorf("run context without resolvers fell back to proxy-level resolver: got %v", got)
		}
	}
}

func TestStaticPostgresResolver(t *testing.T) {
	r := NewStaticPostgresResolver("pw")
	got, err := r.ResolvePassword(context.Background(), "any.host", "u", "d")
	if err != nil || got != "pw" {
		t.Fatalf("ResolvePassword = %q, %v; want \"pw\", nil", got, err)
	}
	r.InvalidatePassword("any.host", "u", "d") // must not panic
}

func TestConnectPostgresUpstreamSCRAM(t *testing.T) {
	fake := startFakePostgres(t, "ep-foo-123.aws.neon.tech", "app_rw", "real-password")
	up, err := connectPostgresUpstream(context.Background(), upstreamParams{
		dialAddr:          fake.addr,
		serverName:        "ep-foo-123.aws.neon.tech",
		rootCAs:           fake.certPool,
		user:              "app_rw",
		password:          "real-password",
		startupParameters: map[string]string{"user": "app_rw", "database": "appdb"},
	})
	if err != nil {
		t.Fatalf("connectPostgresUpstream: %v", err)
	}
	defer up.conn.Close()
	if len(up.postAuthFrames) == 0 {
		t.Error("expected buffered post-auth frames")
	}
	// last frame must be ReadyForQuery: type byte 'Z'
	last := up.postAuthFrames[len(up.postAuthFrames)-1]
	if len(last) == 0 || last[0] != 'Z' {
		t.Errorf("last frame type = %q, want 'Z' (ReadyForQuery)", last[0])
	}
	// first frame must be AuthenticationOk: type byte 'R'
	first := up.postAuthFrames[0]
	if len(first) == 0 || first[0] != 'R' {
		t.Errorf("first frame type = %q, want 'R' (AuthenticationOk)", first[0])
	}
}

func TestConnectPostgresUpstreamBadPassword(t *testing.T) {
	fake := startFakePostgres(t, "ep-foo-123.aws.neon.tech", "app_rw", "real-password")
	_, err := connectPostgresUpstream(context.Background(), upstreamParams{
		dialAddr: fake.addr, serverName: "ep-foo-123.aws.neon.tech", rootCAs: fake.certPool,
		user: "app_rw", password: "wrong",
		startupParameters: map[string]string{"user": "app_rw", "database": "appdb"},
	})
	if !errors.Is(err, errUpstreamAuthFailed) {
		t.Fatalf("err = %v, want errUpstreamAuthFailed", err)
	}
}

func TestConnectPostgresUpstreamUnknownUser(t *testing.T) {
	// fake sends 28000 for unknown role — must also map to errUpstreamAuthFailed
	fake := startFakePostgres(t, "ep-foo-123.aws.neon.tech", "app_rw", "real-password")
	_, err := connectPostgresUpstream(context.Background(), upstreamParams{
		dialAddr: fake.addr, serverName: "ep-foo-123.aws.neon.tech", rootCAs: fake.certPool,
		user: "other_user", password: "real-password",
		startupParameters: map[string]string{"user": "other_user", "database": "appdb"},
	})
	if !errors.Is(err, errUpstreamAuthFailed) {
		t.Fatalf("err = %v, want errUpstreamAuthFailed", err)
	}
}

func TestConnectPostgresUpstreamNonAuthError(t *testing.T) {
	// The upstream completes TLS and SCRAM successfully, then reports a
	// non-auth failure (53300 too_many_connections) before AuthenticationOk.
	// Task 8's retry logic only re-resolves credentials for auth failures, so
	// this must NOT be classified as errUpstreamAuthFailed — otherwise the proxy
	// would needlessly invalidate a valid cached password and retry.
	fake := startFakePostgres(t, "ep-foo-123.aws.neon.tech", "app_rw", "real-password",
		withFailPostAuth("53300"))
	_, err := connectPostgresUpstream(context.Background(), upstreamParams{
		dialAddr: fake.addr, serverName: "ep-foo-123.aws.neon.tech", rootCAs: fake.certPool,
		user: "app_rw", password: "real-password",
		startupParameters: map[string]string{"user": "app_rw", "database": "appdb"},
	})
	if err == nil {
		t.Fatal("expected a non-auth upstream error, got nil")
	}
	if errors.Is(err, errUpstreamAuthFailed) {
		t.Fatalf("non-auth upstream error misclassified as auth failure: %v", err)
	}
}

func TestConnectPostgresUpstreamNoSupportedSASLMechanism(t *testing.T) {
	// The upstream advertises only a mechanism the proxy cannot perform. The
	// proxy must return an error rather than panicking or treating the missing
	// mechanism as either success or an auth failure.
	fake := startFakePostgres(t, "ep-foo-123.aws.neon.tech", "app_rw", "real-password",
		withAuthMechanisms("SCRAM-SHA-256-PLUS"))
	_, err := connectPostgresUpstream(context.Background(), upstreamParams{
		dialAddr: fake.addr, serverName: "ep-foo-123.aws.neon.tech", rootCAs: fake.certPool,
		user: "app_rw", password: "real-password",
		startupParameters: map[string]string{"user": "app_rw", "database": "appdb"},
	})
	if err == nil {
		t.Fatal("expected an error when upstream offers no supported SASL mechanism, got nil")
	}
	if errors.Is(err, errUpstreamAuthFailed) {
		t.Fatalf("missing-mechanism error must not be classified as auth failure: %v", err)
	}
}

func TestConnectPostgresUpstreamRejectsUntrustedCert(t *testing.T) {
	fake := startFakePostgres(t, "ep-foo-123.aws.neon.tech", "app_rw", "real-password")
	_, err := connectPostgresUpstream(context.Background(), upstreamParams{
		dialAddr: fake.addr, serverName: "ep-foo-123.aws.neon.tech", rootCAs: x509.NewCertPool(),
		user: "app_rw", password: "real-password",
		startupParameters: map[string]string{"user": "app_rw", "database": "appdb"},
	})
	if err == nil {
		t.Fatal("expected TLS verification failure")
	}
	if errors.Is(err, errUpstreamAuthFailed) {
		t.Fatal("TLS failure must not be classified as auth failure")
	}
}

// caTrustPool builds a client trust pool from a proxy CA.
func caTrustPool(t *testing.T, ca *CA) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("failed to add CA cert to pool")
	}
	return pool
}

// newTestProxyWithCA returns a proxy with a fresh CA installed.
func newTestProxyWithCA(t *testing.T) (*Proxy, *CA) {
	t.Helper()
	ca, err := generateCA()
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	p := NewProxy()
	p.SetCA(ca)
	return p, ca
}

func newTestPostgresListener(t *testing.T, p *Proxy) *PostgresServer {
	t.Helper()
	srv := NewPostgresServer(p)
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Stop)
	return srv
}

// newTestPostgresListenerWithProxyProtocol is newTestPostgresListener but
// wraps the listener with WrapProxyProtocolListener first, mirroring how
// gatekeeper.go wires postgres.proxy_protocol: true in production (bind,
// wrap, then StartListener on the wrapped listener).
func newTestPostgresListenerWithProxyProtocol(t *testing.T, p *Proxy) *PostgresServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln = WrapProxyProtocolListener(ln)
	srv := NewPostgresServer(p)
	if err := srv.StartListener(ln); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Stop)
	return srv
}

// pgClientHandshake dials the listener, does SSLRequest+TLS, sends the startup
// message, and answers AuthenticationCleartextPassword with password. It returns
// the message received after sending the password (the auth result or an error)
// and the TLS conn so the caller can Close it. caPool trusts the proxy CA.
func pgClientHandshake(t *testing.T, addr, sniHost string, caPool *x509.CertPool, user, db, password string) (pgproto3.BackendMessage, net.Conn) {
	t.Helper()

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return pgClientHandshakeOnConn(t, raw, sniHost, caPool, user, db, password)
}

// pgClientHandshakeOnConn is pgClientHandshake but driven over an
// already-established raw connection, letting a caller write bytes ahead of
// the Postgres wire protocol — e.g. a PROXY protocol header — before the
// handshake begins.
func pgClientHandshakeOnConn(t *testing.T, raw net.Conn, sniHost string, caPool *x509.CertPool, user, db, password string) (pgproto3.BackendMessage, net.Conn) {
	t.Helper()

	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))

	// SSLRequest preamble.
	fe := pgproto3.NewFrontend(raw, raw)
	fe.Send(&pgproto3.SSLRequest{})
	if err := fe.Flush(); err != nil {
		raw.Close()
		t.Fatalf("send SSLRequest: %v", err)
	}
	var resp [1]byte
	if _, err := raw.Read(resp[:]); err != nil {
		raw.Close()
		t.Fatalf("read SSLRequest response: %v", err)
	}
	if resp[0] != 'S' {
		raw.Close()
		t.Fatalf("server refused TLS, got %q want 'S'", resp[0])
	}

	tlsConn := tls.Client(raw, &tls.Config{ServerName: sniHost, RootCAs: caPool})
	if err := tlsConn.Handshake(); err != nil {
		raw.Close()
		t.Fatalf("TLS handshake: %v", err)
	}
	_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))

	params := map[string]string{"user": user}
	if db != "" {
		params["database"] = db
	}
	fe = pgproto3.NewFrontend(tlsConn, tlsConn)
	fe.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      params,
	})
	if err := fe.Flush(); err != nil {
		tlsConn.Close()
		t.Fatalf("send startup: %v", err)
	}

	msg, err := fe.Receive()
	if err != nil {
		tlsConn.Close()
		t.Fatalf("receive auth request: %v", err)
	}
	if _, ok := msg.(*pgproto3.AuthenticationCleartextPassword); !ok {
		tlsConn.Close()
		t.Fatalf("expected AuthenticationCleartextPassword, got %T", msg)
	}

	fe.Send(&pgproto3.PasswordMessage{Password: password})
	if err := fe.Flush(); err != nil {
		tlsConn.Close()
		t.Fatalf("send password: %v", err)
	}

	msg, err = fe.Receive()
	if err != nil {
		tlsConn.Close()
		t.Fatalf("receive auth result: %v", err)
	}
	return msg, tlsConn
}

func TestPostgresListenerRequiresCA(t *testing.T) {
	srv := NewPostgresServer(NewProxy())
	err := srv.Start("127.0.0.1:0")
	if err == nil {
		srv.Stop()
		t.Fatal("Start without CA succeeded, want error")
	}
	if !strings.Contains(err.Error(), "CA") {
		t.Errorf("error = %q, want it to mention CA", err)
	}
}

func TestPostgresListenerRejectsPlaintext(t *testing.T) {
	p, _ := newTestProxyWithCA(t)
	srv := newTestPostgresListener(t, p)

	raw, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))

	// Send a StartupMessage directly, with no SSLRequest preamble.
	fe := pgproto3.NewFrontend(raw, raw)
	fe.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": "app"},
	})
	if err := fe.Flush(); err != nil {
		t.Fatalf("send startup: %v", err)
	}

	// The server must NOT proceed to auth. It either sends an ErrorResponse
	// (28000) or closes the connection — but never AuthenticationCleartextPassword.
	msg, err := fe.Receive()
	if err != nil {
		// Connection closed without any auth challenge: acceptable.
		return
	}
	switch m := msg.(type) {
	case *pgproto3.ErrorResponse:
		if m.Code != "28000" {
			t.Errorf("ErrorResponse code = %q, want 28000", m.Code)
		}
	case *pgproto3.AuthenticationCleartextPassword:
		t.Fatal("server sent AuthenticationCleartextPassword to a plaintext client")
	default:
		t.Fatalf("unexpected message %T", msg)
	}
}

func TestPostgresListenerRejectsBadToken(t *testing.T) {
	p, ca := newTestProxyWithCA(t)
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "good-token" {
			return &RunContextData{}, true
		}
		return nil, false
	})
	srv := newTestPostgresListener(t, p)

	msg, conn := pgClientHandshake(t, srv.Addr(), "db.test.local", caTrustPool(t, ca), "app", "appdb", "bad-token")
	defer conn.Close()

	errResp, ok := msg.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", msg)
	}
	if errResp.Code != "28P01" {
		t.Errorf("ErrorResponse code = %q, want 28P01", errResp.Code)
	}
}

func TestPostgresListenerAcceptsGoodTokenButNoResolver(t *testing.T) {
	p, ca := newTestProxyWithCA(t)
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "good-token" {
			return &RunContextData{}, true
		}
		return nil, false
	})
	srv := newTestPostgresListener(t, p)

	msg, conn := pgClientHandshake(t, srv.Addr(), "db.test.local", caTrustPool(t, ca), "app", "appdb", "good-token")
	defer conn.Close()

	// Auth passed; the serveAuthenticated stub reports no resolver for the host.
	errResp, ok := msg.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", msg)
	}
	if errResp.Code != "08004" {
		t.Errorf("ErrorResponse code = %q, want 08004", errResp.Code)
	}
}

// TestPostgresListenerProxyProtocolV1 verifies that when the Postgres
// listener is wrapped with WrapProxyProtocolListener (postgres.proxy_protocol:
// true in gatekeeper.yaml), a leading PROXY protocol v1 header — sent before
// the client's SSLRequest, since the header is always the very first bytes on
// the wire — is honored: the logged ClientAddr reflects the header's
// advertised source address, not the raw TCP loopback peer address the test
// actually dialed from.
func TestPostgresListenerProxyProtocolV1(t *testing.T) {
	p, ca := newTestProxyWithCA(t)
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "good-token" {
			return &RunContextData{}, true
		}
		return nil, false
	})
	cap := &logCapture{}
	p.SetLogger(cap.log)
	srv := newTestPostgresListenerWithProxyProtocol(t, p)

	raw, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := raw.Write([]byte("PROXY TCP4 100.52.56.181 10.0.0.1 51234 5432\r\n")); err != nil {
		raw.Close()
		t.Fatalf("write PROXY header: %v", err)
	}

	msg, conn := pgClientHandshakeOnConn(t, raw, "db.test.local", caTrustPool(t, ca), "app", "appdb", "good-token")
	defer conn.Close()

	// Auth passed; serveAuthenticated denies for lack of a resolver, but it
	// logs ClientAddr before that — which is all this test needs.
	if _, ok := msg.(*pgproto3.ErrorResponse); !ok {
		t.Fatalf("expected ErrorResponse, got %T", msg)
	}

	var entries []RequestLogData
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		entries = cap.snapshot()
		if len(entries) >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want exactly 1", len(entries))
	}
	host, _, err := net.SplitHostPort(entries[0].ClientAddr)
	if err != nil {
		t.Fatalf("ClientAddr = %q: SplitHostPort: %v", entries[0].ClientAddr, err)
	}
	if host != "100.52.56.181" {
		t.Errorf("ClientAddr host = %q, want 100.52.56.181 (the PROXY-header source), not the raw TCP peer address", host)
	}
}

// TestPostgresListenerProxyProtocolFailSafeNoHeader verifies that a
// connection with no PROXY header still succeeds when the Postgres listener
// is wrapped with WrapProxyProtocolListener: the fail-open USE policy falls
// back to the raw TCP peer address instead of rejecting the connection, so a
// direct probe or an LB health check that never speaks PROXY protocol still
// gets a normal Postgres handshake.
func TestPostgresListenerProxyProtocolFailSafeNoHeader(t *testing.T) {
	p, ca := newTestProxyWithCA(t)
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "good-token" {
			return &RunContextData{}, true
		}
		return nil, false
	})
	cap := &logCapture{}
	p.SetLogger(cap.log)
	srv := newTestPostgresListenerWithProxyProtocol(t, p)

	// No PROXY header written — straight into the Postgres handshake.
	msg, conn := pgClientHandshake(t, srv.Addr(), "db.test.local", caTrustPool(t, ca), "app", "appdb", "good-token")
	defer conn.Close()

	if _, ok := msg.(*pgproto3.ErrorResponse); !ok {
		t.Fatalf("expected ErrorResponse, got %T", msg)
	}

	var entries []RequestLogData
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		entries = cap.snapshot()
		if len(entries) >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want exactly 1", len(entries))
	}
	host, _, err := net.SplitHostPort(entries[0].ClientAddr)
	if err != nil {
		t.Fatalf("ClientAddr = %q: SplitHostPort: %v", entries[0].ClientAddr, err)
	}
	if host != "127.0.0.1" {
		t.Errorf("ClientAddr host = %q, want 127.0.0.1 (fail-open: no PROXY header present)", host)
	}
}

func TestPostgresListenerStaticTokenAuth(t *testing.T) {
	p, ca := newTestProxyWithCA(t)
	p.SetAuthToken("static-token")
	srv := newTestPostgresListener(t, p)
	pool := caTrustPool(t, ca)

	t.Run("correct token", func(t *testing.T) {
		msg, conn := pgClientHandshake(t, srv.Addr(), "db.test.local", pool, "app", "appdb", "static-token")
		defer conn.Close()

		errResp, ok := msg.(*pgproto3.ErrorResponse)
		if !ok {
			t.Fatalf("expected ErrorResponse, got %T", msg)
		}
		if errResp.Code != "08004" {
			t.Errorf("ErrorResponse code = %q, want 08004", errResp.Code)
		}
	})

	t.Run("wrong token", func(t *testing.T) {
		msg, conn := pgClientHandshake(t, srv.Addr(), "db.test.local", pool, "app", "appdb", "wrong-token")
		defer conn.Close()

		errResp, ok := msg.(*pgproto3.ErrorResponse)
		if !ok {
			t.Fatalf("expected ErrorResponse, got %T", msg)
		}
		if errResp.Code != "28P01" {
			t.Errorf("ErrorResponse code = %q, want 28P01", errResp.Code)
		}
	})
}

// errorCountHandler is a slog.Handler that counts records logged at
// slog.LevelError or above. It is safe for concurrent use.
type errorCountHandler struct {
	mu    sync.Mutex
	count int
}

func (h *errorCountHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelError
}

func (h *errorCountHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Level >= slog.LevelError {
		h.mu.Lock()
		h.count++
		h.mu.Unlock()
	}
	return nil
}

func (h *errorCountHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *errorCountHandler) WithGroup(_ string) slog.Handler      { return h }

func (h *errorCountHandler) errorCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.count
}

// TestPostgresListenerStopIsCleanAndSilent verifies that stopping the listener
// is an intentional shutdown: the accept loop must not log an error, Stop must
// be safe to call more than once, and the closed listener must reject further
// connections.
func TestPostgresListenerStopIsCleanAndSilent(t *testing.T) {
	// Capture error-level logs from the accept loop for the duration of the test.
	h := &errorCountHandler{}
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(prev) })

	p, _ := newTestProxyWithCA(t)
	srv := NewPostgresServer(p)
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	addr := srv.Addr()
	if addr == "" {
		t.Fatal("Addr() returned empty string while listening")
	}

	// Clean shutdown: must not log, and must be idempotent.
	srv.Stop()
	srv.Stop() // second call must not panic or double-close.

	// Give the accept loop a moment to observe the closed listener and exit.
	time.Sleep(50 * time.Millisecond)

	if got := h.errorCount(); got != 0 {
		t.Errorf("accept loop logged %d error(s) on clean shutdown; want 0", got)
	}

	// A subsequent connection attempt must fail: the listener is closed.
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("dial to stopped listener succeeded; want failure")
	}
}

// TestPostgresStopNilListenerIsSafe verifies Stop is safe before Start.
func TestPostgresStopNilListenerIsSafe(t *testing.T) {
	srv := NewPostgresServer(NewProxy())
	srv.Stop() // must not panic.
	srv.Stop()
}

// connectThroughGatekeeper drives a real pgx client through the gatekeeper
// Postgres listener: it authenticates with token (the run token, sent as the
// cleartext password) and presents sniHost as the TLS server name.
func connectThroughGatekeeper(t *testing.T, srv *PostgresServer, caPool *x509.CertPool, sniHost, user, db, token string) (*pgconn.PgConn, error) {
	t.Helper()
	cfg, err := pgconn.ParseConfig(fmt.Sprintf("postgres://%s:%s@%s/%s", user, token, srv.Addr(), db))
	if err != nil {
		t.Fatal(err)
	}
	cfg.TLSConfig = &tls.Config{ServerName: sniHost, RootCAs: caPool}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return pgconn.ConnectConfig(ctx, cfg)
}

// logCapture collects RequestLogData entries under a mutex.
type logCapture struct {
	mu      sync.Mutex
	entries []RequestLogData
}

func (c *logCapture) log(data RequestLogData) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, data)
}

func (c *logCapture) snapshot() []RequestLogData {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]RequestLogData, len(c.entries))
	copy(out, c.entries)
	return out
}

func TestPostgresEndToEnd(t *testing.T) {
	fake := startFakePostgres(t, "ep-foo-123.aws.neon.tech", "app_rw", "real-password")

	ca, err := generateCA()
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	p := NewProxy()
	p.SetCA(ca)
	p.SetUpstreamCAs(fake.certPool)
	p.SetAuthToken("run-token")
	p.SetPostgresResolver("*.neon.tech", NewStaticPostgresResolver("real-password"))
	cap := &logCapture{}
	p.SetLogger(cap.log)

	srv := newTestPostgresListener(t, p)
	srv.dialUpstream = func(ctx context.Context, h string) (string, error) {
		if h != "ep-foo-123.aws.neon.tech" {
			t.Errorf("dialUpstream host = %q, want ep-foo-123.aws.neon.tech", h)
		}
		return fake.addr, nil
	}

	conn, err := connectThroughGatekeeper(t, srv, caTrustPool(t, ca),
		"ep-foo-123.aws.neon.tech", "app_rw", "appdb", "run-token")
	if err != nil {
		t.Fatalf("connect through gatekeeper: %v", err)
	}

	res, err := conn.Exec(context.Background(), "SELECT 1").ReadAll()
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if len(res) == 0 {
		t.Fatalf("got %d results, want >= 1", len(res))
	}
	if res[0].Err != nil {
		t.Errorf("result error: %v", res[0].Err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Close(ctx); err != nil {
		t.Errorf("Close: %v", err)
	}

	if got := fake.queriedLast(); got != "SELECT 1" {
		t.Errorf("queriedLast = %q, want %q", got, "SELECT 1")
	}

	// The audit log entry is written after the relay completes (client
	// disconnect). Poll until it appears.
	var entries []RequestLogData
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		entries = cap.snapshot()
		if len(entries) >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want exactly 1", len(entries))
	}
	e := entries[0]
	if e.RequestType != "postgres" {
		t.Errorf("RequestType = %q, want postgres", e.RequestType)
	}
	if e.Host != "ep-foo-123.aws.neon.tech" {
		t.Errorf("Host = %q, want ep-foo-123.aws.neon.tech", e.Host)
	}
	if e.UserID != "app_rw" {
		t.Errorf("UserID = %q, want app_rw", e.UserID)
	}
	if e.Denied {
		t.Errorf("Denied = true, want false")
	}
	if !e.AuthInjected {
		t.Errorf("AuthInjected = false, want true")
	}
	if e.ClientAddr == "" {
		t.Fatal("ClientAddr is empty, want the client's TCP peer address")
	}
	if host, _, err := net.SplitHostPort(e.ClientAddr); err != nil {
		t.Errorf("ClientAddr = %q: SplitHostPort: %v", e.ClientAddr, err)
	} else if host != "127.0.0.1" {
		t.Errorf("ClientAddr host = %q, want 127.0.0.1", host)
	}
}

// flakyResolver returns the next password in a sequence on each
// ResolvePassword call (clamped at the last entry) and records whether
// InvalidatePassword was called.
type flakyResolver struct {
	mu          sync.Mutex
	passwords   []string
	idx         int
	invalidated atomic.Bool
}

func (r *flakyResolver) ResolvePassword(_ context.Context, _, _, _ string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pw := r.passwords[r.idx]
	if r.idx < len(r.passwords)-1 {
		r.idx++
	}
	return pw, nil
}

func (r *flakyResolver) InvalidatePassword(_, _, _ string) {
	r.invalidated.Store(true)
}

func TestPostgresRetriesAfterStalePassword(t *testing.T) {
	fake := startFakePostgres(t, "ep-foo-123.aws.neon.tech", "app_rw", "current-password")

	ca, err := generateCA()
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	p := NewProxy()
	p.SetCA(ca)
	p.SetUpstreamCAs(fake.certPool)
	p.SetAuthToken("run-token")
	flaky := &flakyResolver{passwords: []string{"stale-password", "current-password"}}
	p.SetPostgresResolver("*.neon.tech", flaky)

	srv := newTestPostgresListener(t, p)
	srv.dialUpstream = func(_ context.Context, _ string) (string, error) {
		return fake.addr, nil
	}

	conn, err := connectThroughGatekeeper(t, srv, caTrustPool(t, ca),
		"ep-foo-123.aws.neon.tech", "app_rw", "appdb", "run-token")
	if err != nil {
		t.Fatalf("connect through gatekeeper: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Close(ctx); err != nil {
		t.Errorf("Close: %v", err)
	}

	if !flaky.invalidated.Load() {
		t.Error("expected InvalidatePassword to be called after the stale password failed")
	}
}

// syncBuffer is a concurrency-safe io.Writer for capturing slog output from
// goroutines under test (each Postgres connection is handled on its own
// goroutine).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureSlogText redirects the default slog logger, down to DEBUG, to a
// buffer for the duration of the test and returns it. The previous default
// logger is restored on cleanup.
func captureSlogText(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// waitForLogContaining polls buf until it contains want or two seconds
// elapse (the audit/diagnostic log line is written asynchronously, after the
// client already observes the connection failure), returning the final
// snapshot either way.
func waitForLogContaining(buf *syncBuffer, want string) string {
	deadline := time.Now().Add(2 * time.Second)
	var got string
	for time.Now().Before(deadline) {
		got = buf.String()
		if strings.Contains(got, want) {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
	return got
}

// TestUpstreamErrorResponseAuthFailurePreservesSentinelAndDetail is a
// regression guard for the errUpstreamAuthFailed sentinel: connectWithRetry
// decides whether to invalidate the cached password and retry via
// errors.Is(err, errUpstreamAuthFailed), so any enrichment of the error must
// keep that check working while also carrying the upstream SQLSTATE, instead
// of collapsing it to the bare sentinel with no detail.
func TestUpstreamErrorResponseAuthFailurePreservesSentinelAndDetail(t *testing.T) {
	err := upstreamErrorResponse(&pgproto3.ErrorResponse{
		Severity: "FATAL",
		Code:     "28P01",
		Message:  "password authentication failed for user \"app_rw\"",
	})
	if !errors.Is(err, errUpstreamAuthFailed) {
		t.Fatalf("errors.Is(err, errUpstreamAuthFailed) = false, want true; err = %v", err)
	}
	if !strings.Contains(err.Error(), "28P01") {
		t.Errorf("error text = %q, want it to contain SQLSTATE 28P01", err.Error())
	}
}

// TestPostgresLogsUpstreamErrorResponseDetail drives an upstream rejection
// that is NOT an auth-failure SQLSTATE — the kind of thing an IP-allowlist
// check on the real Neon endpoint would send — and asserts the server-side
// diagnostic log carries the upstream SQLSTATE and message instead of the
// flattened, message-less error the proxy used to log. It also asserts the
// upstream password never reaches the log.
func TestPostgresLogsUpstreamErrorResponseDetail(t *testing.T) {
	buf := captureSlogText(t)

	const rejectMessage = "connection rejected: IP address 203.0.113.5 is not authorized for this endpoint"
	fake := startFakePostgres(t, "ep-foo-123.aws.neon.tech", "app_rw", "real-password",
		withFailPostAuthMessage("08004", rejectMessage))

	ca, err := generateCA()
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	p := NewProxy()
	p.SetCA(ca)
	p.SetUpstreamCAs(fake.certPool)
	p.SetAuthToken("run-token")
	p.SetPostgresResolver("*.neon.tech", NewStaticPostgresResolver("real-password"))

	srv := newTestPostgresListener(t, p)
	srv.dialUpstream = func(_ context.Context, _ string) (string, error) {
		return fake.addr, nil
	}

	conn, err := connectThroughGatekeeper(t, srv, caTrustPool(t, ca),
		"ep-foo-123.aws.neon.tech", "app_rw", "appdb", "run-token")
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn.Close(ctx)
		t.Fatal("connect succeeded, want the simulated upstream rejection to fail it")
	}

	got := waitForLogContaining(buf, "08004")
	if !strings.Contains(got, "08004") {
		t.Fatalf("log output missing upstream SQLSTATE 08004; got:\n%s", got)
	}
	if !strings.Contains(got, rejectMessage) {
		t.Fatalf("log output missing upstream error message %q; got:\n%s", rejectMessage, got)
	}
	if !strings.Contains(got, "upstream_connect") {
		t.Errorf("log output missing stage=upstream_connect marker; got:\n%s", got)
	}
	if strings.Contains(got, "real-password") {
		t.Fatalf("log output leaked the upstream password:\n%s", got)
	}
	if strings.Contains(got, "run-token") {
		t.Fatalf("log output leaked the client run token:\n%s", got)
	}
}

// TestPostgresRunTokenAuthFailureIsLogged drives a client that fails
// run-token authentication and asserts a log line now names the boundary,
// the client address, and the SNI host — that failure used to be completely
// silent server-side. The run token value itself must never appear.
func TestPostgresRunTokenAuthFailureIsLogged(t *testing.T) {
	buf := captureSlogText(t)

	p, ca := newTestProxyWithCA(t)
	p.SetAuthToken("static-token")
	srv := newTestPostgresListener(t, p)

	msg, conn := pgClientHandshake(t, srv.Addr(), "db.test.local", caTrustPool(t, ca), "app", "appdb", "wrong-token")
	defer conn.Close()

	errResp, ok := msg.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", msg)
	}
	if errResp.Code != "28P01" {
		t.Errorf("ErrorResponse code = %q, want 28P01", errResp.Code)
	}

	got := waitForLogContaining(buf, "run_token_auth")
	if !strings.Contains(got, "run_token_auth") {
		t.Fatalf("log output missing stage=run_token_auth marker; got:\n%s", got)
	}
	if !strings.Contains(got, "db.test.local") {
		t.Fatalf("log output missing SNI host db.test.local; got:\n%s", got)
	}
	if !strings.Contains(got, "127.0.0.1") {
		t.Fatalf("log output missing client address; got:\n%s", got)
	}
	if strings.Contains(got, "wrong-token") {
		t.Fatalf("log output leaked the client's run token:\n%s", got)
	}
	if strings.Contains(got, "static-token") {
		t.Fatalf("log output leaked the configured auth token:\n%s", got)
	}
}

// failingResolver always fails to resolve a password, standing in for a Neon
// API resolution failure (missing project, wrong scope, upstream API error).
// It records whether InvalidatePassword was called so a test can assert the
// upstream-auth retry/invalidate path is NOT taken for a resolver failure.
type failingResolver struct {
	err         error
	invalidated atomic.Bool
}

func (r *failingResolver) ResolvePassword(_ context.Context, _, _, _ string) (string, error) {
	return "", r.err
}

func (r *failingResolver) InvalidatePassword(_, _, _ string) {
	r.invalidated.Store(true)
}

// TestPostgresLogsResolveStage drives a credential-resolution failure (the
// resolver's ResolvePassword returns an error) and asserts the diagnostic log
// tags it stage=resolve — distinct from the upstream_connect bucket a real
// dial/TLS/SCRAM failure lands in — so an operator can tell a Neon API
// resolution failure apart from a network/TLS failure to the endpoint. It also
// asserts the resolver failure does NOT trigger the upstream-auth
// invalidate-and-retry path.
func TestPostgresLogsResolveStage(t *testing.T) {
	buf := captureSlogText(t)

	ca, err := generateCA()
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	p := NewProxy()
	p.SetCA(ca)
	p.SetAuthToken("run-token")
	failing := &failingResolver{err: errors.New("neon endpoint \"ep-foo-123\" not found in configured project")}
	p.SetPostgresResolver("*.neon.tech", failing)

	srv := newTestPostgresListener(t, p)

	conn, err := connectThroughGatekeeper(t, srv, caTrustPool(t, ca),
		"ep-foo-123.aws.neon.tech", "app_rw", "appdb", "run-token")
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn.Close(ctx)
		t.Fatal("connect succeeded, want the resolver failure to fail it")
	}

	got := waitForLogContaining(buf, "stage=resolve")
	if !strings.Contains(got, "stage=resolve") {
		t.Fatalf("log output missing stage=resolve marker; got:\n%s", got)
	}
	if !strings.Contains(got, "resolving postgres password") {
		t.Errorf("log output missing human-readable resolver context; got:\n%s", got)
	}
	if strings.Contains(got, "stage=upstream_connect") {
		t.Errorf("resolver failure misclassified as stage=upstream_connect; got:\n%s", got)
	}
	if failing.invalidated.Load() {
		t.Error("resolver failure must not trigger the upstream-auth invalidate-and-retry path")
	}
}

func TestPostgresPolicyDeniesHost(t *testing.T) {
	ca, err := generateCA()
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	p := NewProxy()
	p.SetCA(ca)
	p.SetAuthToken("run-token")
	p.SetNetworkPolicy("strict", []string{"api.github.com"}, nil)
	p.SetPostgresResolver("*.neon.tech", NewStaticPostgresResolver("real-password"))

	srv := newTestPostgresListener(t, p)

	conn, err := connectThroughGatekeeper(t, srv, caTrustPool(t, ca),
		"ep-foo.aws.neon.tech", "app_rw", "appdb", "run-token")
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn.Close(ctx)
		t.Fatal("connect succeeded, want a policy-denial error")
	}
}

// TestPostgresPolicyAllowsPortlessPattern verifies that a portless allow
// pattern -- as shipped in examples/gatekeeper-postgres.yaml
// ("network.policy: strict" + "allow: [\"*.neon.tech\"]") -- permits a
// Postgres data-plane connection. Before the fix, matchHost/matchesPattern's
// HTTP-centric default (an unspecified pattern port matches only 80/443)
// applied here too, so the connection was denied even though
// postgresResolverForHost (via postgresResolverFromEntries, postgres.go)
// already defaults an unspecified pattern port to 5432 when matching
// resolvers -- the same connection was accepted by the resolver but rejected
// by network policy.
func TestPostgresPolicyAllowsPortlessPattern(t *testing.T) {
	fake := startFakePostgres(t, "ep-foo.aws.neon.tech", "app_rw", "real-password")

	ca, err := generateCA()
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	p := NewProxy()
	p.SetCA(ca)
	p.SetUpstreamCAs(fake.certPool)
	p.SetAuthToken("run-token")
	p.SetNetworkPolicy("strict", []string{"*.neon.tech"}, nil)
	p.SetPostgresResolver("*.neon.tech", NewStaticPostgresResolver("real-password"))

	srv := newTestPostgresListener(t, p)
	srv.dialUpstream = func(ctx context.Context, h string) (string, error) {
		return fake.addr, nil
	}

	conn, err := connectThroughGatekeeper(t, srv, caTrustPool(t, ca),
		"ep-foo.aws.neon.tech", "app_rw", "appdb", "run-token")
	if err != nil {
		t.Fatalf("connect through gatekeeper: %v -- want strict policy with portless allow pattern %q to allow a Postgres connection to %q", err, "*.neon.tech", "ep-foo.aws.neon.tech")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Close(ctx); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestPostgresPolicyDeniesUnlistedHostUnderPortlessPattern proves the fix for
// TestPostgresPolicyAllowsPortlessPattern doesn't widen the allow surface: a
// host that doesn't match the portless pattern is still denied.
func TestPostgresPolicyDeniesUnlistedHostUnderPortlessPattern(t *testing.T) {
	ca, err := generateCA()
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	p := NewProxy()
	p.SetCA(ca)
	p.SetAuthToken("run-token")
	p.SetNetworkPolicy("strict", []string{"*.neon.tech"}, nil)
	p.SetPostgresResolver("*.neon.tech", NewStaticPostgresResolver("real-password"))

	srv := newTestPostgresListener(t, p)

	conn, err := connectThroughGatekeeper(t, srv, caTrustPool(t, ca),
		"evil.com", "app_rw", "appdb", "run-token")
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn.Close(ctx)
		t.Fatal("connect succeeded, want evil.com denied under strict policy with allow *.neon.tech")
	}
}

// TestPostgresPolicyExplicitWrongPortDenied proves the fix doesn't relax
// explicit-port patterns: a pattern pinned to a port other than 5432 must
// still deny a Postgres connection (which is always evaluated at 5432).
func TestPostgresPolicyExplicitWrongPortDenied(t *testing.T) {
	ca, err := generateCA()
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	p := NewProxy()
	p.SetCA(ca)
	p.SetAuthToken("run-token")
	p.SetNetworkPolicy("strict", []string{"*.neon.tech:5433"}, nil)
	p.SetPostgresResolver("*.neon.tech", NewStaticPostgresResolver("real-password"))

	srv := newTestPostgresListener(t, p)

	conn, err := connectThroughGatekeeper(t, srv, caTrustPool(t, ca),
		"ep-foo.aws.neon.tech", "app_rw", "appdb", "run-token")
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn.Close(ctx)
		t.Fatal("connect succeeded, want denial: allow pattern is pinned to port 5433, connection is on 5432")
	}
}

// TestPostgresPolicyExplicitCorrectPortAllowed proves an explicit ":5432"
// pattern keeps working exactly as before the fix.
func TestPostgresPolicyExplicitCorrectPortAllowed(t *testing.T) {
	fake := startFakePostgres(t, "ep-foo.aws.neon.tech", "app_rw", "real-password")

	ca, err := generateCA()
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}
	p := NewProxy()
	p.SetCA(ca)
	p.SetUpstreamCAs(fake.certPool)
	p.SetAuthToken("run-token")
	p.SetNetworkPolicy("strict", []string{"*.neon.tech:5432"}, nil)
	p.SetPostgresResolver("*.neon.tech", NewStaticPostgresResolver("real-password"))

	srv := newTestPostgresListener(t, p)
	srv.dialUpstream = func(ctx context.Context, h string) (string, error) {
		return fake.addr, nil
	}

	conn, err := connectThroughGatekeeper(t, srv, caTrustPool(t, ca),
		"ep-foo.aws.neon.tech", "app_rw", "appdb", "run-token")
	if err != nil {
		t.Fatalf("connect through gatekeeper: %v -- want explicit *.neon.tech:5432 pattern to allow a connection on port 5432", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Close(ctx); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestCheckNetworkPolicyHTTPPortDefaultsUnchanged proves the fix for Postgres
// data-plane matching does not touch checkNetworkPolicy, the function the
// HTTP/CONNECT path shares with the Postgres plane's fallback (no run
// context) case. A portless allow pattern must still mean "matches only 80
// and 443" here -- it must not also match the Postgres port.
func TestCheckNetworkPolicyHTTPPortDefaultsUnchanged(t *testing.T) {
	p := NewProxy()
	p.SetNetworkPolicy("strict", []string{"api.github.com"}, nil)

	if !p.checkNetworkPolicy("api.github.com", 443) {
		t.Error(`checkNetworkPolicy("api.github.com", 443) = false, want true (HTTPS default port)`)
	}
	if !p.checkNetworkPolicy("api.github.com", 80) {
		t.Error(`checkNetworkPolicy("api.github.com", 80) = false, want true (HTTP default port)`)
	}
	if p.checkNetworkPolicy("api.github.com", postgresDefaultPort) {
		t.Error(`checkNetworkPolicy("api.github.com", 5432) = true, want false -- a portless HTTP allow pattern must not match the Postgres port`)
	}
}

// --- accept-loop resilience to transient Accept errors ---------------------
//
// These are the sibling of TestDemux_AcceptLoopRetriesTransientErrors and
// TestDemux_AcceptLoopExitsCleanlyOnClose in demux_test.go: PostgresServer's
// own acceptLoop had the identical unconditional-exit-on-any-Accept-error bug
// that PR #56 fixed in Demux.acceptLoop, and was intentionally left out of
// that PR's scope. scriptedAcceptListener (defined in demux_test.go, same
// package) is reused here rather than duplicated.

// TestPostgresServer_AcceptLoopRetriesTransientErrors is the regression guard
// for PostgresServer.acceptLoop: a transient Accept error (EMFILE/ENFILE
// under fd exhaustion, ECONNABORTED -- realistic for a proxy holding many
// long-lived Postgres relay connections) must not permanently kill the
// data-plane listener. The loop must back off and retry -- mirroring
// net/http.Server.Serve and Demux.acceptLoop -- so a good connection
// arriving after a burst of transient errors is still dispatched.
func TestPostgresServer_AcceptLoopRetriesTransientErrors(t *testing.T) {
	p, _ := newTestProxyWithCA(t)
	srv := NewPostgresServer(p)

	// Three transient failures, then a real conn.
	transient := errors.New("simulated EMFILE: too many open files")
	l := newScriptedAcceptListener(3, transient)

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	l.conns <- serverConn

	if err := srv.StartListener(l); err != nil {
		t.Fatalf("StartListener: %v", err)
	}
	t.Cleanup(srv.Stop)

	// If the loop had exited after the first transient error (the bug), the
	// good conn is never Accepted from the scripted listener and handleConn
	// never runs on it, so nothing ever answers the SSLRequest below and this
	// read times out. The 2s bound is far above the ~35ms the three
	// 5ms/10ms/20ms backoffs take.
	fe := pgproto3.NewFrontend(clientConn, clientConn)
	go func() {
		fe.Send(&pgproto3.SSLRequest{})
		_ = fe.Flush()
	}()

	_ = clientConn.SetDeadline(time.Now().Add(2 * time.Second))
	var resp [1]byte
	if _, err := clientConn.Read(resp[:]); err != nil {
		t.Fatalf("read SSLRequest response (proves the post-burst conn reached handleConn): %v", err)
	}
	if resp[0] != 'S' {
		t.Errorf("SSLRequest response = %q, want 'S'", resp[0])
	}
}

// TestPostgresServer_AcceptLoopExitsCleanlyOnStop guards the other half of
// the fix: the retry path must not swallow shutdown. When Stop calls
// beginClose, which sets closed before closing the listener, the resulting
// Accept error is gatekeeper's own doing -- the loop must return immediately
// without logging and without spin-retrying the closed-listener error.
func TestPostgresServer_AcceptLoopExitsCleanlyOnStop(t *testing.T) {
	logBuf := captureSlogText(t)
	p, _ := newTestProxyWithCA(t)
	srv := NewPostgresServer(p)

	l := newScriptedAcceptListener(0, nil)
	if err := srv.StartListener(l); err != nil {
		t.Fatalf("StartListener: %v", err)
	}

	// Let the accept loop reach its blocking Accept before shutting down.
	time.Sleep(20 * time.Millisecond)

	srv.Stop()

	// Give the loop time to observe the close and return. A correct loop
	// calls Accept exactly once more (getting net.ErrClosed), sees closed,
	// and returns; a loop that treated the closed-listener error as
	// transient would keep calling Accept on a ~5ms backoff, so the
	// post-close count would climb past 1 within this window.
	time.Sleep(80 * time.Millisecond)

	if got := l.acceptsAfterCloseCount(); got != 1 {
		t.Errorf("Accept called %d times after close, want exactly 1: >1 means the loop spin-retried the closed-listener error instead of exiting on shutdown", got)
	}
	if s := logBuf.String(); strings.Contains(s, "transient accept error") || strings.Contains(s, "accept loop exited") {
		t.Errorf("clean shutdown logged an accept error/retry line, want none: %q", s)
	}
}
