package proxy

import (
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
