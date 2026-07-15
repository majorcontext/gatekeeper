package proxy

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/xdg-go/scram"
)

// postgresHandshakeTimeout bounds the client-facing handshake: SSLRequest, TLS,
// startup, and the cleartext password exchange must complete within this window.
const postgresHandshakeTimeout = 30 * time.Second

// postgresKeepAlivePeriod is the TCP keep-alive probe interval for the relayed
// connection. The relay has no idle or statement timeout — a long-running query
// or an idle session blocks indefinitely on Receive — so keep-alives let each
// side detect a dead peer and reclaim the connection instead of leaking it.
const postgresKeepAlivePeriod = 30 * time.Second

// enableKeepAlive turns on TCP keep-alives for a relayed connection. It is a
// no-op for non-TCP connections (e.g. test pipes).
func enableKeepAlive(conn net.Conn) {
	tc, ok := underlyingTCPConn(conn)
	if !ok {
		return
	}
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(postgresKeepAlivePeriod)
}

// underlyingTCPConn returns the real *net.TCPConn beneath conn, unwrapping one
// layer through a Raw() accessor first. When the listener is wrapped with
// WrapProxyProtocolListener, an accepted conn is not itself a *net.TCPConn —
// it's a proxyProtoLogConn whose Raw() reaches down through the proxyproto.Conn
// to the transport socket. Raw() never touches the PROXY header (unlike
// RemoteAddr()/Read()), so unwrapping here is side-effect free and safe to call
// before any protocol bytes are read. Returns (nil, false) for a non-TCP conn
// (e.g. a test pipe) so keep-alive setup is skipped.
func underlyingTCPConn(conn net.Conn) (*net.TCPConn, bool) {
	if rc, ok := conn.(interface{ Raw() net.Conn }); ok {
		conn = rc.Raw()
	}
	tc, ok := conn.(*net.TCPConn)
	return tc, ok
}

// postgresDefaultPort is the port used when matching Postgres host patterns.
const postgresDefaultPort = 5432

// postgresDialTimeout bounds the TCP dial to the upstream Postgres server.
const postgresDialTimeout = 10 * time.Second

// errUpstreamAuthFailed indicates the upstream Postgres server rejected the
// credentials the proxy presented (bad password or unknown role).
var errUpstreamAuthFailed = errors.New("upstream authentication failed")

// errResolvePassword indicates the credential resolver (e.g. the Neon API)
// failed to produce an upstream password — the proxy never reached the
// upstream server. It is deliberately distinct from errUpstreamAuthFailed so
// the connect path can classify the failure stage in logs and, crucially, so
// a resolution failure never triggers the invalidate-cached-password-and-retry
// path reserved for an actual upstream credential rejection.
var errResolvePassword = errors.New("resolve upstream password failed")

// PostgresCredentialResolver resolves a Postgres password for a specific
// upstream host, role, and database at connection time. Implementations
// must never log password values.
type PostgresCredentialResolver interface {
	// ResolvePassword returns the password the proxy should present to the
	// upstream server for the given host, user, and database.
	ResolvePassword(ctx context.Context, host, user, database string) (string, error)
	// InvalidatePassword drops any cached password for the tuple. The proxy
	// calls it after an upstream authentication failure, then retries once.
	InvalidatePassword(host, user, database string)
}

// PostgresResolverEntry binds a host pattern (hosts.go glob syntax) to a
// resolver. Patterns match hostname only; a pattern with an explicit port
// other than 5432 (e.g. "db.internal:5433") will never match.
type PostgresResolverEntry struct {
	Pattern  string
	Resolver PostgresCredentialResolver
}

// StaticPostgresResolver returns a fixed password for every connection.
type StaticPostgresResolver struct {
	password string
}

// NewStaticPostgresResolver creates a resolver that always returns password.
func NewStaticPostgresResolver(password string) *StaticPostgresResolver {
	return &StaticPostgresResolver{password: password}
}

// ResolvePassword returns the fixed password.
func (s *StaticPostgresResolver) ResolvePassword(ctx context.Context, host, user, database string) (string, error) {
	return s.password, nil
}

// InvalidatePassword is a no-op: static passwords are never cached.
func (s *StaticPostgresResolver) InvalidatePassword(host, user, database string) {}

// SetPostgresResolver registers a proxy-level Postgres credential resolver
// for hosts matching pattern. Calling again with the same pattern replaces
// the previous resolver. Patterns match hostname only; a pattern with an
// explicit port other than 5432 will never match.
func (p *Proxy) SetPostgresResolver(pattern string, r PostgresCredentialResolver) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, entry := range p.postgresResolvers {
		if entry.Pattern == pattern {
			p.postgresResolvers[i].Resolver = r
			return
		}
	}
	p.postgresResolvers = append(p.postgresResolvers, PostgresResolverEntry{Pattern: pattern, Resolver: r})
}

// postgresResolverForHost returns the Postgres credential resolver for host.
// When a run context is present, only its per-run resolvers are consulted —
// proxy-level resolvers are never used as fallback, even when the run has no
// resolvers at all (matching the credential scoping rule in
// getCredentialsForRequest). Matching is on hostname only: any port in host
// is stripped before matching, and patterns match against the Postgres
// default port (5432).
func (p *Proxy) postgresResolverForHost(rc *RunContextData, host string) PostgresCredentialResolver {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if rc != nil {
		return postgresResolverFromEntries(rc.PostgresResolvers, host)
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return postgresResolverFromEntries(p.postgresResolvers, host)
}

// postgresResolverFromEntries returns the resolver of the first entry whose
// pattern matches host, or nil when none match.
func postgresResolverFromEntries(entries []PostgresResolverEntry, host string) PostgresCredentialResolver {
	for _, entry := range entries {
		pattern := parseHostPattern(entry.Pattern)
		// Patterns without an explicit port match the Postgres default port
		// instead of matchesPattern's HTTP defaults (80/443).
		if pattern.port == 0 {
			pattern.port = postgresDefaultPort
		}
		if matchesPattern(pattern, host, postgresDefaultPort) {
			return entry.Resolver
		}
	}
	return nil
}

// matchHostPostgres reports whether host matches any of patterns for
// Postgres data-plane traffic, which is always evaluated at the Postgres
// default port (5432). It applies the same port-default override as
// postgresResolverFromEntries above: a pattern with no explicit port (e.g.
// "*.neon.tech") is treated as pinned to 5432 rather than matchesPattern's
// HTTP-centric default of 80/443. Without this override, matchHost's shared
// HTTP semantics would make a portless allow pattern unmatchable for any
// Postgres connection — exactly the same trap postgresResolverFromEntries
// works around for resolver lookups, and the two matchers must agree: a host
// with a configured resolver but a denying policy (or vice versa) would be
// an internally inconsistent proxy. explicit-port patterns (e.g.
// "*.neon.tech:5433") are untouched, so a pattern pinned to a non-5432 port
// still never matches. This is Postgres-specific: matchHost/matchesPattern
// and their HTTP/CONNECT callers (checkNetworkPolicy,
// checkNetworkPolicyForRequest) are unchanged.
func matchHostPostgres(patterns []hostPattern, host string) bool {
	for _, pattern := range patterns {
		if pattern.port == 0 {
			pattern.port = postgresDefaultPort
		}
		if matchesPattern(pattern, host, postgresDefaultPort) {
			return true
		}
	}
	return false
}

// upstreamParams describes how to reach and authenticate to the upstream
// Postgres server.
type upstreamParams struct {
	dialAddr          string
	serverName        string
	rootCAs           *x509.CertPool // nil = system roots
	user, password    string
	startupParameters map[string]string
}

// upstreamConn is an authenticated upstream Postgres connection. The
// post-auth backend messages (AuthenticationOk through ReadyForQuery) are
// buffered as encoded frames so they can be written verbatim to the client.
type upstreamConn struct {
	conn           net.Conn
	frontend       *pgproto3.Frontend
	postAuthFrames [][]byte
}

// connectPostgresUpstream dials the upstream Postgres server, requires TLS
// (SSLRequest preamble plus a verified handshake), replays the client's
// startup parameters, completes SCRAM-SHA-256 authentication with the
// resolved password, and buffers the post-auth messages up to ReadyForQuery.
func connectPostgresUpstream(ctx context.Context, p upstreamParams) (*upstreamConn, error) {
	dialer := net.Dialer{Timeout: postgresDialTimeout, KeepAlive: postgresKeepAlivePeriod}
	rawConn, err := dialer.DialContext(ctx, "tcp", p.dialAddr)
	if err != nil {
		return nil, fmt.Errorf("dial upstream: %w", err)
	}
	success := false
	defer func() {
		if !success {
			rawConn.Close()
		}
	}()

	// Bound the whole exchange by the caller's deadline, if any. Cleared
	// before returning success: the relay phase manages its own deadlines.
	if d, ok := ctx.Deadline(); ok {
		if err := rawConn.SetDeadline(d); err != nil {
			return nil, fmt.Errorf("set upstream deadline: %w", err)
		}
	}

	// SSLRequest preamble: the server answers with a single byte, 'S' to
	// proceed with TLS or 'N' to refuse.
	sslReq := pgproto3.NewFrontend(rawConn, rawConn)
	sslReq.Send(&pgproto3.SSLRequest{})
	if err := sslReq.Flush(); err != nil {
		return nil, fmt.Errorf("send SSLRequest: %w", err)
	}
	var sslResp [1]byte
	if _, err := io.ReadFull(rawConn, sslResp[:]); err != nil {
		return nil, fmt.Errorf("read SSLRequest response: %w", err)
	}
	if sslResp[0] != 'S' {
		return nil, errors.New("upstream refused TLS; plaintext upstream connections are not supported")
	}

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName: p.serverName,
		RootCAs:    p.rootCAs,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("upstream TLS handshake: %w", err)
	}

	frontend := pgproto3.NewFrontend(tlsConn, tlsConn)
	frontend.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      p.startupParameters,
	})
	if err := frontend.Flush(); err != nil {
		return nil, fmt.Errorf("send startup message: %w", err)
	}

	if err := authenticateSCRAM(frontend, p.user, p.password); err != nil {
		return nil, err
	}

	frames, err := collectPostAuthFrames(frontend)
	if err != nil {
		return nil, err
	}

	if err := rawConn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear upstream deadline: %w", err)
	}
	success = true
	return &upstreamConn{conn: tlsConn, frontend: frontend, postAuthFrames: frames}, nil
}

// authenticateSCRAM completes a SCRAM-SHA-256 conversation with the upstream
// server. ErrorResponses with authentication-failure SQLSTATEs map to
// errUpstreamAuthFailed at every receive point: the server may reject the
// user before SASL starts, or reject the proof mid-conversation.
func authenticateSCRAM(frontend *pgproto3.Frontend, user, password string) error {
	msg, err := frontend.Receive()
	if err != nil {
		return fmt.Errorf("receive auth request: %w", err)
	}
	var sasl *pgproto3.AuthenticationSASL
	switch m := msg.(type) {
	case *pgproto3.AuthenticationSASL:
		sasl = m
	case *pgproto3.ErrorResponse:
		return upstreamErrorResponse(m)
	default:
		return fmt.Errorf("upstream requested unsupported authentication (%T)", msg)
	}
	supported := false
	for _, mech := range sasl.AuthMechanisms {
		if mech == "SCRAM-SHA-256" {
			supported = true
			break
		}
	}
	if !supported {
		return errors.New("upstream does not support SCRAM-SHA-256 authentication")
	}

	// Deliberately not wrapped: scram.NewClient formats the username and
	// password verbatim into its SASLprep errors.
	client, err := scram.SHA256.NewClient(user, password, "")
	if err != nil {
		return errors.New("create SCRAM client: invalid username or password encoding")
	}
	conv := client.NewConversation()

	clientFirst, err := conv.Step("")
	if err != nil {
		return fmt.Errorf("SCRAM client-first: %w", err)
	}
	frontend.Send(&pgproto3.SASLInitialResponse{
		AuthMechanism: "SCRAM-SHA-256",
		Data:          []byte(clientFirst),
	})
	if err := frontend.Flush(); err != nil {
		return fmt.Errorf("send SASL initial response: %w", err)
	}

	msg, err = frontend.Receive()
	if err != nil {
		return fmt.Errorf("receive SASL continue: %w", err)
	}
	var cont *pgproto3.AuthenticationSASLContinue
	switch m := msg.(type) {
	case *pgproto3.AuthenticationSASLContinue:
		cont = m
	case *pgproto3.ErrorResponse:
		return upstreamErrorResponse(m)
	default:
		return fmt.Errorf("expected AuthenticationSASLContinue, got %T", msg)
	}

	clientFinal, err := conv.Step(string(cont.Data))
	if err != nil {
		return fmt.Errorf("SCRAM client-final: %w", err)
	}
	frontend.Send(&pgproto3.SASLResponse{Data: []byte(clientFinal)})
	if err := frontend.Flush(); err != nil {
		return fmt.Errorf("send SASL response: %w", err)
	}

	msg, err = frontend.Receive()
	if err != nil {
		return fmt.Errorf("receive SASL final: %w", err)
	}
	var final *pgproto3.AuthenticationSASLFinal
	switch m := msg.(type) {
	case *pgproto3.AuthenticationSASLFinal:
		final = m
	case *pgproto3.ErrorResponse:
		return upstreamErrorResponse(m)
	default:
		return fmt.Errorf("expected AuthenticationSASLFinal, got %T", msg)
	}

	// Verifies the server signature — proof that the server knows the
	// credentials too, not just an attacker terminating TLS.
	if _, err := conv.Step(string(final.Data)); err != nil {
		return fmt.Errorf("verify SCRAM server signature: %w", err)
	}
	return nil
}

// collectPostAuthFrames receives backend messages after SASL completion and
// returns them as encoded frames, ending with ReadyForQuery. Frames are
// encoded immediately because messages returned by Receive may share internal
// buffers invalidated by the next Receive.
func collectPostAuthFrames(frontend *pgproto3.Frontend) ([][]byte, error) {
	var frames [][]byte
	for {
		msg, err := frontend.Receive()
		if err != nil {
			return nil, fmt.Errorf("receive post-auth message: %w", err)
		}
		if errResp, ok := msg.(*pgproto3.ErrorResponse); ok {
			return nil, upstreamErrorResponse(errResp)
		}
		frame, err := msg.Encode(nil)
		if err != nil {
			return nil, fmt.Errorf("encode post-auth message: %w", err)
		}
		frames = append(frames, frame)
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			return frames, nil
		}
	}
}

// upstreamErrorResponse maps an upstream ErrorResponse to a proxy error.
// Authentication-failure SQLSTATEs wrap errUpstreamAuthFailed (so
// connectWithRetry's errors.Is check and its invalidate-and-retry-once
// behavior keep working) with the upstream's severity, SQLSTATE, and
// message attached; other SQLSTATEs get the same detail without the
// sentinel. These are the UPSTREAM SERVER's own error fields — safe to log,
// never a credential — and this is the only place gatekeeper preserves them
// instead of discarding them, so the resulting error is never returned to
// the client (see serveAuthenticated's sanitized "could not authenticate to
// upstream database" reply) but is logged in full server-side.
func upstreamErrorResponse(e *pgproto3.ErrorResponse) error {
	detail := fmt.Sprintf("upstream error %s %s: %s", e.Severity, e.Code, e.Message)
	if isAuthFailureCode(e.Code) {
		return fmt.Errorf("%w: %s", errUpstreamAuthFailed, detail)
	}
	return errors.New(detail)
}

// isAuthFailureCode reports whether code is a SQLSTATE that indicates an
// authentication failure: 28P01 (invalid_password) or 28000
// (invalid_authorization_specification, e.g. unknown role).
func isAuthFailureCode(code string) bool {
	return code == "28P01" || code == "28000"
}

// PostgresServer is the client-facing Postgres listener. It terminates TLS with
// a certificate minted from the proxy's CA for the SNI hostname, requires the
// client to present a cleartext password (the run token, which is safe inside
// the TLS tunnel), and resolves that token to a per-run context. Plaintext
// connections are refused before any credential is requested.
type PostgresServer struct {
	proxy    *Proxy
	listener net.Listener

	// closed is set before the listener is closed so acceptLoop can distinguish
	// an intentional shutdown from a real Accept failure.
	closed atomic.Bool

	// active tracks in-flight connections so Shutdown can wait for them to drain
	// and force-close them when the deadline expires.
	mu     sync.Mutex
	active map[net.Conn]struct{}
	wg     sync.WaitGroup

	// dialUpstream overrides upstream dialing in tests; nil means dial host:5432.
	dialUpstream func(ctx context.Context, host string) (string, error)
}

// NewPostgresServer creates a Postgres listener backed by the given proxy. The
// proxy supplies the CA (for TLS termination), the context resolver / auth
// token (for run-token authentication), and the Postgres credential resolvers
// (for upstream credentials).
func NewPostgresServer(p *Proxy) *PostgresServer {
	return &PostgresServer{proxy: p}
}

// Start binds the listener on addr and begins accepting connections. It returns
// an error if the proxy has no CA, since the listener cannot terminate TLS
// without one.
func (s *PostgresServer) Start(addr string) error {
	if s.proxy.ca == nil {
		return errors.New("postgres listener requires a CA for TLS termination")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("postgres listen: %w", err)
	}
	return s.startListener(ln)
}

// StartListener begins accepting connections on a pre-created listener
// instead of binding one itself, so the caller can wrap it first — e.g. with
// WrapProxyProtocolListener, to add PROXY protocol support (see
// PostgresConfig.ProxyProtocol). It performs the same CA check as Start.
func (s *PostgresServer) StartListener(ln net.Listener) error {
	if s.proxy.ca == nil {
		return errors.New("postgres listener requires a CA for TLS termination")
	}
	return s.startListener(ln)
}

func (s *PostgresServer) startListener(ln net.Listener) error {
	s.listener = ln
	go s.acceptLoop(ln)
	return nil
}

// Addr returns the listener's address, or "" if the server is not listening.
func (s *PostgresServer) Addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// Stop closes the listener. It is safe to call on a nil-listener server and
// idempotent: the closed flag guards against a double close and signals
// acceptLoop to treat the resulting Accept error as an intentional shutdown.
// beginClose marks the server closed (under the lock, so trackConn observes it
// atomically with its wg.Add) and closes the listener once.
func (s *PostgresServer) beginClose() {
	s.mu.Lock()
	first := s.closed.CompareAndSwap(false, true)
	s.mu.Unlock()
	if first {
		_ = s.listener.Close()
	}
}

// Stop closes the listener immediately and force-closes active connections
// without waiting for relays to finish. Prefer Shutdown for graceful drain.
func (s *PostgresServer) Stop() {
	if s.listener == nil {
		return
	}
	s.beginClose()
	s.closeActiveConns()
	s.wg.Wait()
}

// Shutdown stops accepting new connections and waits for active relays to drain.
// If ctx expires first, it force-closes the remaining connections (interrupting
// in-flight queries) and returns ctx.Err().
//
// A connection that is mid-credential-resolution when shutdown begins blocks the
// drain until that resolution returns, since a singleflight-shared Neon API call
// cannot be interrupted by closing the client socket. The standalone server
// bounds this by closing credential resolvers before calling Shutdown (see
// NeonResolver.Close), which cancels in-flight API calls; an embedder that wires
// Shutdown directly should close its resolvers first for the same reason.
func (s *PostgresServer) Shutdown(ctx context.Context) error {
	if s.listener == nil {
		return nil
	}
	s.beginClose()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		// Deadline hit: force-close active connections so the blocked relay
		// goroutines unblock and exit, then wait for them.
		s.closeActiveConns()
		s.wg.Wait()
		return ctx.Err()
	}
}

func (s *PostgresServer) closeActiveConns() {
	s.mu.Lock()
	for c := range s.active {
		_ = c.Close()
	}
	s.mu.Unlock()
}

// acceptLoop accepts connections on ln and dispatches each to handleConn. It
// mirrors Demux.acceptLoop's accept-error handling (demux.go), which in turn
// mirrors net/http.Server.Serve: a transient Accept error is retried after a
// capped exponential backoff rather than tearing down the listener, and only
// an intentional shutdown (s.closed set by beginClose before the listener is
// closed) exits the loop. Without this, a transient error (EMFILE/ENFILE
// under fd exhaustion, ECONNABORTED -- realistic for a proxy holding many
// long-lived Postgres relay connections) permanently kills the data-plane
// listener until process restart.
//
// Like Demux.acceptLoop, this does not gate the retry on the deprecated and
// unreliable net.Error.Temporary(): any error while the listener is still
// live is treated as transient and retried.
func (s *PostgresServer) acceptLoop(ln net.Listener) {
	var backoff time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.closed.Load() {
				// Intentional shutdown: the listener was closed.
				return
			}
			if backoff == 0 {
				backoff = demuxAcceptRetryBaseDelay
			} else {
				backoff *= 2
			}
			if backoff > demuxAcceptRetryMaxDelay {
				backoff = demuxAcceptRetryMaxDelay
			}
			slog.Warn("postgres: transient accept error; retrying",
				"subsystem", "proxy",
				"error", err,
				"retry_in", backoff)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		// Register the connection under the same lock that Shutdown uses to set
		// closed. This makes the closed check and wg.Add atomic with respect to
		// shutdown: either we add to the WaitGroup before Shutdown observes the
		// count, or Shutdown has already set closed and we reject the connection.
		// Without this, Shutdown could see a zero WaitGroup and return between
		// the check and wg.Add, leaving an untracked goroutine running.
		if !s.trackConn(conn) {
			_ = conn.Close()
			continue
		}
		go func() {
			defer s.wg.Done()
			defer s.untrackConn(conn)
			s.handleConn(conn)
		}()
	}
}

// trackConn registers a connection and increments the WaitGroup, unless a
// shutdown is already in progress. It returns false when the caller should
// reject the connection.
func (s *PostgresServer) trackConn(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return false
	}
	if s.active == nil {
		s.active = make(map[net.Conn]struct{})
	}
	s.active[conn] = struct{}{}
	s.wg.Add(1)
	return true
}

func (s *PostgresServer) untrackConn(conn net.Conn) {
	s.mu.Lock()
	delete(s.active, conn)
	s.mu.Unlock()
}

// handleConn runs the client-facing handshake: refuse plaintext, terminate TLS,
// read the startup message, demand a cleartext password (the run token),
// authenticate it, then hand off to serveAuthenticated.
func (s *PostgresServer) handleConn(conn net.Conn) {
	defer conn.Close()

	// Keep-alives so a dead client is detected during a long-running query or
	// an idle session, which the relay would otherwise block on indefinitely.
	enableKeepAlive(conn)

	// Bound the handshake on both reads and writes: a stalled client write (a
	// full socket buffer while we flush AuthenticationCleartextPassword or an
	// ErrorResponse) must not pin this goroutine. The relay phase (Task 8)
	// clears this deadline before entering the bidirectional copy.
	_ = conn.SetDeadline(time.Now().Add(postgresHandshakeTimeout))

	backend := pgproto3.NewBackend(conn, conn)
	startup, err := backend.ReceiveStartupMessage()
	if err != nil {
		return
	}

	// Refuse plaintext before requesting any credential: the first message must
	// be an SSLRequest. Anything else gets a 28000 and the connection closes.
	if _, ok := startup.(*pgproto3.SSLRequest); !ok {
		sendPGError(backend, "28000", "SSL required")
		return
	}
	if _, err := conn.Write([]byte{'S'}); err != nil {
		return
	}

	var sniHost string
	tlsConn := tls.Server(conn, &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sniHost = hello.ServerName
			return s.proxy.ca.GenerateCert(hello.ServerName)
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), postgresHandshakeTimeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return
	}
	// Bound reads and writes for the same reason as above. The relay phase
	// (Task 8) clears this deadline before entering the bidirectional copy.
	_ = tlsConn.SetDeadline(time.Now().Add(postgresHandshakeTimeout))

	backend = pgproto3.NewBackend(tlsConn, tlsConn)

	if sniHost == "" {
		// Without SNI there is no host to resolve credentials for. Drain the
		// startup message so the client receives the error cleanly.
		_, _ = backend.ReceiveStartupMessage()
		sendPGError(backend, "08004", "server name indication (SNI) required")
		return
	}

	startup, err = backend.ReceiveStartupMessage()
	if err != nil {
		return
	}
	sm, ok := startup.(*pgproto3.StartupMessage)
	if !ok {
		sendPGError(backend, "08P01", "expected startup message after TLS handshake")
		return
	}
	user := sm.Parameters["user"]
	database := sm.Parameters["database"]
	if database == "" {
		database = user
	}

	// Demand a cleartext password — the run token. It is only ever read inside
	// the TLS tunnel established above, so it is never exposed on the wire.
	backend.Send(&pgproto3.AuthenticationCleartextPassword{})
	if err := backend.Flush(); err != nil {
		return
	}
	if err := backend.SetAuthType(pgproto3.AuthTypeCleartextPassword); err != nil {
		return
	}
	msg, err := backend.Receive()
	if err != nil {
		return
	}
	pw, ok := msg.(*pgproto3.PasswordMessage)
	if !ok {
		sendPGError(backend, "28P01", "password authentication failed")
		return
	}

	rc, ok := s.authenticate(pw.Password)
	if !ok {
		// The run token itself must never be logged, not even a prefix — only
		// that authentication at this boundary failed, and where from.
		slog.Warn("postgres run-token authentication failed",
			"subsystem", "proxy",
			"stage", "run_token_auth",
			"client_addr", conn.RemoteAddr().String(),
			"host", sniHost)
		sendPGError(backend, "28P01", "password authentication failed")
		return
	}

	// Forward only ordinary session parameters upstream. `replication` would
	// request a WAL-streaming session — an elevated privilege the data plane is
	// not meant to grant — and `options` can set arbitrary server-side GUCs at
	// startup. Normal libpq clients send neither unless explicitly asked to.
	forwardParams := make(map[string]string, len(sm.Parameters))
	for k, v := range sm.Parameters {
		switch k {
		case "replication", "options":
			// Intentionally dropped.
		default:
			forwardParams[k] = v
		}
	}

	// Reuse the handshake context so the upstream connect shares the remaining
	// timeout budget rather than starting a fresh 30s window after a slow
	// client handshake has already consumed most of it.
	s.serveAuthenticated(ctx, tlsConn, backend, rc, sniHost, user, database, forwardParams)
}

// authenticate validates the run token and returns the matching run context.
// Resolution mirrors the HTTP plane:
//   - When a context resolver is configured (daemon mode), it maps the token to
//     a per-run context.
//   - When only a static auth token is configured (standalone mode), the token
//     is compared in constant time; no run context exists.
//   - When neither is configured, every token is accepted (localhost trust),
//     matching the HTTP plane's behavior when no auth is set.
func (s *PostgresServer) authenticate(token string) (*RunContextData, bool) {
	if s.proxy.contextResolver != nil {
		return s.proxy.contextResolver(token)
	}
	if s.proxy.authToken != "" {
		match := subtle.ConstantTimeCompare([]byte(token), []byte(s.proxy.authToken)) == 1
		return nil, match
	}
	return nil, true
}

// serveAuthenticated takes over a fully authenticated client connection: it
// enforces network policy, resolves the upstream password (re-resolving once on
// an upstream auth failure), connects to the upstream server, forwards the
// buffered post-auth frames to the client, then relays messages in both
// directions until either side closes. Every outcome is audit-logged once.
func (s *PostgresServer) serveAuthenticated(ctx context.Context, clientConn net.Conn, backend *pgproto3.Backend, rc *RunContextData, sniHost, user, database string, startupParams map[string]string) {
	start := time.Now()
	logEntry := RequestLogData{
		Method:       "STARTUP",
		URL:          sniHost,
		Host:         sniHost,
		RequestType:  "postgres",
		UserID:       user,
		RequestSize:  -1,
		ResponseSize: -1,
		ClientAddr:   clientConn.RemoteAddr().String(),
	}
	if rc != nil {
		logEntry.RunID = rc.RunID
	}

	// deny sends a fatal error to the client and writes one audit row. statusCode
	// keeps the log's StatusCode non-zero and category-consistent with the HTTP
	// plane (403 not allowed, 502 upstream failure), so dashboards keyed on it
	// don't see a 0 for denied Postgres connections.
	deny := func(statusCode int, code, clientMsg, logReason string) {
		sendPGError(backend, code, clientMsg)
		logEntry.StatusCode = statusCode
		logEntry.Denied = true
		logEntry.DenyReason = logReason
		logEntry.Duration = time.Since(start)
		s.log(logEntry)
	}

	// Network policy: when a run context is present, honor its scoped policy;
	// otherwise fall back to the proxy-level policy.
	//
	// Like the HTTP CONNECT path, the Postgres plane intentionally enforces only
	// host-level allow/deny here. It deliberately does not consult per-run
	// RequestCheck or host-gateway (isHostGateway) handling: Neon endpoints are
	// public DNS, so host-gateway routing does not apply to the Postgres data plane.
	var allowed bool
	if rc != nil {
		allowed = rc.Policy != "strict" || matchHostPostgres(rc.AllowedHosts, sniHost)
	} else {
		allowed = s.proxy.checkNetworkPolicyPostgres(sniHost)
	}
	if !allowed {
		if s.proxy.policyLogger != nil {
			runID := ""
			if rc != nil {
				runID = rc.RunID
			}
			s.proxy.policyLogger(PolicyLogData{
				RunID:     runID,
				Scope:     "network",
				Operation: "postgres.connect",
				Message:   "Host not in allow list: " + sniHost,
			})
		}
		deny(403, "28000", "connection not allowed by network policy", "Host not in allow list: "+sniHost)
		return
	}

	resolver := s.proxy.postgresResolverForHost(rc, sniHost)
	if resolver == nil {
		deny(403, "08004", "no credentials configured for this host", "no postgres resolver for host")
		return
	}

	up, grants, err := s.connectWithRetry(ctx, resolver, sniHost, user, database, startupParams)
	if err != nil {
		// Never include the underlying error in the client-facing message: it
		// could echo the upstream server's identifiers. The full error —
		// including the upstream server's own ErrorResponse fields when the
		// failure came from there (see upstreamErrorResponse) — is only logged
		// at debug level, never with credential values. stage names which of the
		// three failure boundaries the error came from, so they are never
		// conflated in the log: resolve (the credential resolver, e.g. the Neon
		// API, failed before the proxy reached the upstream), upstream_auth (the
		// upstream server rejected the presented credential), and upstream_connect
		// (dial/TLS/SCRAM/protocol failure reaching the upstream).
		stage := "upstream_connect"
		switch {
		case errors.Is(err, errUpstreamAuthFailed):
			stage = "upstream_auth"
		case errors.Is(err, errResolvePassword):
			stage = "resolve"
		}
		slog.Debug("postgres upstream connection failed",
			"subsystem", "proxy",
			"stage", stage,
			"host", sniHost,
			"user", user,
			"error", err)
		deny(502, "28P01", "could not authenticate to upstream database", "upstream connection failed")
		return
	}
	defer up.conn.Close()
	logEntry.AuthInjected = true
	logEntry.Grants = grants

	// Forward the buffered post-auth frames (AuthenticationOk .. ReadyForQuery)
	// verbatim. These are pre-encoded wire bytes, so they go straight to the
	// client socket, not through backend.Send.
	for _, frame := range up.postAuthFrames {
		if _, err := clientConn.Write(frame); err != nil {
			// Upstream authenticated but the client vanished before we could
			// deliver the post-auth frames. Record a non-zero status (like every
			// other exit path) so the row isn't logged with StatusCode 0.
			logEntry.StatusCode = 502
			logEntry.Err = err
			logEntry.Duration = time.Since(start)
			s.log(logEntry)
			return
		}
	}

	// The handshake deadlines must not bound the (potentially long-lived) relay.
	_ = clientConn.SetDeadline(time.Time{})
	_ = up.conn.SetDeadline(time.Time{})

	msgsIn, msgsOut := relayPostgres(backend, up.frontend, clientConn, up.conn)
	logEntry.StatusCode = 200
	// The relay forwards whole protocol messages and does not count bytes, so
	// the byte-valued size fields stay unknown and the counts go in their own
	// fields (keeping RequestSize/ResponseSize meaning bytes everywhere).
	logEntry.RequestMessages = msgsIn
	logEntry.ResponseMessages = msgsOut
	logEntry.Duration = time.Since(start)
	s.log(logEntry)
}

// connectWithRetry resolves the upstream password and connects to the upstream
// Postgres server, retrying exactly once on an upstream authentication failure
// after invalidating the (presumably stale) cached password. It returns the
// authenticated upstream connection and the grant names for audit logging.
func (s *PostgresServer) connectWithRetry(ctx context.Context, resolver PostgresCredentialResolver, host, user, database string, startupParams map[string]string) (*upstreamConn, []string, error) {
	dialAddr := net.JoinHostPort(host, "5432")
	if s.dialUpstream != nil {
		addr, err := s.dialUpstream(ctx, host)
		if err != nil {
			return nil, nil, err
		}
		dialAddr = addr
	}

	connect := func() (*upstreamConn, error) {
		password, err := resolver.ResolvePassword(ctx, host, user, database)
		if err != nil {
			// Wrap both the errResolvePassword sentinel (so the connect path can
			// classify this as stage=resolve via errors.Is, and so it is never
			// mistaken for an upstream credential rejection that would invalidate
			// and retry) and the human-readable context in one error.
			return nil, fmt.Errorf("resolving postgres password: %w: %w", errResolvePassword, err)
		}
		return connectPostgresUpstream(ctx, upstreamParams{
			dialAddr:          dialAddr,
			serverName:        host,
			rootCAs:           s.proxy.upstreamCAs,
			user:              user,
			password:          password,
			startupParameters: startupParams,
		})
	}
	grants := []string{"postgres:" + host}

	up, err := connect()
	if err == nil {
		return up, grants, nil
	}
	// Retry exactly once, and only when the upstream rejected the credential:
	// the cached password may be stale (Neon rotates on branch reset), so drop
	// it and resolve again. Any other failure is returned as-is.
	if !errors.Is(err, errUpstreamAuthFailed) {
		return nil, nil, err
	}
	resolver.InvalidatePassword(host, user, database)
	up, err = connect()
	if err != nil {
		return nil, nil, err
	}
	return up, grants, nil
}

// relayPostgres pumps pgproto3 messages in both directions between the client
// (via backend) and the upstream server (via frontend) until either side errors
// or the client sends Terminate. Both readers are buffered, so a raw io.Copy
// would risk stranding bytes already pulled past the handshake — the message
// pump drains those buffers correctly. When one direction errors, both conns
// are closed so the other Receive unblocks. The returned counts are
// protocol-message counts, not byte counts.
func relayPostgres(backend *pgproto3.Backend, frontend *pgproto3.Frontend, clientConn, upConn net.Conn) (msgsIn, msgsOut int64) {
	// Concurrency invariant: the two pumps below share one *pgproto3.Frontend
	// and one *pgproto3.Backend, but each pump uses only one direction of each
	// object — the client->upstream pump calls backend.Receive + frontend.Send,
	// and the upstream->client pump calls frontend.Receive + backend.Send. This
	// is safe only because pgproto3's read path (chunkReader + message
	// flyweights) and write path (write buffer + writer + encodeError) live in
	// disjoint struct fields, so a concurrent Send and Receive on one object
	// touch different memory. pgproto3 does NOT document Send/Receive as
	// concurrency-safe; this was verified against the pinned v5.10.0 (via
	// jackc/pgx/v5 v5.10.0). If pgproto3 is upgraded, re-verify this
	// field-disjointness or split into per-direction objects over the same conn.
	var inCount, outCount atomic.Int64
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			clientConn.Close()
			upConn.Close()
		})
	}

	done := make(chan struct{}, 2)

	// client -> upstream
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			msg, err := backend.Receive()
			if err != nil {
				closeBoth()
				return
			}
			frontend.Send(msg)
			if err := frontend.Flush(); err != nil {
				closeBoth()
				return
			}
			inCount.Add(1)
			if _, ok := msg.(*pgproto3.Terminate); ok {
				closeBoth()
				return
			}
		}
	}()

	// upstream -> client
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			msg, err := frontend.Receive()
			if err != nil {
				closeBoth()
				return
			}
			backend.Send(msg)
			if err := backend.Flush(); err != nil {
				closeBoth()
				return
			}
			outCount.Add(1)
		}
	}()

	<-done
	<-done
	return inCount.Load(), outCount.Load()
}

// log forwards an audit entry to the proxy's request logger, if configured.
func (s *PostgresServer) log(data RequestLogData) {
	if s.proxy.logger != nil {
		s.proxy.logger(data)
	}
}

// sendPGError sends a FATAL ErrorResponse with the given SQLSTATE and message,
// then flushes. Messages must never include credential values.
func sendPGError(backend *pgproto3.Backend, code, message string) {
	backend.Send(&pgproto3.ErrorResponse{
		Severity: "FATAL",
		Code:     code,
		Message:  message,
	})
	_ = backend.Flush()
}
