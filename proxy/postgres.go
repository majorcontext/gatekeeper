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

// postgresDefaultPort is the port used when matching Postgres host patterns.
const postgresDefaultPort = 5432

// postgresDialTimeout bounds the TCP dial to the upstream Postgres server.
const postgresDialTimeout = 10 * time.Second

// errUpstreamAuthFailed indicates the upstream Postgres server rejected the
// credentials the proxy presented (bad password or unknown role).
var errUpstreamAuthFailed = errors.New("upstream authentication failed")

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
	dialer := net.Dialer{Timeout: postgresDialTimeout}
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
// Authentication-failure SQLSTATEs map to errUpstreamAuthFailed; everything
// else reports the SQLSTATE code only (the message could echo identifiers).
func upstreamErrorResponse(e *pgproto3.ErrorResponse) error {
	if isAuthFailureCode(e.Code) {
		return errUpstreamAuthFailed
	}
	return fmt.Errorf("upstream error (SQLSTATE %s)", e.Code)
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

	// closed is set by Stop before the listener is closed so acceptLoop can
	// distinguish an intentional shutdown from a real Accept failure.
	closed atomic.Bool

	// dialUpstream overrides upstream dialing in tests; nil means dial host:5432.
	// Task 8 (the relay) consumes it.
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
func (s *PostgresServer) Stop() {
	if s.listener == nil {
		return
	}
	if s.closed.CompareAndSwap(false, true) {
		s.listener.Close()
	}
}

func (s *PostgresServer) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.closed.Load() {
				// Intentional shutdown via Stop: the listener was closed.
				return
			}
			slog.Error("postgres accept loop exited",
				"subsystem", "proxy",
				"error", err)
			return
		}
		go s.handleConn(conn)
	}
}

// handleConn runs the client-facing handshake: refuse plaintext, terminate TLS,
// read the startup message, demand a cleartext password (the run token),
// authenticate it, then hand off to serveAuthenticated.
func (s *PostgresServer) handleConn(conn net.Conn) {
	defer conn.Close()

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
		sendPGError(backend, "28P01", "password authentication failed")
		return
	}

	s.serveAuthenticated(tlsConn, backend, rc, sniHost, user, database, sm.Parameters)
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
func (s *PostgresServer) serveAuthenticated(clientConn net.Conn, backend *pgproto3.Backend, rc *RunContextData, sniHost, user, database string, startupParams map[string]string) {
	start := time.Now()
	logEntry := RequestLogData{
		Method:       "STARTUP",
		URL:          sniHost,
		Host:         sniHost,
		RequestType:  "postgres",
		UserID:       user,
		RequestSize:  -1,
		ResponseSize: -1,
	}
	if rc != nil {
		logEntry.RunID = rc.RunID
	}

	deny := func(code, clientMsg, logReason string) {
		sendPGError(backend, code, clientMsg)
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
		allowed = rc.Policy != "strict" || matchHost(rc.AllowedHosts, sniHost, postgresDefaultPort)
	} else {
		allowed = s.proxy.checkNetworkPolicy(sniHost, postgresDefaultPort)
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
		deny("28000", "connection not allowed by network policy", "Host not in allow list: "+sniHost)
		return
	}

	resolver := s.proxy.postgresResolverForHost(rc, sniHost)
	if resolver == nil {
		deny("08004", "no credentials configured for this host", "no postgres resolver for host")
		return
	}

	up, grants, err := s.connectWithRetry(resolver, sniHost, user, database, startupParams)
	if err != nil {
		// Never include the underlying error in the client-facing message: it
		// could echo the upstream server's identifiers. The full error is only
		// logged at debug level, never with credential values.
		slog.Debug("postgres upstream connection failed",
			"subsystem", "proxy",
			"host", sniHost,
			"user", user,
			"error", err)
		deny("28P01", "could not authenticate to upstream database", "upstream connection failed")
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
			logEntry.Duration = time.Since(start)
			s.log(logEntry)
			return
		}
	}

	// The handshake deadlines must not bound the (potentially long-lived) relay.
	_ = clientConn.SetDeadline(time.Time{})
	_ = up.conn.SetDeadline(time.Time{})

	bytesIn, bytesOut := relayPostgres(backend, up.frontend, clientConn, up.conn)
	logEntry.StatusCode = 200
	// These are postgres protocol-message counts, not byte counts (for HTTP
	// traffic RequestSize/ResponseSize carry byte counts).
	logEntry.RequestSize = bytesIn
	logEntry.ResponseSize = bytesOut
	logEntry.Duration = time.Since(start)
	s.log(logEntry)
}

// connectWithRetry resolves the upstream password and connects to the upstream
// Postgres server, retrying exactly once on an upstream authentication failure
// after invalidating the (presumably stale) cached password. It returns the
// authenticated upstream connection and the grant names for audit logging.
func (s *PostgresServer) connectWithRetry(resolver PostgresCredentialResolver, host, user, database string, startupParams map[string]string) (*upstreamConn, []string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), postgresHandshakeTimeout)
	defer cancel()

	dialAddr := net.JoinHostPort(host, "5432")
	if s.dialUpstream != nil {
		addr, err := s.dialUpstream(ctx, host)
		if err != nil {
			return nil, nil, err
		}
		dialAddr = addr
	}

	for attempt := 0; attempt < 2; attempt++ {
		password, err := resolver.ResolvePassword(ctx, host, user, database)
		if err != nil {
			return nil, nil, fmt.Errorf("resolving postgres password: %w", err)
		}
		up, err := connectPostgresUpstream(ctx, upstreamParams{
			dialAddr:          dialAddr,
			serverName:        host,
			rootCAs:           s.proxy.upstreamCAs,
			user:              user,
			password:          password,
			startupParameters: startupParams,
		})
		if err == nil {
			return up, []string{"postgres:" + host}, nil
		}
		if !errors.Is(err, errUpstreamAuthFailed) || attempt == 1 {
			return nil, nil, err
		}
		// The cached password was rejected: drop it and try once more.
		resolver.InvalidatePassword(host, user, database)
	}
	// unreachable: the loop returns on every path
	return nil, nil, errors.New("unreachable")
}

// relayPostgres pumps pgproto3 messages in both directions between the client
// (via backend) and the upstream server (via frontend) until either side errors
// or the client sends Terminate. Both readers are buffered, so a raw io.Copy
// would risk stranding bytes already pulled past the handshake — the message
// pump drains those buffers correctly. When one direction errors, both conns
// are closed so the other Receive unblocks. The returned counts are
// protocol-message counts, not byte counts.
func relayPostgres(backend *pgproto3.Backend, frontend *pgproto3.Frontend, clientConn, upConn net.Conn) (bytesIn, bytesOut int64) {
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
