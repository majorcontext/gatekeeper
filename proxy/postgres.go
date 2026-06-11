package proxy

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
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

// Stop closes the listener. It is safe to call on a nil-listener server.
func (s *PostgresServer) Stop() {
	if s.listener != nil {
		s.listener.Close()
	}
}

func (s *PostgresServer) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
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

	// Bound the handshake. The relay phase (Task 8) clears this deadline before
	// entering the bidirectional copy.
	_ = conn.SetReadDeadline(time.Now().Add(postgresHandshakeTimeout))

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
	_ = tlsConn.SetReadDeadline(time.Now().Add(postgresHandshakeTimeout))

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

// serveAuthenticated takes over a fully authenticated client connection.
//
// This is a stub for Task 7: it resolves the upstream credential resolver for
// the SNI host and reports failure either way (relay not yet implemented).
//
// Task 8 replaces the relay-not-implemented branch with the real upstream
// connection and bidirectional copy. Handoff notes for Task 8:
//   - connectPostgresUpstream returns post-auth data as postAuthFrames [][]byte,
//     pre-encoded wire frames. Write those bytes directly to clientConn (NOT via
//     backend.Send, which takes typed messages).
//   - Clear the handshake read deadline on clientConn before entering the relay
//     phase.
func (s *PostgresServer) serveAuthenticated(clientConn net.Conn, backend *pgproto3.Backend, rc *RunContextData, sniHost, user, database string, startupParams map[string]string) {
	if s.proxy.postgresResolverForHost(rc, sniHost) == nil {
		sendPGError(backend, "08004", "no credentials configured for this host")
		return
	}
	sendPGError(backend, "08004", "relay not implemented")
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
