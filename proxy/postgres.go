package proxy

import (
	"context"
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
