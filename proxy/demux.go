package proxy

// demux.go implements single-port multiplexing: when gatekeeper's HTTP/
// CONNECT proxy listener and its Postgres data-plane listener are configured
// on the same address, one real net.Listener carries both. Each accepted
// connection is classified by its first bytes in its own goroutine — never
// in the shared accept loop, so a silent or slow client can never stall
// Accept for every other pending connection — and routed to one of two
// in-memory virtual listeners. http.Server.Serve and
// PostgresServer.StartListener then run completely unmodified against those
// virtual listeners, unaware they aren't backed by a real socket.
//
// This is a hand-rolled, minimal cmux-style demultiplexer: gatekeeper is
// dependency-conscious, so rather than adding a cmux dependency this reuses
// the existing connection-wrapping pattern from proxyProtoLogConn
// (proxyproto.go), which already holds and replays bytes consumed ahead of
// a connection's real payload.

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// demuxSniffLen is the number of leading bytes the demux reads from a newly
// accepted connection before routing it. It is exactly enough to positively
// identify every Postgres startup signature gatekeeper's data plane
// recognizes: a 4-byte big-endian header followed by either a well-known
// magic code (SSLRequest, GSSENCRequest) or protocol version 3.0
// (StartupMessage). Anything else — an HTTP/1.x request line, the h2 client
// preface, or any other prefix — is routed to the HTTP plane by default.
const demuxSniffLen = 8

// demuxSniffDeadline bounds how long the demux waits for the first
// demuxSniffLen bytes of a new connection before giving up on it. It reuses
// the same 10s window as WrapProxyProtocolListener's PROXY header read (see
// proxyproto.go), so a silent client — an LB health check that opens a
// socket and waits, or a slow-loris — is dropped on the same timescale
// wherever gatekeeper reads a connection's opening bytes. Once
// classification succeeds, this deadline is cleared before the connection
// is handed to a downstream server, so only that server's own timeouts
// (http.Server's ReadHeaderTimeout, or PostgresServer's handshake timeout)
// ever apply from that point on.
const demuxSniffDeadline = 10 * time.Second

// demuxBacklog bounds each virtual listener's queue of classified,
// not-yet-Accepted connections. It absorbs a burst of concurrent handshakes
// arriving faster than the downstream server's Accept loop drains them; a
// connection that can't be enqueued (backlog full, or the listener already
// closed) is closed by the dispatcher instead of blocking the accept loop
// that's classifying other connections.
const demuxBacklog = 64

// demuxProtocol identifies which plane a connection belongs to.
type demuxProtocol int

const (
	demuxHTTP demuxProtocol = iota
	demuxPostgres
)

// String returns the protocol label used in the per-connection DEBUG log
// line. It never includes any connection content — only "http" or
// "postgres".
func (p demuxProtocol) String() string {
	if p == demuxPostgres {
		return "postgres"
	}
	return "http"
}

// classifyPrefix reports which plane a connection belongs to, given its
// first demuxSniffLen bytes. Classification is positive-match Postgres —
// the same approach as Caddy-L4's postgres matcher: only a recognized
// Postgres startup signature routes to demuxPostgres, and every other
// prefix defaults to demuxHTTP.
func classifyPrefix(prefix []byte) demuxProtocol {
	if isPostgresStartup(prefix) {
		return demuxPostgres
	}
	return demuxHTTP
}

// isPostgresStartup reports whether prefix opens with one of the three
// Postgres startup signatures gatekeeper's data plane accepts:
//
//   - SSLRequest:        length 00 00 00 08, code 04 d2 16 2f (80877103)
//   - GSSENCRequest:     length 00 00 00 08, code 04 d2 16 30 (80877104)
//   - v3 StartupMessage: any 4-byte length, then protocol 00 03 00 00
//
// A prefix shorter than demuxSniffLen can never match.
func isPostgresStartup(prefix []byte) bool {
	if len(prefix) < demuxSniffLen {
		return false
	}
	if prefix[0] == 0x00 && prefix[1] == 0x00 && prefix[2] == 0x00 && prefix[3] == 0x08 &&
		prefix[4] == 0x04 && prefix[5] == 0xd2 && prefix[6] == 0x16 &&
		(prefix[7] == 0x2f || prefix[7] == 0x30) {
		return true
	}
	return prefix[4] == 0x00 && prefix[5] == 0x03 && prefix[6] == 0x00 && prefix[7] == 0x00
}

// demuxConn wraps a newly accepted connection so the demuxSniffLen bytes
// consumed while classifying it are replayed on the first Read calls, ahead
// of any further bytes from the underlying conn. This mirrors
// proxyProtoLogConn's hold-then-replay pattern in proxyproto.go, which
// exists for the same reason: net.Conn has no way to "un-read" bytes once
// they're consumed, so the bytes read to classify a connection must be
// spliced back in front of it for its actual owner (http.Server or
// PostgresServer) to see the whole, unmodified byte stream.
type demuxConn struct {
	net.Conn
	prefix []byte
}

func (c *demuxConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

// Raw unwraps to the innermost connection, so a caller that needs the real
// transport conn — e.g. postgres.go's underlyingTCPConn, for TCP keep-alive
// setup — can reach it through a demuxConn exactly as it already does
// through a proxyProtoLogConn (proxyproto.go). It recurses through any
// further Raw()-implementing wrapper beneath it, e.g. a proxyProtoLogConn
// when the shared listener is also PROXY-protocol-wrapped.
func (c *demuxConn) Raw() net.Conn {
	if rc, ok := c.Conn.(interface{ Raw() net.Conn }); ok {
		return rc.Raw()
	}
	return c.Conn
}

// virtualListener is an in-memory net.Listener fed by a Demux's dispatcher
// goroutine instead of a real socket. http.Server.Serve and
// PostgresServer.StartListener run against it completely unmodified.
type virtualListener struct {
	addr net.Addr

	mu     sync.Mutex
	closed bool
	conns  chan net.Conn
	done   chan struct{}
}

func newVirtualListener(addr net.Addr) *virtualListener {
	return &virtualListener{
		addr:  addr,
		conns: make(chan net.Conn, demuxBacklog),
		done:  make(chan struct{}),
	}
}

// push enqueues conn for a future Accept call. It returns false — without
// blocking — when the listener is already closed or its backlog is full, so
// the dispatcher can close conn itself instead of leaking it or stalling on
// a slow Accept loop.
func (l *virtualListener) push(conn net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return false
	}
	select {
	case l.conns <- conn:
		return true
	default:
		return false
	}
}

func (l *virtualListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close marks the listener closed and closes any connection still queued
// but never Accepted, so it doesn't leak a file descriptor with nobody left
// to close it. Nothing can push after closed is set (push takes the same
// lock), so the drain below is race-free.
func (l *virtualListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	close(l.done)
	l.mu.Unlock()

	for {
		select {
		case conn := <-l.conns:
			conn.Close()
		default:
			return nil
		}
	}
}

func (l *virtualListener) Addr() net.Addr { return l.addr }

// Demux owns a single real listener carrying both HTTP/CONNECT proxy
// traffic and Postgres data-plane traffic. It classifies each accepted
// connection by its first bytes (see classifyPrefix) in its own goroutine —
// never in the accept loop — and routes it to one of two virtual listeners,
// so a silent or slow client can never stall Accept for every other pending
// connection (the same discipline WrapProxyProtocolListener's Accept
// follows, and for the same reason: see proxyproto.go).
type Demux struct {
	ln     net.Listener
	httpVL *virtualListener
	pgVL   *virtualListener
	closed atomic.Bool
}

// NewDemux begins accepting connections on ln — which may already be
// wrapped with WrapProxyProtocolListener, in which case its PROXY header (if
// any) is consumed lazily on the demux's own sniff Read, ahead of
// classification — and routes each one to HTTPListener or PostgresListener
// based on its first bytes.
func NewDemux(ln net.Listener) *Demux {
	d := &Demux{
		ln:     ln,
		httpVL: newVirtualListener(ln.Addr()),
		pgVL:   newVirtualListener(ln.Addr()),
	}
	go d.acceptLoop()
	return d
}

// HTTPListener returns the virtual listener carrying HTTP/CONNECT proxy
// traffic. Pass it to http.Server.Serve unmodified.
func (d *Demux) HTTPListener() net.Listener { return d.httpVL }

// PostgresListener returns the virtual listener carrying Postgres
// data-plane traffic. Pass it to PostgresServer.StartListener unmodified.
func (d *Demux) PostgresListener() net.Listener { return d.pgVL }

// Close closes the real listener and both virtual listeners. It's meant for
// a Demux used standalone (e.g. tests): an embedder that separately owns
// graceful shutdown of the two downstream servers — as gatekeeper.go does —
// should call StopAccepting instead and let each server close its own
// virtual listener as part of its own Shutdown/Stop.
func (d *Demux) Close() error {
	err := d.StopAccepting()
	d.httpVL.Close()
	d.pgVL.Close()
	return err
}

// StopAccepting closes only the real listener, so no further connections
// are accepted and classified. It deliberately leaves both virtual
// listeners open: PostgresServer.Shutdown/Stop and http.Server.Shutdown each
// close the virtual listener they were started on as part of their own
// graceful drain, and closing it out from under them here first would race
// their own closed-flag bookkeeping — for PostgresServer that would surface
// as a spurious "postgres accept loop exited" error log on an entirely
// ordinary shutdown.
func (d *Demux) StopAccepting() error {
	d.closed.Store(true)
	return d.ln.Close()
}

func (d *Demux) acceptLoop() {
	for {
		conn, err := d.ln.Accept()
		if err != nil {
			if !d.closed.Load() {
				slog.Error("demux accept loop exited", "subsystem", "proxy", "error", err)
			}
			return
		}
		go d.classifyAndDispatch(conn)
	}
}

// classifyAndDispatch runs in its own goroutine per connection — never in
// acceptLoop — so a silent or slow-to-classify client blocks only itself,
// not Accept for every other pending connection.
func (d *Demux) classifyAndDispatch(conn net.Conn) {
	proto, sniffed, err := sniffProtocol(conn)
	if err != nil {
		// Never log connection content — only that classification failed and
		// why (a timeout, a short read, or a closed peer), never any bytes.
		slog.Debug("demux: dropping connection", "subsystem", "proxy", "err", err)
		conn.Close()
		return
	}

	vl := d.httpVL
	if proto == demuxPostgres {
		vl = d.pgVL
	}
	slog.Debug("demux: classified connection", "subsystem", "proxy", "protocol", proto.String())
	if !vl.push(sniffed) {
		sniffed.Close()
	}
}

// sniffProtocol reads the first demuxSniffLen bytes of conn, bounded by
// demuxSniffDeadline, and classifies them. On success it returns a conn
// that replays those bytes before reading any more from the underlying
// connection (see demuxConn), with the read deadline it set cleared so only
// the downstream server's own timeouts apply from here on. On failure — the
// deadline expires with nothing sent (a silent client), the peer closes
// early (a short or malformed opener), or any other read error — it returns
// a non-nil error and the caller drops the connection.
func sniffProtocol(conn net.Conn) (demuxProtocol, net.Conn, error) {
	if err := conn.SetReadDeadline(time.Now().Add(demuxSniffDeadline)); err != nil {
		return demuxHTTP, nil, fmt.Errorf("set sniff deadline: %w", err)
	}
	prefix := make([]byte, demuxSniffLen)
	n, readErr := io.ReadFull(conn, prefix)
	clearErr := conn.SetReadDeadline(time.Time{})
	if readErr != nil {
		return demuxHTTP, nil, fmt.Errorf("read sniff prefix (%d/%d bytes): %w", n, demuxSniffLen, readErr)
	}
	if clearErr != nil {
		return demuxHTTP, nil, fmt.Errorf("clear sniff deadline: %w", clearErr)
	}
	return classifyPrefix(prefix), &demuxConn{Conn: conn, prefix: prefix}, nil
}
