package proxy

import (
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pires/go-proxyproto"
)

// WrapProxyProtocolListener wraps ln with PROXY protocol v1/v2 parsing,
// matching HAProxy's per-bind `accept-proxy` semantics: a leading PROXY
// header is honored when present, and a connection that doesn't open with
// one falls back to its real TCP peer address (fail-open) rather than being
// rejected — so load balancer health checks and direct probes of the port
// keep working. The header-read is bounded by a 10s timeout, and a
// connection whose header is present but fails to parse is dropped and
// logged once at DEBUG (a connection with no header at all stays silent —
// that's the correct fail-open path, not an error).
//
// Both gatekeeper's HTTP/CONNECT listener and its Postgres data-plane
// listener call this helper so their PROXY protocol handling is
// byte-identical; see ProxyConfig.ProxyProtocol and
// PostgresConfig.ProxyProtocol.
func WrapProxyProtocolListener(ln net.Listener) net.Listener {
	ln = &proxyproto.Listener{
		Listener:          ln,
		ReadHeaderTimeout: 10 * time.Second,
		ConnPolicy: func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			return proxyproto.USE, nil
		},
	}
	return &proxyProtoLogListener{Listener: ln}
}

// proxyProtoLogListener wraps a *proxyproto.Listener so that a connection
// whose PROXY header fails to parse gets a single DEBUG log line before it's
// dropped. go-proxyproto has no error-callback hook for header parse
// failures in this version: ValidateHeader only runs against a
// *successfully* parsed header, and header parsing itself is lazy — it
// happens inside the returned Conn on the first Read/RemoteAddr, not in
// Accept. A malformed header (as opposed to a merely absent one, which is
// the correct, silent USE-policy fallback) therefore surfaces only as an
// error from Conn.Read, which callers otherwise treat as a dead connection
// and close without a trace.
type proxyProtoLogListener struct {
	net.Listener
}

func (l *proxyProtoLogListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	// Capture the raw peer address WITHOUT triggering the lazy PROXY header
	// parse. On a *proxyproto.Conn, RemoteAddr() (like Read()) blocks on
	// reading the header until the peer sends bytes or the 10s
	// ReadHeaderTimeout fires — calling it here would stall the accept loop
	// for every new connection behind a single silent client (a slow-loris,
	// or an LB TCP health check that opens a socket and waits). Raw() has no
	// such side effect, so read the address through it exclusively for a
	// proxyproto conn. Only a non-proxyproto conn — which this listener never
	// actually wraps, but guard defensively — needs the direct RemoteAddr().
	var peer net.Addr
	if pc, ok := conn.(*proxyproto.Conn); ok {
		peer = pc.Raw().RemoteAddr()
	} else {
		peer = conn.RemoteAddr()
	}
	return &proxyProtoLogConn{Conn: conn, peer: peer}, nil
}

// proxyProtoLogConn wraps an accepted connection to detect and log genuine
// PROXY header parse failures. Header parsing is lazy: it happens inside the
// wrapped proxyproto.Conn on the first Read, not in Accept, and a parse
// failure surfaces only as an error from that Read. A connection that simply
// has no PROXY header at all is not an error here (proxyproto's USE policy
// falls back to the real peer address for it) and must stay quiet.
type proxyProtoLogConn struct {
	net.Conn
	peer net.Addr
	once sync.Once
}

func (c *proxyProtoLogConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil && !errors.Is(err, proxyproto.ErrNoProxyProtocol) && strings.HasPrefix(err.Error(), "proxyproto:") {
		c.once.Do(func() {
			slog.Debug("dropping connection: malformed PROXY protocol header", "peer", c.peer.String(), "err", err)
		})
	}
	return n, err
}

// Raw returns the innermost non-PROXY-protocol connection, so a caller that
// needs the true transport conn (e.g. to enable TCP keep-alives via a
// *net.TCPConn type assertion) can get it without triggering a blocking
// PROXY header read: unlike RemoteAddr() or Read(), Raw() never touches the
// header.
func (c *proxyProtoLogConn) Raw() net.Conn {
	if pc, ok := c.Conn.(*proxyproto.Conn); ok {
		return pc.Raw()
	}
	return c.Conn
}
