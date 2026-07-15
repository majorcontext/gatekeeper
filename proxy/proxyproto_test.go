package proxy

import (
	"net"
	"testing"
	"time"
)

// TestWrapProxyProtocolListenerAcceptDoesNotBlockOnSilentClient guards against
// a slow-loris stall of the whole accept loop. WrapProxyProtocolListener's
// Accept must NOT trigger the lazy PROXY header parse: on a *proxyproto.Conn,
// RemoteAddr() (and Read()) block on reading the header until bytes arrive or
// the 10s ReadHeaderTimeout fires. If Accept calls RemoteAddr() on the
// proxyproto conn, a single client that connects and sends nothing (a
// slow-loris, or just an LB TCP health check that opens a socket and waits)
// stalls Accept — and therefore every other pending connection on that
// listener — for the full timeout. Accept must capture the raw peer address
// via Raw().RemoteAddr(), which has no such side effect.
func TestWrapProxyProtocolListenerAcceptDoesNotBlockOnSilentClient(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln := WrapProxyProtocolListener(base)
	defer ln.Close()

	// Connect but send nothing — the silent-client / slow-loris case.
	dialConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer dialConn.Close()

	accepted := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		accepted <- c
	}()

	// The bug hangs Accept for the full 10s ReadHeaderTimeout; a 2s bound is
	// well clear of that and non-flaky, since a correct Accept returns as soon
	// as the connection is accepted (no header read at all).
	select {
	case c := <-accepted:
		c.Close()
	case err := <-errCh:
		t.Fatalf("Accept returned an error: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("Accept blocked on a silent client for >2s: the accept loop stalls until ReadHeaderTimeout because RemoteAddr() triggers the lazy blocking PROXY header read in Accept")
	}
}

// TestUnderlyingTCPConnUnwrapsWrappedListenerConn verifies that a connection
// accepted through WrapProxyProtocolListener — a proxyProtoLogConn over a
// proxyproto.Conn over the transport *net.TCPConn — can still be unwrapped to
// its underlying *net.TCPConn via the Raw() accessor, so enableKeepAlive's
// keep-alive settings reach the real socket. Without the unwrap, a direct
// *net.TCPConn assertion fails through the wrapper layers and keep-alive setup
// silently no-ops on a PROXY-protocol-wrapped listener.
func TestUnderlyingTCPConnUnwrapsWrappedListenerConn(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln := WrapProxyProtocolListener(base)
	defer ln.Close()

	dialConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer dialConn.Close()

	acceptedCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		acceptedCh <- c
	}()

	var accepted net.Conn
	select {
	case accepted = <-acceptedCh:
	case err := <-errCh:
		t.Fatalf("Accept returned an error: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("Accept timed out")
	}
	defer accepted.Close()

	// Precondition: the wrapper layers hide the *net.TCPConn, so a naive direct
	// assertion (what enableKeepAlive would do without the unwrap) fails — which
	// is exactly why the Raw() unwrap is load-bearing.
	if _, ok := accepted.(*net.TCPConn); ok {
		t.Fatal("expected the accepted conn to hide its *net.TCPConn behind the proxyproto wrappers")
	}

	tc, ok := underlyingTCPConn(accepted)
	if !ok {
		t.Fatal("underlyingTCPConn did not reach the *net.TCPConn through proxyProtoLogConn + proxyproto.Conn; keep-alives would silently no-op on a PROXY-protocol-wrapped listener")
	}
	if tc == nil {
		t.Fatal("underlyingTCPConn returned a nil *net.TCPConn with ok=true")
	}

	// The whole point: enableKeepAlive must run against the real socket without
	// panicking on the wrapped conn.
	enableKeepAlive(accepted)
}
