package proxy

// demux_test.go tests the single-port multiplexer: classification of a
// connection's first bytes as HTTP/CONNECT proxy traffic or Postgres
// data-plane traffic, the virtual listeners that feed http.Server and
// PostgresServer unmodified, and the end-to-end wiring that lets both
// planes share one real listener.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// --- classification -------------------------------------------------------

func TestClassifyPrefix_PostgresSSLRequest(t *testing.T) {
	// length 00 00 00 08, code 04 d2 16 2f (80877103).
	prefix := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
	if got := classifyPrefix(prefix); got != demuxPostgres {
		t.Errorf("classifyPrefix(SSLRequest) = %v, want demuxPostgres", got)
	}
}

func TestClassifyPrefix_PostgresGSSENCRequest(t *testing.T) {
	// length 00 00 00 08, code 04 d2 16 30 (80877104).
	prefix := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x30}
	if got := classifyPrefix(prefix); got != demuxPostgres {
		t.Errorf("classifyPrefix(GSSENCRequest) = %v, want demuxPostgres", got)
	}
}

func TestClassifyPrefix_PostgresV3StartupMessage(t *testing.T) {
	tests := []struct {
		name   string
		length [4]byte
	}{
		// A real StartupMessage's length reflects the full message
		// (parameters included), which varies per connection — the
		// classifier must not care what it is, only that the protocol
		// version that follows is 3.0.
		{"typical length", [4]byte{0x00, 0x00, 0x00, 0x29}},
		{"minimal length", [4]byte{0x00, 0x00, 0x00, 0x08}},
		{"large length", [4]byte{0x00, 0x00, 0x01, 0x00}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix := append(tt.length[:], 0x00, 0x03, 0x00, 0x00)
			if got := classifyPrefix(prefix); got != demuxPostgres {
				t.Errorf("classifyPrefix(v3 StartupMessage, %s) = %v, want demuxPostgres", tt.name, got)
			}
		})
	}
}

func TestClassifyPrefix_HTTPDefaults(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
	}{
		{"GET", "GET / HTTP/1.1\r\n"},
		{"POST", "POST /x HTTP/1.1\r\n"},
		{"PUT", "PUT /x HTTP/1.1\r\n"},
		{"DELETE", "DELETE /x HTTP/1.1\r\n"},
		{"PATCH", "PATCH /x HTTP/1.1\r\n"},
		{"HEAD", "HEAD / HTTP/1.1\r\n"},
		{"OPTIONS", "OPTIONS * HTTP/1.1\r\n"},
		{"CONNECT", "CONNECT example.com:443 HTTP/1.1\r\n"},
		{"TRACE", "TRACE / HTTP/1.1\r\n"},
		// h2 client connection preface (RFC 7540 3.5).
		{"h2 preface", "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"},
		// Bytes that don't match any Postgres startup signature and aren't
		// even a plausible HTTP method still default to HTTP — the
		// classifier only positively matches Postgres.
		{"garbage", "\x01\x02\x03\x04\x05\x06\x07\x08"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix := []byte(tt.prefix)
			if len(prefix) < demuxSniffLen {
				t.Fatalf("test prefix %q shorter than demuxSniffLen (%d)", tt.prefix, demuxSniffLen)
			}
			if got := classifyPrefix(prefix[:demuxSniffLen]); got != demuxHTTP {
				t.Errorf("classifyPrefix(%q) = %v, want demuxHTTP", tt.name, got)
			}
		})
	}
}

// TestClassifyPrefix_LengthAloneIsNotEnoughToMatch guards against a
// classifier that keys only on the length field (00 00 00 08) shared by
// SSLRequest and GSSENCRequest: a StartupMessage-shaped 8-byte message (an
// implausibly small one, but not impossible) must not be misclassified just
// because its length happens to also be 8.
func TestClassifyPrefix_LengthAloneIsNotEnoughToMatch(t *testing.T) {
	prefix := []byte{0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00}
	if got := classifyPrefix(prefix); got != demuxPostgres {
		t.Errorf("classifyPrefix(8-byte v3 StartupMessage) = %v, want demuxPostgres (still a valid v3 startup signature)", got)
	}

	// But an SSLRequest-length message with neither the SSLRequest/GSSENCRequest
	// code nor the v3 protocol version must default to HTTP.
	prefix2 := []byte{0x00, 0x00, 0x00, 0x08, 0xff, 0xff, 0xff, 0xff}
	if got := classifyPrefix(prefix2); got != demuxHTTP {
		t.Errorf("classifyPrefix(length-8, unrecognized code) = %v, want demuxHTTP", got)
	}
}

// --- byte replay ------------------------------------------------------

// TestSniffProtocol_ReplaysPeekedBytesBeforeUnderlyingConn verifies that
// sniffProtocol's returned conn replays the sniffed prefix on Read before
// any further bytes reach the caller — the same hold-then-replay contract
// proxyProtoLogConn upholds for the PROXY protocol header.
func TestSniffProtocol_ReplaysPeekedBytesBeforeUnderlyingConn(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	payload := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	go func() {
		client.Write([]byte(payload))
	}()

	proto, sniffed, err := sniffProtocol(server)
	if err != nil {
		t.Fatalf("sniffProtocol: %v", err)
	}
	defer sniffed.Close()
	if proto != demuxHTTP {
		t.Fatalf("proto = %v, want demuxHTTP", proto)
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(sniffed, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(got) != payload {
		t.Errorf("replayed+continued bytes = %q, want %q", got, payload)
	}
}

// deadlineRecordingConn wraps a net.Conn and records every SetReadDeadline
// call, so a test can assert on the final deadline value without depending
// on real-time timing.
type deadlineRecordingConn struct {
	net.Conn
	mu    sync.Mutex
	calls []time.Time
}

func (c *deadlineRecordingConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.calls = append(c.calls, t)
	c.mu.Unlock()
	return c.Conn.SetReadDeadline(t)
}

func (c *deadlineRecordingConn) deadlineCalls() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]time.Time, len(c.calls))
	copy(out, c.calls)
	return out
}

// TestSniffProtocol_ClearsDeadlineOnSuccess verifies that a successful sniff
// clears the read deadline it set (the last SetReadDeadline call is the zero
// value), so the downstream server's own timeout governs subsequent reads
// instead of the sniff window silently persisting.
func TestSniffProtocol_ClearsDeadlineOnSuccess(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()

	rec := &deadlineRecordingConn{Conn: server}

	go func() { client.Write([]byte("GET / HTTP/1.1\r\n")) }()

	_, sniffed, err := sniffProtocol(rec)
	if err != nil {
		t.Fatalf("sniffProtocol: %v", err)
	}
	defer sniffed.Close()

	calls := rec.deadlineCalls()
	if len(calls) == 0 {
		t.Fatal("sniffProtocol never called SetReadDeadline")
	}
	last := calls[len(calls)-1]
	if !last.IsZero() {
		t.Errorf("last SetReadDeadline call = %v, want the zero value (no deadline), so the sniff window doesn't leak into the downstream server's own timeout handling", last)
	}
}

// TestSniffProtocol_ClearsDeadlineOnFailure verifies the deadline is cleared
// even when the sniff itself fails (a short connection), so a caller that
// reuses the raw conn after logging the drop never inherits a stale
// deadline either. This uses a real TCP loopback conn rather than
// net.Pipe: net.Pipe ties both ends' deadline machinery together, so once
// one side closes, SetReadDeadline on the other side starts failing too —
// which would mask the very call sequence this test verifies.
func TestSniffProtocol_ClearsDeadlineOnFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	acceptedCh := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(acceptedCh)
			return
		}
		acceptedCh <- c
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Fewer than demuxSniffLen bytes, then close: a short/malformed opener.
	if _, err := client.Write([]byte{0x01, 0x02}); err != nil {
		t.Fatalf("write: %v", err)
	}
	client.Close()

	server := <-acceptedCh
	if server == nil {
		t.Fatal("Accept failed")
	}
	defer server.Close()

	rec := &deadlineRecordingConn{Conn: server}
	_, _, sniffErr := sniffProtocol(rec)
	if sniffErr == nil {
		t.Fatal("sniffProtocol succeeded on a short connection, want an error")
	}

	calls := rec.deadlineCalls()
	if len(calls) < 2 {
		t.Fatalf("SetReadDeadline called %d times, want at least 2 (set, then clear)", len(calls))
	}
	last := calls[len(calls)-1]
	if !last.IsZero() {
		t.Errorf("last SetReadDeadline call = %v, want the zero value even on a failed sniff", last)
	}
}

// --- virtualListener --------------------------------------------------

type fakeConn struct {
	net.Conn
	closed bool
}

func (c *fakeConn) Close() error {
	c.closed = true
	return nil
}

func TestVirtualListener_PushThenAccept(t *testing.T) {
	vl := newVirtualListener(&net.TCPAddr{})
	c := &fakeConn{}
	if !vl.push(c) {
		t.Fatal("push returned false, want true")
	}
	got, err := vl.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if got != net.Conn(c) {
		t.Error("Accept returned a different conn than was pushed")
	}
}

func TestVirtualListener_CloseUnblocksAccept(t *testing.T) {
	vl := newVirtualListener(&net.TCPAddr{})
	errCh := make(chan error, 1)
	go func() {
		_, err := vl.Accept()
		errCh <- err
	}()
	// Give Accept a moment to block before closing.
	time.Sleep(20 * time.Millisecond)
	vl.Close()
	select {
	case err := <-errCh:
		if err != net.ErrClosed {
			t.Errorf("Accept error = %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not unblock after Close")
	}
}

func TestVirtualListener_PushAfterCloseReturnsFalseAndDoesNotLeak(t *testing.T) {
	vl := newVirtualListener(&net.TCPAddr{})
	vl.Close()
	c := &fakeConn{}
	if vl.push(c) {
		t.Error("push after Close returned true, want false")
	}
}

func TestVirtualListener_CloseClosesQueuedButUnacceptedConns(t *testing.T) {
	vl := newVirtualListener(&net.TCPAddr{})
	c := &fakeConn{}
	if !vl.push(c) {
		t.Fatal("push returned false, want true")
	}
	vl.Close()
	if !c.closed {
		t.Error("conn queued but never Accepted was not closed by Close, want it closed to avoid leaking the file descriptor")
	}
}

func TestVirtualListener_BacklogFullDropsInsteadOfBlocking(t *testing.T) {
	vl := newVirtualListener(&net.TCPAddr{})
	// Fill the backlog.
	for i := 0; i < demuxBacklog; i++ {
		if !vl.push(&fakeConn{}) {
			t.Fatalf("push %d failed before backlog was full", i)
		}
	}
	// One more must not block and must report failure.
	done := make(chan bool, 1)
	go func() { done <- vl.push(&fakeConn{}) }()
	select {
	case ok := <-done:
		if ok {
			t.Error("push into a full backlog returned true, want false")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("push into a full backlog blocked, want a non-blocking false")
	}
}

// --- Demux: routing -----------------------------------------------------

func newTestDemux(t *testing.T) (*Demux, net.Listener) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	d := NewDemux(ln)
	t.Cleanup(func() { d.Close() })
	return d, ln
}

func TestDemux_RoutesHTTPConnToHTTPListener(t *testing.T) {
	d, ln := newTestDemux(t)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	accepted := acceptWithTimeout(t, d.HTTPListener(), 2*time.Second)
	defer accepted.Close()

	buf := make([]byte, len("GET / HTTP/1.1\r\n"))
	if _, err := io.ReadFull(accepted, buf); err != nil {
		t.Fatalf("read replayed bytes: %v", err)
	}
	if !bytes.HasPrefix(buf, []byte("GET / HTTP/1.1")) {
		t.Errorf("replayed bytes = %q, want prefix %q", buf, "GET / HTTP/1.1")
	}

	select {
	case c := <-acceptAsync(d.PostgresListener()):
		if c != nil {
			c.Close()
		}
		t.Fatal("HTTP conn was also routed to the Postgres listener")
	case <-time.After(200 * time.Millisecond):
		// Expected: nothing arrives on the Postgres listener.
	}
}

func TestDemux_RoutesPostgresConnToPostgresListener(t *testing.T) {
	d, ln := newTestDemux(t)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	fe := pgproto3.NewFrontend(conn, conn)
	fe.Send(&pgproto3.SSLRequest{})
	if err := fe.Flush(); err != nil {
		t.Fatalf("send SSLRequest: %v", err)
	}

	accepted := acceptWithTimeout(t, d.PostgresListener(), 2*time.Second)
	defer accepted.Close()

	// SSLRequest is exactly 8 bytes on the wire: length(4) + code(4).
	buf := make([]byte, 8)
	if _, err := io.ReadFull(accepted, buf); err != nil {
		t.Fatalf("read replayed bytes: %v", err)
	}
	want := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
	if !bytes.Equal(buf, want) {
		t.Errorf("replayed bytes = %x, want %x", buf, want)
	}

	select {
	case c := <-acceptAsync(d.HTTPListener()):
		if c != nil {
			c.Close()
		}
		t.Fatal("Postgres conn was also routed to the HTTP listener")
	case <-time.After(200 * time.Millisecond):
	}
}

func acceptWithTimeout(t *testing.T, ln net.Listener, timeout time.Duration) net.Conn {
	t.Helper()
	ch := acceptAsync(ln)
	select {
	case c := <-ch:
		if c == nil {
			t.Fatal("Accept returned a nil conn")
		}
		return c
	case <-time.After(timeout):
		t.Fatalf("Accept on %v timed out after %v", ln.Addr(), timeout)
		return nil
	}
}

func acceptAsync(ln net.Listener) <-chan net.Conn {
	ch := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			ch <- nil
			return
		}
		ch <- c
	}()
	return ch
}

// TestDemux_SilentClientDoesNotBlockOtherAccepts guards the same class of bug
// TestWrapProxyProtocolListenerAcceptDoesNotBlockOnSilentClient guards in
// proxyproto_test.go: classification must happen in a per-connection
// goroutine, never in the shared accept loop, so one silent client can never
// stall Accept for every other pending connection.
func TestDemux_SilentClientDoesNotBlockOtherAccepts(t *testing.T) {
	d, ln := newTestDemux(t)

	silent, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial (silent): %v", err)
	}
	defer silent.Close()
	// Deliberately write nothing.

	normal, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial (normal): %v", err)
	}
	defer normal.Close()
	if _, err := normal.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The 2s bound is well clear of demuxSniffDeadline (10s): a correct demux
	// classifies the normal connection immediately, independent of the
	// silent one still being sniffed in its own goroutine.
	accepted := acceptWithTimeout(t, d.HTTPListener(), 2*time.Second)
	accepted.Close()
}

// TestDemux_MalformedShortConnDroppedNoPanic verifies that a connection
// which sends fewer than demuxSniffLen bytes and then closes is dropped —
// routed to neither virtual listener — without panicking the dispatcher, and
// that the drop is logged at DEBUG.
func TestDemux_MalformedShortConnDroppedNoPanic(t *testing.T) {
	buf := captureSlogText(t)
	d, ln := newTestDemux(t)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := conn.Write([]byte{0x01, 0x02}); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.Close()

	select {
	case c := <-acceptAsync(d.HTTPListener()):
		if c != nil {
			c.Close()
		}
		t.Fatal("short/malformed conn was routed to the HTTP listener, want dropped")
	case <-time.After(300 * time.Millisecond):
	}
	select {
	case c := <-acceptAsync(d.PostgresListener()):
		if c != nil {
			c.Close()
		}
		t.Fatal("short/malformed conn was routed to the Postgres listener, want dropped")
	case <-time.After(300 * time.Millisecond):
	}

	got := waitForLogContaining(buf, "demux")
	if !strings.Contains(got, "demux") {
		t.Errorf("log output = %q, want a DEBUG line mentioning the demux dropping the connection", got)
	}
}

// --- Demux: lifecycle -----------------------------------------------------

func TestDemux_CloseClosesRealListenerAndBothVirtualListeners(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	d := NewDemux(ln)
	addr := ln.Addr().String()

	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		t.Error("dial succeeded after Close, want the real listener closed")
	}
	if _, err := d.HTTPListener().Accept(); err != net.ErrClosed {
		t.Errorf("HTTPListener().Accept() after Close = %v, want net.ErrClosed", err)
	}
	if _, err := d.PostgresListener().Accept(); err != net.ErrClosed {
		t.Errorf("PostgresListener().Accept() after Close = %v, want net.ErrClosed", err)
	}
}

// TestDemux_StopAcceptingLeavesVirtualListenersOpen verifies StopAccepting's
// narrower contract (used by gatekeeper.go, which owns the two downstream
// servers' own graceful shutdown): the real listener stops taking new
// connections, but both virtual listeners stay open for their owners to
// close in their own time.
func TestDemux_StopAcceptingLeavesVirtualListenersOpen(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	d := NewDemux(ln)
	addr := ln.Addr().String()

	if err := d.StopAccepting(); err != nil {
		t.Fatalf("StopAccepting: %v", err)
	}

	if _, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		t.Error("dial succeeded after StopAccepting, want the real listener closed")
	}

	// Both virtual listeners must still be open — pushing into them and
	// Accepting must still work — until their owners close them.
	c := &fakeConn{}
	if !d.HTTPListener().(*virtualListener).push(c) {
		t.Fatal("push into HTTP virtual listener failed after StopAccepting, want it still open")
	}
	got, err := d.HTTPListener().Accept()
	if err != nil {
		t.Fatalf("Accept on HTTP virtual listener after StopAccepting: %v", err)
	}
	if got != net.Conn(c) {
		t.Error("Accept returned a different conn than was pushed")
	}

	d.HTTPListener().Close()
	d.PostgresListener().Close()
}

// --- end-to-end: both planes share one port -------------------------------

// newDemuxE2ESetup wires an http.Server and a PostgresServer onto one shared
// Demux listener — exactly how gatekeeper.go wires them when
// postgres.port == proxy.port — backed by a real HTTPS backend (for
// CONNECT + TLS interception + credential injection) and a real fake
// Postgres server (for SCRAM upstream auth). ln may already be wrapped
// (e.g. with WrapProxyProtocolListener); the caller retains it to dial
// against.
type demuxE2ESetup struct {
	CA           *CA
	Proxy        *Proxy
	Backend      *httptest.Server
	Postgres     *PostgresServer
	FakePostgres *fakePostgresServer
	Addr         string
	ReceivedAuth func() string
}

func newDemuxE2ESetup(t *testing.T, ln net.Listener) *demuxE2ESetup {
	t.Helper()

	ca, err := generateCA()
	if err != nil {
		t.Fatalf("generateCA: %v", err)
	}

	var mu sync.Mutex
	var receivedAuth string
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.Write([]byte("ok"))
	}))
	t.Cleanup(backend.Close)

	fake := startFakePostgres(t, "ep-foo-123.aws.neon.tech", "app_rw", "real-password")

	p := NewProxy()
	p.SetCA(ca)
	// Trust both upstream TLS identities the shared listener will need to
	// reach: the HTTPS backend (CONNECT-relayed) and the fake Postgres
	// server (SCRAM upstream).
	combinedCAs := x509.NewCertPool()
	combinedCAs.AddCert(backend.Certificate())
	combinedCAs.AddCert(fake.cert.Leaf)
	p.SetUpstreamCAs(combinedCAs)
	// No proxy.SetAuthToken: leaving it unset means both planes accept any
	// token ("localhost trust", matching HTTP's and Postgres's behavior when
	// no auth is configured) — the run-token literal below exists only to
	// exercise the Postgres password-carries-the-token wire format, not to
	// be validated against anything.
	p.SetPostgresResolver("*.neon.tech", NewStaticPostgresResolver("real-password"))
	p.SetCredentialWithGrant(mustParseURL(backend.URL).Hostname(), "Authorization", "Bearer test-token-123", "test-grant")

	dx := NewDemux(ln)
	t.Cleanup(func() { dx.Close() })

	httpServer := &http.Server{Handler: p}
	go func() { _ = httpServer.Serve(dx.HTTPListener()) }()
	t.Cleanup(func() { httpServer.Close() })

	pg := NewPostgresServer(p)
	pg.dialUpstream = func(_ context.Context, _ string) (string, error) {
		return fake.addr, nil
	}
	if err := pg.StartListener(dx.PostgresListener()); err != nil {
		t.Fatalf("StartListener: %v", err)
	}
	t.Cleanup(pg.Stop)

	return &demuxE2ESetup{
		CA:           ca,
		Proxy:        p,
		Backend:      backend,
		Postgres:     pg,
		FakePostgres: fake,
		Addr:         ln.Addr().String(),
		ReceivedAuth: func() string {
			mu.Lock()
			defer mu.Unlock()
			return receivedAuth
		},
	}
}

// TestDemuxEndToEnd_HTTPAndPostgresShareOnePort is the core scenario this
// feature exists for: a real HTTP CONNECT request with TLS interception and
// credential injection, and a real Postgres handshake authenticated and
// relayed upstream, both succeed against the SAME listener address — proving
// http.Server and PostgresServer genuinely run unmodified against their
// virtual listeners.
func TestDemuxEndToEnd_HTTPAndPostgresShareOnePort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	setup := newDemuxE2ESetup(t, ln)

	// --- HTTP CONNECT + TLS interception + credential injection ---
	clientCAs := x509.NewCertPool()
	clientCAs.AppendCertsFromPEM(setup.CA.CertPEM())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(mustParseURL("http://" + setup.Addr)),
			TLSClientConfig: &tls.Config{RootCAs: clientCAs},
		},
	}
	resp, err := client.Get(setup.Backend.URL + "/api/data")
	if err != nil {
		t.Fatalf("HTTP request through shared listener: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200", resp.StatusCode)
	}
	if got := setup.ReceivedAuth(); got != "Bearer test-token-123" {
		t.Errorf("backend Authorization = %q, want %q", got, "Bearer test-token-123")
	}

	// --- Postgres handshake + SCRAM upstream + query relay ---
	conn, err := connectThroughGatekeeper(t, setup.Postgres, caTrustPool(t, setup.CA),
		"ep-foo-123.aws.neon.tech", "app_rw", "appdb", "run-token")
	if err != nil {
		t.Fatalf("connect through shared listener (postgres): %v", err)
	}
	res, err := conn.Exec(context.Background(), "SELECT 1").ReadAll()
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if len(res) == 0 || res[0].Err != nil {
		t.Fatalf("query result = %+v", res)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn.Close(ctx)
}

// TestDemuxEndToEnd_ProxyProtocolAdvertisedAddrOnBothPlanes verifies the
// PROXY protocol interaction: a shared listener wrapped with
// WrapProxyProtocolListener strips a leading PROXY v1 header lazily on the
// demux's own sniff Read (before classification), for both planes — so the
// advertised client address, not the raw loopback test-dialer address,
// reaches each plane's request log.
func TestDemuxEndToEnd_ProxyProtocolAdvertisedAddrOnBothPlanes(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln := WrapProxyProtocolListener(base)
	setup := newDemuxE2ESetup(t, ln)

	proxyHeader := "PROXY TCP4 100.52.56.181 10.0.0.1 51234 443\r\n"

	t.Run("http", func(t *testing.T) {
		// A fresh logCapture per subtest: the two subtests share setup.Proxy,
		// and reinstalling the logger here (rather than sharing one capture
		// across both) keeps each subtest's "exactly one entry" assertion
		// from racing the other subtest's request.
		cap := &logCapture{}
		setup.Proxy.SetLogger(cap.log)

		conn, err := net.Dial("tcp", setup.Addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte(proxyHeader)); err != nil {
			t.Fatalf("write PROXY header: %v", err)
		}

		backendAddr := mustParseURL(setup.Backend.URL).Host
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", backendAddr, backendAddr)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("read CONNECT response: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
		}

		clientCAs := x509.NewCertPool()
		clientCAs.AppendCertsFromPEM(setup.CA.CertPEM())
		tlsConn := tls.Client(conn, &tls.Config{RootCAs: clientCAs, ServerName: mustParseURL(setup.Backend.URL).Hostname()})
		if err := tlsConn.Handshake(); err != nil {
			t.Fatalf("TLS handshake: %v", err)
		}
		defer tlsConn.Close()

		fmt.Fprintf(tlsConn, "GET /api/data HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", backendAddr)
		innerResp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
		if err != nil {
			t.Fatalf("read inner response: %v", err)
		}
		io.ReadAll(innerResp.Body)
		innerResp.Body.Close()

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
			t.Errorf("ClientAddr host = %q, want 100.52.56.181 (PROXY-header source)", host)
		}
	})

	t.Run("postgres", func(t *testing.T) {
		cap := &logCapture{}
		setup.Proxy.SetLogger(cap.log)

		raw, err := net.Dial("tcp", setup.Addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		if _, err := raw.Write([]byte(proxyHeader)); err != nil {
			raw.Close()
			t.Fatalf("write PROXY header: %v", err)
		}

		msg, conn := pgClientHandshakeOnConn(t, raw, "ep-foo-123.aws.neon.tech", caTrustPool(t, setup.CA), "app_rw", "appdb", "run-token")
		if _, ok := msg.(*pgproto3.AuthenticationOk); !ok {
			conn.Close()
			t.Fatalf("expected AuthenticationOk, got %T", msg)
		}
		// The audit log entry is written when the relay completes, after the
		// client disconnects — close now so the log-wait loop below doesn't
		// race a still-open, still-relaying connection.
		conn.Close()

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
			t.Errorf("ClientAddr host = %q, want 100.52.56.181 (PROXY-header source)", host)
		}
	})
}
