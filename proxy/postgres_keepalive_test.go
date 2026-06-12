package proxy

import (
	"net"
	"testing"
)

// enableKeepAlive must enable keep-alive on a real TCP conn and be a safe
// no-op on a non-TCP conn (e.g. net.Pipe used in some tests).
func TestEnableKeepAlive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, ok := conn.(*net.TCPConn); !ok {
		t.Fatalf("expected *net.TCPConn, got %T", conn)
	}
	enableKeepAlive(conn) // must not panic; sets the socket option

	// Non-TCP conn: must be a no-op, not a panic.
	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()
	enableKeepAlive(p1)
}
