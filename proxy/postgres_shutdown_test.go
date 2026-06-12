package proxy

import (
	"context"
	"testing"
	"time"
)

// Shutdown with no active connections returns promptly with no error.
func TestPostgresServerShutdownDrainsCleanly(t *testing.T) {
	ca, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}
	p := NewProxy()
	p.SetCA(ca)
	srv := NewPostgresServer(p)
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown with no active conns = %v, want nil", err)
	}
}

// Shutdown force-closes a still-active connection when the deadline expires,
// and reports the deadline error rather than blocking forever on the relay.
func TestPostgresServerShutdownForceClosesActiveConn(t *testing.T) {
	const host = "ep-foo-123.aws.neon.tech"
	fake := startFakePostgres(t, host, "app_rw", "real-password")

	ca, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}
	p := NewProxy()
	p.SetCA(ca)
	p.SetUpstreamCAs(fake.certPool)
	p.SetAuthToken("run-token")
	p.SetPostgresResolver("*.neon.tech", NewStaticPostgresResolver("real-password"))
	srv := NewPostgresServer(p)
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	srv.dialUpstream = func(ctx context.Context, h string) (string, error) { return fake.addr, nil }

	conn, err := connectThroughGatekeeper(t, srv, caTrustPool(t, ca), host, "app_rw", "appdb", "run-token")
	if err != nil {
		t.Fatalf("connect through gatekeeper: %v", err)
	}
	defer conn.Close(context.Background())

	// The connection is open and idle, so its relay goroutines are blocked on
	// Receive. Shutdown must hit the deadline, force-close the connection, and
	// return the deadline error rather than hanging.
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	if err := srv.Shutdown(ctx); err == nil {
		t.Fatal("Shutdown with an active idle conn = nil, want a deadline error")
	}

	if _, err := conn.Exec(context.Background(), "SELECT 1").ReadAll(); err == nil {
		t.Error("expected a query to fail after the connection was force-closed")
	}
}
