package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func startUpstreamTCP(t *testing.T) (addr string, accepted <-chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ch := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
			ch <- c
		}
	}()
	return ln.Addr().String(), ch
}

func connectThrough(t *testing.T, proxyAddr, target string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("CONNECT response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", resp.StatusCode)
	}
	return c, br
}

func assertClosedByPeer(t *testing.T, c net.Conn, r interface{ Read([]byte) (int, error) }, what string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := r.Read(make([]byte, 1))
	if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("%s still open after Stop: read err = %v, want closed connection", what, err)
	}
}

func TestServerStopClosesCONNECTTunnel(t *testing.T) {
	upstream, accepted := startUpstreamTCP(t)
	s := NewServer(NewProxy())
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	client, br := connectThrough(t, s.Addr(), upstream)
	up := <-accepted

	if err := s.Stop(context.Background()); err != nil {
		t.Fatalf("Stop = %v, want nil", err)
	}

	assertClosedByPeer(t, client, br, "client tunnel conn")
	assertClosedByPeer(t, up, up, "upstream tunnel conn")
}

func TestServerStopClosesInterceptedConnection(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(backend.Close)
	ca, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}
	p := NewProxy()
	p.SetCA(ca)
	up := x509.NewCertPool()
	up.AddCert(backend.Certificate())
	p.SetUpstreamCAs(up)
	s := NewServer(p)
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}

	target := backend.Listener.Addr().String()
	raw, br := connectThrough(t, s.Addr(), target)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM())
	tc := tls.Client(&bufferedConn{Conn: raw, r: br}, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("handshake through interception: %v", err)
	}

	if err := s.Stop(context.Background()); err != nil {
		t.Fatalf("Stop = %v, want nil", err)
	}

	assertClosedByPeer(t, raw, tc, "intercepted client conn")
}

func TestProxyRefusesConnectionsAfterCloseConnections(t *testing.T) {
	upstream, _ := startUpstreamTCP(t)
	p := NewProxy()
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	if err := p.CloseConnections(context.Background()); err != nil {
		t.Fatal(err)
	}

	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstream, upstream)
	br := bufio.NewReader(c)
	if resp, err := http.ReadResponse(br, nil); err == nil && resp.StatusCode == http.StatusOK {
		t.Fatal("CONNECT after CloseConnections was established, want it refused")
	}
}

func TestCAGenerateCertCacheEvictsLeastRecentlyUsed(t *testing.T) {
	ca, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}
	ca.certCacheMax = 3
	gen := func(h string) *tls.Certificate {
		t.Helper()
		c, err := ca.GenerateCert(h)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	a := gen("a.example")
	b := gen("b.example")
	gen("c.example")
	if gen("a.example") != a {
		t.Fatal("a.example regenerated while cached")
	}
	gen("d.example")
	if n := len(ca.certCache); n != 3 {
		t.Fatalf("cert cache holds %d entries, want 3", n)
	}
	if gen("a.example") != a {
		t.Error("recently used a.example was evicted")
	}
	b2 := gen("b.example")
	if b2 == b {
		t.Error("least recently used b.example was not evicted")
	}
	leaf, err := x509.ParseCertificate(b2.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM())
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "b.example"}); err != nil {
		t.Fatalf("regenerated cert does not verify: %v", err)
	}
}

func TestServerStopClosesTunnelWhileRequestDrains(t *testing.T) {
	inHandler := make(chan struct{})
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(inHandler)
		<-release
	}))
	t.Cleanup(backend.Close)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	tunnelTarget, _ := startUpstreamTCP(t)
	s := NewServer(NewProxy())
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	tunnel, br := connectThrough(t, s.Addr(), tunnelTarget)

	slow, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { slow.Close() })
	fmt.Fprintf(slow, "GET %s/ HTTP/1.1\r\nHost: %s\r\n\r\n", backend.URL, backend.Listener.Addr())
	<-inHandler

	stopped := make(chan error, 1)
	go func() { stopped <- s.Stop(context.Background()) }()

	assertClosedByPeer(t, tunnel, br, "tunnel during request drain")
	close(release)
	if err := <-stopped; err != nil {
		t.Fatalf("Stop = %v, want nil", err)
	}
}
