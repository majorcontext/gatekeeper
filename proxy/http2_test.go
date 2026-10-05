package proxy

// Black-box acceptance tests for HTTP/2 (gRPC) support through the
// TLS-intercepting proxy.  These tests drive the proxy through its HTTP
// CONNECT interface using a real http2.Transport, verifying that:
//   - the proxy negotiates h2 via ALPN on the client-facing TLS connection
//   - credential headers are injected into h2 requests
//   - the proxy forwards requests upstream over h2 when the backend supports it

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// bufferedConn wraps a net.Conn with a pre-filled bufio.Reader so bytes
// already consumed into the buffer (e.g., from reading the CONNECT response)
// are not lost when the connection is handed to tls.Client.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// newGRPCServer returns an httptest.Server that speaks HTTP/2 and handles
// minimal unary gRPC calls on any path.  receivedHeaders captures all
// request headers from the first call.
func newGRPCServer(t *testing.T, receivedHeaders *http.Header) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			http.Error(w, "require HTTP/2", http.StatusHTTPVersionNotSupported)
			return
		}
		if *receivedHeaders == nil {
			*receivedHeaders = r.Header.Clone()
		}

		// Read and discard the gRPC request frame (5-byte length-prefix + body).
		frame := make([]byte, 5)
		if _, err := io.ReadFull(r.Body, frame); err == nil {
			msgLen := binary.BigEndian.Uint32(frame[1:])
			io.CopyN(io.Discard, r.Body, int64(msgLen))
		}

		// gRPC trailers must be declared before WriteHeader.
		w.Header().Set("Trailer", "grpc-status")
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		// Minimal gRPC response: compressed-flag(0) + message-length(0) = 5 zero bytes.
		w.Write([]byte{0, 0, 0, 0, 0})
		w.(http.Flusher).Flush()
		// Setting grpc-status after Flush makes it a trailer in HTTP/2.
		w.Header().Set("grpc-status", "0")
	})

	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	return srv
}

// newGRPCProxySetup creates a TLS-intercepting proxy configured to inject
// Modal-style credentials for api.modal.com.  The fake gRPC backend is
// reachable via the HostGateway mechanism so the credential host check fires.
func newGRPCProxySetup(t *testing.T, receivedHeaders *http.Header) (transport *http2.Transport, backendURL string) {
	t.Helper()

	backend := newGRPCServer(t, receivedHeaders)
	t.Cleanup(backend.Close)
	transport, backendURL, _ = newHTTP2ProxySetup(t, backend)
	return transport, backendURL
}

func newHTTP2ProxySetup(t *testing.T, backends ...*httptest.Server) (transport *http2.Transport, backendURL string, p *Proxy) {
	t.Helper()
	ca, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}

	upstreamCAs := x509.NewCertPool()
	var backendPorts []int
	for _, backend := range backends {
		upstreamCAs.AddCert(backend.Certificate())
		backendAddr, _ := url.Parse(backend.URL)
		backendPort := 0
		fmt.Sscanf(backendAddr.Port(), "%d", &backendPort)
		backendPorts = append(backendPorts, backendPort)
	}

	p = NewProxy()
	p.SetCA(ca)
	p.SetUpstreamCAs(upstreamCAs)
	t.Cleanup(p.CloseIdleConnections)
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token != "grpctest" {
			return nil, false
		}
		return &RunContextData{
			Policy:           "permissive",
			HostGateway:      "api.modal.com",
			HostGatewayIP:    "127.0.0.1",
			AllowedHostPorts: backendPorts,
			Credentials: map[string][]credentialHeader{
				"api.modal.com": {
					{Name: "x-modal-token-id", Value: "token-id-test", Grant: "modal"},
					{Name: "x-modal-token-secret", Value: "token-secret-test", Grant: "modal"},
				},
			},
		}, true
	})

	proxyServer := httptest.NewServer(p)
	t.Cleanup(proxyServer.Close)

	clientCAs := x509.NewCertPool()
	clientCAs.AppendCertsFromPEM(ca.certPEM)

	proxyAddr := proxyServer.Listener.Addr().String()
	authHeader := "Basic " + basicAuth("user", "grpctest")

	// http2.Transport uses DialTLSContext to establish the connection.
	// We manually build the CONNECT tunnel first, then negotiate h2 via ALPN.
	transport = &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			conn, err := net.Dial("tcp", proxyAddr)
			if err != nil {
				return nil, fmt.Errorf("dial proxy: %w", err)
			}
			connectReq := "CONNECT " + addr + " HTTP/1.1\r\n" +
				"Host: " + addr + "\r\n" +
				"Proxy-Authorization: " + authHeader + "\r\n\r\n"
			if _, err := conn.Write([]byte(connectReq)); err != nil {
				conn.Close()
				return nil, fmt.Errorf("write CONNECT: %w", err)
			}
			// http.ReadResponse handles partial reads and validates the status line.
			// Wrap conn in a bufferedConn so any bytes pre-fetched by the
			// bufio.Reader are not lost before the TLS handshake consumes them.
			br := bufio.NewReader(conn)
			cresp, err := http.ReadResponse(br, nil)
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("read CONNECT response: %w", err)
			}
			cresp.Body.Close()
			if cresp.StatusCode != http.StatusOK {
				conn.Close()
				return nil, fmt.Errorf("CONNECT failed: %s", cresp.Status)
			}
			// Upgrade to TLS, advertising h2 in ALPN.
			serverName, _, _ := net.SplitHostPort(addr)
			tlsCfg := &tls.Config{
				RootCAs:    clientCAs,
				ServerName: serverName,
				NextProtos: []string{http2.NextProtoTLS},
			}
			tlsConn := tls.Client(&bufferedConn{Conn: conn, r: br}, tlsCfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, fmt.Errorf("TLS handshake: %w", err)
			}
			return tlsConn, nil
		},
	}

	t.Cleanup(transport.CloseIdleConnections)
	backendURL = fmt.Sprintf("https://api.modal.com:%d", backendPorts[0])
	return transport, backendURL, p
}

// TestHTTP2_GRPCCredentialInjection verifies that HTTP/2 (gRPC) requests
// through the CONNECT proxy succeed and receive credential injection.
//
// This test is expected to FAIL until HTTP/2 support is implemented in
// handleConnectWithInterception (proxy must advertise h2 in ALPN and use
// http2.ConfigureServer on the inner http.Server).
func TestHTTP2_GRPCCredentialInjection(t *testing.T) {
	var receivedHeaders http.Header
	transport, backendURL := newGRPCProxySetup(t, &receivedHeaders)

	// Minimal gRPC request frame: compressed=0, message-length=0.
	grpcBody := []byte{0, 0, 0, 0, 0}

	req, err := http.NewRequestWithContext(context.Background(),
		"POST", backendURL+"/modal.api.v1.AppService/ListApps",
		strings.NewReader(string(grpcBody)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("te", "trailers")

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("gRPC request through proxy failed: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	// grpc-status arrives as an HTTP/2 trailer — must read from resp.Trailer
	// (only populated after the body is fully consumed).
	if got := resp.Trailer.Get("grpc-status"); got != "0" {
		t.Errorf("grpc-status trailer = %q, want 0 (header: %q)", got, resp.Header.Get("grpc-status"))
	}

	if receivedHeaders == nil {
		t.Fatal("backend received no request — proxy may have blocked or h2 ALPN not negotiated")
	}
	if got := receivedHeaders.Get("x-modal-token-id"); got != "token-id-test" {
		t.Errorf("x-modal-token-id = %q, want token-id-test", got)
	}
	if got := receivedHeaders.Get("x-modal-token-secret"); got != "token-secret-test" {
		t.Errorf("x-modal-token-secret = %q, want token-secret-test", got)
	}
}

func TestHTTP2_UpstreamALPN(t *testing.T) {
	for _, tc := range []struct {
		name      string
		protos    []string
		wantProto int
	}{
		{"h1-only", []string{"http/1.1"}, 1},
		{"no-alpn", []string{}, 1},
		{"h2", []string{"h2", "http/1.1"}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			release := make(chan struct{})
			defer close(release)
			backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor != tc.wantProto {
					t.Errorf("upstream protocol = %s, want HTTP/%d", r.Proto, tc.wantProto)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != `{"name":"box.event"}` {
					t.Errorf("event body = %q, error = %v", body, err)
				}
				if r.Header.Get("x-modal-token-id") != "token-id-test" {
					t.Error("missing injected credential")
				}
				if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("Proxy-Connection") != "" {
					t.Error("proxy headers leaked upstream")
				}
				w.Header().Set("Trailer", "X-Event-Status")
				if tc.wantProto == 1 {
					w.Header().Set("Connection", "X-Hop")
					w.Header().Set("X-Hop", "must-not-forward")
				}
				w.Write([]byte("accepted\n"))
				w.(http.Flusher).Flush()
				<-release
				w.Header().Set("X-Event-Status", "ok")
			}))
			backend.EnableHTTP2 = tc.wantProto == 2
			backend.TLS = &tls.Config{NextProtos: tc.protos}
			backend.StartTLS()
			t.Cleanup(backend.Close)
			transport, backendURL, p := newHTTP2ProxySetup(t, backend)
			logs := make(chan RequestLogData, 1)
			p.SetLogger(func(data RequestLogData) { logs <- data })
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "POST", backendURL+"/e/test-key", strings.NewReader(`{"name":"box.event"}`))
			req.Header.Set("Proxy-Connection", "keep-alive")
			resp, err := transport.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				b, _ := io.ReadAll(resp.Body)
				t.Fatalf("POST /e/test-key status = %d, want 200: %s", resp.StatusCode, b)
			}
			if resp.ProtoMajor != 2 {
				t.Errorf("client protocol = %s, want HTTP/2", resp.Proto)
			}
			if resp.Header.Get("X-Hop") != "" || resp.Header.Get("Connection") != "" {
				t.Error("hop-by-hop response headers leaked")
			}
			first := make([]byte, len("accepted\n"))
			if _, err := io.ReadFull(resp.Body, first); err != nil || string(first) != "accepted\n" {
				t.Fatalf("streamed body = %q, error = %v", first, err)
			}
			release <- struct{}{}
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				t.Fatal(err)
			}
			if got := resp.Trailer.Get("X-Event-Status"); got != "ok" {
				t.Errorf("trailer = %q, want ok", got)
			}
			select {
			case data := <-logs:
				if data.StatusCode != 200 || !data.AuthInjected || !data.InjectedHeaders["x-modal-token-id"] {
					t.Errorf("request log status = %d, injected = %v, headers = %v", data.StatusCode, data.AuthInjected, data.InjectedHeaders)
				}
				if data.RequestHeaders.Get("x-modal-token-id") != "" || data.RequestHeaders.Get("x-modal-token-secret") != "" {
					t.Error("injected credential values leaked into request log")
				}
			case <-ctx.Done():
				t.Fatal("missing request log")
			}
		})
	}
}

func TestHTTP2_UpstreamProtocolCache(t *testing.T) {
	var connections [2]atomic.Int32
	var backends []*httptest.Server
	for i, wantProto := range []int{1, 2} {
		backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor != wantProto {
				t.Errorf("upstream protocol = %s, want HTTP/%d", r.Proto, wantProto)
			}
			io.WriteString(w, "ok")
		}))
		backend.EnableHTTP2 = wantProto == 2
		backend.Config.ConnState = func(_ net.Conn, state http.ConnState) {
			if state == http.StateNew {
				connections[i].Add(1)
			}
		}
		backend.StartTLS()
		t.Cleanup(backend.Close)
		backends = append(backends, backend)
	}
	transport, _, _ := newHTTP2ProxySetup(t, backends...)
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	for range 3 {
		for _, backend := range backends {
			u, _ := url.Parse(backend.URL)
			resp, err := client.Get("https://api.modal.com:" + u.Port() + "/cached")
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || resp.StatusCode != 200 || string(body) != "ok" {
				t.Fatalf("cached request status = %d, body = %q, error = %v", resp.StatusCode, body, err)
			}
			transport.CloseIdleConnections()
		}
	}
	for i := range connections {
		if got := connections[i].Load(); got != 1 {
			t.Errorf("upstream %d TLS connections = %d, want 1 across client tunnels", i, got)
		}
	}
}

func TestHTTP2_UpstreamCAChange(t *testing.T) {
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	backend.EnableHTTP2 = true
	backend.StartTLS()
	t.Cleanup(backend.Close)
	transport, backendURL, p := newHTTP2ProxySetup(t, backend)
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	request := func(wantStatus int) {
		t.Helper()
		resp, err := client.Get(backendURL + "/trust")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != wantStatus {
			t.Fatalf("status after upstream CA change = %d, want %d", resp.StatusCode, wantStatus)
		}
		transport.CloseIdleConnections()
	}
	request(http.StatusOK)
	p.SetUpstreamCAs(x509.NewCertPool())
	request(http.StatusBadGateway)
	trusted := x509.NewCertPool()
	trusted.AddCert(backend.Certificate())
	p.SetUpstreamCAs(trusted)
	request(http.StatusOK)
}
