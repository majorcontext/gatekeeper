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
	"testing"

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

	ca, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}

	backend := newGRPCServer(t, receivedHeaders)
	t.Cleanup(backend.Close)

	upstreamCAs := x509.NewCertPool()
	upstreamCAs.AddCert(backend.Certificate())

	backendAddr, _ := url.Parse(backend.URL)
	backendPort := 0
	fmt.Sscanf(backendAddr.Port(), "%d", &backendPort)

	p := NewProxy()
	p.SetCA(ca)
	p.SetUpstreamCAs(upstreamCAs)
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token != "grpctest" {
			return nil, false
		}
		return &RunContextData{
			Policy:           "permissive",
			HostGateway:      "api.modal.com",
			HostGatewayIP:    "127.0.0.1",
			AllowedHostPorts: []int{backendPort},
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

	backendURL = fmt.Sprintf("https://api.modal.com:%d", backendPort)
	return transport, backendURL
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
