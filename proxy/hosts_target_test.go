package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// Characters net/http maps to "." before it dials.
const (
	ideographicFullStop = "。"
	fullwidthFullStop   = "．"
	halfwidthFullStop   = "｡"
)

// rawStatus serves one raw request through p and returns the response status.
// It bypasses net/http's client so the request line reaches the proxy as written.
func rawStatus(t *testing.T, p *Proxy, raw string) int {
	t.Helper()
	srv := httptest.NewServer(p)
	defer srv.Close()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("status line for %q: %v", raw, err)
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		t.Fatalf("bad status line %q", line)
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		t.Fatalf("bad status line %q", line)
	}
	return code
}

func absoluteForm(target string) string {
	return "GET " + target + " HTTP/1.1\r\nHost: ignored\r\nConnection: close\r\n\r\n"
}

func connectRequest(target string) string {
	return "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
}

// recordingTransport replaces the shared upstream transport and records what
// the proxy would send: the name it would dial and the credential with it.
type recordingTransport struct {
	mu   sync.Mutex
	reqs []*http.Request
}

func (rt *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.mu.Lock()
	rt.reqs = append(rt.reqs, r)
	rt.mu.Unlock()
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
}

func useRecordingTransport(t *testing.T) *recordingTransport {
	t.Helper()
	rt := &recordingTransport{}
	old := httpTransport
	httpTransport = rt
	t.Cleanup(func() { httpTransport = old })
	return rt
}

func TestProxy_AbsoluteFormTargets(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		status   int
		wantHost string // host the transport receives; "" when nothing is forwarded
		wantAuth string
	}{
		{"one label", "http://pr-1.meetneptune.dev/", 200, "pr-1.meetneptune.dev", "Bearer prefix"},
		{"uppercase", "http://PR-1.MeetNeptune.DEV/", 200, "PR-1.MeetNeptune.DEV", "Bearer prefix"},
		{"trailing root dot", "http://pr-1.meetneptune.dev./", 200, "pr-1.meetneptune.dev", "Bearer prefix"},
		{"suffix continues", "http://pr-1.meetneptune.devx/", 200, "pr-1.meetneptune.devx", ""},
		{"two labels", "http://pr-1.evil.meetneptune.dev/", 200, "pr-1.evil.meetneptune.dev", ""},
		{"ideographic full stop", "http://pr-1" + ideographicFullStop + "evil.meetneptune.dev/", 200, "pr-1.evil.meetneptune.dev", ""},
		{"percent-encoded full stop", "http://pr-1%E3%80%82evil.meetneptune.dev/", 200, "pr-1.evil.meetneptune.dev", ""},
		{"suffix key, dotted capital I", "http://a.aİ.example/", 200, "a.xn--ai-sub.example", ""},
		{"exact key, dotted capital I", "http://aİ.example/", 200, "xn--ai-sub.example", ""},
		{"IPv6 literal", "http://[::1]:8080/", 200, "[::1]:8080", ""},
		{"empty label", "http://pr-1..meetneptune.dev/", 400, "", ""},
		{"zoned IPv6 under a suffix key", "http://[::ffff:192.0.2.1%25x.example.com]/", 400, "", ""},
		{"legacy numeric IPv4", "http://0177.0.0.1/", 400, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := useRecordingTransport(t)
			p := NewProxy()
			p.SetInsecureCredentialWithGrant("pr-*.meetneptune.dev", "Authorization", "Bearer prefix", "prefix")
			p.SetInsecureCredentialWithGrant("*.ai.example", "Authorization", "Bearer suffix", "suffix")
			p.SetInsecureCredentialWithGrant("ai.example", "Authorization", "Bearer exact", "exact")
			p.SetInsecureCredentialWithGrant("*.example.com", "Authorization", "Bearer wildcard", "wildcard")

			if got := rawStatus(t, p, absoluteForm(tt.target)); got != tt.status {
				t.Errorf("status = %d, want %d", got, tt.status)
			}
			if tt.wantHost == "" {
				if len(rt.reqs) != 0 {
					t.Fatalf("forwarded to %q, want no request", rt.reqs[0].URL.Host)
				}
				return
			}
			if len(rt.reqs) != 1 {
				t.Fatalf("transport got %d requests, want 1", len(rt.reqs))
			}
			out := rt.reqs[0]
			if out.URL.Host != tt.wantHost {
				t.Errorf("transport host = %q, want %q", out.URL.Host, tt.wantHost)
			}
			if got := out.Header.Get("Authorization"); got != tt.wantAuth {
				t.Errorf("Authorization sent to %q = %q, want %q", out.URL.Host, got, tt.wantAuth)
			}
		})
	}
}

// A resolver on "pr-*.example" outranks a static "*." credential only for a
// real single "pr-" label; a name that merely looks like one gets the static.
func TestProxy_PrefixResolverRanksOverStaticWildcard(t *testing.T) {
	tests := []struct {
		target   string
		wantAuth string
	}{
		{"http://pr-1.meetneptune.dev/", "Bearer resolver"},
		{"http://pr-1" + ideographicFullStop + "evil.meetneptune.dev/", "Bearer static"},
		{"http://www.meetneptune.dev/", "Bearer static"},
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			rt := useRecordingTransport(t)
			p := NewProxy()
			p.SetInsecureCredentialWithGrant("*.meetneptune.dev", "Authorization", "Bearer static", "static")
			p.SetCredentialResolver("pr-*.meetneptune.dev", func(context.Context, *http.Request, *http.Request, string) ([]CredentialHeader, error) {
				return []CredentialHeader{{AllowInsecure: true, Name: "Authorization", Value: "Bearer resolver", Grant: "resolver"}}, nil
			})
			if got := rawStatus(t, p, absoluteForm(tt.target)); got != 200 || len(rt.reqs) != 1 {
				t.Fatalf("status = %d, forwarded %d", got, len(rt.reqs))
			}
			if got := rt.reqs[0].Header.Get("Authorization"); got != tt.wantAuth {
				t.Errorf("Authorization sent to %q = %q, want %q", rt.reqs[0].URL.Host, got, tt.wantAuth)
			}
		})
	}
}

// CONNECT targets get the same treatment under each kind of allow pattern.
// net/http's server already answers 400 to a non-ASCII CONNECT authority.
func TestProxy_ConnectTargets(t *testing.T) {
	ca, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		allow  string
		target string
		want   int
	}{
		{"prefix: one label", "pr-*.meetneptune.dev", "pr-1.meetneptune.dev:443", 200},
		{"prefix: uppercase", "pr-*.meetneptune.dev", "PR-1.MeetNeptune.DEV:443", 200},
		{"prefix: trailing root dot", "pr-*.meetneptune.dev", "pr-1.meetneptune.dev.:443", 200},
		{"prefix: suffix continues", "pr-*.meetneptune.dev", "pr-1.meetneptune.devx:443", 407},
		{"prefix: two labels", "pr-*.meetneptune.dev", "pr-1.evil.meetneptune.dev:443", 407},
		{"prefix: ideographic full stop", "pr-*.meetneptune.dev", "pr-1" + ideographicFullStop + "evil.meetneptune.dev:443", 400},
		{"prefix: two trailing dots", "pr-*.meetneptune.dev", "pr-1.meetneptune.dev..:443", 400},
		{"prefix: IPv6 literal", "pr-*.meetneptune.dev", "[::1]:443", 407},
		{"exact: trailing root dot", "api.meetneptune.dev", "api.meetneptune.dev.:443", 200},
		{"suffix: trailing root dot", "*.meetneptune.dev", "a.meetneptune.dev.:443", 200},
		{"suffix: bare domain", "*.meetneptune.dev", "meetneptune.dev:443", 407},
		{"suffix: leading empty label", "*.meetneptune.dev", ".meetneptune.dev:443", 400},
		{"suffix: zoned IPv6", "*.example.com", "[::ffff:192.0.2.1%25x.example.com]:443", 400},
		{"legacy numeric IPv4", "api.meetneptune.dev", "0177.0.0.1:443", 400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewProxy()
			p.SetCA(ca)
			if err := p.SetNetworkPolicy("strict", []string{tt.allow}, nil); err != nil {
				t.Fatal(err)
			}
			if got := rawStatus(t, p, connectRequest(tt.target)); got != tt.want {
				t.Errorf("CONNECT %q under allow %q = %d, want %d", tt.target, tt.allow, got, tt.want)
			}
		})
	}
}

// openTunnel sends CONNECT hostPort through the proxy and completes TLS against
// the interception CA. proxyAuth is an optional Proxy-Authorization value.
func openTunnel(t *testing.T, proxyAddr, hostPort, serverName, proxyAuth string, ca *CA) *tls.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", hostPort, hostPort)
	if proxyAuth != "" {
		fmt.Fprintf(conn, "Proxy-Authorization: %s\r\n", proxyAuth)
	}
	io.WriteString(conn, "\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT %s: %v %v", hostPort, resp, err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.certPEM)
	tc := tls.Client(conn, &tls.Config{RootCAs: pool, ServerName: serverName})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	return tc
}

// innerStatus sends one request inside a tunnel and returns its status.
func innerStatus(t *testing.T, tc *tls.Conn, request string) int {
	t.Helper()
	io.WriteString(tc, request)
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// After CONNECT to H, a request inside the tunnel for another authority is
// refused before credential resolution or any dial: the proxy resolves
// credentials for H, so honoring another Host header would send H's credential
// to a virtual host the policy never checked.
func TestIntercept_InnerAuthorityMustMatchConnectTarget(t *testing.T) {
	var mu sync.Mutex
	var seen []string // Authorization of each request the backend received
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Write([]byte("ok"))
	}))
	setup.Proxy.SetCredentialWithGrant(setup.BackendHost, "Authorization", "Bearer secret", "g")
	var resolved []string // inner Host of each request the resolver ran for
	setup.Proxy.SetCredentialResolver(setup.BackendHost, func(_ context.Context, _, inner *http.Request, _ string) ([]CredentialHeader, error) {
		mu.Lock()
		resolved = append(resolved, inner.Host)
		mu.Unlock()
		return nil, nil
	})
	hostPort := mustParseURL(setup.Backend.URL).Host
	port := mustParseURL(setup.Backend.URL).Port()

	tests := []struct {
		name string
		host string // Host header
		line string // request line; the default is "GET /"
		want int
	}{
		{"same host and port", hostPort, "", 200},
		{"same host without port", setup.BackendHost, "", 200},
		{"other host", "attacker.example", "", 421},
		{"other host, same port", "attacker.example:" + port, "", 421},
		{"same host, other port", setup.BackendHost + ":1", "", 421},
		{"absolute-form for other host", hostPort, "GET https://attacker.example/", 421},
	}
	var wantResolved int
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mu.Lock()
			seen = nil
			mu.Unlock()
			line := tt.line
			if line == "" {
				line = "GET /"
			}
			tc := openTunnel(t, setup.ProxyServer.Listener.Addr().String(), hostPort, setup.BackendHost, "", setup.CA)
			got := innerStatus(t, tc, line+" HTTP/1.1\r\nHost: "+tt.host+"\r\nConnection: close\r\n\r\n")
			if got != tt.want {
				t.Errorf("status = %d, want %d", got, tt.want)
			}
			mu.Lock()
			defer mu.Unlock()
			if tt.want == 200 {
				wantResolved++
				if len(seen) != 1 || seen[0] != "Bearer secret" {
					t.Errorf("backend Authorization = %v, want [Bearer secret]", seen)
				}
			} else if len(seen) != 0 {
				t.Errorf("backend saw %v for a refused request", seen)
			}
		})
	}
	mu.Lock()
	defer mu.Unlock()
	if len(resolved) != wantResolved {
		t.Errorf("resolver ran for %q, want only the %d matching requests", resolved, wantResolved)
	}
}
