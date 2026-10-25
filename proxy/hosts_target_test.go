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

// Characters that net/http's transport maps to "." before it dials.
const (
	ideographicFullStop = "。"
	fullwidthFullStop   = "．"
	halfwidthFullStop   = "｡"
)

func TestValidateHostPattern_EmptyLabels(t *testing.T) {
	tests := []struct {
		pattern string
		valid   bool
	}{
		{"pr-*.meetneptune.dev", true},
		{"pr-*.com", false},
		{"pr-*.com.", false},
		{"pr-*..com", false},
		{"pr-*...", false},
		{"pr-*.example..com", false},
		{"pr-*.example.com.", false},
		{"pr-*.example.com.:8443", false},
		{"*.example.com.", false},
		{"*..example.com", false},
		{"example..com", false},
		{"example.com.", false},
		{".example.com", false},
		{"example.com", true},
		{"*.example.com", true},
		{"pr-*.münchen.de", false},
		{"münchen.de", false},
		{"*.münchen.de", false},
	}
	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			err := ValidateHostPattern(tt.pattern)
			if (err == nil) != tt.valid {
				t.Errorf("ValidateHostPattern(%q) = %v, want valid=%v", tt.pattern, err, tt.valid)
			}
		})
	}
}

func TestSetNetworkPolicy_RejectsBadPatterns(t *testing.T) {
	for _, pattern := range []string{"pr-*-x.example.com", "pr-*.com.", "pr-*..com", "*foo.example.com"} {
		p := NewProxy()
		if err := p.SetNetworkPolicy("permissive", []string{"kept.example.com"}, nil); err != nil {
			t.Fatal(err)
		}
		if err := p.SetNetworkPolicy("strict", []string{"ok.example.com", pattern}, nil); err == nil {
			t.Errorf("SetNetworkPolicy accepted %q", pattern)
		}
		if err := p.SetNetworkPolicyWithRules("strict", []string{pattern}, nil, nil, nil); err == nil {
			t.Errorf("SetNetworkPolicyWithRules accepted %q", pattern)
		}
		if len(p.allowedHosts) != 1 || p.allowedHosts[0].host != "kept.example.com" || p.policy != "permissive" {
			t.Errorf("a rejected %q changed state: policy=%q allowed=%v", pattern, p.policy, p.allowedHosts)
		}
	}
}

func TestSetCredential_IgnoresBadPatterns(t *testing.T) {
	p := NewProxy()
	for _, host := range []string{"pr-*.com.", "pr-*..com", "pr-*-x.example.com", "pr-*.münchen.de"} {
		p.SetCredentialWithGrant(host, "Authorization", "Bearer x", "g")
		p.SetCredentialResolver(host, func(context.Context, *http.Request, *http.Request, string) ([]CredentialHeader, error) {
			return nil, nil
		})
	}
	if len(p.credentials) != 0 || len(p.credentialResolvers) != 0 {
		t.Errorf("bad host keys were stored: credentials=%v resolvers=%d", p.credentials, len(p.credentialResolvers))
	}
}

// serveRaw sends raw bytes to the proxy and returns the response status code
// and the bytes after the status line. It bypasses net/http's client so the
// request line reaches the proxy exactly as written.
func serveRaw(t *testing.T, addr, raw string) int {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("reading status line for %q: %v", raw, err)
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

// recordingTransport replaces the shared upstream transport and records the
// requests the proxy would send, so a test sees the name that would be dialed
// and the credential that would go with it, without a network.
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
		wantHost string // host the transport receives; "" when the request must not be forwarded
		wantAuth string
	}{
		{"one label", "http://pr-1.meetneptune.dev/", 200, "pr-1.meetneptune.dev", "Bearer prefix"},
		{"uppercase", "http://PR-1.MeetNeptune.DEV/", 200, "PR-1.MeetNeptune.DEV", "Bearer prefix"},
		{"trailing root dot", "http://pr-1.meetneptune.dev./", 200, "pr-1.meetneptune.dev", "Bearer prefix"},
		{"suffix continues", "http://pr-1.meetneptune.devx/", 200, "pr-1.meetneptune.devx", ""},
		{"two labels", "http://pr-1.evil.meetneptune.dev/", 200, "pr-1.evil.meetneptune.dev", ""},
		{"ideographic full stop", "http://pr-1" + ideographicFullStop + "evil.meetneptune.dev/", 200, "pr-1.evil.meetneptune.dev", ""},
		{"fullwidth full stop", "http://pr-1" + fullwidthFullStop + "evil.meetneptune.dev/", 200, "pr-1.evil.meetneptune.dev", ""},
		{"halfwidth ideographic full stop", "http://pr-1" + halfwidthFullStop + "evil.meetneptune.dev/", 200, "pr-1.evil.meetneptune.dev", ""},
		{"percent-encoded full stop", "http://pr-1%E3%80%82evil.meetneptune.dev/", 200, "pr-1.evil.meetneptune.dev", ""},
		{"full stop before the suffix", "http://pr-1" + ideographicFullStop + "meetneptune.dev/", 200, "pr-1.meetneptune.dev", "Bearer prefix"},
		{"IPv6 literal", "http://[::1]:8080/", 200, "[::1]:8080", ""},
		{"suffix credential", "http://a.ai.example/", 200, "a.ai.example", "Bearer suffix"},
		{"exact credential", "http://ai.example/", 200, "ai.example", "Bearer exact"},
		{"capital I with dot above under a suffix key", "http://a.a\u0130.example/", 200, "a.xn--ai-sub.example", ""},
		{"capital I with dot above under an exact key", "http://a\u0130.example/", 200, "xn--ai-sub.example", ""},
		{"empty label", "http://pr-1..meetneptune.dev/", 400, "", ""},
		{"leading dot", "http://.meetneptune.dev/", 400, "", ""},
		{"two trailing dots", "http://pr-1.meetneptune.dev../", 400, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := useRecordingTransport(t)
			p := NewProxy()
			p.SetInsecureCredentialWithGrant("pr-*.meetneptune.dev", "Authorization", "Bearer prefix", "prefix")
			p.SetInsecureCredentialWithGrant("*.ai.example", "Authorization", "Bearer suffix", "suffix")
			p.SetInsecureCredentialWithGrant("ai.example", "Authorization", "Bearer exact", "exact")
			srv := httptest.NewServer(p)
			defer srv.Close()

			raw := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: ignored\r\nConnection: close\r\n\r\n", tt.target)
			if got := serveRaw(t, srv.Listener.Addr().String(), raw); got != tt.status {
				t.Errorf("status = %d, want %d", got, tt.status)
			}
			if tt.wantHost == "" {
				if len(rt.reqs) != 0 {
					t.Fatalf("forwarded %q, want no request", rt.reqs[0].URL.Host)
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

// A static credential on "*.example" and a resolver on "pr-*.example" must
// rank the same way for every spelling of one name: the resolver wins only
// for a single "pr-" label, and a name that merely looks like one gets the
// "*." credential, never the resolver's.
func TestProxy_PrefixResolverRanksOverStaticWildcard(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		wantAuth string
	}{
		{"one label", "http://pr-1.meetneptune.dev/", "Bearer resolver"},
		{"trailing root dot", "http://pr-1.meetneptune.dev./", "Bearer resolver"},
		{"two labels", "http://pr-1.evil.meetneptune.dev/", "Bearer static"},
		{"ideographic full stop", "http://pr-1" + ideographicFullStop + "evil.meetneptune.dev/", "Bearer static"},
		{"other label", "http://www.meetneptune.dev/", "Bearer static"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := useRecordingTransport(t)
			p := NewProxy()
			p.SetInsecureCredentialWithGrant("*.meetneptune.dev", "Authorization", "Bearer static", "static")
			p.SetCredentialResolver("pr-*.meetneptune.dev", func(context.Context, *http.Request, *http.Request, string) ([]CredentialHeader, error) {
				return []CredentialHeader{{AllowInsecure: true, Name: "Authorization", Value: "Bearer resolver", Grant: "resolver"}}, nil
			})
			srv := httptest.NewServer(p)
			defer srv.Close()

			raw := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: ignored\r\nConnection: close\r\n\r\n", tt.target)
			if got := serveRaw(t, srv.Listener.Addr().String(), raw); got != 200 {
				t.Fatalf("status = %d, want 200", got)
			}
			if len(rt.reqs) != 1 {
				t.Fatalf("transport got %d requests, want 1", len(rt.reqs))
			}
			if got := rt.reqs[0].Header.Get("Authorization"); got != tt.wantAuth {
				t.Errorf("Authorization sent to %q = %q, want %q", rt.reqs[0].URL.Host, got, tt.wantAuth)
			}
		})
	}
}

// CONNECT targets get the same treatment as absolute-form URLs, whichever
// kind of host pattern allows them. net/http's server already answers 400 to a
// CONNECT authority with non-ASCII bytes; those rows pin that it stays closed.
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
		{"prefix: fullwidth full stop", "pr-*.meetneptune.dev", "pr-1" + fullwidthFullStop + "evil.meetneptune.dev:443", 400},
		{"prefix: halfwidth ideographic full stop", "pr-*.meetneptune.dev", "pr-1" + halfwidthFullStop + "evil.meetneptune.dev:443", 400},
		{"prefix: two trailing dots", "pr-*.meetneptune.dev", "pr-1.meetneptune.dev..:443", 400},
		{"prefix: IPv6 literal", "pr-*.meetneptune.dev", "[::1]:443", 407},
		{"exact: trailing root dot", "api.meetneptune.dev", "api.meetneptune.dev.:443", 200},
		{"exact: uppercase", "api.meetneptune.dev", "API.meetneptune.dev:443", 200},
		{"exact: other host", "api.meetneptune.dev", "api.meetneptune.devx:443", 407},
		{"suffix: trailing root dot", "*.meetneptune.dev", "a.meetneptune.dev.:443", 200},
		{"suffix: bare domain", "*.meetneptune.dev", "meetneptune.dev:443", 407},
		{"suffix: leading empty label", "*.meetneptune.dev", ".meetneptune.dev:443", 400},
		{"suffix: dotless-I lookalike", "*.ai.example", "a.aİ.example:443", 400},
		{"exact: dotless-I lookalike", "ai.example", "aİ.example:443", 400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewProxy()
			p.SetCA(ca)
			if err := p.SetNetworkPolicy("strict", []string{tt.allow}, nil); err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewServer(p)
			defer srv.Close()

			raw := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", tt.target, tt.target)
			if got := serveRaw(t, srv.Listener.Addr().String(), raw); got != tt.want {
				t.Errorf("CONNECT %q under allow %q = %d, want %d", tt.target, tt.allow, got, tt.want)
			}
		})
	}
}

// interceptRaw opens a CONNECT tunnel to hostPort through the proxy, completes
// TLS against the interception CA, and returns the TLS connection for raw
// requests.
func interceptRaw(t *testing.T, proxyAddr, hostPort, serverName string, ca *CA) *tls.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", hostPort, hostPort)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
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

// After CONNECT to host H, a request inside the tunnel for another authority
// is refused before credential resolution or any upstream dial. The proxy
// resolves credentials for H, so honoring another Host header would send H's
// credential to a virtual host the policy never checked.
func TestIntercept_InnerAuthorityMustMatchConnectTarget(t *testing.T) {
	var mu sync.Mutex
	var seen []string // Authorization of every request the backend received
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Host+"|"+r.Header.Get("Authorization"))
		mu.Unlock()
		w.Write([]byte("ok"))
	}))
	setup.Proxy.SetCredentialWithGrant(setup.BackendHost, "Authorization", "Bearer secret", "g")
	hostPort := mustParseURL(setup.Backend.URL).Host

	// Credential lookup runs on the CONNECT target, so a resolver on that
	// host is called for every request that gets past the authority check.
	var resolverMu sync.Mutex
	var resolverHosts []string // inner Host of every request the resolver saw
	setup.Proxy.SetCredentialResolver(setup.BackendHost, func(_ context.Context, _, inner *http.Request, _ string) ([]CredentialHeader, error) {
		resolverMu.Lock()
		resolverHosts = append(resolverHosts, inner.Host)
		resolverMu.Unlock()
		return nil, nil
	})

	tests := []struct {
		name    string
		request string
		want    int
	}{
		{"same host and port", "GET / HTTP/1.1\r\nHost: " + hostPort + "\r\nConnection: close\r\n\r\n", 200},
		{"same host without port", "GET / HTTP/1.1\r\nHost: " + setup.BackendHost + "\r\nConnection: close\r\n\r\n", 200},
		{"other host", "GET / HTTP/1.1\r\nHost: attacker.example\r\nConnection: close\r\n\r\n", 421},
		{"other host, same port", "GET / HTTP/1.1\r\nHost: attacker.example:" + mustParseURL(setup.Backend.URL).Port() + "\r\nConnection: close\r\n\r\n", 421},
		{"same host, other port", "GET / HTTP/1.1\r\nHost: " + setup.BackendHost + ":1\r\nConnection: close\r\n\r\n", 421},
		{"absolute-form for other host", "GET https://attacker.example/ HTTP/1.1\r\nHost: " + hostPort + "\r\nConnection: close\r\n\r\n", 421},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mu.Lock()
			seen = nil
			mu.Unlock()
			tc := interceptRaw(t, setup.ProxyServer.Listener.Addr().String(), hostPort, setup.BackendHost, setup.CA)
			io.WriteString(tc, tt.request)
			resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != tt.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.want)
			}
			mu.Lock()
			defer mu.Unlock()
			if tt.want == 200 {
				if len(seen) != 1 || !strings.HasSuffix(seen[0], "|Bearer secret") {
					t.Errorf("backend saw %v, want one request with the credential", seen)
				}
			} else if len(seen) != 0 {
				t.Errorf("backend saw %v, want no request", seen)
			}
		})
	}
	resolverMu.Lock()
	defer resolverMu.Unlock()
	if len(resolverHosts) != 2 {
		t.Errorf("resolver saw requests for hosts %q, want only the two requests for the CONNECT target", resolverHosts)
	}
	for _, h := range resolverHosts {
		if !strings.HasPrefix(h, setup.BackendHost) {
			t.Errorf("resolver ran for mismatched host %q", h)
		}
	}
}

// The same rule on the prefix pattern the credential is keyed on: CONNECT to
// pr-1.meetneptune.dev through a host gateway, then inner Host headers.
func TestIntercept_InnerAuthorityOnPrefixCredential(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Write([]byte("ok"))
	}))
	defer backend.Close()
	port, _ := strconv.Atoi(mustParseURL(backend.URL).Port())

	ca, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}
	upstream := x509.NewCertPool()
	upstream.AddCert(backend.Certificate())
	p := NewProxy()
	p.SetCA(ca)
	p.SetUpstreamCAs(upstream)
	p.SetContextResolver(func(string) (*RunContextData, bool) {
		return &RunContextData{
			Policy:           "permissive",
			HostGateway:      "pr-1.meetneptune.dev",
			HostGatewayIP:    "127.0.0.1",
			AllowedHostPorts: []int{port},
			Credentials: map[string][]CredentialHeader{
				"pr-*.meetneptune.dev": {{Name: "Authorization", Value: "Bearer prefix", Grant: "prefix"}},
			},
		}, true
	})
	srv := httptest.NewServer(p)
	defer srv.Close()

	hostPort := fmt.Sprintf("pr-1.meetneptune.dev:%d", port)
	tests := []struct {
		name string
		host string
		want int
	}{
		{"same", hostPort, 200},
		{"other case", fmt.Sprintf("PR-1.MeetNeptune.dev:%d", port), 200},
		{"no port", "pr-1.meetneptune.dev", 200},
		{"trailing root dot", hostPort[:len("pr-1.meetneptune.dev")] + "." + hostPort[len("pr-1.meetneptune.dev"):], 200},
		{"other host", "attacker.example", 421},
		{"sibling pr host", fmt.Sprintf("pr-2.meetneptune.dev:%d", port), 421},
		{"two-label lookalike", fmt.Sprintf("pr-1.evil.meetneptune.dev:%d", port), 421},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mu.Lock()
			seen = nil
			mu.Unlock()
			conn, err := net.Dial("tcp", srv.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", hostPort, hostPort, "cnVuOnRvaw==")
			br := bufio.NewReader(conn)
			resp, err := http.ReadResponse(br, nil)
			if err != nil || resp.StatusCode != 200 {
				t.Fatalf("CONNECT: %v %v", resp, err)
			}
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(ca.certPEM)
			tc := tls.Client(conn, &tls.Config{RootCAs: pool, ServerName: "pr-1.meetneptune.dev"})
			if err := tc.Handshake(); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(tc, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", tt.host)
			resp, err = http.ReadResponse(bufio.NewReader(tc), nil)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != tt.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.want)
			}
			mu.Lock()
			defer mu.Unlock()
			switch {
			case tt.want == 200 && (len(seen) != 1 || seen[0] != "Bearer prefix"):
				t.Errorf("backend Authorization = %v, want [Bearer prefix]", seen)
			case tt.want != 200 && len(seen) != 0:
				t.Errorf("backend saw %v for a refused request", seen)
			}
		})
	}
}
