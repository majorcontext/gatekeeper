package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// A relay target is configuration, but it reaches the same credential lookup
// and transport as a request, so it is matched in the form that is dialed.
func TestRelay_TargetHostIsMatchedAsDialed(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		wantHost string
		wantAuth string
	}{
		{"one label", "https://pr-1.meetneptune.dev/", "pr-1.meetneptune.dev", "Bearer prefix"},
		{"trailing root dot", "https://pr-1.meetneptune.dev./", "pr-1.meetneptune.dev", "Bearer prefix"},
		{"ideographic full stop", "https://pr-1" + ideographicFullStop + "evil.meetneptune.dev/", "pr-1.evil.meetneptune.dev", ""},
		{"port kept", "https://pr-1" + ideographicFullStop + "evil.meetneptune.dev:8443/x", "pr-1.evil.meetneptune.dev:8443", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out *http.Request
			orig := relayClient.Transport
			defer func() { relayClient.Transport = orig }()
			relayClient.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				out = req
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok")), Request: req}, nil
			})

			p := NewProxy()
			p.SetCredentialWithGrant("pr-*.meetneptune.dev", "Authorization", "Bearer prefix", "prefix")
			if err := p.AddRelay("x", tt.target); err != nil {
				t.Fatalf("AddRelay(%q): %v", tt.target, err)
			}
			rec := httptest.NewRecorder()
			p.handleRelay(rec, httptest.NewRequest("GET", "/relay/x/", nil))
			if rec.Code != 200 || out == nil {
				t.Fatalf("status = %d, forwarded = %v", rec.Code, out != nil)
			}
			if out.URL.Host != tt.wantHost {
				t.Errorf("transport host = %q, want %q", out.URL.Host, tt.wantHost)
			}
			if got := out.Header.Get("Authorization"); got != tt.wantAuth {
				t.Errorf("Authorization sent to %q = %q, want %q", out.URL.Host, got, tt.wantAuth)
			}
		})
	}
}

func TestAddRelay_RejectsUndialableHost(t *testing.T) {
	for _, target := range []string{"https://pr-1..evil.meetneptune.dev/", "https://a‮b.example/"} {
		p := NewProxy()
		if err := p.AddRelay("x", target); err == nil || len(p.relays) != 0 {
			t.Errorf("AddRelay(%q) = %v, stored %v; want an error and nothing stored", target, err, p.relays)
		}
	}
}

func TestSetNetworkPolicy_RejectsBadPatterns(t *testing.T) {
	for _, pattern := range []string{"pr-*-x.example.com", "pr-*.com.", "0177.0.0.1"} {
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

// The host-keyed setters take host patterns, and the three that accept a port
// also take exact IP literals. Malformed keys, zoned IPv6 and bracketed
// non-IPs are ignored.
func TestHostKeyedSetters_Keys(t *testing.T) {
	tests := []struct {
		key   string
		valid bool
	}{
		{"api.example.com", true},
		{"*.example.com", true},
		{"pr-*.example.com", true},
		{"api.example.com:8443", true},
		{"::1", true},
		{"[::1]", true},
		{"[::1]:8080", true},
		{"127.0.0.1", true},
		{"127.0.0.1:8080", true},
		{"2001:db8::1", true},
		{"*.aİ.example", false},
		{"pr-*.com.", false},
		{"pr-*-x.example.com", false},
		{"fe80::1%eth0", false},
		{"[fe80::1%25eth0]:80", false},
		{"[::1]:0", false},
		{"::zz", false},
		{"[::1", false},
		{"1.2.3.4:99999", false},
		{"[999.0.0.1]", false},
		{"[example.com]:80", false},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			p := NewProxy()
			p.RemoveRequestHeader(tt.key, "Authorization")
			p.SetTokenSubstitution(tt.key, "PLACEHOLDER", "secret")
			p.SetInsecureTokenSubstitution(tt.key, "PLACEHOLDER", "secret")
			if stored := len(p.removeHeaders) == 1 && len(p.tokenSubstitutions) == 1; stored != tt.valid {
				t.Errorf("key %q stored = %v, want %v", tt.key, stored, tt.valid)
			}
		})
	}

	p := NewProxy()
	for _, host := range []string{"pr-*.com.", "pr-*-x.example.com", "pr-*.münchen.de"} {
		p.SetCredentialWithGrant(host, "Authorization", "Bearer x", "g")
		p.SetCredentialResolver(host, func(context.Context, *http.Request, *http.Request, string) ([]CredentialHeader, error) {
			return nil, nil
		})
		p.SetPostgresResolver(host, NewStaticPostgresResolver("pw"))
	}
	if len(p.credentials) != 0 || len(p.credentialResolvers) != 0 || len(p.postgresResolvers) != 0 {
		t.Errorf("bad host keys were stored: %v %d %d", p.credentials, len(p.credentialResolvers), len(p.postgresResolvers))
	}
}

// RunContextData maps are filled by the embedder, so the lookup itself must
// not fold a non-ASCII key onto an ASCII host: strings.ToLower maps U+0130 to
// "i", but IDNA, and so the dial, maps it to another label.
func TestLookupHostKeyed_NonASCIIKeysDoNotFoldOntoASCIIHosts(t *testing.T) {
	tests := []struct{ key, host string }{
		{"*.aİ.example", "x.ai.example"},
		{"aİ.example", "ai.example"},
		{"pr-İ*.example.com", "pr-i1.example.com"},
	}
	for _, tt := range tests {
		m := map[string][]string{tt.key: {"leaked"}}
		if got, _ := lookupHostKeyed(m, tt.host, nonEmptySlice); len(got) != 0 {
			t.Errorf("lookupHostKeyed(%q) matched key %q", tt.host, tt.key)
		}
	}
}

// An IP literal is an address, never a DNS name: "*." and prefix patterns do
// not match it, whatever its text ends with. A zone is free text, so
// "::ffff:192.0.2.1%x.example.com" is the address 192.0.2.1, not a host under
// example.com. An exact IP pattern still matches.
func TestIPLiteralsNeverMatchDNSPatterns(t *testing.T) {
	hosts := []string{"192.0.2.1", "::ffff:192.0.2.1", "::ffff:192.0.2.1%x.example.com", "[::ffff:192.0.2.1%x.example.com]"}
	patterns := []string{"*.0.2.1", "19*.0.2.1", "*.example.com", "pr-*.example.com"}
	for _, host := range hosts {
		for _, pattern := range patterns {
			if matchHost([]HostPattern{parseHostPattern(pattern)}, host, 443) {
				t.Errorf("allow pattern %q matched the IP literal %q", pattern, host)
			}
			m := map[string][]string{pattern: {"leaked"}}
			if got, _ := lookupHostKeyed(m, host+":443", nonEmptySlice); len(got) != 0 {
				t.Errorf("host key %q matched the IP literal %q", pattern, host)
			}
		}
	}
	if !matchHost([]HostPattern{parseHostPattern("192.0.2.1")}, "192.0.2.1", 443) {
		t.Error("exact pattern 192.0.2.1 no longer matches 192.0.2.1")
	}
}

// An IP key names an address: it matches however the key or the target spells
// it, with the port compared as a number, and among keys for one address the
// one pinned to the target port wins over a portless key.
func TestLookupHostKeyed_IPKeys(t *testing.T) {
	tests := []struct {
		name string
		keys []string
		host string // the lookup host of a request: host:port
		want string // the winning key, or "" for none
	}{
		{"spelled-out key, compressed target", []string{"[0:0:0:0:0:0:0:1]:8080"}, "[::1]:8080", "[0:0:0:0:0:0:0:1]:8080"},
		{"IPv4 key, IPv4-mapped target", []string{"127.0.0.1"}, "[::ffff:127.0.0.1]:8080", "127.0.0.1"},
		{"IPv4-mapped key, IPv4 target", []string{"::ffff:127.0.0.1"}, "127.0.0.1:8080", "::ffff:127.0.0.1"},
		{"bracketed key without port", []string{"[::1]"}, "[::1]:8080", "[::1]"},
		{"other port", []string{"[::1]:9090"}, "[::1]:8080", ""},
		{"other address", []string{"127.0.0.2"}, "127.0.0.1:8080", ""},
		{"not a name", []string{"127.0.0.1"}, "localhost:8080", ""},
		{"pinned over portless, IPv4 target", []string{"127.0.0.1", "[::ffff:127.0.0.1]:8080"}, "127.0.0.1:8080", "[::ffff:127.0.0.1]:8080"},
		{"pinned over portless, mapped target", []string{"127.0.0.1", "[::ffff:127.0.0.1]:8080"}, "[::ffff:127.0.0.1]:8080", "[::ffff:127.0.0.1]:8080"},
		{"pinned over portless, IPv6", []string{"::1", "[0:0:0:0:0:0:0:1]:8080"}, "[::1]:8080", "[0:0:0:0:0:0:0:1]:8080"},
		{"pin for another port loses", []string{"127.0.0.1", "[::ffff:127.0.0.1]:9090"}, "127.0.0.1:8080", "127.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := map[string]string{}
			for _, k := range tt.keys {
				m[k] = k
			}
			if got, _ := lookupHostKeyed(m, tt.host, presenceUsable); got != tt.want {
				t.Errorf("lookupHostKeyed(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}

// Request level: an IP key, from a setter or an embedder map, acts on a
// request to that address as before keys were validated.
func TestHostKeyedHeaders_IPKeysActOnIPTargets(t *testing.T) {
	tests := []struct {
		name   string
		key    string
		inMap  bool // an embedder RunContextData map rather than the setters
		target string
	}{
		{"bare IPv6 key", "::1", false, "http://[::1]:8080/"},
		{"IPv6 key with port", "[::1]:8080", false, "http://[::1]:8080/"},
		{"IPv4 key, IPv4-mapped target", "127.0.0.1", false, "http://[::ffff:127.0.0.1]:8080/"},
		{"spelled-out IPv6 key in an embedder map", "[0:0:0:0:0:0:0:1]:8080", true, "http://[::1]:8080/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := useRecordingTransport(t)
			p := NewProxy()
			auth := ""
			if tt.inMap {
				p.SetContextResolver(func(string) (*RunContextData, bool) {
					return &RunContextData{Policy: "permissive", RemoveHeaders: map[string][]string{tt.key: {"X-Remove"}}}, true
				})
				auth = "Proxy-Authorization: Basic cnVuOnRvaw==\r\n"
			} else {
				p.RemoveRequestHeader(tt.key, "X-Remove")
				p.SetInsecureTokenSubstitution(tt.key, "PLACEHOLDER", "secret")
			}
			raw := "GET " + tt.target + " HTTP/1.1\r\nHost: ignored\r\nX-Remove: 1\r\nAuthorization: PLACEHOLDER\r\n" + auth + "Connection: close\r\n\r\n"
			if got := rawStatus(t, p, raw); got != 200 || len(rt.reqs) != 1 {
				t.Fatalf("status = %d, forwarded %d", got, len(rt.reqs))
			}
			out := rt.reqs[0]
			if got := out.Header.Get("X-Remove"); got != "" {
				t.Errorf("X-Remove = %q, want it removed", got)
			}
			if got, want := out.Header.Get("Authorization"), map[bool]string{true: "PLACEHOLDER", false: "secret"}[tt.inMap]; got != want {
				t.Errorf("Authorization = %q, want %q", got, want)
			}
		})
	}
}

// The Postgres listener routes on the client's TLS SNI, matched in its ASCII
// form: "a.aİ.example" is "a.xn--ai-sub.example" and is not on an allow list
// for "*.ai.example". (Minting a certificate for a non-ASCII name already
// failed, so the handshake used to fail closed.)
func TestPostgresSNIIsMatchedAsDialed(t *testing.T) {
	p, _ := newTestProxyWithCA(t)
	p.SetAuthToken("run-token")
	if err := p.SetNetworkPolicy("strict", []string{"*.ai.example"}, nil); err != nil {
		t.Fatal(err)
	}
	p.SetPostgresResolver("*.ai.example", NewStaticPostgresResolver("real-password"))
	srv := newTestPostgresListener(t, p)

	conn, err := dialPostgresTLS(srv.Addr(), "a.aİ.example")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fe := pgproto3.NewFrontend(conn, conn)
	fe.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "app", "database": "db"}})
	fe.Flush()
	if _, err := fe.Receive(); err != nil {
		t.Fatalf("receive: %v", err)
	}
	fe.Send(&pgproto3.PasswordMessage{Password: "run-token"})
	fe.Flush()
	msg, _ := fe.Receive()
	if e, ok := msg.(*pgproto3.ErrorResponse); !ok || !strings.Contains(e.Message, "network policy") {
		t.Fatalf("got %#v, want a network policy ErrorResponse", msg)
	}
}

// dialPostgresTLS opens the Postgres TLS session without verifying the minted
// certificate, which names the ASCII form of a Unicode SNI.
func dialPostgresTLS(addr, sni string) (*tls.Conn, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	fe := pgproto3.NewFrontend(conn, conn)
	fe.Send(&pgproto3.SSLRequest{})
	if err := fe.Flush(); err != nil {
		return nil, err
	}
	var resp [1]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil || resp[0] != 'S' {
		return nil, fmt.Errorf("SSLRequest answer %q: %v", resp[0], err)
	}
	tc := tls.Client(conn, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return tc, tc.HandshakeContext(ctx)
}
