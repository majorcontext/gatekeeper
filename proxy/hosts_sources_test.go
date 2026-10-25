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

// A relay target is configuration, not a client request, but it reaches the
// same credential lookup and the same transport, so its host must be matched
// in the form that is dialed.
func TestRelay_TargetHostIsMatchedAsDialed(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		wantHost string
		wantAuth string
	}{
		{"one label", "https://pr-1.meetneptune.dev/", "pr-1.meetneptune.dev", "Bearer prefix"},
		{"trailing root dot", "https://pr-1.meetneptune.dev./", "pr-1.meetneptune.dev", "Bearer prefix"},
		{"two labels", "https://pr-1.evil.meetneptune.dev/", "pr-1.evil.meetneptune.dev", ""},
		{"ideographic full stop", "https://pr-1" + ideographicFullStop + "evil.meetneptune.dev/", "pr-1.evil.meetneptune.dev", ""},
		{"fullwidth full stop", "https://pr-1" + fullwidthFullStop + "evil.meetneptune.dev/", "pr-1.evil.meetneptune.dev", ""},
		{"halfwidth ideographic full stop", "https://pr-1" + halfwidthFullStop + "evil.meetneptune.dev/", "pr-1.evil.meetneptune.dev", ""},
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
	for _, target := range []string{
		"https://pr-1..evil.meetneptune.dev/",
		"https://.meetneptune.dev/",
		"https://pr-1.meetneptune.dev../",
		"https://a‮b.example/",
	} {
		p := NewProxy()
		if err := p.AddRelay("x", target); err == nil {
			t.Errorf("AddRelay(%q) succeeded, want an error", target)
		}
		if len(p.relays) != 0 {
			t.Errorf("AddRelay(%q) stored %v", target, p.relays)
		}
	}
}

// The substitution and header setters take the same host patterns as the
// credential setters, and refuse the same malformed ones.
func TestHostKeyedSetters_RejectBadPatterns(t *testing.T) {
	bad := []string{"*.aİ.example", "aİ.example", "pr-*.com.", "pr-*..com", "pr-*-x.example.com", "*foo.example.com"}
	p := NewProxy()
	for _, host := range bad {
		p.SetTokenSubstitution(host, "PLACEHOLDER", "secret")
		p.SetInsecureTokenSubstitution(host, "PLACEHOLDER", "secret")
		p.RemoveRequestHeader(host, "X-Remove")
		p.SetPostgresResolver(host, NewStaticPostgresResolver("pw"))
	}
	if len(p.tokenSubstitutions) != 0 || len(p.removeHeaders) != 0 || len(p.postgresResolvers) != 0 {
		t.Errorf("bad host keys were stored: substitutions=%v removeHeaders=%v postgres=%d",
			p.tokenSubstitutions, p.removeHeaders, len(p.postgresResolvers))
	}

	for _, host := range []string{"api.example.com", "*.example.com", "pr-*.example.com", "api.example.com:8443"} {
		q := NewProxy()
		q.SetTokenSubstitution(host, "PLACEHOLDER", "secret")
		q.RemoveRequestHeader(host, "X-Remove")
		if len(q.tokenSubstitutions) != 1 || len(q.removeHeaders) != 1 {
			t.Errorf("valid host key %q was not stored", host)
		}
	}
}

// A request to https://a.ai.example/ must not receive a substitution keyed
// on "*.aİ.example": strings.ToLower maps İ to i, but the transport dials the
// IDNA form, a different name.
func TestTokenSubstitution_DoesNotMatchUnicodeLookalikeKey(t *testing.T) {
	rt := useRecordingTransport(t)
	p := NewProxy()
	p.SetInsecureTokenSubstitution("*.aİ.example", "PLACEHOLDER", "secret")
	srv := httptest.NewServer(p)
	defer srv.Close()

	raw := "GET http://a.ai.example/ HTTP/1.1\r\nHost: a.ai.example\r\nAuthorization: PLACEHOLDER\r\nConnection: close\r\n\r\n"
	if got := serveRaw(t, srv.Listener.Addr().String(), raw); got != 200 {
		t.Fatalf("status = %d, want 200", got)
	}
	if len(rt.reqs) != 1 {
		t.Fatalf("transport got %d requests, want 1", len(rt.reqs))
	}
	if got := rt.reqs[0].Header.Get("Authorization"); got != "PLACEHOLDER" {
		t.Errorf("Authorization = %q, want the placeholder untouched", got)
	}
}

// RunContextData maps are filled by the embedder, with no setter to validate
// them, so the lookup itself must not fold a non-ASCII key onto an ASCII host.
func TestLookupHostKeyed_NonASCIIKeysDoNotFoldOntoASCIIHosts(t *testing.T) {
	tests := []struct {
		name string
		key  string
		host string
	}{
		{"suffix key with dotted capital I", "*.aİ.example", "x.ai.example"},
		{"exact key with dotted capital I", "aİ.example", "ai.example"},
		{"prefix key with dotted capital I", "pr-İ*.example.com", "pr-i1.example.com"},
		{"suffix key with Kelvin sign", "*.K.example", "x.k.example"},
		{"exact key with long s", "ſ.example", "s.example"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := map[string][]string{tt.key: {"leaked"}}
			if got, _ := lookupHostKeyed(m, tt.host, nonEmptySlice); len(got) != 0 {
				t.Errorf("lookupHostKeyed(%q) matched key %q", tt.host, tt.key)
			}
		})
	}
	for _, p := range []HostPattern{parseHostPattern("*.aİ.example"), parseHostPattern("aİ.example")} {
		if hostMatchesPattern(p, "x.ai.example") || hostMatchesPattern(p, "ai.example") {
			t.Errorf("pattern %q matched an ASCII host", p.pattern)
		}
	}
}

// The Postgres listener routes on the TLS SNI, which the client sets. A
// Unicode SNI is matched as its ASCII form, so "a.aİ.example" is the host
// "a.xn--ai-sub.example" and does not match an allow list entry for
// "*.ai.example". (Before the SNI was canonicalized, minting a certificate
// for a non-ASCII name already failed, so the handshake failed closed; now the
// client gets the ordinary allow-list denial for the ASCII name.)
func TestPostgresSNIIsMatchedAsDialed(t *testing.T) {
	p, _ := newTestProxyWithCA(t)
	p.SetAuthToken("run-token")
	if err := p.SetNetworkPolicy("strict", []string{"*.ai.example"}, nil); err != nil {
		t.Fatal(err)
	}
	p.SetPostgresResolver("*.ai.example", NewStaticPostgresResolver("real-password"))
	logs := &logCapture{}
	p.SetLogger(logs.log)
	srv := newTestPostgresListener(t, p)

	raw, err := dialPostgresTLS(srv.Addr(), "a.aİ.example")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	fe := pgproto3.NewFrontend(raw, raw)
	fe.Send(&pgproto3.StartupMessage{ProtocolVersion: pgproto3.ProtocolVersionNumber, Parameters: map[string]string{"user": "app", "database": "db"}})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := fe.Receive(); err != nil {
		t.Fatalf("receive: %v", err)
	}
	fe.Send(&pgproto3.PasswordMessage{Password: "run-token"})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}
	msg, _ := fe.Receive()
	if _, ok := msg.(*pgproto3.ErrorResponse); !ok {
		t.Fatalf("got %T, want an ErrorResponse: the SNI is not on the allow list", msg)
	}
	deadline := time.After(5 * time.Second)
	for {
		for _, d := range logs.snapshot() {
			if d.Denied {
				if !strings.Contains(d.DenyReason, "a.xn--ai-sub.example") {
					t.Errorf("DenyReason = %q, want the ASCII form of the SNI", d.DenyReason)
				}
				return
			}
		}
		select {
		case <-deadline:
			t.Fatalf("no denial logged; logs = %+v", logs.snapshot())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// dialPostgresTLS opens the Postgres TLS session without verifying the
// minted certificate, which names the ASCII form of a Unicode SNI.
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

// An IP literal is an address, never a DNS name: a "*." or prefix pattern must
// not match it, in a network allow list or a host-keyed lookup, whatever the
// literal's text ends with. A zone is free text (net/http dials the address
// and ignores it for IPv4-mapped IPv6), so "[::ffff:192.0.2.1%25x.example.com]"
// is the address 192.0.2.1, not a host under example.com.
func TestIPLiteralsNeverMatchDNSPatterns(t *testing.T) {
	hosts := []string{
		"192.0.2.1",
		"::ffff:192.0.2.1",
		"::ffff:192.0.2.1%x.example.com",
		"[::ffff:192.0.2.1%x.example.com]",
		"fe80::1%x.example.com",
		"::1",
	}
	patterns := []string{"*.0.2.1", "19*.0.2.1", "*.example.com", "pr-*.example.com", "*.2.1"}
	for _, host := range hosts {
		for _, pattern := range patterns {
			if matchHost([]HostPattern{parseHostPattern(pattern)}, host, 443) {
				t.Errorf("allow pattern %q matched the IP literal %q", pattern, host)
			}
			m := map[string][]string{pattern: {"leaked"}}
			if got, _ := lookupHostKeyed(m, host, nonEmptySlice); len(got) != 0 {
				t.Errorf("host key %q matched the IP literal %q", pattern, host)
			}
			if got, _ := lookupHostKeyed(m, host+":443", nonEmptySlice); len(got) != 0 {
				t.Errorf("host key %q matched the IP literal %q with a port", pattern, host)
			}
		}
	}
	// An exact IP pattern still matches that address.
	if !matchHost([]HostPattern{parseHostPattern("192.0.2.1")}, "192.0.2.1", 443) {
		t.Error("exact pattern 192.0.2.1 no longer matches 192.0.2.1")
	}
	if got, _ := lookupHostKeyed(map[string][]string{"192.0.2.1": {"ok"}}, "192.0.2.1:443", nonEmptySlice); len(got) != 1 {
		t.Error("exact key 192.0.2.1 no longer matches 192.0.2.1:443")
	}
}

// A zoned IPv6 literal has no use in a proxy request (a zone names an
// interface of the proxy's host), so it is refused before any policy decision.
func TestProxy_ZonedIPv6TargetsAreRefused(t *testing.T) {
	targets := []string{
		"[::ffff:192.0.2.1%25x.example.com]",
		"[::1%25x.example.com]",
		"[fe80::1%25eth0]",
	}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			rt := useRecordingTransport(t)
			p := NewProxy()
			if err := p.SetNetworkPolicy("strict", []string{"*.example.com"}, nil); err != nil {
				t.Fatal(err)
			}
			p.SetInsecureCredentialWithGrant("*.example.com", "Authorization", "Bearer wildcard", "wildcard")
			srv := httptest.NewServer(p)
			defer srv.Close()

			raw := "GET http://" + target + "/ HTTP/1.1\r\nHost: ignored\r\nConnection: close\r\n\r\n"
			if got := serveRaw(t, srv.Listener.Addr().String(), raw); got != 400 {
				t.Errorf("status = %d, want 400", got)
			}
			if len(rt.reqs) != 0 {
				t.Errorf("forwarded to %q with Authorization %q", rt.reqs[0].URL.Host, rt.reqs[0].Header.Get("Authorization"))
			}
		})
	}
}

func TestProxy_ZonedIPv6ConnectTargetsAreRefused(t *testing.T) {
	ca, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"[::ffff:192.0.2.1%25x.example.com]:443", "[fe80::1%25eth0]:443"} {
		p := NewProxy()
		p.SetCA(ca)
		if err := p.SetNetworkPolicy("strict", []string{"*.example.com"}, nil); err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewServer(p)
		raw := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
		if got := serveRaw(t, srv.Listener.Addr().String(), raw); got == 200 {
			t.Errorf("CONNECT %s established a tunnel", target)
		}
		srv.Close()
	}
}

// IP literals are exact keys for the host-keyed setters that take a port:
// IPv4 and IPv6, bare or bracketed, with or without a port. A zone is refused.
func TestHostKeyedSetters_AcceptExactIPKeys(t *testing.T) {
	for _, key := range []string{"::1", "[::1]", "[::1]:8080", "127.0.0.1", "127.0.0.1:8080", "2001:db8::1"} {
		t.Run(key, func(t *testing.T) {
			p := NewProxy()
			p.RemoveRequestHeader(key, "Authorization")
			p.SetTokenSubstitution(key, "PLACEHOLDER", "secret")
			p.SetInsecureTokenSubstitution(key, "PLACEHOLDER", "secret")
			if len(p.removeHeaders) != 1 || len(p.tokenSubstitutions) != 1 {
				t.Errorf("key %q was not stored: removeHeaders=%v substitutions=%v", key, p.removeHeaders, p.tokenSubstitutions)
			}
		})
	}
	for _, key := range []string{"fe80::1%eth0", "[fe80::1%25eth0]:80", "[::1%x.example.com]", "[::1]:0", "::zz", "[::1", "1.2.3.4:99999"} {
		p := NewProxy()
		p.RemoveRequestHeader(key, "Authorization")
		p.SetTokenSubstitution(key, "PLACEHOLDER", "secret")
		p.SetInsecureTokenSubstitution(key, "PLACEHOLDER", "secret")
		if len(p.removeHeaders) != 0 || len(p.tokenSubstitutions) != 0 {
			t.Errorf("bad key %q was stored: removeHeaders=%v substitutions=%v", key, p.removeHeaders, p.tokenSubstitutions)
		}
	}
}

// An exact IP key acts on requests to that address, as before the setters
// validated their keys.
func TestHostKeyedSetters_IPKeysActOnIPTargets(t *testing.T) {
	tests := []struct {
		name   string
		key    string
		target string
	}{
		{"bare IPv6 key", "::1", "http://[::1]:8080/"},
		{"bracketed IPv6 key", "[::1]", "http://[::1]:8080/"},
		{"IPv6 key with port", "[::1]:8080", "http://[::1]:8080/"},
		{"spelled-out IPv6", "0:0:0:0:0:0:0:1", "http://[::1]:8080/"},
		{"IPv4 key", "127.0.0.1", "http://127.0.0.1:8080/"},
		{"IPv4 key with port", "127.0.0.1:8080", "http://127.0.0.1:8080/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := useRecordingTransport(t)
			p := NewProxy()
			p.RemoveRequestHeader(tt.key, "X-Remove")
			p.SetInsecureTokenSubstitution(tt.key, "PLACEHOLDER", "secret")
			srv := httptest.NewServer(p)
			defer srv.Close()

			raw := "GET " + tt.target + " HTTP/1.1\r\nHost: ignored\r\nX-Remove: 1\r\nAuthorization: PLACEHOLDER\r\nConnection: close\r\n\r\n"
			if got := serveRaw(t, srv.Listener.Addr().String(), raw); got != 200 {
				t.Fatalf("status = %d, want 200", got)
			}
			if len(rt.reqs) != 1 {
				t.Fatalf("transport got %d requests, want 1", len(rt.reqs))
			}
			out := rt.reqs[0]
			if got := out.Header.Get("X-Remove"); got != "" {
				t.Errorf("X-Remove = %q, want it removed", got)
			}
			if got := out.Header.Get("Authorization"); got != "secret" {
				t.Errorf("Authorization = %q, want the substituted token", got)
			}
		})
	}
}
