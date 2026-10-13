package proxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"sync/atomic"
	"testing"
)

type fakeResolver struct {
	names   map[string][]string
	lookups atomic.Int32
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	f.lookups.Add(1)
	ips, ok := f.names[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	var out []netip.Addr
	for _, s := range ips {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, nil
}

func useFakeResolver(t *testing.T, names map[string][]string) *fakeResolver {
	t.Helper()
	f := &fakeResolver{names: names}
	old := dialResolver
	dialResolver = f
	t.Cleanup(func() { dialResolver = old })
	return f
}

func gatewayProxy(t *testing.T) *httptest.Server {
	t.Helper()
	p := NewProxy()
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		return &RunContextData{
			Policy:           "permissive",
			HostGateway:      "host.docker.internal",
			HostGatewayIP:    "10.254.254.254",
			AllowedHostPorts: nil,
		}, token == "run"
	})
	s := httptest.NewServer(p)
	t.Cleanup(s.Close)
	return s
}

func TestDialRefusesNameResolvingToRestrictedAddress(t *testing.T) {
	var hits atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer backend.Close()
	_, port, _ := net.SplitHostPort(backend.Listener.Addr().String())

	useFakeResolver(t, map[string][]string{
		"loopback.example":  {"127.0.0.1"},
		"loopback6.example": {"::1"},
		"linklocal.example": {"169.254.169.254"},
		"mixed.example":     {"93.184.216.34", "127.0.0.1"},
	})
	proxySrv := gatewayProxy(t)

	for _, name := range []string{"loopback.example", "loopback6.example", "linklocal.example", "mixed.example"} {
		t.Run("http/"+name, func(t *testing.T) {
			client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(mustParseURL(proxySrv.URL))}}
			req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s:%s/", name, port), nil)
			req.Header.Set("Proxy-Authorization", "Bearer run")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadGateway {
				t.Errorf("status = %d, want 502", resp.StatusCode)
			}
		})
		t.Run("connect/"+name, func(t *testing.T) {
			conn, err := net.Dial("tcp", mustParseURL(proxySrv.URL).Host)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			fmt.Fprintf(conn, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\nProxy-Authorization: Bearer run\r\n\r\n", name, port, name, port)
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadGateway {
				t.Errorf("status = %d, want 502", resp.StatusCode)
			}
		})
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("backend reached %d times through a name that resolves to a restricted address", n)
	}
}

func TestSetDelegateAuthWithoutTokenFailsClosed(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer backend.Close()

	p := NewProxy()
	if err := p.SetDelegateAuth(true); err == nil {
		t.Error("SetDelegateAuth(true) with no auth token returned nil, want an error")
	}
	s := httptest.NewServer(p)
	defer s.Close()
	pu := mustParseURL(s.URL)
	pu.User = url.UserPassword("alice", "any-password")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	resp, err := client.Get(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("status = %d, want 407 after a rejected SetDelegateAuth(true)", resp.StatusCode)
	}
}

func TestSetNetworkPolicyRejectsUnknownPolicy(t *testing.T) {
	for _, policy := range []string{"Strict", "deny", "strict ", "allow"} {
		p := NewProxy()
		if err := p.SetNetworkPolicy(policy, nil, nil); err == nil {
			t.Errorf("SetNetworkPolicy(%q) returned nil, want an error", policy)
		}
		if err := p.SetNetworkPolicyWithRules(policy, nil, nil, nil, nil); err == nil {
			t.Errorf("SetNetworkPolicyWithRules(%q) returned nil, want an error", policy)
		}
	}
}

func TestInterceptDialRefusesNameResolvingToLoopback(t *testing.T) {
	var hits atomic.Int32
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	resolver := useFakeResolver(t, map[string][]string{"loopback.example": {"127.0.0.1"}})
	setup.Proxy.SetContextResolver(func(token string) (*RunContextData, bool) {
		return &RunContextData{
			Policy:        "permissive",
			HostGateway:   "host.docker.internal",
			HostGatewayIP: "10.254.254.254",
		}, token == "run"
	})
	tr := setup.Client.Transport.(*http.Transport)
	tr.ProxyConnectHeader = http.Header{"Proxy-Authorization": {"Bearer run"}}

	_, port, _ := net.SplitHostPort(setup.Backend.Listener.Addr().String())
	resp, err := setup.Client.Get(fmt.Sprintf("https://loopback.example:%s/", port))
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway {
			t.Errorf("status = %d, want 502", resp.StatusCode)
		}
	}
	if resolver.lookups.Load() == 0 {
		t.Error("intercepted upstream dial did not consult the guarded resolver")
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("backend reached %d times through intercepted name resolving to loopback", n)
	}
}
