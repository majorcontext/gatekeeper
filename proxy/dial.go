package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"time"
)

type ipResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

var dialResolver ipResolver = net.DefaultResolver

var errRestrictedDial = errors.New("destination address is restricted")

const upstreamDialTimeout = 30 * time.Second

func restrictedAddr(a netip.Addr) bool {
	a = a.WithZone("").Unmap()
	return a.IsLoopback() || a.IsUnspecified() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast()
}

// dialContext connects to addr. When the run context carries a host gateway,
// it resolves a hostname itself, refuses the dial if any resolved address is
// loopback, unspecified or link-local, and dials the checked IP so a second
// lookup cannot change the answer. The gateway itself is exempt.
func dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, upstreamDialTimeout)
	defer cancel()
	d := net.Dialer{KeepAlive: 30 * time.Second}
	rc, _ := ctx.Value(runContextKey).(*RunContextData)
	if rc == nil || rc.HostGateway == "" {
		return d.DialContext(ctx, network, addr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if isHostGateway(rc, host) || (rc.HostGatewayIP != "" && host == rc.HostGatewayIP) {
		return d.DialContext(ctx, network, addr)
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else if addrs, err = dialResolver.LookupNetIP(ctx, "ip", host); err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true}
	}
	gatewayIP, _ := netip.ParseAddr(rc.HostGatewayIP)
	for _, a := range addrs {
		if restrictedAddr(a) || (gatewayIP.IsValid() && a.Unmap() == gatewayIP.Unmap()) {
			return nil, errRestrictedDial
		}
	}
	var lastErr error
	for _, a := range addrs {
		c, err := d.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// poolKey names the connection pool a request may use. Idle connections skip
// dialContext, so a request that must pass the dial guard never shares a pool
// with one that did not, nor with a run whose host gateway differs.
type poolKey struct{ gateway, gatewayIP string }

func poolKeyFor(rc *RunContextData) poolKey {
	if rc == nil || rc.HostGateway == "" {
		return poolKey{}
	}
	return poolKey{rc.HostGateway, rc.HostGatewayIP}
}

func (p *Proxy) httpTransportFor(rc *RunContextData) http.RoundTripper {
	k := poolKeyFor(rc)
	if k == (poolKey{}) {
		return httpTransport
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	t := p.guardedHTTPTransports[k]
	if t == nil {
		if p.guardedHTTPTransports == nil {
			p.guardedHTTPTransports = make(map[poolKey]*http.Transport)
		}
		t = newHTTPTransport()
		p.guardedHTTPTransports[k] = t
	}
	return t
}
