package proxy

import (
	"context"
	"errors"
	"net"
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
// it resolves a hostname itself (IP literals are left to the
// host-gateway policy check), refuses the dial if any resolved address is
// loopback, unspecified or link-local, and dials the checked IP so a second
// lookup cannot change the answer. The gateway itself is exempt.
func dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: upstreamDialTimeout, KeepAlive: 30 * time.Second}
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
	if _, err := netip.ParseAddr(host); err == nil {
		return d.DialContext(ctx, network, addr)
	}
	addrs, err := dialResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true}
	}
	for _, a := range addrs {
		if restrictedAddr(a) {
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
