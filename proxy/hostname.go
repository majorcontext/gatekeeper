package proxy

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// canonicalTargetHost returns the name the upstream transport dials for host,
// so policy and credential matching decide on the name the connection goes to.
// A non-ASCII host is mapped to ASCII with the IDNA Lookup profile, as net/http
// does before it dials: that turns U+3002, U+FF0E and U+FF61 into "." and
// U+0130 into a label unlike "i". One trailing dot is dropped. An IP literal
// comes back in canonical text form. It errors on an empty label, a name IDNA
// rejects, an IPv6 zone (free text that the dial ignores for IPv4-mapped
// addresses), and a name that ends in a number (see endsInNumber).
func canonicalTargetHost(host string) (string, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return "", fmt.Errorf("IP literal %q has a zone", host)
		}
		return addr.String(), nil
	}
	if strings.Contains(host, ":") {
		return "", fmt.Errorf("invalid IP literal %q", host)
	}
	if !isASCII(host) {
		ascii, err := idna.Lookup.ToASCII(host)
		if err != nil {
			return "", fmt.Errorf("host %q is not a valid IDNA name: %w", host, err)
		}
		host = ascii
	}
	host = strings.TrimSuffix(host, ".")
	if hasEmptyLabel(host) {
		return "", fmt.Errorf("host %q has an empty label", host)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.String(), nil
	}
	if endsInNumber(host) {
		return "", fmt.Errorf("host %q ends in a number but is not a dotted-quad IPv4 address", host)
	}
	return host, nil
}

// endsInNumber reports whether the last label of host is a decimal or
// 0x-hexadecimal number. No DNS name ends in one, but libc's inet_aton, which
// the cgo resolver follows, reads "0177.0.0.1", "127.1" and "2130706433" as
// 127.0.0.1. Such a host must be a canonical dotted quad or be refused.
func endsInNumber(host string) bool {
	label := host[strings.LastIndexByte(host, '.')+1:]
	if rest, ok := strings.CutPrefix(strings.ToLower(label), "0x"); ok {
		return strings.Trim(rest, "0123456789abcdef") == ""
	}
	return label != "" && strings.Trim(label, "0123456789") == ""
}

// isIPv4Literal reports whether host is a canonical dotted-quad address.
func isIPv4Literal(host string) bool {
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Is4()
}

// ipKeyMatches reports whether key is an IP key (see splitIPKey) for hostAddr,
// and whether it is pinned to hostPort. Addresses compare after Unmap, ports as
// numbers; a key pinned to another port does not match.
func ipKeyMatches(key string, hostAddr netip.Addr, hostPort string) (match, pinned bool) {
	addr, port, ok := splitIPKey(key)
	if !ok || addr.Unmap() != hostAddr.Unmap() {
		return false, false
	}
	return port == "" || samePort(port, hostPort), port != ""
}

func samePort(a, b string) bool {
	x, err1 := strconv.Atoi(a)
	y, err2 := strconv.Atoi(b)
	return err1 == nil && err2 == nil && x == y
}

// isIPLiteral reports whether host is an IP address (bare or bracketed, with
// or without zone or port). A DNS pattern must never match one: a zone is free
// text, and "192.0.2.1" ends in ".0.2.1".
func isIPLiteral(host string) bool {
	_, _, ok := splitIPKey(host)
	return ok
}

// hostKey validates the key of a host-keyed setter that takes a port-pinned
// key: a host pattern, or an exact IP literal (bare or bracketed, optional
// port). An IP key is returned in the form a request's lookup host takes. A
// zone is refused, since it is never part of a request host.
func hostKey(key string) (string, error) {
	addr, port, isIP := splitIPKey(key)
	if !isIP {
		return key, ValidateHostPattern(key)
	}
	if addr.Zone() != "" {
		return "", fmt.Errorf("host key %q has an IPv6 zone", key)
	}
	if port == "" {
		return addr.String(), nil
	}
	if n, err := strconv.Atoi(port); err != nil || n <= 0 || n > 65535 {
		return "", fmt.Errorf("host key %q has an invalid port", key)
	}
	return net.JoinHostPort(addr.String(), port), nil
}

// splitIPKey splits an IP literal, with an optional port, into address and port.
func splitIPKey(key string) (addr netip.Addr, port string, ok bool) {
	if a, err := netip.ParseAddr(key); err == nil {
		return a, "", true
	}
	if strings.HasPrefix(key, "[") && strings.HasSuffix(key, "]") {
		if a, err := netip.ParseAddr(key[1 : len(key)-1]); err == nil {
			return a, "", true
		}
	}
	if hostPart, portPart, err := net.SplitHostPort(key); err == nil {
		if a, err := netip.ParseAddr(hostPart); err == nil {
			return a, portPart, true
		}
	}
	return netip.Addr{}, "", false
}

// lowerASCII lowercases ASCII letters only. DNS folds case for ASCII alone;
// Unicode lowercasing would match hosts the transport dials as different names
// (U+0130 lowercases to "i", but IDNA maps it to another label).
func lowerASCII(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		if c := s[i]; 'A' <= c && c <= 'Z' {
			if b == nil {
				b = []byte(s)
			}
			b[i] = c + 'a' - 'A'
		}
	}
	if b == nil {
		return s
	}
	return string(b)
}

// hasEmptyLabel reports whether a dotted name is empty or has an empty label.
func hasEmptyLabel(name string) bool {
	return name == "" || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..")
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// canonicalizeTarget returns r with the host of its target (the CONNECT
// authority, or the host of an absolute-form URL) in canonical form, so every
// later policy, credential and dial decision reads one name. It returns r when
// nothing changes and a copy otherwise.
func canonicalizeTarget(r *http.Request) (*http.Request, error) {
	u := r.URL
	if r.Method == http.MethodConnect {
		c := *r.URL
		c.Host = r.Host
		u = &c
	} else if u.Host == "" {
		return r, nil
	}
	canon, err := canonicalizeURLHost(u)
	if err != nil || canon == u {
		return r, err
	}
	out := new(http.Request)
	*out = *r
	out.URL, out.Host = canon, canon.Host
	return out, nil
}

// canonicalizeURLHost returns u with its host canonical (see
// canonicalTargetHost), or u itself when nothing changes. Relay and MCP target
// URLs go through it too, so what is matched is what is dialed.
func canonicalizeURLHost(u *url.URL) (*url.URL, error) {
	host := u.Hostname()
	canon, err := canonicalTargetHost(host)
	if err != nil {
		return nil, err
	}
	if canon == host {
		return u, nil
	}
	out := *u
	out.Host = canon
	if port := u.Port(); port != "" {
		out.Host = net.JoinHostPort(canon, port)
	} else if strings.Contains(canon, ":") {
		out.Host = "[" + canon + "]"
	}
	return &out, nil
}

// authorityMatchesConnect reports whether the authority of a request inside a
// CONNECT tunnel (its Host header, or the host of an absolute-form URL) names
// the CONNECT target. Credentials are resolved for the target and the request
// is dialed to it, so another authority would get the target's credential on a
// virtual host the policy never checked. Hosts compare canonically and without
// ASCII case; the inner port may be absent or must equal the CONNECT port; an
// empty authority (HTTP/1.0 without Host) matches.
func authorityMatchesConnect(connect, inner string) bool {
	if inner == "" {
		return true
	}
	connectHost, connectPort, err := net.SplitHostPort(connect)
	if err != nil {
		return false
	}
	innerHost, innerPort, err := net.SplitHostPort(inner)
	if err != nil {
		innerHost, innerPort = strings.TrimSuffix(strings.TrimPrefix(inner, "["), "]"), ""
	}
	connectHost, err1 := canonicalTargetHost(connectHost)
	innerHost, err2 := canonicalTargetHost(innerHost)
	if err1 != nil || err2 != nil || !sameHost(connectHost, innerHost) {
		return false
	}
	return innerPort == "" || samePort(connectPort, innerPort)
}

// sameHost compares canonical hosts: IP literals by address, names without
// ASCII case.
func sameHost(a, b string) bool {
	x, errA := netip.ParseAddr(a)
	y, errB := netip.ParseAddr(b)
	if errA == nil && errB == nil {
		return x.Unmap() == y.Unmap()
	}
	return lowerASCII(a) == lowerASCII(b)
}
