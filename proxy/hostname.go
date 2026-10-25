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

// canonicalTargetHost returns the name the upstream transport dials for a
// request to host, so that policy and credential matching decide on the same
// name the connection goes to.
//
// A non-ASCII host is mapped to its ASCII (A-label) form with the IDNA Lookup
// profile, the mapping net/http applies before it dials. That mapping turns
// U+3002, U+FF0E and U+FF61 into "." and U+0130 into a different label from
// "i", differences a byte-wise match on the raw host cannot see. One trailing
// root dot is dropped, so "api.example.com." is the host "api.example.com"
// for exact, "*." and prefix patterns alike. An IP literal is returned in its
// canonical text form. It returns an error for a host that has no dialable
// form: an empty label, a name IDNA rejects, or an IPv6 literal with a zone
// (the zone is free text, and the dial ignores it for an IPv4-mapped address).
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
// 0x-hexadecimal number. No DNS name ends in one (a top-level domain is never
// numeric), but libc's inet_aton, which the cgo resolver follows, reads such a
// name as an IPv4 address in a form Go's parser rejects: "0177.0.0.1",
// "127.1", "0x7f.1", "2130706433" all mean 127.0.0.1. A host that ends in a
// number is therefore either a canonical dotted quad or refused.
func endsInNumber(host string) bool {
	label := host[strings.LastIndexByte(host, '.')+1:]
	if rest, ok := strings.CutPrefix(strings.ToLower(label), "0x"); ok {
		return strings.Trim(rest, "0123456789abcdef") == ""
	}
	return label != "" && strings.Trim(label, "0123456789") == ""
}

// isIPv4Literal reports whether host is a canonical dotted-quad IPv4 address.
func isIPv4Literal(host string) bool {
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.Is4()
}

// ipKeyMatches reports whether key is an IP literal key (see splitIPKey) that
// names hostAddr, and whether the key is pinned to a port that equals
// hostPort. An address compares after Unmap, so "127.0.0.1" and
// "::ffff:127.0.0.1" are one address, and a port compares as a number. A key
// with a port that differs from hostPort does not match.
func ipKeyMatches(key string, hostAddr netip.Addr, hostPort string) (match, pinned bool) {
	addr, port, ok := splitIPKey(key)
	if !ok || addr.WithZone("").Unmap() != hostAddr.WithZone("").Unmap() {
		return false, false
	}
	if port == "" {
		return true, false
	}
	want, err1 := strconv.Atoi(port)
	got, err2 := strconv.Atoi(hostPort)
	return err1 == nil && err2 == nil && want == got, true
}

// isIPLiteral reports whether host, bare or in brackets, with or without a
// zone, is an IP address. An address is never a DNS name: a "*." or prefix
// pattern must not match one, however its text ends (a zone is free text, and
// "192.0.2.1" ends in ".0.2.1").
func isIPLiteral(host string) bool {
	_, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"))
	return err == nil
}

// hostKey validates and normalizes the key of a host-keyed setter that takes
// a port-pinned key: a host pattern (ValidateHostPattern), or an exact IP
// literal, IPv4 or IPv6, bare or in brackets, with an optional port
// ("::1", "[::1]:8080", "127.0.0.1:8080"). An IP key is returned in the form
// a request's lookup host takes, which is the canonical address, bracketed
// when it has a port. A zone is refused: it is never part of a request host.
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

// splitIPKey splits an IP literal key into its address and port.
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

// lowerASCII lowercases the ASCII letters of s and nothing else. DNS folds
// case for ASCII only: Unicode lowercasing would match hosts the transport
// dials as different names (U+0130 lowercases to "i", but IDNA maps it to a
// different label), so every host comparison folds with this.
func lowerASCII(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; 'A' <= c && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if 'A' <= b[j] && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
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

// canonicalizeTarget returns r with the host of its target in canonical form
// (see canonicalTargetHost): the CONNECT authority, or the host of an
// absolute-form URL. Every later policy, credential and dial decision reads
// that one form. It returns r itself when nothing changes, and a copy
// otherwise, so the caller's request is never modified. A request that is
// not a proxy request (no URL host) and a CONNECT without a port pass
// through; the handlers answer those.
func canonicalizeTarget(r *http.Request) (*http.Request, error) {
	var host, port string
	if r.Method == http.MethodConnect {
		var err error
		if host, port, err = net.SplitHostPort(r.Host); err != nil {
			return r, nil
		}
	} else if r.URL.Host != "" {
		u, err := canonicalizeURLHost(r.URL)
		if err != nil || u == r.URL {
			return r, err
		}
		out := new(http.Request)
		*out = *r
		out.URL, out.Host = u, u.Host
		return out, nil
	} else {
		return r, nil
	}
	canon, err := canonicalTargetHost(host)
	if err != nil {
		return nil, err
	}
	if canon == host {
		return r, nil
	}
	target := net.JoinHostPort(canon, port)
	out := new(http.Request)
	*out = *r
	u := *r.URL
	u.Host = target
	out.URL = &u
	out.Host = target
	return out, nil
}

// canonicalizeURLHost returns u with its host in canonical form (see
// canonicalTargetHost), keeping the port. It returns u itself when nothing
// changes and a copy otherwise. A target URL that came from configuration
// (a relay, an MCP server) goes through it too, so what is matched is what is
// dialed.
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
// the CONNECT target. The proxy resolves credentials for the CONNECT target
// and dials it, so a request for another authority would have the target's
// credential sent to a virtual host the policy never checked.
//
// Hosts compare after the canonicalTargetHost mapping and case folding. An
// inner authority without a port, or with the CONNECT port, matches; any
// other port does not. An empty authority (an HTTP/1.0 request with no Host
// header) names the CONNECT target by default.
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
	if err1 != nil || err2 != nil || !sameHostName(connectHost, innerHost) {
		return false
	}
	if innerPort == "" {
		return true
	}
	want, err1 := strconv.Atoi(connectPort)
	got, err2 := strconv.Atoi(innerPort)
	return err1 == nil && err2 == nil && want == got
}

// sameHostName compares two canonical hosts: IP literals by address, names
// without regard to case.
func sameHostName(a, b string) bool {
	x, errA := netip.ParseAddr(a)
	y, errB := netip.ParseAddr(b)
	if errA == nil && errB == nil {
		return x.WithZone("").Unmap() == y.WithZone("").Unmap()
	}
	return lowerASCII(a) == lowerASCII(b)
}
