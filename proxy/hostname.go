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
// for exact, "*." and prefix patterns alike. An IP literal passes unchanged.
// It returns an error for a host that has no dialable form: an empty label,
// or a name IDNA rejects.
func canonicalTargetHost(host string) (string, error) {
	if strings.Contains(host, ":") {
		if _, err := netip.ParseAddr(host); err != nil {
			return "", fmt.Errorf("invalid IP literal %q", host)
		}
		return host, nil
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
	return host, nil
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
