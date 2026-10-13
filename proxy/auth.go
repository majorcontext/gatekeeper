package proxy

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

// ProxyAuth returns the user and password of a Basic Proxy-Authorization
// header. ok is false when the header is absent, is not Basic, is not valid
// base64, or has no ":" separator. Bearer credentials are not Basic and
// report ok false.
func ProxyAuth(r *http.Request) (user, pass string, ok bool) {
	if r == nil {
		return "", "", false
	}
	auth := r.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(auth[6:])
	if err != nil {
		return "", "", false
	}
	user, pass, ok = strings.Cut(string(decoded), ":")
	if !ok {
		return "", "", false
	}
	return user, pass, true
}

// proxyToken returns the token of a Bearer header or the password of a
// Basic header.
func proxyToken(r *http.Request) (string, bool) {
	if auth := r.Header.Get("Proxy-Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return auth[7:], true
	}
	_, pass, ok := ProxyAuth(r)
	return pass, ok
}

// checkAuth validates the Proxy-Authorization header against the required
// token. Accepts both Basic auth (from HTTP_PROXY=http://moat:token@host)
// and Bearer format. Uses constant-time comparison to prevent timing
// attacks. present is false when the request carries no proxy credentials
// at all, in which case ok is meaningless; callers that only care whether
// a mismatched password was presented check present before ok.
func (p *Proxy) checkAuth(r *http.Request) (ok, present bool) {
	token, present := proxyToken(r)
	if !present {
		return false, false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(p.authToken)) == 1, true
}

// rejectMismatchedAuth calls checkAuth once and writes a 407 when the
// request presents a proxy password that does not equal authToken,
// returning rejected so the caller can stop. It never rejects for absence
// (present is false) or when authToken is empty, so callers that also need
// to require a password check present themselves instead of calling
// checkAuth again. The 407 body is identical to the "no credentials"
// response so a prober cannot tell whether authToken is configured; the
// WARN log never carries the presented value. Every caller that enforces
// authToken — the plain authToken branch, delegateAuth, and the relay path,
// which bypasses that chain entirely — calls this same check.
func (p *Proxy) rejectMismatchedAuth(w http.ResponseWriter, r *http.Request) (rejected, present bool) {
	ok, present := p.checkAuth(r)
	if !present || p.authToken == "" || ok {
		return false, present
	}
	slog.Warn("proxy auth mismatch", "subsystem", "proxy", "action", "auth-reject")
	writeProxyAuthRequired(w, "Proxy authentication required")
	return true, present
}

// checkNetworkPolicy checks if the host:port is allowed by the network policy.
// Returns true if allowed, false if blocked.
func (p *Proxy) checkNetworkPolicy(host string, port int) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Permissive policy allows everything
	if p.policy != "strict" {
		return true
	}

	// Strict policy requires host to match allowedHosts
	return matchHost(p.allowedHosts, host, port)
}

// checkNetworkPolicyPostgres checks if host is allowed by the network policy
// for Postgres data-plane traffic, evaluated at the Postgres default port
// (5432). It is the Postgres-plane counterpart to checkNetworkPolicy: same
// policy and allowedHosts state, but matched with matchHostPostgres
// (postgres.go) instead of matchHost, so a portless allow pattern (e.g.
// "*.neon.tech") means "matches port 5432" here instead of checkNetworkPolicy's
// HTTP-centric "matches ports 80/443". checkNetworkPolicy itself, and the
// HTTP/CONNECT path that calls it, are unaffected by this method's existence.
func (p *Proxy) checkNetworkPolicyPostgres(host string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.policy != "strict" {
		return true
	}
	return matchHostPostgres(p.allowedHosts, host)
}

// writeProxyAuthRequired writes a 407 with a Proxy-Authenticate challenge.
// Without the challenge header, clients like git's libcurl treat 407 as fatal
// and never retry with credentials.
func writeProxyAuthRequired(w http.ResponseWriter, msg string) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="gatekeeper"`)
	http.Error(w, msg, http.StatusProxyAuthRequired)
}

// writeBlockedResponse writes a 407 response when a request is blocked by network policy.
func (p *Proxy) writeBlockedResponse(w http.ResponseWriter, host string) {
	w.Header().Set("X-Moat-Blocked", "request-rule")
	w.Header().Set("Proxy-Authenticate", "Moat-Policy")
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusProxyAuthRequired)
	_, _ = w.Write([]byte("Moat: request blocked by network policy.\nHost \"" + host + "\" is not in the allow list.\nAdd it to network.rules in moat.yaml or use policy: permissive.\n"))
}

// writeHostBlockedResponse writes a 407 response when a request to the host gateway is blocked.
func (p *Proxy) writeHostBlockedResponse(w http.ResponseWriter, host string, port int) {
	w.Header().Set("X-Moat-Blocked", "host-service")
	w.Header().Set("Proxy-Authenticate", "Moat-Policy")
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusProxyAuthRequired)
	_, _ = fmt.Fprintf(w, "Moat: request blocked — host service access to %s:%d is not allowed by default.\n"+
		"To allow port %d on the host, add to moat.yaml:\n\n"+
		"  network:\n    host:\n      - %d\n", host, port, port, port)
}
