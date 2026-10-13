package proxy

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// rewriteURLHost replaces the host in rawURL with newHost, preserving scheme,
// port, path, query, and fragment. Falls back to the original string on parse
// failure. Uses url.Parse rather than strings.Replace so bracketed IPv6 hosts
// like "http://[::1]:8080/path" rewrite to a valid URL (e.g. "http://127.0.0.1:8080/path"
// rather than "http://[127.0.0.1]:8080/path"), and so path or query text that
// happens to match the host literal is not corrupted.
func rewriteURLHost(rawURL, newHost string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	if port := u.Port(); port != "" {
		u.Host = net.JoinHostPort(newHost, port)
	} else if strings.Contains(newHost, ":") {
		// Bracket bare IPv6 hosts; url.URL.Host expects "[::1]", not "::1".
		u.Host = "[" + newHost + "]"
	} else {
		u.Host = newHost
	}
	return u.String()
}

// rewriteHostPort replaces the host portion of a "host:port" address with
// newHost, emitting bracketed form for IPv6 when necessary. Falls back to the
// original string on parse failure.
func rewriteHostPort(hostPort, newHost string) string {
	_, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	return net.JoinHostPort(newHost, port)
}

// isHostGateway returns true if the given host matches the run's host gateway address.
// Also matches loopback aliases when the gateway routes to loopback, preventing
// containers from bypassing policy by connecting to "localhost" or "::1" directly.
func isHostGateway(rc *RunContextData, host string) bool {
	if rc == nil || rc.HostGateway == "" {
		return false
	}
	if host == rc.HostGateway {
		return true
	}
	if gatewayRoutesToLoopback(rc) {
		return isLoopbackAlias(host)
	}
	return false
}

func isLoopbackAlias(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(host, "[]"), "."))
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	a = a.WithZone("").Unmap()
	return a.IsLoopback() || a.IsUnspecified()
}

// gatewayRoutesToLoopback reports whether the host gateway ultimately routes
// to a loopback address. Checks HostGatewayIP first (the resolved forwarding
// address), falling back to HostGateway itself (which may be a loopback IP
// directly, or a synthetic hostname that implies loopback forwarding).
func gatewayRoutesToLoopback(rc *RunContextData) bool {
	if rc.HostGatewayIP != "" {
		ip := net.ParseIP(rc.HostGatewayIP)
		return ip != nil && ip.IsLoopback()
	}
	ip := net.ParseIP(rc.HostGateway)
	if ip != nil {
		return ip.IsLoopback()
	}
	// Non-IP gateway (synthetic hostname) without HostGatewayIP set — assume
	// loopback since synthetic hostnames are injected into container /etc/hosts
	// pointing at the host, which is loopback from the proxy's perspective.
	return true
}

// isAllowedHostPort returns true if the given port is in the run's allowed host ports list.
func isAllowedHostPort(rc *RunContextData, port int) bool {
	for _, p := range rc.AllowedHostPorts {
		if p == port {
			return true
		}
	}
	return false
}

// checkNetworkPolicyForRequest checks network policy using RunContextData first,
// then falling back to the proxy's own policy.
//
// For CONNECT requests, only host-level checking is performed. Per-path rules
// are enforced on the inner HTTP requests after TLS interception.
func (p *Proxy) checkNetworkPolicyForRequest(r *http.Request, host string, port int, method, path string) bool {
	if rc := getRunContext(r); rc != nil {
		// Block host-gateway traffic unless the port is explicitly allowed.
		if isHostGateway(rc, host) {
			return isAllowedHostPort(rc, port)
		}
		if method != "CONNECT" && rc.RequestCheck != nil {
			return rc.RequestCheck(host, port, method, path)
		}
		if rc.Policy != "strict" {
			return true
		}
		return matchHost(rc.AllowedHosts, host, port)
	}

	p.mu.RLock()
	checker := p.requestChecker
	p.mu.RUnlock()

	if method != "CONNECT" && checker != nil {
		return checker(host, port, method, path)
	}
	return p.checkNetworkPolicy(host, port)
}

// hasPathRulesForHost returns true if any matching host entry has per-path rules.
func (p *Proxy) hasPathRulesForHost(r *http.Request, host string, port int) bool {
	if rc := getRunContext(r); rc != nil {
		if rc.PathRulesCheck != nil {
			return rc.PathRulesCheck(host, port)
		}
		return false
	}
	p.mu.RLock()
	checker := p.pathRulesChecker
	p.mu.RUnlock()
	if checker != nil {
		return checker(host, port)
	}
	return false
}

// getMCPServersForRequest returns MCP servers from RunContextData or falls
// back to the proxy's own list.
func (p *Proxy) getMCPServersForRequest(r *http.Request) []MCPServerConfig {
	if rc := getRunContext(r); rc != nil {
		return rc.MCPServers
	}
	return p.mcpServers
}

// getCredStoreForRequest returns the credential store from RunContextData
// or falls back to the proxy's own store.
func (p *Proxy) getCredStoreForRequest(r *http.Request) credentialStore {
	if rc := getRunContext(r); rc != nil && rc.CredStore != nil {
		return rc.CredStore
	}
	return p.credStore
}

// getAWSHandlerForRequest returns the AWS handler from RunContextData
// or falls back to the proxy's own handler.
func (p *Proxy) getAWSHandlerForRequest(r *http.Request) http.Handler {
	if rc := getRunContext(r); rc != nil && rc.AWSHandler != nil {
		return rc.AWSHandler
	}
	return p.awsHandler
}

// handleDirectMCPRelay handles MCP relay requests that arrive directly (not through proxy).
// URL format: /mcp/{token}/{server-name}[/path]
// Extracts the auth token from the URL, resolves run context, rewrites the path
// to strip the token, and dispatches to handleMCPRelay.
func (p *Proxy) handleDirectMCPRelay(w http.ResponseWriter, r *http.Request) {
	// Parse: /mcp/{token}/{name}[/subpath]
	rest := strings.TrimPrefix(r.URL.Path, "/mcp/")
	idx := strings.IndexByte(rest, '/')
	if idx < 0 {
		// No server name after token — malformed URL
		http.Error(w, "invalid MCP relay URL", http.StatusBadRequest)
		return
	}
	token := rest[:idx]
	remainder := rest[idx:] // starts with /, e.g. /server-name or /server-name/subpath

	rc, found := p.contextResolver(token)
	if !found {
		w.Header().Set("WWW-Authenticate", `Basic realm="gatekeeper"`)
		http.Error(w, "Invalid proxy token", http.StatusUnauthorized)
		return
	}

	// Rewrite path to strip token: /mcp/{name}[/subpath]
	r.URL.Path = "/mcp" + remainder
	ctx := context.WithValue(r.Context(), runContextKey, rc)
	r = r.WithContext(ctx)
	p.handleMCPRelay(w, r)
}

// handleDirectAWSCredentials handles AWS credential endpoint requests that arrive
// directly from containers. The credential helper sends Authorization: Bearer {token}
// where token is the run's proxy auth token. We extract it to resolve run context,
// then dispatch to the per-run AWS handler.
func (p *Proxy) handleDirectAWSCredentials(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		http.Error(w, "Authorization required", http.StatusUnauthorized)
		return
	}
	token := auth[7:]

	rc, found := p.contextResolver(token)
	if !found {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	if rc.AWSHandler == nil {
		http.Error(w, "AWS credentials not configured for this run", http.StatusNotFound)
		return
	}

	ctx := context.WithValue(r.Context(), runContextKey, rc)
	r = r.WithContext(ctx)
	rc.AWSHandler.ServeHTTP(w, r)
}
