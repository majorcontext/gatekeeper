package proxy

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// relayClient is a reused HTTP client for relay requests. It bypasses proxy
// settings to prevent circular proxy loops — the proxy runs on the host,
// where localhost correctly reaches host-side services.
var relayClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	Transport: &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 5 * time.Minute,
		IdleConnTimeout:       90 * time.Second,
	},
}

// AddRelay registers a named relay endpoint. Requests to /relay/{name}/{path...}
// are forwarded to the target URL with credential injection. This is used when
// the target host would be in NO_PROXY (e.g., a host-side proxy reachable via
// the same address as the proxy), which would cause direct connections to
// bypass credential injection.
//
// AddRelay must be called before the proxy starts serving.
func (p *Proxy) AddRelay(name, targetURL string) error {
	if name == "" || strings.ContainsAny(name, "/ \t\n\r") {
		return fmt.Errorf("invalid relay name %q: must be non-empty with no slashes or whitespace", name)
	}
	u, err := url.Parse(targetURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("invalid relay target URL %q", targetURL)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.relays == nil {
		p.relays = make(map[string]string)
	}
	p.relays[name] = targetURL
	return nil
}

// handleRelay proxies requests through the proxy to a configured target
// URL with credential injection.
//
// Path format: /relay/{name}/{path...}
// The /relay/{name} prefix is stripped, and the remaining path is appended
// to the configured target URL.
func (p *Proxy) handleRelay(w http.ResponseWriter, r *http.Request) {
	if p.delegateAuth && p.authToken == "" {
		writeProxyAuthRequired(w, "Proxy authentication required")
		return
	}
	// handleRelay is reached directly (the NO_PROXY bypass in ServeHTTP),
	// bypassing the CONNECT/plain-HTTP auth chain entirely, so it enforces
	// authToken itself before any resolver or STS call. Absent credentials
	// are unaffected: relay traffic requires no Proxy-Authorization at all.
	if rejected, _ := p.rejectMismatchedAuth(w, r); rejected {
		return
	}

	start := time.Now()

	// Extract relay name from path: /relay/anthropic/v1/messages -> anthropic
	relPath := strings.TrimPrefix(r.URL.Path, "/relay/")
	name, rest, _ := strings.Cut(relPath, "/")
	if rest != "" {
		rest = "/" + rest
	}

	// Base canonical log entry shared by every exit path below. Each path
	// copies it and sets only its own StatusCode/Duration/Err/credential
	// fields. URL and Host are refreshed once the target URL and lookup
	// host are known.
	logBase := RequestLogData{
		Method:       r.Method,
		URL:          r.URL.String(),
		Host:         name,
		Path:         rest,
		RequestType:  "relay",
		RequestSize:  r.ContentLength,
		ResponseSize: -1,
		ClientAddr:   r.RemoteAddr,
	}

	// Look up relay target
	p.mu.RLock()
	target, ok := p.relays[name]
	p.mu.RUnlock()

	if !ok {
		// No Err: a typo'd relay name is a client/config mistake, not a
		// proxy-side failure — the 404 status and request URL already
		// identify it. Mirrors the parallel unknown-MCP-server 404 in
		// mcp.go, which also carries no Err.
		p.logExit(r, logBase, start, http.StatusNotFound, nil)
		http.Error(w, p.errorPrefix()+": Unknown relay endpoint '"+name+"'", http.StatusNotFound)
		return
	}

	// Build target URL
	targetURL, err := url.Parse(target)
	if err != nil {
		p.logExit(r, logBase, start, http.StatusInternalServerError, func(d *RequestLogData) { d.Err = err })
		http.Error(w, p.errorPrefix()+": Invalid relay target URL", http.StatusInternalServerError)
		return
	}
	targetURL.Path = strings.TrimSuffix(targetURL.Path, "/") + rest
	targetURL.RawQuery = r.URL.RawQuery

	// The lookup host carries a port — with the scheme default made
	// explicit when the target URL omits it — so port-pinned host keys
	// match on the relay path like they do on CONNECT and plain HTTP.
	// Computed before the request is built so logging on every exit path
	// below (including request-construction failure) can carry it.
	host := lookupHostForURL(targetURL)
	logBase.URL = targetURL.String()
	logBase.Host = host

	// Create forwarded request
	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL.String(), r.Body)
	if err != nil {
		p.logExit(r, logBase, start, http.StatusInternalServerError, func(d *RequestLogData) { d.Err = err })
		http.Error(w, p.errorPrefix()+": Failed to create relay request", http.StatusInternalServerError)
		return
	}
	proxyReq.ContentLength = r.ContentLength

	// Resolve credentials before copying headers so resolver side effects
	// (e.g., subject header stripping) are reflected in proxyReq.
	resolved, err := p.getCredentialsForRequest(r, r, host)
	if err != nil {
		if p.refusesMissingCredential(w, err) {
			p.logExit(r, logBase, start, http.StatusForbidden, func(d *RequestLogData) { d.Denied, d.DenyReason = true, err.Error() })
			return
		}
		slog.Warn("dynamic credential resolution failed",
			"subsystem", "proxy", "host", host, "error", err)
		p.logExit(r, logBase, start, http.StatusBadGateway, func(d *RequestLogData) { d.Err = err })
		http.Error(w, "credential resolution failed", http.StatusBadGateway)
		return
	}

	if p.refusesCleartextInjection(r, targetURL.Scheme, host, resolved.creds) {
		p.logExit(r, logBase, start, http.StatusForbidden, func(d *RequestLogData) {
			d.Denied = true
			d.DenyReason = "credential injection over plain HTTP refused: " + host
		})
		p.writeCleartextRefusal(w, targetURL.Hostname())
		return
	}

	for key, values := range r.Header {
		if key == "Proxy-Authorization" || key == "Proxy-Connection" {
			continue
		}
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	bundleResult := injectCredentialBundles(proxyReq, p.getCredentialBundlesForRequest(r), targetURL.Scheme, targetURL.Host)
	if bundleResult.Skipped {
		p.logPolicyObservation(r, "credential-bundle", "http.request", "", bundleResult.Reason)
	}
	credResult := p.prepareOutbound(r, proxyReq, outboundPrep{
		creds:      resolved.creds,
		bundle:     bundleResult.credentialInjectionResult,
		host:       host,
		lookupHost: host,
		path:       rest,
	})

	if proxyReq.Header.Get("X-Request-Id") == "" {
		proxyReq.Header.Set("X-Request-Id", RequestIDFromContext(r.Context()))
	}

	// Forward to target
	resp, err := relayClient.Do(proxyReq)
	if err != nil {
		slog.Debug("relay failed",
			"subsystem", "proxy",
			"action", "relay-error",
			"relay", name,
			"target", targetURL.String(),
			"error", err)
		p.logExit(r, logBase, start, http.StatusBadGateway, func(d *RequestLogData) {
			d.Err = err
			d.InjectedHeaders = credResult.InjectedHeaders
			d.Grants = credResult.Grants
		})
		http.Error(w, p.errorPrefix()+": Relay '"+name+"' connection failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	settleUpstreamResponse(resp, credResult.Injected, resolved.declined)

	written, streamErr := forwardStreaming(r.Context(), w, resp)

	p.logExit(r, logBase, start, resp.StatusCode, func(d *RequestLogData) {
		d.Err = streamErr
		d.ResponseSize = written
		d.InjectedHeaders = credResult.InjectedHeaders
		d.Grants = credResult.Grants
	})
}
