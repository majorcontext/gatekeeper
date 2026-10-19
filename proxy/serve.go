package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ServeHTTP handles proxy requests.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Assign a request ID: use X-Request-Id from the caller if present, otherwise generate one.
	reqID := r.Header.Get("X-Request-Id")
	if reqID == "" {
		reqID = newRequestID()
	}
	r = r.WithContext(withRequestID(r.Context(), reqID))
	w.Header().Set("X-Request-Id", reqID)

	// Relay endpoints are accessed directly (via NO_PROXY bypass), not through
	// the proxy mechanism, so they appear as direct HTTP requests (r.URL.Host is
	// empty). We check r.URL.Host == "" to distinguish direct requests from
	// proxied requests that happen to have /relay/ in the path — without this,
	// a proxied request to http://anything.com/relay/foo would match and bypass auth.
	// This chain's context/delegateAuth checks below are skipped — handleRelay
	// enforces authToken itself (see rejectMismatchedAuth) — and relays only
	// forward to pre-configured URLs, not arbitrary hosts.
	if len(p.relays) > 0 && r.URL.Host == "" && strings.HasPrefix(r.URL.Path, "/relay/") {
		p.handleRelay(w, r)
		return
	}

	// Direct MCP relay requests from containers (via NO_PROXY bypass).
	// URL format: /mcp/{token}/{server-name}[/path]
	// The auth token is embedded in the URL because direct requests don't carry
	// Proxy-Authorization. We resolve run context from the token, strip it from
	// the path, and dispatch to handleMCPRelay.
	if p.contextResolver != nil && r.URL.Host == "" && strings.HasPrefix(r.URL.Path, "/mcp/") {
		p.handleDirectMCPRelay(w, r)
		return
	}

	// Direct AWS credential endpoint requests from containers.
	// The credential helper sends Authorization: Bearer {token} (not Proxy-Authorization).
	// We extract the run's auth token from that header to resolve context.
	if p.contextResolver != nil && r.URL.Host == "" && strings.HasPrefix(r.URL.Path, "/_aws/") {
		p.handleDirectAWSCredentials(w, r)
		return
	}

	// Authentication and context resolution.
	// When a contextResolver is set (daemon mode), extract the proxy auth token,
	// resolve it to per-run context data, and store it in the request context.
	// When no contextResolver is set (legacy single-run mode), use p.authToken check.
	if p.contextResolver != nil {
		token, ok := proxyToken(r)
		if !ok {
			writeProxyAuthRequired(w, "Proxy authentication required")
			return
		}
		rc, found := p.contextResolver(token)
		if !found {
			writeProxyAuthRequired(w, "Proxy authentication required")
			return
		}
		ctx := context.WithValue(r.Context(), runContextKey, rc)
		if uid, _, _ := ProxyAuth(r); uid != "" {
			ctx = withUserID(ctx, uid)
		}
		r = r.WithContext(ctx)
	} else if p.delegateAuth {
		if p.authToken == "" {
			writeProxyAuthRequired(w, "Proxy authentication required")
			return
		}
		// A password that mismatches a configured authToken is rejected even under delegateAuth.
		if rejected, _ := p.rejectMismatchedAuth(w, r); rejected {
			return
		}
		if _, pass, ok := ProxyAuth(r); !ok || pass == "" {
			writeProxyAuthRequired(w, "Proxy authentication required")
			return
		}
		if uid, _, _ := ProxyAuth(r); uid != "" {
			r = r.WithContext(withUserID(r.Context(), uid))
		}
	} else if p.authToken != "" {
		rejected, present := p.rejectMismatchedAuth(w, r)
		if rejected {
			return
		}
		if !present {
			writeProxyAuthRequired(w, "Proxy authentication required")
			return
		}
		if uid, _, _ := ProxyAuth(r); uid != "" {
			r = r.WithContext(withUserID(r.Context(), uid))
		}
	}

	// Handle AWS credential endpoint
	if awsH := p.getAWSHandlerForRequest(r); awsH != nil && strings.HasPrefix(r.URL.Path, "/_aws/credentials") {
		awsH.ServeHTTP(w, r)
		return
	}

	// Handle MCP relay endpoint
	if strings.HasPrefix(r.URL.Path, "/mcp/") {
		p.handleMCPRelay(w, r)
		return
	}

	// Inject MCP credentials if request matches configured server
	p.injectMCPCredentials(r)

	// Log the proxied request
	if r.Method == http.MethodConnect {
		host, port, _ := net.SplitHostPort(r.Host)
		slog.Debug("proxy connect",
			"subsystem", "proxy",
			"action", "connect",
			"host", host,
			"port", port)
		p.handleConnect(w, r)
		return
	}

	slog.Debug("proxy request",
		"subsystem", "proxy",
		"action", "forward",
		"method", r.Method,
		"host", r.URL.Hostname(),
		"port", r.URL.Port(),
		"path", r.URL.Path)
	p.handleHTTP(w, r)
}

// lookupHostForURL returns the URL's host with a port always present — the
// URL's own port when it has one, otherwise the scheme default — so
// port-pinned host keys match however the target was spelled (e.g. a key
// pinned to ":80" fires for "http://host/" as well as "http://host:80/").
// JoinHostPort also re-brackets IPv6 literals correctly.
//
// handleHTTP does not use this helper for its lookup host: it has its own
// int port derived for the network-policy check, and builds the lookup
// host from that same int so the two can never diverge. This helper
// remains the source of the lookup host for handleRelay, which has no
// separate policy-port derivation to stay in sync with.
func lookupHostForURL(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Extract host and infer port from scheme.
	host := r.URL.Hostname()

	// Capture request body before forwarding
	var reqBody []byte
	reqBody, r.Body = captureBody(r.Body, r.Header.Get("Content-Type"))

	port := 80
	if r.URL.Scheme == "https" {
		port = 443
	}
	if r.URL.Port() != "" {
		// Port explicitly specified in URL
		var err error
		port, err = net.LookupPort("tcp", r.URL.Port())
		if err != nil {
			port = 80 // fallback
		}
	}

	// Host-keyed lookups get host:port — with the scheme-default port made
	// explicit, so a key pinned to ":80" fires for "http://host/" too —
	// while host stays bare for policy checks and logging. Built from the
	// same int the network-policy check below uses (not lookupHostForURL's
	// raw URL-port parse), so the two can never disagree about which port
	// a request is really headed to — e.g. an out-of-range URL port like
	// ":99999" falls back to 80 for policy, and the credential lookup must
	// see :80 too.
	lookupHost := net.JoinHostPort(host, strconv.Itoa(port))

	// Check network policy
	if !p.checkNetworkPolicyForRequest(r, host, port, r.Method, r.URL.Path) {
		duration := time.Since(start)
		// Log blocked request
		rc := getRunContext(r)
		var denyReason string
		if rc != nil && isHostGateway(rc, host) {
			denyReason = "Host service blocked: " + host + ":" + strconv.Itoa(port)
		} else {
			denyReason = "Host not in allow list: " + host
		}
		p.logRequest(r, RequestLogData{
			Method:         r.Method,
			URL:            r.URL.String(),
			Host:           host,
			Path:           r.URL.Path,
			RequestType:    "http",
			StatusCode:     http.StatusProxyAuthRequired,
			Duration:       duration,
			RequestHeaders: p.logHeadersRedacted(r.Header, lookupHost),
			RequestBody:    reqBody,
			RequestSize:    r.ContentLength,
			ResponseSize:   -1,
			Denied:         true,
			DenyReason:     denyReason,
			ClientAddr:     r.RemoteAddr,
		})
		if rc != nil && isHostGateway(rc, host) {
			p.logPolicy(r, "network", "http.request", "", "Host service blocked: "+host+":"+strconv.Itoa(port))
			p.writeHostBlockedResponse(w, host, port)
		} else {
			p.logPolicy(r, "network", "http.request", "", "Host not in allow list: "+host)
			p.writeBlockedResponse(w, host)
		}
		return
	}

	// Resolve credentials only after the policy check: resolvers can have
	// external side effects (e.g. token-exchange round trips), which a
	// client must not be able to trigger through policy-denied hosts —
	// and a denied client must see the policy denial, not a resolver
	// error. Same order as the CONNECT interception path.
	resolved, err := p.getCredentialsForRequest(r, r, lookupHost)
	if err != nil {
		http.Error(w, "credential resolution failed", http.StatusBadGateway)
		p.logRequest(r, RequestLogData{
			Method:         r.Method,
			URL:            r.URL.String(),
			Host:           host,
			Path:           r.URL.Path,
			RequestType:    "http",
			StatusCode:     http.StatusBadGateway,
			Duration:       time.Since(start),
			RequestHeaders: p.logHeadersRedacted(r.Header, lookupHost),
			RequestSize:    r.ContentLength,
			ResponseSize:   -1,
			Err:            err,
			ClientAddr:     r.RemoteAddr,
		})
		return
	}

	if p.refusesCleartextInjection(r, r.URL.Scheme, lookupHost, resolved.creds) {
		p.logRequest(r, RequestLogData{
			Method:       r.Method,
			URL:          r.URL.String(),
			Host:         host,
			Path:         r.URL.Path,
			RequestType:  "http",
			StatusCode:   http.StatusForbidden,
			Duration:     time.Since(start),
			RequestSize:  r.ContentLength,
			ResponseSize: -1,
			Denied:       true,
			DenyReason:   "credential injection over plain HTTP refused: " + host,
			ClientAddr:   r.RemoteAddr,
		})
		p.writeCleartextRefusal(w, host)
		return
	}

	// Snapshot request headers for logging only after credential
	// resolution: a resolver may have stripped a subject-identity token
	// from the request, and credential values must never be logged.
	originalReqHeaders := r.Header.Clone()

	// Rewrite synthetic host-gateway hostname to actual IP for forwarding.
	// The container uses a synthetic hostname (only in its /etc/hosts),
	// but the proxy runs on the host where that name doesn't resolve.
	outURL := r.URL.String()
	if rc := getRunContext(r); rc != nil && rc.HostGatewayIP != "" && isHostGateway(rc, host) {
		outURL = rewriteURLHost(outURL, rc.HostGatewayIP)
	}

	// Create outgoing request
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, outURL, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	outReq.ContentLength = r.ContentLength

	// Copy headers and inject credentials
	for key, values := range r.Header {
		for _, value := range values {
			outReq.Header.Add(key, value)
		}
	}
	bundleResult := injectCredentialBundles(outReq, p.getCredentialBundlesForRequest(r), r.URL.Scheme, lookupHost)
	if bundleResult.Skipped {
		// Nothing was injected and the request continues. Record it: a bundle
		// whose scope does not match where its client actually goes is a
		// configuration problem, and without this it would be invisible.
		p.logPolicyObservation(r, "credential-bundle", "http.request", "", bundleResult.Reason)
	}
	credResult := p.prepareOutbound(r, outReq, outboundPrep{
		creds:      resolved.creds,
		bundle:     bundleResult.credentialInjectionResult,
		host:       host,
		lookupHost: lookupHost,
		path:       r.URL.Path,
	})

	if outReq.Header.Get("X-Request-Id") == "" {
		outReq.Header.Set("X-Request-Id", RequestIDFromContext(r.Context()))
	}

	// Forward request
	resp, err := p.httpTransportFor(getRunContext(r)).RoundTrip(outReq)

	// Fields shared by the error and success log lines.
	logData := RequestLogData{
		Method:          r.Method,
		URL:             r.URL.String(),
		Host:            host,
		Path:            r.URL.Path,
		RequestType:     "http",
		RequestHeaders:  originalReqHeaders,
		RequestBody:     reqBody,
		RequestSize:     r.ContentLength,
		ResponseSize:    -1,
		ClientAddr:      r.RemoteAddr,
		InjectedHeaders: credResult.InjectedHeaders,
		Grants:          credResult.Grants,
	}

	if err != nil {
		logData.StatusCode = http.StatusBadGateway
		logData.Duration = time.Since(start)
		logData.Err = err
		p.logRequest(r, logData)
		http.Error(w, p.errorPrefix()+": upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	settleUpstreamResponse(resp.Header, resp.StatusCode, credResult.Injected, resolved.declined)

	logData.StatusCode = resp.StatusCode
	logData.ResponseHeaders = resp.Header.Clone()
	logData.ResponseSize = resp.ContentLength

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Stream to the client, capturing a bounded sample for logging without a
	// blocking read-ahead (which would starve a streamed response). The log line
	// is written after the body completes. Non-text bodies carry no useful
	// sample, so they stream straight through.
	if isTextContentType(resp.Header.Get("Content-Type")) {
		cb := newCapturingBody(resp.Body, MaxBodySize, nil)
		_, _ = io.Copy(w, cb)
		logData.ResponseBody = cb.Captured()
	} else {
		_, _ = io.Copy(w, resp.Body)
	}
	logData.Duration = time.Since(start)
	p.logRequest(r, logData)
}
