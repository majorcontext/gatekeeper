package proxy

import (
	"errors"
	"fmt"
	"io"
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
// the same address as the Moat proxy), which would cause direct connections to
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

// handleRelay proxies requests through the Moat proxy to a configured target
// URL with credential injection.
//
// Path format: /relay/{name}/{path...}
// The /relay/{name} prefix is stripped, and the remaining path is appended
// to the configured target URL.
func (p *Proxy) handleRelay(w http.ResponseWriter, r *http.Request) {
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
		logData := logBase
		logData.StatusCode = http.StatusNotFound
		logData.Duration = time.Since(start)
		logData.Err = errors.New("unknown relay endpoint: " + name)
		p.logRequest(r, logData)
		http.Error(w, "MOAT: Unknown relay endpoint '"+name+"'", http.StatusNotFound)
		return
	}

	// Build target URL
	targetURL, err := url.Parse(target)
	if err != nil {
		logData := logBase
		logData.StatusCode = http.StatusInternalServerError
		logData.Duration = time.Since(start)
		logData.Err = err
		p.logRequest(r, logData)
		http.Error(w, "MOAT: Invalid relay target URL", http.StatusInternalServerError)
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
		logData := logBase
		logData.StatusCode = http.StatusInternalServerError
		logData.Duration = time.Since(start)
		logData.Err = err
		p.logRequest(r, logData)
		http.Error(w, "MOAT: Failed to create relay request", http.StatusInternalServerError)
		return
	}

	// Resolve credentials before copying headers so resolver side effects
	// (e.g., subject header stripping) are reflected in proxyReq.
	creds, err := p.getCredentialsForRequest(r, r, host)
	if err != nil {
		slog.Warn("dynamic credential resolution failed",
			"subsystem", "proxy", "host", host, "error", err)
		logData := logBase
		logData.StatusCode = http.StatusBadGateway
		logData.Duration = time.Since(start)
		logData.Err = err
		p.logRequest(r, logData)
		http.Error(w, "credential resolution failed", http.StatusBadGateway)
		return
	}

	// Copy headers (skip proxy-specific ones)
	for key, values := range r.Header {
		if key == "Proxy-Authorization" || key == "Proxy-Connection" {
			continue
		}
		for _, value := range values {
			proxyReq.Header.Add(key, value)
		}
	}

	credResult := injectCredentials(proxyReq, creds, host, r.Method, rest)
	mergeExtraHeaders(proxyReq, host, p.getExtraHeadersForRequest(r, host))
	for _, headerName := range p.getRemoveHeadersForRequest(r, host) {
		if credResult.InjectedHeaders[strings.ToLower(headerName)] {
			continue
		}
		proxyReq.Header.Del(headerName)
	}

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
		logData := logBase
		logData.StatusCode = http.StatusBadGateway
		logData.Duration = time.Since(start)
		logData.Err = err
		logData.InjectedHeaders = credResult.InjectedHeaders
		logData.Grants = credResult.Grants
		p.logRequest(r, logData)
		http.Error(w, "MOAT: Relay '"+name+"' connection failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	invalidateCredentialsOnAuthFailure(credResult.Injected, resp.StatusCode)

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Copy status code and body with streaming support.
	// Use a flushing copy loop so SSE/chunked streaming responses
	// (e.g., Claude Code's /v1/messages with stream:true) are flushed
	// incrementally rather than buffered in io.Copy's 32KB buffer.
	w.WriteHeader(resp.StatusCode)
	flusher, canFlush := w.(http.Flusher)
	if canFlush {
		flusher.Flush()
	}
	// streamErr records an abnormal end of the stream: the upstream status
	// was already sent, so the client sees a truncated body rather than an
	// error status, and the canonical log line is the only place the
	// failure can surface. An upstream read error is the one that matters;
	// a client write error is recorded only when the upstream side was
	// still healthy.
	var streamErr error
	buf := make([]byte, 4096)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				streamErr = fmt.Errorf("writing response to client: %w", writeErr)
				break
			}
			if canFlush {
				flusher.Flush()
			}
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				streamErr = fmt.Errorf("reading upstream response body: %w", readErr)
			}
			break
		}
	}

	logData := logBase
	logData.StatusCode = resp.StatusCode
	logData.Duration = time.Since(start)
	logData.Err = streamErr
	logData.ResponseSize = resp.ContentLength
	logData.InjectedHeaders = credResult.InjectedHeaders
	logData.Grants = credResult.Grants
	p.logRequest(r, logData)
}
