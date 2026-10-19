package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync/atomic"
	"time"

	keeplib "github.com/majorcontext/keep"
	"golang.org/x/net/http2"
)

// singleConnListener wraps a single net.Conn as a net.Listener.
// Accept returns the connection once, then blocks until Close is called.
// This keeps http.Server.Serve alive for the lifetime of the connection.
type singleConnListener struct {
	conn    net.Conn
	connCh  chan net.Conn
	closeCh chan struct{}
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	ch := make(chan net.Conn, 1)
	ch <- conn
	return &singleConnListener{conn: conn, connCh: ch, closeCh: make(chan struct{})}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connCh:
		return conn, nil
	case <-l.closeCh:
		return nil, net.ErrClosed
	}
}

func (l *singleConnListener) Close() error {
	select {
	case <-l.closeCh:
	default:
		close(l.closeCh)
	}
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

// evaluateAndReplaceLLMResponse evaluates LLM gateway policy and replaces
// the response in-place if denied. Returns whether a denial occurred and the reason.
func (p *Proxy) evaluateAndReplaceLLMResponse(ctxReq *http.Request, req *http.Request, resp *http.Response, eng *keeplib.Engine) (denied bool, reason string) {
	respBodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, maxLLMResponseSize+1))
	resp.Body.Close()
	if readErr != nil {
		p.logPolicy(ctxReq, "llm-gateway", "llm.read_error", "read-error", "Failed to read response body for policy evaluation")
		errorBody := buildPolicyDeniedResponse("read-error", "Failed to read response body for policy evaluation.")
		resp.StatusCode = http.StatusBadRequest
		resp.Header = make(http.Header)
		resp.Header.Set("Content-Type", "application/json")
		setBlocked(resp.Header, "llm-policy")
		resp.ContentLength = int64(len(errorBody))
		resp.Body = io.NopCloser(bytes.NewReader(errorBody))
		return true, "LLM policy read error"
	}
	if int64(len(respBodyBytes)) > maxLLMResponseSize {
		p.logPolicy(ctxReq, "llm-gateway", "llm.response_too_large", "size-limit", "Response too large for policy evaluation")
		errorBody := buildPolicyDeniedResponse("size-limit", "Response too large for policy evaluation.")
		resp.StatusCode = http.StatusBadRequest
		resp.Header = make(http.Header)
		resp.Header.Set("Content-Type", "application/json")
		setBlocked(resp.Header, "llm-policy")
		resp.ContentLength = int64(len(errorBody))
		resp.Body = io.NopCloser(bytes.NewReader(errorBody))
		return true, "LLM policy response too large"
	}
	result := evaluateLLMResponse(req.Context(), eng, respBodyBytes, resp)
	if result.Denied {
		p.logPolicy(ctxReq, "llm-gateway", "llm.tool_use", result.Rule, result.Message)
		errorBody := buildPolicyDeniedResponse(result.Rule, result.Message)
		resp.StatusCode = http.StatusBadRequest
		resp.Header = make(http.Header)
		resp.Header.Set("Content-Type", "application/json")
		setBlocked(resp.Header, "llm-policy")
		resp.ContentLength = int64(len(errorBody))
		resp.Body = io.NopCloser(bytes.NewReader(errorBody))
		return true, "LLM policy denied: " + result.Rule + " " + result.Message
	} else if result.Events != nil {
		var buf bytes.Buffer
		for _, ev := range result.Events {
			if ev.ID != "" {
				fmt.Fprintf(&buf, "id: %s\n", ev.ID)
			}
			if ev.Type != "" {
				fmt.Fprintf(&buf, "event: %s\n", ev.Type)
			}
			lines := strings.Split(ev.Data, "\n")
			for _, line := range lines {
				fmt.Fprintf(&buf, "data: %s\n", line)
			}
			buf.WriteByte('\n')
		}
		resp.Header.Del("Content-Encoding")
		resp.Body = io.NopCloser(&buf)
		resp.ContentLength = int64(buf.Len())
	} else {
		resp.Body = io.NopCloser(bytes.NewReader(respBodyBytes))
		resp.ContentLength = int64(len(respBodyBytes))
	}
	return false, ""
}

func (p *Proxy) handleConnectWithInterception(w http.ResponseWriter, r *http.Request, host string) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	done, ok := p.conns.add(clientConn)
	if !ok {
		clientConn.Close()
		return
	}
	clientConn = &trackedConn{Conn: clientConn, done: done}

	// Track whether the inner http.Server's connection was hijacked
	// (e.g., for WebSocket upgrade). If hijacked, ReverseProxy owns the
	// TLS conn and will close it; we must not close clientConn ourselves.
	var hijacked atomic.Bool
	defer func() {
		if !hijacked.Load() {
			clientConn.Close()
		}
	}()

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	cert, err := p.ca.GenerateCert(host)
	if err != nil {
		slog.Debug("failed to generate cert for CONNECT interception",
			"subsystem", "proxy", "host", host, "error", err)
		return
	}

	// Advertise h2 first so it is preferred during ALPN negotiation;
	// http/1.1 is kept as fallback for non-h2 clients.
	// Ordering matters: ConfigureServer only appends missing protos, it
	// does not reorder, so h2-preference must be established here.
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{http2.NextProtoTLS, "http/1.1"},
	}
	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		slog.Debug("TLS handshake failed during CONNECT interception",
			"subsystem", "proxy", "host", host, "error", err)
		return
	}
	defer func() {
		if !hijacked.Load() {
			tlsClientConn.Close()
		}
	}()

	var transport http.RoundTripper
	if tlsClientConn.ConnectionState().NegotiatedProtocol == http2.NextProtoTLS {
		transport, err = p.getH2UpstreamTransportFor(getRunContext(r))
		if err != nil {
			slog.Debug("failed to configure upstream transport",
				"subsystem", "proxy", "host", host, "error", err)
			return
		}
	} else {
		transport = newUpstreamTransport(p.getUpstreamCAs())
	}

	// Extract port from the CONNECT request for rule checking.
	// Defaults to 443 since this is a TLS-intercepted connection.
	connectPort := 443
	if _, pStr, err := net.SplitHostPort(r.Host); err == nil {
		if p, err := net.LookupPort("tcp", pStr); err == nil {
			connectPort = p
		}
	}

	// Create a reverse proxy that handles request forwarding, including
	// WebSocket upgrades via the stdlib's built-in protocol switch support.
	reverseProxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "https"
			connectHost := r.Host
			if rc := getRunContext(r); rc != nil && rc.HostGatewayIP != "" && isHostGateway(rc, host) {
				connectHost = rewriteHostPort(r.Host, rc.HostGatewayIP)
			}
			pr.Out.URL.Host = connectHost
			pr.Out.Host = pr.In.Host
			pr.Out.RequestURI = ""

			// Credentials were resolved in the wrapping handler and passed via context.
			resolved, _ := pr.Out.Context().Value(interceptCredsKey{}).(resolvedCredentials)

			// Snapshot headers before injection so logs never hold credential values.
			preInjectionHeaders, _ := pr.Out.Context().Value(interceptPreInjHeadersKey{}).(http.Header)
			if preInjectionHeaders == nil {
				preInjectionHeaders = pr.Out.Header.Clone()
			}

			bundleResult, _ := pr.Out.Context().Value(interceptBundleResultKey{}).(credentialInjectionResult)
			// Capture URL before token substitution so logs don't contain real tokens.
			logURL := pr.Out.URL.String()

			credResult := p.prepareOutbound(r, pr.Out, outboundPrep{
				creds:      resolved.creds,
				bundle:     bundleResult,
				host:       host,
				lookupHost: r.Host,
				path:       pr.Out.URL.Path,
			})

			// Store credential result and pre-injection headers in context.
			ctx := pr.Out.Context()
			if rc := getRunContext(r); rc != nil {
				ctx = context.WithValue(ctx, runContextKey, rc)
			}
			ctx = context.WithValue(ctx, interceptCredResultKey{}, credResult)
			ctx = context.WithValue(ctx, interceptPreInjHeadersKey{}, preInjectionHeaders)
			ctx = context.WithValue(ctx, interceptLogURLKey{}, logURL)
			*pr.Out = *pr.Out.WithContext(ctx)

			if pr.Out.Header.Get("X-Request-Id") == "" {
				pr.Out.Header.Set("X-Request-Id", newRequestID())
			}
		},
		Transport: transport,
		ModifyResponse: func(resp *http.Response) error {
			req := resp.Request

			// The destination rejected us: if the credential came from a cache,
			// drop it so the next request re-resolves rather than replaying a
			// credential the destination has already refused. Rewrite stored the
			// injection result, so this evicts only what was actually sent.
			cr, _ := req.Context().Value(interceptCredResultKey{}).(credentialInjectionResult)
			resolved, _ := req.Context().Value(interceptCredsKey{}).(resolvedCredentials)
			settleUpstreamResponse(resp, cr.Injected, resolved.declined)

			// Track LLM policy denials for the canonical log line.
			var llmDenied bool
			var llmDenyReason string

			// LLM gateway policy evaluation (Anthropic API only).
			if resp.StatusCode == http.StatusOK && host == "api.anthropic.com" {
				if rc := getRunContext(r); rc != nil && rc.KeepEngines != nil {
					if eng, ok := rc.KeepEngines["llm-gateway"]; ok {
						llmDenied, llmDenyReason = p.evaluateAndReplaceLLMResponse(r, req, resp, eng)
					}
				}
			}

			// Response transformers.
			if transformers := p.getResponseTransformersForRequest(r, r.Host); len(transformers) > 0 {
				for _, transformer := range transformers {
					if newRespInterface, transformed := transformer(req, resp); transformed {
						if newResp, ok := newRespInterface.(*http.Response); ok {
							*resp = *newResp
						}
						break
					}
				}
			}

			// Canonical log line.
			credResult, _ := req.Context().Value(interceptCredResultKey{}).(credentialInjectionResult)
			// Use pre-substitution URL so logs don't contain real tokens.
			logURL, _ := req.Context().Value(interceptLogURLKey{}).(string)
			if logURL == "" {
				logURL = req.URL.String()
			}
			// Use pre-injection headers so credential values don't appear in logs.
			preHeaders, _ := req.Context().Value(interceptPreInjHeadersKey{}).(http.Header)
			if preHeaders == nil {
				preHeaders = req.Header.Clone()
			}
			reqBody, _ := req.Context().Value(interceptReqBodyKey{}).([]byte)

			logData := RequestLogData{
				RequestID:       req.Header.Get("X-Request-Id"),
				Method:          req.Method,
				URL:             logURL,
				Host:            host,
				Path:            req.URL.Path,
				RequestType:     "connect",
				StatusCode:      resp.StatusCode,
				RequestHeaders:  preHeaders,
				ResponseHeaders: resp.Header.Clone(),
				RequestBody:     reqBody,
				RequestSize:     req.ContentLength,
				ResponseSize:    resp.ContentLength,
				AuthInjected:    len(credResult.InjectedHeaders) > 0,
				InjectedHeaders: credResult.InjectedHeaders,
				Grants:          credResult.Grants,
				Denied:          llmDenied,
				DenyReason:      llmDenyReason,
				ClientAddr:      r.RemoteAddr,
			}
			reqStart := reqStartFromContext(req.Context())

			// For text responses (SSE, ndjson, chunked JSON, …) defer the canonical
			// log line until the body is read and closed, capturing a bounded sample
			// as it streams. A blocking read-ahead here would withhold the status
			// line and every chunk from the client until the sample filled, starving
			// streamed responses and tripping the client's first-byte timeout.
			//
			// The deferred line is emitted exactly once: httputil.ReverseProxy
			// closes the response body unconditionally (success and copy-error
			// paths), so onClose always runs. Responses with no useful streamed
			// sample are logged synchronously instead: non-text bodies, and protocol
			// upgrades (101), whose body is the hijacked connection rather than a
			// readable stream.
			if isTextContentType(resp.Header.Get("Content-Type")) && resp.StatusCode != http.StatusSwitchingProtocols {
				resp.Body = newCapturingBody(resp.Body, MaxBodySize, func(captured []byte) {
					logData.ResponseBody = captured
					logData.Duration = time.Since(reqStart)
					p.logRequest(r, logData)
				})
			} else {
				logData.Duration = time.Since(reqStart)
				p.logRequest(r, logData)
			}

			return nil
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			rw.WriteHeader(http.StatusBadGateway)
			credResult, _ := req.Context().Value(interceptCredResultKey{}).(credentialInjectionResult)
			logURL, _ := req.Context().Value(interceptLogURLKey{}).(string)
			if logURL == "" {
				logURL = req.URL.String()
			}
			preHeaders, _ := req.Context().Value(interceptPreInjHeadersKey{}).(http.Header)
			if preHeaders == nil {
				preHeaders = req.Header.Clone()
			}
			p.logRequest(r, RequestLogData{
				RequestID:       req.Header.Get("X-Request-Id"),
				Method:          req.Method,
				URL:             logURL,
				Host:            host,
				Path:            req.URL.Path,
				RequestType:     "connect",
				StatusCode:      http.StatusBadGateway,
				Duration:        time.Since(reqStartFromContext(req.Context())),
				RequestHeaders:  preHeaders,
				RequestSize:     req.ContentLength,
				ResponseSize:    -1,
				Err:             err,
				ClientAddr:      r.RemoteAddr,
				AuthInjected:    len(credResult.InjectedHeaders) > 0,
				InjectedHeaders: credResult.InjectedHeaders,
				Grants:          credResult.Grants,
			})
		},
	}

	// Wrapping handler: policy checks and credential resolution before ReverseProxy.
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		reqStart := time.Now()

		innerReqID := req.Header.Get("X-Request-Id")
		if innerReqID == "" {
			innerReqID = newRequestID()
		}

		// Network policy check.
		if !p.checkNetworkPolicyForRequest(r, host, connectPort, req.Method, req.URL.Path) {
			p.logRequest(r, RequestLogData{
				RequestID:      innerReqID,
				Method:         req.Method,
				URL:            "https://" + r.Host + req.URL.RequestURI(),
				Host:           host,
				Path:           req.URL.Path,
				RequestType:    "connect",
				StatusCode:     http.StatusProxyAuthRequired,
				Duration:       time.Since(reqStart),
				RequestHeaders: p.logHeadersRedacted(req.Header, r.Host),
				RequestSize:    req.ContentLength,
				ResponseSize:   -1,
				ClientAddr:     r.RemoteAddr,
				Denied:         true,
				DenyReason:     "Request blocked by network policy: " + req.Method + " " + host + req.URL.Path,
			})
			p.logPolicy(r, "network", "http.request", "", req.Method+" "+host+req.URL.Path)
			setBlocked(w.Header(), "request-rule")
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusProxyAuthRequired)
			fmt.Fprintf(w, "%s: request blocked by network policy.\nHost: %s\n%s", p.brandName(), host, p.networkHint())
			return
		}

		// Keep HTTP policy check.
		if rc := getRunContext(r); rc != nil && rc.KeepEngines != nil {
			if eng, ok := rc.KeepEngines["http"]; ok {
				// httpDenial describes a fail-closed http-scope policy denial.
				// logMsg feeds the internal policy log only; clientHint is an
				// optional detail line shown to the client (left empty for
				// internal-only reasons). clientMsg fills the blank in
				// "<name>: request blocked <clientMsg>".
				type httpDenial struct {
					rule       string
					logMsg     string
					denyReason string
					clientMsg  string
					clientHint string
					err        error
				}
				denyHTTP := func(d httpDenial) {
					p.logRequest(r, RequestLogData{
						RequestID:      innerReqID,
						Method:         req.Method,
						URL:            "https://" + r.Host + req.URL.RequestURI(),
						Host:           host,
						Path:           req.URL.Path,
						RequestType:    "connect",
						StatusCode:     http.StatusForbidden,
						Duration:       time.Since(reqStart),
						RequestHeaders: p.logHeadersRedacted(req.Header, r.Host),
						RequestSize:    req.ContentLength,
						ResponseSize:   -1,
						ClientAddr:     r.RemoteAddr,
						Denied:         true,
						DenyReason:     d.denyReason,
						Err:            d.err,
					})
					p.logPolicy(r, "http", "http.request", d.rule, d.logMsg)
					setBlocked(w.Header(), "keep-policy")
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusForbidden)
					msg := fmt.Sprintf("%s: request blocked %s.\nHost: %s\n", p.brandName(), d.clientMsg, host)
					if d.clientHint != "" {
						msg += d.clientHint + "\n"
					}
					fmt.Fprint(w, msg)
				}

				// Build the call, buffering and parsing the body when a body rule
				// is in effect. Fail closed if the body can't be inspected.
				call, callOK, bodyDenyReason := buildHTTPCall(eng, req, host)
				if !callOK {
					// clientHint is intentionally omitted: the specific reason
					// (size limit, duplicate keys, content-type) is enforcement
					// detail kept in the policy log, not revealed to the client.
					denyHTTP(httpDenial{
						rule:       "body-inspection-error",
						logMsg:     bodyDenyReason,
						denyReason: "Keep policy body inspection failed: " + bodyDenyReason,
						clientMsg:  "— request body could not be inspected",
					})
					return
				}
				call.Context.Scope = "http-" + host

				result, evalErr := keeplib.SafeEvaluate(req.Context(), eng, call, "http")
				if evalErr != nil {
					denyHTTP(httpDenial{
						rule:       "evaluation-error",
						logMsg:     "Policy evaluation failed",
						denyReason: "Keep policy evaluation error",
						clientMsg:  "— policy evaluation error",
						err:        evalErr,
					})
					return
				}
				if result.Decision == keeplib.Deny {
					denyHTTP(httpDenial{
						rule:       result.Rule,
						logMsg:     result.Message,
						denyReason: "Keep policy denied: " + result.Rule + " " + result.Message,
						clientMsg:  "by Keep policy",
						clientHint: result.Message,
					})
					return
				}
			}
		}

		// MCP credential injection.
		p.injectMCPCredentialsWithContext(r, req)

		// Resolve credentials before forwarding so errors are caught early.
		// r.Host is the CONNECT target with its port, so port-pinned host
		// keys can match; the lookup falls back to the bare host.
		resolved, credErr := p.getCredentialsForRequest(r, req, r.Host)
		if credErr != nil {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprint(w, "credential resolution failed\n")
			p.logRequest(r, RequestLogData{
				RequestID:      innerReqID,
				Method:         req.Method,
				URL:            "https://" + r.Host + req.URL.RequestURI(),
				Host:           host,
				Path:           req.URL.Path,
				RequestType:    "connect",
				StatusCode:     http.StatusBadGateway,
				Duration:       time.Since(reqStart),
				RequestHeaders: p.logHeadersRedacted(req.Header, r.Host),
				RequestSize:    req.ContentLength,
				ResponseSize:   -1,
				ClientAddr:     r.RemoteAddr,
				Err:            credErr,
			})
			return
		}

		// Credential bundles are evaluated and applied before ReverseProxy so a
		// match is in place on the request it forwards. A mismatch injects
		// nothing and the request goes on unchanged.
		// Snapshot first: logs must retain only the client-sent placeholders.
		preBundleHeaders := req.Header.Clone()
		bundleResult := injectCredentialBundles(req, p.getCredentialBundlesForRequest(r), "https", r.Host)
		if bundleResult.Skipped {
			p.logPolicyObservation(r, "credential-bundle", "http.request", "", bundleResult.Reason)
		}

		// Capture request body for logging before ReverseProxy consumes it.
		var reqBody []byte
		reqBody, req.Body = captureBody(req.Body, req.Header.Get("Content-Type"))

		// Propagate request ID so Rewrite preserves it (instead of generating a new one).
		req.Header.Set("X-Request-Id", innerReqID)

		// Pass resolved credentials, start time, and captured body to Rewrite via context.
		ctx := req.Context()
		ctx = context.WithValue(ctx, interceptReqStartKey{}, reqStart)
		ctx = context.WithValue(ctx, interceptCredsKey{}, resolved)
		ctx = context.WithValue(ctx, interceptBundleResultKey{}, bundleResult.credentialInjectionResult)
		ctx = context.WithValue(ctx, interceptPreInjHeadersKey{}, preBundleHeaders)
		ctx = context.WithValue(ctx, interceptReqBodyKey{}, reqBody)
		reverseProxy.ServeHTTP(w, req.WithContext(ctx))
	})

	// Serve on a single-connection listener wrapping the TLS connection.
	ln := newSingleConnListener(tlsClientConn)
	srv := &http.Server{
		Handler:     handler,
		IdleTimeout: 120 * time.Second,
		ErrorLog:    log.New(io.Discard, "", 0), // Suppress server-level errors; handled in ErrorHandler.
		ConnState: func(conn net.Conn, state http.ConnState) {
			if state == http.StateHijacked {
				hijacked.Store(true)
			}
			if state == http.StateClosed || state == http.StateHijacked {
				ln.Close()
			}
		},
	}
	// Enable HTTP/2 on the inner server so h2 clients (e.g., gRPC) get
	// proper framing.  h1 clients are unaffected — ConfigureServer
	// falls back to the normal http.Handler when h2 is not negotiated.
	if err := http2.ConfigureServer(srv, nil); err != nil {
		slog.Warn("http2.ConfigureServer failed, falling back to HTTP/1.1",
			"subsystem", "proxy", "host", host, "error", err)
		// If the client already negotiated h2 we cannot serve it correctly
		// over h1 — close rather than produce a framing error.
		if tlsClientConn.ConnectionState().NegotiatedProtocol == http2.NextProtoTLS {
			return
		}
	}
	_ = srv.Serve(ln)
}
