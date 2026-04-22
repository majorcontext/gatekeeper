# WebSocket Support via ReverseProxy Refactor — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the manual HTTP request loop in `handleConnectWithInterception` with `httputil.ReverseProxy`, enabling WebSocket upgrade support while preserving all existing behaviors.

**Architecture:** After CONNECT hijack and TLS handshake (unchanged), create a single-connection `http.Server` with an `httputil.ReverseProxy` handler wrapped in a policy-checking middleware. The wrapping handler performs network policy, Keep policy, and credential resolution before delegating to `ReverseProxy`. Credential injection happens in `Rewrite`, response processing in `ModifyResponse`, transport errors in `ErrorHandler`. WebSocket upgrades work automatically via `ReverseProxy.handleUpgradeResponse`.

**Tech Stack:** Go stdlib `net/http/httputil.ReverseProxy`, `net/http.Server`, `crypto/tls`

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `proxy/proxy.go` | Modify | Replace `handleConnectWithInterception` loop (lines 1812-2177) with `http.Server` + `ReverseProxy` |
| `proxy/intercept_test.go` | Modify | Add WebSocket upgrade test |
| `proxy/proxy_test.go` | Verify | Existing tests must keep passing |

The refactor is contained to one function in one file. No new files needed — the handler, rewrite, and modify-response logic are methods on `*Proxy` defined inline or as closures within the existing file.

---

## Task 1: Add WebSocket upgrade test (will fail against current code)

This test establishes the target behavior. It will fail now and pass after the refactor.

**Files:**
- Modify: `proxy/intercept_test.go`

- [ ] **Step 1: Write the WebSocket upgrade test**

Add to `proxy/intercept_test.go`:

```go
func TestIntercept_WebSocketUpgrade(t *testing.T) {
	// Backend that accepts WebSocket upgrades and echoes messages.
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "expected websocket upgrade", 400)
			return
		}
		// Minimal WebSocket handshake.
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		w.WriteHeader(http.StatusSwitchingProtocols)

		// Hijack and echo bytes back.
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, brw, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		brw.Flush()

		// Simple echo: read up to 1024 bytes, write them back.
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		conn.Write(buf[:n])
	}))
	defer backend.Close()

	ca, err := generateCA()
	if err != nil {
		t.Fatal(err)
	}

	upstreamCAs := x509.NewCertPool()
	upstreamCAs.AddCert(backend.Certificate())

	p := NewProxy()
	p.SetCA(ca)
	p.SetUpstreamCAs(upstreamCAs)

	// Set credential to verify injection on the upgrade request.
	backendHost := mustParseURL(backend.URL).Hostname()
	p.SetCredential(backendHost, "Bearer ws-token")

	proxyServer := httptest.NewServer(p)
	defer proxyServer.Close()

	// Dial through the proxy using CONNECT.
	proxyURL := mustParseURL(proxyServer.URL)
	proxyConn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer proxyConn.Close()

	// Send CONNECT.
	backendAddr := mustParseURL(backend.URL).Host
	fmt.Fprintf(proxyConn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", backendAddr, backendAddr)
	br := bufio.NewReader(proxyConn)
	connectResp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if connectResp.StatusCode != 200 {
		t.Fatalf("CONNECT status = %d, want 200", connectResp.StatusCode)
	}

	// TLS handshake with the proxy's interception cert.
	clientCAs := x509.NewCertPool()
	clientCAs.AppendCertsFromPEM(ca.certPEM)
	tlsConn := tls.Client(proxyConn, &tls.Config{
		RootCAs:    clientCAs,
		ServerName: backendHost,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	defer tlsConn.Close()

	// Send WebSocket upgrade request.
	upgradeReq := "GET /ws HTTP/1.1\r\n" +
		"Host: " + backendAddr + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"
	if _, err := tlsConn.Write([]byte(upgradeReq)); err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}

	// Read the 101 response.
	tlsBr := bufio.NewReader(tlsConn)
	upgradeResp, err := http.ReadResponse(tlsBr, nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if upgradeResp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status = %d, want 101", upgradeResp.StatusCode)
	}

	// Send a raw message through the WebSocket tunnel.
	testMsg := []byte("hello websocket")
	if _, err := tlsConn.Write(testMsg); err != nil {
		t.Fatalf("write message: %v", err)
	}

	// Read echoed message back.
	echoBuf := make([]byte, len(testMsg))
	if _, err := io.ReadFull(tlsBr, echoBuf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(echoBuf) != string(testMsg) {
		t.Errorf("echo = %q, want %q", echoBuf, testMsg)
	}
}
```

- [ ] **Step 2: Run test to verify it fails against current code**

Run: `go test -run TestIntercept_WebSocketUpgrade -v -count=1 ./proxy/`
Expected: FAIL — the current code will either hang or error with "malformed HTTP request" after the 101.

- [ ] **Step 3: Commit the failing test**

```bash
git add proxy/intercept_test.go
git commit -m "test(proxy): add WebSocket upgrade test (expected to fail)"
```

---

## Task 2: Refactor handleConnectWithInterception to use ReverseProxy

This is the core change. Replace lines 1812-2177 (the manual `for` loop) with an `http.Server` + `httputil.ReverseProxy`.

**Files:**
- Modify: `proxy/proxy.go` (lines 1749-2178)

- [ ] **Step 1: Replace the request loop with http.Server + ReverseProxy**

Replace the code from line 1812 (`clientReader := bufio.NewReader(tlsClientConn)`) through line 2177 (closing `}` of the for loop) with:

```go
	// Create a reverse proxy that handles request forwarding, including
	// WebSocket upgrades via the stdlib's built-in protocol switch support.
	reverseProxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			// Preserve the original Proxy-Authorization from In before
			// ReverseProxy strips hop-by-hop headers.
			// token-exchange subject_from: proxy-auth needs this.
			proxyAuth := pr.In.Header.Get("Proxy-Authorization")

			pr.Out.URL.Scheme = "https"
			connectHost := r.Host
			if rc := getRunContext(r); rc != nil && rc.HostGatewayIP != "" && isHostGateway(rc, host) {
				connectHost = rewriteHostPort(r.Host, rc.HostGatewayIP)
			}
			pr.Out.URL.Host = connectHost
			pr.Out.Host = pr.In.Host

			// Restore Proxy-Authorization so credential resolver can read it.
			if proxyAuth != "" {
				pr.Out.Header.Set("Proxy-Authorization", proxyAuth)
			}

			// MCP credential injection.
			p.injectMCPCredentialsWithContext(r, pr.Out)

			// Credential injection.
			creds, credErr := p.getCredentialsForRequest(r, pr.Out, host)
			if credErr != nil {
				// Store error in context for ErrorHandler to pick up.
				*pr.Out = *pr.Out.WithContext(context.WithValue(pr.Out.Context(), interceptCredErrKey{}, credErr))
				return
			}
			credResult := injectCredentials(pr.Out, creds, host, pr.Out.Method, pr.Out.URL.Path)

			// Store credential result in context for ModifyResponse/logging.
			ctx := pr.Out.Context()
			ctx = context.WithValue(ctx, interceptCredResultKey{}, credResult)
			*pr.Out = *pr.Out.WithContext(ctx)

			// Extra headers.
			mergeExtraHeaders(pr.Out, r.Host, p.getExtraHeadersForRequest(r, r.Host))

			// Strip proxy headers.
			pr.Out.Header.Del("Proxy-Connection")
			pr.Out.Header.Del("Proxy-Authorization")

			// Remove configured headers (but not injected credential headers).
			for _, headerName := range p.getRemoveHeadersForRequest(r, host) {
				if credResult.InjectedHeaders[strings.ToLower(headerName)] {
					continue
				}
				pr.Out.Header.Del(headerName)
			}

			// Token substitution.
			if sub := p.getTokenSubstitutionForRequest(r, host); sub != nil {
				p.applyTokenSubstitution(pr.Out, sub)
			}

			// Request ID.
			if pr.Out.Header.Get("X-Request-Id") == "" {
				pr.Out.Header.Set("X-Request-Id", newRequestID())
			}
		},
		Transport: transport,
		ModifyResponse: func(resp *http.Response) error {
			req := resp.Request

			// LLM gateway policy evaluation (Anthropic API only).
			if resp.StatusCode == http.StatusOK && host == "api.anthropic.com" {
				if rc := getRunContext(r); rc != nil && rc.KeepEngines != nil {
					if eng, ok := rc.KeepEngines["llm-gateway"]; ok {
						p.evaluateAndReplaceLLMResponse(r, req, resp, eng)
					}
				}
			}

			// Response transformers.
			if transformers := p.getResponseTransformersForRequest(r, host); len(transformers) > 0 {
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
			var respBody []byte
			respBody, resp.Body = captureBody(resp.Body, resp.Header.Get("Content-Type"))
			var reqBody []byte
			// Request body was already consumed by the transport; capture from context if available.
			_ = reqBody
			_ = respBody

			p.logRequest(r, RequestLogData{
				RequestID:       req.Header.Get("X-Request-Id"),
				Method:          req.Method,
				URL:             req.URL.String(),
				Host:            host,
				Path:            req.URL.Path,
				RequestType:     "connect",
				StatusCode:      resp.StatusCode,
				Duration:        time.Since(reqStartFromContext(req.Context())),
				RequestHeaders:  req.Header.Clone(),
				ResponseHeaders: resp.Header.Clone(),
				ResponseBody:    respBody,
				RequestSize:     req.ContentLength,
				ResponseSize:    resp.ContentLength,
				AuthInjected:    len(credResult.InjectedHeaders) > 0,
				InjectedHeaders: credResult.InjectedHeaders,
				Grants:          credResult.Grants,
			})

			return nil
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			// Check for credential resolution error from Rewrite.
			if credErr, ok := req.Context().Value(interceptCredErrKey{}).(error); ok {
				http.Error(rw, "credential resolution failed\n", http.StatusBadGateway)
				p.logRequest(r, RequestLogData{
					RequestID:   req.Header.Get("X-Request-Id"),
					Method:      req.Method,
					URL:         req.URL.String(),
					Host:        host,
					Path:        req.URL.Path,
					RequestType: "connect",
					StatusCode:  http.StatusBadGateway,
					Err:         credErr,
				})
				return
			}

			rw.WriteHeader(http.StatusBadGateway)
			credResult, _ := req.Context().Value(interceptCredResultKey{}).(credentialInjectionResult)
			p.logRequest(r, RequestLogData{
				RequestID:       req.Header.Get("X-Request-Id"),
				Method:          req.Method,
				URL:             req.URL.String(),
				Host:            host,
				Path:            req.URL.Path,
				RequestType:     "connect",
				StatusCode:      http.StatusBadGateway,
				Err:             err,
				AuthInjected:    len(credResult.InjectedHeaders) > 0,
				InjectedHeaders: credResult.InjectedHeaders,
				Grants:          credResult.Grants,
			})
		},
	}

	// Wrapping handler: policy checks before ReverseProxy.
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Network policy check.
		if !p.checkNetworkPolicyForRequest(r, host, connectPort, req.Method, req.URL.Path) {
			innerReqID := req.Header.Get("X-Request-Id")
			if innerReqID == "" {
				innerReqID = newRequestID()
			}
			p.logRequest(r, RequestLogData{
				RequestID:    innerReqID,
				Method:       req.Method,
				URL:          "https://" + r.Host + req.URL.Path,
				Host:         host,
				Path:         req.URL.Path,
				RequestType:  "connect",
				StatusCode:   http.StatusProxyAuthRequired,
				RequestSize:  req.ContentLength,
				ResponseSize: -1,
				Denied:       true,
				DenyReason:   "Request blocked by network policy: " + req.Method + " " + host + req.URL.Path,
			})
			p.logPolicy(r, "network", "http.request", "", req.Method+" "+host+req.URL.Path)
			w.Header().Set("X-Moat-Blocked", "request-rule")
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusProxyAuthRequired)
			fmt.Fprintf(w, "Moat: request blocked by network policy.\nHost: %s\nTo allow this request, update network.rules in moat.yaml.\n", host)
			return
		}

		// Keep HTTP policy check.
		if rc := getRunContext(r); rc != nil && rc.KeepEngines != nil {
			if eng, ok := rc.KeepEngines["http"]; ok {
				call := keeplib.NewHTTPCall(req.Method, host, req.URL.Path)
				call.Context.Scope = "http-" + host
				result, evalErr := keeplib.SafeEvaluate(eng, call, "http")
				if evalErr != nil {
					innerReqID := req.Header.Get("X-Request-Id")
					if innerReqID == "" {
						innerReqID = newRequestID()
					}
					p.logRequest(r, RequestLogData{
						RequestID:    innerReqID,
						Method:       req.Method,
						URL:          "https://" + r.Host + req.URL.Path,
						Host:         host,
						Path:         req.URL.Path,
						RequestType:  "connect",
						StatusCode:   http.StatusForbidden,
						RequestSize:  req.ContentLength,
						ResponseSize: -1,
						Denied:       true,
						DenyReason:   "Keep policy evaluation error",
						Err:          evalErr,
					})
					p.logPolicy(r, "http", "http.request", "evaluation-error", "Policy evaluation failed")
					w.Header().Set("X-Moat-Blocked", "keep-policy")
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusForbidden)
					fmt.Fprintf(w, "Moat: request blocked — policy evaluation error.\nHost: %s\n", host)
					return
				}
				if result.Decision == keeplib.Deny {
					innerReqID := req.Header.Get("X-Request-Id")
					if innerReqID == "" {
						innerReqID = newRequestID()
					}
					p.logRequest(r, RequestLogData{
						RequestID:    innerReqID,
						Method:       req.Method,
						URL:          "https://" + r.Host + req.URL.Path,
						Host:         host,
						Path:         req.URL.Path,
						RequestType:  "connect",
						StatusCode:   http.StatusForbidden,
						RequestSize:  req.ContentLength,
						ResponseSize: -1,
						Denied:       true,
						DenyReason:   "Keep policy denied: " + result.Rule + " " + result.Message,
					})
					p.logPolicy(r, "http", "http.request", result.Rule, result.Message)
					w.Header().Set("X-Moat-Blocked", "keep-policy")
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusForbidden)
					msg := fmt.Sprintf("Moat: request blocked by Keep policy.\nHost: %s\n", host)
					if result.Message != "" {
						msg += result.Message + "\n"
					}
					fmt.Fprint(w, msg)
					return
				}
			}
		}

		// Store request start time in context for duration calculation.
		ctx := context.WithValue(req.Context(), interceptReqStartKey{}, time.Now())
		reverseProxy.ServeHTTP(w, req.WithContext(ctx))
	})

	// Serve on a single-connection listener wrapping the TLS connection.
	srv := &http.Server{
		Handler:     handler,
		IdleTimeout: 120 * time.Second,
		ErrorLog:    log.New(io.Discard, "", 0), // Suppress server-level errors (we handle them in ErrorHandler).
	}
	srv.Serve(newSingleConnListener(tlsClientConn))
```

This requires several supporting types. Add before the function:

```go
// Context keys for passing data between ReverseProxy hooks.
type interceptCredResultKey struct{}
type interceptCredErrKey struct{}
type interceptReqStartKey struct{}

func reqStartFromContext(ctx context.Context) time.Time {
	if t, ok := ctx.Value(interceptReqStartKey{}).(time.Time); ok {
		return t
	}
	return time.Now()
}

// singleConnListener wraps a single net.Conn as a net.Listener.
// Accept returns the connection once, then blocks until Close is called.
type singleConnListener struct {
	conn net.Conn
	once sync.Once
	ch   chan net.Conn
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	ch := make(chan net.Conn, 1)
	ch <- conn
	return &singleConnListener{conn: conn, ch: ch}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	conn, ok := <-l.ch
	if !ok {
		return nil, io.EOF
	}
	return conn, nil
}

func (l *singleConnListener) Close() error {
	l.once.Do(func() { close(l.ch) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}
```

Also add `evaluateAndReplaceLLMResponse` as a method that encapsulates the LLM policy logic currently inline in the loop (lines 2024-2106). This keeps ModifyResponse readable:

```go
// evaluateAndReplaceLLMResponse evaluates LLM gateway policy and replaces
// the response in-place if denied. Called from ModifyResponse.
func (p *Proxy) evaluateAndReplaceLLMResponse(ctxReq *http.Request, req *http.Request, resp *http.Response, eng *keeplib.Engine) {
	respBodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, maxLLMResponseSize+1))
	resp.Body.Close()
	if readErr != nil {
		p.logPolicy(ctxReq, "llm-gateway", "llm.read_error", "read-error", "Failed to read response body for policy evaluation")
		errorBody := buildPolicyDeniedResponse("read-error", "Failed to read response body for policy evaluation.")
		resp.StatusCode = http.StatusBadRequest
		resp.Header = make(http.Header)
		resp.Header.Set("Content-Type", "application/json")
		resp.Header.Set("X-Moat-Blocked", "llm-policy")
		resp.ContentLength = int64(len(errorBody))
		resp.Body = io.NopCloser(bytes.NewReader(errorBody))
		return
	}
	if int64(len(respBodyBytes)) > maxLLMResponseSize {
		p.logPolicy(ctxReq, "llm-gateway", "llm.response_too_large", "size-limit", "Response too large for policy evaluation")
		errorBody := buildPolicyDeniedResponse("size-limit", "Response too large for policy evaluation.")
		resp.StatusCode = http.StatusBadRequest
		resp.Header = make(http.Header)
		resp.Header.Set("Content-Type", "application/json")
		resp.Header.Set("X-Moat-Blocked", "llm-policy")
		resp.ContentLength = int64(len(errorBody))
		resp.Body = io.NopCloser(bytes.NewReader(errorBody))
		return
	}
	result := evaluateLLMResponse(eng, respBodyBytes, resp)
	if result.Denied {
		p.logPolicy(ctxReq, "llm-gateway", "llm.tool_use", result.Rule, result.Message)
		errorBody := buildPolicyDeniedResponse(result.Rule, result.Message)
		resp.StatusCode = http.StatusBadRequest
		resp.Header = make(http.Header)
		resp.Header.Set("Content-Type", "application/json")
		resp.Header.Set("X-Moat-Blocked", "llm-policy")
		resp.ContentLength = int64(len(errorBody))
		resp.Body = io.NopCloser(bytes.NewReader(errorBody))
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
}
```

- [ ] **Step 2: Add required imports**

Add to the import block in `proxy/proxy.go`:
- `"log"` (for `log.New` in http.Server ErrorLog)
- `"net/http/httputil"` (for ReverseProxy)

- [ ] **Step 3: Verify compilation**

Run: `go build ./proxy/`
Expected: compiles cleanly

- [ ] **Step 4: Run the full test suite**

Run: `go test -count=1 ./proxy/`
Expected: All existing `TestIntercept_*` and `TestProxy_*` tests pass

- [ ] **Step 5: Run the WebSocket test**

Run: `go test -run TestIntercept_WebSocketUpgrade -v -count=1 ./proxy/`
Expected: PASS

- [ ] **Step 6: Run go vet**

Run: `go vet ./...`
Expected: clean

- [ ] **Step 7: Commit**

```bash
git add proxy/proxy.go
git commit -m "feat(proxy): replace interception loop with ReverseProxy for WebSocket support

Replace the manual for { http.ReadRequest → transport.RoundTrip → resp.Write }
loop in handleConnectWithInterception with http.Server + httputil.ReverseProxy.

ReverseProxy natively handles WebSocket upgrades (101 Switching Protocols)
by hijacking both sides and doing bidirectional io.Copy.

All existing behaviors preserved: credential injection, network policy,
Keep policy, LLM gateway policy, response transformers, canonical log
lines, X-Request-Id, extra/remove headers, token substitution, host
gateway rewrite."
```

---

## Task 3: Full verification

- [ ] **Step 1: Run the complete test suite with race detector**

Run: `go test -race -count=1 ./...`
Expected: All tests pass, no data races

- [ ] **Step 2: Run go vet**

Run: `go vet ./...`
Expected: clean

- [ ] **Step 3: Clean up any dead code**

Remove the `bufio` import from proxy.go if no longer used (the manual `bufio.NewReader` loop is gone). Check for any other dead code.

- [ ] **Step 4: Final commit if cleanup needed**

```bash
git add -A
git commit -m "refactor(proxy): remove dead code from interception loop replacement"
```
