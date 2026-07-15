// Package proxy provides a TLS-intercepting HTTP proxy for credential injection.
//
// # Security Model
//
// The proxy intercepts HTTPS traffic via CONNECT tunneling with dynamic certificate
// generation. It injects credentials (Authorization headers, etc.) for configured
// hosts without exposing raw tokens to the container.
//
// # Firewall Integration
//
// Container firewall rules (iptables) work in conjunction with the proxy:
//
//   - Docker: Proxy binds to 127.0.0.1 (localhost only). Containers reach it via
//     host.docker.internal or host network mode. Firewall allows proxy port only.
//
//   - Apple containers: Proxy binds to 0.0.0.0 with per-run token authentication.
//     Security is maintained via cryptographic tokens in HTTP_PROXY URL, not IP filtering.
//
// The firewall rules intentionally do NOT filter by destination IP for the proxy port.
// This is because host.docker.internal resolves to different IPs across environments.
// The security boundaries are:
//
//  1. Random high port assignment (reduces collision with other services)
//  2. Token authentication for Apple containers
//  3. Container isolation (other containers can't reach host ports by default)
//
// This trade-off prioritizes reliability over defense-in-depth. The proxy validates
// credentials are only injected for explicitly configured hosts.
package proxy

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	keeplib "github.com/majorcontext/keep"
	"go.jetify.com/typeid"
	"golang.org/x/net/http2"
)

// contextKey is the type for request-scoped context values.
type contextKey int

const (
	runContextKey contextKey = iota
	requestIDKey
	userIDKey
)

// newRequestID generates a TypeID with prefix "req" (e.g., "req_01h455vb4pex5vsknk084sn02q").
func newRequestID() string {
	tid, err := typeid.WithPrefix("req")
	if err != nil {
		return "req_unknown"
	}
	return tid.String()
}

// withRequestID returns a new context with the given request ID.
func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestIDFromContext extracts the request ID from a context, or empty string.
func RequestIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

// withUserID returns a new context with the given user ID.
func withUserID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, userIDKey, id)
}

// UserIDFromContext extracts the user ID from a context, or empty string.
func UserIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(userIDKey).(string); ok {
		return id
	}
	return ""
}

// ResponseTransformer transforms HTTP responses before body capture.
// Cast to *http.Request and *http.Response in the transformer implementation.
// Returns the modified response and true if transformed, or original and false.
type ResponseTransformer func(req, resp any) (any, bool)

// CredentialStore retrieves tokens by provider name (grant).
// The proxy uses this for MCP credential injection when credentials are
// not pre-resolved in RunContextData.
type CredentialStore interface {
	GetToken(provider string) (string, error)
}

// MCPServerConfig holds the MCP server configuration needed by the proxy.
type MCPServerConfig struct {
	Name string
	URL  string
	Auth *MCPAuthConfig
}

// MCPAuthConfig defines authentication for an MCP server.
type MCPAuthConfig struct {
	Grant  string
	Header string
}

// RequestChecker checks if a request to host:port with the given method and
// path is allowed. Provided by the caller to encapsulate network rule evaluation.
type RequestChecker func(host string, port int, method, path string) bool

// PathRulesChecker reports whether path-level rules exist for a given host.
// When true, the proxy intercepts CONNECT tunnels for path-level inspection.
type PathRulesChecker func(host string, port int) bool

// httpTransport is a shared transport for non-CONNECT HTTP forwarding with
// sane timeout defaults. No client-level Timeout is set because the proxy may
// handle streaming responses. Typed as http.RoundTripper so tests can swap
// in a recording transport.
var httpTransport http.RoundTripper = &http.Transport{
	Proxy: nil,
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	TLSHandshakeTimeout:   10 * time.Second,
	ResponseHeaderTimeout: 5 * time.Minute,
	IdleConnTimeout:       90 * time.Second,
}

// MaxBodySize is the maximum size of request/response bodies to capture (8KB).
// Only this much is buffered for logging; the full body is always forwarded.
const MaxBodySize = 8 * 1024

// maxPolicyBodySize is the maximum request-body size (10MB) the proxy will
// buffer to evaluate http-scope Keep policy rules that inspect the body. Unlike
// MaxBodySize (a logging-only sample), the entire body must be buffered and
// parsed here, because partial JSON cannot be unmarshalled. Requests whose body
// exceeds this limit are denied (fail-closed) when a body rule is in effect.
// Mirrors maxLLMResponseSize, the equivalent cap on the response side.
const maxPolicyBodySize = 10 << 20

// RequestLogData contains all data for a logged request.
// Designed for canonical log lines: one wide structured entry per request.
type RequestLogData struct {
	RequestID        string // Unique request identifier (from X-Request-Id or generated)
	Method           string
	URL              string
	Host             string // Target hostname (extracted from URL or CONNECT)
	Path             string // Request path (empty for CONNECT tunnel-level logs)
	RequestType      string // "http", "connect", "mcp", "relay", "postgres"
	StatusCode       int
	Duration         time.Duration
	Err              error
	RequestHeaders   http.Header
	ResponseHeaders  http.Header
	RequestBody      []byte
	ResponseBody     []byte
	RequestSize      int64           // Content-Length of the request body, -1 if unknown. Always -1 for postgres connections (see RequestMessages).
	ResponseSize     int64           // For the streaming relay/MCP paths, the actual bytes delivered to the client; for other paths, the response Content-Length (-1 if unknown). Always -1 for postgres connections (see ResponseMessages).
	RequestMessages  int64           // Postgres protocol messages relayed client→upstream; 0 for non-postgres connections.
	ResponseMessages int64           // Postgres protocol messages relayed upstream→client; 0 for non-postgres connections.
	AuthInjected     bool            // True if any credential header was injected for this host
	InjectedHeaders  map[string]bool // Lower-cased header names that were injected
	Grants           []string        // Credential grant names that were injected
	Denied           bool            // True if request was denied by network/keep policy
	DenyReason       string          // Why the request was denied (e.g., "network_policy", "keep_policy")
	RunID            string          // Run ID from per-run context (daemon mode)
	UserID           string          // User ID from proxy auth username. For postgres connections this carries the Postgres role, not the proxy auth user.
	Ctx              context.Context // Request context (for OTel span extraction, may be nil)

	// ClientAddr is the client's network address ("ip:port") as seen by the
	// listener. For intercepted CONNECT traffic it is the address of the
	// client that opened the tunnel, not the address of the (hijacked,
	// TLS-terminated) connection carrying the individual inner requests. For
	// postgres connections it is the TCP peer of the data-plane listener.
	ClientAddr string

	// ApplicationName is the client-supplied Postgres "application_name"
	// startup parameter, captured for request tracing. It is free-form,
	// client-controlled text (sanitized before being placed here — see
	// SanitizeLogValue) and, unlike RunID, is a correlation slug rather than
	// a trusted identity: a client can set it to anything, including another
	// caller's label. Empty for non-postgres connections and for postgres
	// connections whose client did not set it.
	ApplicationName string
}

// RequestLogger is called for each proxied request.
type RequestLogger func(data RequestLogData)

// PolicyLogData contains data for a policy denial event.
type PolicyLogData struct {
	RunID     string
	Scope     string
	Operation string
	Rule      string
	Message   string
	Ctx       context.Context // Request context (for OTel span extraction, may be nil)
}

// PolicyLogger is called when a policy denial occurs.
type PolicyLogger func(data PolicyLogData)

// isTextContentType returns true for text-based content types that should be captured.
func isTextContentType(ct string) bool {
	if ct == "" {
		return false
	}
	ct = strings.ToLower(ct)
	return strings.HasPrefix(ct, "text/") ||
		strings.Contains(ct, "json") ||
		strings.Contains(ct, "xml") ||
		strings.Contains(ct, "x-www-form-urlencoded") ||
		strings.Contains(ct, "javascript")
}

// isJSONContentType reports whether the Content-Type denotes a JSON body
// (e.g. "application/json", "application/vnd.api+json"). Parameters such as
// "; charset=utf-8" are tolerated. Used to decide whether a request body can be
// parsed for http-scope body policy evaluation.
func isJSONContentType(ct string) bool {
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(strings.ToLower(ct))
	return ct == "application/json" || strings.HasSuffix(ct, "+json")
}

// buildHTTPCall constructs the Keep Call for an http-scope policy evaluation.
//
// When no loaded rule in the "http" scope inspects the request body
// (eng.RequiresBody is false), it returns a body-less call and leaves req
// untouched — the common, zero-overhead path.
//
// When a body rule is in effect, it buffers and JSON-parses the request body,
// exposing it to rules under params.body, and restores req.Body so the upstream
// request is unchanged. It fails closed: a body that cannot be inspected
// (non-JSON Content-Type with a payload, malformed JSON, duplicate JSON keys, or
// a body exceeding maxPolicyBodySize) returns ok=false with a reason, and the
// caller denies. A request with no body is allowed through with params.body ==
// null, so body rules simply don't match while path rules still apply.
//
// Note: RequiresBody is scope-global — a single body rule makes this path apply
// to every request in the "http" scope. As a result, any non-JSON request with
// a payload is denied once a body rule exists, even for hosts the rule's `when`
// clause would never match. Scope body rules by host in the rule itself if that
// over-broad denial is a concern.
func buildHTTPCall(eng *keeplib.Engine, req *http.Request, host string) (call keeplib.Call, ok bool, denyReason string) {
	if !eng.RequiresBody("http") {
		return keeplib.NewHTTPCall(req.Method, host, req.URL.Path), true, ""
	}

	if req.Body == nil || req.ContentLength == 0 {
		return keeplib.NewHTTPCallWithBody(req.Method, host, req.URL.Path, nil), true, ""
	}

	// A compressed body can't be inspected without decoding it first, so fail
	// closed with an explicit reason rather than a misleading JSON parse error.
	if enc := req.Header.Get("Content-Encoding"); enc != "" {
		req.Body.Close()
		return keeplib.Call{}, false, "request body uses unsupported Content-Encoding: " + enc
	}

	if ct := req.Header.Get("Content-Type"); !isJSONContentType(ct) {
		req.Body.Close()
		return keeplib.Call{}, false, "request body is not JSON (Content-Type: " + ct + ")"
	}

	// Read one byte past the limit so an exactly-limit body is still accepted
	// while a larger one is detected. Restore req.Body afterward so the upstream
	// request remains intact on the allow path; on a deny path the request is
	// never forwarded, so a truncated restore is harmless.
	buf, err := io.ReadAll(io.LimitReader(req.Body, maxPolicyBodySize+1))
	req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(buf))
	if err != nil {
		return keeplib.Call{}, false, "failed to read request body for policy evaluation"
	}
	if int64(len(buf)) > maxPolicyBodySize {
		return keeplib.Call{}, false, "request body exceeds policy inspection limit"
	}

	// An empty or whitespace-only body carries no JSON to inspect — e.g. a
	// chunked/unknown-length request (ContentLength == -1, so it slips past the
	// fast path above) with no payload. Treat it as bodyless rather than failing
	// closed on json.Unmarshal of empty input, so path rules still apply and body
	// rules simply don't match.
	if len(bytes.TrimSpace(buf)) == 0 {
		return keeplib.NewHTTPCallWithBody(req.Method, host, req.URL.Path, nil), true, ""
	}

	var parsed any
	if err := json.Unmarshal(buf, &parsed); err != nil {
		return keeplib.Call{}, false, "request body is not valid JSON"
	}

	// encoding/json silently keeps the last value for duplicate object keys.
	// An upstream parser that keeps the first would see a different value, so a
	// crafted body (e.g. two "model" keys) could satisfy the rule while a
	// different value reaches the server — a policy bypass. No legitimate client
	// sends duplicate keys, so reject them fail-closed to keep the proxy's view
	// of the body authoritative.
	if hasDuplicateJSONKeys(json.NewDecoder(bytes.NewReader(buf))) {
		return keeplib.Call{}, false, "request body has duplicate JSON keys"
	}
	return keeplib.NewHTTPCallWithBody(req.Method, host, req.URL.Path, parsed), true, ""
}

// hasDuplicateJSONKeys reports whether any object in the JSON read from dec
// contains a duplicate key, recursing into nested objects and arrays. It
// consumes exactly one JSON value. A token error is reported as a duplicate
// (fail-closed): the caller has already confirmed the bytes parse, so an error
// here means the input is ambiguous and must not be trusted.
func hasDuplicateJSONKeys(dec *json.Decoder) bool {
	tok, err := dec.Token()
	if err != nil {
		return true
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return false // scalar value
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return true
			}
			key, ok := keyTok.(string)
			if !ok {
				return true
			}
			if _, dup := seen[key]; dup {
				return true
			}
			seen[key] = struct{}{}
			if hasDuplicateJSONKeys(dec) { // the key's value
				return true
			}
		}
		if _, err := dec.Token(); err != nil { // closing '}'
			return true
		}
	case '[':
		for dec.More() {
			if hasDuplicateJSONKeys(dec) {
				return true
			}
		}
		if _, err := dec.Token(); err != nil { // closing ']'
			return true
		}
	}
	return false
}

// readCloserWrapper wraps a Reader and Closer together.
type readCloserWrapper struct {
	io.Reader
	io.Closer
}

// captureBody reads up to MaxBodySize bytes from a body for logging, returning
// the captured data and a new ReadCloser that streams the full content.
// For small bodies (<=MaxBodySize), the body is fully buffered.
// For large bodies, only MaxBodySize is buffered; the rest streams through.
//
// captureBody does a blocking read-ahead, so it must only be used on bodies that
// are already fully available — i.e. request bodies. For response bodies, which
// may be produced incrementally (Server-Sent Events, ndjson, chunked JSON), use
// capturingBody: a read-ahead there would withhold the response from the client
// until MaxBodySize accumulated, starving streamed responses.
func captureBody(body io.ReadCloser, contentType string) ([]byte, io.ReadCloser) {
	if body == nil {
		return nil, nil
	}

	// Skip binary content types - don't capture but still pass through
	if !isTextContentType(contentType) {
		return nil, body
	}

	// Read first MaxBodySize bytes for capture/logging
	captureBuf := make([]byte, MaxBodySize)
	n, err := io.ReadFull(body, captureBuf)

	if err == io.EOF || err == io.ErrUnexpectedEOF {
		// Body was <= MaxBodySize, we got it all
		body.Close()
		captured := captureBuf[:n]
		return captured, io.NopCloser(bytes.NewReader(captured))
	}

	if err != nil {
		// Read error - return what we got
		body.Close()
		captured := captureBuf[:n]
		return captured, io.NopCloser(bytes.NewReader(captured))
	}

	// Body is larger than MaxBodySize - stream the rest through
	// Chain captured bytes with remaining body for full forwarding
	captured := captureBuf[:n]
	fullBody := io.MultiReader(bytes.NewReader(captured), body)
	return captured, &readCloserWrapper{Reader: fullBody, Closer: body}
}

// capturingBody wraps a response body, copying up to limit bytes into an
// in-memory buffer as the body is read, then invoking onClose (if non-nil)
// exactly once when the body is closed. Capture happens lazily as the downstream
// consumer reads, so — unlike captureBody's read-ahead — it never blocks the
// forwarding of a streamed response. Used for response-body logging on the
// streaming proxy paths.
//
// Not safe for concurrent Read/Close; the proxy paths read the body to
// completion and then close it, which is sequential.
type capturingBody struct {
	rc      io.ReadCloser
	buf     bytes.Buffer
	limit   int
	onClose func(captured []byte)
	closed  bool
}

func newCapturingBody(rc io.ReadCloser, limit int, onClose func(captured []byte)) *capturingBody {
	return &capturingBody{rc: rc, limit: limit, onClose: onClose}
}

func (c *capturingBody) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	if n > 0 {
		if room := c.limit - c.buf.Len(); room > 0 {
			if room > n {
				room = n
			}
			c.buf.Write(p[:room])
		}
	}
	return n, err
}

// Captured returns the bytes buffered so far (up to limit).
func (c *capturingBody) Captured() []byte { return c.buf.Bytes() }

func (c *capturingBody) Close() error {
	err := c.rc.Close()
	if !c.closed {
		c.closed = true
		if c.onClose != nil {
			c.onClose(c.buf.Bytes())
		}
	}
	return err
}

// FilterHeaders creates a copy of headers with sensitive values filtered.
// injectedHeaders is a set of lower-cased header names whose values should be
// redacted (credential headers the proxy injected).
func FilterHeaders(headers http.Header, injectedHeaders map[string]bool) map[string]string {
	if headers == nil {
		return nil
	}

	result := make(map[string]string)
	for key, values := range headers {
		// Always filter proxy headers
		if strings.EqualFold(key, "Proxy-Authorization") || strings.EqualFold(key, "Proxy-Connection") {
			continue
		}
		// Redact injected credential headers
		if injectedHeaders[strings.ToLower(key)] {
			result[key] = "[REDACTED]"
			continue
		}
		// Join multiple values with comma (standard HTTP practice)
		result[key] = strings.Join(values, ", ")
	}
	return result
}

// logRequest is a helper that logs request data if a logger is configured.
// The ctxReq parameter provides the RunContextData (from CONNECT or HTTP request context)
// for extracting the RunID; it may be nil when context is unavailable.
// The data struct is passed by value; this method enriches it with RunID, UserID,
// and Ctx from ctxReq before forwarding to the logger callback.
func (p *Proxy) logRequest(ctxReq *http.Request, data RequestLogData) {
	if p.logger == nil {
		return
	}
	if ctxReq != nil {
		if rc := getRunContext(ctxReq); rc != nil {
			data.RunID = rc.RunID
		}
		if uid := UserIDFromContext(ctxReq.Context()); uid != "" {
			data.UserID = uid
		}
		data.Ctx = ctxReq.Context()
		if data.RequestID == "" {
			data.RequestID = RequestIDFromContext(ctxReq.Context())
		}
	}
	data.AuthInjected = len(data.InjectedHeaders) > 0
	p.logger(data)
}

// logExit emits the canonical log line for a handler exit path. It copies
// base, stamps StatusCode and Duration (measured from start), applies mutate
// to let the caller set exit-specific fields (Err, Denied, DenyReason,
// InjectedHeaders, Grants, ResponseSize, ...), then forwards to logRequest.
// mutate may be nil when no extra fields apply.
func (p *Proxy) logExit(r *http.Request, base RequestLogData, start time.Time, status int, mutate func(*RequestLogData)) {
	data := base
	data.StatusCode = status
	data.Duration = time.Since(start)
	if mutate != nil {
		mutate(&data)
	}
	p.logRequest(r, data)
}

// credentialHeader holds a header name and value for credential injection.
type credentialHeader struct {
	Name  string // Header name (e.g., "Authorization", "x-api-key")
	Value string // Header value (e.g., "Bearer token", "sk-ant-...")
	Grant string // Grant name for logging (e.g., "github", "anthropic")

	// Invalidate, when non-nil, drops whatever cached state produced Value so
	// the next request re-resolves it. The proxy calls it when the destination
	// rejects the credential (401/403), which usually means the credential was
	// rotated or re-authorized upstream and the cached copy is stale. Sources
	// are expected to rate-limit their own evictions: a 403 does not reliably
	// distinguish a stale credential from an authorized-but-forbidden request.
	// Nil for credentials with no cache behind them (e.g. static headers).
	Invalidate func()
}

// extraHeader holds an additional header to inject for a host.
type extraHeader struct {
	Name  string
	Value string
}

// tokenSubstitution maps a placeholder string to the real token for a host.
type tokenSubstitution struct {
	placeholder string
	realToken   string
}

// CredentialHeader is the exported version of credentialHeader for daemon use.
type CredentialHeader = credentialHeader

// ExtraHeader is the exported version of extraHeader for daemon use.
type ExtraHeader = extraHeader

// TokenSubstitution is the exported version of tokenSubstitution for daemon use.
type TokenSubstitution = tokenSubstitution

// NewTokenSubstitution creates a TokenSubstitution with the given placeholder and real token.
func NewTokenSubstitution(placeholder, realToken string) *TokenSubstitution {
	return &TokenSubstitution{placeholder: placeholder, realToken: realToken}
}

// HostPattern is the exported version of hostPattern.
type HostPattern = hostPattern

// ParseHostPattern is the exported wrapper for parseHostPattern.
func ParseHostPattern(pattern string) HostPattern {
	return parseHostPattern(pattern)
}

// MatchesHostPattern reports whether a host:port matches a parsed host pattern.
func MatchesHostPattern(pattern HostPattern, host string, port int) bool {
	return matchesPattern(pattern, host, port)
}

// RunContextData holds per-run credential data resolved by ContextResolver.
// The host-keyed maps are read without synchronization on every request —
// including linear scans for wildcard and case-fold matching — so they must
// not be mutated after the RunContextData is registered with the proxy.
type RunContextData struct {
	RunID                string
	Credentials          map[string][]credentialHeader
	ExtraHeaders         map[string][]extraHeader
	RemoveHeaders        map[string][]string
	TokenSubstitutions   map[string]*tokenSubstitution
	ResponseTransformers map[string][]ResponseTransformer
	MCPServers           []MCPServerConfig
	Policy               string
	AllowedHosts         []hostPattern
	RequestCheck         RequestChecker
	PathRulesCheck       PathRulesChecker
	AWSHandler           http.Handler
	CredStore            CredentialStore
	KeepEngines          map[string]*keeplib.Engine
	HostGateway          string
	HostGatewayIP        string // actual IP to forward allowed host-gateway requests to
	AllowedHostPorts     []int
	PostgresResolvers    []PostgresResolverEntry
}

// ContextResolver resolves a proxy auth token to per-run context data.
type ContextResolver func(token string) (*RunContextData, bool)

// CredentialResolver resolves credentials dynamically per-request. Unlike
// static credentials (pre-resolved at startup), resolvers may inspect and
// modify the request (e.g., strip a subject identity header) and may make
// external calls (e.g., RFC 8693 token exchange).
//
// proxyReq is the original proxy-level request (CONNECT for intercepted
// connections, or the same as innerReq for plain HTTP/relay). It carries
// Proxy-Authorization and other proxy-hop headers. innerReq is the
// application-level request the resolver may inspect and modify.
//
// Returns nil with no error when the resolver has no credentials to offer.
type CredentialResolver func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]credentialHeader, error)

// Proxy is an HTTP proxy that injects credentials into outgoing requests.
//
// # Security Model
//
// The proxy handles two distinct security concerns:
//
//  1. Credential injection: The proxy injects credential headers for
//     configured hosts (e.g., api.github.com, api.anthropic.com). When CA
//     is set, it performs TLS interception (MITM) to inject headers into
//     HTTPS requests. Supports custom header names (Authorization, x-api-key, etc).
//
//  2. Proxy authentication: When authToken is set, clients must authenticate
//     to the proxy itself via Proxy-Authorization header. This prevents
//     unauthorized access when the proxy binds to all interfaces (0.0.0.0),
//     which is required for Apple containers that access the host via
//     gateway IP rather than localhost.
//
// For Docker containers, the proxy binds to localhost (127.0.0.1) and
// authentication is not required. For Apple containers, the proxy binds
// to all interfaces with a cryptographically secure token for authentication.
type Proxy struct {
	credentials          map[string][]credentialHeader      // host -> credential headers
	credentialResolvers  map[string]credentialResolverEntry // host -> dynamic resolver + declared strip headers
	postgresResolvers    []PostgresResolverEntry            // host pattern -> Postgres password resolver
	extraHeaders         map[string][]extraHeader           // host -> additional headers to inject
	responseTransformers map[string][]ResponseTransformer   // host -> response transformers
	mu                   sync.RWMutex
	ca                   *CA              // Optional CA for TLS interception
	logger               RequestLogger    // Optional request logger
	authToken            string           // Optional auth token required for proxy access
	delegateAuth         bool             // Skip static authToken check; delegate to credential resolvers
	policy               string           // "permissive" or "strict"
	allowedHosts         []hostPattern    // parsed allow patterns for strict policy
	requestChecker       RequestChecker   // per-host request rules checker
	pathRulesChecker     PathRulesChecker // checks if host has path-level rules
	awsHandler           http.Handler     // Optional handler for AWS credential endpoint
	credStore            CredentialStore
	mcpServers           []MCPServerConfig
	removeHeaders        map[string][]string           // host -> []headerName
	tokenSubstitutions   map[string]*tokenSubstitution // host -> substitution
	relays               map[string]string             // name -> target URL for relay endpoints
	contextResolver      ContextResolver               // optional per-run credential resolver
	policyLogger         PolicyLogger                  // optional policy decision logger
	upstreamCAs          *x509.CertPool                // optional CA pool for upstream TLS verification
	captureHeaders       []string                      // headers to capture in logs and strip before forwarding
}

// NewProxy creates a new auth proxy.
func NewProxy() *Proxy {
	return &Proxy{
		credentials:          make(map[string][]credentialHeader),
		credentialResolvers:  make(map[string]credentialResolverEntry),
		extraHeaders:         make(map[string][]extraHeader),
		responseTransformers: make(map[string][]ResponseTransformer),
		removeHeaders:        make(map[string][]string),
		tokenSubstitutions:   make(map[string]*tokenSubstitution),
		policy:               "permissive", // default to permissive
	}
}

// SetAuthToken sets the required authentication token for proxy access.
func (p *Proxy) SetAuthToken(token string) {
	p.authToken = token
}

// SetDelegateAuth skips the static authToken check, allowing credential
// resolvers to validate caller identity instead. Used when actor_token_from
// is configured and each caller has a unique proxy auth password that the
// STS validates.
func (p *Proxy) SetDelegateAuth(delegate bool) {
	p.delegateAuth = delegate
}

// SetCA sets the CA for TLS interception.
func (p *Proxy) SetCA(ca *CA) {
	p.ca = ca
}

// SetUpstreamCAs sets a custom CA pool for verifying upstream (origin server)
// TLS certificates during CONNECT interception. When nil (the default), the
// system root certificates are used. This is useful for environments with
// private PKI or for testing.
func (p *Proxy) SetUpstreamCAs(pool *x509.CertPool) {
	p.upstreamCAs = pool
}

// SetLogger sets the request logger.
func (p *Proxy) SetLogger(logger RequestLogger) {
	p.logger = logger
}

// SetPolicyLogger sets the policy decision logger.
func (p *Proxy) SetPolicyLogger(logger PolicyLogger) {
	p.policyLogger = logger
}

// logPolicy logs a policy denial if a logger is configured.
func (p *Proxy) logPolicy(ctxReq *http.Request, scope, operation, rule, message string) {
	if p.policyLogger == nil {
		return
	}
	var runID string
	var reqCtx context.Context
	if ctxReq != nil {
		if rc := getRunContext(ctxReq); rc != nil {
			runID = rc.RunID
		}
		reqCtx = ctxReq.Context()
	}
	p.policyLogger(PolicyLogData{
		RunID:     runID,
		Scope:     scope,
		Operation: operation,
		Rule:      rule,
		Message:   message,
		Ctx:       reqCtx,
	})
}

// SetAWSHandler sets the handler for AWS credential requests.
func (p *Proxy) SetAWSHandler(h http.Handler) {
	p.awsHandler = h
}

// SetMCPServers configures MCP servers for credential injection.
func (p *Proxy) SetMCPServers(servers []MCPServerConfig) {
	p.mcpServers = servers
}

// SetCredentialStore sets the credential store for MCP credential retrieval.
func (p *Proxy) SetCredentialStore(store CredentialStore) {
	p.credStore = store
}

// SetContextResolver sets the per-run context resolver for multi-tenant proxy use.
// When set, the proxy can resolve auth tokens to per-run credential data.
func (p *Proxy) SetContextResolver(resolver ContextResolver) {
	p.contextResolver = resolver
}

// SetCaptureHeaders configures headers to capture in request logs and strip
// before forwarding upstream. Header matching is case-insensitive.
// Returns an error if any header is sensitive (Authorization, Proxy-Authorization, Cookie),
// if there are more than 10 headers, or if duplicates are present.
func (p *Proxy) SetCaptureHeaders(headers []string) error {
	if err := ValidateCaptureHeaders(headers); err != nil {
		return err
	}
	p.captureHeaders = headers
	return nil
}

// sensitiveHeaders are headers that must never be captured, even if configured.
var sensitiveHeaders = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
}

// ValidateCaptureHeaders checks a capture headers list for validity.
// Rejects sensitive headers, more than 10 entries, and case-insensitive duplicates.
func ValidateCaptureHeaders(headers []string) error {
	if len(headers) > 10 {
		return fmt.Errorf("capture_headers: max 10 headers allowed, got %d", len(headers))
	}
	seen := make(map[string]bool, len(headers))
	for _, h := range headers {
		lower := strings.ToLower(h)
		if sensitiveHeaders[lower] {
			return fmt.Errorf("capture_headers: %q is a sensitive header and cannot be captured", h)
		}
		if seen[lower] {
			return fmt.Errorf("capture_headers: duplicate header %q", h)
		}
		seen[lower] = true
	}
	return nil
}

// maxCapturedLogValueLen bounds how many bytes of a client-controlled string
// are kept in a request log entry.
const maxCapturedLogValueLen = 256

// SanitizeLogValue prepares a client-controlled string for inclusion in a
// structured log line: it discards invalid UTF-8, strips control characters
// (newlines, carriage returns, NUL, tabs, ...) so the value cannot forge
// additional log lines or otherwise corrupt structured log output, and
// bounds the result to maxCapturedLogValueLen bytes, truncating at a valid
// UTF-8 boundary rather than splitting a multi-byte rune. Used for both
// captured HTTP header values (capture_headers) and the Postgres
// application_name startup parameter — both are free-form text supplied by
// the client, not constrained by any protocol grammar the way most other
// logged fields are.
func SanitizeLogValue(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	if strings.ContainsFunc(s, unicode.IsControl) {
		s = strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return -1
			}
			return r
		}, s)
	}
	if len(s) > maxCapturedLogValueLen {
		s = s[:maxCapturedLogValueLen]
		for len(s) > 0 && !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

// ResolveContext looks up per-run context data by auth token.
// Returns nil, false when no resolver is set or the token is not found.
func (p *Proxy) ResolveContext(token string) (*RunContextData, bool) {
	if p.contextResolver == nil {
		return nil, false
	}
	return p.contextResolver(token)
}

// SetCredential sets the credential for a host using the Authorization header.
func (p *Proxy) SetCredential(host, authHeader string) {
	p.SetCredentialHeader(host, "Authorization", authHeader)
}

// SetCredentialHeader sets a custom credential header for a host.
// Use this for APIs that use non-standard header names like "x-api-key".
// The host must be a valid hostname (not empty, no path components).
func (p *Proxy) SetCredentialHeader(host, headerName, headerValue string) {
	p.SetCredentialWithGrant(host, headerName, headerValue, "")
}

// SetCredentialWithGrant sets a credential header with grant info for logging.
// Grant is used for structured logging to identify the credential source.
// If a credential with the same grant and header name already exists for
// the host, it is updated in place (upsert). Otherwise, a new entry is
// appended. Matching on both grant and header name prevents empty-grant
// collisions when SetCredentialHeader is called multiple times with
// different headers.
func (p *Proxy) SetCredentialWithGrant(host, headerName, headerValue, grant string) {
	if !isValidHost(host) {
		slog.Debug("ignoring invalid host for credential injection",
			"subsystem", "proxy",
			"host", host,
			"header", headerName)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	entry := credentialHeader{Name: headerName, Value: headerValue, Grant: grant}
	for i, existing := range p.credentials[host] {
		if existing.Grant == grant && existing.Name == headerName {
			p.credentials[host][i] = entry
			return
		}
	}
	p.credentials[host] = append(p.credentials[host], entry)
}

// SetCredentialResolver registers a dynamic credential resolver for a host.
// Unlike static credentials, resolvers are called per-request and may make
// external calls (e.g., RFC 8693 token exchange). Only one resolver per host
// is supported; calling again for the same host replaces the previous
// resolver. Passing a nil resolver disables resolution for that host: the
// nil entry matches and terminates the lookup, so a broader (bare-host or
// wildcard) resolver does not apply.
//
// A resolver that removes request headers (e.g. a subject-identity header it
// consumes) should be registered with SetCredentialResolverWithStripHeaders
// instead, so the removal still happens when the proxy skips the resolver
// because a better-matched static credential exists.
func (p *Proxy) SetCredentialResolver(host string, resolver CredentialResolver) {
	p.setCredentialResolver(host, credentialResolverEntry{resolve: resolver})
}

// SetCredentialResolverWithStripHeaders registers a dynamic credential
// resolver together with the request headers it consumes and removes. When a
// better-matched static credential outranks the resolver, the resolver is
// not called — its external round trip must not stall requests whose
// credential is already decided — and the proxy removes the declared headers
// itself so they never leak upstream.
func (p *Proxy) SetCredentialResolverWithStripHeaders(host string, resolver CredentialResolver, stripHeaders ...string) {
	p.setCredentialResolver(host, credentialResolverEntry{resolve: resolver, stripHeaders: stripHeaders, declared: true})
}

func (p *Proxy) setCredentialResolver(host string, entry credentialResolverEntry) {
	if !isValidHost(host) {
		slog.Debug("ignoring invalid host for credential resolver",
			"subsystem", "proxy",
			"host", host)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.credentialResolvers[host]; exists {
		slog.Debug("replacing existing credential resolver",
			"subsystem", "proxy",
			"host", host)
	}
	p.credentialResolvers[host] = entry
}

// AddExtraHeader adds an additional header to inject for a host.
// This is used for headers beyond the main credential header, such as
// beta feature flags or API version headers.
// The host must be a valid hostname (not empty, no path components).
func (p *Proxy) AddExtraHeader(host, headerName, headerValue string) {
	if !isValidHost(host) {
		slog.Debug("ignoring invalid host for extra header injection", "host", host, "header", headerName)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.extraHeaders[host] = append(p.extraHeaders[host], extraHeader{Name: headerName, Value: headerValue})
}

// AddResponseTransformer registers a response transformer for a host.
// Transformers are called in registration order after receiving the upstream response.
// Each transformer can inspect and optionally modify the response.
// The host must be a valid hostname (not empty, no path components).
func (p *Proxy) AddResponseTransformer(host string, transformer ResponseTransformer) {
	if !isValidHost(host) {
		slog.Debug("ignoring invalid host for response transformer", "host", host)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.responseTransformers[host] = append(p.responseTransformers[host], transformer)
}

// RemoveRequestHeader removes a client-sent header before forwarding.
func (p *Proxy) RemoveRequestHeader(host, headerName string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.removeHeaders[host] = append(p.removeHeaders[host], headerName)
}

// SetTokenSubstitution replaces placeholder tokens with real tokens
// in both Authorization headers and request bodies for a specific host.
func (p *Proxy) SetTokenSubstitution(host, placeholder, realToken string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokenSubstitutions[host] = &tokenSubstitution{
		placeholder: placeholder,
		realToken:   realToken,
	}
}

// getTokenSubstitution returns the token substitution for a host.
func (p *Proxy) getTokenSubstitution(host string) *tokenSubstitution {
	p.mu.RLock()
	defer p.mu.RUnlock()
	sub, _ := lookupHostKeyed(p.tokenSubstitutions, host, presenceUsable)
	return sub
}

// getRemoveHeaders returns header names to remove for a host.
func (p *Proxy) getRemoveHeaders(host string) []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	headers, _ := lookupHostKeyed(p.removeHeaders, host, presenceUsable)
	return headers
}

// maxTokenSubBodySize is the maximum request body size for token substitution.
// Larger bodies (like file uploads) are not substituted to avoid memory issues.
const maxTokenSubBodySize = 64 * 1024

// applyTokenSubstitution replaces placeholder tokens with real tokens in
// the request's URL path, Authorization header, and body.
// URL path substitution is needed for APIs like Telegram Bot API where
// the token is embedded in the URL (e.g., /bot{TOKEN}/sendMessage).
func (p *Proxy) applyTokenSubstitution(req *http.Request, sub *tokenSubstitution) {
	// Replace in URL path
	if newPath := strings.ReplaceAll(req.URL.Path, sub.placeholder, sub.realToken); newPath != req.URL.Path {
		req.URL.Path = newPath
		if req.URL.RawPath != "" {
			req.URL.RawPath = strings.ReplaceAll(req.URL.RawPath, sub.placeholder, sub.realToken)
		}
	}

	// Replace in Authorization header
	if auth := req.Header.Get("Authorization"); auth != "" {
		if newAuth := strings.ReplaceAll(auth, sub.placeholder, sub.realToken); newAuth != auth {
			req.Header.Set("Authorization", newAuth)
		}
	}

	// Replace in request body (limited to maxTokenSubBodySize)
	if req.Body != nil && req.ContentLength > 0 && req.ContentLength <= maxTokenSubBodySize {
		bodyBytes, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err == nil {
			bodyStr := string(bodyBytes)
			if newBody := strings.ReplaceAll(bodyStr, sub.placeholder, sub.realToken); newBody != bodyStr {
				bodyBytes = []byte(newBody)
			}
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			req.ContentLength = int64(len(bodyBytes))
		}
	}
}

// isValidHost checks if a host string is valid for credential injection.
// Returns false for empty strings, paths, or other invalid values.
func isValidHost(host string) bool {
	if host == "" {
		return false
	}
	// Reject anything that looks like a path or URL
	if strings.ContainsAny(host, "/:@") {
		return false
	}
	// Reject whitespace
	if strings.ContainsAny(host, " \t\n\r") {
		return false
	}
	return true
}

// SetNetworkPolicy sets the network policy and allowed hosts.
// policy should be "permissive" or "strict".
// allows is a list of host patterns like "api.example.com" or "*.example.com".
// grants is a list of grant names like "github" that will be expanded to host patterns.
func (p *Proxy) SetNetworkPolicy(policy string, allows []string, grants []string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.policy = policy
	p.allowedHosts = nil
	p.requestChecker = nil
	p.pathRulesChecker = nil

	// Parse explicit allow patterns
	for _, pattern := range allows {
		p.allowedHosts = append(p.allowedHosts, parseHostPattern(pattern))
	}

	// Add hosts from grants
	for _, grant := range grants {
		grantHosts := GetHostsForGrant(grant)
		for _, pattern := range grantHosts {
			p.allowedHosts = append(p.allowedHosts, parseHostPattern(pattern))
		}
	}
}

// SetNetworkPolicyWithRules sets the network policy with per-host request rules.
// The allows list should include hosts from rules (the caller extracts them).
// checker evaluates per-request rules; pathChecker reports if path-level rules exist.
func (p *Proxy) SetNetworkPolicyWithRules(policy string, allows []string, grants []string, checker RequestChecker, pathChecker PathRulesChecker) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.policy = policy
	p.allowedHosts = nil
	p.requestChecker = checker
	p.pathRulesChecker = pathChecker

	for _, pattern := range allows {
		p.allowedHosts = append(p.allowedHosts, parseHostPattern(pattern))
	}
	for _, grant := range grants {
		for _, pattern := range GetHostsForGrant(grant) {
			p.allowedHosts = append(p.allowedHosts, parseHostPattern(pattern))
		}
	}
}

// bareHost strips the port from a host:port string, returning the host
// unchanged when it has no port.
func bareHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil && h != "" {
		return h
	}
	// A bracketed, portless IPv6 literal ("[::1]") fails SplitHostPort;
	// unwrap it so it matches keys stored in canonical form ("::1").
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host[1 : len(host)-1]
	}
	return host
}

// matchWildcardHostKey reports whether a wildcard host map key like
// "*.example.com" matches the request host, given the pre-lowercased host
// and bare (port-stripped) host. "*.example.com" matches "api.example.com"
// and "a.b.example.com", never "example.com" itself. This applies the same
// suffix rule as hostHasSuffixFold (matchesPattern's wildcard branch),
// inlined against the pre-lowered inputs so the per-key scan does not
// re-lower the host — a semantic change to one must be mirrored in the
// other. A port-less key matches the port-stripped host (any port); a key
// carrying a port ("*.example.com:8443") matches the full host:port, so the
// port must match exactly.
func matchWildcardHostKey(key, lowerHost, lowerBare string) bool {
	if !strings.HasPrefix(key, "*.") {
		return false
	}
	suffix := strings.ToLower(key[1:]) // "*.example.com" -> ".example.com"
	return strings.HasSuffix(lowerBare, suffix) ||
		(lowerHost != lowerBare && strings.HasSuffix(lowerHost, suffix))
}

// compareHostKeySpecificity ranks two host keys of the same tier that match
// the same host: positive when a is more specific than b, negative when
// less, zero when equally specific. Specificity is the length of the key's
// domain part — a port suffix must not make a domain-broader key outrank a
// domain-narrower one — then a port-pinned key beats a port-less one. Both
// in-map selection (lookupHostKeyed) and cross-map ranking
// (hostMatch.outranks) use this single comparator so they cannot diverge.
func compareHostKeySpecificity(a, b string) int {
	da, db := bareHost(a), bareHost(b)
	if len(da) != len(db) {
		return len(da) - len(db)
	}
	aPinned, bPinned := len(a) > len(da), len(b) > len(db)
	if aPinned != bPinned {
		if aPinned {
			return 1
		}
		return -1
	}
	return 0
}

// moreSpecificWildcardKey reports whether wildcard key a should be preferred
// over b when both match the same host: higher specificity first, then the
// lexicographically smallest key so the pick never depends on map iteration
// order.
func moreSpecificWildcardKey(a, b string) bool {
	if c := compareHostKeySpecificity(a, b); c != 0 {
		return c > 0
	}
	return a < b
}

// hostMatchTier classifies how lookupHostKeyed matched a host against a key.
// Order matters: higher tiers outrank lower ones. A verbatim (case-exact)
// key match outranks a case-fold match, which outranks a wildcard match.
type hostMatchTier int

const (
	hostMatchNone hostMatchTier = iota
	hostMatchWildcard
	hostMatchExactFold
	hostMatchExact
)

// hostMatch records how a lookup matched, for callers that rank matches
// from different maps against each other (e.g. static credentials vs
// credential resolvers).
type hostMatch struct {
	tier hostMatchTier
	key  string
}

// outranks reports whether m is a strictly better match than other for the
// same host: verbatim exact beats case-fold exact beats wildcard, and
// within a tier compareHostKeySpecificity decides — so a port-pinned key
// outranks a port-less one in the exact and fold tiers too, matching the
// in-map ordering (host:port is tried before the bare host). Equal-rank
// matches do not outrank each other (the caller's own preference order
// breaks that tie).
func (m hostMatch) outranks(other hostMatch) bool {
	if m.tier != other.tier {
		return m.tier > other.tier
	}
	return m.tier != hostMatchNone && compareHostKeySpecificity(m.key, other.key) > 0
}

// lookupHostKeyed resolves a host against a map keyed by exact hostnames or
// "*." wildcard patterns, skipping entries the usable predicate rejects
// (embedder-supplied maps may hold empty slices or nil values, which must
// not shadow a key from a later tier). Exact keys win over wildcard keys:
// the host is tried verbatim, then port-stripped, then case-insensitively;
// only when every exact tier misses is the most specific (longest) matching
// wildcard key used, ranked by moreSpecificWildcardKey. In the fold tier, a
// key matching the full host:port beats a key matching only the bare host
// (mirroring the verbatim tiers' order), and any remaining tie goes to the
// lexicographically smallest key so the pick never depends on map iteration
// order. The fallback scan is linear in the number of configured host keys;
// it runs only when the verbatim and bare lookups miss, and the maps are
// config-scale, not request-scale.
func lookupHostKeyed[V any](m map[string]V, host string, usable func(V) bool) (V, hostMatch) {
	if v, ok := m[host]; ok && usable(v) {
		return v, hostMatch{hostMatchExact, host}
	}
	bare := bareHost(host)
	if bare != host {
		if v, ok := m[bare]; ok && usable(v) {
			return v, hostMatch{hostMatchExact, bare}
		}
	}
	lowerHost, lowerBare := strings.ToLower(host), strings.ToLower(bare)
	var best V
	var bestKey string
	tier := hostMatchNone
	bestFoldsHost := false // best fold key matches the full host:port, not just bare
	for key, v := range m {
		if !usable(v) {
			continue
		}
		// The case-insensitive exact tier must fold both the bare host and
		// the full host:port — port-bearing keys are expressible in
		// embedder-built RunContextData maps. A host:port fold match beats
		// a bare fold match, as in the verbatim tiers. Folding is via
		// ToLower so this tier agrees with the wildcard tier's semantics
		// (EqualFold's simple folding differs for e.g. U+017F ſ).
		lowerKey := strings.ToLower(key)
		if foldsHost := host != bare && lowerKey == lowerHost; foldsHost || lowerKey == lowerBare {
			if tier != hostMatchExactFold ||
				(foldsHost && !bestFoldsHost) ||
				(foldsHost == bestFoldsHost && key < bestKey) {
				bestKey, best, tier, bestFoldsHost = key, v, hostMatchExactFold, foldsHost
			}
			continue
		}
		if tier == hostMatchExactFold {
			continue
		}
		if matchWildcardHostKey(key, lowerHost, lowerBare) &&
			(tier == hostMatchNone || moreSpecificWildcardKey(key, bestKey)) {
			bestKey, best, tier = key, v, hostMatchWildcard
		}
	}
	return best, hostMatch{tier, bestKey}
}

// Usable predicates for lookupHostKeyed. Credentials use nonEmptySlice,
// preserving their historical len>0 gating: an empty entry falls through to
// the next tier. The companion maps (extra headers, remove-headers, token
// substitutions, response transformers) use presenceUsable, preserving
// their historical presence gating: an explicit empty or nil entry matches
// and terminates the lookup, letting embedders opt a specific host:port out
// of a broader key's behavior.
func nonEmptySlice[T any](v []T) bool { return len(v) > 0 }

func presenceUsable[V any](V) bool { return true }

// getCredentials returns all credential headers for a host; see
// lookupHostKeyed for the matching rules.
func (p *Proxy) getCredentials(host string) []credentialHeader {
	creds, _ := p.getCredentialsMatch(host)
	return creds
}

// getCredentialsMatch is getCredentials plus the match rank, for callers
// that weigh exact static credentials against wildcard-keyed resolvers.
// Returns a copy of the slice to avoid data races with concurrent
// SetCredentialWithGrant calls (e.g., token refresh).
func (p *Proxy) getCredentialsMatch(host string) ([]credentialHeader, hostMatch) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	creds, match := lookupHostKeyed(p.credentials, host, nonEmptySlice)
	if len(creds) == 0 {
		return nil, hostMatch{}
	}
	out := make([]credentialHeader, len(creds))
	copy(out, creds)
	return out, match
}

// credentialResolverEntry is a registered dynamic resolver plus the request
// headers it declared for removal. A nil resolve func is an explicit
// opt-out: the entry matches and terminates the lookup.
type credentialResolverEntry struct {
	resolve      CredentialResolver
	stripHeaders []string
	// declared is true for resolvers registered via
	// SetCredentialResolverWithStripHeaders: the caller has stated the full
	// set of request headers the resolver removes, so the proxy may skip
	// the resolver when it is outranked and strip those headers itself.
	// Legacy registrations (SetCredentialResolver) may have arbitrary
	// request-mutating side effects the proxy cannot reproduce, so they
	// always run.
	declared bool
}

// getCredentialResolver returns the dynamic resolver for a host; see
// lookupHostKeyed for the matching rules.
func (p *Proxy) getCredentialResolver(host string) CredentialResolver {
	entry, _ := p.getCredentialResolverMatch(host)
	return entry.resolve
}

// getCredentialResolverMatch returns the resolver entry for a host plus the
// match rank. The lookup is presence-based: SetCredentialResolver(host, nil)
// plants a nil entry that matches and terminates the lookup, disabling
// resolution for that host even when a broader (bare-host or wildcard)
// resolver exists — the same opt-out semantics as the companion maps.
func (p *Proxy) getCredentialResolverMatch(host string) (credentialResolverEntry, hostMatch) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return lookupHostKeyed(p.credentialResolvers, host, presenceUsable)
}

// credentialInjectionResult holds the outcome of credential injection.
type credentialInjectionResult struct {
	InjectedHeaders map[string]bool // Lower-cased header names that were injected
	Grants          []string        // Grant names of injected credentials
	// Injected holds the credentials whose values are actually on the request,
	// one per header name. This is narrower than InjectedHeaders: when several
	// credentials share a header name, only the one that won the tie appears
	// here. Consumers acting on a credential's identity (invalidation) must use
	// this, not the header name set.
	Injected []credentialHeader
}

// injectCredentials replaces credential headers in the request.
//
// A credential is selected in one of two ways:
//
//   - Placeholder selection. If the client already sent a credential's header
//     (any non-empty value), that credential is chosen and its real value
//     replaces what the client sent. This lets a client pick which grant to use
//     when several target the same host.
//   - Auto-injection. If the client sent none of the credentials' headers, all
//     of them are injected unconditionally, for transparent auth.
//
// Exactly one credential is injected per header name. When several share a
// header name the tie is broken by grant, and the two paths break it in
// opposite directions: auto-injection prefers a non-"claude" grant, while
// placeholder selection prefers "claude". The claude grant is Claude Code's
// OAuth flow, so it must not be injected transparently, but a client that
// explicitly sends the header is asking for exactly it. The winner does not
// depend on the order credentials appear in.
//
// Client-sent headers are sampled once, before anything is written. Testing the
// request as it is mutated would let a credential injected by an earlier
// iteration look like a placeholder the client sent, selecting several
// same-named credentials at once.
//
// Returns a credentialInjectionResult naming the headers injected, the
// credentials whose values reached the wire, and their grants. Grants and
// Injected describe only what was sent — never a credential that lost the tie.
func injectCredentials(req *http.Request, creds []credentialHeader, host, method, path string) credentialInjectionResult {
	if len(creds) == 0 {
		return credentialInjectionResult{}
	}

	// Sample the client's headers before any injection mutates them.
	clientSent := make(map[string]bool, len(creds))
	for _, c := range creds {
		if req.Header.Get(c.Name) != "" {
			clientSent[strings.ToLower(c.Name)] = true
		}
	}

	// selectWinners maps each eligible header name to the index of the single
	// credential that will be injected for it. Iterating creds in order makes
	// the choice independent of map iteration order.
	selectWinners := func(eligible func(headerKey string) bool, preferClaude bool) map[string]int {
		winners := make(map[string]int, len(creds))
		for i, c := range creds {
			key := strings.ToLower(c.Name)
			if !eligible(key) {
				continue
			}
			j, seen := winners[key]
			if !seen {
				winners[key] = i
				continue
			}
			incumbent := creds[j].Grant == "claude"
			challenger := c.Grant == "claude"
			if preferClaude && challenger && !incumbent {
				winners[key] = i
			} else if !preferClaude && incumbent && !challenger {
				winners[key] = i
			}
		}
		return winners
	}

	winners := selectWinners(func(key string) bool { return clientSent[key] }, true)
	autoInjected := len(winners) == 0
	if autoInjected {
		winners = selectWinners(func(string) bool { return true }, false)
	}

	injected := make(map[string]bool, len(winners))
	grants := make([]string, 0, len(winners))
	injectedCreds := make([]credentialHeader, 0, len(winners))

	msg, action := "credential injected", "inject"
	if autoInjected {
		msg, action = "credential auto-injected", "inject-auto"
	}

	for i, c := range creds {
		key := strings.ToLower(c.Name)
		if w, ok := winners[key]; !ok || w != i {
			continue
		}
		req.Header.Set(c.Name, c.Value)
		injected[key] = true
		injectedCreds = append(injectedCreds, c)
		if c.Grant != "" {
			grants = append(grants, c.Grant)
		}
		slog.Debug(msg,
			"subsystem", "proxy",
			"action", action,
			"grant", c.Grant,
			"host", host,
			"header", c.Name,
			"method", method,
			"path", path)
	}

	return credentialInjectionResult{InjectedHeaders: injected, Grants: grants, Injected: injectedCreds}
}

// mergeExtraHeaders injects extra headers into a request. If the request
// already has a value for a header, the new value is appended with a comma
// separator (standard HTTP multi-value format). This preserves client-sent
// flags like anthropic-beta while adding proxy-injected flags.
//
// Note: comma-joining is correct for list-valued headers (RFC 9110 §5.3) like
// anthropic-beta, Accept, Cache-Control, etc. It is NOT correct for headers
// like Set-Cookie that cannot be combined. All headers currently registered
// via routing.go are list-safe; if that changes, this function will need a
// per-header strategy.
func mergeExtraHeaders(req *http.Request, host string, headers []extraHeader) {
	for _, h := range headers {
		if existing := req.Header.Get(h.Name); existing != "" {
			req.Header.Set(h.Name, existing+","+h.Value)
		} else {
			req.Header.Set(h.Name, h.Value)
		}
	}
	if len(headers) > 0 {
		slog.Debug("extra headers injected",
			"subsystem", "proxy",
			"action", "inject-extra",
			"host", host,
			"count", len(headers))
	}
}

// getExtraHeaders returns additional headers to inject for a host.
func (p *Proxy) getExtraHeaders(host string) []extraHeader {
	p.mu.RLock()
	defer p.mu.RUnlock()
	headers, _ := lookupHostKeyed(p.extraHeaders, host, presenceUsable)
	return headers
}

// getResponseTransformers returns response transformers for a host.
func (p *Proxy) getResponseTransformers(host string) []ResponseTransformer {
	p.mu.RLock()
	defer p.mu.RUnlock()
	transformers, _ := lookupHostKeyed(p.responseTransformers, host, presenceUsable)
	return transformers
}

// getRunContext extracts per-run context data from the request context.
// Returns nil when no RunContextData is present (legacy mode).
func getRunContext(r *http.Request) *RunContextData {
	if rc, ok := r.Context().Value(runContextKey).(*RunContextData); ok {
		return rc
	}
	return nil
}

// logHeadersRedacted clones h for logging with the subject-identity
// headers declared by the host's matching resolver removed. Policy-denial
// logs snapshot headers before any resolver has run (denied requests must
// not trigger resolver side effects), so the proxy redacts the declared
// headers itself — credential values must never be logged. Headers a
// legacy (undeclared) resolver would strip cannot be known here; those
// registrations should migrate to SetCredentialResolverWithStripHeaders.
func (p *Proxy) logHeadersRedacted(h http.Header, host string) http.Header {
	out := h.Clone()
	entry, _ := p.getCredentialResolverMatch(host)
	for _, name := range entry.stripHeaders {
		out.Del(name)
	}
	return out
}

// getCredentialsForRequest returns all credentials for a host. When
// RunContextData is present, only its credentials are used (the caller
// owns the full credential set for that run). Otherwise, which credentials
// are injected is decided by match rank: a static credential whose key
// match outranks the resolver's (an exact key over a wildcard, or a more
// specific wildcard over a broader one) wins. An outranked resolver
// registered with declared strip headers is skipped — its external round
// trip must not stall a request whose credential is already decided — and
// the proxy removes the declared headers itself; an outranked legacy
// registration (no declaration) still runs for its side effects, with its
// credentials discarded and its error non-fatal. At equal or lower static
// rank the resolver's credentials win when it returns any; if it returns
// nil (e.g., no subject identity found), the proxy falls through to static
// credentials for the same host. This enables patterns like "per-user
// OAuth via token-exchange, with a bot identity fallback."
//
// ctxReq carries the RunContextData (the CONNECT request for intercepted
// connections, or the same request for plain HTTP). innerReq is the actual
// request the resolver may inspect and modify.
func (p *Proxy) getCredentialsForRequest(ctxReq, innerReq *http.Request, host string) ([]credentialHeader, error) {
	if rc := getRunContext(ctxReq); rc != nil {
		creds, _ := lookupHostKeyed(rc.Credentials, host, nonEmptySlice)
		if len(creds) > 0 {
			return creds, nil
		}
		return nil, nil
	}
	entry, resolverMatch := p.getCredentialResolverMatch(host)
	if entry.resolve == nil {
		return p.getCredentials(host), nil
	}
	if staticCreds, staticMatch := p.getCredentialsMatch(host); staticMatch.outranks(resolverMatch) {
		if entry.declared {
			// A better-matched static credential decides this request, so
			// the resolver's external round trip must not stall it. The
			// resolver is skipped; the request headers it declared at
			// registration are removed here so they never leak upstream.
			for _, h := range entry.stripHeaders {
				innerReq.Header.Del(h)
			}
			return staticCreds, nil
		}
		// A legacy registration made no declaration, so the resolver may
		// have request-mutating side effects only it can perform (e.g.
		// stripping a subject header). Run it, discard its credentials,
		// and treat its error as non-fatal — the static credential was
		// going to be injected either way.
		if _, err := entry.resolve(innerReq.Context(), ctxReq, innerReq, host); err != nil {
			slog.Debug("ignoring error from outranked credential resolver",
				"subsystem", "proxy",
				"host", host,
				"error", err)
		}
		// Read static credentials after the resolver has run, not before: a
		// token refresh landing while the resolver was out (e.g. a
		// refreshing source rotating the static token mid-call) must be
		// seen, or the request injects a credential that's already stale.
		return p.getCredentials(host), nil
	}
	resolved, resolveErr := entry.resolve(innerReq.Context(), ctxReq, innerReq, host)
	if resolveErr != nil {
		return nil, resolveErr
	}
	if len(resolved) > 0 {
		return resolved, nil
	}
	// Read static credentials after the resolver has run, not before: a
	// token refresh landing while a slow resolver was out must be seen.
	return p.getCredentials(host), nil
}

// invalidateCredentialsOnAuthFailure drops the cached state behind each
// credential that was injected into the rejected request. Pass
// credentialInjectionResult.Injected, never the full candidate list for the
// host: only one credential wins when several share a header name, and evicting
// the losers would drop cache entries that had no part in this request — and,
// since sources rate-limit evictions per key, could suppress a loser's own
// legitimate eviction later.
//
// A 401 or 403 is the
// only signal gatekeeper gets that a credential resolved from a cache has gone
// stale — the upstream credential behind it was rotated or re-authorized while
// the cache entry was still live. Without this, the proxy keeps injecting the
// dead credential until the entry expires on its own, which can be hours.
//
// This is deliberately evict-only: the failed request is not retried. Its body
// has already been consumed by the time the response arrives, and the requests
// that surface this (a git push, say) are not idempotent. The next request
// re-resolves and succeeds.
//
// Statuses other than 401/403 are left alone; a 5xx says nothing about the
// credential. Sources rate-limit their own evictions, since a 403 also covers
// rate limits and genuinely-forbidden requests.
func invalidateCredentialsOnAuthFailure(creds []credentialHeader, statusCode int) {
	if statusCode != http.StatusUnauthorized && statusCode != http.StatusForbidden {
		return
	}
	for _, cred := range creds {
		if cred.Invalidate != nil {
			cred.Invalidate()
		}
	}
}

// getExtraHeadersForRequest returns extra headers for a host, checking
// RunContextData first, then falling back to the proxy's own map.
func (p *Proxy) getExtraHeadersForRequest(r *http.Request, host string) []extraHeader {
	if rc := getRunContext(r); rc != nil {
		headers, _ := lookupHostKeyed(rc.ExtraHeaders, host, presenceUsable)
		return headers
	}
	return p.getExtraHeaders(host)
}

// getRemoveHeadersForRequest returns headers to remove for a host, checking
// RunContextData first, then falling back to the proxy's own map.
func (p *Proxy) getRemoveHeadersForRequest(r *http.Request, host string) []string {
	if rc := getRunContext(r); rc != nil {
		headers, _ := lookupHostKeyed(rc.RemoveHeaders, host, presenceUsable)
		return headers
	}
	return p.getRemoveHeaders(host)
}

// getTokenSubstitutionForRequest returns the token substitution for a host,
// checking RunContextData first, then falling back to the proxy's own map.
func (p *Proxy) getTokenSubstitutionForRequest(r *http.Request, host string) *tokenSubstitution {
	if rc := getRunContext(r); rc != nil {
		sub, _ := lookupHostKeyed(rc.TokenSubstitutions, host, presenceUsable)
		return sub
	}
	return p.getTokenSubstitution(host)
}

// getResponseTransformersForRequest returns response transformers for a host,
// checking RunContextData first, then falling back to the proxy's own map.
func (p *Proxy) getResponseTransformersForRequest(r *http.Request, host string) []ResponseTransformer {
	if rc := getRunContext(r); rc != nil {
		transformers, _ := lookupHostKeyed(rc.ResponseTransformers, host, presenceUsable)
		return transformers
	}
	return p.getResponseTransformers(host)
}

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
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	}
	return false
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
func (p *Proxy) getCredStoreForRequest(r *http.Request) CredentialStore {
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
	// Auth is skipped because direct requests don't carry Proxy-Authorization.
	// Safety: relays only forward to pre-configured URLs, not arbitrary hosts.
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
		token, ok := extractProxyToken(r)
		if !ok {
			writeProxyAuthRequired(w, "Proxy authentication required")
			return
		}
		rc, found := p.contextResolver(token)
		if !found {
			writeProxyAuthRequired(w, "Invalid proxy token")
			return
		}
		ctx := context.WithValue(r.Context(), runContextKey, rc)
		if uid := extractProxyUsername(r); uid != "" {
			ctx = withUserID(ctx, uid)
		}
		r = r.WithContext(ctx)
	} else if p.delegateAuth {
		if !hasBasicProxyAuth(r) {
			writeProxyAuthRequired(w, "Proxy authentication required")
			return
		}
		if uid := extractProxyUsername(r); uid != "" {
			r = r.WithContext(withUserID(r.Context(), uid))
		}
	} else if p.authToken != "" && !p.checkAuth(r) {
		writeProxyAuthRequired(w, "Proxy authentication required")
		return
	} else if p.authToken != "" {
		// Auth passed — extract username if present.
		if uid := extractProxyUsername(r); uid != "" {
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

// hasBasicProxyAuth returns true if the request carries a Basic
// Proxy-Authorization with a non-empty password. Used by delegateAuth to
// require credentials without comparing against a static token.
func hasBasicProxyAuth(r *http.Request) bool {
	auth := r.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(auth[6:])
	if err != nil {
		return false
	}
	_, password, ok := strings.Cut(string(decoded), ":")
	return ok && password != ""
}

// extractProxyToken extracts the token from a Proxy-Authorization header.
// Supports both Basic auth (from HTTP_PROXY=http://moat:token@host) and Bearer format.
// Returns the extracted token and true, or empty string and false if no valid token found.
func extractProxyToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return "", false
	}

	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:], true
	}

	if strings.HasPrefix(auth, "Basic ") {
		decoded, err := base64.StdEncoding.DecodeString(auth[6:])
		if err != nil {
			return "", false
		}
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			return "", false
		}
		return parts[1], true
	}

	return "", false
}

// extractProxyUsername extracts the username from a Basic Proxy-Authorization header.
// For HTTP_PROXY=http://user:token@host, this returns "user".
// Returns empty string for Bearer auth or if no valid username is found.
func extractProxyUsername(r *http.Request) string {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Basic ") {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(auth[6:])
	if err != nil {
		return ""
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[0]
}

// checkAuth validates the Proxy-Authorization header against the required token.
// Accepts both Basic auth (from HTTP_PROXY=http://moat:token@host) and Bearer format.
// Uses constant-time comparison to prevent timing attacks.
func (p *Proxy) checkAuth(r *http.Request) bool {
	token, ok := extractProxyToken(r)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(p.authToken)) == 1
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
	creds, err := p.getCredentialsForRequest(r, r, lookupHost)
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

	// Copy headers and inject credentials
	for key, values := range r.Header {
		for _, value := range values {
			outReq.Header.Add(key, value)
		}
	}
	credResult := injectCredentials(outReq, creds, host, r.Method, r.URL.Path)

	// Inject any additional headers configured for this host.
	// Merges with existing values (comma-separated) to preserve client
	// headers like anthropic-beta that support multiple flags.
	mergeExtraHeaders(outReq, host, p.getExtraHeadersForRequest(r, lookupHost))

	outReq.Header.Del("Proxy-Connection")
	outReq.Header.Del("Proxy-Authorization")

	// Remove headers that should be stripped, but never remove a
	// credential header the proxy just injected. This prevents conflicts
	// when multiple grants target the same host — e.g., "claude" registers
	// RemoveRequestHeader("x-api-key") for OAuth, but if "anthropic" also
	// injected x-api-key, the injected header must survive.
	for _, headerName := range p.getRemoveHeadersForRequest(r, lookupHost) {
		if credResult.InjectedHeaders[strings.ToLower(headerName)] {
			continue
		}
		outReq.Header.Del(headerName)
	}

	// Strip capture headers — they're metadata for the proxy, not the destination.
	// Skip headers that were just injected as credentials.
	for _, headerName := range p.captureHeaders {
		if credResult.InjectedHeaders[strings.ToLower(headerName)] {
			continue
		}
		outReq.Header.Del(headerName)
	}

	// Apply token substitution if configured.
	// Substitution targets outReq (not r), so r.URL.String() used for logging
	// below still contains the placeholder, not the real token.
	if sub := p.getTokenSubstitutionForRequest(r, lookupHost); sub != nil {
		p.applyTokenSubstitution(outReq, sub)
	}

	if outReq.Header.Get("X-Request-Id") == "" {
		outReq.Header.Set("X-Request-Id", RequestIDFromContext(r.Context()))
	}

	// Forward request
	resp, err := httpTransport.RoundTrip(outReq)

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
		http.Error(w, "moat proxy: upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	invalidateCredentialsOnAuthFailure(credResult.Injected, resp.StatusCode)

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

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Extract host and port for network policy check
	host, portStr, err := net.SplitHostPort(r.Host)
	if err != nil {
		// r.Host should always have port in CONNECT requests
		http.Error(w, "invalid host format", http.StatusBadRequest)
		return
	}

	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		http.Error(w, "invalid port", http.StatusBadRequest)
		return
	}

	start := time.Now()

	// Check network policy before establishing tunnel
	if !p.checkNetworkPolicyForRequest(r, host, port, "CONNECT", "") {
		rc := getRunContext(r)
		var denyReason string
		if rc != nil && isHostGateway(rc, host) {
			denyReason = "Host service blocked: " + host + ":" + strconv.Itoa(port)
		} else {
			denyReason = "Host not in allow list: " + host
		}
		p.logRequest(r, RequestLogData{
			Method:       r.Method,
			URL:          r.Host,
			Host:         host,
			RequestType:  "connect",
			StatusCode:   http.StatusProxyAuthRequired,
			Duration:     time.Since(start),
			RequestSize:  -1,
			ResponseSize: -1,
			ClientAddr:   r.RemoteAddr,
			Denied:       true,
			DenyReason:   denyReason,
		})
		if rc != nil && isHostGateway(rc, host) {
			p.logPolicy(r, "network", "http.connect", "", "Host service blocked: "+host+":"+strconv.Itoa(port))
			p.writeHostBlockedResponse(w, host, port)
		} else {
			p.logPolicy(r, "network", "http.connect", "", "Host not in allow list: "+host)
			p.writeBlockedResponse(w, host)
		}
		return
	}

	// Do MITM interception when we have a CA configured.
	//
	// Security note: This intercepts ALL HTTPS traffic, not just credential-injected hosts.
	// This is intentional for full observability - a core Moat feature. The container
	// trusts our CA (mounted at /etc/ssl/certs/moat-ca/) and we verify upstream certs.
	//
	// Applications with certificate pinning may fail. This is expected behavior since
	// observability requires seeing all traffic.
	if p.ca != nil {
		p.handleConnectWithInterception(w, r, host)
		return
	}

	// Without TLS interception, per-path rules cannot be enforced on HTTPS
	// traffic — only host-level allow/deny applies. Warn if rules exist.
	if p.hasPathRulesForHost(r, host, port) {
		slog.Warn("per-path rules configured but TLS interception disabled; only host-level rules apply",
			"subsystem", "proxy", "host", host)
	}

	p.handleConnectTunnel(w, r)
}

// connectTunnelDialTimeout bounds how long the proxy waits to connect to the
// upstream on behalf of a CONNECT request. An unreachable HostGatewayIP (e.g.
// daemon-version-skew sends an empty IP and the fallback resolves nowhere)
// would otherwise cause the container to stall indefinitely.
const connectTunnelDialTimeout = 10 * time.Second

func (p *Proxy) handleConnectTunnel(w http.ResponseWriter, r *http.Request) {
	// Rewrite synthetic host-gateway hostname to actual IP for dialing.
	dialAddr := r.Host
	if rc := getRunContext(r); rc != nil && rc.HostGatewayIP != "" {
		host, _, _ := net.SplitHostPort(r.Host)
		if isHostGateway(rc, host) {
			dialAddr = rewriteHostPort(r.Host, rc.HostGatewayIP)
		}
	}
	targetConn, err := net.DialTimeout("tcp", dialAddr, connectTunnelDialTimeout)
	if err != nil {
		http.Error(w, "moat proxy: dial upstream failed", http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		targetConn.Close()
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		targetConn.Close()
		return
	}

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	var closeOnce sync.Once
	closeConns := func() {
		closeOnce.Do(func() {
			clientConn.Close()
			targetConn.Close()
		})
	}

	go func() {
		_, _ = io.Copy(targetConn, clientConn)
		closeConns()
	}()
	go func() {
		_, _ = io.Copy(clientConn, targetConn)
		closeConns()
	}()
}

// Context keys for passing data between ReverseProxy hooks in the interception path.
type interceptCredResultKey struct{}
type interceptCredsKey struct{}
type interceptReqStartKey struct{}
type interceptLogURLKey struct{}
type interceptPreInjHeadersKey struct{}
type interceptReqBodyKey struct{}

func reqStartFromContext(ctx context.Context) time.Time {
	if t, ok := ctx.Value(interceptReqStartKey{}).(time.Time); ok {
		return t
	}
	return time.Now()
}

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
		resp.Header.Set("X-Moat-Blocked", "llm-policy")
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
		resp.Header.Set("X-Moat-Blocked", "llm-policy")
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
		resp.Header.Set("X-Moat-Blocked", "llm-policy")
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

	// Shared TLS config for upstream connections (both h2 and h1 paths).
	upstreamTLS := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    p.upstreamCAs,
	}

	// Build an upstream transport matching the negotiated protocol.
	// When the client negotiated h2 (e.g., gRPC), the request object is an
	// h2 request and cannot be round-tripped via an HTTP/1.1 transport
	// without framing errors, so we must forward upstream over h2 as well.
	//
	// Limitation: http2.Transport never falls back to HTTP/1.1, so if the
	// upstream only speaks HTTP/1.1 the connection will fail when the client
	// has negotiated h2. For gRPC this is always correct (gRPC requires h2);
	// for general h2 clients hitting h1-only upstreams it is a known
	// limitation of the current implementation.
	var transport http.RoundTripper
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	if tlsClientConn.ConnectionState().NegotiatedProtocol == http2.NextProtoTLS {
		transport = &http2.Transport{
			TLSClientConfig: upstreamTLS,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				if cfg == nil {
					cfg = upstreamTLS
				}
				return (&tls.Dialer{NetDialer: dialer, Config: cfg}).DialContext(ctx, network, addr)
			},
			ReadIdleTimeout: 30 * time.Second,
			PingTimeout:     15 * time.Second,
		}
	} else {
		transport = &http.Transport{
			Proxy:           nil,
			DialContext:     dialer.DialContext,
			TLSClientConfig: upstreamTLS,
			// Do NOT set ForceAttemptHTTP2: this path handles HTTP/1.1
			// requests. Enabling h2 upstream for h1 clients causes
			// framing mismatches.
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 5 * time.Minute,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
		}
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
			creds, _ := pr.Out.Context().Value(interceptCredsKey{}).([]credentialHeader)

			// Snapshot headers before credential injection so logs don't
			// contain raw credential values (CLAUDE.md: never log credential values).
			preInjectionHeaders := pr.Out.Header.Clone()

			credResult := injectCredentials(pr.Out, creds, host, pr.Out.Method, pr.Out.URL.Path)

			// Store credential result and pre-injection headers in context.
			ctx := pr.Out.Context()
			ctx = context.WithValue(ctx, interceptCredResultKey{}, credResult)
			ctx = context.WithValue(ctx, interceptPreInjHeadersKey{}, preInjectionHeaders)
			*pr.Out = *pr.Out.WithContext(ctx)

			// Extra headers.
			mergeExtraHeaders(pr.Out, r.Host, p.getExtraHeadersForRequest(r, r.Host))

			// Strip proxy headers.
			pr.Out.Header.Del("Proxy-Connection")
			pr.Out.Header.Del("Proxy-Authorization")

			// Remove configured headers (but not injected credential headers).
			// r.Host is the CONNECT target with its port, so port-pinned
			// host keys can match; the lookup falls back to the bare host.
			for _, headerName := range p.getRemoveHeadersForRequest(r, r.Host) {
				if credResult.InjectedHeaders[strings.ToLower(headerName)] {
					continue
				}
				pr.Out.Header.Del(headerName)
			}

			// Strip capture headers — they're metadata for the proxy, not the destination.
			// Skip headers that were just injected as credentials.
			for _, headerName := range p.captureHeaders {
				if credResult.InjectedHeaders[strings.ToLower(headerName)] {
					continue
				}
				pr.Out.Header.Del(headerName)
			}

			// Capture URL before token substitution so logs don't contain real tokens.
			logURL := pr.Out.URL.String()
			ctx = context.WithValue(pr.Out.Context(), interceptLogURLKey{}, logURL)
			*pr.Out = *pr.Out.WithContext(ctx)

			// Token substitution.
			if sub := p.getTokenSubstitutionForRequest(r, r.Host); sub != nil {
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

			// The destination rejected us: if the credential came from a cache,
			// drop it so the next request re-resolves rather than replaying a
			// credential the destination has already refused. Rewrite stored the
			// injection result, so this evicts only what was actually sent.
			if cr, ok := req.Context().Value(interceptCredResultKey{}).(credentialInjectionResult); ok {
				invalidateCredentialsOnAuthFailure(cr.Injected, resp.StatusCode)
			}

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
			w.Header().Set("X-Moat-Blocked", "request-rule")
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusProxyAuthRequired)
			fmt.Fprintf(w, "Moat: request blocked by network policy.\nHost: %s\nTo allow this request, update network.rules in moat.yaml.\n", host)
			return
		}

		// Keep HTTP policy check.
		if rc := getRunContext(r); rc != nil && rc.KeepEngines != nil {
			if eng, ok := rc.KeepEngines["http"]; ok {
				// httpDenial describes a fail-closed http-scope policy denial.
				// logMsg feeds the internal policy log only; clientHint is an
				// optional detail line shown to the client (left empty for
				// internal-only reasons). clientMsg fills the blank in
				// "Moat: request blocked <clientMsg>".
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
					w.Header().Set("X-Moat-Blocked", "keep-policy")
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusForbidden)
					msg := fmt.Sprintf("Moat: request blocked %s.\nHost: %s\n", d.clientMsg, host)
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
		creds, credErr := p.getCredentialsForRequest(r, req, r.Host)
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

		// Capture request body for logging before ReverseProxy consumes it.
		var reqBody []byte
		reqBody, req.Body = captureBody(req.Body, req.Header.Get("Content-Type"))

		// Propagate request ID so Rewrite preserves it (instead of generating a new one).
		req.Header.Set("X-Request-Id", innerReqID)

		// Pass resolved credentials, start time, and captured body to Rewrite via context.
		ctx := req.Context()
		ctx = context.WithValue(ctx, interceptReqStartKey{}, reqStart)
		ctx = context.WithValue(ctx, interceptCredsKey{}, creds)
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
