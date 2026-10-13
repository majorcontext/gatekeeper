package proxy

import (
	"context"
	"crypto/x509"
	"net/http"
	"sync"
	"time"

	keeplib "github.com/majorcontext/keep"
	"go.jetify.com/typeid"
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

// userIDFromContext extracts the user ID from a context, or empty string.
func userIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(userIDKey).(string); ok {
		return id
	}
	return ""
}

// ResponseTransformer transforms HTTP responses before body capture.
// Cast to *http.Request and *http.Response in the transformer implementation.
// Returns the modified response and true if transformed, or original and false.
type ResponseTransformer func(req, resp any) (any, bool)

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

	// AllowInsecure permits injecting the credential into a request to an
	// http:// MCP server. The default refuses the request.
	AllowInsecure bool
}

// httpTransport is a shared transport for non-CONNECT HTTP forwarding with
// sane timeout defaults. No client-level Timeout is set because the proxy may
// handle streaming responses. Typed as http.RoundTripper so tests can swap
// in a recording transport.
var httpTransport http.RoundTripper = &http.Transport{
	Proxy:                 nil,
	DialContext:           dialContext,
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

// PolicyLogData contains data for a policy denial event.
type PolicyLogData struct {
	RunID     string
	Scope     string
	Operation string
	Rule      string
	Message   string
	Ctx       context.Context // Request context (for OTel span extraction, may be nil)

	// NonBlocking marks an entry that policy noticed but did not stop.
	// Consumers alert and count on denials, so an observation reported as one
	// would page an operator for traffic nothing blocked.
	//
	// The sense is negative on purpose: the zero value is a denial. This struct
	// is built as a literal in several places, and a field defaulting to
	// "observation" would silently drop any denial whose author did not know to
	// set it — the failure is silence in an alerting path, which is strictly
	// worse than an extra warning. Getting it wrong now over-reports.
	NonBlocking bool
}

// CredentialHeader holds a header name and value for credential injection.
type CredentialHeader struct {
	Name  string // Header name (e.g., "Authorization", "x-api-key")
	Value string // Header value (e.g., "Bearer token", "sk-ant-...")
	Grant string // Grant name for logging (e.g., "github", "anthropic")

	// Invalidate, when non-nil, drops whatever cached state produced Value so
	// the next request re-resolves it. The proxy calls it when the destination
	// rejects the credential (401/403), or reports an exhausted allowance (429).
	// Sources are expected to rate-limit their own evictions: these statuses do
	// not reliably distinguish a stale credential from one that will resolve to
	// the same value again.
	// Nil for credentials with no cache behind them (e.g. static headers).
	Invalidate func()

	// AllowInsecure permits injecting this credential into a request whose
	// upstream scheme is http. The default refuses the request.
	AllowInsecure bool
}

// ExtraHeader holds an additional header to inject for a host.
type ExtraHeader struct {
	Name  string
	Value string
}

// TokenSubstitution maps a placeholder string to the real token for a host.
type TokenSubstitution struct {
	placeholder string
	realToken   string

	// AllowInsecure permits substituting the token into a request whose
	// upstream scheme is http. The default refuses the request.
	AllowInsecure bool
}

// NewTokenSubstitution creates a TokenSubstitution with the given placeholder and real token.
func NewTokenSubstitution(placeholder, realToken string) *TokenSubstitution {
	return &TokenSubstitution{placeholder: placeholder, realToken: realToken}
}

// ParseHostPattern is the exported wrapper for parseHostPattern.
func ParseHostPattern(pattern string) HostPattern {
	return parseHostPattern(pattern)
}

// MatchesHostPattern reports whether a host:port matches a parsed host pattern.
func MatchesHostPattern(pattern HostPattern, host string, port int) bool {
	return matchesPattern(pattern, host, port)
}

// RunContextData holds per-run credential data resolved by the context resolver.
// The host-keyed maps are read without synchronization on every request —
// including linear scans for wildcard and case-fold matching — so they must
// not be mutated after the RunContextData is registered with the proxy.
type RunContextData struct {
	RunID                string
	Credentials          map[string][]CredentialHeader
	credentialBundles    []credentialBundle
	ExtraHeaders         map[string][]ExtraHeader
	RemoveHeaders        map[string][]string
	TokenSubstitutions   map[string]*TokenSubstitution
	ResponseTransformers map[string][]ResponseTransformer
	MCPServers           []MCPServerConfig
	Policy               string
	AllowedHosts         []HostPattern
	RequestCheck         func(host string, port int, method, path string) bool
	PathRulesCheck       func(host string, port int) bool
	AWSHandler           http.Handler
	CredStore            interface {
		GetToken(provider string) (string, error)
	}
	KeepEngines       map[string]*keeplib.Engine
	HostGateway       string
	HostGatewayIP     string // actual IP to forward allowed host-gateway requests to
	AllowedHostPorts  []int
	postgresResolvers []postgresResolverEntry
}

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
type CredentialResolver func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]CredentialHeader, error)

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
	credentials          map[string][]CredentialHeader      // host -> credential headers
	credentialResolvers  map[string]credentialResolverEntry // host -> dynamic resolver + declared strip headers
	postgresResolvers    []postgresResolverEntry            // host pattern -> Postgres password resolver
	extraHeaders         map[string][]ExtraHeader           // host -> additional headers to inject
	responseTransformers map[string][]ResponseTransformer   // host -> response transformers
	mu                   sync.RWMutex
	ca                   *CA                                                   // Optional CA for TLS interception
	logger               func(data RequestLogData)                             // Optional request logger
	authToken            string                                                // Optional auth token required for proxy access
	delegateAuth         bool                                                  // When authToken is empty, require some non-empty password and delegate its validation to credential resolvers
	policy               string                                                // "permissive" or "strict"
	allowedHosts         []HostPattern                                         // parsed allow patterns for strict policy
	requestChecker       func(host string, port int, method, path string) bool // per-host request rules checker
	pathRulesChecker     func(host string, port int) bool                      // checks if host has path-level rules
	awsHandler           http.Handler                                          // Optional handler for AWS credential endpoint
	credStore            interface {
		GetToken(provider string) (string, error)
	}
	mcpServers         []MCPServerConfig
	removeHeaders      map[string][]string                        // host -> []headerName
	tokenSubstitutions map[string]*TokenSubstitution              // host -> substitution
	relays             map[string]string                          // name -> target URL for relay endpoints
	contextResolver    func(token string) (*RunContextData, bool) // optional per-run credential resolver
	policyLogger       func(data PolicyLogData)                   // optional policy decision logger
	upstreamCAs        *x509.CertPool                             // optional CA pool for upstream TLS verification
	captureHeaders     []string                                   // headers to capture in logs and strip before forwarding
	branding           Branding                                   // client-visible wording of blocks and errors

	h2UpstreamTransport *http.Transport

	conns connTracker
}

// NewProxy creates a new auth proxy.
func NewProxy() *Proxy {
	return &Proxy{
		credentials:          make(map[string][]CredentialHeader),
		credentialResolvers:  make(map[string]credentialResolverEntry),
		extraHeaders:         make(map[string][]ExtraHeader),
		responseTransformers: make(map[string][]ResponseTransformer),
		removeHeaders:        make(map[string][]string),
		tokenSubstitutions:   make(map[string]*TokenSubstitution),
		policy:               "permissive", // default to permissive
	}
}

// ResolveContext looks up per-run context data by auth token.
// Returns nil, false when no resolver is set or the token is not found.
func (p *Proxy) ResolveContext(token string) (*RunContextData, bool) {
	if p.contextResolver == nil {
		return nil, false
	}
	return p.contextResolver(token)
}
