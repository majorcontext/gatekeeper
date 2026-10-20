package proxy

import (
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

// SetAuthToken sets the required authentication token for proxy access.
func (p *Proxy) SetAuthToken(token string) {
	p.authToken = token
}

// SetDelegateAuth makes ServeHTTP require a non-empty proxy auth password and
// leave its validation to credential resolvers. With authToken empty, no
// static check applies to the password; with authToken set, ServeHTTP still
// requires a presented password to equal it before any resolver runs.
//
// Delegation without an auth token would accept any non-empty password, so
// SetDelegateAuth(true) with no token returns an error, and ServeHTTP refuses
// every request until SetAuthToken supplies one.
func (p *Proxy) SetDelegateAuth(delegate bool) error {
	p.delegateAuth = delegate
	if delegate && p.authToken == "" {
		return errDelegateAuthNoToken
	}
	return nil
}

var errDelegateAuthNoToken = errors.New("delegate auth requires an auth token")

func validatePolicy(policy string) (string, error) {
	switch policy {
	case "":
		return "permissive", nil
	case "permissive", "strict":
		return policy, nil
	}
	return "", fmt.Errorf("network policy %q is not one of \"permissive\" or \"strict\"", policy)
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
	p.mu.Lock()
	p.upstreamCAs = pool
	transports := p.h2UpstreamTransports
	p.h2UpstreamTransports = nil
	p.mu.Unlock()
	for _, transport := range transports {
		// Existing tunnels retain their trust settings. Retired connections
		// still in use are reclaimed by the transport's timeout once idle.
		transport.CloseIdleConnections()
	}
}

// SetLogger sets the request logger.
func (p *Proxy) SetLogger(logger func(data RequestLogData)) {
	p.logger = logger
}

// SetPolicyLogger sets the policy decision logger.
func (p *Proxy) SetPolicyLogger(logger func(data PolicyLogData)) {
	p.policyLogger = logger
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
func (p *Proxy) SetCredentialStore(store interface {
	GetToken(provider string) (string, error)
}) {
	p.credStore = store
}

// SetContextResolver sets the per-run context resolver for multi-tenant proxy use.
// When set, the proxy can resolve auth tokens to per-run credential data.
func (p *Proxy) SetContextResolver(resolver func(token string) (*RunContextData, bool)) {
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
	p.setCredential(host, CredentialHeader{Name: headerName, Value: headerValue, Grant: grant})
}

// SetInsecureCredentialWithGrant is SetCredentialWithGrant for a credential
// that may also be injected into plain-HTTP requests.
func (p *Proxy) SetInsecureCredentialWithGrant(host, headerName, headerValue, grant string) {
	p.setCredential(host, CredentialHeader{Name: headerName, Value: headerValue, Grant: grant, AllowInsecure: true})
}

func (p *Proxy) setCredential(host string, entry CredentialHeader) {
	headerName, grant := entry.Name, entry.Grant
	if !isValidHost(host) {
		slog.Debug("ignoring invalid host for credential injection",
			"subsystem", "proxy",
			"host", host,
			"header", headerName)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
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
		slog.Warn("replacing existing credential resolver",
			"subsystem", "proxy",
			"host", host)
	}
	p.credentialResolvers[host] = []credentialResolverEntry{entry}
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
	p.extraHeaders[host] = append(p.extraHeaders[host], ExtraHeader{Name: headerName, Value: headerValue})
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
	p.tokenSubstitutions[host] = &TokenSubstitution{
		placeholder: placeholder,
		realToken:   realToken,
	}
}

// SetInsecureTokenSubstitution is SetTokenSubstitution for a substitution
// that may also apply to plain-HTTP requests.
func (p *Proxy) SetInsecureTokenSubstitution(host, placeholder, realToken string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokenSubstitutions[host] = &TokenSubstitution{
		placeholder:   placeholder,
		realToken:     realToken,
		AllowInsecure: true,
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
// policy must be "permissive" or "strict" (empty means permissive); any other
// value returns an error and changes nothing.
// allows is a list of host patterns like "api.example.com" or "*.example.com".
// grants is a list of grant names like "github" that will be expanded to host patterns.
func (p *Proxy) SetNetworkPolicy(policy string, allows []string, grants []string) error {
	policy, err := validatePolicy(policy)
	if err != nil {
		return err
	}
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
		grantHosts := getHostsForGrant(grant)
		for _, pattern := range grantHosts {
			p.allowedHosts = append(p.allowedHosts, parseHostPattern(pattern))
		}
	}
	return nil
}

// SetNetworkPolicyWithRules sets the network policy with per-host request rules.
// The allows list should include hosts from rules (the caller extracts them).
// checker evaluates per-request rules; pathChecker reports if path-level rules exist.
func (p *Proxy) SetNetworkPolicyWithRules(policy string, allows []string, grants []string, checker func(host string, port int, method, path string) bool, pathChecker func(host string, port int) bool) error {
	policy, err := validatePolicy(policy)
	if err != nil {
		return err
	}
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
		for _, pattern := range getHostsForGrant(grant) {
			p.allowedHosts = append(p.allowedHosts, parseHostPattern(pattern))
		}
	}
	return nil
}

// permissive reports whether the run allows hosts outside AllowedHosts. Any
// value other than "" or "permissive" is strict.
func (rc *RunContextData) permissive() bool {
	return rc.Policy == "" || rc.Policy == "permissive"
}

// SetMatchedCredentialResolver appends a resolver for host that applies only
// to requests matching m. Entries on one host are tried in registration
// order; the first match wins. SetCredentialResolver and
// SetCredentialResolverWithStripHeaders replace every entry on the host,
// including matched ones. A nil resolver or an empty match (no header, paths,
// or methods) is ignored.
func (p *Proxy) SetMatchedCredentialResolver(host string, m RequestMatch, resolver CredentialResolver, stripHeaders ...string) {
	if resolver == nil || (m.Header == "" && len(m.Paths) == 0 && len(m.Methods) == 0) {
		slog.Debug("ignoring nil resolver or empty match for matched credential resolver",
			"subsystem", "proxy",
			"host", host)
		return
	}
	if !isValidHost(host) {
		slog.Debug("ignoring invalid host for credential resolver",
			"subsystem", "proxy",
			"host", host)
		return
	}
	entry := credentialResolverEntry{resolve: resolver, stripHeaders: stripHeaders, declared: true, match: &m}
	p.mu.Lock()
	defer p.mu.Unlock()
	entries := p.credentialResolvers[host]
	if n := len(entries); n > 0 && entries[n-1].match == nil {
		// The unmatched entry stays last as the catch-all.
		entries = append(entries[:n-1:n-1], entry, entries[n-1])
	} else {
		entries = append(entries[:len(entries):len(entries)], entry)
	}
	p.credentialResolvers[host] = entries
}
