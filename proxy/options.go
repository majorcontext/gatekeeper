package proxy

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"

	"golang.org/x/net/http/httpguts"
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

// SetCaptureRequestHeaders configures request headers to capture and strip.
func (p *Proxy) SetCaptureRequestHeaders(headers []string) error {
	if err := ValidateCaptureRequestHeaders(headers); err != nil {
		return err
	}
	p.captureRequestHeaders = headers
	return nil
}

// SetCaptureResponseHeaders configures response headers to capture in logs.
func (p *Proxy) SetCaptureResponseHeaders(headers []string) error {
	if err := ValidateCaptureResponseHeaders(headers); err != nil {
		return err
	}
	p.captureResponseHeaders = headers
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

func cloneCredentialHeader(credential CredentialHeader) CredentialHeader {
	if credential.Match != nil {
		match := *credential.Match
		match.Paths = slices.Clone(match.Paths)
		match.Methods = slices.Clone(match.Methods)
		credential.Match = &match
	}
	credential.AddHeaders = maps.Clone(credential.AddHeaders)
	credential.RemoveHeaders = slices.Clone(credential.RemoveHeaders)
	return credential
}

// ValidateRequestPolicy checks the credential's request matching and header transforms.
func (credential Credential) ValidateRequestPolicy() error {
	if credential.Postgres != nil && (credential.Match != nil || len(credential.AddHeaders) > 0 || len(credential.RemoveHeaders) > 0) {
		return fmt.Errorf("credentials: host %q grant %q: match and header transforms do not apply to postgres credentials", credential.Host, credential.Grant)
	}
	for _, header := range []string{credential.Header, credential.Name} {
		if header != "" && !httpguts.ValidHeaderFieldName(header) {
			return fmt.Errorf("credentials: host %q grant %q: invalid header name %q", credential.Host, credential.Grant, header)
		}
	}
	if credential.Match != nil {
		if credential.Match.Header == "" {
			return fmt.Errorf("credentials: host %q grant %q: match.header is required", credential.Host, credential.Grant)
		}
		if !httpguts.ValidHeaderFieldName(credential.Match.Header) {
			return fmt.Errorf("credentials: host %q grant %q: match.header %q is not a valid HTTP header name", credential.Host, credential.Grant, credential.Match.Header)
		}
		for _, path := range credential.Match.Paths {
			if !strings.HasPrefix(path, "/") {
				return fmt.Errorf("credentials: host %q grant %q: match.paths entry %q must start with \"/\"", credential.Host, credential.Grant, path)
			}
		}
		for _, method := range credential.Match.Methods {
			if method == "" || strings.IndexFunc(method, func(r rune) bool { return r < 'A' || r > 'Z' }) >= 0 {
				return fmt.Errorf("credentials: host %q grant %q: match.methods entry %q must be upper-case letters", credential.Host, credential.Grant, method)
			}
		}
	}
	seen := make(map[string]bool, len(credential.AddHeaders))
	for name, value := range credential.AddHeaders {
		for _, credentialHeader := range []string{credential.Header, credential.Name} {
			if credentialHeader != "" && strings.EqualFold(name, credentialHeader) {
				return fmt.Errorf("credentials: host %q grant %q: add_headers cannot target credential header %q", credential.Host, credential.Grant, credentialHeader)
			}
		}
		lower := strings.ToLower(name)
		if !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
			return fmt.Errorf("credentials: host %q grant %q: add_headers contains an invalid name or value", credential.Host, credential.Grant)
		}
		if seen[lower] {
			return fmt.Errorf("credentials: host %q grant %q: add_headers has duplicate header %q", credential.Host, credential.Grant, name)
		}
		seen[lower] = true
	}
	seen = make(map[string]bool, len(credential.RemoveHeaders))
	for _, name := range credential.RemoveHeaders {
		lower := strings.ToLower(name)
		if !httpguts.ValidHeaderFieldName(name) {
			return fmt.Errorf("credentials: host %q grant %q: remove_headers has invalid header %q", credential.Host, credential.Grant, name)
		}
		if seen[lower] {
			return fmt.Errorf("credentials: host %q grant %q: remove_headers has duplicate header %q", credential.Host, credential.Grant, name)
		}
		seen[lower] = true
	}
	if credential.Match != nil {
		if err := credential.ValidateAgainst(nil); err != nil {
			return err
		}
	}
	return nil
}

// ValidateAgainst rejects a credential whose request match is identical to or fully covered by an earlier match.
func (credential Credential) ValidateAgainst(earlier []Credential) error {
	if credential.Match == nil {
		return nil
	}
	for _, previous := range earlier {
		if previous.Match == nil || !strings.EqualFold(previous.Host, credential.Host) {
			continue
		}
		if previous.Match.Equal(*credential.Match) {
			return fmt.Errorf("credential match for host %q grant %q is identical to earlier grant %q", credential.Host, credential.Grant, previous.Grant)
		}
		if matchCovers(*previous.Match, *credential.Match) {
			return fmt.Errorf("credential match for host %q grant %q is covered by earlier grant %q", credential.Host, credential.Grant, previous.Grant)
		}
	}
	return nil
}

func matchCovers(earlier, later RequestMatch) bool {
	if !strings.EqualFold(earlier.Header, later.Header) {
		return false
	}
	if len(earlier.Paths) > 0 {
		if len(later.Paths) == 0 {
			return false
		}
		for _, laterPath := range later.Paths {
			if !slices.ContainsFunc(earlier.Paths, func(earlierPath string) bool { return strings.HasPrefix(laterPath, earlierPath) }) {
				return false
			}
		}
	}
	if len(earlier.Methods) > 0 {
		if len(later.Methods) == 0 {
			return false
		}
		for _, laterMethod := range later.Methods {
			if !slices.Contains(earlier.Methods, laterMethod) {
				return false
			}
		}
	}
	return true
}

func normalizeCredentialHeader(credential CredentialHeader) CredentialHeader {
	if credential.Name == "" {
		credential.Name = credential.Header
		if credential.Name == "" {
			credential.Name = "Authorization"
		}
	}
	if credential.Header == "" {
		credential.Header = credential.Name
	}
	return cloneCredentialHeader(credential)
}

func (p *Proxy) validateRegisteredCredentialLocked(credential Credential, allowUpdate bool) error {
	var earlier []Credential
	for hostKey, registered := range p.credentials {
		for _, previous := range registered {
			if allowUpdate && credential.Match != nil && previous.Match != nil && previous.Host == credential.Host && previous.Grant == credential.Grant && strings.EqualFold(previous.Name, credential.Name) && previous.Match.Equal(*credential.Match) {
				continue
			}
			if previous.Host == "" {
				previous.Host = hostKey
			}
			earlier = append(earlier, previous)
		}
	}
	for hostKey, entries := range p.credentialResolvers {
		replaceAt := -1
		if allowUpdate && hostKey == credential.Host && credential.Match != nil {
			for i, entry := range entries {
				if entry.credential == nil || entry.match == nil || entry.credential.Grant != credential.Grant || !strings.EqualFold(entry.credential.Name, credential.Name) || !entry.match.Equal(*credential.Match) {
					continue
				}
				if entry.credential.Resolver != nil {
					return errors.New("UpdateCredentialEntry cannot replace a resolver-backed credential")
				}
				replaceAt = i
				break
			}
		}
		for i, entry := range entries {
			if replaceAt >= 0 && i >= replaceAt {
				break
			}
			if entry.credential != nil {
				previous := *entry.credential
				if previous.Host == "" {
					previous.Host = hostKey
				}
				earlier = append(earlier, previous)
			} else if entry.match != nil {
				earlier = append(earlier, Credential{Host: hostKey, Match: entry.match})
			}
		}
	}
	return credential.ValidateAgainst(earlier)
}

// SetCredentialEntry registers a credential with optional request matching
// and header transforms.
func (p *Proxy) SetCredentialEntry(credential CredentialHeader) error {
	return p.registerCredential(credential, false)
}

// UpdateCredentialEntry replaces a registered static credential with the same
// host, grant, header, and match. It rejects resolver-backed credentials.
func (p *Proxy) UpdateCredentialEntry(credential CredentialHeader) error {
	return p.registerCredential(credential, true)
}

func (p *Proxy) registerCredential(credential CredentialHeader, allowUpdate bool) error {
	credential = normalizeCredentialHeader(credential)
	if err := credential.ValidateRequestPolicy(); err != nil {
		return err
	}
	host := credential.Host
	if credential.Resolver != nil {
		if allowUpdate {
			return errors.New("resolver credentials cannot be refreshed through UpdateCredentialEntry")
		}
		return p.SetCredentialResolverEntry(credential)
	}
	if credential.Match == nil {
		p.setCredential(host, credential)
		return nil
	}
	resolver := func(context.Context, *http.Request, *http.Request, string) ([]CredentialHeader, error) {
		return []CredentialHeader{credential}, nil
	}
	return p.registerMatchedCredential(credential, resolver, nil, allowUpdate)
}

func (p *Proxy) registerMatchedCredential(credential CredentialHeader, resolver CredentialResolver, stripHeaders []string, allowUpdate bool) error {
	if !isValidHost(credential.Host) {
		return fmt.Errorf("credential host %q is invalid", credential.Host)
	}
	match := *credential.Match
	entry := credentialResolverEntry{resolve: resolver, stripHeaders: slices.Clone(stripHeaders), declared: true, match: &match, credential: &credential}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.validateRegisteredCredentialLocked(credential, allowUpdate); err != nil {
		return err
	}
	entries := p.credentialResolvers[credential.Host]
	if allowUpdate {
		for i, existing := range entries {
			if existing.credential != nil && existing.match != nil && existing.credential.Grant == credential.Grant && strings.EqualFold(existing.credential.Name, credential.Name) && existing.match.Equal(match) {
				entries = slices.Clone(entries)
				entries[i] = entry
				p.credentialResolvers[credential.Host] = entries
				return nil
			}
		}
	}
	if n := len(entries); n > 0 && entries[n-1].match == nil {
		entries = append(entries[:n-1:n-1], entry, entries[n-1])
	} else {
		entries = append(entries[:len(entries):len(entries)], entry)
	}
	p.credentialResolvers[credential.Host] = entries
	return nil
}

// SetCredentialResolverEntry registers Credential.Resolver with the request policy.
func (p *Proxy) SetCredentialResolverEntry(credential CredentialHeader, stripHeaders ...string) error {
	resolver := credential.Resolver
	if resolver == nil {
		return errors.New("credential resolver is required")
	}
	credential = normalizeCredentialHeader(credential)
	if err := credential.ValidateRequestPolicy(); err != nil {
		return err
	}
	credential.Resolver = resolver
	resolver = credentialResolverWithPolicy(credential, resolver)
	host := credential.Host
	if credential.Match != nil {
		return p.registerMatchedCredential(credential, resolver, stripHeaders, false)
	}
	p.SetCredentialResolverWithStripHeaders(host, resolver, stripHeaders...)
	return nil
}

func credentialResolverWithPolicy(policy CredentialHeader, resolve CredentialResolver) CredentialResolver {
	return func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]CredentialHeader, error) {
		resolved, err := resolve(ctx, proxyReq, innerReq, host)
		resolved = slices.Clone(resolved)
		for i := range resolved {
			if resolved[i].Name == "" {
				resolved[i].Name = resolved[i].Header
			}
			if resolved[i].Header == "" {
				resolved[i].Header = resolved[i].Name
			}
			if policy.Name != "" {
				resolved[i].Name = policy.Name
			}
			if policy.Header != "" {
				resolved[i].Header = policy.Header
			}
			if policy.Grant != "" {
				resolved[i].Grant = policy.Grant
			}
			resolved[i].Match = policy.Match
			if policy.AddHeaders != nil {
				resolved[i].AddHeaders = policy.AddHeaders
			}
			if policy.RemoveHeaders != nil {
				resolved[i].RemoveHeaders = policy.RemoveHeaders
			}
			if policy.AllowInsecure {
				resolved[i].AllowInsecure = true
			}
			if err := resolved[i].ValidateRequestPolicy(); err != nil {
				return nil, err
			}
		}
		return resolved, err
	}
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
	if !validHostKey(host, "request header removal") {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.removeHeaders[host] = append(p.removeHeaders[host], headerName)
}

// SetTokenSubstitution replaces placeholder tokens with real tokens
// in both Authorization headers and request bodies for a specific host.
// host is a host pattern (see ValidateHostPattern), optionally pinned to a
// port; an invalid one is ignored and logged at debug level.
func (p *Proxy) SetTokenSubstitution(host, placeholder, realToken string) {
	if !validHostKey(host, "token substitution") {
		return
	}
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
	if !validHostKey(host, "token substitution") {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokenSubstitutions[host] = &TokenSubstitution{
		placeholder:   placeholder,
		realToken:     realToken,
		AllowInsecure: true,
	}
}

// validHostKey reports whether host is a valid host pattern for a host-keyed
// setter that accepts a port-pinned key. An invalid one is logged and refused.
func validHostKey(host, what string) bool {
	if err := ValidateHostPattern(host); err != nil {
		slog.Debug("ignoring invalid host for "+what, "subsystem", "proxy", "host", host, "error", err)
		return false
	}
	return true
}

// isValidHost checks if a host string is valid for credential injection.
// Returns false for empty strings, malformed host patterns, paths, or other
// invalid values. The credential setters that take no error ignore (and log)
// an invalid host; a caller that wants the reason calls ValidateHostPattern.
func isValidHost(host string) bool {
	if host == "" {
		return false
	}
	// Reject a malformed host pattern: a "*" other than the whole first label
	// or the end of it, an empty label, or a non-ASCII name.
	if ValidateHostPattern(host) != nil {
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
// policy must be "permissive" or "strict" (empty means permissive), and every
// entry of allows must pass ValidateHostPattern; otherwise it returns an error
// and changes nothing.
// allows is a list of host patterns like "api.example.com", "*.example.com" or
// "pr-*.example.com".
// grants is a list of grant names like "github" that will be expanded to host patterns.
func (p *Proxy) SetNetworkPolicy(policy string, allows []string, grants []string) error {
	policy, err := validatePolicy(policy)
	if err != nil {
		return err
	}
	if err := validateHostPatterns(allows); err != nil {
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
// The allows list should include hosts from rules (the caller extracts them),
// and each entry must pass ValidateHostPattern, as in SetNetworkPolicy.
// checker evaluates per-request rules; pathChecker reports if path-level rules exist.
func (p *Proxy) SetNetworkPolicyWithRules(policy string, allows []string, grants []string, checker func(host string, port int, method, path string) bool, pathChecker func(host string, port int) bool) error {
	policy, err := validatePolicy(policy)
	if err != nil {
		return err
	}
	if err := validateHostPatterns(allows); err != nil {
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

// validateHostPatterns returns the error of the first pattern that
// ValidateHostPattern rejects.
func validateHostPatterns(patterns []string) error {
	for _, pattern := range patterns {
		if err := ValidateHostPattern(pattern); err != nil {
			return err
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
		slog.Debug("ignoring nil resolver or empty match for matched credential resolver", "subsystem", "proxy", "host", host)
		return
	}
	if !isValidHost(host) {
		slog.Debug("ignoring invalid host for credential resolver", "subsystem", "proxy", "host", host)
		return
	}
	p.addMatchedCredentialResolver(host, m, resolver, stripHeaders, nil)
}

func (p *Proxy) addMatchedCredentialResolver(host string, match RequestMatch, resolver CredentialResolver, stripHeaders []string, credential *CredentialHeader) {
	if resolver == nil || (match.Header == "" && len(match.Paths) == 0 && len(match.Methods) == 0) || !isValidHost(host) {
		return
	}
	match.Paths = slices.Clone(match.Paths)
	match.Methods = slices.Clone(match.Methods)
	entry := credentialResolverEntry{
		resolve:      resolver,
		stripHeaders: slices.Clone(stripHeaders),
		declared:     true,
		match:        &match,
		credential:   credential,
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	entries := p.credentialResolvers[host]
	if credential != nil && credential.Resolver == nil {
		for i := range entries {
			existing := entries[i]
			if existing.credential != nil && existing.credential.Resolver == nil && existing.match != nil && existing.credential.Grant == credential.Grant && strings.EqualFold(existing.credential.Name, credential.Name) && existing.match.Equal(match) {
				entries = slices.Clone(entries)
				entries[i] = entry
				p.credentialResolvers[host] = entries
				return
			}
		}
	}
	if n := len(entries); n > 0 && entries[n-1].match == nil {
		entries = append(entries[:n-1:n-1], entry, entries[n-1])
	} else {
		entries = append(entries[:len(entries):len(entries)], entry)
	}
	p.credentialResolvers[host] = entries
}
