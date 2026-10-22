package proxy

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
)

// getTokenSubstitution returns the token substitution for a host.
func (p *Proxy) getTokenSubstitution(host string) *TokenSubstitution {
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
func (p *Proxy) applyTokenSubstitution(req *http.Request, sub *TokenSubstitution) {
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

// refusesCleartextInjection reports whether forwarding the request over scheme http
// would inject a secret that was not marked AllowInsecure.
func (p *Proxy) refusesCleartextInjection(in *http.Request, scheme, lookupHost string, creds []CredentialHeader) bool {
	if !strings.EqualFold(scheme, "http") {
		return false
	}
	for _, c := range creds {
		if !c.AllowInsecure {
			return true
		}
	}
	sub := p.getTokenSubstitutionForRequest(in, lookupHost)
	return sub != nil && !sub.AllowInsecure
}

func (p *Proxy) cleartextRefusalMessage(host string) string {
	return p.brandName() + ": credential injection over plain HTTP is refused for host " + host +
		". Use https, or set allow_insecure on the credential.\n"
}

func (p *Proxy) writeCleartextRefusal(w http.ResponseWriter, host string) {
	slog.Warn("credential injection over plain HTTP refused",
		"subsystem", "proxy",
		"action", "refuse-cleartext",
		"host", host)
	setBlocked(w.Header(), "cleartext-credential")
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(p.cleartextRefusalMessage(host)))
}

type outboundPrep struct {
	creds      []CredentialHeader
	bundle     credentialInjectionResult
	host       string
	lookupHost string
	path       string
}

// prepareOutbound turns a copied client request into the request sent
// upstream. Bundles must already be applied; o.bundle is their result.
// Substitution targets out, so logs built from in keep the placeholder.
func (p *Proxy) prepareOutbound(in, out *http.Request, o outboundPrep) credentialInjectionResult {
	credResult := mergeCredentialInjectionResults(o.bundle, injectCredentials(out, o.creds, o.host, out.Method, o.path, o.bundle.InjectedHeaders))
	legacyPolicy := p.legacyCredentialPolicy(in, o.lookupHost, out.Header, credResult.InjectedHeaders)
	applyCredentialTransforms(out, legacyPolicy, credResult.InjectedHeaders)
	for _, credential := range credResult.Injected {
		applyCredentialTransforms(out, credential, credResult.InjectedHeaders)
	}

	out.Header.Del("Proxy-Connection")
	out.Header.Del("Proxy-Authorization")
	for _, headerName := range p.captureRequestHeaders {
		if !credResult.InjectedHeaders[strings.ToLower(headerName)] {
			out.Header.Del(headerName)
		}
	}
	if sub := p.getTokenSubstitutionForRequest(in, o.lookupHost); sub != nil {
		p.applyTokenSubstitution(out, sub)
	}
	return credResult
}

func applyCredentialTransforms(req *http.Request, credential CredentialHeader, injectedHeaders map[string]bool) {
	for _, header := range credential.RemoveHeaders {
		if !injectedHeaders[strings.ToLower(header)] {
			req.Header.Del(header)
		}
	}
	for _, header := range sortedHeaderNames(credential.SetHeaders) {
		req.Header.Set(header, credential.SetHeaders[header])
	}
}

func (p *Proxy) legacyCredentialPolicy(r *http.Request, host string, headers http.Header, injectedHeaders map[string]bool) CredentialHeader {
	policy := CredentialHeader{RemoveHeaders: p.getRemoveHeadersForRequest(r, host)}
	extraHeaders := p.getExtraHeadersForRequest(r, host)
	if len(extraHeaders) == 0 {
		return policy
	}
	merged := headers.Clone()
	policy.SetHeaders = make(map[string]string, len(extraHeaders))
	for _, header := range extraHeaders {
		if existing := merged.Get(header.Name); existing != "" {
			merged.Set(header.Name, existing+","+header.Value)
		} else {
			merged.Set(header.Name, header.Value)
		}
		policy.SetHeaders[http.CanonicalHeaderKey(header.Name)] = merged.Get(header.Name)
	}
	for name := range policy.SetHeaders {
		if !injectedHeaders[strings.ToLower(name)] && slices.ContainsFunc(policy.RemoveHeaders, func(header string) bool { return strings.EqualFold(header, name) }) {
			delete(policy.SetHeaders, name)
		}
	}
	slog.Debug("extra headers injected",
		"subsystem", "proxy",
		"action", "inject-extra",
		"host", host,
		"count", len(extraHeaders))
	return policy
}

func sortedHeaderNames(headers map[string]string) []string {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// getCredentials returns all credential headers for a host; see
// lookupHostKeyed for the matching rules.
func (p *Proxy) getCredentials(host string) []CredentialHeader {
	creds, _ := p.getCredentialsMatch(host)
	return creds
}

// getCredentialsMatch is getCredentials plus the match rank, for callers
// that weigh exact static credentials against wildcard-keyed resolvers.
// Returns a copy of the slice to avoid data races with concurrent
// SetCredentialWithGrant calls (e.g., token refresh).
func (p *Proxy) getCredentialsMatch(host string) ([]CredentialHeader, hostMatch) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	creds, match := lookupHostKeyed(p.credentials, host, nonEmptySlice)
	if len(creds) == 0 {
		return nil, hostMatch{}
	}
	out := make([]CredentialHeader, len(creds))
	copy(out, creds)
	return out, match
}

// credentialResolverEntry holds a credential resolver and its request policy.
// A nil resolver is an explicit opt-out that terminates the lookup.
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
	// match restricts the entry to requests it matches; nil matches every
	// request. An unmatched entry is always the last of its host's entries.
	match      *RequestMatch
	credential *CredentialHeader
}

// getCredentialResolver returns the first dynamic resolver for a host; see
// lookupHostKeyed for the matching rules.
func (p *Proxy) getCredentialResolver(host string) CredentialResolver {
	entries, _ := p.getCredentialResolverMatch(host)
	if len(entries) == 0 {
		return nil
	}
	return entries[0].resolve
}

// getCredentialResolverMatch returns the resolver entries for a host, in
// selection order, plus the match rank. The lookup is presence-based:
// SetCredentialResolver(host, nil) plants a nil entry that matches and
// terminates the lookup, disabling resolution for that host even when a
// broader (bare-host or wildcard) resolver exists — the same opt-out
// semantics as the companion maps.
func (p *Proxy) getCredentialResolverMatch(host string) ([]credentialResolverEntry, hostMatch) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return lookupHostKeyed(p.credentialResolvers, host, presenceUsable)
}

func (p *Proxy) getCredentialResolverEntriesForRequest(host string, req *http.Request, path string) ([]credentialResolverEntry, hostMatch, int, []credentialResolverEntry) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return selectRequestCredentialEntries(p.credentialResolvers, host, req, path, func(entry credentialResolverEntry) *RequestMatch { return entry.match })
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
	Injected []CredentialHeader
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
func injectCredentials(req *http.Request, creds []CredentialHeader, host, method, path string, reserved map[string]bool) credentialInjectionResult {
	if len(creds) == 0 {
		return credentialInjectionResult{}
	}

	// Sample the client's headers before any injection mutates them.
	//
	// A reserved header belongs to a credential bundle that has already written
	// its value here, so it is skipped entirely: the sample would read the
	// bundle's own value as if the client had sent it, and the winner would
	// overwrite an atomic replacement with one half of something else.
	clientSent := make(map[string]bool, len(creds))
	for _, c := range creds {
		key := strings.ToLower(c.Name)
		if reserved[key] {
			continue
		}
		if req.Header.Get(c.Name) != "" {
			clientSent[key] = true
		}
	}

	// selectWinners maps each eligible header name to the index of the single
	// credential that will be injected for it. Iterating creds in order makes
	// the choice independent of map iteration order.
	selectWinners := func(eligible func(headerKey string) bool, preferClaude bool) map[string]int {
		winners := make(map[string]int, len(creds))
		for i, c := range creds {
			key := strings.ToLower(c.Name)
			if reserved[key] || !eligible(key) {
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
	// Auto-injection is the "client asked for nothing, so give it everything"
	// fallback. A bundle replacement is itself a placeholder the client sent,
	// so a request that matched one did ask for something and must not trigger
	// it — otherwise reserving the bundle's header would start auto-injecting
	// the host's other credentials.
	autoInjected := len(winners) == 0 && len(reserved) == 0
	if autoInjected {
		winners = selectWinners(func(key string) bool { return !reserved[key] }, false)
	}

	injected := make(map[string]bool, len(winners))
	grants := make([]string, 0, len(winners))
	injectedCreds := make([]CredentialHeader, 0, len(winners))

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

// getExtraHeaders returns additional headers to inject for a host.
func (p *Proxy) getExtraHeaders(host string) []ExtraHeader {
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
// rank the resolver's credentials win the headers it answers, and
// withRequestedStatics merges in static credentials on other headers that
// the client asked for by name; if the resolver returns nil (e.g., no
// subject identity found), the proxy falls through to static credentials
// for the same host. This enables patterns like "per-user OAuth via
// token-exchange, with a bot identity fallback." A resolver that returns
// *ResolverDeclined falls through the same way, and the result carries the
// decline for settleUpstreamResponse.
//
// ctxReq carries the RunContextData (the CONNECT request for intercepted
// connections, or the same request for plain HTTP). innerReq is the actual
// request the resolver may inspect and modify. path is what resolver entry
// matches are tested against.
//
// A host may carry several resolver entries; the first whose match accepts
// the request is used, and a request that none accepts is handled as if the
// host had no resolver. A chosen entry that selected the request by a client
// header and whose credentials do not answer that header has the header
// removed, so the selecting placeholder never reaches upstream.
func (p *Proxy) getCredentialsForRequest(ctxReq, innerReq *http.Request, host, path string) (resolvedCredentials, error) {
	if rc := getRunContext(ctxReq); rc != nil {
		return p.resolveRunContextCredentials(ctxReq, innerReq, host, path, rc)
	}
	entries, resolverMatch, selected, skipped := p.getCredentialResolverEntriesForRequest(host, innerReq, path)
	allEntries := append(skipped, entries...)
	entry := credentialResolverEntry{}
	if selected >= 0 {
		entry = entries[selected]
	}
	if entry.resolve == nil {
		// No rule applies, so no resolver runs; the headers every declared
		// rule consumes must still not reach upstream.
		stripDeclared(innerReq, allEntries, nil)
		return resolvedCredentials{creds: p.getCredentials(host)}, nil
	}
	// Whichever rule is chosen, the subject headers of every rule on the host
	// are removed once the chosen resolver has had its chance to read its own.
	// The chosen entry's own headers are left to its resolver: it may set one
	// itself, and the proxy removes only what the client sent.
	finish := func(res resolvedCredentials) resolvedCredentials {
		stripDeclared(innerReq, allEntries, entry.stripHeaders)
		return entry.stripSelector(innerReq, res)
	}
	if staticCreds, staticMatch := p.getCredentialsMatch(host); staticMatch.outranks(resolverMatch) {
		if entry.declared {
			// A better-matched static credential decides this request, so
			// the resolver's external round trip must not stall it. The
			// resolver is skipped; the request headers declared at
			// registration are removed here so they never leak upstream.
			stripDeclared(innerReq, allEntries, nil)
			return entry.stripSelector(innerReq, resolvedCredentials{creds: staticCreds}), nil
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
		return finish(resolvedCredentials{creds: p.getCredentials(host)}), nil
	}
	// A resolver is handed innerReq and may mutate it, so which headers the
	// client sent is only knowable before it runs.
	sentBefore := make(map[string]bool, len(innerReq.Header))
	for name := range innerReq.Header {
		if innerReq.Header.Get(name) != "" {
			sentBefore[strings.ToLower(name)] = true
		}
	}

	resolved, resolveErr := entry.resolve(innerReq.Context(), ctxReq, innerReq, host)
	var declined *ResolverDeclined
	if errors.As(resolveErr, &declined) {
		statics := p.getCredentials(host)
		if declined.ExplicitOnly {
			statics = namedByClient(sentBefore, innerReq, statics)
			if len(statics) == 0 {
				return resolvedCredentials{}, &CredentialRequiredError{Grant: declined.Grant, Host: host, Reason: declined.Reason}
			}
		}
		return finish(resolvedCredentials{creds: statics, declined: declined}), nil
	}
	if resolveErr != nil {
		return resolvedCredentials{}, resolveErr
	}
	if len(resolved) > 0 {
		if entry.match != nil {
			// The selecting header chose the rule; it must not also request a
			// same-name static credential.
			delete(sentBefore, strings.ToLower(entry.match.Header))
		}
		// Read static credentials after the resolver has run, not before: a
		// token refresh landing while a slow resolver was out must be seen.
		if entry.credential != nil {
			return finish(resolvedCredentials{creds: resolved}), nil
		}
		return finish(resolvedCredentials{creds: withRequestedStatics(sentBefore, innerReq, resolved, p.getCredentials(host))}), nil
	}
	return finish(resolvedCredentials{creds: p.getCredentials(host)}), nil
}

func validateRunContextCredentialMatches(credentials map[string][]CredentialHeader) error {
	for host, entries := range credentials {
		var earlier []Credential
		for _, entry := range entries {
			entry.Host = host
			if err := entry.ValidateRequestPolicy(); err != nil {
				return err
			}
			if err := entry.ValidateAgainst(earlier); err != nil {
				return err
			}
			earlier = append(earlier, entry)
		}
	}
	return nil
}

func (p *Proxy) resolveRunContextCredentials(ctxReq, innerReq *http.Request, host, path string, rc *RunContextData) (resolvedCredentials, error) {
	if err := validateRunContextCredentialMatches(rc.Credentials); err != nil {
		return resolvedCredentials{}, err
	}
	entries, _, selected, skipped := selectRequestCredentialEntries(rc.Credentials, host, innerReq, path, func(credential CredentialHeader) *RequestMatch { return credential.Match })
	if selected < 0 {
		stripRunContextSubjectHeaders(innerReq, skipped, "")
		return resolvedCredentials{}, nil
	}
	credential := entries[selected]
	if credential.Name == "" {
		credential.Name = credential.Header
		if credential.Name == "" {
			credential.Name = "Authorization"
		}
	}
	if credential.Header == "" {
		credential.Header = credential.Name
	}
	matched := credential.Match != nil
	if matched {
		if err := credential.ValidateRequestPolicy(); err != nil {
			return resolvedCredentials{}, err
		}
	} else {
		for _, entry := range entries {
			if entry.Match == nil {
				if err := entry.ValidateRequestPolicy(); err != nil {
					return resolvedCredentials{}, err
				}
			}
		}
	}
	subjectEntries := append(skipped, entries...)
	finish := func(result resolvedCredentials) resolvedCredentials {
		keep := ""
		if credential.Resolver != nil {
			keep = credential.Source.SubjectHeader
		}
		stripRunContextSubjectHeaders(innerReq, subjectEntries, keep)
		if matched {
			stripCredentialSelector(innerReq, credential, result.creds)
		}
		return result
	}
	statics := unmatchedRunContextCredentials(rc.Credentials, host)
	if !matched {
		statics = staticRunContextCredentials(entries)
	}
	if credential.Resolver == nil {
		if matched {
			return finish(resolvedCredentials{creds: []CredentialHeader{credential}}), nil
		}
		return finish(resolvedCredentials{creds: statics}), nil
	}
	sentBefore := sentHeaders(innerReq)
	resolver := credentialResolverWithPolicy(credential, credential.Resolver)
	resolved, err := resolver(innerReq.Context(), ctxReq, innerReq, host)
	var declined *ResolverDeclined
	if errors.As(err, &declined) {
		fallback, fallbackErr := runContextCredentialFallback(innerReq, credential, statics, sentBefore, declined)
		return finish(fallback), fallbackErr
	}
	if err != nil {
		return resolvedCredentials{}, err
	}
	if len(resolved) == 0 {
		if credential.Source.StaticFallback == "explicit" {
			declined = &ResolverDeclined{ExplicitOnly: true, Grant: credential.Grant}
			fallback, fallbackErr := runContextCredentialFallback(innerReq, credential, statics, sentBefore, declined)
			return finish(fallback), fallbackErr
		}
		return finish(resolvedCredentials{creds: statics}), nil
	}
	if matched {
		return finish(resolvedCredentials{creds: resolved}), nil
	}
	return finish(resolvedCredentials{creds: withRequestedStatics(sentBefore, innerReq, resolved, statics)}), nil
}

func runContextCredentialFallback(req *http.Request, credential CredentialHeader, statics []CredentialHeader, sentBefore map[string]bool, declined *ResolverDeclined) (resolvedCredentials, error) {
	if declined.ExplicitOnly {
		statics = namedByClient(sentBefore, req, statics)
		if len(statics) == 0 {
			return resolvedCredentials{}, &CredentialRequiredError{Grant: declined.Grant, Host: credential.Host, Reason: declined.Reason}
		}
	}
	return resolvedCredentials{creds: statics, declined: declined}, nil
}

func unmatchedRunContextCredentials(credentials map[string][]CredentialHeader, host string) []CredentialHeader {
	entries, _ := lookupHostKeyed(credentials, host, func(entries []CredentialHeader) bool {
		return len(staticRunContextCredentials(entries)) > 0
	})
	return staticRunContextCredentials(entries)
}

func staticRunContextCredentials(entries []CredentialHeader) []CredentialHeader {
	var statics []CredentialHeader
	for _, credential := range entries {
		if credential.Match == nil && credential.Resolver == nil {
			if credential.Name == "" {
				credential.Name = credential.Header
				if credential.Name == "" {
					credential.Name = "Authorization"
				}
			}
			statics = append(statics, credential)
		}
	}
	return statics
}

func stripRunContextSubjectHeaders(req *http.Request, credentials []CredentialHeader, keep string) {
	for _, credential := range credentials {
		header := credential.Source.SubjectHeader
		if credential.Source.Type == "token-exchange" && header != "" && !strings.EqualFold(header, keep) {
			req.Header.Del(header)
		}
	}
}

func sentHeaders(req *http.Request) map[string]bool {
	sent := make(map[string]bool, len(req.Header))
	for name := range req.Header {
		if req.Header.Get(name) != "" {
			sent[strings.ToLower(name)] = true
		}
	}
	return sent
}

func stripCredentialSelector(req *http.Request, credential CredentialHeader, resolved []CredentialHeader) {
	if credential.Match != nil && !answersHeader(resolved, credential.Match.Header) {
		req.Header.Del(credential.Match.Header)
	}
}

// stripDeclared removes the request headers every entry declared for removal,
// except those named in keep.
func stripDeclared(req *http.Request, entries []credentialResolverEntry, keep []string) {
	for _, e := range entries {
		for _, h := range e.stripHeaders {
			if !slices.ContainsFunc(keep, func(k string) bool { return strings.EqualFold(k, h) }) {
				req.Header.Del(h)
			}
		}
	}
}

// stripSelector removes the header the entry's match selected the request by,
// unless a final credential answers that header, so the client's placeholder
// never reaches upstream. It returns res unchanged.
func (e credentialResolverEntry) stripSelector(req *http.Request, res resolvedCredentials) resolvedCredentials {
	if e.match != nil && e.match.Header != "" && !answersHeader(res.creds, e.match.Header) {
		req.Header.Del(e.match.Header)
	}
	return res
}

// answersHeader reports whether any credential targets the named header.
func answersHeader(creds []CredentialHeader, name string) bool {
	for _, c := range creds {
		if strings.EqualFold(c.Name, name) {
			return true
		}
	}
	return false
}

// getCredentialBundlesForRequest returns the caller's credential bundles.
//
// Unlike credentials, bundles are not keyed by host: each one carries its own
// scope and injectCredentialBundles matches the request against it, so there is
// nothing to look up here.
func (p *Proxy) getCredentialBundlesForRequest(ctxReq *http.Request) []credentialBundle {
	if rc := getRunContext(ctxReq); rc != nil {
		bundles := append([]credentialBundle(nil), rc.credentialBundles...)
		return append(bundles, rc.CredentialBundles...)
	}
	return nil
}

// withRequestedStatics appends the static credentials the client asked for by
// sending their header, and that the resolver did not answer for.
//
// Scoped to headers the client actually sent, because injectCredentials falls
// back to auto-injecting every credential it is given when a request carries
// none of their headers. Merging unconditionally would let that fallback
// attach a resolver's per-user token — a Claude Code subscription, say — to a
// request that never asked for it. A request carrying neither header still
// sees only the resolver's credential, exactly as before.
//
// A static credential sharing the resolver's header stays dropped: on
// api.github.com the token exchange and the GitHub App key both target
// Authorization, and the exchange must keep winning it.
//
// A header counts as asked for only if the client sent it AND the resolver left
// it in place. Both halves matter, because a resolver is given the request to
// mutate: one that strips a header would otherwise leave injectCredentials no
// client header to select on, sending it down the auto-inject path with both
// credentials attached, and one that sets a header would otherwise merge a
// static credential the client never asked for. Either way the request ends up
// carrying a credential nobody requested.
func withRequestedStatics(sentBefore map[string]bool, req *http.Request, resolved, static []CredentialHeader) []CredentialHeader {
	if len(static) == 0 {
		return resolved
	}
	answered := make(map[string]bool, len(resolved))
	for _, c := range resolved {
		answered[strings.ToLower(c.Name)] = true
	}
	merged := resolved
	for _, c := range static {
		if answered[strings.ToLower(c.Name)] || !sentBefore[strings.ToLower(c.Name)] || req.Header.Get(c.Name) == "" {
			continue
		}
		if len(merged) == len(resolved) {
			// Copy before the first append so a resolver's slice is never
			// extended in place; callers may retain it.
			merged = append(append(make([]CredentialHeader, 0, len(resolved)+len(static)), resolved...), c)
			continue
		}
		merged = append(merged, c)
	}
	return merged
}

// invalidateCredentialsOnCredentialFailure drops the cached state behind each
// credential that was injected into the rejected request. Pass
// credentialInjectionResult.Injected, never the full candidate list for the
// host: only one credential wins when several share a header name, and evicting
// the losers would drop cache entries that had no part in this request — and,
// since sources rate-limit evictions per key, could suppress a loser's own
// legitimate eviction later.
//
// A request carrying several placeholders injects one credential per header,
// so a single rejection evicts all of them — a resolver's token included, when
// a static key may have been the one revoked. Upstream does not say which
// credential it rejected, and leaving a genuinely bad one cached costs more
// than one extra resolve.
//
// A 401, 403, or 429 is a signal that a credential resolved from a cache may
// have gone stale. A 401/403 says the destination rejected it; a 429 can mean
// the selected backing account exhausted its allowance and a subsequent resolve
// may select a different account. Without eviction, the proxy keeps injecting
// the cached credential until it expires on its own.
//
// This is deliberately evict-only: the failed request is not retried. Its body
// has already been consumed by the time the response arrives, and the requests
// that surface this (a git push, say) are not idempotent. The next request
// re-resolves and succeeds.
//
// Statuses other than 401/403/429 are left alone; a 5xx says nothing about the
// credential. Sources rate-limit their own evictions, since these statuses also
// cover cases where resolving again will return the same credential.
func invalidateCredentialsOnCredentialFailure(creds []CredentialHeader, statusCode int) {
	if !isCredentialFailure(statusCode) {
		return
	}
	for _, cred := range creds {
		if cred.Invalidate != nil {
			cred.Invalidate()
		}
	}
}

// namedByClient returns the credentials whose header the client sent and the
// resolver left in place: a header the resolver consumed named nothing.
func namedByClient(sentBefore map[string]bool, req *http.Request, creds []CredentialHeader) []CredentialHeader {
	var out []CredentialHeader
	for _, c := range creds {
		if sentBefore[strings.ToLower(c.Name)] && req.Header.Get(c.Name) != "" {
			out = append(out, c)
		}
	}
	return out
}

func isCredentialFailure(statusCode int) bool {
	return statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden || statusCode == http.StatusTooManyRequests
}

// getExtraHeadersForRequest returns extra headers for a host, checking
// RunContextData first, then falling back to the proxy's own map.
func (p *Proxy) getExtraHeadersForRequest(r *http.Request, host string) []ExtraHeader {
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
func (p *Proxy) getTokenSubstitutionForRequest(r *http.Request, host string) *TokenSubstitution {
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
