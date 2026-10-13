package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

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

// refusesCleartextInjection reports whether forwarding the request over scheme http
// would inject a secret that was not marked AllowInsecure.
func (p *Proxy) refusesCleartextInjection(in *http.Request, scheme, lookupHost string, creds []credentialHeader) bool {
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

func cleartextRefusalMessage(host string) string {
	return "gatekeeper: credential injection over plain HTTP is refused for host " + host +
		". Use https, or set allow_insecure on the credential.\n"
}

func (p *Proxy) writeCleartextRefusal(w http.ResponseWriter, host string) {
	slog.Warn("credential injection over plain HTTP refused",
		"subsystem", "proxy",
		"action", "refuse-cleartext",
		"host", host)
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(cleartextRefusalMessage(host)))
}

type outboundPrep struct {
	creds      []credentialHeader
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
	mergeExtraHeaders(out, o.lookupHost, p.getExtraHeadersForRequest(in, o.lookupHost))

	out.Header.Del("Proxy-Connection")
	out.Header.Del("Proxy-Authorization")

	// A header the proxy just injected survives removal: "claude" registers
	// RemoveRequestHeader("x-api-key") for OAuth, but if "anthropic" also
	// injected x-api-key on the same host, that value must reach upstream.
	for _, headerName := range p.getRemoveHeadersForRequest(in, o.lookupHost) {
		if credResult.InjectedHeaders[strings.ToLower(headerName)] {
			continue
		}
		out.Header.Del(headerName)
	}
	for _, headerName := range p.captureHeaders {
		if credResult.InjectedHeaders[strings.ToLower(headerName)] {
			continue
		}
		out.Header.Del(headerName)
	}
	if sub := p.getTokenSubstitutionForRequest(in, o.lookupHost); sub != nil {
		p.applyTokenSubstitution(out, sub)
	}
	return credResult
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

// matchWildcardHostKey reports whether a wildcard key like "*.example.com"
// matches the pre-lowercased host or port-stripped bare host. It mirrors
// hostHasSuffixFold; change them together. A key with a port matches host:port
// exactly.
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
func injectCredentials(req *http.Request, creds []credentialHeader, host, method, path string, reserved map[string]bool) credentialInjectionResult {
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
// token-exchange, with a bot identity fallback."
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
	// A resolver is handed innerReq and may mutate it, so which headers the
	// client sent is only knowable before it runs.
	sentBefore := make(map[string]bool, len(innerReq.Header))
	for name := range innerReq.Header {
		if innerReq.Header.Get(name) != "" {
			sentBefore[strings.ToLower(name)] = true
		}
	}

	resolved, resolveErr := entry.resolve(innerReq.Context(), ctxReq, innerReq, host)
	if resolveErr != nil {
		return nil, resolveErr
	}
	if len(resolved) > 0 {
		// Read static credentials after the resolver has run, not before: a
		// token refresh landing while a slow resolver was out must be seen.
		return withRequestedStatics(sentBefore, innerReq, resolved, p.getCredentials(host)), nil
	}
	return p.getCredentials(host), nil
}

// getCredentialBundlesForRequest returns the caller's credential bundles.
//
// Unlike credentials, bundles are not keyed by host: each one carries its own
// scope and injectCredentialBundles matches the request against it, so there is
// nothing to look up here.
func (p *Proxy) getCredentialBundlesForRequest(ctxReq *http.Request) []CredentialBundle {
	if rc := getRunContext(ctxReq); rc != nil {
		return rc.CredentialBundles
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
func withRequestedStatics(sentBefore map[string]bool, req *http.Request, resolved, static []credentialHeader) []credentialHeader {
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
			merged = append(append(make([]credentialHeader, 0, len(resolved)+len(static)), resolved...), c)
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
func invalidateCredentialsOnCredentialFailure(creds []credentialHeader, statusCode int) {
	if statusCode != http.StatusUnauthorized && statusCode != http.StatusForbidden && statusCode != http.StatusTooManyRequests {
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
