package proxy

import (
	"net"
	"net/http"
	"net/url"
	pathpkg "path"
	"strings"
)

// HeaderReplacement describes one exact placeholder-to-secret replacement.
// A bundle is validated in full before any replacement is applied.
type HeaderReplacement struct {
	Name        string
	Placeholder string
	Value       string
}

// CredentialScope limits where a credential bundle may be injected.
type CredentialScope struct {
	RequireTLS   bool
	Origins      []string
	Methods      []string
	PathPrefixes []string
}

// CredentialBundle groups headers that must be selected and replaced as one
// atomic credential. It is intended for protocols whose identity consists of
// more than one header, such as an OAuth access token plus account identifier.
type CredentialBundle struct {
	ID           string
	Grant        string
	Scope        CredentialScope
	Replacements []HeaderReplacement
	RequireAll   bool
}

type credentialBundleInjectionResult struct {
	credentialInjectionResult
	Denied bool
	Reason string
}

func mergeCredentialInjectionResults(a, b credentialInjectionResult) credentialInjectionResult {
	if len(a.InjectedHeaders) == 0 {
		return b
	}
	if len(b.InjectedHeaders) == 0 {
		return a
	}
	merged := credentialInjectionResult{
		InjectedHeaders: make(map[string]bool, len(a.InjectedHeaders)+len(b.InjectedHeaders)),
		// Grants name the request log's credential sources. A bundle and a
		// static credential can both fire for one host under the same grant,
		// and listing it twice would misreport one injection as two.
		Grants:   mergeGrants(a.Grants, b.Grants),
		Injected: append(append([]credentialHeader(nil), a.Injected...), b.Injected...),
	}
	for key := range a.InjectedHeaders {
		merged.InjectedHeaders[key] = true
	}
	for key := range b.InjectedHeaders {
		merged.InjectedHeaders[key] = true
	}
	return merged
}

// mergeGrants concatenates two grant lists, keeping first-seen order and
// dropping duplicates.
func mergeGrants(a, b []string) []string {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]struct{}, len(a)+len(b))
	merged := make([]string, 0, len(a)+len(b))
	for _, grant := range append(append([]string(nil), a...), b...) {
		if _, dup := seen[grant]; dup {
			continue
		}
		seen[grant] = struct{}{}
		merged = append(merged, grant)
	}
	return merged
}

// headerKey is the canonical map key for a header name. Header lookups are
// case-insensitive, and InjectedHeaders is consumed by callers that key on the
// lowercase name, so every producer has to agree on one spelling.
func headerKey(name string) string { return strings.ToLower(name) }

// bundleIsWellFormed reports whether a bundle can be evaluated at all.
//
// A replacement missing any of its three fields cannot be matched safely: an
// empty Placeholder compares equal to every absent header. Two replacements on
// one header name are contradictory. Neither is a request-level decision, so a
// bundle failing this test is ignored rather than denied.
func bundleIsWellFormed(bundle CredentialBundle) bool {
	if len(bundle.Replacements) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(bundle.Replacements))
	for _, replacement := range bundle.Replacements {
		if replacement.Name == "" || replacement.Placeholder == "" || replacement.Value == "" {
			return false
		}
		key := headerKey(replacement.Name)
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}

// carriesBundlePlaceholder reports whether the request presents any well-formed
// bundle's placeholder, and names the bundle if so.
//
// The MCP relay uses this to refuse such a request rather than to inject one.
// A bundle is scoped to an origin and path on the forwarding paths; the relay
// selects its target from a registered server list instead, so evaluating a
// bundle's scope there would mean honoring it against a destination the scope
// was never written for. Refusing keeps a placeholder from being forwarded to a
// third party while making it impossible for the relay to hand out the real
// value by a route the scope does not cover.
func carriesBundlePlaceholder(req *http.Request, bundles []CredentialBundle) (string, bool) {
	for _, bundle := range bundles {
		if !bundleIsWellFormed(bundle) {
			continue
		}
		for _, replacement := range bundle.Replacements {
			if req.Header.Get(replacement.Name) == replacement.Placeholder {
				return bundle.ID, true
			}
		}
	}
	return "", false
}

// injectCredentialBundles replaces an eligible bundle atomically. Bundles are
// opt-in: a request is considered a candidate only when it carries at least
// one header named by a bundle. Once selected, any scope or placeholder
// mismatch fails closed so a synthetic credential cannot escape upstream.
func injectCredentialBundles(req *http.Request, bundles []CredentialBundle, scheme, host string) credentialBundleInjectionResult {
	if len(bundles) == 0 {
		return credentialBundleInjectionResult{}
	}
	candidate := false
	for _, bundle := range bundles {
		if !bundleIsWellFormed(bundle) {
			// A malformed bundle is inert rather than fail-closed. An empty
			// placeholder would otherwise match every request that simply does
			// not carry that header — Get returns "" for an absent header — so
			// one misconfigured entry would deny far more traffic than it was
			// ever scoped to cover.
			continue
		}
		requested := false
		for _, replacement := range bundle.Replacements {
			if req.Header.Get(replacement.Name) == replacement.Placeholder {
				requested = true
				candidate = true
				break
			}
		}
		if !requested {
			continue
		}
		if !bundleScopeMatches(bundle.Scope, req, scheme, host) {
			continue
		}

		matched := 0
		valid := true
		for _, replacement := range bundle.Replacements {
			if req.Header.Get(replacement.Name) == replacement.Placeholder {
				matched++
			} else if bundle.RequireAll {
				valid = false
				break
			}
		}
		if !valid || matched == 0 || bundle.RequireAll && matched != len(bundle.Replacements) {
			continue
		}

		injectedHeaders := make(map[string]bool, matched)
		injected := make([]credentialHeader, 0, matched)
		for _, replacement := range bundle.Replacements {
			if req.Header.Get(replacement.Name) != replacement.Placeholder {
				continue
			}
			req.Header.Set(replacement.Name, replacement.Value)
			key := headerKey(replacement.Name)
			injectedHeaders[key] = true
			injected = append(injected, credentialHeader{
				Name: replacement.Name, Value: replacement.Value, Grant: bundle.Grant,
			})
		}
		grants := []string(nil)
		if bundle.Grant != "" {
			grants = []string{bundle.Grant}
		}
		return credentialBundleInjectionResult{credentialInjectionResult: credentialInjectionResult{
			InjectedHeaders: injectedHeaders,
			Grants:          grants,
			Injected:        injected,
		}}
	}

	if candidate {
		return credentialBundleInjectionResult{Denied: true, Reason: "credential bundle scope or placeholder mismatch"}
	}
	return credentialBundleInjectionResult{}
}

func bundleScopeMatches(scope CredentialScope, req *http.Request, scheme, host string) bool {
	if scope.RequireTLS && !strings.EqualFold(scheme, "https") {
		return false
	}
	origin, ok := canonicalOrigin(scheme, host)
	if !ok || !containsFold(scope.Origins, origin) {
		return false
	}
	if len(scope.Methods) > 0 && !containsFold(scope.Methods, req.Method) {
		return false
	}
	canonicalPath, ok := canonicalRequestPath(req.URL)
	if !ok {
		return false
	}
	for _, prefix := range scope.PathPrefixes {
		if canonicalPath == prefix || strings.HasPrefix(canonicalPath, strings.TrimSuffix(prefix, "/")+"/") {
			return true
		}
	}
	return len(scope.PathPrefixes) == 0
}

func canonicalOrigin(scheme, host string) (string, bool) {
	scheme = strings.ToLower(scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	hostname := host
	port := ""
	if h, p, err := net.SplitHostPort(host); err == nil {
		hostname, port = h, p
	}
	hostname = strings.Trim(strings.ToLower(hostname), "[]")
	if hostname == "" {
		return "", false
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	authority := hostname
	if strings.Contains(hostname, ":") {
		authority = "[" + hostname + "]"
	}
	if port != "" {
		authority = net.JoinHostPort(hostname, port)
	}
	return scheme + "://" + authority, true
}

func canonicalRequestPath(u *url.URL) (string, bool) {
	escaped := u.EscapedPath()
	decoded, err := url.PathUnescape(escaped)
	if err != nil || decoded == "" || !strings.HasPrefix(decoded, "/") || strings.Contains(decoded, "\\") || strings.ContainsRune(decoded, '\x00') {
		return "", false
	}
	for _, segment := range strings.Split(decoded, "/") {
		if segment == "." || segment == ".." {
			return "", false
		}
	}
	if pathpkg.Clean(decoded) != decoded {
		return "", false
	}
	return decoded, true
}

func containsFold(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}
