package proxy

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// HostPattern represents a parsed host pattern for matching.
type HostPattern struct {
	pattern    string // the original pattern
	host       string // the host part (without port)
	port       int    // specific port, or 0 if unspecified (matches only ports 80 and 443)
	isWildcard bool   // true if pattern starts with *.
	prefix     string // lowercase prefix of a one-label prefix wildcard (pr-*.example.com), else empty
}

// parseHostPattern parses a host pattern string into a HostPattern struct.
// Supports patterns like:
//   - api.example.com
//   - api.example.com:8080
//   - *.example.com
//   - *.example.com:443
//   - pr-*.example.com (one label that starts with "pr-" and has more characters)
func parseHostPattern(s string) HostPattern {
	p, _ := parseHostPatternChecked(s)
	return p
}

// ValidateHostPattern reports why s is not a usable host pattern. Unlike
// ParseHostPattern, which treats an unparsable port as "ports 80 and 443",
// it rejects the pattern.
func ValidateHostPattern(s string) error {
	_, err := parseHostPatternChecked(s)
	return err
}

func parseHostPatternChecked(s string) (HostPattern, error) {
	p := HostPattern{
		pattern: s,
		port:    0, // 0 = unspecified, will match only ports 80 and 443
	}
	orig := s

	// Check for wildcard prefix
	if strings.HasPrefix(s, "*.") {
		p.isWildcard = true
		s = s[2:] // Remove "*."
	}

	// Split host and port
	host, portStr, hasPort := strings.Cut(s, ":")
	p.host = lowerASCII(host)

	var err error
	switch {
	case host == "":
		err = fmt.Errorf("host pattern %q has no host", orig)
	case strings.ContainsAny(host, "[]"):
		err = fmt.Errorf("host pattern %q has brackets; an IPv6 literal is not a host pattern", orig)
	case !isASCII(host):
		err = fmt.Errorf("host pattern %q is not ASCII; write internationalized names in their xn-- form", orig)
	case hasEmptyLabel(host):
		err = fmt.Errorf("host pattern %q has an empty label or a trailing dot", orig)
	case endsInNumber(host) && (p.isWildcard || strings.Contains(host, "*") || !isIPv4Literal(host)):
		err = fmt.Errorf("host pattern %q ends in a number; write an IPv4 address as an exact dotted quad", orig)
	case p.isWildcard && strings.Contains(host, "*"):
		err = fmt.Errorf("host pattern %q has a * after its leading \"*.\"", orig)
	case strings.Contains(host, "*"):
		if prefix, rest, ok := splitPrefixWildcard(host); ok {
			p.prefix, p.host = prefix, rest
		} else {
			err = fmt.Errorf("host pattern %q: * must be the whole first label (*.example.com) or end it (pr-*.example.com)", orig)
		}
	}
	if hasPort {
		port, perr := strconv.Atoi(portStr)
		if perr == nil && port > 0 && port <= 65535 {
			p.port = port
		} else if err == nil {
			err = fmt.Errorf("host pattern %q has an invalid port", orig)
		}
	}

	return p, err
}

// splitPrefixWildcard splits a one-label prefix wildcard such as
// "pr-*.example.com[:port]" into its lowercase prefix ("pr-") and the rest
// after the first dot ("example.com[:port]"). The prefix is non-empty and has
// no "." or "*", the "*" ends the first label, and the rest has no "*" and at
// least two non-empty labels, so "pr-*.com" and "pr-*.com." are not prefix
// wildcards.
func splitPrefixWildcard(s string) (prefix, rest string, ok bool) {
	label, rest, found := strings.Cut(s, ".")
	if !found || len(label) < 2 || !strings.HasSuffix(label, "*") || strings.Contains(label[:len(label)-1], "*") {
		return "", "", false
	}
	domain, _, _ := strings.Cut(rest, ":")
	if strings.Contains(rest, "*") || !strings.Contains(domain, ".") || hasEmptyLabel(domain) {
		return "", "", false
	}
	return lowerASCII(label[:len(label)-1]), lowerASCII(rest), true
}

// matchPrefixWildcard reports whether host is one label that starts with
// prefix and has at least one more character, followed by exactly rest.
// Both prefix and rest must already be lowercase.
func matchPrefixWildcard(prefix, rest, host string) bool {
	label, remainder, found := strings.Cut(lowerASCII(host), ".")
	return found && remainder == rest && len(label) > len(prefix) && strings.HasPrefix(label, prefix)
}

// hostMatchesPattern is the host half of matchesPattern, without the port
// policy.
func hostMatchesPattern(pattern HostPattern, host string) bool {
	if (pattern.prefix != "" || pattern.isWildcard) && isIPLiteral(host) {
		return false
	}
	switch {
	case pattern.prefix != "":
		return matchPrefixWildcard(pattern.prefix, pattern.host, host)
	case pattern.isWildcard:
		// *.example.com matches api.example.com, foo.bar.example.com: the
		// host must end with .{pattern.host}
		return hostHasSuffixFold(host, "."+pattern.host)
	default:
		return lowerASCII(pattern.host) == lowerASCII(host)
	}
}

// matchHost checks if the given host:port matches any of the patterns.
// Matching rules:
//   - Exact match: "api.github.com" matches only "api.github.com"
//   - Wildcard: "*.github.com" matches "api.github.com", "foo.bar.github.com"
//   - Prefix wildcard: "pr-*.example.com" matches "pr-1.example.com" only: one
//     label, "pr-" plus at least one character, then exactly ".example.com"
//   - Port matching: if pattern has port, must match exactly;
//     if pattern has no port (0), match 80 or 443
func matchHost(patterns []HostPattern, host string, port int) bool {
	for _, pattern := range patterns {
		if matchesPattern(pattern, host, port) {
			return true
		}
	}
	return false
}

// matchesPattern checks if a single pattern matches the host:port.
func matchesPattern(pattern HostPattern, host string, port int) bool {
	if !allowPatternPortMatches(pattern.port, port) {
		return false
	}

	return hostMatchesPattern(pattern, host)
}

// allowPatternPortMatches is the port policy of network allow patterns: a
// pattern port of 0 matches only the default ports 80 and 443.
func allowPatternPortMatches(patternPort, port int) bool {
	if patternPort != 0 {
		return patternPort == port
	}
	return port == 80 || port == 443
}

// hostHasSuffixFold reports whether host ends with suffix, ignoring ASCII case
// (see lowerASCII).
func hostHasSuffixFold(host, suffix string) bool {
	return strings.HasSuffix(lowerASCII(host), lowerASCII(suffix))
}

// grantHosts maps grant names to their allowed host patterns.
var grantHosts = map[string][]string{
	"github": {
		"github.com",
		"api.github.com",
		"*.githubusercontent.com",
		"*.github.com",
	},
	"anthropic": {
		"api.anthropic.com",
		"*.anthropic.com",
	},
	"claude": {
		"api.anthropic.com",
		"*.anthropic.com",
	},
	"openai": {
		"api.openai.com", // API key endpoint
		"chatgpt.com",    // ChatGPT subscription endpoint
		"*.openai.com",   // Other OpenAI services
	},
	"aws": {
		"sts.amazonaws.com",
		"sts.*.amazonaws.com",
		"*.amazonaws.com",
	},
	"graphite": {
		"api.graphite.com",
		"*.graphite.com",
	},
	"meta": {
		"graph.facebook.com",
		"graph.instagram.com",
	},
}

// RegisterGrantHosts registers host patterns for a grant name.
// This is used by config-driven providers to register their hosts dynamically.
// Must be called during initialization only (before concurrent access).
func RegisterGrantHosts(grant string, hosts []string) {
	grantHosts[grant] = hosts
}

// getHostsForGrant returns the host patterns for a given grant name.
// Supports scoped grants like "github:repo" by extracting the provider name.
// Returns an empty slice if the grant is unknown.
func getHostsForGrant(grant string) []string {
	// Extract provider from scoped grant (e.g., "github:repo" -> "github")
	provider := grant
	if idx := strings.Index(grant, ":"); idx != -1 {
		provider = grant[:idx]
	}

	hosts, ok := grantHosts[provider]
	if !ok {
		return []string{}
	}
	return hosts
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

// matchWildcardHostKey is the credential-key policy for a "*." key: a key
// without a port matches the host on any port (it is tried against the bare
// host), and a key with a port matches only that host:port.
func matchWildcardHostKey(key, host, bare string) bool {
	if !strings.HasPrefix(key, "*.") {
		return false
	}
	suffix := key[1:]
	return hostHasSuffixFold(bare, suffix) ||
		(host != bare && hostHasSuffixFold(host, suffix))
}

// matchPrefixWildcardHostKey is the same policy for a one-label prefix key
// such as "pr-*.example.com": the key's rest (which keeps any ":port") is
// compared against the bare host, or against the full host:port.
func matchPrefixWildcardHostKey(key, host, bare string) bool {
	prefix, rest, ok := splitPrefixWildcard(key)
	return ok && (matchPrefixWildcard(prefix, rest, bare) ||
		(host != bare && matchPrefixWildcard(prefix, rest, host)))
}

// wildcardHostKeyTier reports how a wildcard key matches host: a prefix key
// ("pr-*.example.com") or a "*." key, or hostMatchNone.
func wildcardHostKeyTier(key, host, bare string) hostMatchTier {
	if isIPLiteral(bare) {
		return hostMatchNone
	}
	switch {
	case matchPrefixWildcardHostKey(key, host, bare):
		return hostMatchPrefixWildcard
	case matchWildcardHostKey(key, host, bare):
		return hostMatchWildcard
	}
	return hostMatchNone
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
// key match outranks a case-fold match, which outranks a prefix wildcard
// ("pr-*.example.com"), which outranks a "*." wildcard. So an exact host beats
// a prefix pattern beats a "*." pattern, whatever the key lengths.
type hostMatchTier int

const (
	hostMatchNone hostMatchTier = iota
	hostMatchWildcard
	hostMatchPrefixWildcard
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

// lookupHostKeyed resolves a host against a map keyed by exact hostnames,
// "*." wildcard patterns, or one-label prefix patterns ("pr-*.example.com"),
// skipping entries the usable predicate rejects
// (embedder-supplied maps may hold empty slices or nil values, which must
// not shadow a key from a later tier). Exact keys win over wildcard keys:
// the host is tried verbatim, then port-stripped, then case-insensitively;
// only when every exact tier misses is a matching wildcard key used: a prefix
// key before a "*." key, then the most specific (longest) by
// moreSpecificWildcardKey. In the fold tier, a
// key matching the full host:port beats a key matching only the bare host
// (mirroring the verbatim tiers' order), and any remaining tie goes to the
// lexicographically smallest key so the pick never depends on map iteration
// order. The fallback scan is linear in the number of configured host keys;
// it runs only when the verbatim and bare lookups miss, and the maps are
// config-scale, not request-scale.
func lookupHostKeyed[V any](m map[string]V, host string, usable func(V) bool) (V, hostMatch) {
	return lookupHostKeyedExcluding(m, host, usable, nil)
}

func lookupHostKeyedExcluding[V any](m map[string]V, host string, usable func(V) bool, excluded map[string]bool) (V, hostMatch) {
	if !excluded[host] {
		if v, ok := m[host]; ok && usable(v) {
			return v, hostMatch{hostMatchExact, host}
		}
	}
	bare := bareHost(host)
	hostAddr, hostPort, hostIsIP := splitIPKey(host)
	if bare != host && hostIsIP {
		// A key pinned to this address and port outranks a portless key.
		if v, key, ok := pinnedIPKey(m, hostAddr, hostPort, usable, excluded); ok {
			return v, hostMatch{hostMatchExactFold, key}
		}
	}
	if bare != host && !excluded[bare] {
		if v, ok := m[bare]; ok && usable(v) {
			return v, hostMatch{hostMatchExact, bare}
		}
	}
	lowerHost, lowerBare := lowerASCII(host), lowerASCII(bare)
	var best V
	var bestKey string
	tier := hostMatchNone
	bestFoldsHost := false // best fold key matches the full host:port, not just bare
	for key, v := range m {
		if excluded[key] || !usable(v) {
			continue
		}
		// The case-insensitive exact tier must fold both the bare host and
		// the full host:port — port-bearing keys are expressible in
		// embedder-built RunContextData maps. A host:port fold match beats
		// a bare fold match, as in the verbatim tiers.
		lowerKey := lowerASCII(key)
		// An IP key matches by parsed address and port, not by text.
		var ipMatch, ipPinned bool
		if hostIsIP {
			ipMatch, ipPinned = ipKeyMatches(key, hostAddr, hostPort)
		}
		if foldsHost := (host != bare && lowerKey == lowerHost) || (ipMatch && ipPinned); foldsHost || lowerKey == lowerBare || ipMatch {
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
		if wt := wildcardHostKeyTier(key, host, bare); wt != hostMatchNone &&
			(wt > tier || wt == tier && moreSpecificWildcardKey(key, bestKey)) {
			bestKey, best, tier = key, v, wt
		}
	}
	return best, hostMatch{tier, bestKey}
}

// pinnedIPKey returns the entry of the smallest IP key (a stable pick) that
// names hostAddr and is pinned to hostPort.
func pinnedIPKey[V any](m map[string]V, hostAddr netip.Addr, hostPort string, usable func(V) bool, excluded map[string]bool) (best V, bestKey string, found bool) {
	for key, v := range m {
		if excluded[key] || !usable(v) {
			continue
		}
		if match, pinned := ipKeyMatches(key, hostAddr, hostPort); match && pinned && (!found || key < bestKey) {
			best, bestKey, found = v, key, true
		}
	}
	return best, bestKey, found
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
