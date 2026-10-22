package proxy

import (
	"net/http"
	"slices"
	"strings"
)

// RequestMatch selects a credential for a request. A zero field matches anything.
type RequestMatch struct {
	Header  string   `yaml:"header"`            // non-empty request header required for a match
	Paths   []string `yaml:"paths,omitempty"`   // path prefixes; any prefix matches
	Methods []string `yaml:"methods,omitempty"` // exact upper-case methods; any method matches
}

func firstMatchingRequestMatch(req *http.Request, path string, count int, matchAt func(int) *RequestMatch) int {
	for i := 0; i < count; i++ {
		match := matchAt(i)
		if match != nil && match.matches(req, path) {
			return i
		}
	}
	return -1
}

func selectRequestCredentialEntries[T any](entries map[string][]T, host string, req *http.Request, path string, matchAt func(T) *RequestMatch) ([]T, hostMatch, int, []T) {
	excluded := make(map[string]bool)
	var skipped []T
	for {
		candidates, rank := lookupHostKeyedExcluding(entries, host, func(items []T) bool { return len(items) > 0 }, excluded)
		if len(candidates) == 0 {
			return nil, rank, -1, skipped
		}
		selected := firstMatchingRequestMatch(req, path, len(candidates), func(i int) *RequestMatch { return matchAt(candidates[i]) })
		if selected >= 0 {
			return candidates, rank, selected, skipped
		}
		for i, candidate := range candidates {
			if matchAt(candidate) == nil {
				return candidates, rank, i, skipped
			}
		}
		if rank.key == "" {
			return nil, hostMatch{}, -1, skipped
		}
		skipped = append(skipped, candidates...)
		excluded[rank.key] = true
	}
}

// Equal reports whether two request predicates have the same fields.
func (m RequestMatch) Equal(o RequestMatch) bool {
	return strings.EqualFold(m.Header, o.Header) && slices.Equal(m.Paths, o.Paths) && slices.Equal(m.Methods, o.Methods)
}

func (m RequestMatch) matches(req *http.Request, path string) bool {
	if m.Header != "" && req.Header.Get(m.Header) == "" {
		return false
	}
	if path == "" {
		path = "/"
	}
	if len(m.Paths) > 0 && !slices.ContainsFunc(m.Paths, func(p string) bool { return strings.HasPrefix(path, p) }) {
		return false
	}
	return len(m.Methods) == 0 || slices.Contains(m.Methods, req.Method)
}
