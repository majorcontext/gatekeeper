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
