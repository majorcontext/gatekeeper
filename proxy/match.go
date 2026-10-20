package proxy

import (
	"net/http"
	"slices"
	"strings"
)

// RequestMatch selects a resolver for a request. A zero field matches anything.
type RequestMatch struct {
	Header  string   // the client must send this header with a non-empty value
	Paths   []string // URL path prefixes; empty = any path
	Methods []string // exact upper-case HTTP methods; empty = any method
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
