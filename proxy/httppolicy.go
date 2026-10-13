package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	keeplib "github.com/majorcontext/keep"
)

// isTextContentType returns true for text-based content types that should be captured.
func isTextContentType(ct string) bool {
	if ct == "" {
		return false
	}
	ct = strings.ToLower(ct)
	return strings.HasPrefix(ct, "text/") ||
		strings.Contains(ct, "json") ||
		strings.Contains(ct, "xml") ||
		strings.Contains(ct, "x-www-form-urlencoded") ||
		strings.Contains(ct, "javascript")
}

// isJSONContentType reports whether the Content-Type denotes a JSON body
// (e.g. "application/json", "application/vnd.api+json"). Parameters such as
// "; charset=utf-8" are tolerated. Used to decide whether a request body can be
// parsed for http-scope body policy evaluation.
func isJSONContentType(ct string) bool {
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(strings.ToLower(ct))
	return ct == "application/json" || strings.HasSuffix(ct, "+json")
}

// buildHTTPCall constructs the Keep Call for an http-scope policy evaluation.
//
// When no loaded rule in the "http" scope inspects the request body
// (eng.RequiresBody is false), it returns a body-less call and leaves req
// untouched — the common, zero-overhead path.
//
// When a body rule is in effect, it buffers and JSON-parses the request body,
// exposing it to rules under params.body, and restores req.Body so the upstream
// request is unchanged. It fails closed: a body that cannot be inspected
// (non-JSON Content-Type with a payload, malformed JSON, duplicate JSON keys, or
// a body exceeding maxPolicyBodySize) returns ok=false with a reason, and the
// caller denies. A request with no body is allowed through with params.body ==
// null, so body rules simply don't match while path rules still apply.
//
// Note: RequiresBody is scope-global — a single body rule makes this path apply
// to every request in the "http" scope. As a result, any non-JSON request with
// a payload is denied once a body rule exists, even for hosts the rule's `when`
// clause would never match. Scope body rules by host in the rule itself if that
// over-broad denial is a concern.
func buildHTTPCall(eng *keeplib.Engine, req *http.Request, host string) (call keeplib.Call, ok bool, denyReason string) {
	if !eng.RequiresBody("http") {
		return keeplib.NewHTTPCall(req.Method, host, req.URL.Path), true, ""
	}

	if req.Body == nil || req.ContentLength == 0 {
		return keeplib.NewHTTPCallWithBody(req.Method, host, req.URL.Path, nil), true, ""
	}

	// A compressed body can't be inspected without decoding it first, so fail
	// closed with an explicit reason rather than a misleading JSON parse error.
	if enc := req.Header.Get("Content-Encoding"); enc != "" {
		req.Body.Close()
		return keeplib.Call{}, false, "request body uses unsupported Content-Encoding: " + enc
	}

	if ct := req.Header.Get("Content-Type"); !isJSONContentType(ct) {
		req.Body.Close()
		return keeplib.Call{}, false, "request body is not JSON (Content-Type: " + ct + ")"
	}

	// Read one byte past the limit so an exactly-limit body is still accepted
	// while a larger one is detected. Restore req.Body afterward so the upstream
	// request remains intact on the allow path; on a deny path the request is
	// never forwarded, so a truncated restore is harmless.
	buf, err := io.ReadAll(io.LimitReader(req.Body, maxPolicyBodySize+1))
	req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(buf))
	if err != nil {
		return keeplib.Call{}, false, "failed to read request body for policy evaluation"
	}
	if int64(len(buf)) > maxPolicyBodySize {
		return keeplib.Call{}, false, "request body exceeds policy inspection limit"
	}

	// An empty or whitespace-only body carries no JSON to inspect — e.g. a
	// chunked/unknown-length request (ContentLength == -1, so it slips past the
	// fast path above) with no payload. Treat it as bodyless rather than failing
	// closed on json.Unmarshal of empty input, so path rules still apply and body
	// rules simply don't match.
	if len(bytes.TrimSpace(buf)) == 0 {
		return keeplib.NewHTTPCallWithBody(req.Method, host, req.URL.Path, nil), true, ""
	}

	var parsed any
	if err := json.Unmarshal(buf, &parsed); err != nil {
		return keeplib.Call{}, false, "request body is not valid JSON"
	}

	// encoding/json silently keeps the last value for duplicate object keys.
	// An upstream parser that keeps the first would see a different value, so a
	// crafted body (e.g. two "model" keys) could satisfy the rule while a
	// different value reaches the server — a policy bypass. No legitimate client
	// sends duplicate keys, so reject them fail-closed to keep the proxy's view
	// of the body authoritative.
	if hasDuplicateJSONKeys(json.NewDecoder(bytes.NewReader(buf))) {
		return keeplib.Call{}, false, "request body has duplicate JSON keys"
	}
	return keeplib.NewHTTPCallWithBody(req.Method, host, req.URL.Path, parsed), true, ""
}

// hasDuplicateJSONKeys reports whether any object in the JSON read from dec
// contains a duplicate key, recursing into nested objects and arrays. It
// consumes exactly one JSON value. A token error is reported as a duplicate
// (fail-closed): the caller has already confirmed the bytes parse, so an error
// here means the input is ambiguous and must not be trusted.
func hasDuplicateJSONKeys(dec *json.Decoder) bool {
	tok, err := dec.Token()
	if err != nil {
		return true
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return false // scalar value
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return true
			}
			key, ok := keyTok.(string)
			if !ok {
				return true
			}
			if _, dup := seen[key]; dup {
				return true
			}
			seen[key] = struct{}{}
			if hasDuplicateJSONKeys(dec) { // the key's value
				return true
			}
		}
		if _, err := dec.Token(); err != nil { // closing '}'
			return true
		}
	case '[':
		for dec.More() {
			if hasDuplicateJSONKeys(dec) {
				return true
			}
		}
		if _, err := dec.Token(); err != nil { // closing ']'
			return true
		}
	}
	return false
}
