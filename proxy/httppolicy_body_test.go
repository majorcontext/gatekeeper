package proxy

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	keeplib "github.com/majorcontext/keep"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// httpBodyRules references params.body, so RequiresBody("http") is true.
// operation is omitted (empty pattern matches every operation) because the
// http call operation is "METHOD host/path" and path.Match's * does not cross
// the '/' separators.
const httpBodyRules = `
scope: http
mode: enforce
rules:
  - name: deny-gpt4
    match:
      when: "params.body.model == 'gpt-4'"
    action: deny
    message: "model blocked"
`

// httpNoBodyRules references only path, so RequiresBody("http") is false.
const httpNoBodyRules = `
scope: http
mode: enforce
rules:
  - name: deny-path
    match:
      when: "params.path == '/blocked'"
    action: deny
    message: "path blocked"
`

func TestIsJSONContentType(t *testing.T) {
	cases := []struct {
		ct   string
		want bool
	}{
		{"application/json", true},
		{"application/json; charset=utf-8", true},
		{"application/vnd.api+json", true},
		{"APPLICATION/JSON", true},
		{"text/plain", false},
		{"application/octet-stream", false},
		{"application/x-www-form-urlencoded", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isJSONContentType(c.ct); got != c.want {
			t.Errorf("isJSONContentType(%q) = %v, want %v", c.ct, got, c.want)
		}
	}
}

func newJSONRequest(t *testing.T, method, body string) *http.Request {
	t.Helper()
	var r *http.Request
	var err error
	if body == "" {
		r, err = http.NewRequest(method, "https://api.example.com/v1/messages", nil)
	} else {
		r, err = http.NewRequest(method, "https://api.example.com/v1/messages", strings.NewReader(body))
	}
	require.NoError(t, err)
	r.Header.Set("Content-Type", "application/json")
	return r
}

// TestBuildHTTPCall_NoBodyRule verifies the zero-overhead path: when no rule
// inspects the body, the call carries no body and the request is untouched.
func TestBuildHTTPCall_NoBodyRule(t *testing.T) {
	eng, err := keeplib.LoadFromBytes([]byte(httpNoBodyRules))
	require.NoError(t, err)
	defer eng.Close()
	require.False(t, eng.RequiresBody("http"))

	req := newJSONRequest(t, "POST", `{"model":"gpt-4"}`)
	call, ok, reason := buildHTTPCall(eng, req, "api.example.com")
	require.True(t, ok)
	assert.Empty(t, reason)
	_, hasBody := call.Params["body"]
	assert.False(t, hasBody, "body should not be populated when no rule needs it")

	// Body must remain fully readable and unmodified for the upstream request.
	got, _ := io.ReadAll(req.Body)
	assert.Equal(t, `{"model":"gpt-4"}`, string(got))
}

// TestBuildHTTPCall_JSONBodyParsedAndRestored verifies the body is exposed to
// rules and the request body is restored intact.
func TestBuildHTTPCall_JSONBodyParsedAndRestored(t *testing.T) {
	eng, err := keeplib.LoadFromBytes([]byte(httpBodyRules))
	require.NoError(t, err)
	defer eng.Close()
	require.True(t, eng.RequiresBody("http"))

	body := `{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`
	req := newJSONRequest(t, "POST", body)
	call, ok, reason := buildHTTPCall(eng, req, "api.example.com")
	require.True(t, ok)
	assert.Empty(t, reason)

	parsed, hasBody := call.Params["body"].(map[string]any)
	require.True(t, hasBody, "body should be a parsed map")
	assert.Equal(t, "gpt-4", parsed["model"])

	got, _ := io.ReadAll(req.Body)
	assert.Equal(t, body, string(got), "body must be restored intact for upstream")
}

// TestBuildHTTPCall_NoBodyAllowed verifies a bodyless request (e.g. GET) is
// allowed through with params.body == null so path rules still apply.
func TestBuildHTTPCall_NoBodyAllowed(t *testing.T) {
	eng, err := keeplib.LoadFromBytes([]byte(httpBodyRules))
	require.NoError(t, err)
	defer eng.Close()

	req := newJSONRequest(t, "GET", "")
	call, ok, reason := buildHTTPCall(eng, req, "api.example.com")
	require.True(t, ok)
	assert.Empty(t, reason)
	v, hasBody := call.Params["body"]
	assert.True(t, hasBody, "body key should be present")
	assert.Nil(t, v, "body should be nil for a request without a payload")
}

// TestBuildHTTPCall_NonJSONDenied verifies a non-JSON payload fails closed when
// a body rule is in effect.
func TestBuildHTTPCall_NonJSONDenied(t *testing.T) {
	eng, err := keeplib.LoadFromBytes([]byte(httpBodyRules))
	require.NoError(t, err)
	defer eng.Close()

	req, err := http.NewRequest("POST", "https://api.example.com/v1/messages", strings.NewReader("model=gpt-4"))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, ok, reason := buildHTTPCall(eng, req, "api.example.com")
	assert.False(t, ok)
	assert.Contains(t, reason, "not JSON")
}

// TestBuildHTTPCall_CompressedBodyDenied verifies a body with a Content-Encoding
// the proxy can't decode fails closed with an explicit reason (not a misleading
// JSON parse error).
func TestBuildHTTPCall_CompressedBodyDenied(t *testing.T) {
	eng, err := keeplib.LoadFromBytes([]byte(httpBodyRules))
	require.NoError(t, err)
	defer eng.Close()

	req := newJSONRequest(t, "POST", `{"model":"gpt-4"}`)
	req.Header.Set("Content-Encoding", "gzip")
	_, ok, reason := buildHTTPCall(eng, req, "api.example.com")
	assert.False(t, ok)
	assert.Contains(t, reason, "Content-Encoding")
}

// TestBuildHTTPCall_MalformedJSONDenied verifies malformed JSON fails closed.
func TestBuildHTTPCall_MalformedJSONDenied(t *testing.T) {
	eng, err := keeplib.LoadFromBytes([]byte(httpBodyRules))
	require.NoError(t, err)
	defer eng.Close()

	req := newJSONRequest(t, "POST", `{"model":"gpt-4"`) // missing closing brace
	_, ok, reason := buildHTTPCall(eng, req, "api.example.com")
	assert.False(t, ok)
	assert.Contains(t, reason, "not valid JSON")
}

// TestBuildHTTPCall_OversizedDenied verifies a body over maxPolicyBodySize fails
// closed rather than being silently truncated (which would bypass the rule).
func TestBuildHTTPCall_OversizedDenied(t *testing.T) {
	eng, err := keeplib.LoadFromBytes([]byte(httpBodyRules))
	require.NoError(t, err)
	defer eng.Close()

	big := `{"x":"` + strings.Repeat("a", maxPolicyBodySize) + `"}`
	req := newJSONRequest(t, "POST", big)
	_, ok, reason := buildHTTPCall(eng, req, "api.example.com")
	assert.False(t, ok)
	assert.Contains(t, reason, "exceeds policy inspection limit")
}

// TestBuildHTTPCall_JSONArrayBody verifies a top-level JSON array body parses
// (the helper accepts any JSON shape, not just objects).
func TestBuildHTTPCall_JSONArrayBody(t *testing.T) {
	eng, err := keeplib.LoadFromBytes([]byte(httpBodyRules))
	require.NoError(t, err)
	defer eng.Close()

	body := `["a","b"]`
	req := newJSONRequest(t, "POST", body)
	call, ok, reason := buildHTTPCall(eng, req, "api.example.com")
	require.True(t, ok)
	assert.Empty(t, reason)
	arr, isArr := call.Params["body"].([]any)
	require.True(t, isArr)
	assert.Len(t, arr, 2)

	got, _ := io.ReadAll(req.Body)
	assert.Equal(t, body, string(got))
}

// newChunkedRequest builds a request with unknown length (ContentLength == -1,
// as Go represents a chunked / no-Content-Length request) and a non-nil body.
func newChunkedRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest("POST", "https://api.example.com/v1/messages", nil)
	require.NoError(t, err)
	req.Body = io.NopCloser(strings.NewReader(body))
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	return req
}

// TestBuildHTTPCall_ChunkedBodyInspected verifies that a chunked/unknown-length
// request (ContentLength == -1) is still buffered and inspected — it must NOT
// slip past the bodyless fast path (which only matches ContentLength == 0).
func TestBuildHTTPCall_ChunkedBodyInspected(t *testing.T) {
	eng, err := keeplib.LoadFromBytes([]byte(httpBodyRules))
	require.NoError(t, err)
	defer eng.Close()

	body := `{"model":"gpt-4"}`
	req := newChunkedRequest(t, body)
	call, ok, reason := buildHTTPCall(eng, req, "api.example.com")
	require.True(t, ok)
	assert.Empty(t, reason)
	parsed, hasBody := call.Params["body"].(map[string]any)
	require.True(t, hasBody, "chunked body must be parsed, not skipped")
	assert.Equal(t, "gpt-4", parsed["model"])

	got, _ := io.ReadAll(req.Body)
	assert.Equal(t, body, string(got), "chunked body must be restored intact")
}

// TestBuildHTTPCall_EmptyChunkedBodyAllowed verifies that an empty
// chunked/unknown-length request with a JSON content-type is treated as
// bodyless (params.body == null) rather than failing closed on empty input.
func TestBuildHTTPCall_EmptyChunkedBodyAllowed(t *testing.T) {
	eng, err := keeplib.LoadFromBytes([]byte(httpBodyRules))
	require.NoError(t, err)
	defer eng.Close()

	for _, body := range []string{"", "   \n\t"} {
		req := newChunkedRequest(t, body)
		call, ok, reason := buildHTTPCall(eng, req, "api.example.com")
		require.Truef(t, ok, "empty chunked body %q should be allowed, got deny: %s", body, reason)
		v, hasBody := call.Params["body"]
		assert.True(t, hasBody, "body key should be present")
		assert.Nil(t, v, "empty body should yield params.body == null")
	}
}

// TestBuildHTTPCall_DuplicateKeysDenied verifies that bodies with duplicate JSON
// keys (at any nesting level) fail closed — encoding/json keeps the last value,
// which could diverge from an upstream parser and bypass the rule.
func TestBuildHTTPCall_DuplicateKeysDenied(t *testing.T) {
	eng, err := keeplib.LoadFromBytes([]byte(httpBodyRules))
	require.NoError(t, err)
	defer eng.Close()

	for _, body := range []string{
		`{"model":"gpt-4","model":"safe"}`,         // top-level duplicate
		`{"outer":{"x":1,"x":2}}`,                  // nested object duplicate
		`{"messages":[{"role":"user","role":"x"}]}`, // duplicate inside array element
	} {
		req := newJSONRequest(t, "POST", body)
		_, ok, reason := buildHTTPCall(eng, req, "api.example.com")
		assert.Falsef(t, ok, "body %q should be denied", body)
		assert.Contains(t, reason, "duplicate")
	}
}

// TestBuildHTTPCall_RepeatedKeysInDistinctObjectsAllowed verifies the
// duplicate-key check does not false-positive on the same key appearing in
// different objects.
func TestBuildHTTPCall_RepeatedKeysInDistinctObjectsAllowed(t *testing.T) {
	eng, err := keeplib.LoadFromBytes([]byte(httpBodyRules))
	require.NoError(t, err)
	defer eng.Close()

	req := newJSONRequest(t, "POST", `{"a":{"x":1},"b":{"x":2}}`)
	_, ok, reason := buildHTTPCall(eng, req, "api.example.com")
	assert.Truef(t, ok, "repeated key in distinct objects should be allowed, got: %s", reason)
}

// TestBuildHTTPCall_DeniesViaEngine closes the loop: the call built from a
// body-matching request, when evaluated against the engine, actually denies.
func TestBuildHTTPCall_DeniesViaEngine(t *testing.T) {
	eng, err := keeplib.LoadFromBytes([]byte(httpBodyRules))
	require.NoError(t, err)
	defer eng.Close()

	req := newJSONRequest(t, "POST", `{"model":"gpt-4"}`)
	call, ok, _ := buildHTTPCall(eng, req, "api.example.com")
	require.True(t, ok)
	call.Context.Scope = "http-api.example.com"

	result, evalErr := keeplib.SafeEvaluate(context.Background(), eng, call, "http")
	require.NoError(t, evalErr)
	assert.Equal(t, keeplib.Deny, result.Decision, "gpt-4 body should be denied by the rule")

	// A non-matching model must be allowed.
	req2 := newJSONRequest(t, "POST", `{"model":"claude"}`)
	call2, ok2, _ := buildHTTPCall(eng, req2, "api.example.com")
	require.True(t, ok2)
	call2.Context.Scope = "http-api.example.com"
	result2, evalErr2 := keeplib.SafeEvaluate(context.Background(), eng, call2, "http")
	require.NoError(t, evalErr2)
	assert.NotEqual(t, keeplib.Deny, result2.Decision, "non-gpt-4 body should be allowed")
}
