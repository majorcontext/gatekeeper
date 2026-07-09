package proxy

import (
	"net/http"
	"slices"
	"sort"
	"testing"
)

// grantsOf returns the grants injectCredentials recorded, sorted for comparison.
func grantsOf(res credentialInjectionResult) []string {
	g := slices.Clone(res.Grants)
	sort.Strings(g)
	return g
}

// injectedGrantsOf returns the grants of the credentials actually on the wire.
func injectedGrantsOf(res credentialInjectionResult) []string {
	var g []string
	for _, c := range res.Injected {
		g = append(g, c.Grant)
	}
	sort.Strings(g)
	return g
}

func newInjectReq(t *testing.T, clientHeaders map[string]string) *http.Request {
	t.Helper()
	req, err := http.NewRequest("GET", "https://example.test/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range clientHeaders {
		req.Header.Set(k, v)
	}
	return req
}

// When several credentials share a header name and the client sends a
// placeholder for it, exactly one credential may be injected. The "claude"
// grant wins the placeholder path: it is OAuth, and per injectCredentials'
// contract it should only be injected when Claude Code explicitly asks for it
// by sending the header.
func TestInjectCredentials_PlaceholderSameHeaderPrefersClaude(t *testing.T) {
	creds := []credentialHeader{
		{Name: "Authorization", Value: "Bearer other", Grant: "other"},
		{Name: "Authorization", Value: "Bearer claude", Grant: "claude"},
	}
	req := newInjectReq(t, map[string]string{"Authorization": "placeholder"})

	res := injectCredentials(req, creds, "example.test", "GET", "/x")

	if got := req.Header.Get("Authorization"); got != "Bearer claude" {
		t.Errorf("wire Authorization = %q, want %q", got, "Bearer claude")
	}
	if got := grantsOf(res); !slices.Equal(got, []string{"claude"}) {
		t.Errorf("Grants = %v, want [claude] (only the injected credential)", got)
	}
	if got := injectedGrantsOf(res); !slices.Equal(got, []string{"claude"}) {
		t.Errorf("Injected = %v, want [claude]", got)
	}
}

// Slice order must not decide the winner. Same as above with the credentials
// reversed: claude still wins.
func TestInjectCredentials_PlaceholderWinnerIndependentOfOrder(t *testing.T) {
	creds := []credentialHeader{
		{Name: "Authorization", Value: "Bearer claude", Grant: "claude"},
		{Name: "Authorization", Value: "Bearer other", Grant: "other"},
	}
	req := newInjectReq(t, map[string]string{"Authorization": "placeholder"})

	res := injectCredentials(req, creds, "example.test", "GET", "/x")

	if got := req.Header.Get("Authorization"); got != "Bearer claude" {
		t.Errorf("wire Authorization = %q, want %q", got, "Bearer claude")
	}
	if got := grantsOf(res); !slices.Equal(got, []string{"claude"}) {
		t.Errorf("Grants = %v, want [claude]", got)
	}
}

// The first pass must test what the *client* sent, not what an earlier
// iteration wrote. A credential whose header the client never sent must not be
// injected just because a same-named credential was injected before it.
func TestInjectCredentials_PlaceholderDoesNotSelectUnsentHeaders(t *testing.T) {
	creds := []credentialHeader{
		{Name: "Authorization", Value: "Bearer auth", Grant: "auth"},
		{Name: "X-Api-Key", Value: "real-key", Grant: "apikey"},
	}
	req := newInjectReq(t, map[string]string{"Authorization": "placeholder"})

	res := injectCredentials(req, creds, "example.test", "GET", "/x")

	if got := req.Header.Get("Authorization"); got != "Bearer auth" {
		t.Errorf("wire Authorization = %q, want %q", got, "Bearer auth")
	}
	if got := req.Header.Get("X-Api-Key"); got != "" {
		t.Errorf("X-Api-Key = %q, want empty (client never sent it)", got)
	}
	if got := grantsOf(res); !slices.Equal(got, []string{"auth"}) {
		t.Errorf("Grants = %v, want [auth]", got)
	}
	if res.InjectedHeaders["x-api-key"] {
		t.Error("InjectedHeaders marks x-api-key injected, but it was not")
	}
}

// Unchanged behavior: with no placeholder, auto-injection prefers the
// non-claude grant on a shared header name.
func TestInjectCredentials_AutoInjectPrefersNonClaude(t *testing.T) {
	creds := []credentialHeader{
		{Name: "Authorization", Value: "Bearer claude", Grant: "claude"},
		{Name: "Authorization", Value: "Bearer other", Grant: "other"},
	}
	req := newInjectReq(t, nil)

	res := injectCredentials(req, creds, "example.test", "GET", "/x")

	if got := req.Header.Get("Authorization"); got != "Bearer other" {
		t.Errorf("wire Authorization = %q, want %q", got, "Bearer other")
	}
	if got := grantsOf(res); !slices.Equal(got, []string{"other"}) {
		t.Errorf("Grants = %v, want [other] (claude must not be reported)", got)
	}
	if got := injectedGrantsOf(res); !slices.Equal(got, []string{"other"}) {
		t.Errorf("Injected = %v, want [other]", got)
	}
}

// Unchanged behavior: distinct header names are all auto-injected.
func TestInjectCredentials_AutoInjectDistinctHeaders(t *testing.T) {
	creds := []credentialHeader{
		{Name: "Authorization", Value: "Bearer a", Grant: "a"},
		{Name: "X-Api-Key", Value: "k", Grant: "b"},
	}
	req := newInjectReq(t, nil)

	res := injectCredentials(req, creds, "example.test", "GET", "/x")

	if got := req.Header.Get("Authorization"); got != "Bearer a" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer a")
	}
	if got := req.Header.Get("X-Api-Key"); got != "k" {
		t.Errorf("X-Api-Key = %q, want %q", got, "k")
	}
	if got := grantsOf(res); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("Grants = %v, want [a b]", got)
	}
}

// A placeholder on one header selects that credential; credentials for other
// headers are not auto-injected in the same request (existing behavior: the
// auto pass only runs when no placeholder matched).
func TestInjectCredentials_PlaceholderSuppressesAutoInject(t *testing.T) {
	creds := []credentialHeader{
		{Name: "Authorization", Value: "Bearer a", Grant: "a"},
		{Name: "X-Api-Key", Value: "k", Grant: "b"},
	}
	req := newInjectReq(t, map[string]string{"X-Api-Key": "placeholder"})

	res := injectCredentials(req, creds, "example.test", "GET", "/x")

	if got := req.Header.Get("X-Api-Key"); got != "k" {
		t.Errorf("X-Api-Key = %q, want %q", got, "k")
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization = %q, want empty", got)
	}
	if got := grantsOf(res); !slices.Equal(got, []string{"b"}) {
		t.Errorf("Grants = %v, want [b]", got)
	}
}

// Grants must never name a credential that did not reach the wire: the
// canonical log line is an audit record.
func TestInjectCredentials_GrantsNeverOverReport(t *testing.T) {
	creds := []credentialHeader{
		{Name: "Authorization", Value: "Bearer claude", Grant: "claude"},
		{Name: "Authorization", Value: "Bearer other", Grant: "other"},
		{Name: "Authorization", Value: "Bearer third", Grant: "third"},
	}

	for _, tc := range []struct {
		name       string
		clientHdrs map[string]string
		wantGrants []string
	}{
		{"placeholder", map[string]string{"Authorization": "ph"}, []string{"claude"}},
		{"auto", nil, []string{"other"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := newInjectReq(t, tc.clientHdrs)
			res := injectCredentials(req, creds, "example.test", "GET", "/x")

			if got := grantsOf(res); !slices.Equal(got, tc.wantGrants) {
				t.Errorf("Grants = %v, want %v", got, tc.wantGrants)
			}
			if len(res.Injected) != 1 {
				t.Errorf("Injected has %d creds, want 1", len(res.Injected))
			}
		})
	}
}

func TestInjectCredentials_Empty(t *testing.T) {
	req := newInjectReq(t, nil)
	res := injectCredentials(req, nil, "example.test", "GET", "/x")
	if len(res.Injected) != 0 || len(res.Grants) != 0 || len(res.InjectedHeaders) != 0 {
		t.Errorf("empty creds should produce an empty result, got %+v", res)
	}
}
