package gatekeeper

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/majorcontext/gatekeeper/proxy"
)

func TestNewTokenExchangeResolver(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "gho_resolved",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type":        "Bearer",
			"expires_in":        3600,
		})
	}))
	defer srv.Close()

	resolver := newTokenExchangeResolver(tokenExchangeResolverConfig{
		Endpoint:      srv.URL,
		ClientID:      "gk",
		ClientSecret:  "secret",
		Resource:      "https://api.github.com",
		SubjectHeader: "X-Gatekeeper-Subject",
		Grant:         "github",
		Header:        "Authorization",
		Prefix:        "Bearer",
	})

	req := httptest.NewRequest("GET", "https://api.github.com/user", nil)
	req.Header.Set("X-Gatekeeper-Subject", "usr_abc123")

	creds, err := resolver(context.Background(), req, req, "api.github.com")
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("got %d creds, want 1", len(creds))
	}
	if creds[0].Value != "Bearer gho_resolved" {
		t.Errorf("Value = %q, want %q", creds[0].Value, "Bearer gho_resolved")
	}
	if creds[0].Grant != "github" {
		t.Errorf("Grant = %q, want %q", creds[0].Grant, "github")
	}

	// Subject header should be stripped
	if req.Header.Get("X-Gatekeeper-Subject") != "" {
		t.Error("subject header should be stripped from request")
	}
}

// Regression: a user's GitHub OAuth token went stale, so the STS handed
// gatekeeper an unauthorized token; gatekeeper cached it for the full
// expires_in (~8h, GitHub's remaining token lifetime). The user reconnected
// their GitHub account and the STS began returning a working token, but the
// proxy kept injecting the cached pre-reconnect one, and every push got a 403
// from github.com on /info/refs until the process was restarted.
//
// Invoking the credential's Invalidate hook — as the proxy now does on a 401 or
// 403 from the destination — must drop the stale entry so the next request
// carries the reconnected token.
func TestNewTokenExchangeResolver_InvalidateOnAuthFailureRecovers(t *testing.T) {
	var exchanges atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := exchanges.Add(1)
		token := "gho_stale_pre_reconnect"
		if n > 1 {
			token = "gho_fresh_post_reconnect"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": token,
			"token_type":   "Bearer",
			"expires_in":   28573, // observed advertised lifetime
		})
	}))
	defer srv.Close()

	resolver := newTokenExchangeResolver(tokenExchangeResolverConfig{
		Endpoint:       srv.URL,
		ClientID:       "gk",
		ClientSecret:   "secret",
		SubjectFrom:    "proxy-auth",
		ActorTokenFrom: "proxy-auth-password",
		Grant:          "github-user",
		Header:         "Authorization",
		Prefix:         "x-access-token",
		Format:         "basic",
	})

	newReq := func() *http.Request {
		req := httptest.NewRequest("GET", "https://github.com/meetneptune/web.git/info/refs", nil)
		req.SetBasicAuth("usr_abc", "ak_run_token")
		req.Header.Set("Proxy-Authorization", req.Header.Get("Authorization"))
		req.Header.Del("Authorization")
		return req
	}

	req := newReq()
	creds, err := resolver(context.Background(), req, req, "github.com")
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("got %d creds, want 1", len(creds))
	}
	if !strings.Contains(decodeBasic(t, creds[0].Value), "gho_stale_pre_reconnect") {
		t.Fatalf("first credential = %q, want the stale token", creds[0].Value)
	}

	// Without invalidation the stale token is served for the full ~8h TTL.
	req = newReq()
	again, err := resolver(context.Background(), req, req, "github.com")
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	if again[0].Value != creds[0].Value {
		t.Fatalf("expected the cached token on a repeat request")
	}
	if n := exchanges.Load(); n != 1 {
		t.Fatalf("STS exchanges = %d, want 1 (second request should be cached)", n)
	}

	// github.com answers /info/refs with 403; the proxy calls Invalidate.
	if creds[0].Invalidate == nil {
		t.Fatal("token-exchange credential has no Invalidate hook")
	}
	creds[0].Invalidate()

	req = newReq()
	recovered, err := resolver(context.Background(), req, req, "github.com")
	if err != nil {
		t.Fatalf("resolver after invalidate: %v", err)
	}
	if got := decodeBasic(t, recovered[0].Value); !strings.Contains(got, "gho_fresh_post_reconnect") {
		t.Errorf("credential after invalidate = %q, want the reconnected token", got)
	}
	if n := exchanges.Load(); n != 2 {
		t.Errorf("STS exchanges = %d, want 2", n)
	}
}

// decodeBasic returns the decoded user:pass of a "Basic <b64>" header value.
func decodeBasic(t *testing.T, headerValue string) string {
	t.Helper()
	encoded, ok := strings.CutPrefix(headerValue, "Basic ")
	if !ok {
		t.Fatalf("header value %q is not Basic-encoded", headerValue)
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decoding %q: %v", encoded, err)
	}
	return string(decoded)
}

// TestNewTokenExchangeResolver_BotSubjectFallsThrough proves a configured
// bot_subject sentinel gets exactly the same (nil, nil) fallthrough
// treatment as an empty proxy-auth subject: getCredentialsForRequest
// reads that as "try the next credential for this host",
// which is how a per-host github-app (bot) credential rule is expected to
// take over -- see the boxes configmap's "per-user token-exchange, then
// github-app bot fallback" credential-rule ordering. The STS must never be
// called for the sentinel: it is not a real subject to exchange, and
// calling out for it would leak the sentinel to an external service and
// burn a round trip for no reason.
func TestNewTokenExchangeResolver_BotSubjectFallsThrough(t *testing.T) {
	var stsCalled atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stsCalled.Store(true)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "gho_should_not_be_used",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	resolver := newTokenExchangeResolver(tokenExchangeResolverConfig{
		Endpoint:     srv.URL,
		ClientID:     "gk",
		ClientSecret: "secret",
		SubjectFrom:  "proxy-auth",
		BotSubject:   "-",
		Grant:        "github",
		Header:       "Authorization",
		Prefix:       "Bearer",
	})

	proxyReq, _ := http.NewRequest("CONNECT", "http://api.github.com:443", nil)
	proxyReq.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("-:ak_bot_proxy_token")))
	innerReq := httptest.NewRequest("GET", "https://api.github.com/user", nil)

	creds, err := resolver(context.Background(), proxyReq, innerReq, "api.github.com")
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("got %d creds, want 0 (sentinel subject must fall through to the next credential, like an empty subject)", len(creds))
	}
	if stsCalled.Load() {
		t.Error("STS must not be called for the bot_subject sentinel")
	}
}

// TestNewTokenExchangeResolver_BotSubjectUnconfigured_NoSpecialCasing proves
// back-compat: with no bot_subject configured (the zero value, matching
// every config written before this field existed), a subject that happens
// to equal a plausible sentinel string is not special-cased -- it is
// exchanged with the STS exactly like any other subject.
func TestNewTokenExchangeResolver_BotSubjectUnconfigured_NoSpecialCasing(t *testing.T) {
	var stsCalled atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stsCalled.Store(true)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "gho_resolved",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	resolver := newTokenExchangeResolver(tokenExchangeResolverConfig{
		Endpoint:      srv.URL,
		ClientID:      "gk",
		ClientSecret:  "secret",
		SubjectHeader: "X-Gatekeeper-Subject",
		// BotSubject deliberately left unset.
		Grant:  "github",
		Header: "Authorization",
		Prefix: "Bearer",
	})

	req := httptest.NewRequest("GET", "https://api.github.com/user", nil)
	req.Header.Set("X-Gatekeeper-Subject", "-")

	creds, err := resolver(context.Background(), req, req, "api.github.com")
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("got %d creds, want 1 (no bot_subject configured, so \"-\" is an ordinary subject)", len(creds))
	}
	if !stsCalled.Load() {
		t.Error("STS should have been called: with no bot_subject configured, \"-\" is not special")
	}
}

// TestResolveTokenExchange_BotSubjectWiring proves resolveTokenExchange
// plumbs Source.BotSubject (the credential config's bot_subject field)
// through to the resolver it builds, end to end from CredentialConfig.
func TestResolveTokenExchange_BotSubjectWiring(t *testing.T) {
	var stsCalled atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stsCalled.Store(true)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "gho_resolved",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	resolver, err := resolveTokenExchange(CredentialConfig{
		Host: "api.github.com",
		Source: SourceConfig{
			Type:         "token-exchange",
			Endpoint:     srv.URL,
			ClientID:     "gk",
			ClientSecret: "secret",
			SubjectFrom:  "proxy-auth",
			BotSubject:   "-",
		},
		Grant: "github-bot",
	})
	if err != nil {
		t.Fatalf("resolveTokenExchange: %v", err)
	}

	proxyReq, _ := http.NewRequest("CONNECT", "http://api.github.com:443", nil)
	proxyReq.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("-:ak_bot_proxy_token")))
	innerReq := httptest.NewRequest("GET", "https://api.github.com/user", nil)

	creds, err := resolver(context.Background(), proxyReq, innerReq, "api.github.com")
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("got %d creds, want 0 (bot_subject from CredentialConfig.Source must fall through)", len(creds))
	}
	if stsCalled.Load() {
		t.Error("STS must not be called for the bot_subject sentinel")
	}
}

// TestNewTokenExchangeResolver_BotSubjectIgnoredOutsideProxyAuthMode pins that
// bot_subject is inert outside proxy-auth mode. In subject_header mode the
// caller controls the header, so sending the sentinel must still reach the STS
// and never fall through to a broader credential rule. The test builds the
// resolver directly to bypass the config-level rejection.
func TestNewTokenExchangeResolver_BotSubjectIgnoredOutsideProxyAuthMode(t *testing.T) {
	var stsCalled atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stsCalled.Store(true)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "gho_resolved",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	resolver := newTokenExchangeResolver(tokenExchangeResolverConfig{
		Endpoint:      srv.URL,
		ClientID:      "gk",
		ClientSecret:  "secret",
		SubjectHeader: "X-Gatekeeper-Subject",
		BotSubject:    "-",
		Grant:         "github",
		Header:        "Authorization",
		Prefix:        "Bearer",
	})

	req := httptest.NewRequest("GET", "https://api.github.com/user", nil)
	req.Header.Set("X-Gatekeeper-Subject", "-")

	creds, err := resolver(context.Background(), req, req, "api.github.com")
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("got %d creds, want 1 (subject_header mode must exchange the sentinel value with the STS like any other subject, never fall through)", len(creds))
	}
	if !stsCalled.Load() {
		t.Error("STS should have been called: bot_subject must be inert in subject_header mode")
	}
}

// TestResolveTokenExchange_BotSubjectRequiresProxyAuth pins that config
// load rejects bot_subject combined with anything other than
// subject_from: proxy-auth,
// mirroring the existing actor_token_from/subject_from mutual-exclusion
// check just above resolveTokenExchange in this file. Belt (this
// validation) and suspenders (the runtime gate proven by
// TestNewTokenExchangeResolver_BotSubjectIgnoredOutsideProxyAuthMode
// above) for a credential-injection code path.
func TestResolveTokenExchange_BotSubjectRequiresProxyAuth(t *testing.T) {
	_, err := resolveTokenExchange(CredentialConfig{
		Host: "api.github.com",
		Source: SourceConfig{
			Type:          "token-exchange",
			Endpoint:      "https://sts.example.com/token",
			ClientID:      "gk",
			ClientSecret:  "secret",
			SubjectHeader: "X-Gatekeeper-Subject",
			BotSubject:    "-",
		},
	})
	if err == nil {
		t.Fatal("expected error: bot_subject with subject_header mode must be rejected at config load")
	}
	if !strings.Contains(err.Error(), "bot_subject") || !strings.Contains(err.Error(), "proxy-auth") {
		t.Errorf("error = %q, want it to name both bot_subject and proxy-auth", err)
	}
}

// TestNewTokenExchangeResolver_BotSubjectActorTokenParityWithEmptySubject pins
// that with actor_token_from: proxy-auth-password, an empty proxy-auth username
// and the bot_subject sentinel both hit the same actor-token error and never
// the fallthrough.
func TestNewTokenExchangeResolver_BotSubjectActorTokenParityWithEmptySubject(t *testing.T) {
	resolver := newTokenExchangeResolver(tokenExchangeResolverConfig{
		Endpoint:       "http://unused",
		ClientID:       "gk",
		ClientSecret:   "secret",
		SubjectFrom:    "proxy-auth",
		ActorTokenFrom: "proxy-auth-password",
		BotSubject:     "-",
		Grant:          "github",
		Header:         "Authorization",
		Prefix:         "Bearer",
	})

	newReqWithProxyAuth := func(username string) *http.Request {
		req, _ := http.NewRequest("CONNECT", "http://api.github.com:443", nil)
		// Empty password: base64("username:") -- extractProxyAuthCredentials
		// splits on the first colon, so this decodes to (username, "").
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":")))
		return req
	}
	innerReq := httptest.NewRequest("GET", "https://api.github.com/user", nil)

	wantErrSubstr := `actor_token_from "proxy-auth-password" requires a proxy auth password`

	t.Run("empty subject, empty password", func(t *testing.T) {
		proxyReq := newReqWithProxyAuth("")
		creds, err := resolver(context.Background(), proxyReq, innerReq, "api.github.com")
		if err == nil {
			t.Fatalf("resolver returned (creds=%v, err=nil), want the actor-token-password error", creds)
		}
		if !strings.Contains(err.Error(), wantErrSubstr) {
			t.Errorf("error = %q, want it to contain %q", err, wantErrSubstr)
		}
		if creds != nil {
			t.Errorf("creds = %v, want nil alongside the error", creds)
		}
	})

	t.Run("bot_subject sentinel, empty password", func(t *testing.T) {
		proxyReq := newReqWithProxyAuth("-")
		creds, err := resolver(context.Background(), proxyReq, innerReq, "api.github.com")
		if err == nil {
			t.Fatalf("resolver returned (creds=%v, err=nil), want the SAME actor-token-password error the empty-subject case gets", creds)
		}
		if !strings.Contains(err.Error(), wantErrSubstr) {
			t.Errorf("error = %q, want it to contain %q -- exact parity with the empty-subject case, not a new fallthrough path", err, wantErrSubstr)
		}
		if creds != nil {
			t.Errorf("creds = %v, want nil alongside the error", creds)
		}
	})
}

func TestNewTokenExchangeResolver_NoSubjectHeader(t *testing.T) {
	resolver := newTokenExchangeResolver(tokenExchangeResolverConfig{
		Endpoint:      "http://unused",
		ClientID:      "gk",
		ClientSecret:  "secret",
		SubjectHeader: "X-Gatekeeper-Subject",
		Grant:         "github",
		Header:        "Authorization",
	})

	req := httptest.NewRequest("GET", "https://api.github.com/user", nil)
	// No X-Gatekeeper-Subject header set

	creds, err := resolver(context.Background(), req, req, "api.github.com")
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("got %d creds, want 0 (no subject header means skip)", len(creds))
	}
}

func TestExtractProxyAuthCredentials(t *testing.T) {
	tests := []struct {
		name         string
		auth         string
		wantUser     string
		wantPassword string
	}{
		{"basic with email", "Basic " + base64.StdEncoding.EncodeToString([]byte("alice@example.com:token123")), "alice@example.com", "token123"},
		{"basic with simple user", "Basic " + base64.StdEncoding.EncodeToString([]byte("bob:secret")), "bob", "secret"},
		{"basic with empty username", "Basic " + base64.StdEncoding.EncodeToString([]byte(":token")), "", "token"},
		{"basic with empty password", "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:")), "alice", ""},
		{"bearer token", "Bearer some-token", "", ""},
		{"no auth header", "", "", ""},
		{"invalid base64", "Basic !!!invalid!!!", "", ""},
		{"basic no colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon")), "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest("CONNECT", "http://example.com:443", nil)
			if tt.auth != "" {
				r.Header.Set("Proxy-Authorization", tt.auth)
			}
			gotUser, gotPassword := extractProxyAuthCredentials(r)
			if gotUser != tt.wantUser {
				t.Errorf("username = %q, want %q", gotUser, tt.wantUser)
			}
			if gotPassword != tt.wantPassword {
				t.Errorf("password = %q, want %q", gotPassword, tt.wantPassword)
			}
		})
	}
}

func TestNewTokenExchangeResolver_ActorTokenFromProxyAuth(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "gho_resolved",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	resolver := newTokenExchangeResolver(tokenExchangeResolverConfig{
		Endpoint:       srv.URL,
		ClientID:       "gk",
		ClientSecret:   "secret",
		Resource:       "https://api.github.com",
		SubjectFrom:    "proxy-auth",
		ActorTokenFrom: "proxy-auth-password",
		Grant:          "github",
		Header:         "Authorization",
		Prefix:         "Bearer",
	})

	proxyReq, _ := http.NewRequest("CONNECT", "http://api.github.com:443", nil)
	proxyReq.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice@example.com:ak_alice_xxx")))

	innerReq := httptest.NewRequest("GET", "https://api.github.com/user", nil)

	creds, err := resolver(context.Background(), proxyReq, innerReq, "api.github.com")
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("got %d creds, want 1", len(creds))
	}
	if creds[0].Value != "Bearer gho_resolved" {
		t.Errorf("Value = %q, want %q", creds[0].Value, "Bearer gho_resolved")
	}

	if !strings.Contains(gotBody, "actor_token=ak_alice_xxx") {
		t.Errorf("STS body missing actor_token, got: %s", gotBody)
	}
	if !strings.Contains(gotBody, "actor_token_type=") {
		t.Errorf("STS body missing actor_token_type, got: %s", gotBody)
	}
	if !strings.Contains(gotBody, "subject_token=alice%40example.com") {
		t.Errorf("STS body missing subject_token, got: %s", gotBody)
	}
}

func TestNewTokenExchangeResolver_NoActorTokenWithoutConfig(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "gho_resolved",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	resolver := newTokenExchangeResolver(tokenExchangeResolverConfig{
		Endpoint:     srv.URL,
		ClientID:     "gk",
		ClientSecret: "secret",
		SubjectFrom:  "proxy-auth",
		Grant:        "github",
		Header:       "Authorization",
		Prefix:       "Bearer",
	})

	proxyReq, _ := http.NewRequest("CONNECT", "http://api.github.com:443", nil)
	proxyReq.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice@example.com:ak_alice_xxx")))

	innerReq := httptest.NewRequest("GET", "https://api.github.com/user", nil)

	_, err := resolver(context.Background(), proxyReq, innerReq, "api.github.com")
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}

	if strings.Contains(gotBody, "actor_token") {
		t.Errorf("STS body should not contain actor_token when actor_token_from is not configured, got: %s", gotBody)
	}
}

func TestNewTokenExchangeResolver_ActorTokenRequiredButMissing(t *testing.T) {
	var stsCalled atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stsCalled.Store(true)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "gho_resolved",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	resolver := newTokenExchangeResolver(tokenExchangeResolverConfig{
		Endpoint:       srv.URL,
		ClientID:       "gk",
		ClientSecret:   "secret",
		SubjectFrom:    "proxy-auth",
		ActorTokenFrom: "proxy-auth-password",
		Grant:          "github",
		Header:         "Authorization",
		Prefix:         "Bearer",
	})

	proxyReq, _ := http.NewRequest("CONNECT", "http://api.github.com:443", nil)
	proxyReq.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice@example.com:")))

	innerReq := httptest.NewRequest("GET", "https://api.github.com/user", nil)

	_, err := resolver(context.Background(), proxyReq, innerReq, "api.github.com")
	if err == nil {
		t.Fatal("expected error when actor_token_from is configured but password is empty")
	}
	if !strings.Contains(err.Error(), "requires a proxy auth password") {
		t.Errorf("error = %q, want to contain 'requires a proxy auth password'", err)
	}
	if stsCalled.Load() {
		t.Error("STS should not be called when actor_token_from is configured but password is empty")
	}
}

func TestExtractProxyAuthCredentials_PasswordWithColons(t *testing.T) {
	r, _ := http.NewRequest("CONNECT", "http://example.com:443", nil)
	r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:pass:with:colons")))
	gotUser, gotPassword := extractProxyAuthCredentials(r)
	if gotUser != "alice" {
		t.Errorf("username = %q, want %q", gotUser, "alice")
	}
	if gotPassword != "pass:with:colons" {
		t.Errorf("password = %q, want %q", gotPassword, "pass:with:colons")
	}
}

func TestExtractProxyAuthCredentials_NilRequest(t *testing.T) {
	gotUser, gotPassword := extractProxyAuthCredentials(nil)
	if gotUser != "" {
		t.Errorf("username = %q, want empty", gotUser)
	}
	if gotPassword != "" {
		t.Errorf("password = %q, want empty", gotPassword)
	}
}

func TestResolveTokenExchange_ActorTokenFromValidation(t *testing.T) {
	tests := []struct {
		name    string
		cred    CredentialConfig
		wantErr string
	}{
		{
			name: "unsupported actor_token_from value",
			cred: CredentialConfig{
				Host: "api.github.com",
				Source: SourceConfig{
					Type:           "token-exchange",
					Endpoint:       "https://sts.example.com/token",
					ClientID:       "gk",
					ClientSecret:   "secret",
					SubjectFrom:    "proxy-auth",
					ActorTokenFrom: "magic",
				},
			},
			wantErr: "unsupported actor_token_from",
		},
		{
			name: "actor_token_from requires proxy-auth subject",
			cred: CredentialConfig{
				Host: "api.github.com",
				Source: SourceConfig{
					Type:           "token-exchange",
					Endpoint:       "https://sts.example.com/token",
					ClientID:       "gk",
					ClientSecret:   "secret",
					SubjectHeader:  "X-Subject",
					ActorTokenFrom: "proxy-auth-password",
				},
			},
			wantErr: "requires subject_from 'proxy-auth'",
		},
		{
			name: "valid actor_token_from with proxy-auth",
			cred: CredentialConfig{
				Host: "api.github.com",
				Source: SourceConfig{
					Type:           "token-exchange",
					Endpoint:       "https://sts.example.com/token",
					ClientID:       "gk",
					ClientSecret:   "secret",
					SubjectFrom:    "proxy-auth",
					ActorTokenFrom: "proxy-auth-password",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resolveTokenExchange(tt.cred)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want to contain %q", err, tt.wantErr)
			}
		})
	}
}

// A box with no live grant gets the host's configured static credential,
// sees the STS hint on the destination's 403, and its retry after the grant
// is approved gets the upgraded token without waiting out the cached
// decline.
func TestTokenExchangeDecline_FallsBackToConfiguredDefault(t *testing.T) {
	var exchanges atomic.Int32
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if exchanges.Add(1) == 1 {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"error":"invalid_target","gatekeeper_fallback":"default",`+
				`"gatekeeper_upgrade":{"route":"gcp","entitlements":["gcp-ssh-staging"]}}`)
			return
		}
		io.WriteString(w, `{"access_token":"ya29.upgraded","token_type":"Bearer","expires_in":3600}`)
	}))
	defer sts.Close()
	var gotAuth []string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		if r.Header.Get("Authorization") != "Bearer ya29.upgraded" {
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer backend.Close()
	port := mustURL(t, backend.URL).Port()

	srv := newBareServer(t)
	cfg := &Config{Credentials: []CredentialConfig{
		{Host: "127.0.0.1", Grant: "gcp-box", AllowInsecure: true, Source: SourceConfig{
			Type: "token-exchange", Endpoint: sts.URL, ClientID: "c", ClientSecret: "s", SubjectHeader: "X-Subject"}},
		{Host: "127.0.0.1", Grant: "gcp-config", AllowInsecure: true, Source: SourceConfig{Type: "static", Value: "default-token"}},
	}}
	if err := srv.loadCredentials(context.Background(), cfg); err != nil {
		t.Fatalf("loadCredentials: %v", err)
	}

	var hints []string
	for range 2 {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:"+port+"/compute/v1/projects", nil)
		req.Header.Set("X-Subject", "usr_1|box_1")
		rec := httptest.NewRecorder()
		srv.proxy.ServeHTTP(rec, req)
		hints = append(hints, rec.Header().Get(proxy.UpgradeHintHeader))
	}

	if want := []string{"Bearer default-token", "Bearer ya29.upgraded"}; !slices.Equal(gotAuth, want) {
		t.Errorf("upstream Authorization = %q, want %q", gotAuth, want)
	}
	if want := []string{`entitlements=("gcp-ssh-staging"), route=("gcp")`, ""}; !slices.Equal(hints, want) {
		t.Errorf("%s = %q, want %q", proxy.UpgradeHintHeader, hints, want)
	}
	if n := exchanges.Load(); n != 2 {
		t.Errorf("STS exchanges = %d, want 2", n)
	}
}

// A box with no subscription subject (the bot sentinel) sends the claude
// CLI's OAuth request to api.anthropic.com. With static_fallback explicit,
// gatekeeper must refuse it instead of injecting the static x-api-key, and a
// declined exchange must be refused the same way. A request that sends its
// own x-api-key still gets the static key.
func TestStaticFallbackExplicit_RefusesSubscriptionFallthrough(t *testing.T) {
	const decline = `{"error":"invalid_target","gatekeeper_fallback":"default"}`
	const noAccount = `{"error":"invalid_grant","error_description":"no Claude subscription is connected for this box's creator"}`
	for _, tc := range []struct {
		name, user string
		fallback   string
		stsStatus  int
		stsBody    string
		headers    map[string]string
		wantStatus int
		wantAPIKey string
		wantSTS    int32
		wantInBody string
	}{
		{"bot subject, OAuth request", "-", "explicit", 400, decline, map[string]string{"Authorization": "Bearer placeholder"}, http.StatusForbidden, "", 0, "claude-code-user"},
		{"declined exchange, OAuth request", "usr_1|box_1", "explicit", 400, decline, map[string]string{"Authorization": "Bearer placeholder"}, http.StatusForbidden, "", 1, "claude-code-user"},
		{"bot subject, client names x-api-key", "-", "explicit", 400, decline, map[string]string{"X-Api-Key": "placeholder"}, http.StatusOK, "default-key", 0, ""},
		{"subject with no account, OAuth request", "usr_1|box_1", "explicit", 404, noAccount, map[string]string{"Authorization": "Bearer placeholder"}, http.StatusForbidden, "", 1, "no Claude subscription is connected"},
		{"subject with no account, auto fallback", "usr_1|box_1", "auto", 404, noAccount, map[string]string{"Authorization": "Bearer placeholder"}, http.StatusBadGateway, "", 1, ""},
		{"STS 401 stays a failure", "usr_1|box_1", "explicit", 401, `{"error":"invalid_client"}`, map[string]string{"Authorization": "Bearer placeholder"}, http.StatusBadGateway, "", 1, ""},
		{"STS 500 stays a failure", "usr_1|box_1", "explicit", 500, `{"error":"server_error"}`, map[string]string{"Authorization": "Bearer placeholder"}, http.StatusBadGateway, "", 1, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var exchanges atomic.Int32
			sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				exchanges.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.stsStatus)
				io.WriteString(w, tc.stsBody)
			}))
			defer sts.Close()
			var gotAPIKey []string
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAPIKey = append(gotAPIKey, r.Header.Get("X-Api-Key"))
			}))
			defer backend.Close()
			port := mustURL(t, backend.URL).Port()

			srv := newBareServer(t)
			cfg := &Config{Credentials: []CredentialConfig{
				{Host: "127.0.0.1", Grant: "claude-code-user", AllowInsecure: true, Source: SourceConfig{
					Type: "token-exchange", Endpoint: sts.URL, ClientID: "c", ClientSecret: "s",
					SubjectFrom: "proxy-auth", BotSubject: "-", StaticFallback: tc.fallback}},
				{Host: "127.0.0.1", Grant: "anthropic", Header: "x-api-key", Prefix: "", AllowInsecure: true,
					Source: SourceConfig{Type: "static", Value: "default-key"}},
			}}
			if err := srv.loadCredentials(context.Background(), cfg); err != nil {
				t.Fatalf("loadCredentials: %v", err)
			}
			req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:"+port+"/v1/messages", nil)
			req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(tc.user+":boxtoken")))
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			srv.proxy.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if tc.wantInBody != "" && !strings.Contains(rec.Body.String(), tc.wantInBody) {
				t.Errorf("body = %q, want it to contain %q", rec.Body.String(), tc.wantInBody)
			}
			var want []string
			if tc.wantStatus == http.StatusOK {
				want = []string{tc.wantAPIKey}
			}
			if !slices.Equal(gotAPIKey, want) {
				t.Errorf("upstream x-api-key = %q, want %q", gotAPIKey, want)
			}
			if n := exchanges.Load(); n != tc.wantSTS {
				t.Errorf("STS exchanges = %d, want %d", n, tc.wantSTS)
			}
		})
	}
}

func TestStaticFallback_Validation(t *testing.T) {
	te := func(fallback string) SourceConfig {
		return SourceConfig{Type: "token-exchange", Endpoint: "http://sts", ClientID: "c", ClientSecret: "s",
			SubjectFrom: "proxy-auth", StaticFallback: fallback}
	}
	for _, tc := range []struct {
		name    string
		source  SourceConfig
		wantErr bool
	}{
		{"token-exchange default", te(""), false},
		{"token-exchange auto", te("auto"), false},
		{"token-exchange explicit", te("explicit"), false},
		{"token-exchange unknown value", te("never"), true},
		{"static source", SourceConfig{Type: "static", Value: "v", StaticFallback: "explicit"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.source.Type == "token-exchange" {
				_, err = resolveTokenExchange(CredentialConfig{Host: "api.anthropic.com", Source: tc.source})
			} else {
				_, err = resolveSource(tc.source)
			}
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("err = %v, want error %v", err, tc.wantErr)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "static_fallback") {
				t.Errorf("err = %v, want it to name static_fallback", err)
			}
		})
	}
}

func TestMatchedTokenExchangeRules_EndToEnd(t *testing.T) {
	newSTS := func(token string, calls *atomic.Int32) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"access_token":"`+token+`","token_type":"Bearer","expires_in":3600}`)
		}))
	}
	var subCalls, apiCalls atomic.Int32
	subSTS := newSTS("sub-token", &subCalls)
	defer subSTS.Close()
	apiSTS := newSTS("api-token", &apiCalls)
	defer apiSTS.Close()
	var gotAuth, gotAPIKey, gotSubject []string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSubject = append(gotSubject, r.Header.Get("X-Subject"))
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		gotAPIKey = append(gotAPIKey, r.Header.Get("X-Api-Key"))
	}))
	defer backend.Close()
	port := mustURL(t, backend.URL).Port()

	srv := newBareServer(t)
	cfg := &Config{Credentials: []CredentialConfig{
		{Host: "127.0.0.1", Grant: "claude-code-user", AllowInsecure: true, Match: &MatchConfig{Header: "Authorization"},
			Source: SourceConfig{Type: "token-exchange", Endpoint: subSTS.URL, ClientID: "c", ClientSecret: "s", SubjectHeader: "X-Subject"}},
		{Host: "127.0.0.1", Grant: "claude-api", Header: "Authorization", AllowInsecure: true, Match: &MatchConfig{Header: "x-api-key"},
			Source: SourceConfig{Type: "token-exchange", Endpoint: apiSTS.URL, ClientID: "c", ClientSecret: "s", SubjectHeader: "X-Subject",
				Resource: "https://api.anthropic.com/workload"}},
	}}
	if err := srv.loadCredentials(context.Background(), cfg); err != nil {
		t.Fatalf("loadCredentials: %v", err)
	}
	do := func(h, v string) {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:"+port+"/v1/messages", nil)
		req.Header.Set("X-Subject", "usr_1")
		if h != "" {
			req.Header.Set(h, v)
		}
		rec := httptest.NewRecorder()
		srv.proxy.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s request: status %d: %s", h, rec.Code, rec.Body)
		}
	}
	do("Authorization", "Bearer placeholder")
	do("X-Api-Key", "placeholder")
	do("", "")

	if want := []string{"Bearer sub-token", "Bearer api-token", ""}; !slices.Equal(gotAuth, want) {
		t.Errorf("upstream Authorization = %q, want %q", gotAuth, want)
	}
	if want := []string{"", "", ""}; !slices.Equal(gotSubject, want) {
		t.Errorf("upstream X-Subject = %q, want %q", gotSubject, want)
	}
	if want := []string{"", "", ""}; !slices.Equal(gotAPIKey, want) {
		t.Errorf("upstream X-Api-Key = %q, want %q", gotAPIKey, want)
	}
	if subCalls.Load() != 1 || apiCalls.Load() != 1 {
		t.Errorf("STS calls = %d and %d, want 1 and 1", subCalls.Load(), apiCalls.Load())
	}
}
