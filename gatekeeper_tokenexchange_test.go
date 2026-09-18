package gatekeeper

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
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
			"expires_in":   28573, // what Neptune's STS returned in the incident
		})
	}))
	defer srv.Close()

	// The production config from the incident report.
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
// (proxy/proxy.go) reads that as "try the next credential for this host",
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

// TestNewTokenExchangeResolver_BotSubjectIgnoredOutsideProxyAuthMode is the
// defense-in-depth regression guard for a claude[bot] review finding on
// this PR (gatekeeper_tokenexchange.go:76, comment 3804897191): the
// fallthrough check originally ran after the cfg.SubjectFrom switch
// unconditionally, so subject_header mode (a header ANY caller controls --
// self-asserted, not proxy-auth) combined with a configured bot_subject let
// a caller simply send the sentinel value in the header to skip the STS
// entirely and fall through to the broader credential rule below it (e.g.
// a github-app bot credential), bypassing per-subject authentication for
// that host. This test constructs the resolver directly -- bypassing
// resolveTokenExchange's own config-level rejection of this combination
// (TestResolveTokenExchange_BotSubjectRequiresProxyAuth below) -- to prove
// the runtime gate on cfg.SubjectFrom == "proxy-auth" holds even if a
// caller reaches newTokenExchangeResolver some other way. bot_subject must
// be inert entirely outside proxy-auth mode: sending the configured
// sentinel value in the subject header must still reach the STS like any
// other subject, never fall through.
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

// TestResolveTokenExchange_BotSubjectRequiresProxyAuth is the config-level
// half of the fix for the same finding: reject bot_subject combined with
// anything other than subject_from: proxy-auth at config-load time,
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

// TestNewTokenExchangeResolver_BotSubjectActorTokenParityWithEmptySubject
// tests the premise behind a claude[bot] review comment on this PR
// (gatekeeper_tokenexchange.go:89, comment 3805148031): with
// actor_token_from: proxy-auth-password AND bot_subject both configured,
// a caller sending the sentinel with an EMPTY proxy-auth password hits the
// "requires a proxy auth password" error (lines 53-58) before ever
// reaching the bot_subject fallthrough check (line 89) -- the bot read
// that as a bug and suggested reordering the fallthrough ahead of the
// actor-token validation.
//
// That reordering would be wrong: this error fires unconditionally inside
// the "proxy-auth" case of the cfg.SubjectFrom switch, for ANY subject
// value the switch produces -- including a genuinely empty subject, which
// predates bot_subject entirely (this exact check shipped with actor-token
// forwarding, long before this PR). This test proves that by exercising
// BOTH subjects side by side, with the SAME actor_token_from config: an
// empty proxy-auth username and the configured bot_subject sentinel both
// hit the identical hard error, never the fallthrough. That is exact
// parity with pre-existing empty-subject treatment, not a new asymmetry
// bot_subject introduced -- reordering here would be a behavior change to
// that pre-existing empty-subject semantics, out of scope for this PR.
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
