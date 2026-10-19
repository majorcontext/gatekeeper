package credentialsource

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
)

// stsReplying returns a source whose STS answers every exchange with status
// and body.
func stsReplying(t *testing.T, calls *atomic.Int32, status int, body string) *TokenExchangeSource {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return NewTokenExchangeSource(TokenExchangeConfig{Endpoint: srv.URL, ClientID: "gk", ClientSecret: "s", Resource: "https://compute.googleapis.com"})
}

const boxDecline = `{"error":"invalid_target","error_description":"no live grant; use the configured default",` +
	`"gatekeeper_fallback":"default","gatekeeper_upgrade":{"route":"gcp","entitlements":["gcp-deploy-dev","gcp-ssh-staging"]}}`

var boxHint = UpgradeHint{"route": {"gcp"}, "entitlements": {"gcp-deploy-dev", "gcp-ssh-staging"}}

// A box with no live grant on compute.googleapis.com must get the configured
// default, and the decline must be cached like a token so every request to a
// host with a static default does not call the STS.
func TestTokenExchange_DeclineIsTypedAndCached(t *testing.T) {
	var calls atomic.Int32
	src := stsReplying(t, &calls, http.StatusBadRequest, boxDecline)

	for i := range 2 {
		_, err := src.ResolveToken(context.Background(), "usr_1|box_1", "boxtoken", "")
		var declined *TokenExchangeDeclined
		if !errors.As(err, &declined) {
			t.Fatalf("request %d: err = %v, want *TokenExchangeDeclined", i, err)
		}
		if !reflect.DeepEqual(declined.Upgrade, boxHint) {
			t.Errorf("request %d: Upgrade = %v, want %v", i, declined.Upgrade, boxHint)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("STS calls = %d, want 1 (the decline is cached)", n)
	}
}

// Only the explicit decline falls back to the default. A misconfigured route
// also answers invalid_target, and treating it as a decline would silently
// replace a broken upgrade with the default credential.
func TestTokenExchange_ErrorsThatAreNotDeclines(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"bare invalid_target", http.StatusBadRequest, `{"error":"invalid_target"}`},
		{"unknown fallback", http.StatusBadRequest, `{"error":"invalid_target","gatekeeper_fallback":"anything"}`},
		{"fallback on another error", http.StatusBadRequest, `{"error":"invalid_grant","gatekeeper_fallback":"default"}`},
		{"fallback on a 401", http.StatusUnauthorized, `{"error":"invalid_target","gatekeeper_fallback":"default"}`},
		{"not JSON", http.StatusBadRequest, `invalid_target`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			src := stsReplying(t, &calls, tc.status, tc.body)
			for range 2 {
				_, err := src.ResolveToken(context.Background(), "usr_1|box_1", "boxtoken", "")
				var declined *TokenExchangeDeclined
				if err == nil || errors.As(err, &declined) {
					t.Fatalf("err = %v, want a failure that is not a decline", err)
				}
			}
			if n := calls.Load(); n != 2 {
				t.Errorf("STS calls = %d, want 2 (a failure is never cached)", n)
			}
		})
	}
}

func TestTokenExchange_UpgradeHintOnSuccessIsCached(t *testing.T) {
	var calls atomic.Int32
	src := stsReplying(t, &calls, http.StatusOK,
		`{"access_token":"gho_default","token_type":"Bearer","expires_in":3600,`+
			`"gatekeeper_upgrade":{"route":"github","entitlements":["github-admin"]}}`)

	want := UpgradeHint{"route": {"github"}, "entitlements": {"github-admin"}}
	for i := range 2 {
		tok, err := src.ResolveToken(context.Background(), "usr_1|box_1", "boxtoken", "")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if tok.AccessToken != "gho_default" {
			t.Errorf("request %d: AccessToken = %q, want gho_default", i, tok.AccessToken)
		}
		if !reflect.DeepEqual(tok.Upgrade, want) {
			t.Errorf("request %d: Upgrade = %v, want %v", i, tok.Upgrade, want)
		}
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("STS calls = %d, want 1", n)
	}
}

// A hint only guides the client. A malformed one must never cost the
// request its credential.
func TestTokenExchange_MalformedUpgradeHintIsDropped(t *testing.T) {
	for _, hint := range []string{`"gcp"`, `{"route":5}`, `{"route":["gcp",5]}`, `{"route":"gcp","entitlements":5}`, `[]`} {
		t.Run(hint, func(t *testing.T) {
			var calls atomic.Int32
			src := stsReplying(t, &calls, http.StatusOK,
				`{"access_token":"tok","token_type":"Bearer","gatekeeper_upgrade":`+hint+`}`)
			tok, err := src.ResolveToken(context.Background(), "usr_1|box_1", "boxtoken", "")
			if err != nil {
				t.Fatalf("ResolveToken: %v", err)
			}
			if tok.AccessToken != "tok" || tok.Upgrade != nil {
				t.Errorf("got %+v, want token %q and no hint", tok, "tok")
			}
		})
	}
}

// The owner approves a grant while the decline is cached. The agent's retry
// gets a 403 under the default credential; the proxy calls Invalidate, so
// the next request exchanges again and gets the upgraded token instead of
// waiting out the cache.
func TestTokenExchange_InvalidateEvictsDecline(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, boxDecline)
			return
		}
		io.WriteString(w, `{"access_token":"ya29.upgraded","token_type":"Bearer","expires_in":3600}`)
	}))
	t.Cleanup(srv.Close)
	src := NewTokenExchangeSource(TokenExchangeConfig{Endpoint: srv.URL, ClientID: "gk", ClientSecret: "s"})

	ctx := context.Background()
	var declined *TokenExchangeDeclined
	if _, err := src.ResolveToken(ctx, "usr_1|box_1", "boxtoken", ""); !errors.As(err, &declined) {
		t.Fatalf("first exchange: err = %v, want a decline", err)
	}
	src.Invalidate("usr_1|box_1", "boxtoken")
	tok, err := src.ResolveToken(ctx, "usr_1|box_1", "boxtoken", "")
	if err != nil {
		t.Fatalf("after Invalidate: %v", err)
	}
	if tok.AccessToken != "ya29.upgraded" {
		t.Errorf("after Invalidate: AccessToken = %q, want ya29.upgraded", tok.AccessToken)
	}
}

// A static default that the destination keeps refusing must not turn every
// request into an STS call: decline eviction shares Invalidate's per-key
// cooldown.
func TestTokenExchange_DeclineEvictionIsRateLimited(t *testing.T) {
	var calls atomic.Int32
	src := stsReplying(t, &calls, http.StatusBadRequest, boxDecline)
	ctx := context.Background()
	for range 5 {
		_, _ = src.ResolveToken(ctx, "usr_1|box_1", "boxtoken", "")
		src.Invalidate("usr_1|box_1", "boxtoken")
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("STS calls = %d, want 2 (one eviction per cooldown)", n)
	}
}
