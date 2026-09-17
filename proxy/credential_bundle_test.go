package proxy

import (
	"net/http"
	"testing"
)

func codexTestBundle() CredentialBundle {
	return CredentialBundle{
		ID:    "codex-subscription-v1",
		Grant: "codex",
		Scope: CredentialScope{
			RequireTLS:   true,
			Origins:      []string{"https://chatgpt.com"},
			Methods:      []string{"POST"},
			PathPrefixes: []string{"/backend-api/codex"},
		},
		RequireAll: true,
		Replacements: []HeaderReplacement{
			{Name: "Authorization", Placeholder: "Bearer fake-access", Value: "Bearer real-access"},
			{Name: "ChatGPT-Account-ID", Placeholder: "fake-account", Value: "real-account"},
		},
	}
}

func TestInjectCredentialBundles_ReplacesAllHeadersAtomically(t *testing.T) {
	req, err := http.NewRequest("POST", "https://chatgpt.com/backend-api/codex/responses", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer fake-access")
	req.Header.Set("ChatGPT-Account-ID", "fake-account")

	res := injectCredentialBundles(req, []CredentialBundle{codexTestBundle()}, "https", "chatgpt.com")

	if res.Denied {
		t.Fatalf("bundle denied: %s", res.Reason)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer real-access" {
		t.Errorf("Authorization = %q, want real access token", got)
	}
	if got := req.Header.Get("ChatGPT-Account-ID"); got != "real-account" {
		t.Errorf("ChatGPT-Account-ID = %q, want real account ID", got)
	}
	if len(res.Injected) != 2 || len(res.Grants) != 1 || res.Grants[0] != "codex" {
		t.Errorf("unexpected injection result: %+v", res)
	}
}

func TestInjectCredentialBundles_FailsClosedWithoutMutating(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		url     string
		scheme  string
		host    string
		auth    string
		account string
	}{
		{name: "plain HTTP", method: "POST", url: "http://chatgpt.com/backend-api/codex/responses", scheme: "http", host: "chatgpt.com", auth: "Bearer fake-access", account: "fake-account"},
		{name: "wrong origin", method: "POST", url: "https://evil.example/backend-api/codex/responses", scheme: "https", host: "evil.example", auth: "Bearer fake-access", account: "fake-account"},
		{name: "wrong method", method: "GET", url: "https://chatgpt.com/backend-api/codex/responses", scheme: "https", host: "chatgpt.com", auth: "Bearer fake-access", account: "fake-account"},
		{name: "wrong path", method: "POST", url: "https://chatgpt.com/other", scheme: "https", host: "chatgpt.com", auth: "Bearer fake-access", account: "fake-account"},
		{name: "adjacent prefix", method: "POST", url: "https://chatgpt.com/backend-api/codexevil", scheme: "https", host: "chatgpt.com", auth: "Bearer fake-access", account: "fake-account"},
		{name: "encoded traversal", method: "POST", url: "https://chatgpt.com/backend-api/codex/%2e%2e/other", scheme: "https", host: "chatgpt.com", auth: "Bearer fake-access", account: "fake-account"},
		{name: "missing account", method: "POST", url: "https://chatgpt.com/backend-api/codex/responses", scheme: "https", host: "chatgpt.com", auth: "Bearer fake-access"},
		{name: "wrong placeholder", method: "POST", url: "https://chatgpt.com/backend-api/codex/responses", scheme: "https", host: "chatgpt.com", auth: "Bearer attacker-value", account: "fake-account"},
		// A plain "ws" scheme is as insecure as "http" and must fail RequireTLS
		// the same way; an upgrade is not an exemption.
		{name: "insecure websocket", method: "GET", url: "ws://chatgpt.com/backend-api/codex/ws", scheme: "ws", host: "chatgpt.com", auth: "Bearer fake-access", account: "fake-account"},
		// Unencoded dot segments, backslashes, and a doubled separator are all
		// ways to write a path that does not mean what the prefix check reads.
		{name: "dot segment", method: "POST", url: "https://chatgpt.com/backend-api/codex/../other", scheme: "https", host: "chatgpt.com", auth: "Bearer fake-access", account: "fake-account"},
		{name: "backslash separator", method: "POST", url: "https://chatgpt.com/backend-api%5Ccodex/responses", scheme: "https", host: "chatgpt.com", auth: "Bearer fake-access", account: "fake-account"},
		{name: "doubled separator", method: "POST", url: "https://chatgpt.com//backend-api/codex/responses", scheme: "https", host: "chatgpt.com", auth: "Bearer fake-access", account: "fake-account"},
		// A non-default port is a different origin.
		{name: "non-default port", method: "POST", url: "https://chatgpt.com:8443/backend-api/codex/responses", scheme: "https", host: "chatgpt.com:8443", auth: "Bearer fake-access", account: "fake-account"},
		// Only one of the two placeholders present: RequireAll means neither is
		// replaced, so a partial bundle can never reach upstream.
		{name: "missing authorization", method: "POST", url: "https://chatgpt.com/backend-api/codex/responses", scheme: "https", host: "chatgpt.com", account: "fake-account"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, tc.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			if tc.account != "" {
				req.Header.Set("ChatGPT-Account-ID", tc.account)
			}
			beforeAuth, beforeAccount := req.Header.Get("Authorization"), req.Header.Get("ChatGPT-Account-ID")

			res := injectCredentialBundles(req, []CredentialBundle{codexTestBundle()}, tc.scheme, tc.host)

			if !res.Denied {
				t.Fatal("request was not denied")
			}
			if got := req.Header.Get("Authorization"); got != beforeAuth {
				t.Errorf("Authorization mutated on deny: %q", got)
			}
			if got := req.Header.Get("ChatGPT-Account-ID"); got != beforeAccount {
				t.Errorf("ChatGPT-Account-ID mutated on deny: %q", got)
			}
		})
	}
}

// The default port is the same origin written differently, and an explicit
// :443 must not be read as a different one. Companion to "non-default port".
func TestInjectCredentialBundles_AcceptsExplicitDefaultPort(t *testing.T) {
	req, err := http.NewRequest("POST", "https://chatgpt.com:443/backend-api/codex/responses", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer fake-access")
	req.Header.Set("ChatGPT-Account-ID", "fake-account")

	res := injectCredentialBundles(req, []CredentialBundle{codexTestBundle()}, "https", "chatgpt.com:443")
	if res.Denied {
		t.Fatalf("https://chatgpt.com:443 was denied; it is the same origin as https://chatgpt.com")
	}
	if got := req.Header.Get("Authorization"); got != "Bearer real-access" {
		t.Errorf("Authorization = %q, want the real value", got)
	}
}

// The prefix must match the path exactly as well as its descendants, or the
// backend's own root route would be excluded.
func TestInjectCredentialBundles_AcceptsPrefixItself(t *testing.T) {
	req, err := http.NewRequest("POST", "https://chatgpt.com/backend-api/codex", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer fake-access")
	req.Header.Set("ChatGPT-Account-ID", "fake-account")

	res := injectCredentialBundles(req, []CredentialBundle{codexTestBundle()}, "https", "chatgpt.com")
	if res.Denied {
		t.Fatal("the prefix path itself was denied")
	}
}

func TestInjectCredentialBundles_IgnoresUnrelatedRequestWithoutPlaceholders(t *testing.T) {
	req, err := http.NewRequest("GET", "https://chatgpt.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	res := injectCredentialBundles(req, []CredentialBundle{codexTestBundle()}, "https", "chatgpt.com")
	if res.Denied || len(res.Injected) != 0 {
		t.Fatalf("unrelated request should be untouched, got %+v", res)
	}
}
