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
		{name: "encoded traversal", method: "POST", url: "https://chatgpt.com/backend-api/codex/%2e%2e/other", scheme: "https", host: "chatgpt.com", auth: "Bearer fake-access", account: "fake-account"},
		{name: "missing account", method: "POST", url: "https://chatgpt.com/backend-api/codex/responses", scheme: "https", host: "chatgpt.com", auth: "Bearer fake-access"},
		{name: "wrong placeholder", method: "POST", url: "https://chatgpt.com/backend-api/codex/responses", scheme: "https", host: "chatgpt.com", auth: "Bearer attacker-value", account: "fake-account"},
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
