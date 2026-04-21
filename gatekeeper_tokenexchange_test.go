package gatekeeper

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
