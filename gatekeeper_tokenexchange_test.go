package gatekeeper

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
