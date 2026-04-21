package credentialsource

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTokenExchange_BasicExchange(t *testing.T) {
	var gotContentType string
	var gotBody string
	var gotAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "gho_exchanged_token",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type":        "Bearer",
			"expires_in":        3600,
		})
	}))
	defer srv.Close()

	src := NewTokenExchangeSource(TokenExchangeConfig{
		Endpoint:         srv.URL,
		ClientID:         "gatekeeper",
		ClientSecret:     "secret123",
		Resource:         "https://api.github.com",
		SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
	})

	token, err := src.Exchange(context.Background(), "usr_abc123")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	if token.AccessToken != "gho_exchanged_token" {
		t.Errorf("access_token = %q, want %q", token.AccessToken, "gho_exchanged_token")
	}
	if token.ExpiresIn != 3600 {
		t.Errorf("expires_in = %d, want 3600", token.ExpiresIn)
	}

	if gotContentType != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", gotContentType)
	}

	// Verify Basic auth: base64("gatekeeper:secret123")
	wantAuth := "Basic Z2F0ZWtlZXBlcjpzZWNyZXQxMjM="
	if gotAuth != wantAuth {
		t.Errorf("Authorization = %q, want %q", gotAuth, wantAuth)
	}

	// Verify RFC 8693 grant type in body
	if !strings.Contains(gotBody, "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange") {
		t.Errorf("body missing grant_type, got: %s", gotBody)
	}
	if !strings.Contains(gotBody, "subject_token=usr_abc123") {
		t.Errorf("body missing subject_token, got: %s", gotBody)
	}
	if !strings.Contains(gotBody, "resource=https%3A%2F%2Fapi.github.com") {
		t.Errorf("body missing resource, got: %s", gotBody)
	}
}

func TestTokenExchange_CachesToken(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "gho_cached",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type":        "Bearer",
			"expires_in":        3600,
		})
	}))
	defer srv.Close()

	src := NewTokenExchangeSource(TokenExchangeConfig{
		Endpoint:     srv.URL,
		ClientID:     "gk",
		ClientSecret: "secret",
		Resource:     "https://api.github.com",
	})

	token1, err := src.Resolve(context.Background(), "usr_abc", "")
	if err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	token2, err := src.Resolve(context.Background(), "usr_abc", "")
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}

	if token1 != "gho_cached" || token2 != "gho_cached" {
		t.Errorf("tokens = %q, %q, want gho_cached", token1, token2)
	}
	if callCount != 1 {
		t.Errorf("STS calls = %d, want 1 (second call should be cached)", callCount)
	}
}

func TestTokenExchange_CachePerSubject(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		r.ParseForm()
		subject := r.FormValue("subject_token")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "token_for_" + subject,
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type":        "Bearer",
			"expires_in":        3600,
		})
	}))
	defer srv.Close()

	src := NewTokenExchangeSource(TokenExchangeConfig{
		Endpoint:     srv.URL,
		ClientID:     "gk",
		ClientSecret: "secret",
		Resource:     "https://api.github.com",
	})

	token1, _ := src.Resolve(context.Background(), "usr_alice", "")
	token2, _ := src.Resolve(context.Background(), "usr_bob", "")

	if token1 != "token_for_usr_alice" {
		t.Errorf("alice token = %q, want token_for_usr_alice", token1)
	}
	if token2 != "token_for_usr_bob" {
		t.Errorf("bob token = %q, want token_for_usr_bob", token2)
	}
	if callCount != 2 {
		t.Errorf("STS calls = %d, want 2", callCount)
	}
}

func TestTokenExchange_CacheExpiry(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":      fmt.Sprintf("token_v%d", callCount),
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type":        "Bearer",
			"expires_in":        1,
		})
	}))
	defer srv.Close()

	src := NewTokenExchangeSource(TokenExchangeConfig{
		Endpoint:     srv.URL,
		ClientID:     "gk",
		ClientSecret: "secret",
		Resource:     "https://api.github.com",
	})

	token1, _ := src.Resolve(context.Background(), "usr_abc", "")
	if token1 != "token_v1" {
		t.Errorf("first token = %q, want token_v1", token1)
	}

	time.Sleep(1100 * time.Millisecond)

	token2, _ := src.Resolve(context.Background(), "usr_abc", "")
	if token2 != "token_v2" {
		t.Errorf("second token = %q, want token_v2", token2)
	}
	if callCount != 2 {
		t.Errorf("STS calls = %d, want 2", callCount)
	}
}

func TestTokenExchange_STSError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()

	src := NewTokenExchangeSource(TokenExchangeConfig{
		Endpoint:     srv.URL,
		ClientID:     "gk",
		ClientSecret: "secret",
	})

	_, err := src.Exchange(context.Background(), "bad_subject")
	if err == nil {
		t.Fatal("expected error for 400 response")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error = %q, want to contain 400", err)
	}
}

func TestTokenExchange_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{not json`))
	}))
	defer srv.Close()

	src := NewTokenExchangeSource(TokenExchangeConfig{
		Endpoint:     srv.URL,
		ClientID:     "gk",
		ClientSecret: "secret",
	})

	_, err := src.Exchange(context.Background(), "usr_abc")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestTokenExchange_MissingAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"token_type": "Bearer",
			"expires_in": 3600,
		})
	}))
	defer srv.Close()

	src := NewTokenExchangeSource(TokenExchangeConfig{
		Endpoint:     srv.URL,
		ClientID:     "gk",
		ClientSecret: "secret",
	})

	_, err := src.Exchange(context.Background(), "usr_abc")
	if err == nil {
		t.Fatal("expected error for missing access_token")
	}
}

func TestTokenExchange_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer srv.Close()

	src := NewTokenExchangeSource(TokenExchangeConfig{
		Endpoint:     srv.URL,
		ClientID:     "gk",
		ClientSecret: "secret",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := src.Exchange(ctx, "usr_abc")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestTokenExchange_ConcurrentCacheMiss(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		time.Sleep(10 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "deduped-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	src := NewTokenExchangeSource(TokenExchangeConfig{
		Endpoint:     srv.URL,
		ClientID:     "k",
		ClientSecret: "s",
	})

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := src.Resolve(context.Background(), "usr_x", "")
			if err != nil {
				t.Errorf("Resolve: %v", err)
				return
			}
			if token != "deduped-token" {
				t.Errorf("token = %q, want %q", token, "deduped-token")
			}
		}()
	}
	wg.Wait()

	if n := callCount.Load(); n != 1 {
		t.Errorf("STS calls = %d, want 1 (singleflight should deduplicate)", n)
	}
}

func TestTokenExchange_ActorToken(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "exchanged",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	src := NewTokenExchangeSource(TokenExchangeConfig{
		Endpoint:     srv.URL,
		ClientID:     "gk",
		ClientSecret: "secret",
		Resource:     "https://api.github.com",
	})

	_, err := src.Exchange(context.Background(), "alice@example.com", ExchangeOptions{ActorToken: "ak_alice_xxx"})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	if !strings.Contains(gotBody, "actor_token=ak_alice_xxx") {
		t.Errorf("body missing actor_token, got: %s", gotBody)
	}
	if !strings.Contains(gotBody, "actor_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token") {
		t.Errorf("body missing actor_token_type, got: %s", gotBody)
	}
}

func TestTokenExchange_ActorTokenNotSentWhenEmpty(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "exchanged",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	src := NewTokenExchangeSource(TokenExchangeConfig{
		Endpoint:     srv.URL,
		ClientID:     "gk",
		ClientSecret: "secret",
	})

	_, err := src.Exchange(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	if strings.Contains(gotBody, "actor_token") {
		t.Errorf("body should not contain actor_token when not provided, got: %s", gotBody)
	}
}

func TestTokenExchange_CachePerActorToken(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		r.ParseForm()
		actor := r.FormValue("actor_token")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "token_for_actor_" + actor,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	src := NewTokenExchangeSource(TokenExchangeConfig{
		Endpoint:     srv.URL,
		ClientID:     "gk",
		ClientSecret: "secret",
	})

	token1, _ := src.Resolve(context.Background(), "alice", "ak_alice")
	token2, _ := src.Resolve(context.Background(), "alice", "ak_bob")
	token3, _ := src.Resolve(context.Background(), "alice", "ak_alice")

	if token1 != "token_for_actor_ak_alice" {
		t.Errorf("token1 = %q, want token_for_actor_ak_alice", token1)
	}
	if token2 != "token_for_actor_ak_bob" {
		t.Errorf("token2 = %q, want token_for_actor_ak_bob", token2)
	}
	if token3 != token1 {
		t.Errorf("token3 = %q, want same as token1 (cached)", token3)
	}
	if n := callCount.Load(); n != 2 {
		t.Errorf("STS calls = %d, want 2 (same actor should be cached)", n)
	}
}
