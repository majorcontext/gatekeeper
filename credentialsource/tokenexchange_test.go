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

	token, err := src.Exchange(context.Background(), "usr_abc123", "", "")
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

	token1, err := src.Resolve(context.Background(), "usr_abc", "", "")
	if err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	token2, err := src.Resolve(context.Background(), "usr_abc", "", "")
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

	token1, _ := src.Resolve(context.Background(), "usr_alice", "", "")
	token2, _ := src.Resolve(context.Background(), "usr_bob", "", "")

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

	token1, _ := src.Resolve(context.Background(), "usr_abc", "", "")
	if token1 != "token_v1" {
		t.Errorf("first token = %q, want token_v1", token1)
	}

	time.Sleep(1100 * time.Millisecond)

	token2, _ := src.Resolve(context.Background(), "usr_abc", "", "")
	if token2 != "token_v2" {
		t.Errorf("second token = %q, want token_v2", token2)
	}
	if callCount != 2 {
		t.Errorf("STS calls = %d, want 2", callCount)
	}
}

// wantMaxTTL is the ceiling the token cache must respect. Asserted independently
// of the production constant so that raising the cap is a deliberate, visible change.
const wantMaxTTL = time.Minute

// cachedTTL returns the remaining lifetime of the cache entry for subject/actor.
func cachedTTL(t *testing.T, src *TokenExchangeSource, subject, actor string) time.Duration {
	t.Helper()
	src.mu.Lock()
	defer src.mu.Unlock()
	entry, ok := src.cache[tokenCacheKey{subject: subject, actor: actor}]
	if !ok {
		t.Fatalf("no cache entry for subject %q actor %q", subject, actor)
	}
	return time.Until(entry.expiresAt)
}

// The STS may advertise a very long expires_in — Neptune returns the remaining
// lifetime of the underlying GitHub token, which can be hours. That token can be
// revoked or rotated upstream at any moment, so caching it for the full window
// means gatekeeper keeps injecting a stale credential (and the destination keeps
// returning 403) long after the user has reconnected their account.
func TestTokenExchange_CacheTTLCappedBelowAdvertisedExpiry(t *testing.T) {
	// Observed in production: expires_in of ~8 hours.
	const advertisedExpiresIn = 28573

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "gho_stale",
			"token_type":   "Bearer",
			"expires_in":   advertisedExpiresIn,
		})
	}))
	defer srv.Close()

	src := NewTokenExchangeSource(TokenExchangeConfig{
		Endpoint:     srv.URL,
		ClientID:     "gk",
		ClientSecret: "secret",
	})

	if _, err := src.Resolve(context.Background(), "usr_abc", "", ""); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// However long the STS claims, a rotated credential must not stay cached
	// for more than the cap.
	if ttl := cachedTTL(t, src, "usr_abc", ""); ttl > wantMaxTTL {
		t.Errorf("cached TTL = %v, want <= %v (STS advertised %ds)", ttl, wantMaxTTL, advertisedExpiresIn)
	}
}

// A short expires_in must still be honored — the cap is a ceiling, not a floor.
func TestTokenExchange_CacheTTLHonorsShortExpiry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "gho_short",
			"token_type":   "Bearer",
			"expires_in":   5,
		})
	}))
	defer srv.Close()

	src := NewTokenExchangeSource(TokenExchangeConfig{
		Endpoint:     srv.URL,
		ClientID:     "gk",
		ClientSecret: "secret",
	})

	if _, err := src.Resolve(context.Background(), "usr_abc", "", ""); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if ttl := cachedTTL(t, src, "usr_abc", ""); ttl > 5*time.Second {
		t.Errorf("cached TTL = %v, want <= 5s (the advertised expires_in)", ttl)
	}
}

// An STS that omits expires_in must not produce a zero-TTL (uncacheable) or
// unbounded entry.
func TestTokenExchange_CacheTTLMissingExpiry(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "gho_no_expiry",
			"token_type":   "Bearer",
		})
	}))
	defer srv.Close()

	src := NewTokenExchangeSource(TokenExchangeConfig{
		Endpoint:     srv.URL,
		ClientID:     "gk",
		ClientSecret: "secret",
	})

	if _, err := src.Resolve(context.Background(), "usr_abc", "", ""); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if _, err := src.Resolve(context.Background(), "usr_abc", "", ""); err != nil {
		t.Fatalf("second Resolve: %v", err)
	}

	if n := callCount.Load(); n != 1 {
		t.Errorf("STS calls = %d, want 1 (missing expires_in should still cache)", n)
	}
	if ttl := cachedTTL(t, src, "usr_abc", ""); ttl <= 0 || ttl > wantMaxTTL {
		t.Errorf("cached TTL = %v, want in (0, %v]", ttl, wantMaxTTL)
	}
}

// rotatingSTS returns a server handing out token_v1, token_v2, ... one per call.
func rotatingSTS(t *testing.T, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": fmt.Sprintf("token_v%d", n),
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// When the destination rejects an injected credential, the cached token is the
// prime suspect: the upstream credential behind the exchange was rotated or
// re-authorized, and the cache is still serving the pre-rotation token. Dropping
// the entry lets the next request pick up the fresh one.
func TestTokenExchange_InvalidateForcesReExchange(t *testing.T) {
	var calls atomic.Int32
	srv := rotatingSTS(t, &calls)

	src := NewTokenExchangeSource(TokenExchangeConfig{
		Endpoint:     srv.URL,
		ClientID:     "gk",
		ClientSecret: "secret",
	})

	token1, err := src.Resolve(context.Background(), "usr_abc", "ak", "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if token1 != "token_v1" {
		t.Fatalf("token1 = %q, want token_v1", token1)
	}

	src.Invalidate("usr_abc", "ak")

	token2, err := src.Resolve(context.Background(), "usr_abc", "ak", "")
	if err != nil {
		t.Fatalf("Resolve after Invalidate: %v", err)
	}
	if token2 != "token_v2" {
		t.Errorf("token2 = %q, want token_v2 (Invalidate should force re-exchange)", token2)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("STS calls = %d, want 2", n)
	}
}

// Invalidate must only drop the entry it names — one caller's 403 must not
// evict every other subject's token.
func TestTokenExchange_InvalidateScopedToKey(t *testing.T) {
	var calls atomic.Int32
	srv := rotatingSTS(t, &calls)

	src := NewTokenExchangeSource(TokenExchangeConfig{
		Endpoint:     srv.URL,
		ClientID:     "gk",
		ClientSecret: "secret",
	})

	if _, err := src.Resolve(context.Background(), "alice", "", ""); err != nil {
		t.Fatalf("Resolve alice: %v", err)
	}
	bob1, err := src.Resolve(context.Background(), "bob", "", "")
	if err != nil {
		t.Fatalf("Resolve bob: %v", err)
	}

	src.Invalidate("alice", "")

	bob2, err := src.Resolve(context.Background(), "bob", "", "")
	if err != nil {
		t.Fatalf("Resolve bob after invalidating alice: %v", err)
	}
	if bob2 != bob1 {
		t.Errorf("bob's token = %q, want %q (unchanged — only alice was invalidated)", bob2, bob1)
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("STS calls = %d, want 2 (bob should still be cached)", n)
	}
}

// Gatekeeper cannot tell a "re-authorize" 403 from a rate-limit or
// permission-denied 403 — the request logger only records the status code. So a
// client looping on a URL that always 403s must not turn into one STS exchange
// per request. Invalidate is rate-limited per key.
func TestTokenExchange_InvalidateCooldown(t *testing.T) {
	var calls atomic.Int32
	srv := rotatingSTS(t, &calls)

	src := NewTokenExchangeSource(TokenExchangeConfig{
		Endpoint:     srv.URL,
		ClientID:     "gk",
		ClientSecret: "secret",
	})
	src.invalidateCooldown = time.Hour // no second eviction should get through

	if _, err := src.Resolve(context.Background(), "usr_abc", "", ""); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// First 403: evicts, so the next request re-exchanges.
	src.Invalidate("usr_abc", "")
	if _, err := src.Resolve(context.Background(), "usr_abc", "", ""); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("STS calls = %d, want 2 after first Invalidate", n)
	}

	// A burst of further 403s within the cooldown must not each force an exchange.
	for range 20 {
		src.Invalidate("usr_abc", "")
		if _, err := src.Resolve(context.Background(), "usr_abc", "", ""); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
	}
	if n := calls.Load(); n != 2 {
		t.Errorf("STS calls = %d, want 2 (cooldown should suppress the burst)", n)
	}
}

// An Invalidate racing an in-flight Exchange must not be undone by that
// exchange writing its (pre-invalidation) result into the cache.
func TestTokenExchange_InvalidateDuringInflightResolve(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			close(entered)
			<-release
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": fmt.Sprintf("token_v%d", n),
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

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := src.Resolve(context.Background(), "usr_abc", "", ""); err != nil {
			t.Errorf("Resolve: %v", err)
		}
	}()

	<-entered
	src.Invalidate("usr_abc", "") // lands while the exchange is in flight
	close(release)
	<-done

	// The in-flight result predates the invalidation, so it must not be cached.
	src.mu.Lock()
	_, cached := src.cache[tokenCacheKey{subject: "usr_abc"}]
	src.mu.Unlock()
	if cached {
		t.Error("in-flight exchange re-cached a token across an Invalidate")
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

	_, err := src.Exchange(context.Background(), "bad_subject", "", "")
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

	_, err := src.Exchange(context.Background(), "usr_abc", "", "")
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

	_, err := src.Exchange(context.Background(), "usr_abc", "", "")
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

	_, err := src.Exchange(ctx, "usr_abc", "", "")
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
			token, err := src.Resolve(context.Background(), "usr_x", "", "")
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

	_, err := src.Exchange(context.Background(), "alice@example.com", "ak_alice_xxx", "")
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

	_, err := src.Exchange(context.Background(), "alice@example.com", "", "")
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

	token1, _ := src.Resolve(context.Background(), "alice", "ak_alice", "")
	token2, _ := src.Resolve(context.Background(), "alice", "ak_bob", "")
	token3, _ := src.Resolve(context.Background(), "alice", "ak_alice", "")

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

func TestTokenExchange_CachePerSubjectWithSameActor(t *testing.T) {
	var callCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "token_for_" + r.FormValue("subject_token"),
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

	token1, _ := src.Resolve(context.Background(), "alice", "shared_key", "")
	token2, _ := src.Resolve(context.Background(), "bob", "shared_key", "")
	token3, _ := src.Resolve(context.Background(), "alice", "shared_key", "")

	if token1 != "token_for_alice" {
		t.Errorf("token1 = %q, want token_for_alice", token1)
	}
	if token2 != "token_for_bob" {
		t.Errorf("token2 = %q, want token_for_bob", token2)
	}
	if token3 != token1 {
		t.Errorf("token3 = %q, want same as token1 (cached)", token3)
	}
	if n := callCount.Load(); n != 2 {
		t.Errorf("STS calls = %d, want 2 (same subject+actor should be cached)", n)
	}
}

func TestTokenExchange_CustomActorTokenType(t *testing.T) {
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
		Endpoint:       srv.URL,
		ClientID:       "gk",
		ClientSecret:   "secret",
		ActorTokenType: "urn:ietf:params:oauth:token-type:jwt",
	})

	_, err := src.Exchange(context.Background(), "alice", "jwt_token_here", "")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	if !strings.Contains(gotBody, "actor_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt") {
		t.Errorf("expected custom actor_token_type, got: %s", gotBody)
	}
}

func TestTokenExchange_RequestIDForwarded(t *testing.T) {
	var gotRequestID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRequestID = r.Header.Get("X-Request-Id")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "token",
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

	_, err := src.Exchange(context.Background(), "usr_abc", "", "req_test-correlation-id")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if gotRequestID != "req_test-correlation-id" {
		t.Errorf("X-Request-Id = %q, want %q", gotRequestID, "req_test-correlation-id")
	}
}

func TestTokenExchange_RequestIDOmittedWhenEmpty(t *testing.T) {
	var gotRequestID string
	var hasHeader bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRequestID = r.Header.Get("X-Request-Id")
		_, hasHeader = r.Header["X-Request-Id"]
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "token",
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

	_, err := src.Exchange(context.Background(), "usr_abc", "", "")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if hasHeader {
		t.Errorf("X-Request-Id header should not be set when requestID is empty, got %q", gotRequestID)
	}
}
