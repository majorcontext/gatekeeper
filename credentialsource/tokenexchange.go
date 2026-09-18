package credentialsource

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const tokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

// TokenExchangeConfig configures an RFC 8693 token exchange source.
type TokenExchangeConfig struct {
	Endpoint         string // STS token endpoint URL
	ClientID         string // OAuth client ID for client credentials auth
	ClientSecret     string // OAuth client secret
	Resource         string // Target resource URI (e.g., "https://api.github.com")
	SubjectTokenType string // Subject token type URI (defaults to access_token type)
	ActorTokenType   string // Actor token type URI (defaults to access_token type)
}

// TokenExchangeResponse is the STS response per RFC 8693 §2.2.1.
type TokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
}

// TokenExchangeSource exchanges a subject token for an access token via
// RFC 8693. It caches tokens per subject with TTL from the STS response,
// capped at maxTokenTTL.
type TokenExchangeSource struct {
	endpoint         string
	clientID         string
	clientSecret     string
	resource         string
	subjectTokenType string
	actorTokenType   string
	client           *http.Client

	// invalidateCooldown bounds how often a given key may be evicted by
	// Invalidate. Overridden in tests.
	invalidateCooldown time.Duration

	mu    sync.Mutex
	cache map[tokenCacheKey]cachedToken
	// cacheGen increments on every Invalidate. A Resolve that captured an
	// older generation must not write its result: the exchange may have been
	// issued before the upstream credential rotated, so caching it would
	// re-stale the entry the invalidation just cleared.
	cacheGen        uint64
	lastInvalidated map[tokenCacheKey]time.Time
	sf              singleflight.Group
}

type tokenCacheKey struct {
	subject string
	actor   string
}

type cachedToken struct {
	accessToken string
	expiresAt   time.Time
}

// NewTokenExchangeSource creates a new RFC 8693 token exchange source.
func NewTokenExchangeSource(cfg TokenExchangeConfig) *TokenExchangeSource {
	subjectTokenType := cfg.SubjectTokenType
	if subjectTokenType == "" {
		subjectTokenType = "urn:ietf:params:oauth:token-type:access_token"
	}
	actorTokenType := cfg.ActorTokenType
	if actorTokenType == "" {
		actorTokenType = "urn:ietf:params:oauth:token-type:access_token"
	}
	return &TokenExchangeSource{
		endpoint:           cfg.Endpoint,
		clientID:           cfg.ClientID,
		clientSecret:       cfg.ClientSecret,
		resource:           cfg.Resource,
		subjectTokenType:   subjectTokenType,
		actorTokenType:     actorTokenType,
		client:             &http.Client{Timeout: 30 * time.Second},
		cache:              make(map[tokenCacheKey]cachedToken),
		lastInvalidated:    make(map[tokenCacheKey]time.Time),
		invalidateCooldown: defaultInvalidateCooldown,
	}
}

// Exchange performs an RFC 8693 token exchange for the given subject token.
// When actorToken is non-empty, it is included as the actor_token parameter.
// When requestID is non-empty, it is forwarded as X-Request-Id to the STS.
func (s *TokenExchangeSource) Exchange(ctx context.Context, subjectToken, actorToken, requestID string) (*TokenExchangeResponse, error) {
	form := url.Values{
		"grant_type":         {tokenExchangeGrantType},
		"subject_token":      {subjectToken},
		"subject_token_type": {s.subjectTokenType},
	}
	if s.resource != "" {
		form.Set("resource", s.resource)
	}
	if actorToken != "" {
		form.Set("actor_token", actorToken)
		form.Set("actor_token_type", s.actorTokenType)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(s.clientID, s.clientSecret)
	if requestID != "" {
		req.Header.Set("X-Request-Id", requestID)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request: %w", err)
	}
	defer resp.Body.Close()

	body, err := readTokenResponse(resp, http.StatusOK, "token exchange")
	if err != nil {
		return nil, err
	}

	var result TokenExchangeResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	if result.AccessToken == "" {
		return nil, fmt.Errorf("response missing access_token field")
	}

	return &result, nil
}

// maxTokenTTL caps how long an exchanged token is cached, regardless of the
// expires_in the STS advertises. A long expires_in only means the token may
// live that long, not that it stays valid: the upstream credential behind the
// exchange can be revoked or rotated at any time, and gatekeeper has no way to
// learn of it. Capping bounds how long a stale credential keeps being injected
// after such a change. Resolve is singleflighted, so the extra STS calls are
// coalesced and cheap.
const maxTokenTTL = time.Minute

// defaultInvalidateCooldown bounds how often one key may force a re-exchange.
//
// Invalidate's trigger is an upstream rejection, which gatekeeper can only see
// as a status code — a GitHub 403 means "re-authorize the app", but equally
// "secondary rate limit" or "no write access to this repo". A client looping on
// a request that always fails would otherwise drive one STS exchange per
// request, so evictions for a given key are rate-limited. The cost is bounded
// recovery latency: at worst one cooldown passes before a genuinely rotated
// credential is picked up.
const defaultInvalidateCooldown = 10 * time.Second

// Invalidate drops the cached token for the given subject and actor, so the
// next Resolve performs a fresh exchange. Callers invoke it when the
// destination rejects an injected credential, which usually means the upstream
// credential behind the exchange was rotated or re-authorized and the cached
// token predates that change.
//
// Evictions are rate-limited per key (see defaultInvalidateCooldown); calls
// within the cooldown are no-ops. Invalidate is safe to call when no entry is
// cached — it still bars any in-flight exchange from caching a result that
// predates it.
func (s *TokenExchangeSource) Invalidate(subjectToken, actorToken string) {
	ck := tokenCacheKey{subject: subjectToken, actor: actorToken}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if last, ok := s.lastInvalidated[ck]; ok && now.Sub(last) < s.invalidateCooldown {
		return
	}
	s.lastInvalidated[ck] = now

	delete(s.cache, ck)
	s.cacheGen++

	// Bound the bookkeeping map: entries past their cooldown carry no meaning.
	for k, t := range s.lastInvalidated {
		if now.Sub(t) >= s.invalidateCooldown {
			delete(s.lastInvalidated, k)
		}
	}
}

// Resolve returns a credential for the given subject, using the cache when
// possible. Cache entries live for the STS-advertised expires_in, capped at
// maxTokenTTL. Concurrent requests for the same subject are coalesced into a
// single STS call via singleflight. When actorToken is non-empty, it is
// forwarded to the STS as the RFC 8693 actor_token parameter and included
// in the cache key. When requestID is non-empty, it is forwarded as
// X-Request-Id to the STS for cross-service correlation.
func (s *TokenExchangeSource) Resolve(ctx context.Context, subjectToken, actorToken, requestID string) (string, error) {
	ck := tokenCacheKey{subject: subjectToken, actor: actorToken}
	sfKey := fmt.Sprintf("%q\x00%q", subjectToken, actorToken)

	s.mu.Lock()
	if cached, ok := s.cache[ck]; ok && time.Now().Before(cached.expiresAt) {
		token := cached.accessToken
		s.mu.Unlock()
		return token, nil
	}
	s.mu.Unlock()

	v, err, _ := s.sf.Do(sfKey, func() (any, error) {
		s.mu.Lock()
		if cached, ok := s.cache[ck]; ok && time.Now().Before(cached.expiresAt) {
			s.mu.Unlock()
			return cached.accessToken, nil
		}
		gen := s.cacheGen
		s.mu.Unlock()

		// WithoutCancel strips both cancellation and deadline from the parent.
		// This is intentional: a short deadline from one caller shouldn't cancel
		// the STS call for all singleflight waiters. The 30s http.Client timeout
		// still bounds the call.
		//
		// The winning goroutine's requestID is forwarded to the STS call.
		// Callers coalesced by singleflight do not each get a correlated STS entry.
		result, err := s.Exchange(context.WithoutCancel(ctx), subjectToken, actorToken, requestID)
		if err != nil {
			return nil, err
		}

		ttl := time.Duration(result.ExpiresIn) * time.Second
		if ttl <= 0 || ttl > maxTokenTTL {
			ttl = maxTokenTTL
		}

		s.mu.Lock()
		now := time.Now()
		for k, v := range s.cache {
			if now.After(v.expiresAt) {
				delete(s.cache, k)
			}
		}
		// Only cache when no Invalidate ran while the exchange was in flight.
		// Otherwise this token may predate the rotation that prompted the
		// invalidation, and writing it would re-stale the entry that was just
		// cleared. The caller still gets this token; only the caching is skipped.
		if s.cacheGen == gen {
			s.cache[ck] = cachedToken{
				accessToken: result.AccessToken,
				expiresAt:   now.Add(ttl),
			}
		}
		s.mu.Unlock()

		return result.AccessToken, nil
	})
	if err != nil {
		return "", err
	}

	return v.(string), nil
}
