package credentialsource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	// Upgrade is the gatekeeper_upgrade extension parameter, if any.
	Upgrade UpgradeHint `json:"-"`
}

// UpgradeHint is the gatekeeper_upgrade extension parameter of an STS
// response: what the caller could request beyond the credential it got. Each
// key maps to one or more values.
type UpgradeHint map[string][]string

// TokenExchangeDeclined reports that the STS issued no token and told the
// caller to use its configured default credential instead: a 400
// invalid_target response that carries gatekeeper_fallback "default".
type TokenExchangeDeclined struct {
	Upgrade UpgradeHint
	// Invalidate drops the cached decline. TokenExchangeResolver sets it.
	Invalidate func()
}

func (*TokenExchangeDeclined) Error() string {
	return "token exchange declined: use the configured default credential"
}

// TokenExchangeNotFound reports an STS 404: the subject has no credential
// for the target. Description is the STS error_description when it is at
// most 200 printable ASCII characters, truncated past that, or "" otherwise.
type TokenExchangeNotFound struct {
	Description string
}

func (e *TokenExchangeNotFound) Error() string {
	if e.Description == "" {
		return "token exchange returned 404"
	}
	return "token exchange returned 404: " + e.Description
}

// ExchangedToken is a token that ResolveToken returns.
type ExchangedToken struct {
	AccessToken string
	Upgrade     UpgradeHint
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
	upgrade     UpgradeHint
	declined    bool
	expiresAt   time.Time
}

func (c cachedToken) result() (ExchangedToken, error) {
	if c.declined {
		return ExchangedToken{}, &TokenExchangeDeclined{Upgrade: c.upgrade}
	}
	return ExchangedToken{AccessToken: c.accessToken, Upgrade: c.upgrade}, nil
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

	if resp.StatusCode == http.StatusNotFound {
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseSize))
		if err != nil {
			return nil, fmt.Errorf("reading response: %w", err)
		}
		return nil, &TokenExchangeNotFound{Description: clientSafeDescription(body)}
	}
	if resp.StatusCode == http.StatusBadRequest {
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseSize))
		if err != nil {
			return nil, fmt.Errorf("reading response: %w", err)
		}
		if declined := parseDecline(body); declined != nil {
			return nil, declined
		}
		return nil, tokenResponseError("token exchange", resp.StatusCode, body)
	}

	body, err := readTokenResponse(resp, http.StatusOK, "token exchange")
	if err != nil {
		return nil, err
	}

	var wire struct {
		TokenExchangeResponse
		Upgrade json.RawMessage `json:"gatekeeper_upgrade"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	result := wire.TokenExchangeResponse
	if result.AccessToken == "" {
		return nil, fmt.Errorf("response missing access_token field")
	}
	result.Upgrade = parseUpgradeHint(wire.Upgrade)

	return &result, nil
}

// parseDecline returns the decline that an RFC 6749 §5.2 error body carries,
// or nil. A bare invalid_target is not a decline: it also reports a target
// the STS does not know, which must fail rather than fall back.
func parseDecline(body []byte) *TokenExchangeDeclined {
	var e struct {
		Error    string          `json:"error"`
		Fallback string          `json:"gatekeeper_fallback"`
		Upgrade  json.RawMessage `json:"gatekeeper_upgrade"`
	}
	if json.Unmarshal(body, &e) != nil || e.Error != "invalid_target" || e.Fallback != "default" {
		return nil
	}
	return &TokenExchangeDeclined{Upgrade: parseUpgradeHint(e.Upgrade)}
}

// clientSafeDescription returns the error_description of an RFC 6749 §5.2
// body, truncated to 200 bytes, or "" when it holds anything but printable
// ASCII: the proxy shows it to the client.
func clientSafeDescription(body []byte) string {
	var e struct {
		Description string `json:"error_description"`
	}
	if json.Unmarshal(body, &e) != nil {
		return ""
	}
	for i := 0; i < len(e.Description); i++ {
		if c := e.Description[i]; c < 0x20 || c > 0x7e {
			return ""
		}
	}
	if len(e.Description) > 200 {
		return e.Description[:200]
	}
	return e.Description
}

// parseUpgradeHint decodes a gatekeeper_upgrade object whose values are
// strings or arrays of strings. Any other shape, null included, drops the
// whole hint: a hint only guides the client, so it must never fail the
// exchange.
func parseUpgradeHint(raw json.RawMessage) UpgradeHint {
	if len(raw) == 0 {
		return nil
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		slog.Debug("ignoring malformed gatekeeper_upgrade", "subsystem", "credentialsource", "error", err)
		return nil
	}
	hint := make(UpgradeHint, len(fields))
	for k, v := range fields {
		values, ok := hintValues(v)
		if !ok {
			slog.Debug("ignoring malformed gatekeeper_upgrade", "subsystem", "credentialsource", "key", k)
			return nil
		}
		hint[k] = values
	}
	if len(hint) == 0 {
		return nil
	}
	return hint
}

func hintValues(v any) ([]string, bool) {
	switch v := v.(type) {
	case string:
		return []string{v}, true
	case []any:
		values := make([]string, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			values = append(values, s)
		}
		return values, true
	}
	return nil, false
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
// Invalidate's trigger is an upstream status code that may indicate a stale or
// exhausted backing credential. The same status can also mean resolving again
// will return the same value. A client looping on a request that always fails
// would otherwise drive one STS exchange per request, so evictions for a given
// key are rate-limited. The cost is bounded recovery latency: at worst one
// cooldown passes before a changed backing credential is picked up.
const defaultInvalidateCooldown = 10 * time.Second

// Invalidate drops the cached token for the given subject and actor, so the
// next Resolve performs a fresh exchange. Callers invoke it when the
// destination returns a status that may indicate the backing credential was
// rotated, re-authorized, or exhausted after the cached token was issued.
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

// Resolve returns the access token that ResolveToken returns.
func (s *TokenExchangeSource) Resolve(ctx context.Context, subjectToken, actorToken, requestID string) (string, error) {
	tok, err := s.ResolveToken(ctx, subjectToken, actorToken, requestID)
	return tok.AccessToken, err
}

// ResolveToken returns a credential for the given subject, using the cache
// when possible. Cache entries live for the STS-advertised expires_in, capped
// at maxTokenTTL. A decline returns *TokenExchangeDeclined and is cached for
// maxTokenTTL, so a host whose default is a static credential does not call
// the STS on every request. Concurrent requests for the same subject are
// coalesced into a single STS call via singleflight. When actorToken is
// non-empty, it is forwarded to the STS as the RFC 8693 actor_token parameter
// and included in the cache key. When requestID is non-empty, it is forwarded
// as X-Request-Id to the STS for cross-service correlation.
func (s *TokenExchangeSource) ResolveToken(ctx context.Context, subjectToken, actorToken, requestID string) (ExchangedToken, error) {
	ck := tokenCacheKey{subject: subjectToken, actor: actorToken}
	sfKey := fmt.Sprintf("%q\x00%q", subjectToken, actorToken)

	s.mu.Lock()
	if cached, ok := s.cache[ck]; ok && time.Now().Before(cached.expiresAt) {
		s.mu.Unlock()
		return cached.result()
	}
	s.mu.Unlock()

	v, err, _ := s.sf.Do(sfKey, func() (any, error) {
		s.mu.Lock()
		if cached, ok := s.cache[ck]; ok && time.Now().Before(cached.expiresAt) {
			s.mu.Unlock()
			return cached, nil
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
		var entry cachedToken
		var declined *TokenExchangeDeclined
		switch {
		case errors.As(err, &declined):
			entry = cachedToken{declined: true, upgrade: declined.Upgrade}
		case err != nil:
			return nil, err
		default:
			entry = cachedToken{accessToken: result.AccessToken, upgrade: result.Upgrade}
		}

		ttl := maxTokenTTL
		if result != nil {
			if advertised := time.Duration(result.ExpiresIn) * time.Second; advertised > 0 && advertised < ttl {
				ttl = advertised
			}
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
		entry.expiresAt = now.Add(ttl)
		if s.cacheGen == gen {
			s.cache[ck] = entry
		}
		s.mu.Unlock()

		return entry, nil
	})
	if err != nil {
		return ExchangedToken{}, err
	}

	return v.(cachedToken).result()
}
