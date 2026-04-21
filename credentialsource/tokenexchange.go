package credentialsource

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
}

// TokenExchangeResponse is the STS response per RFC 8693 §2.2.1.
type TokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
}

// TokenExchangeSource exchanges a subject token for an access token via
// RFC 8693. It caches tokens per subject with TTL from the STS response.
type TokenExchangeSource struct {
	endpoint         string
	clientID         string
	clientSecret     string
	resource         string
	subjectTokenType string
	client           *http.Client

	mu    sync.Mutex
	cache map[string]cachedToken
	sf    singleflight.Group
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
	return &TokenExchangeSource{
		endpoint:         cfg.Endpoint,
		clientID:         cfg.ClientID,
		clientSecret:     cfg.ClientSecret,
		resource:         cfg.Resource,
		subjectTokenType: subjectTokenType,
		client:           &http.Client{Timeout: 30 * time.Second},
		cache:            make(map[string]cachedToken),
	}
}

// ExchangeOptions provides optional parameters for a token exchange.
type ExchangeOptions struct {
	ActorToken string
}

// Exchange performs an RFC 8693 token exchange for the given subject token.
func (s *TokenExchangeSource) Exchange(ctx context.Context, subjectToken string, opts ...ExchangeOptions) (*TokenExchangeResponse, error) {
	form := url.Values{
		"grant_type":         {tokenExchangeGrantType},
		"subject_token":      {subjectToken},
		"subject_token_type": {s.subjectTokenType},
	}
	if s.resource != "" {
		form.Set("resource", s.resource)
	}
	if len(opts) > 0 && opts[0].ActorToken != "" {
		form.Set("actor_token", opts[0].ActorToken)
		form.Set("actor_token_type", "urn:ietf:params:oauth:token-type:access_token")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(s.clientID, s.clientSecret)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		msg := string(body)
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return nil, fmt.Errorf("token exchange returned %d: %s", resp.StatusCode, msg)
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

const defaultTokenTTL = 5 * time.Minute

// Resolve returns a credential for the given subject, using the cache when
// possible. Concurrent requests for the same subject are coalesced into a
// single STS call via singleflight. When actorToken is non-empty, it is
// forwarded to the STS as the RFC 8693 actor_token parameter and included
// in the cache key.
func (s *TokenExchangeSource) Resolve(ctx context.Context, subjectToken, actorToken string) (string, error) {
	cacheKey := subjectToken
	if actorToken != "" {
		cacheKey = fmt.Sprintf("%d:%s:%s", len(subjectToken), subjectToken, actorToken)
	}

	s.mu.Lock()
	if cached, ok := s.cache[cacheKey]; ok && time.Now().Before(cached.expiresAt) {
		token := cached.accessToken
		s.mu.Unlock()
		return token, nil
	}
	s.mu.Unlock()

	v, err, _ := s.sf.Do(cacheKey, func() (any, error) {
		s.mu.Lock()
		if cached, ok := s.cache[cacheKey]; ok && time.Now().Before(cached.expiresAt) {
			s.mu.Unlock()
			return cached.accessToken, nil
		}
		s.mu.Unlock()

		// WithoutCancel strips both cancellation and deadline from the parent.
		// This is intentional: a short deadline from one caller shouldn't cancel
		// the STS call for all singleflight waiters. The 30s http.Client timeout
		// still bounds the call.
		var opts []ExchangeOptions
		if actorToken != "" {
			opts = append(opts, ExchangeOptions{ActorToken: actorToken})
		}
		result, err := s.Exchange(context.WithoutCancel(ctx), subjectToken, opts...)
		if err != nil {
			return nil, err
		}

		ttl := time.Duration(result.ExpiresIn) * time.Second
		if ttl <= 0 {
			ttl = defaultTokenTTL
		}

		s.mu.Lock()
		now := time.Now()
		for k, v := range s.cache {
			if now.After(v.expiresAt) {
				delete(s.cache, k)
			}
		}
		s.cache[cacheKey] = cachedToken{
			accessToken: result.AccessToken,
			expiresAt:   now.Add(ttl),
		}
		s.mu.Unlock()

		return result.AccessToken, nil
	})
	if err != nil {
		return "", err
	}

	return v.(string), nil
}
