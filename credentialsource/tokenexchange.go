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

// Exchange performs an RFC 8693 token exchange for the given subject token.
func (s *TokenExchangeSource) Exchange(ctx context.Context, subjectToken string) (*TokenExchangeResponse, error) {
	form := url.Values{
		"grant_type":         {tokenExchangeGrantType},
		"subject_token":      {subjectToken},
		"subject_token_type": {s.subjectTokenType},
	}
	if s.resource != "" {
		form.Set("resource", s.resource)
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

// Resolve returns a credential for the given subject, using the cache when
// possible. This is the method called by the CredentialResolver function.
func (s *TokenExchangeSource) Resolve(ctx context.Context, subjectToken string) (string, error) {
	s.mu.Lock()
	if cached, ok := s.cache[subjectToken]; ok && time.Now().Before(cached.expiresAt) {
		token := cached.accessToken
		s.mu.Unlock()
		return token, nil
	}
	s.mu.Unlock()

	result, err := s.Exchange(ctx, subjectToken)
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	s.cache[subjectToken] = cachedToken{
		accessToken: result.AccessToken,
		expiresAt:   time.Now().Add(time.Duration(result.ExpiresIn) * time.Second),
	}
	s.mu.Unlock()

	return result.AccessToken, nil
}
