package credentialsource

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	gcpDefaultTokenURI    = "https://oauth2.googleapis.com/token"
	gcpDefaultScope       = "https://www.googleapis.com/auth/cloud-platform"
	gcpJWTBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

// gcpSAKey holds the fields of a GCP service account key JSON needed to
// mint access tokens.
type gcpSAKey struct {
	email    string
	key      *rsa.PrivateKey
	tokenURI string
}

// GCPServiceAccountSource mints OAuth2 access tokens from a GCP service
// account key (the JSON file format produced by `gcloud iam service-accounts
// keys create`). It signs a JWT with the key and exchanges it for an access
// token at the key's token_uri. It implements both CredentialSource and
// RefreshingSource.
type GCPServiceAccountSource struct {
	keySource CredentialSource // yields the key JSON; nil when key was provided directly
	scopes    string
	client    *http.Client

	mu        sync.Mutex
	sa        *gcpSAKey // parsed key, cached after a successful load
	expiresAt time.Time
}

// NewGCPServiceAccountSource creates a credential source from a service
// account key JSON. scopes is a space-separated list of OAuth scopes;
// when empty it defaults to the cloud-platform scope.
func NewGCPServiceAccountSource(keyJSON []byte, scopes string) (*GCPServiceAccountSource, error) {
	sa, err := parseGCPSAKey(keyJSON)
	if err != nil {
		return nil, err
	}
	s := newGCPServiceAccountSource(nil, scopes)
	s.sa = sa
	return s, nil
}

// NewGCPServiceAccountSourceFromKeySource creates a credential source whose
// service account key JSON is fetched from another CredentialSource (e.g.,
// GCP Secret Manager) on first use and cached. When the token endpoint
// rejects an assertion, the cached key is dropped and re-fetched on the next
// attempt, so key rotation in the backing source is picked up without a
// restart. Close releases the key source if it implements io.Closer.
func NewGCPServiceAccountSourceFromKeySource(keySource CredentialSource, scopes string) *GCPServiceAccountSource {
	return newGCPServiceAccountSource(keySource, scopes)
}

func newGCPServiceAccountSource(keySource CredentialSource, scopes string) *GCPServiceAccountSource {
	if scopes == "" {
		scopes = gcpDefaultScope
	}
	return &GCPServiceAccountSource{
		keySource: keySource,
		scopes:    scopes,
		client:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *GCPServiceAccountSource) Type() string { return "gcp-service-account" }

func (s *GCPServiceAccountSource) Fetch(ctx context.Context) (string, error) {
	sa, err := s.loadKey(ctx)
	if err != nil {
		return "", err
	}

	jwt, err := buildGCPJWT(sa, s.scopes)
	if err != nil {
		return "", fmt.Errorf("building JWT: %w", err)
	}

	form := url.Values{
		"grant_type": {gcpJWTBearerGrantType},
		"assertion":  {jwt},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sa.tokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting access token: %w", err)
	}
	defer resp.Body.Close()

	body, err := readTokenResponse(resp, http.StatusOK, "token endpoint")
	if err != nil {
		// A 4xx rejection may mean the cached key was rotated or revoked;
		// drop it so the next attempt re-reads from the key source.
		if s.keySource != nil && resp.StatusCode >= 400 && resp.StatusCode < 500 {
			s.mu.Lock()
			s.sa = nil
			s.mu.Unlock()
		}
		return "", err
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("decoding response: %w", err)
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("response missing access_token field")
	}
	if result.ExpiresIn <= 0 {
		return "", fmt.Errorf("response missing expires_in field")
	}

	s.mu.Lock()
	s.expiresAt = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	s.mu.Unlock()

	return result.AccessToken, nil
}

func (s *GCPServiceAccountSource) TTL() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.expiresAt.IsZero() {
		return 0
	}
	ttl := time.Until(s.expiresAt)
	if ttl < 0 {
		return 0
	}
	return ttl
}

// Close releases the key source if it implements io.Closer.
func (s *GCPServiceAccountSource) Close() error {
	if c, ok := s.keySource.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// loadKey returns the parsed service account key, fetching it from the key
// source when not cached. The fetch and parse happen outside the lock so a
// slow key-source call never blocks TTL or concurrent fetches; concurrent
// first fetches may duplicate the read, with the last writer winning.
func (s *GCPServiceAccountSource) loadKey(ctx context.Context) (*gcpSAKey, error) {
	s.mu.Lock()
	sa := s.sa
	s.mu.Unlock()
	if sa != nil {
		return sa, nil
	}

	keyJSON, err := s.keySource.Fetch(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching service account key: %w", err)
	}
	sa, err = parseGCPSAKey([]byte(keyJSON))
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.sa = sa
	s.mu.Unlock()
	return sa, nil
}

// parseGCPSAKey parses a service account key JSON into its email, RSA
// private key, and token URI. Error messages never include key material.
func parseGCPSAKey(keyJSON []byte) (*gcpSAKey, error) {
	var raw struct {
		Type        string `json:"type"`
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
		TokenURI    string `json:"token_uri"`
	}
	if err := json.Unmarshal(keyJSON, &raw); err != nil {
		return nil, fmt.Errorf("parsing service account key JSON: invalid JSON")
	}
	if raw.Type != "service_account" {
		return nil, fmt.Errorf("service account key has type %q, want service_account", raw.Type)
	}
	if raw.ClientEmail == "" {
		return nil, fmt.Errorf("service account key missing client_email field")
	}
	if raw.PrivateKey == "" {
		return nil, fmt.Errorf("service account key missing private_key field")
	}

	block, _ := pem.Decode([]byte(raw.PrivateKey))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from service account private key")
	}
	key, err := parseRSAPrivateKey(block)
	if err != nil {
		return nil, err
	}

	tokenURI := raw.TokenURI
	if tokenURI == "" {
		tokenURI = gcpDefaultTokenURI
	}
	return &gcpSAKey{email: raw.ClientEmail, key: key, tokenURI: tokenURI}, nil
}

// buildGCPJWT builds the RS256-signed JWT assertion for the jwt-bearer
// grant: iss is the service account email, aud is the token endpoint, and
// scope carries the requested OAuth scopes.
func buildGCPJWT(sa *gcpSAKey, scopes string) (string, error) {
	// Backdate iat to tolerate clock skew between this host and Google.
	// exp is computed from the same base because Google rejects assertions
	// whose exp is more than one hour after iat.
	iat := time.Now().Add(-10 * time.Second)
	return signRS256JWT(sa.key, map[string]any{
		"iss":   sa.email,
		"scope": scopes,
		"aud":   sa.tokenURI,
		"iat":   iat.Unix(),
		"exp":   iat.Add(time.Hour).Unix(),
	})
}
