package credentialsource

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const gitHubAPIBaseURL = "https://api.github.com"

// GitHubAppSource generates GitHub App installation access tokens.
// It implements both CredentialSource and RefreshingSource.
type GitHubAppSource struct {
	appID          string
	installationID string
	key            *rsa.PrivateKey
	client         *http.Client
	apiBaseURL     string

	mu        sync.Mutex
	expiresAt time.Time
}

// NewGitHubAppSource creates a credential source that generates GitHub App
// installation tokens. privateKeyPEM must be a PEM-encoded RSA private key.
func NewGitHubAppSource(appID, installationID string, privateKeyPEM []byte) (*GitHubAppSource, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from private key")
	}

	var key *rsa.PrivateKey
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("parsing PKCS8 private key: %w", parseErr)
		}
		var ok bool
		key, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key is not RSA")
		}
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q, want RSA PRIVATE KEY or PRIVATE KEY", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parsing RSA private key: %w", err)
	}

	return &GitHubAppSource{
		appID:          appID,
		installationID: installationID,
		key:            key,
		client:         http.DefaultClient,
		apiBaseURL:     gitHubAPIBaseURL,
	}, nil
}

func (s *GitHubAppSource) Type() string { return "github-app" }

func (s *GitHubAppSource) Fetch(ctx context.Context) (string, error) {
	jwt, err := s.buildJWT()
	if err != nil {
		return "", fmt.Errorf("building JWT: %w", err)
	}

	url := s.apiBaseURL + "/app/installations/" + s.installationID + "/access_tokens"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting installation token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		msg := string(body)
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return "", fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, msg)
	}

	var result struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("decoding response: %w", err)
	}
	if result.Token == "" {
		return "", fmt.Errorf("response missing token field")
	}
	if result.ExpiresAt == "" {
		return "", fmt.Errorf("response missing expires_at field")
	}

	expiresAt, err := time.Parse(time.RFC3339, result.ExpiresAt)
	if err != nil {
		return "", fmt.Errorf("parsing expires_at: %w", err)
	}

	s.mu.Lock()
	s.expiresAt = expiresAt
	s.mu.Unlock()

	return result.Token, nil
}

func (s *GitHubAppSource) TTL() time.Duration {
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

func (s *GitHubAppSource) buildJWT() (string, error) {
	now := time.Now()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))

	claims, err := json.Marshal(map[string]any{
		"iss": s.appID,
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(claims)

	signingInput := header + "." + payload
	hash := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
