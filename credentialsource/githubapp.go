package credentialsource

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
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

	key, err := parseRSAPrivateKey(block)
	if err != nil {
		return nil, err
	}

	return &GitHubAppSource{
		appID:          appID,
		installationID: installationID,
		key:            key,
		client:         &http.Client{},
		apiBaseURL:     gitHubAPIBaseURL,
	}, nil
}

func (s *GitHubAppSource) Type() string { return "github-app" }

func (s *GitHubAppSource) Fetch(ctx context.Context) (string, error) {
	jwt, err := s.buildJWT()
	if err != nil {
		return "", fmt.Errorf("building JWT: %w", err)
	}

	endpoint, err := url.JoinPath(s.apiBaseURL, "app", "installations", s.installationID, "access_tokens")
	if err != nil {
		return "", fmt.Errorf("building URL: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
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

// parseRSAPrivateKey extracts an RSA private key from a PEM block.
// It tries the standard PKCS1/PKCS8 parsers first. If the key has
// inconsistent CRT parameters (p*q != n), it falls back to raw ASN.1
// parsing and builds a key from just N, E, D — matching the lenient
// behavior of OpenSSL-based runtimes (Node, Ruby, Python).
func parseRSAPrivateKey(block *pem.Block) (*rsa.PrivateKey, error) {
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err == nil {
			return key, nil
		}
		return parsePKCS1Lenient(block.Bytes)
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PKCS8 private key: %w", err)
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key is not RSA")
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q, want RSA PRIVATE KEY or PRIVATE KEY", block.Type)
	}
}

// pkcs1RawKey mirrors the ASN.1 structure of an RSA private key (RFC 8017 A.1.2).
type pkcs1RawKey struct {
	Version int
	N       *big.Int
	E       int
	D       *big.Int
	P       *big.Int
	Q       *big.Int
	Dp      *big.Int
	Dq      *big.Int
	Qinv    *big.Int
}

// parsePKCS1Lenient parses a PKCS#1 DER block into an rsa.PrivateKey using
// only N, E, and D, ignoring invalid CRT parameters.
func parsePKCS1Lenient(der []byte) (*rsa.PrivateKey, error) {
	var raw pkcs1RawKey
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		return nil, fmt.Errorf("parsing RSA private key ASN.1: %w", err)
	}
	if raw.N == nil || raw.D == nil || raw.E == 0 {
		return nil, fmt.Errorf("RSA private key missing required fields")
	}
	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: raw.N,
			E: raw.E,
		},
		D: raw.D,
	}
	return key, nil
}
