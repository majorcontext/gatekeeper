package credentialsource

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/auth"
	"cloud.google.com/go/auth/credentials"
)

const (
	gcpIAMCredentialsURL = "https://iamcredentials.googleapis.com"

	// gcpImpersonationLifetime is the lifetime requested from
	// generateAccessToken: one hour, the IAM default and maximum without
	// an org policy exception.
	gcpImpersonationLifetime = "3600s"

	// gcpStartupRetryWindow bounds how long a caller retries the first
	// Fetch. The GKE metadata server can refuse requests for the first
	// seconds of a new Pod.
	gcpStartupRetryWindow = 30 * time.Second
)

// GCPDefaultCredentialsSource mints OAuth2 access tokens from Google
// Application Default Credentials (ADC): GOOGLE_APPLICATION_CREDENTIALS, the
// gcloud well-known file, or the metadata server, which on GKE serves the
// Kubernetes service account's Workload Identity. No service account key is
// read. With a target service account, the source uses the ADC token to call
// the IAM Credentials generateAccessToken method and returns the target's
// token instead. It implements both CredentialSource and RefreshingSource,
// and is safe for concurrent use.
type GCPDefaultCredentialsSource struct {
	scopes []string
	target string
	iamURL string
	client *http.Client

	// detectMu guards provider. It is held across ADC detection, which
	// can probe the metadata server, so it is separate from mu and a slow
	// detection never blocks TTL.
	detectMu sync.Mutex
	provider auth.TokenProvider // ADC, detected on first Fetch

	mu        sync.Mutex
	expiresAt time.Time
}

// NewGCPDefaultCredentialsSource creates a credential source backed by
// Application Default Credentials. scopes is a space-separated list of OAuth
// scopes; when empty it defaults to the cloud-platform scope. When
// targetServiceAccount is not empty, Fetch returns a token for that service
// account, and the ADC principal needs permission to mint it
// (roles/iam.serviceAccountTokenCreator).
//
// The constructor does no I/O: ADC is detected on the first Fetch, so a
// metadata server that is not ready yet fails a Fetch that the caller can
// retry, not the constructor.
func NewGCPDefaultCredentialsSource(scopes, targetServiceAccount string) *GCPDefaultCredentialsSource {
	s := strings.Fields(scopes)
	if len(s) == 0 {
		s = []string{gcpDefaultScope}
	}
	return &GCPDefaultCredentialsSource{
		scopes: s,
		target: targetServiceAccount,
		iamURL: gcpIAMCredentialsURL,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (s *GCPDefaultCredentialsSource) Type() string { return "gcp-service-account" }

func (s *GCPDefaultCredentialsSource) Fetch(ctx context.Context) (string, error) {
	tp, err := s.loadProvider()
	if err != nil {
		return "", err
	}
	tok, err := tp.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("fetching application default credentials token: %w", err)
	}
	if tok.Value == "" || tok.Expiry.IsZero() {
		return "", fmt.Errorf("application default credentials returned a token without a value or expiry")
	}
	value, expiry := tok.Value, tok.Expiry
	if s.target != "" {
		value, expiry, err = s.impersonate(ctx, tok.Value)
		if err != nil {
			return "", err
		}
	}

	s.mu.Lock()
	s.expiresAt = expiry
	s.mu.Unlock()
	return value, nil
}

func (s *GCPDefaultCredentialsSource) TTL() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.expiresAt.IsZero() {
		return 0
	}
	return max(time.Until(s.expiresAt), 0)
}

// StartupRetryWindow returns how long a caller should keep retrying a failed
// first Fetch before it gives up.
func (s *GCPDefaultCredentialsSource) StartupRetryWindow() time.Duration {
	return gcpStartupRetryWindow
}

// loadProvider returns the ADC token provider, detecting it on first use.
// A failed detection is not cached, so the next Fetch detects again.
//
// The provider caches its token until 3m45s before expiry, and refreshes in
// the calling goroutine (DisableAsyncRefresh) so a refresh failure reaches
// the caller's retry. The token it returns still carries its real expiry, so
// a refresh loop that fetches at a fraction of TTL never holds an expired
// token. For a one-hour token, a loop at 75% of TTL makes a few fetches that
// return the cached token with a shorter TTL (about 45m, 56m, 59m) before
// the cache lapses and a new token comes back. DetectDefault takes no
// context; its metadata probe is bounded by the library's own timeouts.
func (s *GCPDefaultCredentialsSource) loadProvider() (auth.TokenProvider, error) {
	s.detectMu.Lock()
	defer s.detectMu.Unlock()
	if s.provider != nil {
		return s.provider, nil
	}
	scopes := s.scopes
	if s.target != "" {
		// The ADC token only calls the IAM Credentials API.
		scopes = []string{gcpDefaultScope}
	}
	creds, err := credentials.DetectDefault(&credentials.DetectOptions{
		Scopes:              scopes,
		DisableAsyncRefresh: true,
	})
	if err != nil {
		return nil, fmt.Errorf("detecting application default credentials: %w", err)
	}
	s.provider = creds
	return creds, nil
}

// impersonate exchanges the ADC token for a token of the target service
// account with the rule's scopes. Every call mints a new token, as the key
// path does. Errors never include either token.
func (s *GCPDefaultCredentialsSource) impersonate(ctx context.Context, adcToken string) (string, time.Time, error) {
	body, err := json.Marshal(map[string]any{
		"scope":    s.scopes,
		"lifetime": gcpImpersonationLifetime,
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("encoding generateAccessToken request: %w", err)
	}
	endpoint := s.iamURL + "/v1/projects/-/serviceAccounts/" + url.PathEscape(s.target) + ":generateAccessToken"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adcToken)

	resp, err := s.client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("requesting access token for %s: %w", s.target, err)
	}
	defer resp.Body.Close()

	respBody, err := readTokenResponse(resp, http.StatusOK, "IAM Credentials generateAccessToken for "+s.target)
	if err != nil {
		return "", time.Time{}, err
	}
	var result struct {
		AccessToken string    `json:"accessToken"`
		ExpireTime  time.Time `json:"expireTime"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", time.Time{}, fmt.Errorf("decoding generateAccessToken response: invalid JSON")
	}
	if result.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("generateAccessToken response missing accessToken field")
	}
	if result.ExpireTime.IsZero() {
		return "", time.Time{}, fmt.Errorf("generateAccessToken response missing expireTime field")
	}
	return result.AccessToken, result.ExpireTime, nil
}
