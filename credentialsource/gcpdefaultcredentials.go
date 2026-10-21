package credentialsource

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/auth"
	"cloud.google.com/go/auth/credentials"
	"cloud.google.com/go/compute/metadata"
)

const (
	gcpIAMCredentialsURL = "https://iamcredentials.googleapis.com"

	// gcpImpersonationLifetime is the lifetime requested from
	// generateAccessToken: one hour, the IAM default and maximum without
	// an org policy exception.
	gcpImpersonationLifetime = "3600s"
)

// GCPDefaultCredentialsSource mints OAuth2 access tokens from Google
// Application Default Credentials (ADC): GOOGLE_APPLICATION_CREDENTIALS, the
// gcloud well-known file, or the metadata server, which on GKE serves the
// Kubernetes service account's Workload Identity. The caller configures no
// key; ADC uses one only when GOOGLE_APPLICATION_CREDENTIALS or the
// well-known file holds a service account key. With a target service
// account, the source uses the ADC token to call the IAM Credentials
// generateAccessToken method and returns the target's token instead. It
// implements both CredentialSource and RefreshingSource, and is safe for
// concurrent use.
type GCPDefaultCredentialsSource struct {
	scopes []string
	target string
	iamURL string
	client *http.Client

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
// The constructor does no I/O: each Fetch detects ADC, so a metadata server
// that is not ready yet fails a Fetch that the caller can retry, not the
// constructor.
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
	tp, err := s.newProvider()
	if err != nil {
		return "", err
	}
	tok, err := tp.Token(ctx)
	if err != nil {
		return "", adcTokenError(err)
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
	return startupRetryWindow
}

// newProvider detects ADC and returns a token provider for it. Fetch calls
// it every time, so every Fetch mints a new token, as the key path does. A
// provider kept across Fetches would return its cached token until 3m45s
// before expiry, so a refresh loop at 75% of TTL would get a one-hour token
// back with 15 minutes left, then with about one minute left. A failure at
// that last refresh would leave the proxy almost no time before the token
// expired.
//
// DetectDefault takes no context; its metadata probe is bounded by the
// library's own timeouts, and the library makes that probe once per process.
func (s *GCPDefaultCredentialsSource) newProvider() (auth.TokenProvider, error) {
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

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseSize))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("reading generateAccessToken response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, iamError(s.target, resp.StatusCode, respBody)
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

// adcTokenError describes a failed ADC token fetch without the upstream
// response body. The metadata client and the auth library put the body in
// their error text, and gatekeeper logs this error at startup and on every
// failed refresh, so an error body that carries a credential must not reach
// it. Transport errors (a refused connection, a timeout) carry no body and
// are kept for diagnosis.
func adcTokenError(err error) error {
	const op = "fetching application default credentials token"
	var (
		metaErr    *metadata.Error
		authErr    *auth.Error
		notDefined metadata.NotDefinedError
		urlErr     *url.Error
	)
	switch {
	case errors.As(err, &metaErr):
		return fmt.Errorf("%s: metadata server returned %d", op, metaErr.Code)
	case errors.As(err, &authErr):
		if authErr.Response != nil {
			return fmt.Errorf("%s: token endpoint returned %d", op, authErr.Response.StatusCode)
		}
		return fmt.Errorf("%s: token endpoint returned an error", op)
	case errors.As(err, &notDefined), errors.As(err, &urlErr):
		return fmt.Errorf("%s: %w", op, err)
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("%s: %w", op, context.Canceled)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%s: %w", op, context.DeadlineExceeded)
	default:
		return fmt.Errorf("%s: failed (%T)", op, err)
	}
}

// iamError describes a non-200 generateAccessToken response by its status
// code and the Google error status (such as PERMISSION_DENIED), never the
// response body, which can carry arbitrary text.
func iamError(target string, status int, body []byte) error {
	var parsed struct {
		Error struct {
			Status string `json:"status"`
		} `json:"error"`
	}
	msg := fmt.Sprintf("IAM Credentials generateAccessToken for %s returned %d", target, status)
	if json.Unmarshal(body, &parsed) == nil && isGoogleErrorStatus(parsed.Error.Status) {
		msg += " " + parsed.Error.Status
	}
	return errors.New(msg)
}

// isGoogleErrorStatus reports whether s looks like a google.rpc.Code name:
// upper-case letters and underscores, at most 64 bytes.
func isGoogleErrorStatus(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' || r == '_') {
			return false
		}
	}
	return true
}
