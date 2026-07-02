package credentialsource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// DefaultProcessTTL is the refresh interval reported when the command
// output carries no expiry information and no default was configured.
const DefaultProcessTTL = 5 * time.Minute

// ProcessSource runs a host command and serves its trimmed stdout as the
// credential value. It is the universal "bring your own backend" source:
// any helper that prints a credential (keychain CLIs, `pass`, 1Password,
// corp credential processes) can back a grant without a dedicated Go
// implementation. It implements both CredentialSource and RefreshingSource.
type ProcessSource struct {
	command    string
	defaultTTL time.Duration

	mu        sync.Mutex
	expiresAt time.Time
}

// NewProcessSource creates a credential source that runs command with
// `sh -c` on every fetch. defaultTTL is the refresh interval to report
// when the command output carries no expiry information.
func NewProcessSource(command string, defaultTTL time.Duration) *ProcessSource {
	return &ProcessSource{command: command, defaultTTL: defaultTTL}
}

func (s *ProcessSource) Type() string { return "process" }

func (s *ProcessSource) Fetch(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", s.command)
	// Without WaitDelay, Output() keeps waiting for the stdout pipe even
	// after ctx cancellation kills sh, because a grandchild process may
	// still hold the pipe open.
	cmd.WaitDelay = 3 * time.Second
	out, err := cmd.Output()
	if err != nil {
		// Include stderr so helper failures (expired SSO session, missing
		// profile) are diagnosable from logs. Never include stdout: it may
		// hold a credential.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return "", fmt.Errorf("running credential command: %w: %s", err, truncate(string(exitErr.Stderr), 256))
		}
		return "", fmt.Errorf("running credential command: %w", err)
	}
	val := strings.TrimSpace(sanitizeHeaderValue(string(out), s.Type()))
	if val == "" {
		return "", fmt.Errorf("credential command produced no output")
	}

	s.mu.Lock()
	s.expiresAt = sniffExpiration(val)
	s.mu.Unlock()

	return val, nil
}

// TTL implements RefreshingSource. When the last output carried an STS-style
// Expiration, TTL is the time until that expiry (clamped at 0 so an expired
// credential forces an immediate refresh). Otherwise the configured default
// interval applies. The refresh loop's safety margin (it refreshes at 75% of
// TTL) means no margin is subtracted here.
func (s *ProcessSource) TTL() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.expiresAt.IsZero() {
		if s.defaultTTL > 0 {
			return s.defaultTTL
		}
		return DefaultProcessTTL
	}
	ttl := time.Until(s.expiresAt)
	if ttl < 0 {
		return 0
	}
	return ttl
}

// controlChars matches bytes that are invalid in HTTP header values per
// RFC 7230: C0 controls except HTAB, plus DEL. Newlines are included, so
// pretty-printed JSON collapses to a single line (still valid JSON).
var controlChars = regexp.MustCompile("[\x00-\x08\x0a-\x1f\x7f]")

// sanitizeHeaderValue strips header-invalid bytes from a credential value,
// logging a count (never the value) so users learn their helper is emitting
// garbage instead of debugging opaque 400s from the upstream API.
func sanitizeHeaderValue(raw, sourceType string) string {
	cleaned := controlChars.ReplaceAllString(raw, "")
	if len(cleaned) != len(raw) {
		slog.Warn("credential output contained header-invalid control characters; stripped",
			"source", sourceType,
			"stripped_bytes", len(raw)-len(cleaned))
	}
	return cleaned
}

// sniffExpiration extracts the Expiration timestamp when the output is
// credential_process-format JSON (RFC 3339, per the AWS spec). Returns the
// zero time for non-JSON output or JSON without a parseable Expiration —
// the caller falls back to the default interval.
func sniffExpiration(output string) time.Time {
	var payload struct {
		Expiration string `json:"Expiration"`
	}
	if err := json.Unmarshal([]byte(output), &payload); err != nil || payload.Expiration == "" {
		return time.Time{}
	}
	exp, err := time.Parse(time.RFC3339, payload.Expiration)
	if err != nil {
		return time.Time{}
	}
	return exp
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
