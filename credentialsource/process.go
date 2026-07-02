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
	val := strings.TrimSpace(sanitizeHeaderValue(string(out)))
	if val == "" {
		return "", fmt.Errorf("credential command produced no output")
	}

	expiresAt := sniffExpiration(val)
	// Failing the fetch (rather than installing expired credentials that
	// 401 every request) engages the refresh loop's backoff.
	if !expiresAt.IsZero() && time.Now().After(expiresAt) {
		return "", fmt.Errorf("credential command returned already-expired credentials (Expiration %s)", expiresAt.Format(time.RFC3339))
	}

	s.mu.Lock()
	s.expiresAt = expiresAt
	s.mu.Unlock()

	return val, nil
}

// TTL implements RefreshingSource. When the last output carried a
// credential_process Expiration, TTL is the time until that expiry (clamped
// at 0; note the refresh loop floors its wait at 30 seconds, so a
// nearly-expired credential refreshes on that floor, not instantly).
// Otherwise the configured default interval applies. No safety margin is
// subtracted here — the refresh loop refreshes at 75% of TTL.
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

// garbageChars is the stripped set minus whitespace (LF, VT, FF, CR).
// Trailing newlines and pretty-printed JSON are normal helper output; only
// non-whitespace control bytes indicate the helper is emitting garbage.
var garbageChars = regexp.MustCompile("[\x00-\x08\x0e-\x1f\x7f]")

// sanitizeHeaderValue strips header-invalid bytes from a credential value.
// It warns (with a count, never the value) only when non-whitespace control
// bytes were present, so users learn their helper is emitting garbage
// instead of debugging opaque failures from the upstream API.
func sanitizeHeaderValue(raw string) string {
	cleaned := controlChars.ReplaceAllString(raw, "")
	if garbageChars.MatchString(raw) {
		slog.Warn("credential output contained header-invalid control characters; stripped",
			"source", "process",
			"stripped_bytes", len(raw)-len(cleaned))
	}
	return cleaned
}

// sniffExpiration extracts the Expiration timestamp when the output is
// credential_process-format JSON (RFC 3339, per the AWS spec). The format
// check requires the spec's exact-case Version, AccessKeyId, and Expiration
// keys — encoding/json alone matches field names case-insensitively, which
// would let any JSON with an unrelated "expiration" field hijack the
// refresh schedule. Returns the zero time for anything else — the caller
// falls back to the default interval.
func sniffExpiration(output string) time.Time {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal([]byte(output), &payload); err != nil {
		return time.Time{}
	}
	if _, ok := payload["Version"]; !ok {
		return time.Time{}
	}
	if _, ok := payload["AccessKeyId"]; !ok {
		return time.Time{}
	}
	var expiration string
	if raw, ok := payload["Expiration"]; !ok || json.Unmarshal(raw, &expiration) != nil {
		return time.Time{}
	}
	exp, err := time.Parse(time.RFC3339, expiration)
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
