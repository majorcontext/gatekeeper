package credentialsource

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// stsOutput builds credential_process-format JSON with the given expiration.
func stsOutput(exp time.Time) string {
	return fmt.Sprintf(
		`{"Version": 1, "AccessKeyId": "AKIAEXAMPLE", "SecretAccessKey": "sk", "SessionToken": "st", "Expiration": %q}`,
		exp.UTC().Format(time.RFC3339))
}

func TestProcessSourceTTLFromSTSExpiration(t *testing.T) {
	exp := time.Now().Add(15 * time.Minute)
	src := NewProcessSource("printf '%s' '"+stsOutput(exp)+"'", 0)

	val, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}
	if !strings.Contains(val, "AKIAEXAMPLE") {
		t.Fatalf("Fetch() should return the raw JSON for endpoint consumers, got %q", val)
	}

	ttl := src.TTL()
	if ttl <= 14*time.Minute || ttl > 15*time.Minute {
		t.Fatalf("TTL() = %v, want ~15m derived from Expiration", ttl)
	}
}

func TestProcessSourceExpiredCredentialIsError(t *testing.T) {
	// Installing known-expired credentials would 401 every request for a
	// full refresh interval; failing the fetch engages the refresh loop's
	// backoff instead.
	exp := time.Now().Add(-time.Minute)
	src := NewProcessSource("printf '%s' '"+stsOutput(exp)+"'", 0)

	_, err := src.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error for already-expired credentials, got nil")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("error should say the credentials are expired, got: %v", err)
	}
}

func TestProcessSourceNearExpiryStillServes(t *testing.T) {
	exp := time.Now().Add(2 * time.Minute)
	src := NewProcessSource("printf '%s' '"+stsOutput(exp)+"'", 0)

	if _, err := src.Fetch(context.Background()); err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}
	if ttl := src.TTL(); ttl <= time.Minute || ttl > 2*time.Minute {
		t.Fatalf("TTL() = %v, want ~2m for near-expiry credential", ttl)
	}
}

func TestProcessSourceIgnoresNonCredentialProcessJSON(t *testing.T) {
	// encoding/json matches field names case-insensitively, so without a
	// format check any JSON containing an unrelated expiration field would
	// hijack the refresh schedule.
	src := NewProcessSource(`printf '{"token": "abc", "expiration": "2020-01-01T00:00:00Z"}'`, 0)

	if _, err := src.Fetch(context.Background()); err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}
	if ttl := src.TTL(); ttl != DefaultProcessTTL {
		t.Fatalf("TTL() = %v, want default %v: expiry sniffing must require credential_process shape", ttl, DefaultProcessTTL)
	}
}

// captureLogs redirects slog's default logger to a buffer for the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestProcessSourceNoWarningForWhitespace(t *testing.T) {
	// Virtually every CLI ends stdout with \n, and pretty-printed JSON has
	// interior newlines; neither means the helper is emitting garbage.
	logs := captureLogs(t)
	src := NewProcessSource(`printf '{\n  "Version": 1,\n  "AccessKeyId": "A",\n  "SecretAccessKey": "s"\n}\n'`, 0)

	if _, err := src.Fetch(context.Background()); err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}
	if strings.Contains(logs.String(), "control characters") {
		t.Fatalf("whitespace-only stripping must not warn; logs: %s", logs.String())
	}
}

func TestProcessSourceWarnsOnGarbageControlChars(t *testing.T) {
	logs := captureLogs(t)
	src := NewProcessSource(`printf 'tok\aen'`, 0)

	if _, err := src.Fetch(context.Background()); err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}
	if !strings.Contains(logs.String(), "control characters") {
		t.Fatalf("non-whitespace control bytes should warn; logs: %s", logs.String())
	}
}

func TestProcessSourceTTLDefaultWithoutExpiration(t *testing.T) {
	src := NewProcessSource("printf 'plain-token'", 90*time.Second)
	if _, err := src.Fetch(context.Background()); err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}
	if ttl := src.TTL(); ttl != 90*time.Second {
		t.Fatalf("TTL() = %v, want configured default 90s for output without expiry", ttl)
	}
}

func TestProcessSourceTTLZeroDefault(t *testing.T) {
	src := NewProcessSource("printf 'plain-token'", 0)
	if _, err := src.Fetch(context.Background()); err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}
	if ttl := src.TTL(); ttl != 5*time.Minute {
		t.Fatalf("TTL() = %v, want package default 5m when no default configured", ttl)
	}
}

func TestProcessSourceStripsControlCharacters(t *testing.T) {
	// A BEL byte inside the token would be an invalid header value
	// (RFC 7230) and break injection downstream.
	src := NewProcessSource(`printf 'tok\aen'`, 0)
	val, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}
	if val != "token" {
		t.Fatalf("Fetch() = %q, want %q with control characters stripped", val, "token")
	}
}

func TestProcessSourceContextCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	src := NewProcessSource("sleep 10; printf tok", 0)
	_, err := src.Fetch(ctx)
	if err == nil {
		t.Fatal("expected error when context expires, got nil")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Fetch() took %v, should abort promptly on context expiry", elapsed)
	}
}

func TestProcessSourceCommandFails(t *testing.T) {
	src := NewProcessSource("echo 'sso session expired' >&2; exit 1", 0)
	_, err := src.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error for failing command, got nil")
	}
	if !strings.Contains(err.Error(), "sso session expired") {
		t.Fatalf("error should include command stderr for diagnosis, got: %v", err)
	}
}

func TestProcessSourceEmptyOutput(t *testing.T) {
	src := NewProcessSource("true", 0)
	_, err := src.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error for empty command output, got nil")
	}
}

func TestProcessSource(t *testing.T) {
	src := NewProcessSource("printf 'tok-123\\n'", 0)
	if src.Type() != "process" {
		t.Fatalf("Type() = %q, want %q", src.Type(), "process")
	}

	val, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}
	if val != "tok-123" {
		t.Fatalf("Fetch() = %q, want %q (trailing newline should be trimmed)", val, "tok-123")
	}
}
