package proxy

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

// DefaultAuthTokenFileInterval is the poll period when none is configured.
const DefaultAuthTokenFileInterval = time.Second

// ReadAuthTokenFile returns the trimmed token in path. An unreadable or
// blank file is an error; the error never carries file content.
func ReadAuthTokenFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read auth token file: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("auth token file is empty")
	}
	return token, nil
}

// ReloadAuthTokenFile re-reads path and installs its token. On any error
// the previous token stays in force. changed reports whether the token
// differs from the one it replaced.
func (p *Proxy) ReloadAuthTokenFile(path string) (changed bool, err error) {
	token, err := ReadAuthTokenFile(path)
	if err != nil {
		return false, err
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(p.currentAuthToken())) == 1 {
		return false, nil
	}
	p.SetAuthToken(token)
	return true, nil
}

// WatchAuthTokenFile polls path every interval until ctx ends. Polling reads
// through the Kubernetes Secret "..data" symlink swap without depending on
// filesystem notification semantics. A failed reload logs a WARN once per
// distinct error and keeps the previous token.
func (p *Proxy) WatchAuthTokenFile(ctx context.Context, path string, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultAuthTokenFileInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var lastErr string
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		changed, err := p.ReloadAuthTokenFile(path)
		switch {
		case err != nil:
			if msg := err.Error(); msg != lastErr {
				slog.Warn("proxy auth token reload failed; keeping previous token", "subsystem", "proxy", "error", msg)
				lastErr = msg
			}
		case changed:
			lastErr = ""
			slog.Info("proxy auth token reloaded", "subsystem", "proxy")
		default:
			lastErr = ""
		}
	}
}
