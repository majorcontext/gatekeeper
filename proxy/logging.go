package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// readCloserWrapper wraps a Reader and Closer together.
type readCloserWrapper struct {
	io.Reader
	io.Closer
}

// captureBody reads up to MaxBodySize bytes from a body for logging, returning
// the captured data and a new ReadCloser that streams the full content.
// For small bodies (<=MaxBodySize), the body is fully buffered.
// For large bodies, only MaxBodySize is buffered; the rest streams through.
//
// captureBody does a blocking read-ahead, so it must only be used on bodies that
// are already fully available — i.e. request bodies. For response bodies, which
// may be produced incrementally (Server-Sent Events, ndjson, chunked JSON), use
// capturingBody: a read-ahead there would withhold the response from the client
// until MaxBodySize accumulated, starving streamed responses.
func captureBody(body io.ReadCloser, contentType string) ([]byte, io.ReadCloser) {
	if body == nil {
		return nil, nil
	}

	// Skip binary content types - don't capture but still pass through
	if !isTextContentType(contentType) {
		return nil, body
	}

	// Read first MaxBodySize bytes for capture/logging
	captureBuf := make([]byte, MaxBodySize)
	n, err := io.ReadFull(body, captureBuf)

	if err == io.EOF || err == io.ErrUnexpectedEOF {
		// Body was <= MaxBodySize, we got it all
		body.Close()
		captured := captureBuf[:n]
		return captured, io.NopCloser(bytes.NewReader(captured))
	}

	if err != nil {
		// Read error - return what we got
		body.Close()
		captured := captureBuf[:n]
		return captured, io.NopCloser(bytes.NewReader(captured))
	}

	// Body is larger than MaxBodySize - stream the rest through
	// Chain captured bytes with remaining body for full forwarding
	captured := captureBuf[:n]
	fullBody := io.MultiReader(bytes.NewReader(captured), body)
	return captured, &readCloserWrapper{Reader: fullBody, Closer: body}
}

// capturingBody wraps a response body, copying up to limit bytes into an
// in-memory buffer as the body is read, then invoking onClose (if non-nil)
// exactly once when the body is closed. Capture happens lazily as the downstream
// consumer reads, so — unlike captureBody's read-ahead — it never blocks the
// forwarding of a streamed response. Used for response-body logging on the
// streaming proxy paths.
//
// Not safe for concurrent Read/Close; the proxy paths read the body to
// completion and then close it, which is sequential.
type capturingBody struct {
	rc      io.ReadCloser
	buf     bytes.Buffer
	limit   int
	onClose func(captured []byte)
	closed  bool
}

func newCapturingBody(rc io.ReadCloser, limit int, onClose func(captured []byte)) *capturingBody {
	return &capturingBody{rc: rc, limit: limit, onClose: onClose}
}

func (c *capturingBody) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	if n > 0 {
		if room := c.limit - c.buf.Len(); room > 0 {
			if room > n {
				room = n
			}
			c.buf.Write(p[:room])
		}
	}
	return n, err
}

// Captured returns the bytes buffered so far (up to limit).
func (c *capturingBody) Captured() []byte { return c.buf.Bytes() }

func (c *capturingBody) Close() error {
	err := c.rc.Close()
	if !c.closed {
		c.closed = true
		if c.onClose != nil {
			c.onClose(c.buf.Bytes())
		}
	}
	return err
}

// FilterHeaders creates a copy of headers with sensitive values filtered.
// injectedHeaders is a set of lower-cased header names whose values should be
// redacted (credential headers the proxy injected).
func FilterHeaders(headers http.Header, injectedHeaders map[string]bool) map[string]string {
	if headers == nil {
		return nil
	}

	result := make(map[string]string)
	for key, values := range headers {
		// Always filter proxy headers
		if strings.EqualFold(key, "Proxy-Authorization") || strings.EqualFold(key, "Proxy-Connection") {
			continue
		}
		// Redact injected credential headers
		if injectedHeaders[strings.ToLower(key)] {
			result[key] = "[REDACTED]"
			continue
		}
		// Join multiple values with comma (standard HTTP practice)
		result[key] = strings.Join(values, ", ")
	}
	return result
}

// logRequest is a helper that logs request data if a logger is configured.
// The ctxReq parameter provides the RunContextData (from CONNECT or HTTP request context)
// for extracting the RunID; it may be nil when context is unavailable.
// The data struct is passed by value; this method enriches it with RunID, UserID,
// and Ctx from ctxReq before forwarding to the logger callback.
func (p *Proxy) logRequest(ctxReq *http.Request, data RequestLogData) {
	if p.logger == nil {
		return
	}
	if ctxReq != nil {
		if rc := getRunContext(ctxReq); rc != nil {
			data.RunID = rc.RunID
		}
		if uid := UserIDFromContext(ctxReq.Context()); uid != "" {
			data.UserID = uid
		}
		data.Ctx = ctxReq.Context()
		if data.RequestID == "" {
			data.RequestID = RequestIDFromContext(ctxReq.Context())
		}
	}
	data.AuthInjected = len(data.InjectedHeaders) > 0
	p.logger(data)
}

// logExit emits the canonical log line for a handler exit path. It copies
// base, stamps StatusCode and Duration (measured from start), applies mutate
// to let the caller set exit-specific fields (Err, Denied, DenyReason,
// InjectedHeaders, Grants, ResponseSize, ...), then forwards to logRequest.
// mutate may be nil when no extra fields apply.
func (p *Proxy) logExit(r *http.Request, base RequestLogData, start time.Time, status int, mutate func(*RequestLogData)) {
	data := base
	data.StatusCode = status
	data.Duration = time.Since(start)
	if mutate != nil {
		mutate(&data)
	}
	p.logRequest(r, data)
}

// logPolicy logs a policy denial — a request that was refused — if a logger is
// configured. For something policy noticed but did not stop, use
// logPolicyObservation.
func (p *Proxy) logPolicy(ctxReq *http.Request, scope, operation, rule, message string) {
	if p.policyLogger == nil {
		return
	}
	var runID string
	var reqCtx context.Context
	if ctxReq != nil {
		if rc := getRunContext(ctxReq); rc != nil {
			runID = rc.RunID
		}
		reqCtx = ctxReq.Context()
	}
	p.policyLogger(PolicyLogData{
		RunID:     runID,
		Scope:     scope,
		Operation: operation,
		Rule:      rule,
		Message:   message,
		Ctx:       reqCtx,
	})
}

// sensitiveHeaders are headers that must never be captured, even if configured.
var sensitiveHeaders = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
}

// ValidateCaptureHeaders checks a capture headers list for validity.
// Rejects sensitive headers, more than 10 entries, and case-insensitive duplicates.
func ValidateCaptureHeaders(headers []string) error {
	if len(headers) > 10 {
		return fmt.Errorf("capture_headers: max 10 headers allowed, got %d", len(headers))
	}
	seen := make(map[string]bool, len(headers))
	for _, h := range headers {
		lower := strings.ToLower(h)
		if sensitiveHeaders[lower] {
			return fmt.Errorf("capture_headers: %q is a sensitive header and cannot be captured", h)
		}
		if seen[lower] {
			return fmt.Errorf("capture_headers: duplicate header %q", h)
		}
		seen[lower] = true
	}
	return nil
}

// maxCapturedLogValueLen bounds how many bytes of a client-controlled string
// are kept in a request log entry.
const maxCapturedLogValueLen = 256

// SanitizeLogValue prepares a client-controlled string for inclusion in a
// structured log line: it discards invalid UTF-8, strips control characters
// (newlines, carriage returns, NUL, tabs, ...) so the value cannot forge
// additional log lines or otherwise corrupt structured log output, and
// bounds the result to maxCapturedLogValueLen bytes, truncating at a valid
// UTF-8 boundary rather than splitting a multi-byte rune. Used for both
// captured HTTP header values (capture_headers) and the Postgres
// application_name startup parameter — both are free-form text supplied by
// the client, not constrained by any protocol grammar the way most other
// logged fields are.
func SanitizeLogValue(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	if strings.ContainsFunc(s, unicode.IsControl) {
		s = strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return -1
			}
			return r
		}, s)
	}
	if len(s) > maxCapturedLogValueLen {
		s = s[:maxCapturedLogValueLen]
		for len(s) > 0 && !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

// logPolicyObservation records something policy noticed without refusing it.
//
// It reaches the same logger as logPolicy but is marked non-blocking, so a
// consumer can surface it without counting it toward the denial rate it
// alerts on.
func (p *Proxy) logPolicyObservation(ctxReq *http.Request, scope, operation, rule, message string) {
	if p.policyLogger == nil {
		return
	}
	var runID string
	var reqCtx context.Context
	if ctxReq != nil {
		if rc := getRunContext(ctxReq); rc != nil {
			runID = rc.RunID
		}
		reqCtx = ctxReq.Context()
	}
	p.policyLogger(PolicyLogData{
		NonBlocking: true,
		RunID:       runID,
		Scope:       scope,
		Operation:   operation,
		Rule:        rule,
		Message:     message,
		Ctx:         reqCtx,
	})
}

// logHeadersRedacted clones h for logging with the subject-identity
// headers declared by the host's matching resolver removed. Policy-denial
// logs snapshot headers before any resolver has run (denied requests must
// not trigger resolver side effects), so the proxy redacts the declared
// headers itself — credential values must never be logged. Headers a
// legacy (undeclared) resolver would strip cannot be known here; those
// registrations should migrate to SetCredentialResolverWithStripHeaders.
func (p *Proxy) logHeadersRedacted(h http.Header, host string) http.Header {
	out := h.Clone()
	entry, _ := p.getCredentialResolverMatch(host)
	for _, name := range entry.stripHeaders {
		out.Del(name)
	}
	return out
}
