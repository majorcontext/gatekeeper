package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// streamResponseBody copies body to w with per-chunk flushing, returning
// bytes written and the error to attribute (nil for EOF, client
// cancellation, or client-side write failure; the upstream read error when
// the upstream failed while the client was connected).
//
// readErr and writeErr are tracked separately so that, when a single Read
// call returns both n>0 bytes and a non-EOF error and the client Write of
// those bytes also fails, the upstream readErr — the actionable failure —
// is captured rather than being masked by the concurrent writeErr.
//
// The returned error records an abnormal end of the stream: the upstream
// status was already sent, so the client sees a truncated body rather than
// an error status, and the caller's canonical log line is the only place
// the failure can surface. Only a non-EOF upstream read error is returned,
// and only when the client was still there to receive it (ctx.Err() ==
// nil) — a canceled client context and a client-side write failure are both
// routine disconnects, not proxy-side failures, and must not escalate the
// canonical log line to ERROR severity.
func streamResponseBody(w http.ResponseWriter, body io.Reader, ctx context.Context) (int64, error) {
	flusher, canFlush := w.(http.Flusher)

	var readErr, writeErr error
	var written int64
	buf := make([]byte, 4096)
	for {
		n, rErr := body.Read(buf)
		if n > 0 {
			wn, wErr := w.Write(buf[:n])
			written += int64(wn)
			if wErr != nil {
				writeErr = wErr
			} else if canFlush {
				flusher.Flush()
			}
		}
		if rErr != nil {
			readErr = rErr
			break
		}
		if writeErr != nil {
			break
		}
	}

	if readErr != nil && !errors.Is(readErr, io.EOF) && ctx.Err() == nil {
		return written, fmt.Errorf("reading upstream response body: %w", readErr)
	}
	return written, nil
}
