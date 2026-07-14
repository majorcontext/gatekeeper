package proxy

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// recordingReader is an io.Reader that never returns an error (simulating an
// unbounded/infinite upstream stream such as SSE) and records the number of
// bytes returned on each Read call, so a test can distinguish bytes read
// before a client write failure from bytes read afterward (the drain).
type recordingReader struct {
	reads []int
}

func (r *recordingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	r.reads = append(r.reads, len(p))
	return len(p), nil
}

// failingWriter is an http.ResponseWriter whose Write always fails, simulating
// a client that has gone away mid-stream.
type failingWriter struct {
	header http.Header
}

func (w *failingWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("client write failed")
}

func (w *failingWriter) WriteHeader(int) {}

// TestStreamResponseBody_DrainsBoundedAfterClientWriteFailure verifies that
// after a client write failure, streamResponseBody drains a bounded amount of
// the remaining upstream body (rather than nothing, and rather than
// unboundedly) so the caller's deferred resp.Body.Close can return the
// underlying connection to the keep-alive pool instead of tearing it down.
//
// The body here never reaches EOF (like an infinite SSE stream), so an
// unbounded drain would hang the goroutine forever; the drain must stop at
// drainLimit bytes.
func TestStreamResponseBody_DrainsBoundedAfterClientWriteFailure(t *testing.T) {
	body := &recordingReader{}
	w := &failingWriter{}

	_, err := streamResponseBody(w, body, context.Background())
	if err != nil {
		t.Fatalf("streamResponseBody returned error %v, want nil (a client write failure is a routine disconnect, not a proxy-side failure)", err)
	}

	if len(body.reads) < 2 {
		t.Fatalf("body.reads = %d Read call(s), want at least 2 (the initial read plus a drain read) — drain did not occur", len(body.reads))
	}

	var drained int
	for _, n := range body.reads[1:] {
		drained += n
	}
	if drained != drainLimit {
		t.Errorf("drained %d bytes after the client write failure, want exactly %d (drainLimit)", drained, drainLimit)
	}
}

// TestStreamResponseBody_SkipsDrainWhenContextCanceled verifies that when the
// request context is already canceled (the client is gone AND the handler
// should return promptly), streamResponseBody does not attempt the bounded
// drain — net/http will close the body anyway.
func TestStreamResponseBody_SkipsDrainWhenContextCanceled(t *testing.T) {
	body := &recordingReader{}
	w := &failingWriter{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := streamResponseBody(w, body, ctx)
	if err != nil {
		t.Fatalf("streamResponseBody returned error %v, want nil", err)
	}

	if len(body.reads) != 1 {
		t.Errorf("body.reads = %d Read call(s), want exactly 1 (no drain attempted once ctx is already canceled)", len(body.reads))
	}
}
