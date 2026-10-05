package proxy

import (
	"testing"
	"time"
)

func TestUpstreamResponseHeaderTimeouts(t *testing.T) {
	p := NewProxy()
	transport, err := p.getH2UpstreamTransport()
	if err != nil {
		t.Fatal(err)
	}
	defer p.CloseIdleConnections()
	if got := transport.ResponseHeaderTimeout; got != 0 {
		t.Errorf("h2 response header timeout = %s, want no deadline for long-lived gRPC calls", got)
	}
	h1Transport := newUpstreamTransport(nil)
	defer h1Transport.CloseIdleConnections()
	if got := h1Transport.ResponseHeaderTimeout; got != 5*time.Minute {
		t.Errorf("h1 response header timeout = %s, want existing 5m0s", got)
	}
}
