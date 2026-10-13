package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

func newUpstreamTransport(rootCAs *x509.CertPool) *http.Transport {
	return &http.Transport{
		Proxy:       nil,
		DialContext: dialContext,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    rootCAs,
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 5 * time.Minute,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
	}
}

func (p *Proxy) getUpstreamCAs() *x509.CertPool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.upstreamCAs
}

func (p *Proxy) getH2UpstreamTransport() (*http.Transport, error) {
	return p.getH2UpstreamTransportFor(nil)
}

func (p *Proxy) getH2UpstreamTransportFor(rc *RunContextData) (*http.Transport, error) {
	key := poolKeyFor(rc)
	p.mu.RLock()
	transport := p.h2UpstreamTransports[key]
	p.mu.RUnlock()
	if transport != nil {
		return transport, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if transport := p.h2UpstreamTransports[key]; transport != nil {
		return transport, nil
	}
	transport = newUpstreamTransport(p.upstreamCAs)
	transport.ForceAttemptHTTP2 = true
	transport.ResponseHeaderTimeout = 0
	h2Transport, err := http2.ConfigureTransports(transport)
	if err != nil {
		return nil, err
	}
	h2Transport.ReadIdleTimeout = 30 * time.Second
	h2Transport.PingTimeout = 15 * time.Second
	if p.h2UpstreamTransports == nil {
		p.h2UpstreamTransports = make(map[poolKey]*http.Transport)
	}
	p.h2UpstreamTransports[key] = transport
	return transport, nil
}

// CloseIdleConnections closes idle connections in the shared upstream pools.
// Active requests and per-tunnel HTTP/1.1 transports are unaffected.
func (p *Proxy) CloseIdleConnections() {
	p.mu.RLock()
	transports := make([]*http.Transport, 0, len(p.h2UpstreamTransports))
	for _, transport := range p.h2UpstreamTransports {
		transports = append(transports, transport)
	}
	p.mu.RUnlock()
	for _, transport := range transports {
		transport.CloseIdleConnections()
	}
}
