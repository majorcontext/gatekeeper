package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

func newUpstreamTransport(rootCAs *x509.CertPool) *http.Transport {
	return &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
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
	p.mu.RLock()
	transport := p.h2UpstreamTransport
	p.mu.RUnlock()
	if transport != nil {
		return transport, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.h2UpstreamTransport != nil {
		return p.h2UpstreamTransport, nil
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
	p.h2UpstreamTransport = transport
	return transport, nil
}

// CloseIdleConnections closes idle connections in the shared upstream pool.
// Active requests and per-tunnel HTTP/1.1 transports are unaffected.
func (p *Proxy) CloseIdleConnections() {
	p.mu.RLock()
	transport := p.h2UpstreamTransport
	p.mu.RUnlock()
	if transport != nil {
		transport.CloseIdleConnections()
	}
}
