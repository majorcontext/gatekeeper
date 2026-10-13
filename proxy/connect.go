package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Extract host and port for network policy check
	host, portStr, err := net.SplitHostPort(r.Host)
	if err != nil {
		// r.Host should always have port in CONNECT requests
		http.Error(w, "invalid host format", http.StatusBadRequest)
		return
	}

	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		http.Error(w, "invalid port", http.StatusBadRequest)
		return
	}

	start := time.Now()

	// Check network policy before establishing tunnel
	if !p.checkNetworkPolicyForRequest(r, host, port, "CONNECT", "") {
		rc := getRunContext(r)
		var denyReason string
		if rc != nil && isHostGateway(rc, host) {
			denyReason = "Host service blocked: " + host + ":" + strconv.Itoa(port)
		} else {
			denyReason = "Host not in allow list: " + host
		}
		p.logRequest(r, RequestLogData{
			Method:       r.Method,
			URL:          r.Host,
			Host:         host,
			RequestType:  "connect",
			StatusCode:   http.StatusProxyAuthRequired,
			Duration:     time.Since(start),
			RequestSize:  -1,
			ResponseSize: -1,
			ClientAddr:   r.RemoteAddr,
			Denied:       true,
			DenyReason:   denyReason,
		})
		if rc != nil && isHostGateway(rc, host) {
			p.logPolicy(r, "network", "http.connect", "", "Host service blocked: "+host+":"+strconv.Itoa(port))
			p.writeHostBlockedResponse(w, host, port)
		} else {
			p.logPolicy(r, "network", "http.connect", "", "Host not in allow list: "+host)
			p.writeBlockedResponse(w, host)
		}
		return
	}

	// Do MITM interception when we have a CA configured.
	//
	// Security note: This intercepts ALL HTTPS traffic, not just credential-injected hosts.
	// This is intentional for full observability - a core feature. The container
	// trusts our CA and we verify upstream certs.
	//
	// Applications with certificate pinning may fail. This is expected behavior since
	// observability requires seeing all traffic.
	if p.ca != nil {
		p.handleConnectWithInterception(w, r, host)
		return
	}

	// Without TLS interception, per-path rules cannot be enforced on HTTPS
	// traffic — only host-level allow/deny applies. Warn if rules exist.
	if p.hasPathRulesForHost(r, host, port) {
		slog.Warn("per-path rules configured but TLS interception disabled; only host-level rules apply",
			"subsystem", "proxy", "host", host)
	}

	p.handleConnectTunnel(w, r)
}

// connectTunnelDialTimeout bounds how long the proxy waits to connect to the
// upstream on behalf of a CONNECT request. An unreachable HostGatewayIP (e.g.
// daemon-version-skew sends an empty IP and the fallback resolves nowhere)
// would otherwise cause the container to stall indefinitely.
const connectTunnelDialTimeout = 10 * time.Second

func (p *Proxy) handleConnectTunnel(w http.ResponseWriter, r *http.Request) {
	// Rewrite synthetic host-gateway hostname to actual IP for dialing.
	dialAddr := r.Host
	if rc := getRunContext(r); rc != nil && rc.HostGatewayIP != "" {
		host, _, _ := net.SplitHostPort(r.Host)
		if isHostGateway(rc, host) {
			dialAddr = rewriteHostPort(r.Host, rc.HostGatewayIP)
		}
	}
	dialCtx, cancel := context.WithTimeout(r.Context(), connectTunnelDialTimeout)
	defer cancel()
	targetConn, err := dialContext(dialCtx, "tcp", dialAddr)
	if err != nil {
		http.Error(w, p.errorPrefix()+": dial upstream failed", http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		targetConn.Close()
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		targetConn.Close()
		return
	}

	done, ok := p.conns.add(clientConn)
	if !ok {
		clientConn.Close()
		targetConn.Close()
		return
	}

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	var closeOnce sync.Once
	closeConns := func() {
		closeOnce.Do(func() {
			clientConn.Close()
			targetConn.Close()
		})
	}

	var copies sync.WaitGroup
	copies.Add(2)
	go func() {
		defer copies.Done()
		_, _ = io.Copy(targetConn, clientConn)
		closeConns()
	}()
	go func() {
		defer copies.Done()
		_, _ = io.Copy(clientConn, targetConn)
		closeConns()
	}()
	go func() {
		copies.Wait()
		done()
	}()
}

// Context keys for passing data between ReverseProxy hooks in the interception path.
type interceptCredResultKey struct{}

type interceptCredsKey struct{}

type interceptBundleResultKey struct{}

type interceptReqStartKey struct{}

type interceptLogURLKey struct{}

type interceptPreInjHeadersKey struct{}

type interceptReqBodyKey struct{}

func reqStartFromContext(ctx context.Context) time.Time {
	if t, ok := ctx.Value(interceptReqStartKey{}).(time.Time); ok {
		return t
	}
	return time.Now()
}
