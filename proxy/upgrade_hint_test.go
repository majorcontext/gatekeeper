package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestUpgradeHintHeaderValue(t *testing.T) {
	for _, tc := range []struct {
		name string
		hint UpgradeHint
		want string
	}{
		{"nil", nil, ""},
		{"members sorted, values kept in order",
			UpgradeHint{"route": {"gcp"}, "entitlements": {"gcp-ssh-staging", "gcp-deploy-dev"}},
			`entitlements=("gcp-ssh-staging" "gcp-deploy-dev"), route=("gcp")`},
		{"quote and backslash escaped", UpgradeHint{"why": {`say "hi" \o/`}}, `why=("say \"hi\" \\o/")`},
		{"key that is not an sf-key dropped", UpgradeHint{"Route": {"gcp"}, "ok": {"y"}}, `ok=("y")`},
		{"control character drops the member", UpgradeHint{"route": {"gcp\r\nX-Evil: 1"}, "ok": {"y"}}, `ok=("y")`},
		{"non-ASCII drops the member", UpgradeHint{"route": {"gcé"}}, ""},
		{"member with no values dropped", UpgradeHint{"route": {}}, ""},
		{"hint over the size cap dropped whole", UpgradeHint{"route": {"gcp"}, "entitlements": {strings.Repeat("e", maxUpgradeHintHeaderLen)}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.hint.headerValue(); got != tc.want {
				t.Errorf("headerValue() = %q, want %q", got, tc.want)
			}
		})
	}
}

var sshHint = UpgradeHint{"route": {"gcp"}, "entitlements": {"gcp-ssh-staging"}}

const sshHintHeader = `entitlements=("gcp-ssh-staging"), route=("gcp")`

type upgradeRow struct {
	name string
	// static is the host's configured default; empty configures none.
	static   string
	resolve  func(invalidates *atomic.Int32) ([]CredentialHeader, error)
	upstream int
	// forged is an X-Gatekeeper-Upgrade value the upstream itself sends.
	forged string

	wantAuth        string
	wantStatus      int
	wantHint        string
	wantInvalidates int32
}

func declining(hint UpgradeHint) func(*atomic.Int32) ([]CredentialHeader, error) {
	return func(n *atomic.Int32) ([]CredentialHeader, error) {
		return nil, &ResolverDeclined{UpgradeHint: hint, Invalidate: func() { n.Add(1) }}
	}
}

func resolving(hint UpgradeHint) func(*atomic.Int32) ([]CredentialHeader, error) {
	return func(n *atomic.Int32) ([]CredentialHeader, error) {
		return []CredentialHeader{{Name: "Authorization", Value: "Bearer upgraded", Grant: "gcp-user",
			AllowInsecure: true, UpgradeHint: hint, Invalidate: func() { n.Add(1) }}}, nil
	}
}

func upgradeRows() []upgradeRow {
	return []upgradeRow{
		{
			name:   "decline falls back to the static default; a 403 carries the hint and evicts the decline",
			static: "Bearer default", resolve: declining(sshHint), upstream: http.StatusForbidden,
			wantAuth: "Bearer default", wantStatus: http.StatusForbidden, wantHint: sshHintHeader, wantInvalidates: 1,
		},
		{
			name:   "decline with a 200 sends no hint and keeps the decline cached",
			static: "Bearer default", resolve: declining(sshHint), upstream: http.StatusOK,
			wantAuth: "Bearer default", wantStatus: http.StatusOK,
		},
		{
			name:    "decline with no static default forwards the client's own header",
			resolve: declining(sshHint), upstream: http.StatusUnauthorized,
			wantAuth: "Bearer placeholder", wantStatus: http.StatusUnauthorized, wantHint: sshHintHeader, wantInvalidates: 1,
		},
		{
			name:   "resolved credential's hint reaches the client on a 401",
			static: "Bearer default", resolve: resolving(sshHint), upstream: http.StatusUnauthorized,
			wantAuth: "Bearer upgraded", wantStatus: http.StatusUnauthorized, wantHint: sshHintHeader, wantInvalidates: 1,
		},
		{
			name:   "429 evicts but sends no hint",
			static: "Bearer default", resolve: declining(sshHint), upstream: http.StatusTooManyRequests,
			wantAuth: "Bearer default", wantStatus: http.StatusTooManyRequests, wantInvalidates: 1,
		},
		{
			name:   "upstream cannot forge the hint header",
			static: "Bearer default", resolve: resolving(nil), upstream: http.StatusForbidden, forged: `route=("evil")`,
			wantAuth: "Bearer upgraded", wantStatus: http.StatusForbidden, wantInvalidates: 1,
		},
		{
			name:     "other resolver errors still fail closed",
			static:   "Bearer default",
			resolve:  func(*atomic.Int32) ([]CredentialHeader, error) { return nil, errors.New("sts unreachable") },
			upstream: http.StatusOK, wantStatus: http.StatusBadGateway,
		},
	}
}

func upgradeUpstream(t *testing.T, row upgradeRow, tlsServer bool) (*httptest.Server, *atomic.Value) {
	t.Helper()
	var gotAuth atomic.Value
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		if row.forged != "" {
			w.Header().Set(UpgradeHintHeader, row.forged)
		}
		w.WriteHeader(row.upstream)
	})
	s := httptest.NewServer(h)
	if tlsServer {
		s.Close()
		s = httptest.NewTLSServer(h)
	}
	t.Cleanup(s.Close)
	return s, &gotAuth
}

func upgradeProxy(row upgradeRow, host string, invalidates *atomic.Int32) *Proxy {
	p := NewProxy()
	if row.static != "" {
		p.SetInsecureCredentialWithGrant(host, "Authorization", row.static, "default")
	}
	p.SetCredentialResolver(host, func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]CredentialHeader, error) {
		return row.resolve(invalidates)
	})
	return p
}

func TestResolverDeclineAndUpgradeHint(t *testing.T) {
	for _, row := range upgradeRows() {
		t.Run("http-cleartext/"+row.name, func(t *testing.T) {
			up, gotAuth := upgradeUpstream(t, row, false)
			redirectHTTPTransport(t, up.Listener.Addr().String())
			var invalidates atomic.Int32
			p := upgradeProxy(row, "api.example.com", &invalidates)
			req := httptest.NewRequest("GET", "http://api.example.com:8080/v1/projects", nil)
			req.Header.Set("Authorization", "Bearer placeholder")
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)
			assertUpgrade(t, row, rec.Code, rec.Header(), gotAuth, &invalidates)
		})
		t.Run("relay/"+row.name, func(t *testing.T) {
			up, gotAuth := upgradeUpstream(t, row, false)
			var invalidates atomic.Int32
			p := upgradeProxy(row, mustParseURL(up.URL).Hostname(), &invalidates)
			if err := p.AddRelay("gcp", up.URL); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("GET", "/relay/gcp/v1/projects", nil)
			req.Header.Set("Authorization", "Bearer placeholder")
			rec := httptest.NewRecorder()
			p.handleRelay(rec, req)
			assertUpgrade(t, row, rec.Code, rec.Header(), gotAuth, &invalidates)
		})
		t.Run("connect-intercept/"+row.name, func(t *testing.T) {
			up, gotAuth := upgradeUpstream(t, row, true)
			var invalidates atomic.Int32
			p := upgradeProxy(row, mustParseURL(up.URL).Hostname(), &invalidates)
			ca := contractCA(t)
			upstreamCAs := x509.NewCertPool()
			upstreamCAs.AddCert(up.Certificate())
			p.SetCA(ca)
			p.SetUpstreamCAs(upstreamCAs)
			proxySrv := httptest.NewServer(p)
			t.Cleanup(proxySrv.Close)

			clientCAs := x509.NewCertPool()
			clientCAs.AppendCertsFromPEM(ca.certPEM)
			proxyURL, _ := url.Parse(proxySrv.URL)
			client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: clientCAs}}}
			t.Cleanup(client.CloseIdleConnections)
			req, _ := http.NewRequest("GET", up.URL+"/v1/projects", strings.NewReader(""))
			req.Header.Set("Authorization", "Bearer placeholder")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			assertUpgrade(t, row, resp.StatusCode, resp.Header, gotAuth, &invalidates)
		})
	}
}

func assertUpgrade(t *testing.T, row upgradeRow, status int, h http.Header, gotAuth *atomic.Value, invalidates *atomic.Int32) {
	t.Helper()
	if status != row.wantStatus {
		t.Errorf("status = %d, want %d", status, row.wantStatus)
	}
	auth, reached := gotAuth.Load().(string)
	if row.wantStatus == http.StatusBadGateway {
		if reached {
			t.Errorf("request reached upstream with Authorization %q, want it refused", auth)
		}
		return
	}
	if auth != row.wantAuth {
		t.Errorf("upstream Authorization = %q, want %q", auth, row.wantAuth)
	}
	if got := h.Get(UpgradeHintHeader); got != row.wantHint {
		t.Errorf("%s = %q, want %q", UpgradeHintHeader, got, row.wantHint)
	}
	if n := invalidates.Load(); n != row.wantInvalidates {
		t.Errorf("Invalidate calls = %d, want %d", n, row.wantInvalidates)
	}
}

// A hint that serializes to nothing must not hide a usable one.
func TestSettleUpstreamResponse_SkipsEmptyHint(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusForbidden, Header: http.Header{}}
	injected := []CredentialHeader{{Name: "Authorization", UpgradeHint: sshHint}}
	settleUpstreamResponse(resp, injected, &ResolverDeclined{UpgradeHint: UpgradeHint{"Route": {"gcp"}}})
	if got := resp.Header.Get(UpgradeHintHeader); got != sshHintHeader {
		t.Errorf("%s = %q, want %q", UpgradeHintHeader, got, sshHintHeader)
	}
}

// An upstream behind CONNECT interception must not forge the hint as a
// trailer, announced or not. Other trailers still reach the client.
func TestConnectIntercept_ForgedHintTrailerRemoved(t *testing.T) {
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Gatekeeper-Upgrade, X-Checksum")
		io.WriteString(w, "body")
		w.Header().Set("X-Gatekeeper-Upgrade", `route=("announced")`)
		w.Header().Set("X-Checksum", "abc")
		w.Header().Set(http.TrailerPrefix+"X-Gatekeeper-Upgrade", `route=("unannounced")`)
	}))
	t.Cleanup(up.Close)
	ca := contractCA(t)
	upstreamCAs := x509.NewCertPool()
	upstreamCAs.AddCert(up.Certificate())
	p := NewProxy()
	p.SetCA(ca)
	p.SetUpstreamCAs(upstreamCAs)
	proxySrv := httptest.NewServer(p)
	t.Cleanup(proxySrv.Close)
	clientCAs := x509.NewCertPool()
	clientCAs.AppendCertsFromPEM(ca.certPEM)
	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: clientCAs}}}
	t.Cleanup(client.CloseIdleConnections)

	resp, err := client.Get(up.URL + "/")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if _, announced := resp.Trailer[UpgradeHintHeader]; announced {
		t.Errorf("Trailer announces %s, want it removed", UpgradeHintHeader)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "body" {
		t.Errorf("body = %q, want %q", body, "body")
	}
	if got := resp.Trailer.Values(UpgradeHintHeader); len(got) != 0 {
		t.Errorf("trailer %s = %q, want none", UpgradeHintHeader, got)
	}
	if got := resp.Trailer.Get("X-Checksum"); got != "abc" {
		t.Errorf("trailer X-Checksum = %q, want abc", got)
	}
}
