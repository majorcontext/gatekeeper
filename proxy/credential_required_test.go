package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

type requiredRow struct {
	name     string
	explicit bool
	headers  map[string]string

	wantStatus int
	wantAPIKey string
	wantAuth   string
}

// A box with no subscription account sends the claude CLI's OAuth request
// to api.anthropic.com. With explicit-only fallback, the static x-api-key
// must not be auto-injected: the request is refused. A client that names
// the static key by sending its header still gets it.
func requiredRows() []requiredRow {
	return []requiredRow{
		{
			name: "explicit-only refuses a request that names no static credential", explicit: true,
			headers:    map[string]string{"Authorization": "Bearer placeholder"},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "explicit-only injects the static credential the client names", explicit: true,
			headers:    map[string]string{"X-Api-Key": "placeholder"},
			wantStatus: http.StatusOK, wantAPIKey: "sk-static",
		},
		{
			name:       "auto fallback still injects the static credential",
			headers:    map[string]string{"Authorization": "Bearer placeholder"},
			wantStatus: http.StatusOK, wantAPIKey: "sk-static", wantAuth: "Bearer placeholder",
		},
	}
}

func requiredProxy(row requiredRow, host string) *Proxy {
	p := NewProxy()
	p.SetInsecureCredentialWithGrant(host, "x-api-key", "sk-static", "anthropic")
	p.SetCredentialResolver(host, func(context.Context, *http.Request, *http.Request, string) ([]CredentialHeader, error) {
		return nil, &ResolverDeclined{ExplicitOnly: row.explicit, Grant: "claude-code-user"}
	})
	return p
}

type seenRequest struct{ apiKey, auth string }

func requiredUpstream(t *testing.T, tlsServer bool) (*httptest.Server, *atomic.Pointer[seenRequest]) {
	t.Helper()
	var seen atomic.Pointer[seenRequest]
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Store(&seenRequest{apiKey: r.Header.Get("X-Api-Key"), auth: r.Header.Get("Authorization")})
	})
	s := httptest.NewUnstartedServer(h)
	if tlsServer {
		s.StartTLS()
	} else {
		s.Start()
	}
	t.Cleanup(s.Close)
	return s, &seen
}

func TestResolverDeclined_ExplicitOnly(t *testing.T) {
	for _, row := range requiredRows() {
		t.Run("http-cleartext/"+row.name, func(t *testing.T) {
			up, seen := requiredUpstream(t, false)
			redirectHTTPTransport(t, up.Listener.Addr().String())
			p := requiredProxy(row, "api.anthropic.com")
			req := httptest.NewRequest("POST", "http://api.anthropic.com:8080/v1/messages", nil)
			for k, v := range row.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, req)
			assertRequired(t, row, rec.Code, rec.Header(), rec.Body.String(), seen.Load())
		})
		t.Run("relay/"+row.name, func(t *testing.T) {
			up, seen := requiredUpstream(t, false)
			p := requiredProxy(row, mustParseURL(up.URL).Hostname())
			if err := p.AddRelay("anthropic", up.URL); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("POST", "/relay/anthropic/v1/messages", nil)
			for k, v := range row.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			p.handleRelay(rec, req)
			assertRequired(t, row, rec.Code, rec.Header(), rec.Body.String(), seen.Load())
		})
		t.Run("connect-intercept/"+row.name, func(t *testing.T) {
			up, seen := requiredUpstream(t, true)
			p := requiredProxy(row, mustParseURL(up.URL).Hostname())
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
			req, _ := http.NewRequest("POST", up.URL+"/v1/messages", nil)
			for k, v := range row.headers {
				req.Header.Set(k, v)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			assertRequired(t, row, resp.StatusCode, resp.Header, string(body), seen.Load())
		})
	}
}

func assertRequired(t *testing.T, row requiredRow, status int, h http.Header, body string, seen *seenRequest) {
	t.Helper()
	if status != row.wantStatus {
		t.Errorf("status = %d, want %d", status, row.wantStatus)
	}
	if row.wantStatus == http.StatusForbidden {
		if seen != nil {
			t.Errorf("request reached upstream with x-api-key %q, want it refused", seen.apiKey)
		}
		if got := h.Get("X-Gatekeeper-Blocked"); got != "credential-required" {
			t.Errorf("X-Gatekeeper-Blocked = %q, want credential-required", got)
		}
		if !strings.Contains(body, "claude-code-user") {
			t.Errorf("body = %q, want it to name the grant", body)
		}
		return
	}
	if seen == nil {
		t.Fatal("request never reached upstream")
	}
	if seen.apiKey != row.wantAPIKey || seen.auth != row.wantAuth {
		t.Errorf("upstream x-api-key, Authorization = %q, %q; want %q, %q", seen.apiKey, seen.auth, row.wantAPIKey, row.wantAuth)
	}
}

// A resolver that consumed the client's header (subject_header:
// Authorization) left nothing the client chose: the static Authorization
// credential must not ride in on the subject token.
func TestResolverDeclined_ExplicitOnlyIgnoresConsumedHeader(t *testing.T) {
	up, seen := requiredUpstream(t, false)
	redirectHTTPTransport(t, up.Listener.Addr().String())
	p := NewProxy()
	p.SetInsecureCredentialWithGrant("api.example.com", "Authorization", "Bearer static", "bot")
	p.SetCredentialResolver("api.example.com", func(_ context.Context, _, inner *http.Request, _ string) ([]CredentialHeader, error) {
		inner.Header.Del("Authorization")
		return nil, &ResolverDeclined{ExplicitOnly: true, Grant: "user"}
	})
	req := httptest.NewRequest("GET", "http://api.example.com:8080/", nil)
	req.Header.Set("Authorization", "usr_1")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || seen.Load() != nil {
		t.Errorf("status = %d, reached upstream = %v; want 403 and not forwarded", rec.Code, seen.Load() != nil)
	}
}

// A /relay/ refusal must carry the caller's proxy-auth user, like the
// CONNECT and plain-HTTP paths, so the denial is attributable.
func TestRelay_CredentialRequiredLogsUserID(t *testing.T) {
	up, _ := requiredUpstream(t, false)
	p := requiredProxy(requiredRow{explicit: true}, mustParseURL(up.URL).Hostname())
	if err := p.AddRelay("anthropic", up.URL); err != nil {
		t.Fatal(err)
	}
	var logged []RequestLogData
	p.SetLogger(func(d RequestLogData) { logged = append(logged, d) })
	req := httptest.NewRequest("POST", "/relay/anthropic/v1/messages", nil)
	req.SetBasicAuth("usr_1|box_1", "boxtoken")
	req.Header.Set("Proxy-Authorization", req.Header.Get("Authorization"))
	req.Header.Del("Authorization")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || len(logged) != 1 || logged[0].UserID != "usr_1|box_1" || !logged[0].Denied {
		t.Fatalf("status = %d, logs = %+v; want 403 and one denied line with UserID usr_1|box_1", rec.Code, logged)
	}
}
