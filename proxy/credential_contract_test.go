package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type hostKeys struct{ h, hp string }

type contractRow struct {
	name string
	host string // request host override; the CONNECT backend is 127.0.0.1, so overrides run on the plain-HTTP path only
	port string // request port override

	proxy func(p *Proxy, k hostKeys, calls *atomic.Int32)
	rc    func(k hostKeys) *RunContextData

	method  string
	path    string
	body    string
	headers map[string]string

	want       map[string]string
	wantPath   string
	wantBody   string
	wantStatus int
	wantCalls  int32

	// plainHTTPOK marks rows whose injected headers are not secrets, so
	// the plain-HTTP path forwards them.
	plainHTTPOK bool
}

type wireRequest struct {
	header http.Header
	path   string
	body   string
}

var contractNoise = []string{"User-Agent", "Accept-Encoding", "X-Request-Id", "Content-Length", "Transfer-Encoding", "Connection"}

func (w wireRequest) flat() []string {
	h := w.header.Clone()
	for _, n := range contractNoise {
		h.Del(n)
	}
	var out []string
	for k, v := range h {
		out = append(out, k+": "+strings.Join(v, ","))
	}
	slices.Sort(out)
	return out
}

func wantFlat(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, http.CanonicalHeaderKey(k)+": "+v)
	}
	slices.Sort(out)
	return out
}

func newContractUpstream(t *testing.T, tlsServer bool) (*httptest.Server, <-chan wireRequest) {
	t.Helper()
	got := make(chan wireRequest, 4)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- wireRequest{header: r.Header.Clone(), path: r.URL.Path, body: string(b)}
		io.WriteString(w, "ok")
	})
	var s *httptest.Server
	if tlsServer {
		s = httptest.NewTLSServer(h)
	} else {
		s = httptest.NewServer(h)
	}
	t.Cleanup(s.Close)
	return s, got
}

func redirectHTTPTransport(t *testing.T, to string) {
	t.Helper()
	orig := httpTransport
	tr := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, to)
	}}
	httpTransport = tr
	t.Cleanup(func() { httpTransport = orig; tr.CloseIdleConnections() })
}

var (
	contractCAOnce sync.Once
	contractCAVal  *CA
	contractCAErr  error
)

func contractCA(t *testing.T) *CA {
	t.Helper()
	contractCAOnce.Do(func() { contractCAVal, contractCAErr = generateCA() })
	if contractCAErr != nil {
		t.Fatal(contractCAErr)
	}
	return contractCAVal
}

func rawCreds(p *Proxy, key string, creds ...CredentialHeader) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.credentials[key] = creds
}

func cred(name, value, grant string) CredentialHeader {
	return CredentialHeader{Name: name, Value: value, Grant: grant}
}

func rcCreds(m func(k hostKeys) map[string][]CredentialHeader) func(hostKeys) *RunContextData {
	return func(k hostKeys) *RunContextData {
		return &RunContextData{Policy: "permissive", Credentials: m(k)}
	}
}

func authCred(v, grant string) []CredentialHeader {
	return []CredentialHeader{cred("Authorization", v, grant)}
}

func resolverReturning(calls *atomic.Int32, v, grant string) CredentialResolver {
	return func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]CredentialHeader, error) {
		calls.Add(1)
		return authCred(v, grant), nil
	}
}

func contractRows() []contractRow {
	return []contractRow{
		// Per-request context credentials versus proxy-level credentials.
		{
			name: "proxy-level credential injected when no run context",
			proxy: func(p *Proxy, k hostKeys, _ *atomic.Int32) {
				p.SetCredentialWithGrant(k.h, "Authorization", "Bearer proxy", "g")
			},
			want: map[string]string{"Authorization": "Bearer proxy"},
		},
		{
			name: "run context credential replaces proxy-level credential",
			proxy: func(p *Proxy, k hostKeys, _ *atomic.Int32) {
				p.SetCredentialWithGrant(k.h, "Authorization", "Bearer proxy", "g")
			},
			rc: rcCreds(func(k hostKeys) map[string][]CredentialHeader {
				return map[string][]CredentialHeader{k.h: {cred("X-Run-Key", "run", "rg")}}
			}),
			want: map[string]string{"X-Run-Key": "run"},
		},
		{
			name: "run context without a matching key injects nothing even if proxy-level matches",
			proxy: func(p *Proxy, k hostKeys, _ *atomic.Int32) {
				p.SetCredentialWithGrant(k.h, "Authorization", "Bearer proxy", "g")
			},
			rc: rcCreds(func(hostKeys) map[string][]CredentialHeader {
				return map[string][]CredentialHeader{"other.test": authCred("Bearer o", "g")}
			}),
			want: map[string]string{},
		},
		{
			name: "run context empty host:port entry falls through to bare entry",
			rc: rcCreds(func(k hostKeys) map[string][]CredentialHeader {
				return map[string][]CredentialHeader{k.hp: {}, k.h: authCred("Bearer bare", "g")}
			}),
			want: map[string]string{"Authorization": "Bearer bare"},
		},
		{
			name: "no matching credential leaves the client header untouched",
			proxy: func(p *Proxy, _ hostKeys, _ *atomic.Int32) {
				p.SetCredentialWithGrant("unrelated.test", "Authorization", "Bearer x", "g")
			},
			headers: map[string]string{"Authorization": "Bearer client"},
			want:    map[string]string{"Authorization": "Bearer client"},
		},

		// Host-key specificity within one map.
		{
			name: "host:port key beats bare key",
			proxy: func(p *Proxy, k hostKeys, _ *atomic.Int32) {
				rawCreds(p, k.h, cred("Authorization", "Bearer bare", "bare"))
				rawCreds(p, k.hp, cred("Authorization", "Bearer pinned", "pinned"))
			},
			want: map[string]string{"Authorization": "Bearer pinned"},
		},
		{
			name: "host:port key for another port does not match",
			proxy: func(p *Proxy, k hostKeys, _ *atomic.Int32) {
				rawCreds(p, k.h+":1", cred("Authorization", "Bearer other-port", "g"))
			},
			want: map[string]string{},
		},
		{
			name: "exact key beats wildcard key",
			host: "svc.box.test",
			proxy: func(p *Proxy, _ hostKeys, _ *atomic.Int32) {
				p.SetCredentialWithGrant("*.box.test", "Authorization", "Bearer wild", "wild")
				p.SetCredentialWithGrant("svc.box.test", "Authorization", "Bearer exact", "exact")
			},
			want: map[string]string{"Authorization": "Bearer exact"},
		},
		{
			name: "wildcard excludes the apex",
			host: "box.test",
			rc: rcCreds(func(hostKeys) map[string][]CredentialHeader {
				return map[string][]CredentialHeader{"*.box.test": {cred("Cf-Access-Client-Id", "id", "cf")}}
			}),
			want: map[string]string{},
		},
		{
			name: "wildcard matches a subdomain",
			host: "alpha.box.test",
			rc: rcCreds(func(hostKeys) map[string][]CredentialHeader {
				return map[string][]CredentialHeader{"*.box.test": {cred("Cf-Access-Client-Id", "id", "cf")}}
			}),
			want: map[string]string{"Cf-Access-Client-Id": "id"},
		},
		{
			name: "wildcard key with port matches only that port",
			host: "svc.internal.test",
			port: "8443",
			rc: rcCreds(func(hostKeys) map[string][]CredentialHeader {
				return map[string][]CredentialHeader{"*.internal.test:8443": authCred("Bearer tok", "g")}
			}),
			want: map[string]string{"Authorization": "Bearer tok"},
		},
		{
			name: "wildcard key with port skips other ports",
			host: "svc.internal.test",
			port: "9999",
			rc: rcCreds(func(hostKeys) map[string][]CredentialHeader {
				return map[string][]CredentialHeader{"*.internal.test:8443": authCred("Bearer tok", "g")}
			}),
			want: map[string]string{},
		},
		{
			name: "narrower wildcard domain outranks a port suffix on a broader one",
			host: "svc.api.test",
			port: "8443",
			rc: rcCreds(func(hostKeys) map[string][]CredentialHeader {
				return map[string][]CredentialHeader{
					"*.test:8443": authCred("Bearer broad", "broad"),
					"*.api.test":  authCred("Bearer narrow", "narrow"),
				}
			}),
			want: map[string]string{"Authorization": "Bearer narrow"},
		},
		{
			name: "port-pinned wildcard beats port-less wildcard at equal domain",
			host: "svc.api.test",
			port: "8443",
			rc: rcCreds(func(hostKeys) map[string][]CredentialHeader {
				return map[string][]CredentialHeader{
					"*.api.test:8443": authCred("Bearer pinned", "pinned"),
					"*.api.test":      authCred("Bearer plain", "plain"),
				}
			}),
			want: map[string]string{"Authorization": "Bearer pinned"},
		},

		// Case-insensitivity.
		{
			name: "mixed-case request host still hits its exact key over a wildcard",
			host: "Special.box.test",
			proxy: func(p *Proxy, _ hostKeys, _ *atomic.Int32) {
				p.SetCredentialWithGrant("special.box.test", "Authorization", "Bearer exact", "exact")
				p.SetCredentialWithGrant("*.box.test", "Authorization", "Bearer wild", "wild")
			},
			want: map[string]string{"Authorization": "Bearer exact"},
		},
		{
			name: "case-variant host:port hits its port-bearing exact key",
			host: "Internal.test",
			port: "8443",
			rc: rcCreds(func(hostKeys) map[string][]CredentialHeader {
				return map[string][]CredentialHeader{
					"internal.test:8443": authCred("Bearer exact", "exact"),
					"*.test:8443":        authCred("Bearer wild", "wild"),
				}
			}),
			want: map[string]string{"Authorization": "Bearer exact"},
		},
		{
			name: "case-fold host:port match beats case-fold bare match",
			host: "api.test",
			port: "8443",
			rc: rcCreds(func(hostKeys) map[string][]CredentialHeader {
				return map[string][]CredentialHeader{
					"API.test":      authCred("Bearer portless", "portless"),
					"API.test:8443": authCred("Bearer pinned", "pinned"),
				}
			}),
			want: map[string]string{"Authorization": "Bearer pinned"},
		},
		{
			name: "bracketed IPv6 host matches the unbracketed key",
			host: "[::1]",
			rc: rcCreds(func(hostKeys) map[string][]CredentialHeader {
				return map[string][]CredentialHeader{"::1": authCred("Bearer v6", "v6")}
			}),
			want: map[string]string{"Authorization": "Bearer v6"},
		},

		// Static credentials versus resolvers.
		{
			name: "exact static beats wildcard resolver",
			host: "api.box.test",
			proxy: func(p *Proxy, _ hostKeys, c *atomic.Int32) {
				p.SetCredentialWithGrant("api.box.test", "Authorization", "Bearer static", "static")
				p.SetCredentialResolver("*.box.test", resolverReturning(c, "Bearer resolver", "resolver"))
			},
			want:      map[string]string{"Authorization": "Bearer static"},
			wantCalls: 1,
		},
		{
			name: "wildcard resolver serves a host with no exact static entry",
			host: "other.box.test",
			proxy: func(p *Proxy, _ hostKeys, c *atomic.Int32) {
				p.SetCredentialWithGrant("api.box.test", "Authorization", "Bearer static", "static")
				p.SetCredentialResolver("*.box.test", resolverReturning(c, "Bearer resolver", "resolver"))
			},
			want:      map[string]string{"Authorization": "Bearer resolver"},
			wantCalls: 1,
		},
		{
			name: "more specific wildcard static beats broader wildcard resolver",
			host: "svc.api.box.test",
			proxy: func(p *Proxy, _ hostKeys, c *atomic.Int32) {
				p.SetCredentialWithGrant("*.api.box.test", "Authorization", "Bearer static", "static")
				p.SetCredentialResolver("*.box.test", resolverReturning(c, "Bearer resolver", "resolver"))
			},
			want:      map[string]string{"Authorization": "Bearer static"},
			wantCalls: 1,
		},
		{
			name: "verbatim static beats case-fold resolver",
			host: "api.box.test",
			proxy: func(p *Proxy, k hostKeys, c *atomic.Int32) {
				p.SetCredentialWithGrant(k.h, "Authorization", "Bearer static", "static")
				p.SetCredentialResolver("API.box.test", resolverReturning(c, "Bearer resolver", "resolver"))
			},
			want:      map[string]string{"Authorization": "Bearer static"},
			wantCalls: 1,
		},
		{
			name: "port-pinned static beats bare resolver",
			proxy: func(p *Proxy, k hostKeys, c *atomic.Int32) {
				rawCreds(p, k.hp, cred("Authorization", "Bearer pinned", "pinned"))
				p.SetCredentialResolver(k.h, resolverReturning(c, "Bearer resolver", "resolver"))
			},
			want:      map[string]string{"Authorization": "Bearer pinned"},
			wantCalls: 1,
		},
		{
			name: "nil resolver opts the host out of a broader wildcard resolver",
			host: "api.box.test",
			proxy: func(p *Proxy, _ hostKeys, c *atomic.Int32) {
				p.SetCredentialResolver("*.box.test", resolverReturning(c, "Bearer resolver", "resolver"))
				p.SetCredentialResolver("api.box.test", nil)
				p.SetCredentialWithGrant("api.box.test", "Authorization", "Bearer static", "static")
			},
			want: map[string]string{"Authorization": "Bearer static"},
		},
		{
			name: "nil resolver opt-out leaves the wildcard resolver serving other hosts",
			host: "other.box.test",
			proxy: func(p *Proxy, _ hostKeys, c *atomic.Int32) {
				p.SetCredentialResolver("*.box.test", resolverReturning(c, "Bearer resolver", "resolver"))
				p.SetCredentialResolver("api.box.test", nil)
				p.SetCredentialWithGrant("api.box.test", "Authorization", "Bearer static", "static")
			},
			want:      map[string]string{"Authorization": "Bearer resolver"},
			wantCalls: 1,
		},
		{
			name: "declared-strip-headers resolver still serves hosts it is not outranked on",
			host: "other.box.test",
			proxy: func(p *Proxy, _ hostKeys, c *atomic.Int32) {
				p.SetCredentialWithGrant("api.box.test", "Authorization", "Bearer static", "static")
				p.SetCredentialResolverWithStripHeaders("*.box.test", func(ctx context.Context, _, innerReq *http.Request, _ string) ([]CredentialHeader, error) {
					c.Add(1)
					innerReq.Header.Del("X-Subject-Token")
					return authCred("Bearer resolver", "resolver"), nil
				}, "X-Subject-Token")
			},
			headers:   map[string]string{"X-Subject-Token": "caller-identity"},
			want:      map[string]string{"Authorization": "Bearer resolver"},
			wantCalls: 1,
		},
		{
			name: "outranked resolver with declared strip headers is skipped and its headers removed",
			proxy: func(p *Proxy, k hostKeys, c *atomic.Int32) {
				rawCreds(p, k.hp, cred("Authorization", "Bearer static", "static"))
				p.SetCredentialResolverWithStripHeaders(k.h, resolverReturning(c, "Bearer resolver", "resolver"), "X-Subject-Token")
			},
			headers: map[string]string{"X-Subject-Token": "caller-identity"},
			want:    map[string]string{"Authorization": "Bearer static"},
		},
		{
			name: "outranked legacy resolver still runs and static wins",
			proxy: func(p *Proxy, k hostKeys, c *atomic.Int32) {
				rawCreds(p, k.hp, cred("Authorization", "Bearer static", "static"))
				p.SetCredentialResolver(k.h, func(ctx context.Context, _, innerReq *http.Request, _ string) ([]CredentialHeader, error) {
					c.Add(1)
					innerReq.Header.Del("X-Subject-Token")
					return authCred("Bearer resolver", "resolver"), nil
				})
			},
			headers:   map[string]string{"X-Subject-Token": "caller-identity"},
			want:      map[string]string{"Authorization": "Bearer static"},
			wantCalls: 1,
		},
		{
			name: "outranked legacy resolver error is not fatal",
			host: "api.box.test",
			proxy: func(p *Proxy, _ hostKeys, c *atomic.Int32) {
				p.SetCredentialWithGrant("api.box.test", "Authorization", "Bearer static", "static")
				p.SetCredentialResolver("*.box.test", func(context.Context, *http.Request, *http.Request, string) ([]CredentialHeader, error) {
					c.Add(1)
					return nil, errors.New("sts unavailable")
				})
			},
			want:      map[string]string{"Authorization": "Bearer static"},
			wantCalls: 1,
		},
		{
			name: "outranked legacy resolver: static read after resolver sees rotation",
			host: "api.box.test",
			proxy: func(p *Proxy, _ hostKeys, c *atomic.Int32) {
				p.SetCredentialWithGrant("api.box.test", "Authorization", "Bearer v1", "static")
				p.SetCredentialResolver("*.box.test", func(context.Context, *http.Request, *http.Request, string) ([]CredentialHeader, error) {
					c.Add(1)
					p.SetCredentialWithGrant("api.box.test", "Authorization", "Bearer v2", "static")
					return authCred("Bearer resolver", "resolver"), nil
				})
			},
			want:      map[string]string{"Authorization": "Bearer v2"},
			wantCalls: 1,
		},
		{
			name: "resolver miss falls back to static read after resolver ran",
			proxy: func(p *Proxy, k hostKeys, c *atomic.Int32) {
				p.SetCredentialResolver(k.h, func(context.Context, *http.Request, *http.Request, string) ([]CredentialHeader, error) {
					c.Add(1)
					p.SetCredentialWithGrant(k.h, "Authorization", "Bearer refreshed", "static")
					return nil, nil
				})
			},
			want:      map[string]string{"Authorization": "Bearer refreshed"},
			wantCalls: 1,
		},
		{
			name: "resolver error fails closed with 502 and nothing reaches upstream",
			proxy: func(p *Proxy, k hostKeys, c *atomic.Int32) {
				p.SetCredentialWithGrant(k.h, "Authorization", "Bearer static", "static")
				p.SetCredentialResolver(k.h, func(context.Context, *http.Request, *http.Request, string) ([]CredentialHeader, error) {
					c.Add(1)
					return nil, errors.New("sts unavailable")
				})
			},
			wantStatus: http.StatusBadGateway,
			wantCalls:  1,
		},

		// Grant handling.
		{
			name: "auto-injection prefers the non-claude grant on a shared header",
			proxy: func(p *Proxy, k hostKeys, _ *atomic.Int32) {
				p.SetCredentialWithGrant(k.h, "Authorization", "Bearer claude-tok", "claude")
				p.SetCredentialWithGrant(k.h, "Authorization", "Bearer api-tok", "anthropic")
			},
			want: map[string]string{"Authorization": "Bearer api-tok"},
		},
		{
			name: "client-sent placeholder selects the claude grant on a shared header",
			proxy: func(p *Proxy, k hostKeys, _ *atomic.Int32) {
				p.SetCredentialWithGrant(k.h, "Authorization", "Bearer claude-tok", "claude")
				p.SetCredentialWithGrant(k.h, "Authorization", "Bearer api-tok", "anthropic")
			},
			headers: map[string]string{"Authorization": "Bearer placeholder"},
			want:    map[string]string{"Authorization": "Bearer claude-tok"},
		},
		{
			name: "auto-injection sends every credential on distinct headers",
			proxy: func(p *Proxy, k hostKeys, _ *atomic.Int32) {
				p.SetCredentialWithGrant(k.h, "Authorization", "Bearer a", "ga")
				p.SetCredentialWithGrant(k.h, "X-Api-Key", "key", "gb")
			},
			want: map[string]string{"Authorization": "Bearer a", "X-Api-Key": "key"},
		},
		{
			name: "client-sent header selects only its own credential",
			proxy: func(p *Proxy, k hostKeys, _ *atomic.Int32) {
				p.SetCredentialWithGrant(k.h, "Authorization", "Bearer a", "ga")
				p.SetCredentialWithGrant(k.h, "X-Api-Key", "key", "gb")
			},
			headers: map[string]string{"X-Api-Key": "placeholder"},
			want:    map[string]string{"X-Api-Key": "key"},
		},

		// Extra headers.
		{
			name:        "extra header injected",
			plainHTTPOK: true,
			proxy: func(p *Proxy, k hostKeys, _ *atomic.Int32) {
				p.AddExtraHeader(k.h, "X-Api-Version", "2024-01-01")
			},
			want: map[string]string{"X-Api-Version": "2024-01-01"},
		},
		{
			name:        "extra header comma-merges with the client value",
			plainHTTPOK: true,
			proxy: func(p *Proxy, k hostKeys, _ *atomic.Int32) {
				p.AddExtraHeader(k.h, "Anthropic-Beta", "proxy-flag")
			},
			headers: map[string]string{"Anthropic-Beta": "client-flag"},
			want:    map[string]string{"Anthropic-Beta": "client-flag, proxy-flag"},
		},
		{
			name:        "run context extra headers replace proxy-level extra headers",
			plainHTTPOK: true,
			proxy: func(p *Proxy, k hostKeys, _ *atomic.Int32) {
				p.AddExtraHeader(k.h, "X-Proxy-Extra", "p")
			},
			rc: func(k hostKeys) *RunContextData {
				return &RunContextData{Policy: "permissive", ExtraHeaders: map[string][]ExtraHeader{k.h: {{Name: "X-Run-Extra", Value: "r"}}}}
			},
			want: map[string]string{"X-Run-Extra": "r"},
		},

		// Remove headers.
		{
			name: "remove header strips the client value",
			proxy: func(p *Proxy, k hostKeys, _ *atomic.Int32) {
				p.RemoveRequestHeader(k.h, "X-Internal")
			},
			headers: map[string]string{"X-Internal": "secret", "X-Keep": "k"},
			want:    map[string]string{"X-Keep": "k"},
		},
		{
			name: "remove header never strips an injected credential header",
			proxy: func(p *Proxy, k hostKeys, _ *atomic.Int32) {
				p.SetCredentialWithGrant(k.h, "X-Api-Key", "key", "anthropic")
				p.RemoveRequestHeader(k.h, "X-Api-Key")
			},
			headers: map[string]string{"X-Api-Key": "placeholder"},
			want:    map[string]string{"X-Api-Key": "key"},
		},
		{
			name: "run context remove headers replace proxy-level remove headers",
			proxy: func(p *Proxy, k hostKeys, _ *atomic.Int32) {
				p.RemoveRequestHeader(k.h, "X-Proxy-Strip")
			},
			rc: func(k hostKeys) *RunContextData {
				return &RunContextData{Policy: "permissive", RemoveHeaders: map[string][]string{k.h: {"X-Run-Strip"}}}
			},
			headers: map[string]string{"X-Proxy-Strip": "p", "X-Run-Strip": "r"},
			want:    map[string]string{"X-Proxy-Strip": "p"},
		},

		// Token substitution.
		{
			name: "token substitution rewrites path, Authorization and body",
			proxy: func(p *Proxy, k hostKeys, _ *atomic.Int32) {
				p.SetTokenSubstitution(k.h, "placeholder-token", "real-secret")
			},
			method:   "POST",
			path:     "/bot" + "placeholder-token" + "/getUpdates",
			body:     `{"t":"placeholder-token"}`,
			headers:  map[string]string{"Authorization": "Bearer placeholder-token"},
			want:     map[string]string{"Authorization": "Bearer real-secret"},
			wantPath: "/botreal-secret/getUpdates",
			wantBody: `{"t":"real-secret"}`,
		},
		{
			name: "run context token substitution replaces proxy-level substitution",
			proxy: func(p *Proxy, k hostKeys, _ *atomic.Int32) {
				p.SetTokenSubstitution(k.h, "proxy-ph", "proxy-real")
			},
			rc: func(k hostKeys) *RunContextData {
				return &RunContextData{Policy: "permissive", TokenSubstitutions: map[string]*TokenSubstitution{k.h: {placeholder: "run-ph", realToken: "run-real"}}}
			},
			path:     "/run-ph/proxy-ph",
			wantPath: "/run-real/proxy-ph",
			want:     map[string]string{},
		},

		// Capture headers and proxy hop headers.
		{
			name: "capture headers are stripped and other headers pass",
			proxy: func(p *Proxy, _ hostKeys, _ *atomic.Int32) {
				if err := p.SetCaptureRequestHeaders([]string{"X-Workspace-Slug"}); err != nil {
					panic(err)
				}
			},
			headers: map[string]string{"X-Workspace-Slug": "plum", "X-Other": "keep"},
			want:    map[string]string{"X-Other": "keep"},
		},
		{
			name: "capture header survives when it is an injected credential header",
			proxy: func(p *Proxy, k hostKeys, _ *atomic.Int32) {
				if err := p.SetCaptureRequestHeaders([]string{"X-Test-Credential"}); err != nil {
					panic(err)
				}
				p.SetCredentialWithGrant(k.h, "X-Test-Credential", "key", "anthropic")
			},
			headers: map[string]string{"X-Test-Credential": "placeholder"},
			want:    map[string]string{"X-Test-Credential": "key"},
		},
		{
			name:    "proxy hop headers never reach upstream",
			headers: map[string]string{"Proxy-Connection": "keep-alive", "Proxy-Authorization": "Basic Zm9vOmJhcg==", "X-Keep": "k"},
			want:    map[string]string{"X-Keep": "k"},
		},
	}
}

func (r contractRow) normalized() contractRow {
	if r.method == "" {
		r.method = "GET"
	}
	if r.path == "" {
		r.path = "/api"
	}
	if r.wantPath == "" {
		r.wantPath = r.path
	}
	if r.wantStatus == 0 {
		r.wantStatus = http.StatusOK
	}
	if r.wantBody == "" {
		r.wantBody = r.body
	}
	return r
}

// TestCredentialContract pins credential precedence and injection as a
// caller observes it. The http-cleartext subtests refuse any row that injects
// a secret, because credentials need allow_insecure to travel over plain HTTP;
// a deliberate change to that behavior edits the expectation there.
func TestCredentialContract(t *testing.T) {
	for _, row := range contractRows() {
		row = row.normalized()
		t.Run("http-cleartext/"+row.name, func(t *testing.T) { runContractHTTP(t, row) })
		if row.host != "" {
			continue
		}
		t.Run("connect-intercept/"+row.name, func(t *testing.T) { runContractConnect(t, row) })
	}
}

func (r contractRow) injectsSecret() bool {
	if r.plainHTTPOK || r.wantStatus != http.StatusOK {
		return false
	}
	for k, v := range r.want {
		if r.headers[k] != v && r.headers[http.CanonicalHeaderKey(k)] != v {
			return true
		}
	}
	return r.wantPath != r.path || r.wantBody != r.body
}

func runContractHTTP(t *testing.T, row contractRow) {
	if row.injectsSecret() {
		row.wantStatus = http.StatusForbidden
		row.want = nil
	}
	up, got := newContractUpstream(t, false)
	redirectHTTPTransport(t, up.Listener.Addr().String())

	host, port := row.host, row.port
	if host == "" {
		host = "api.example.com"
	}
	if port == "" {
		port = "8080"
	}
	k := hostKeys{h: host, hp: host + ":" + port}

	// Repeated so a map-iteration-order-dependent pick cannot pass by luck.
	for range 25 {
		p, calls := buildContractProxy(row, k)
		req := httptest.NewRequest(row.method, "http://"+host+":"+port+row.path, strings.NewReader(row.body))
		for n, v := range row.headers {
			req.Header.Set(n, v)
		}
		if row.rc != nil {
			req.Header.Set("Proxy-Authorization", "Bearer run-token")
		}
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		assertContract(t, row, rec.Code, got, calls)
		if t.Failed() {
			return
		}
	}
}

func runContractConnect(t *testing.T, row contractRow) {
	ca := contractCA(t)
	up, got := newContractUpstream(t, true)
	upstreamCAs := x509.NewCertPool()
	upstreamCAs.AddCert(up.Certificate())

	u := mustParseURL(up.URL)
	k := hostKeys{h: u.Hostname(), hp: u.Host}
	p, calls := buildContractProxy(row, k)
	p.SetCA(ca)
	p.SetUpstreamCAs(upstreamCAs)
	proxySrv := httptest.NewServer(p)
	t.Cleanup(proxySrv.Close)

	proxyURL := mustParseURL(proxySrv.URL)
	if row.rc != nil {
		proxyURL.User = url.UserPassword("u", "run-token")
	}
	clientCAs := x509.NewCertPool()
	clientCAs.AppendCertsFromPEM(ca.certPEM)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: clientCAs}}}

	req, err := http.NewRequest(row.method, up.URL+row.path, strings.NewReader(row.body))
	if err != nil {
		t.Fatal(err)
	}
	for n, v := range row.headers {
		req.Header.Set(n, v)
	}
	t.Cleanup(client.CloseIdleConnections)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	assertContract(t, row, resp.StatusCode, got, calls)
}

func buildContractProxy(row contractRow, k hostKeys) (*Proxy, *atomic.Int32) {
	p := NewProxy()
	calls := new(atomic.Int32)
	if row.proxy != nil {
		row.proxy(p, k, calls)
	}
	if row.rc != nil {
		rc := row.rc(k)
		p.SetContextResolver(func(token string) (*RunContextData, bool) { return rc, token == "run-token" })
	}
	return p, calls
}

func assertContract(t *testing.T, row contractRow, status int, got <-chan wireRequest, calls *atomic.Int32) {
	t.Helper()
	if status != row.wantStatus {
		t.Errorf("status = %d, want %d", status, row.wantStatus)
	}
	if n := calls.Load(); n != row.wantCalls {
		t.Errorf("resolver calls = %d, want %d", n, row.wantCalls)
	}
	var w wireRequest
	select {
	case w = <-got:
	default:
		if row.wantStatus == http.StatusOK {
			t.Fatal("request never reached upstream")
		}
		return
	}
	if row.wantStatus != http.StatusOK {
		t.Fatalf("request reached upstream with headers %v, want none", w.flat())
	}
	if g, x := w.flat(), wantFlat(row.want); !slices.Equal(g, x) {
		t.Errorf("upstream headers (missing or surplus):\n got  %q\n want %q", g, x)
	}
	if w.path != row.wantPath {
		t.Errorf("upstream path = %q, want %q", w.path, row.wantPath)
	}
	if w.body != row.wantBody {
		t.Errorf("upstream body = %q, want %q", w.body, row.wantBody)
	}
}
