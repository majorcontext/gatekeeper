package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	keeplib "github.com/majorcontext/keep"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntercept_HTTPOperationPolicy(t *testing.T) {
	var backendHits, credentialResolutions atomic.Int32
	setup := newInterceptTestSetup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHits.Add(1)
		// Echo the bytes to verify that inspection preserves the upstream body.
		io.Copy(w, r.Body)
	}))
	policy := fmt.Sprintf(`
scope: http
mode: enforce
rules:
  - name: invalid-graphql
    match:
      operation: "post %s/graphql"
      when: "!graphql(params.body).valid"
    action: deny
  - name: graphql-mutations
    match:
      operation: "post %s/graphql"
      when: "graphql(params.body).mutations.size() > 0"
    action: deny
  - name: push-advertisement
    match:
      when: "params.path.endsWith('/info/refs') && params.query == 'service=git-receive-pack'"
    action: deny
  - name: blocked-path
    match:
      when: "params.path == '/blocked'"
    action: deny
`, setup.BackendHost, setup.BackendHost)
	eng, err := keeplib.LoadFromBytes([]byte(policy))
	require.NoError(t, err)
	t.Cleanup(eng.Close)
	resolve := func(context.Context, *http.Request, *http.Request, string) ([]CredentialHeader, error) {
		credentialResolutions.Add(1)
		return nil, nil
	}
	setup.Proxy.SetContextResolver(func(token string) (*RunContextData, bool) {
		return &RunContextData{
			Policy:      "permissive",
			KeepEngines: map[string]*keeplib.Engine{"http": eng},
			Credentials: map[string][]CredentialHeader{setup.BackendHost: {{Resolver: resolve}}},
		}, token == "tok"
	})
	proxyURL := mustParseURL(setup.ProxyServer.URL)
	proxyURL.User = url.UserPassword("alice", "tok")
	clientCAs := x509.NewCertPool()
	require.True(t, clientCAs.AppendCertsFromPEM(setup.CA.certPEM))
	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: clientCAs},
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}

	for _, tc := range []struct {
		name, method, path, contentType, encoding, body string
		denied                                          bool
	}{
		{name: "git pack forwarded", method: "POST", path: "/acme/app.git/git-receive-pack", contentType: "application/x-git-receive-pack-request", body: "0000PACK\x00\xff\x02binary"},
		{name: "graphql query forwarded", method: "POST", path: "/graphql", contentType: "application/json", body: `{"query":"{ viewer { login } }"}`},
		{name: "graphql mutation denied", method: "POST", path: "/graphql", contentType: "application/json", body: `{"query":"mutation { deleteRef(input:{refId:\"x\"}) { clientMutationId } }"}`, denied: true},
		{name: "invalid graphql denied", method: "POST", path: "/graphql", contentType: "application/json", body: `{"query":"mutation {"}`, denied: true},
		{name: "non-json graphql denied", method: "POST", path: "/graphql", contentType: "application/x-www-form-urlencoded", body: "query=mutation", denied: true},
		{name: "malformed json denied", method: "POST", path: "/graphql", contentType: "application/json", body: `{"query":`, denied: true},
		{name: "duplicate json keys denied", method: "POST", path: "/graphql", contentType: "application/json", body: `{"query":"mutation { deleteRef { id } }","query":"{ viewer { login } }"}`, denied: true},
		{name: "compressed graphql denied", method: "POST", path: "/graphql", contentType: "application/json", encoding: "gzip", body: "compressed", denied: true},
		{name: "fetch advertisement allowed", method: "GET", path: "/acme/app.git/info/refs?service=git-upload-pack"},
		{name: "push advertisement denied", method: "GET", path: "/acme/app.git/info/refs?service=git-receive-pack", denied: true},
		{name: "path policy still denies uninspected pack", method: "POST", path: "/blocked", contentType: "application/octet-stream", body: "PACK\x00binary", denied: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			beforeHits, beforeResolutions := backendHits.Load(), credentialResolutions.Load()
			req, err := http.NewRequest(tc.method, setup.Backend.URL+tc.path, strings.NewReader(tc.body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", tc.contentType)
			if tc.encoding != "" {
				req.Header.Set("Content-Encoding", tc.encoding)
			}
			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			if tc.denied {
				assert.Equal(t, http.StatusForbidden, resp.StatusCode)
				assert.Equal(t, "keep-policy", resp.Header.Get("X-Gatekeeper-Blocked"))
				assert.Equal(t, "keep-policy", resp.Header.Get("X-Moat-Blocked"))
				assert.Equal(t, beforeHits, backendHits.Load(), "denied request must not reach upstream")
				assert.Equal(t, beforeResolutions, credentialResolutions.Load(), "denied request must not resolve credentials")
				return
			}
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, tc.body, string(body))
			assert.Equal(t, beforeHits+1, backendHits.Load())
			assert.Equal(t, beforeResolutions+1, credentialResolutions.Load())
		})
	}
}
