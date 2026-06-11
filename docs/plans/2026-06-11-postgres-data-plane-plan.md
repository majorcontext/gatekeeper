# Postgres Data Plane Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.
> REQUIRED SUB-SKILL: Use superpowers:test-driven-development for every task. Write the failing test first, watch it fail, then implement.

**Goal:** Add a Postgres-aware listener to gatekeeper that authenticates sandboxed clients with their run token and performs real SCRAM authentication upstream using passwords minted on the fly from the Neon API — so no database secret ever enters the sandbox.

**Architecture:** A new TCP listener accepts Postgres connections, terminates TLS with a CA-minted cert for the SNI hostname, validates the client's run token (sent as the Postgres password), resolves the real password via a `PostgresCredentialResolver` (Neon API or static), completes SCRAM-SHA-256 upstream, then relays protocol messages blindly in both directions. Design doc: `docs/plans/2026-06-11-postgres-neon-design.md`.

**Tech Stack:** Go, `github.com/jackc/pgx/v5/pgproto3` (wire protocol framing, both sides), `github.com/xdg-go/scram` (SCRAM-SHA-256 client for upstream auth, server for test fakes).

**Conventions:** Run all tests with `-race` (project rule). Conventional commit messages, no AI `Co-Authored-By` lines. Never log or include credential values in errors.

---

## Task 1: Add dependencies

**Files:**
- Modify: `go.mod`, `go.sum`

**Step 1: Add the modules**

```bash
go get github.com/jackc/pgx/v5@latest github.com/xdg-go/scram@latest
go mod tidy
```

**Step 2: Verify the build still passes**

Run: `go build ./... && go test -race ./...`
Expected: all pass (no code uses the new deps yet; `go mod tidy` may drop them — if it does, that's fine, they'll be re-added by the first import in Task 2's test; re-run `go mod tidy` after Task 2 instead).

**Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "build: add pgproto3 and scram dependencies"
```

---

## Task 2: Neon endpoint-ID parsing

A pure function that extracts the endpoint ID from a Neon hostname. Neon hostnames look like `ep-cool-darkness-123456.us-east-2.aws.neon.tech`; the pooler variant inserts `-pooler` after the endpoint ID (`ep-cool-darkness-123456-pooler.us-east-2.aws.neon.tech`).

**Files:**
- Create: `credentialsource/neon.go`
- Create: `credentialsource/neon_test.go`

**Step 1: Write the failing test**

```go
package credentialsource

import "testing"

func TestParseNeonEndpointID(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		want    string
		wantErr bool
	}{
		{"plain endpoint", "ep-cool-darkness-123456.us-east-2.aws.neon.tech", "ep-cool-darkness-123456", false},
		{"pooler endpoint", "ep-cool-darkness-123456-pooler.us-east-2.aws.neon.tech", "ep-cool-darkness-123456", false},
		{"not an endpoint host", "console.neon.tech", "", true},
		{"empty", "", "", true},
		{"bare label", "ep-foo-123", "ep-foo-123", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseNeonEndpointID(tt.host)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseNeonEndpointID(%q) error = %v, wantErr %v", tt.host, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ParseNeonEndpointID(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -race -run TestParseNeonEndpointID ./credentialsource/`
Expected: FAIL — `undefined: ParseNeonEndpointID`

**Step 3: Write minimal implementation**

```go
package credentialsource

import (
	"fmt"
	"strings"
)

// ParseNeonEndpointID extracts the Neon endpoint ID from a hostname like
// "ep-cool-darkness-123456.us-east-2.aws.neon.tech". The "-pooler" suffix
// (connection pooler endpoints) is stripped.
func ParseNeonEndpointID(host string) (string, error) {
	label, _, _ := strings.Cut(host, ".")
	label = strings.TrimSuffix(label, "-pooler")
	if !strings.HasPrefix(label, "ep-") {
		return "", fmt.Errorf("host %q is not a neon endpoint hostname", host)
	}
	return label, nil
}
```

**Step 4: Run test to verify it passes**

Run: `go test -race -run TestParseNeonEndpointID ./credentialsource/`
Expected: PASS

**Step 5: Commit**

```bash
git add credentialsource/neon.go credentialsource/neon_test.go
git commit -m "feat(credentialsource): parse neon endpoint IDs from hostnames"
```

---

## Task 3: Neon password resolver

`NeonResolver` maps (endpoint hostname, role, database) → password via the Neon API: enumerate projects to find the one owning the endpoint, then `GET /api/v2/projects/{id}/connection_uri?branch_id&database_name&role_name` and extract the password from the returned URI. Cache passwords with a TTL; support explicit invalidation (passwords rotate on branch reset).

Neon API facts the fake must mirror:
- `GET /api/v2/projects` → `{"projects": [{"id": "..."}]}` (auth: `Authorization: Bearer <api-key>`)
- `GET /api/v2/projects/{pid}/endpoints` → `{"endpoints": [{"id": "ep-...", "branch_id": "br-..."}]}`
- `GET /api/v2/projects/{pid}/connection_uri?branch_id=br-...&database_name=db&role_name=role` → `{"uri": "postgresql://role:PASSWORD@ep-....neon.tech/db?sslmode=require"}`

**Files:**
- Modify: `credentialsource/neon.go`
- Modify: `credentialsource/neon_test.go`

**Step 1: Write the failing tests**

Append to `credentialsource/neon_test.go`:

```go
import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"time"
)

// fakeNeonAPI serves the three Neon API routes the resolver uses.
type fakeNeonAPI struct {
	t            *testing.T
	apiKey       string
	password     string
	connURICalls atomic.Int64
}

func (f *fakeNeonAPI) handler() http.Handler {
	mux := http.NewServeMux()
	auth := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer "+f.apiKey {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /api/v2/projects", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"projects": []map[string]string{{"id": "proj-1"}, {"id": "proj-2"}},
		})
	})
	mux.HandleFunc("GET /api/v2/projects/proj-2/endpoints", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"endpoints": []map[string]string{{"id": "ep-cool-darkness-123456", "branch_id": "br-9"}},
		})
	})
	mux.HandleFunc("GET /api/v2/projects/proj-1/endpoints", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"endpoints": []map[string]string{}})
	})
	mux.HandleFunc("GET /api/v2/projects/proj-2/connection_uri", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		f.connURICalls.Add(1)
		q := r.URL.Query()
		if q.Get("branch_id") != "br-9" || q.Get("database_name") != "appdb" || q.Get("role_name") != "app_rw" {
			f.t.Errorf("unexpected connection_uri query: %v", q)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"uri": "postgresql://app_rw:" + f.password + "@ep-cool-darkness-123456.us-east-2.aws.neon.tech/appdb?sslmode=require",
		})
	})
	return mux
}

func newTestNeonResolver(t *testing.T, fake *fakeNeonAPI) *NeonResolver {
	srv := httptest.NewServer(fake.handler())
	t.Cleanup(srv.Close)
	return &NeonResolver{
		APIKey:  NewStatic(fake.apiKey),
		BaseURL: srv.URL,
		TTL:     time.Minute,
	}
}

func TestNeonResolverResolvePassword(t *testing.T) {
	fake := &fakeNeonAPI{t: t, apiKey: "key-123", password: "s3cret"}
	r := newTestNeonResolver(t, fake)

	got, err := r.ResolvePassword(context.Background(), "ep-cool-darkness-123456.us-east-2.aws.neon.tech", "app_rw", "appdb")
	if err != nil {
		t.Fatalf("ResolvePassword: %v", err)
	}
	if got != "s3cret" {
		t.Errorf("password = %q, want %q", got, "s3cret")
	}
}

func TestNeonResolverCachesPasswords(t *testing.T) {
	fake := &fakeNeonAPI{t: t, apiKey: "key-123", password: "s3cret"}
	r := newTestNeonResolver(t, fake)

	for range 3 {
		if _, err := r.ResolvePassword(context.Background(), "ep-cool-darkness-123456.us-east-2.aws.neon.tech", "app_rw", "appdb"); err != nil {
			t.Fatalf("ResolvePassword: %v", err)
		}
	}
	if n := fake.connURICalls.Load(); n != 1 {
		t.Errorf("connection_uri calls = %d, want 1 (cached)", n)
	}
}

func TestNeonResolverInvalidatePassword(t *testing.T) {
	fake := &fakeNeonAPI{t: t, apiKey: "key-123", password: "s3cret"}
	r := newTestNeonResolver(t, fake)

	host := "ep-cool-darkness-123456.us-east-2.aws.neon.tech"
	if _, err := r.ResolvePassword(context.Background(), host, "app_rw", "appdb"); err != nil {
		t.Fatalf("ResolvePassword: %v", err)
	}
	r.InvalidatePassword(host, "app_rw", "appdb")
	fake.password = "rotated"
	got, err := r.ResolvePassword(context.Background(), host, "app_rw", "appdb")
	if err != nil {
		t.Fatalf("ResolvePassword after invalidate: %v", err)
	}
	if got != "rotated" {
		t.Errorf("password = %q, want %q", got, "rotated")
	}
	if n := fake.connURICalls.Load(); n != 2 {
		t.Errorf("connection_uri calls = %d, want 2", n)
	}
}

func TestNeonResolverUnknownEndpoint(t *testing.T) {
	fake := &fakeNeonAPI{t: t, apiKey: "key-123", password: "s3cret"}
	r := newTestNeonResolver(t, fake)

	_, err := r.ResolvePassword(context.Background(), "ep-no-such-endpoint-000.us-east-2.aws.neon.tech", "app_rw", "appdb")
	if err == nil {
		t.Fatal("expected error for unknown endpoint")
	}
}
```

Note: check `credentialsource/static.go` for the static source constructor name; if it is not `NewStatic`, use the actual constructor.

**Step 2: Run tests to verify they fail**

Run: `go test -race -run TestNeonResolver ./credentialsource/`
Expected: FAIL — `undefined: NeonResolver`

**Step 3: Implement**

Append to `credentialsource/neon.go`:

```go
import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// DefaultNeonBaseURL is the production Neon API base URL.
const DefaultNeonBaseURL = "https://console.neon.tech"

// NeonResolver resolves Postgres passwords for arbitrary Neon endpoints by
// exchanging a Neon API key for per-branch connection credentials.
//
// Passwords are cached for TTL. The resolver never logs password values.
type NeonResolver struct {
	APIKey     CredentialSource // source for the Neon API key
	BaseURL    string           // defaults to DefaultNeonBaseURL
	TTL        time.Duration    // password cache TTL; defaults to 5 minutes
	HTTPClient *http.Client     // defaults to a client with a 15s timeout

	mu        sync.Mutex
	passwords map[neonCredKey]neonCachedPassword
	endpoints map[string]neonEndpointInfo // endpoint ID -> project/branch
}

type neonCredKey struct{ endpoint, role, database string }

type neonCachedPassword struct {
	password string
	expires  time.Time
}

type neonEndpointInfo struct{ projectID, branchID string }

func (r *NeonResolver) Type() string { return "neon" }

// ResolvePassword returns the Postgres password for the given Neon endpoint
// hostname, role, and database.
func (r *NeonResolver) ResolvePassword(ctx context.Context, host, user, database string) (string, error) {
	endpoint, err := ParseNeonEndpointID(host)
	if err != nil {
		return "", err
	}
	key := neonCredKey{endpoint, user, database}

	r.mu.Lock()
	if cached, ok := r.passwords[key]; ok && time.Now().Before(cached.expires) {
		r.mu.Unlock()
		return cached.password, nil
	}
	r.mu.Unlock()

	info, err := r.lookupEndpoint(ctx, endpoint)
	if err != nil {
		return "", err
	}
	password, err := r.fetchPassword(ctx, info, user, database)
	if err != nil {
		return "", err
	}

	ttl := r.TTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	r.mu.Lock()
	if r.passwords == nil {
		r.passwords = make(map[neonCredKey]neonCachedPassword)
	}
	r.passwords[key] = neonCachedPassword{password: password, expires: time.Now().Add(ttl)}
	r.mu.Unlock()
	return password, nil
}

// InvalidatePassword drops a cached password (e.g. after an upstream
// authentication failure, since passwords rotate on branch reset).
func (r *NeonResolver) InvalidatePassword(host, user, database string) {
	endpoint, err := ParseNeonEndpointID(host)
	if err != nil {
		return
	}
	r.mu.Lock()
	delete(r.passwords, neonCredKey{endpoint, user, database})
	r.mu.Unlock()
}

// lookupEndpoint finds the project and branch owning an endpoint by
// enumerating the API key's projects. Results are cached indefinitely:
// an endpoint never moves between projects or branches.
func (r *NeonResolver) lookupEndpoint(ctx context.Context, endpoint string) (neonEndpointInfo, error) {
	r.mu.Lock()
	if info, ok := r.endpoints[endpoint]; ok {
		r.mu.Unlock()
		return info, nil
	}
	r.mu.Unlock()

	var projects struct {
		Projects []struct {
			ID string `json:"id"`
		} `json:"projects"`
	}
	if err := r.getJSON(ctx, "/api/v2/projects", nil, &projects); err != nil {
		return neonEndpointInfo{}, err
	}
	for _, p := range projects.Projects {
		var endpoints struct {
			Endpoints []struct {
				ID       string `json:"id"`
				BranchID string `json:"branch_id"`
			} `json:"endpoints"`
		}
		if err := r.getJSON(ctx, "/api/v2/projects/"+url.PathEscape(p.ID)+"/endpoints", nil, &endpoints); err != nil {
			return neonEndpointInfo{}, err
		}
		for _, ep := range endpoints.Endpoints {
			if ep.ID == endpoint {
				info := neonEndpointInfo{projectID: p.ID, branchID: ep.BranchID}
				r.mu.Lock()
				if r.endpoints == nil {
					r.endpoints = make(map[string]neonEndpointInfo)
				}
				r.endpoints[endpoint] = info
				r.mu.Unlock()
				return info, nil
			}
		}
	}
	return neonEndpointInfo{}, fmt.Errorf("neon endpoint %q not found in any accessible project", endpoint)
}

func (r *NeonResolver) fetchPassword(ctx context.Context, info neonEndpointInfo, user, database string) (string, error) {
	q := url.Values{
		"branch_id":     {info.branchID},
		"database_name": {database},
		"role_name":     {user},
	}
	var resp struct {
		URI string `json:"uri"`
	}
	path := "/api/v2/projects/" + url.PathEscape(info.projectID) + "/connection_uri"
	if err := r.getJSON(ctx, path, q, &resp); err != nil {
		return "", err
	}
	u, err := url.Parse(resp.URI)
	if err != nil {
		return "", fmt.Errorf("neon API returned an unparseable connection URI")
	}
	password, ok := u.User.Password()
	if !ok {
		return "", fmt.Errorf("neon connection URI contains no password")
	}
	return password, nil
}

func (r *NeonResolver) getJSON(ctx context.Context, path string, query url.Values, out any) error {
	apiKey, err := r.APIKey.Fetch(ctx)
	if err != nil {
		return fmt.Errorf("fetching neon API key: %w", err)
	}
	base := r.BaseURL
	if base == "" {
		base = DefaultNeonBaseURL
	}
	u := base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")

	client := r.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("neon API request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Do not include the response body: it could echo credentials.
		return fmt.Errorf("neon API %s returned status %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
```

**Step 4: Run tests to verify they pass**

Run: `go test -race -run TestNeonResolver ./credentialsource/ && go vet ./credentialsource/`
Expected: PASS

**Step 5: Commit**

```bash
git add credentialsource/neon.go credentialsource/neon_test.go
git commit -m "feat(credentialsource): add neon password resolver with TTL cache"
```

---

## Task 4: Resolver interface and registration on the proxy

Define the `PostgresCredentialResolver` interface in `proxy/`, a static implementation, and host-pattern-based registration on both `Proxy` (standalone mode) and `RunContextData` (moat daemon mode), mirroring how `CredentialResolver` works today (proxy/proxy.go:383).

**Files:**
- Create: `proxy/postgres.go`
- Create: `proxy/postgres_test.go`

**Step 1: Write the failing test**

```go
package proxy

import (
	"context"
	"testing"
)

func TestPostgresResolverLookup(t *testing.T) {
	p := NewProxy()
	neon := NewStaticPostgresResolver("neon-pass")
	other := NewStaticPostgresResolver("other-pass")
	p.SetPostgresResolver("*.neon.tech", neon)
	p.SetPostgresResolver("db.internal", other)

	tests := []struct {
		host string
		want PostgresCredentialResolver
	}{
		{"ep-foo-123.us-east-2.aws.neon.tech", neon},
		{"db.internal", other},
		{"example.com", nil},
	}
	for _, tt := range tests {
		got := p.postgresResolverForHost(nil, tt.host)
		if got != tt.want {
			t.Errorf("postgresResolverForHost(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestPostgresResolverRunContextOverridesProxy(t *testing.T) {
	p := NewProxy()
	proxyLevel := NewStaticPostgresResolver("proxy-pass")
	runLevel := NewStaticPostgresResolver("run-pass")
	p.SetPostgresResolver("*.neon.tech", proxyLevel)

	rc := &RunContextData{
		PostgresResolvers: []PostgresResolverEntry{{Pattern: "*.neon.tech", Resolver: runLevel}},
	}
	if got := p.postgresResolverForHost(rc, "ep-foo.aws.neon.tech"); got != runLevel {
		t.Errorf("run context resolver not preferred: got %v", got)
	}
	// A run context with resolvers configured must not fall back to
	// proxy-level resolvers for unmatched hosts (scoping rule, same as
	// credentials).
	if got := p.postgresResolverForHost(rc, "db.other.com"); got != nil {
		t.Errorf("expected nil for unmatched host with run context, got %v", got)
	}
}

func TestStaticPostgresResolver(t *testing.T) {
	r := NewStaticPostgresResolver("pw")
	got, err := r.ResolvePassword(context.Background(), "any.host", "u", "d")
	if err != nil || got != "pw" {
		t.Fatalf("ResolvePassword = %q, %v; want \"pw\", nil", got, err)
	}
	r.InvalidatePassword("any.host", "u", "d") // must not panic
}
```

**Step 2: Run test to verify it fails**

Run: `go test -race -run 'TestPostgresResolver|TestStaticPostgres' ./proxy/`
Expected: FAIL — undefined types

**Step 3: Implement**

In `proxy/postgres.go`:

```go
package proxy

import "context"

// PostgresCredentialResolver resolves a Postgres password for a specific
// upstream host, role, and database at connection time. Implementations
// must never log password values.
type PostgresCredentialResolver interface {
	ResolvePassword(ctx context.Context, host, user, database string) (string, error)
	// InvalidatePassword drops any cached password for the tuple. The proxy
	// calls it after an upstream authentication failure, then retries once.
	InvalidatePassword(host, user, database string)
}

// PostgresResolverEntry binds a host pattern (see hosts.go glob syntax) to a
// resolver. Used in RunContextData for per-run scoping.
type PostgresResolverEntry struct {
	Pattern  string
	Resolver PostgresCredentialResolver
}

// StaticPostgresResolver returns a fixed password for every connection.
type StaticPostgresResolver struct{ password string }

// NewStaticPostgresResolver creates a resolver with a fixed password.
func NewStaticPostgresResolver(password string) *StaticPostgresResolver {
	return &StaticPostgresResolver{password: password}
}

func (s *StaticPostgresResolver) ResolvePassword(ctx context.Context, host, user, database string) (string, error) {
	return s.password, nil
}

func (s *StaticPostgresResolver) InvalidatePassword(host, user, database string) {}

// SetPostgresResolver registers a proxy-level Postgres resolver for hosts
// matching pattern. Used in standalone mode; daemon mode scopes resolvers
// per run via RunContextData.PostgresResolvers.
func (p *Proxy) SetPostgresResolver(pattern string, r PostgresCredentialResolver) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.postgresResolvers = append(p.postgresResolvers, PostgresResolverEntry{Pattern: pattern, Resolver: r})
}

// postgresResolverForHost finds the resolver for host. When rc carries
// per-run resolvers, only those are consulted (scoping rule); otherwise
// proxy-level resolvers apply. Postgres has no meaningful port distinction
// here, so patterns match on host with port 5432.
func (p *Proxy) postgresResolverForHost(rc *RunContextData, host string) PostgresCredentialResolver {
	entries := func() []PostgresResolverEntry {
		if rc != nil && len(rc.PostgresResolvers) > 0 {
			return rc.PostgresResolvers
		}
		p.mu.RLock()
		defer p.mu.RUnlock()
		return p.postgresResolvers
	}()
	for _, e := range entries {
		if matchesPattern(parseHostPattern(e.Pattern), host, 5432) {
			return e.Resolver
		}
	}
	return nil
}
```

Also add to the `Proxy` struct (proxy/proxy.go, near `credentialResolvers`):

```go
	postgresResolvers []PostgresResolverEntry // host pattern -> postgres resolver
```

And to `RunContextData` (proxy/proxy.go:348):

```go
	PostgresResolvers []PostgresResolverEntry
```

Check the actual signature of `matchesPattern`/`parseHostPattern` in `proxy/hosts.go` and adjust the call if it differs.

**Step 4: Run tests**

Run: `go test -race -run 'TestPostgresResolver|TestStaticPostgres' ./proxy/ && go vet ./proxy/`
Expected: PASS

**Step 5: Commit**

```bash
git add proxy/postgres.go proxy/postgres_test.go proxy/proxy.go
git commit -m "feat(proxy): add postgres credential resolver interface and registration"
```

---

## Task 5: Test fakes — SCRAM-verifying fake Postgres server

Build the test infrastructure first; every subsequent proxy task uses it. The fake is a real TLS Postgres server that demands SCRAM-SHA-256 and verifies it with `xdg-go/scram`'s server side, then answers `Query` messages with a canned result. Also a self-signed cert helper.

**Files:**
- Create: `proxy/pgtest_test.go`

**Step 1: Write the fake (test infrastructure, no assertion yet — verified by compilation here and used by every later task)**

```go
package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/xdg-go/scram"
)

// testServerCert creates a self-signed TLS cert valid for the given DNS name,
// returning the cert and a pool that trusts it.
func testServerCert(t *testing.T, dnsName string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// fakePostgresServer is a TLS Postgres server that requires SCRAM-SHA-256.
type fakePostgresServer struct {
	t        *testing.T
	addr     string
	certPool *x509.CertPool // trusts the server's self-signed cert

	user     string
	password string

	mu        sync.Mutex
	authOK    int // successful authentications
	authFail  int // failed authentications
	lastQuery string
}

// startFakePostgres starts the server. dnsName is the hostname the TLS cert
// must be valid for (what gatekeeper will verify against).
func startFakePostgres(t *testing.T, dnsName, user, password string) *fakePostgresServer {
	t.Helper()
	cert, pool := testServerCert(t, dnsName)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakePostgresServer{t: t, addr: ln.Addr().String(), certPool: pool, user: user, password: password}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.handle(conn, cert)
		}
	}()
	return f
}

func (f *fakePostgresServer) handle(conn net.Conn, cert tls.Certificate) {
	defer conn.Close()
	backend := pgproto3.NewBackend(conn, conn)
	startup, err := backend.ReceiveStartupMessage()
	if err != nil {
		return
	}
	if _, ok := startup.(*pgproto3.SSLRequest); !ok {
		return // require TLS, like Neon
	}
	if _, err := conn.Write([]byte{'S'}); err != nil {
		return
	}
	tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	backend = pgproto3.NewBackend(tlsConn, tlsConn)
	msg, err := backend.ReceiveStartupMessage()
	if err != nil {
		return
	}
	sm, ok := msg.(*pgproto3.StartupMessage)
	if !ok || sm.Parameters["user"] != f.user {
		f.sendAuthError(backend)
		return
	}

	if !f.runSCRAM(backend) {
		f.mu.Lock()
		f.authFail++
		f.mu.Unlock()
		f.sendAuthError(backend)
		return
	}
	f.mu.Lock()
	f.authOK++
	f.mu.Unlock()

	backend.Send(&pgproto3.AuthenticationOk{})
	backend.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "17.0"})
	backend.Send(&pgproto3.BackendKeyData{ProcessID: 42, SecretKey: 7})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := backend.Flush(); err != nil {
		return
	}

	for {
		fm, err := backend.Receive()
		if err != nil {
			return
		}
		switch m := fm.(type) {
		case *pgproto3.Query:
			f.mu.Lock()
			f.lastQuery = m.String
			f.mu.Unlock()
			backend.Send(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{
				{Name: []byte("ok"), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1, Format: 0},
			}})
			backend.Send(&pgproto3.DataRow{Values: [][]byte{[]byte("yes")}})
			backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
			backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			if err := backend.Flush(); err != nil {
				return
			}
		case *pgproto3.Terminate:
			return
		}
	}
}

func (f *fakePostgresServer) runSCRAM(backend *pgproto3.Backend) bool {
	// Derive stored credentials from the known password.
	kf := scram.KeyFactors{Salt: "pinned-salt-0123", Iters: 4096}
	client, err := scram.SHA256.NewClient(f.user, f.password, "")
	if err != nil {
		return false
	}
	stored := client.GetStoredCredentials(kf)
	server, err := scram.SHA256.NewServer(func(string) (scram.StoredCredentials, error) {
		return stored, nil
	})
	if err != nil {
		return false
	}
	conv := server.NewConversation()

	backend.Send(&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256"}})
	if err := backend.Flush(); err != nil {
		return false
	}
	msg, err := backend.Receive()
	if err != nil {
		return false
	}
	initial, ok := msg.(*pgproto3.SASLInitialResponse)
	if !ok || initial.AuthMechanism != "SCRAM-SHA-256" {
		return false
	}
	serverFirst, err := conv.Step(string(initial.Data))
	if err != nil {
		return false
	}
	backend.Send(&pgproto3.AuthenticationSASLContinue{Data: []byte(serverFirst)})
	if err := backend.Flush(); err != nil {
		return false
	}
	msg, err = backend.Receive()
	if err != nil {
		return false
	}
	resp, ok := msg.(*pgproto3.SASLResponse)
	if !ok {
		return false
	}
	serverFinal, err := conv.Step(string(resp.Data))
	if err != nil || !conv.Valid() {
		return false
	}
	backend.Send(&pgproto3.AuthenticationSASLFinal{Data: []byte(serverFinal)})
	if err := backend.Flush(); err != nil {
		return false
	}
	return true
}

func (f *fakePostgresServer) sendAuthError(backend *pgproto3.Backend) {
	backend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28P01", Message: "password authentication failed"})
	_ = backend.Flush()
}

var errUnused = errors.New("unused") // keep errors import if otherwise unused; delete if not needed
```

Adjust for the installed pgproto3 version: in pgx v5, `Backend.Send` buffers and `Flush` writes; field names above match v5. Delete the `errUnused` line if `errors` ends up unused.

**Step 2: Verify it compiles**

Run: `go vet ./proxy/`
Expected: clean (test-only file; nothing exercises it yet)

**Step 3: Commit**

```bash
git add proxy/pgtest_test.go
git commit -m "test(proxy): add SCRAM-verifying fake postgres server for tests"
```

---

## Task 6: Upstream connector — dial, TLS, SCRAM

`connectPostgresUpstream` dials the real server, requires TLS (verifying against `p.upstreamCAs` or system roots), replays the client's startup parameters, and completes SCRAM-SHA-256 with the resolved password. Returns the connected `*pgproto3.Frontend` + `net.Conn` ready at the AuthenticationOk boundary, plus the buffered post-auth messages (ParameterStatus, BackendKeyData, ReadyForQuery) to forward to the client.

**Files:**
- Modify: `proxy/postgres.go`
- Modify: `proxy/postgres_test.go`

**Step 1: Write the failing tests**

```go
func TestConnectPostgresUpstreamSCRAM(t *testing.T) {
	fake := startFakePostgres(t, "ep-foo-123.aws.neon.tech", "app_rw", "real-password")

	up, err := connectPostgresUpstream(context.Background(), upstreamParams{
		dialAddr:   fake.addr,
		serverName: "ep-foo-123.aws.neon.tech",
		rootCAs:    fake.certPool,
		user:       "app_rw",
		password:   "real-password",
		startupParameters: map[string]string{
			"user": "app_rw", "database": "appdb",
		},
	})
	if err != nil {
		t.Fatalf("connectPostgresUpstream: %v", err)
	}
	defer up.conn.Close()

	if len(up.postAuthMessages) == 0 {
		t.Error("expected buffered post-auth messages (ParameterStatus etc.)")
	}
	var sawReady bool
	for _, m := range up.postAuthMessages {
		if _, ok := m.(*pgproto3.ReadyForQuery); ok {
			sawReady = true
		}
	}
	if !sawReady {
		t.Error("expected ReadyForQuery in post-auth messages")
	}
}

func TestConnectPostgresUpstreamBadPassword(t *testing.T) {
	fake := startFakePostgres(t, "ep-foo-123.aws.neon.tech", "app_rw", "real-password")

	_, err := connectPostgresUpstream(context.Background(), upstreamParams{
		dialAddr:          fake.addr,
		serverName:        "ep-foo-123.aws.neon.tech",
		rootCAs:           fake.certPool,
		user:              "app_rw",
		password:          "wrong",
		startupParameters: map[string]string{"user": "app_rw", "database": "appdb"},
	})
	if !errors.Is(err, errUpstreamAuthFailed) {
		t.Fatalf("err = %v, want errUpstreamAuthFailed", err)
	}
}

func TestConnectPostgresUpstreamRejectsUntrustedCert(t *testing.T) {
	fake := startFakePostgres(t, "ep-foo-123.aws.neon.tech", "app_rw", "real-password")

	_, err := connectPostgresUpstream(context.Background(), upstreamParams{
		dialAddr:          fake.addr,
		serverName:        "ep-foo-123.aws.neon.tech",
		rootCAs:           x509.NewCertPool(), // empty: trusts nothing
		user:              "app_rw",
		password:          "real-password",
		startupParameters: map[string]string{"user": "app_rw", "database": "appdb"},
	})
	if err == nil {
		t.Fatal("expected TLS verification failure")
	}
}
```

Add needed imports (`context`, `errors`, `crypto/x509`, pgproto3).

**Step 2: Run tests to verify they fail**

Run: `go test -race -run TestConnectPostgresUpstream ./proxy/`
Expected: FAIL — `undefined: connectPostgresUpstream`

**Step 3: Implement**

Append to `proxy/postgres.go`:

```go
import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/xdg-go/scram"
)

// errUpstreamAuthFailed marks an upstream authentication failure, which
// triggers one password-cache invalidation and retry.
var errUpstreamAuthFailed = errors.New("upstream authentication failed")

const postgresDialTimeout = 10 * time.Second

type upstreamParams struct {
	dialAddr          string            // host:port to dial
	serverName        string            // TLS SNI / verification name
	rootCAs           *x509.CertPool    // nil = system roots
	user              string
	password          string
	startupParameters map[string]string // replayed from the client verbatim
}

type upstreamConn struct {
	conn             net.Conn
	frontend         *pgproto3.Frontend
	postAuthMessages []pgproto3.BackendMessage // AuthenticationOk through ReadyForQuery
}

// connectPostgresUpstream dials addr, negotiates TLS (required, verified),
// and authenticates with SCRAM-SHA-256. It returns once the server reaches
// ReadyForQuery, with the intermediate messages buffered for the caller to
// forward to the client.
func connectPostgresUpstream(ctx context.Context, p upstreamParams) (*upstreamConn, error) {
	d := net.Dialer{Timeout: postgresDialTimeout}
	raw, err := d.DialContext(ctx, "tcp", p.dialAddr)
	if err != nil {
		return nil, fmt.Errorf("dialing upstream: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			raw.Close()
		}
	}()

	// Postgres TLS preamble: SSLRequest, expect 'S'.
	frontend := pgproto3.NewFrontend(raw, raw)
	frontend.Send(&pgproto3.SSLRequest{})
	if err := frontend.Flush(); err != nil {
		return nil, fmt.Errorf("sending SSLRequest: %w", err)
	}
	resp := make([]byte, 1)
	if _, err := io.ReadFull(raw, resp); err != nil {
		return nil, fmt.Errorf("reading SSLRequest response: %w", err)
	}
	if resp[0] != 'S' {
		return nil, fmt.Errorf("upstream refused TLS; plaintext upstream connections are not supported")
	}
	tlsConn := tls.Client(raw, &tls.Config{ServerName: p.serverName, RootCAs: p.rootCAs})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("upstream TLS handshake: %w", err)
	}
	frontend = pgproto3.NewFrontend(tlsConn, tlsConn)

	frontend.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      p.startupParameters,
	})
	if err := frontend.Flush(); err != nil {
		return nil, fmt.Errorf("sending startup message: %w", err)
	}

	if err := authenticateSCRAM(frontend, p.user, p.password); err != nil {
		return nil, err
	}

	// Collect AuthenticationOk .. ReadyForQuery for the client.
	var post []pgproto3.BackendMessage
	for {
		msg, err := frontend.Receive()
		if err != nil {
			return nil, fmt.Errorf("reading post-auth messages: %w", err)
		}
		switch m := msg.(type) {
		case *pgproto3.ErrorResponse:
			if m.Code == "28P01" || m.Code == "28000" {
				return nil, errUpstreamAuthFailed
			}
			return nil, fmt.Errorf("upstream error during startup: %s", m.Code)
		default:
			// pgproto3 reuses message buffers; copy before retaining.
			encoded, err := msg.Encode(nil)
			if err != nil {
				return nil, err
			}
			_ = encoded // see note below
			post = append(post, msg)
		}
		if _, ready := msg.(*pgproto3.ReadyForQuery); ready {
			ok = true
			return &upstreamConn{conn: tlsConn, frontend: frontend, postAuthMessages: post}, nil
		}
	}
}

func authenticateSCRAM(frontend *pgproto3.Frontend, user, password string) error {
	msg, err := frontend.Receive()
	if err != nil {
		return fmt.Errorf("reading auth request: %w", err)
	}
	switch m := msg.(type) {
	case *pgproto3.AuthenticationSASL:
		var supported bool
		for _, mech := range m.AuthMechanisms {
			if mech == "SCRAM-SHA-256" {
				supported = true
			}
		}
		if !supported {
			return fmt.Errorf("upstream offers no supported SASL mechanism")
		}
	case *pgproto3.ErrorResponse:
		return errUpstreamAuthFailed
	default:
		return fmt.Errorf("upstream requested unsupported authentication")
	}

	client, err := scram.SHA256.NewClient(user, password, "")
	if err != nil {
		return fmt.Errorf("initializing SCRAM client: %w", err)
	}
	conv := client.NewConversation()
	first, err := conv.Step("")
	if err != nil {
		return fmt.Errorf("SCRAM client-first: %w", err)
	}
	frontend.Send(&pgproto3.SASLInitialResponse{AuthMechanism: "SCRAM-SHA-256", Data: []byte(first)})
	if err := frontend.Flush(); err != nil {
		return err
	}

	msg, err = frontend.Receive()
	if err != nil {
		return fmt.Errorf("reading SCRAM server-first: %w", err)
	}
	cont, ok := msg.(*pgproto3.AuthenticationSASLContinue)
	if !ok {
		return errUpstreamAuthFailed
	}
	final, err := conv.Step(string(cont.Data))
	if err != nil {
		return fmt.Errorf("SCRAM client-final: %w", err)
	}
	frontend.Send(&pgproto3.SASLResponse{Data: []byte(final)})
	if err := frontend.Flush(); err != nil {
		return err
	}

	msg, err = frontend.Receive()
	if err != nil {
		return fmt.Errorf("reading SCRAM server-final: %w", err)
	}
	switch m := msg.(type) {
	case *pgproto3.AuthenticationSASLFinal:
		if _, err := conv.Step(string(m.Data)); err != nil {
			return fmt.Errorf("upstream server signature invalid: %w", err)
		}
		return nil
	case *pgproto3.ErrorResponse:
		return errUpstreamAuthFailed
	default:
		return errUpstreamAuthFailed
	}
}
```

Implementation notes for the executor:
- Add `"io"` to imports.
- The `msg.Encode(nil)` line above is a placeholder reminder: **pgproto3 `Receive` reuses internal buffers.** Verify whether retaining messages across `Receive` calls is safe in the installed version; if not, deep-copy each retained message (encode to bytes and keep `[]byte`, then write those bytes to the client instead of re-encoding typed messages). Prefer keeping `post` as `[][]byte` of encoded frames if in doubt — the client-side handler only needs to write them verbatim.
- In pgx v5.5+, `Encode` has signature `Encode(dst []byte) ([]byte, error)`; older v5 returns only `[]byte`. Match the installed version.

**Step 4: Run tests**

Run: `go test -race -run TestConnectPostgresUpstream ./proxy/ && go vet ./proxy/`
Expected: PASS (3 tests)

**Step 5: Commit**

```bash
git add proxy/postgres.go proxy/postgres_test.go
git commit -m "feat(proxy): add postgres upstream connector with SCRAM auth"
```

---

## Task 7: Client-side handshake — TLS required, token auth, context resolution

The server side of the listener: require `SSLRequest` (refuse plaintext before requesting any credential), terminate TLS with a CA-minted cert for the SNI hostname, read the startup message, demand a cleartext password (the run token, safe inside our TLS), and resolve it to a `*RunContextData` via the proxy's `ContextResolver` — or constant-time compare against the static `authToken` in standalone mode.

**Files:**
- Modify: `proxy/postgres.go`
- Modify: `proxy/postgres_test.go`

**Step 1: Write the failing tests**

```go
// testCA builds a proxy CA for tests. Check ca_test.go / intercept_test.go
// for an existing helper first and reuse it if present.
func testCA(t *testing.T) (*CA, *x509.CertPool) {
	t.Helper()
	// Reuse the existing test helper that creates a CA (see proxy_test.go /
	// intercept_test.go); it must return the CA and a pool trusting it.
	...
}

// pgConnect performs the client side of the handshake up to auth, as a raw
// pgproto3 frontend, and returns the post-TLS frontend for assertions.
func pgConnect(t *testing.T, addr, sniHost string, caPool *x509.CertPool, user, db, password string) (*pgproto3.Frontend, net.Conn, pgproto3.BackendMessage) {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	fe := pgproto3.NewFrontend(raw, raw)
	fe.Send(&pgproto3.SSLRequest{})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(raw, buf); err != nil || buf[0] != 'S' {
		t.Fatalf("SSLRequest response = %v %v, want 'S'", buf, err)
	}
	tlsConn := tls.Client(raw, &tls.Config{ServerName: sniHost, RootCAs: caPool})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	fe = pgproto3.NewFrontend(tlsConn, tlsConn)
	fe.Send(&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": user, "database": db},
	})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}
	msg, err := fe.Receive()
	if err != nil {
		t.Fatalf("receiving auth request: %v", err)
	}
	if _, ok := msg.(*pgproto3.AuthenticationCleartextPassword); ok {
		fe.Send(&pgproto3.PasswordMessage{Password: password})
		if err := fe.Flush(); err != nil {
			t.Fatal(err)
		}
		msg, err = fe.Receive()
		if err != nil {
			t.Fatalf("receiving auth result: %v", err)
		}
	}
	return fe, tlsConn, msg
}

func TestPostgresListenerRejectsPlaintext(t *testing.T) {
	ca, _ := testCA(t)
	p := NewProxy()
	p.SetCA(ca)
	srv := newTestPostgresListener(t, p)

	raw, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	fe := pgproto3.NewFrontend(raw, raw)
	fe.Send(&pgproto3.StartupMessage{ // no SSLRequest first
		ProtocolVersion: pgproto3.ProtocolVersionNumber,
		Parameters:      map[string]string{"user": "u", "database": "d"},
	})
	if err := fe.Flush(); err != nil {
		t.Fatal(err)
	}
	msg, err := fe.Receive()
	if err == nil {
		er, ok := msg.(*pgproto3.ErrorResponse)
		if !ok {
			t.Fatalf("expected ErrorResponse, got %T", msg)
		}
		if er.Code != "28000" {
			t.Errorf("error code = %q, want 28000", er.Code)
		}
	}
	// Either an ErrorResponse or an immediate close is acceptable; the key
	// invariant is the server never sent AuthenticationCleartextPassword.
}

func TestPostgresListenerRejectsBadToken(t *testing.T) {
	ca, caPool := testCA(t)
	p := NewProxy()
	p.SetCA(ca)
	p.SetContextResolver(func(token string) (*RunContextData, bool) {
		if token == "good-token" {
			return &RunContextData{RunID: "run-1"}, true
		}
		return nil, false
	})
	srv := newTestPostgresListener(t, p)

	_, conn, msg := pgConnect(t, srv.Addr(), "ep-foo.aws.neon.tech", caPool, "app_rw", "appdb", "bad-token")
	defer conn.Close()
	er, ok := msg.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("expected ErrorResponse for bad token, got %T", msg)
	}
	if er.Code != "28P01" {
		t.Errorf("error code = %q, want 28P01", er.Code)
	}
}

func TestPostgresListenerStaticTokenAuth(t *testing.T) {
	ca, caPool := testCA(t)
	p := NewProxy()
	p.SetCA(ca)
	p.SetAuthToken("static-token")
	// No resolver for this host: auth succeeds, then resolution fails.
	srv := newTestPostgresListener(t, p)

	_, conn, msg := pgConnect(t, srv.Addr(), "ep-foo.aws.neon.tech", caPool, "app_rw", "appdb", "static-token")
	defer conn.Close()
	er, ok := msg.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("expected ErrorResponse (no resolver configured), got %T", msg)
	}
	// Auth passed; failure must be the no-resolver error, not bad-password.
	if er.Code != "08004" { // SQLSTATE: server rejected the connection
		t.Errorf("error code = %q, want 08004", er.Code)
	}
}
```

`newTestPostgresListener` starts the (not yet written) `PostgresServer` on 127.0.0.1:0:

```go
func newTestPostgresListener(t *testing.T, p *Proxy) *PostgresServer {
	t.Helper()
	srv := NewPostgresServer(p)
	if err := srv.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Stop() })
	return srv
}
```

Check `proxy/proxy.go` for `SetContextResolver`; if the setter has a different name, use it. For `testCA`, **reuse the existing CA test helper** — grep `proxy/*_test.go` for `NewCA`/`GenerateCA`; only write a new helper if none exists.

**Step 2: Run tests to verify they fail**

Run: `go test -race -run TestPostgresListener ./proxy/`
Expected: FAIL — `undefined: NewPostgresServer`

**Step 3: Implement the listener and client-side handshake**

Append to `proxy/postgres.go`:

```go
// PostgresServer accepts Postgres client connections, authenticates them
// with the proxy's run token, and relays to the real upstream with injected
// credentials. See docs/plans/2026-06-11-postgres-neon-design.md.
type PostgresServer struct {
	proxy    *Proxy
	listener net.Listener

	// dialUpstream overrides upstream dialing (tests). nil = net dial of
	// host:5432.
	dialUpstream func(ctx context.Context, host string) (string, error) // returns dial addr
}

// NewPostgresServer creates a Postgres listener bound to the proxy's
// credential resolvers, CA, context resolver, and policy.
func NewPostgresServer(p *Proxy) *PostgresServer {
	return &PostgresServer{proxy: p}
}

// Start begins accepting connections on addr (host:port).
func (s *PostgresServer) Start(addr string) error {
	if s.proxy.ca == nil {
		return fmt.Errorf("postgres listener requires a CA for TLS termination")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("starting postgres listener: %w", err)
	}
	s.listener = ln
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handleConn(conn)
		}
	}()
	return nil
}

// Addr returns the listener address.
func (s *PostgresServer) Addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// Stop closes the listener. In-flight connections are not interrupted.
func (s *PostgresServer) Stop() {
	if s.listener != nil {
		s.listener.Close()
	}
}

const postgresHandshakeTimeout = 30 * time.Second

func (s *PostgresServer) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(postgresHandshakeTimeout))

	backend := pgproto3.NewBackend(conn, conn)
	startup, err := backend.ReceiveStartupMessage()
	if err != nil {
		return
	}
	// TLS is mandatory: the client's next message carries the run token.
	if _, ok := startup.(*pgproto3.SSLRequest); !ok {
		sendPGError(backend, "28000", "SSL required")
		return
	}
	if _, err := conn.Write([]byte{'S'}); err != nil {
		return
	}

	var sniHost string
	tlsConn := tls.Server(conn, &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			sniHost = hello.ServerName
			return s.proxy.ca.GenerateCert(hello.ServerName)
		},
	})
	if err := tlsConn.HandshakeContext(context.Background()); err != nil {
		return
	}
	if sniHost == "" {
		// No SNI: we cannot know the intended upstream.
		backend = pgproto3.NewBackend(tlsConn, tlsConn)
		// Drain the startup message so the error is readable by the client.
		_, _ = backend.ReceiveStartupMessage()
		sendPGError(backend, "08004", "server name indication (SNI) required")
		return
	}
	backend = pgproto3.NewBackend(tlsConn, tlsConn)

	msg, err := backend.ReceiveStartupMessage()
	if err != nil {
		return
	}
	sm, ok := msg.(*pgproto3.StartupMessage)
	if !ok {
		return
	}
	user := sm.Parameters["user"]
	database := sm.Parameters["database"]
	if database == "" {
		database = user // postgres convention
	}

	// Authenticate the client: the password field carries the run token.
	backend.Send(&pgproto3.AuthenticationCleartextPassword{})
	if err := backend.Flush(); err != nil {
		return
	}
	pwMsg, err := backend.Receive()
	if err != nil {
		return
	}
	pw, ok := pwMsg.(*pgproto3.PasswordMessage)
	if !ok {
		return
	}
	rc, authOK := s.authenticate(pw.Password)
	if !authOK {
		sendPGError(backend, "28P01", "password authentication failed")
		return
	}

	s.serveAuthenticated(tlsConn, backend, rc, sniHost, user, database, sm.Parameters)
}

// authenticate resolves the run token to per-run context. Standalone mode
// (no context resolver) compares against the static auth token; with no
// auth token configured at all, any client that reached the listener is
// accepted (localhost-only binding, same trust model as the HTTP plane).
func (s *PostgresServer) authenticate(token string) (*RunContextData, bool) {
	p := s.proxy
	if p.contextResolver != nil {
		return p.contextResolver(token)
	}
	if p.authToken != "" {
		if subtle.ConstantTimeCompare([]byte(token), []byte(p.authToken)) == 1 {
			return nil, true
		}
		return nil, false
	}
	return nil, true
}

func sendPGError(backend *pgproto3.Backend, code, message string) {
	backend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: code, Message: message})
	_ = backend.Flush()
}
```

Add a stub so this task compiles without the relay (Task 8 replaces it):

```go
func (s *PostgresServer) serveAuthenticated(clientConn net.Conn, backend *pgproto3.Backend, rc *RunContextData, sniHost, user, database string, startupParams map[string]string) {
	if s.proxy.postgresResolverForHost(rc, sniHost) == nil {
		sendPGError(backend, "08004", "no credentials configured for this host")
		return
	}
	sendPGError(backend, "08004", "relay not implemented")
}
```

Add `"crypto/subtle"` to imports. Note `p.contextResolver` and `p.authToken` are read without the mutex elsewhere only after setup; follow the existing locking convention you find in `proxy.go` (check `ResolveContext`).

**Step 4: Run tests**

Run: `go test -race -run TestPostgresListener ./proxy/ && go vet ./proxy/`
Expected: PASS (3 tests)

**Step 5: Commit**

```bash
git add proxy/postgres.go proxy/postgres_test.go
git commit -m "feat(proxy): postgres listener with TLS termination and token auth"
```

---

## Task 8: Full connection flow — policy check, resolve, upstream, relay, logging

Wire the two halves together in `serveAuthenticated`: network policy check on the SNI host, password resolution (with one invalidate-and-retry on `errUpstreamAuthFailed`), upstream connection, post-auth message forwarding, then a bidirectional **message-granularity relay** (pgproto3 pump, not raw `io.Copy` — the backend reader is buffered, so raw copy could drop pipelined bytes). Emit one audit log entry per connection.

**Files:**
- Modify: `proxy/postgres.go`
- Modify: `proxy/postgres_test.go`

**Step 1: Write the failing tests**

```go
import "github.com/jackc/pgx/v5/pgconn"

// connectThroughGatekeeper opens a real pgconn client connection through the
// postgres listener, with SNI naming the fake upstream.
func connectThroughGatekeeper(t *testing.T, srv *PostgresServer, caPool *x509.CertPool, sniHost, user, db, token string) (*pgconn.PgConn, error) {
	t.Helper()
	cfg, err := pgconn.ParseConfig(fmt.Sprintf("postgres://%s:%s@%s/%s", user, token, srv.Addr(), db))
	if err != nil {
		t.Fatal(err)
	}
	cfg.TLSConfig = &tls.Config{ServerName: sniHost, RootCAs: caPool}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return pgconn.Connect(ctx, cfg)
}

func TestPostgresEndToEnd(t *testing.T) {
	const host = "ep-foo-123.aws.neon.tech"
	fake := startFakePostgres(t, host, "app_rw", "real-password")

	ca, caPool := testCA(t)
	p := NewProxy()
	p.SetCA(ca)
	p.SetUpstreamCAs(fake.certPool)
	p.SetAuthToken("run-token")
	p.SetPostgresResolver("*.neon.tech", NewStaticPostgresResolver("real-password"))

	var logged []RequestLogData
	var logMu sync.Mutex
	p.SetRequestLogger(func(d RequestLogData) {
		logMu.Lock()
		logged = append(logged, d)
		logMu.Unlock()
	})

	srv := newTestPostgresListener(t, p)
	srv.dialUpstream = func(ctx context.Context, h string) (string, error) {
		if h != host {
			t.Errorf("dialUpstream host = %q, want %q", h, host)
		}
		return fake.addr, nil
	}

	conn, err := connectThroughGatekeeper(t, srv, caPool, host, "app_rw", "appdb", "run-token")
	if err != nil {
		t.Fatalf("connect through gatekeeper: %v", err)
	}
	res := conn.Exec(context.Background(), "SELECT 1").ReadAll()
	if len(res) == 0 || res[0].Err != nil {
		t.Fatalf("query through gatekeeper failed: %+v", res)
	}
	conn.Close(context.Background())

	fake.mu.Lock()
	if fake.lastQuery != "SELECT 1" {
		t.Errorf("upstream saw query %q, want SELECT 1", fake.lastQuery)
	}
	fake.mu.Unlock()

	// One audit entry, type postgres, with host/user/db and no password.
	deadline := time.Now().Add(2 * time.Second)
	for {
		logMu.Lock()
		n := len(logged)
		logMu.Unlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	logMu.Lock()
	defer logMu.Unlock()
	if len(logged) != 1 {
		t.Fatalf("logged %d entries, want 1", len(logged))
	}
	d := logged[0]
	if d.RequestType != "postgres" || d.Host != host || d.UserID != "app_rw" {
		t.Errorf("log entry = %+v", d)
	}
}

func TestPostgresRetriesAfterStalePassword(t *testing.T) {
	const host = "ep-foo-123.aws.neon.tech"
	fake := startFakePostgres(t, host, "app_rw", "current-password")

	ca, caPool := testCA(t)
	p := NewProxy()
	p.SetCA(ca)
	p.SetUpstreamCAs(fake.certPool)
	p.SetAuthToken("run-token")

	stale := &flakyResolver{passwords: []string{"stale-password", "current-password"}}
	p.SetPostgresResolver("*.neon.tech", stale)

	srv := newTestPostgresListener(t, p)
	srv.dialUpstream = func(ctx context.Context, h string) (string, error) { return fake.addr, nil }

	conn, err := connectThroughGatekeeper(t, srv, caPool, host, "app_rw", "appdb", "run-token")
	if err != nil {
		t.Fatalf("expected retry to succeed, got: %v", err)
	}
	conn.Close(context.Background())
	if !stale.invalidated.Load() {
		t.Error("expected InvalidatePassword to be called")
	}
}

// flakyResolver returns passwords in sequence; records invalidation.
type flakyResolver struct {
	mu          sync.Mutex
	passwords   []string
	idx         int
	invalidated atomic.Bool
}

func (f *flakyResolver) ResolvePassword(ctx context.Context, host, user, database string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pw := f.passwords[min(f.idx, len(f.passwords)-1)]
	f.idx++
	return pw, nil
}

func (f *flakyResolver) InvalidatePassword(host, user, database string) { f.invalidated.Store(true) }

func TestPostgresPolicyDeniesHost(t *testing.T) {
	ca, caPool := testCA(t)
	p := NewProxy()
	p.SetCA(ca)
	p.SetAuthToken("run-token")
	p.SetPolicy("strict")
	p.SetAllowedHosts([]string{"api.github.com"}) // neon not allowed
	p.SetPostgresResolver("*.neon.tech", NewStaticPostgresResolver("pw"))
	srv := newTestPostgresListener(t, p)

	_, err := connectThroughGatekeeper(t, srv, caPool, "ep-foo.aws.neon.tech", "app_rw", "appdb", "run-token")
	if err == nil {
		t.Fatal("expected policy denial")
	}
}
```

Check the actual names of `SetRequestLogger`, `SetPolicy`, `SetAllowedHosts` in proxy.go (grep `func (p \*Proxy) Set`) and adjust. Use `sync/atomic` import for `atomic.Bool`.

**Step 2: Run tests to verify they fail**

Run: `go test -race -run 'TestPostgresEndToEnd|TestPostgresRetries|TestPostgresPolicy' ./proxy/`
Expected: FAIL — relay not implemented / undefined helpers

**Step 3: Implement**

Replace the Task 7 stub of `serveAuthenticated`:

```go
const postgresUpstreamPort = "5432"

func (s *PostgresServer) serveAuthenticated(clientConn net.Conn, backend *pgproto3.Backend, rc *RunContextData, sniHost, user, database string, startupParams map[string]string) {
	p := s.proxy
	start := time.Now()

	logEntry := RequestLogData{
		Method:      "STARTUP",
		URL:         sniHost,
		Host:        sniHost,
		RequestType: "postgres",
		UserID:      user,
		RequestSize: -1, ResponseSize: -1,
	}
	if rc != nil {
		logEntry.RunID = rc.RunID
	}

	deny := func(code, clientMsg, logReason string) {
		sendPGError(backend, code, clientMsg)
		logEntry.Denied = true
		logEntry.DenyReason = logReason
		logEntry.Duration = time.Since(start)
		s.log(logEntry)
	}

	// Network policy on the SNI host, before any upstream dial.
	if !s.policyAllows(rc, sniHost, 5432) {
		p.logPolicyData(PolicyLogData{
			RunID: logEntry.RunID, Scope: "network", Operation: "postgres.connect",
			Message: "Host not in allow list: " + sniHost,
		})
		deny("28000", "connection not allowed by network policy", "Host not in allow list: "+sniHost)
		return
	}

	resolver := p.postgresResolverForHost(rc, sniHost)
	if resolver == nil {
		deny("08004", "no credentials configured for this host", "no postgres resolver for host")
		return
	}

	up, grants, err := s.connectWithRetry(resolver, sniHost, user, database, startupParams)
	if err != nil {
		// Generic message to the client; detail (sans secrets) to slog.
		slog.Debug("postgres upstream connection failed",
			"subsystem", "proxy", "host", sniHost, "user", user, "error", err)
		deny("28P01", "could not authenticate to upstream database", "upstream connection failed")
		return
	}
	defer up.conn.Close()
	logEntry.AuthInjected = true
	logEntry.Grants = grants

	// Hand the buffered AuthenticationOk..ReadyForQuery to the client.
	for _, m := range up.postAuthMessages {
		backend.Send(m)
	}
	if err := backend.Flush(); err != nil {
		return
	}

	// Handshake done; clear the handshake deadline for the relay phase.
	_ = clientConn.SetDeadline(time.Time{})
	_ = up.conn.SetDeadline(time.Time{})

	bytesIn, bytesOut := relayPostgres(backend, up.frontend)
	logEntry.StatusCode = 200 // connection completed normally
	logEntry.RequestSize = bytesIn
	logEntry.ResponseSize = bytesOut
	logEntry.Duration = time.Since(start)
	s.log(logEntry)
}

// connectWithRetry resolves the password and connects upstream, invalidating
// the cached password and retrying once if upstream rejects it (passwords
// rotate on neon branch reset).
func (s *PostgresServer) connectWithRetry(resolver PostgresCredentialResolver, host, user, database string, startupParams map[string]string) (*upstreamConn, []string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), postgresHandshakeTimeout)
	defer cancel()

	dialAddr := net.JoinHostPort(host, postgresUpstreamPort)
	if s.dialUpstream != nil {
		addr, err := s.dialUpstream(ctx, host)
		if err != nil {
			return nil, nil, err
		}
		dialAddr = addr
	}

	for attempt := range 2 {
		password, err := resolver.ResolvePassword(ctx, host, user, database)
		if err != nil {
			return nil, nil, fmt.Errorf("resolving postgres password: %w", err)
		}
		up, err := connectPostgresUpstream(ctx, upstreamParams{
			dialAddr:          dialAddr,
			serverName:        host,
			rootCAs:           s.proxy.upstreamCAs,
			user:              user,
			password:          password,
			startupParameters: startupParams,
		})
		if err == nil {
			return up, []string{"postgres:" + host}, nil
		}
		if !errors.Is(err, errUpstreamAuthFailed) || attempt == 1 {
			return nil, nil, err
		}
		resolver.InvalidatePassword(host, user, database)
	}
	panic("unreachable")
}

// policyAllows mirrors checkNetworkPolicyForRequest's host-level check for
// non-HTTP connections.
func (s *PostgresServer) policyAllows(rc *RunContextData, host string, port int) bool {
	if rc != nil {
		if rc.Policy != "strict" {
			return true
		}
		return matchHost(rc.AllowedHosts, host, port)
	}
	return s.proxy.checkNetworkPolicy(host, port)
}

func (s *PostgresServer) log(data RequestLogData) {
	if s.proxy.logger == nil {
		return
	}
	s.proxy.logger(data)
}

// relayPostgres pumps protocol messages in both directions until either side
// closes. Message-granularity (not raw byte copy) because both pgproto3
// readers are buffered. Returns bytes relayed client→upstream and
// upstream→client (approximate: message payload sizes).
func relayPostgres(backend *pgproto3.Backend, frontend *pgproto3.Frontend) (bytesIn, bytesOut int64) {
	var inCount, outCount atomic.Int64
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		for {
			msg, err := backend.Receive()
			if err != nil {
				return
			}
			frontend.Send(msg)
			if err := frontend.Flush(); err != nil {
				return
			}
			inCount.Add(1)
			if _, terminated := msg.(*pgproto3.Terminate); terminated {
				return
			}
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			msg, err := frontend.Receive()
			if err != nil {
				return
			}
			backend.Send(msg)
			if err := backend.Flush(); err != nil {
				return
			}
			outCount.Add(1)
		}
	}()
	<-done
	return inCount.Load(), outCount.Load()
}
```

Implementation notes:
- `p.logPolicyData` — check how `logPolicy` is invoked in proxy.go (it takes an `*http.Request`); add a small request-free variant or call the `policyLogger` field directly, following the existing pattern.
- The relay counts messages, not bytes; if `RequestLogData` semantics demand bytes, sum `len(msg encoded)` instead — keep it simple, note the choice in a comment.
- The relay's "forward then Flush per message" is correct but check pgproto3 docs for `Receive` buffer reuse (same caveat as Task 6): the message is consumed by `Send` before the next `Receive`, which is safe.
- When one pump exits, close both conns to unblock the other (use the `closeOnce` pattern from `handleConnectTunnel`, proxy/proxy.go:1832), then drain the second `done`.

**Step 4: Run tests**

Run: `go test -race -run 'TestPostgres' ./proxy/ && go vet ./proxy/`
Expected: PASS (all postgres tests, including earlier tasks')

**Step 5: Run the full package suite to catch regressions**

Run: `go test -race ./proxy/`
Expected: PASS

**Step 6: Commit**

```bash
git add proxy/postgres.go proxy/postgres_test.go
git commit -m "feat(proxy): postgres relay with policy check, retry, and audit logging"
```

---

## Task 9: Config — postgres listener block and credential form

Add `postgres:` top-level config (listener host/port) and a `postgres:` sub-block on credentials selecting a resolver (`neon` or `static`).

**Files:**
- Modify: `config.go`
- Modify: `config_test.go`

**Step 1: Write the failing test**

```go
func TestParseConfigPostgres(t *testing.T) {
	yaml := `
proxy:
  port: 8080
postgres:
  port: 5432
  host: 0.0.0.0
credentials:
  - host: "*.neon.tech"
    postgres:
      resolver: neon
    source:
      type: env
      var: NEON_API_KEY
    grant: neon-databases
`
	cfg, err := ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.Postgres == nil || cfg.Postgres.Port != 5432 || cfg.Postgres.Host != "0.0.0.0" {
		t.Errorf("Postgres config = %+v", cfg.Postgres)
	}
	if len(cfg.Credentials) != 1 {
		t.Fatalf("credentials = %d, want 1", len(cfg.Credentials))
	}
	pg := cfg.Credentials[0].Postgres
	if pg == nil || pg.Resolver != "neon" {
		t.Errorf("credential postgres block = %+v", pg)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -race -run TestParseConfigPostgres ./`
Expected: FAIL — unknown fields

**Step 3: Implement**

In `config.go`:

```go
// PostgresConfig configures the Postgres data-plane listener.
type PostgresConfig struct {
	Port int    `yaml:"port"`           // listener port (e.g. 5432)
	Host string `yaml:"host,omitempty"` // bind address (default: same as proxy)
}

// PostgresCredentialConfig marks a credential as a Postgres credential and
// selects how passwords are resolved.
type PostgresCredentialConfig struct {
	Resolver string `yaml:"resolver"` // "neon" (api key from source) or "static" (password from source)
}
```

Add `Postgres *PostgresConfig` to `Config` and `Postgres *PostgresCredentialConfig` to `CredentialConfig`.

**Step 4: Run tests**

Run: `go test -race ./ && go vet ./`
Expected: PASS

**Step 5: Commit**

```bash
git add config.go config_test.go
git commit -m "feat(config): add postgres listener and credential config"
```

---

## Task 10: Server wiring — build resolvers, start the listener

Wire it together in `gatekeeper.go`: credentials with a `postgres:` block become resolvers on the proxy (`neon` wraps the source as the API key; `static` uses the source's value as the password), and a configured `postgres:` listener starts/stops with the server.

**Files:**
- Modify: `gatekeeper.go`
- Modify: `gatekeeper_test.go`

**Step 1: Write the failing test**

Follow the existing integration-test pattern in `gatekeeper_test.go` (find a test that builds a `Config`, starts a `Server`, and hits the proxy — reuse its CA fixture approach). The test:

```go
func TestServerStartsPostgresListener(t *testing.T) {
	// Build config with TLS CA fixture (reuse existing test CA setup),
	// postgres: {port: 0}, and one credential:
	//   host: "*.neon.tech", postgres: {resolver: static},
	//   source: {type: static, value: "real-password"}
	// Start the server, assert s.PostgresAddr() != "" and that a raw TCP
	// connection to it gets an 'S' response to SSLRequest.
}
```

Keep it lightweight: full protocol round-trips are covered in `proxy/`; this test only proves wiring (listener up, resolver registered — assert via `s.proxy.postgresResolverForHost(nil, "ep-x.aws.neon.tech") != nil` if exported access exists, otherwise via the SSLRequest probe plus a config-validation case).

Also test validation: a config with `postgres.port` set but no `tls` CA must fail at startup with a clear error; a credential `postgres.resolver` value other than neon/static must error.

**Step 2: Run test to verify it fails**

Run: `go test -race -run TestServerStartsPostgresListener ./`
Expected: FAIL

**Step 3: Implement**

In `gatekeeper.go`:
- In the config-processing path (where `ResolveCredentialSource` is called per credential), branch when `cred.Postgres != nil`:
  - `resolver: "neon"` → `&credentialsource.NeonResolver{APIKey: src}` where `src` is the resolved `CredentialSource`; register via `s.proxy.SetPostgresResolver(cred.Host, resolverAdapter)`.
  - `resolver: "static"` → fetch the source value once at startup (like static credentials today) and register `proxy.NewStaticPostgresResolver(value)`.
  - `NeonResolver` lives in `credentialsource` and `PostgresCredentialResolver` in `proxy`; the Neon resolver already satisfies the interface (same method set) — no adapter needed, just check it compiles. If an import cycle threatens, define the interface only in `proxy` and have `credentialsource` satisfy it implicitly (Go structural interfaces).
- In `Start()` (gatekeeper.go:653), after the HTTP listener: if `s.cfg.Postgres != nil`, create `proxy.NewPostgresServer(s.proxy)`, `Start(host:port)` (default host = proxy host), store on `s` for `Stop()`, log the address. Add `PostgresAddr()` accessor following `ProxyAddr()`.
- In `Stop()`: stop the postgres server.
- Validate early: postgres listener configured without `tls.ca_cert` → return a configuration error.

**Step 4: Run the full suite**

Run: `go test -race ./... && go vet ./...`
Expected: PASS

**Step 5: Commit**

```bash
git add gatekeeper.go gatekeeper_test.go
git commit -m "feat: wire postgres data plane into standalone server"
```

---

## Task 11: Documentation and example config

**Files:**
- Modify: `AGENTS.md` (architecture tree: add `proxy/postgres.go`, `credentialsource/neon.go`; key capabilities list; Key Types)
- Modify: `README.md` (feature mention + minimal config example)
- Modify: `examples/` sample config (add commented-out postgres block)

**Step 1: Update docs**

Describe: what the data plane does, the SNI requirement, the run-token-as-password convention, and that DNS interception (`*.neon.tech` → gatekeeper) is the embedder's responsibility (moat). Keep the security framing from the design doc: no database secrets in the sandbox.

**Step 2: Verify**

Run: `go test -race ./... && go vet ./... && go build ./...`
Expected: PASS — final clean state.

**Step 3: Commit**

```bash
git add AGENTS.md README.md examples/
git commit -m "docs: document postgres data plane and neon resolver"
```

---

## Final verification

```bash
go build ./...
go vet ./...
go test -race ./...
```

All green, then use superpowers:finishing-a-development-branch (likely outcome: `gh pr create` with default flags, per AGENTS.md).

## Known deferred items (do NOT implement)

- Query-level SQL logging (relay is message-blind by design)
- Connection pooling
- Startup-parameter routing fallback for non-SNI clients
- Configurable upstream port (hardcoded 5432)
- Neon API pagination beyond the first page of projects (log a warning if `len(projects) >= 100` instead)
