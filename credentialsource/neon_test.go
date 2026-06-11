package credentialsource

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

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

const (
	testNeonAPIKey   = "test-api-key"
	testNeonHost     = "ep-cool-darkness-123456.us-east-2.aws.neon.tech"
	testNeonRole     = "app_rw"
	testNeonDatabase = "appdb"
)

// fakeNeonAPI is a minimal in-process fake of the Neon API surface used by
// NeonResolver: list projects, list a project's endpoints, and fetch a
// connection URI. It owns two projects: proj-1 (no matching endpoints) and
// proj-2 (owns ep-cool-darkness-123456 on branch br-9).
type fakeNeonAPI struct {
	t             *testing.T
	server        *httptest.Server
	uriCalls      atomic.Int64
	projectsCalls atomic.Int64
	projectScoped bool // simulate a project-scoped key: GET /projects returns 404

	mu       sync.Mutex
	password string
	branchID string
}

func newFakeNeonAPI(t *testing.T) *fakeNeonAPI {
	f := &fakeNeonAPI{t: t, password: "s3cret", branchID: "br-9"}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeNeonAPI) setPassword(p string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.password = p
}

func (f *fakeNeonAPI) currentPassword() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.password
}

// setBranchID simulates Neon reassigning the compute endpoint to a different
// branch. Connection URI requests for any other branch are rejected.
func (f *fakeNeonAPI) setBranchID(b string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.branchID = b
}

func (f *fakeNeonAPI) currentBranchID() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.branchID
}

func (f *fakeNeonAPI) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+testNeonAPIKey {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"message":"authorization failed"}`)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/api/v2/projects":
		f.projectsCalls.Add(1)
		if f.projectScoped {
			// Project-scoped API keys cannot list projects.
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"message":"not allowed to perform actions outside the project this key is scoped to"}`)
			return
		}
		fmt.Fprint(w, `{"projects":[{"id":"proj-1"},{"id":"proj-2"}]}`)
	case "/api/v2/projects/proj-1/endpoints":
		fmt.Fprint(w, `{"endpoints":[{"id":"ep-other-endpoint-999999","branch_id":"br-1"}]}`)
	case "/api/v2/projects/proj-2/endpoints":
		fmt.Fprintf(w, `{"endpoints":[{"id":"ep-cool-darkness-123456","branch_id":%q}]}`, f.currentBranchID())
	case "/api/v2/projects/proj-2/connection_uri":
		f.uriCalls.Add(1)
		q := r.URL.Query()
		if got, want := q.Get("branch_id"), f.currentBranchID(); got != want {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"message":"branch not found"}`)
			return
		}
		if got := q.Get("database_name"); got != testNeonDatabase {
			f.t.Errorf("connection_uri database_name = %q, want %q", got, testNeonDatabase)
		}
		if got := q.Get("role_name"); got != testNeonRole {
			f.t.Errorf("connection_uri role_name = %q, want %q", got, testNeonRole)
		}
		uri := fmt.Sprintf("postgresql://%s:%s@%s/%s?sslmode=require",
			q.Get("role_name"), f.currentPassword(), testNeonHost, q.Get("database_name"))
		fmt.Fprintf(w, `{"uri":%q}`, uri)
	default:
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"not found"}`)
	}
}

func newTestNeonResolver(f *fakeNeonAPI, apiKey string) *NeonResolver {
	return &NeonResolver{
		APIKey:  NewStaticSource(apiKey),
		BaseURL: f.server.URL,
	}
}

func TestNeonResolverResolvePassword(t *testing.T) {
	f := newFakeNeonAPI(t)
	r := newTestNeonResolver(f, testNeonAPIKey)

	got, err := r.ResolvePassword(context.Background(), testNeonHost, testNeonRole, testNeonDatabase)
	if err != nil {
		t.Fatalf("ResolvePassword() error = %v", err)
	}
	if got != "s3cret" {
		t.Errorf("ResolvePassword() = %q, want %q", got, "s3cret")
	}
}

func TestNeonResolverCachesPasswords(t *testing.T) {
	f := newFakeNeonAPI(t)
	r := newTestNeonResolver(f, testNeonAPIKey)

	for i := 0; i < 3; i++ {
		got, err := r.ResolvePassword(context.Background(), testNeonHost, testNeonRole, testNeonDatabase)
		if err != nil {
			t.Fatalf("ResolvePassword() call %d error = %v", i+1, err)
		}
		if got != "s3cret" {
			t.Errorf("ResolvePassword() call %d = %q, want %q", i+1, got, "s3cret")
		}
	}
	if calls := f.uriCalls.Load(); calls != 1 {
		t.Errorf("connection_uri calls = %d, want 1", calls)
	}
}

func TestNeonResolverInvalidatePassword(t *testing.T) {
	f := newFakeNeonAPI(t)
	r := newTestNeonResolver(f, testNeonAPIKey)

	got, err := r.ResolvePassword(context.Background(), testNeonHost, testNeonRole, testNeonDatabase)
	if err != nil {
		t.Fatalf("ResolvePassword() error = %v", err)
	}
	if got != "s3cret" {
		t.Errorf("ResolvePassword() = %q, want %q", got, "s3cret")
	}

	r.InvalidatePassword(testNeonHost, testNeonRole, testNeonDatabase)
	f.setPassword("rotated")

	got, err = r.ResolvePassword(context.Background(), testNeonHost, testNeonRole, testNeonDatabase)
	if err != nil {
		t.Fatalf("ResolvePassword() after invalidate error = %v", err)
	}
	if got != "rotated" {
		t.Errorf("ResolvePassword() after invalidate = %q, want %q", got, "rotated")
	}
	if calls := f.uriCalls.Load(); calls != 2 {
		t.Errorf("connection_uri calls = %d, want 2", calls)
	}
}

// Neon can reassign a compute endpoint to a different branch (e.g. branch
// reset). InvalidatePassword must drop the cached endpoint info too, so the
// retry re-discovers the endpoint and resolves against the new branch instead
// of fetching the old branch's credentials forever.
func TestNeonResolverInvalidatePasswordAfterBranchMove(t *testing.T) {
	f := newFakeNeonAPI(t)
	r := newTestNeonResolver(f, testNeonAPIKey)

	got, err := r.ResolvePassword(context.Background(), testNeonHost, testNeonRole, testNeonDatabase)
	if err != nil {
		t.Fatalf("ResolvePassword() error = %v", err)
	}
	if got != "s3cret" {
		t.Errorf("ResolvePassword() = %q, want %q", got, "s3cret")
	}

	f.setBranchID("br-10")
	f.setPassword("moved")
	r.InvalidatePassword(testNeonHost, testNeonRole, testNeonDatabase)

	got, err = r.ResolvePassword(context.Background(), testNeonHost, testNeonRole, testNeonDatabase)
	if err != nil {
		t.Fatalf("ResolvePassword() after branch move error = %v", err)
	}
	if got != "moved" {
		t.Errorf("ResolvePassword() after branch move = %q, want %q", got, "moved")
	}
}

func TestNeonResolverUnknownEndpoint(t *testing.T) {
	f := newFakeNeonAPI(t)
	r := newTestNeonResolver(f, testNeonAPIKey)

	_, err := r.ResolvePassword(context.Background(), "ep-unknown-endpoint-000000.us-east-2.aws.neon.tech", testNeonRole, testNeonDatabase)
	if err == nil {
		t.Fatal("ResolvePassword() with unknown endpoint succeeded, want error")
	}
	if !strings.Contains(err.Error(), "ep-unknown-endpoint-000000") {
		t.Errorf("error %q does not name the endpoint ID", err)
	}
}

// A project-scoped Neon API key cannot list projects. When the resolver is
// told the project ID, it must query that project directly and never hit the
// /projects enumeration endpoint.
func TestNeonResolverProjectScoped(t *testing.T) {
	f := newFakeNeonAPI(t)
	f.projectScoped = true
	r := newTestNeonResolver(f, testNeonAPIKey)
	r.Project = "proj-2"

	got, err := r.ResolvePassword(context.Background(), testNeonHost, testNeonRole, testNeonDatabase)
	if err != nil {
		t.Fatalf("ResolvePassword() error = %v", err)
	}
	if got != "s3cret" {
		t.Errorf("ResolvePassword() = %q, want %q", got, "s3cret")
	}
	if calls := f.projectsCalls.Load(); calls != 0 {
		t.Errorf("projects enumeration calls = %d, want 0 (enumeration must be skipped)", calls)
	}
}

func TestNeonResolverProjectScopedEndpointNotFound(t *testing.T) {
	f := newFakeNeonAPI(t)
	f.projectScoped = true
	r := newTestNeonResolver(f, testNeonAPIKey)
	r.Project = "proj-1" // proj-1 does not own the test endpoint

	_, err := r.ResolvePassword(context.Background(), testNeonHost, testNeonRole, testNeonDatabase)
	if err == nil {
		t.Fatal("ResolvePassword() with endpoint absent from project succeeded, want error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "ep-cool-darkness-123456") {
		t.Errorf("error %q does not name the endpoint ID", msg)
	}
	if strings.Contains(msg, "s3cret") {
		t.Errorf("error %q contains the password", msg)
	}
	if strings.Contains(msg, testNeonAPIKey) {
		t.Errorf("error %q contains the API key", msg)
	}
	if calls := f.projectsCalls.Load(); calls != 0 {
		t.Errorf("projects enumeration calls = %d, want 0 (enumeration must be skipped)", calls)
	}
}

func TestNeonResolverMixedCaseHost(t *testing.T) {
	f := newFakeNeonAPI(t)
	r := newTestNeonResolver(f, testNeonAPIKey)

	got, err := r.ResolvePassword(context.Background(), "EP-COOL-DARKNESS-123456.US-EAST-2.aws.neon.tech", testNeonRole, testNeonDatabase)
	if err != nil {
		t.Fatalf("ResolvePassword() with mixed-case host error = %v", err)
	}
	if got != "s3cret" {
		t.Errorf("ResolvePassword() = %q, want %q", got, "s3cret")
	}
}

func TestNeonResolverBadAPIKey(t *testing.T) {
	f := newFakeNeonAPI(t)
	r := newTestNeonResolver(f, "wrong-api-key")

	_, err := r.ResolvePassword(context.Background(), testNeonHost, testNeonRole, testNeonDatabase)
	if err == nil {
		t.Fatal("ResolvePassword() with bad API key succeeded, want error")
	}
	msg := err.Error()
	if strings.Contains(msg, "wrong-api-key") {
		t.Errorf("error %q contains the API key", msg)
	}
	if strings.Contains(msg, "s3cret") {
		t.Errorf("error %q contains the password", msg)
	}
	if !strings.Contains(msg, "401") {
		t.Errorf("error %q does not mention status 401", msg)
	}
}
