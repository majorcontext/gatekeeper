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
	t        *testing.T
	server   *httptest.Server
	uriCalls atomic.Int64

	mu       sync.Mutex
	password string
}

func newFakeNeonAPI(t *testing.T) *fakeNeonAPI {
	f := &fakeNeonAPI{t: t, password: "s3cret"}
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

func (f *fakeNeonAPI) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+testNeonAPIKey {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"message":"authorization failed"}`)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/api/v2/projects":
		fmt.Fprint(w, `{"projects":[{"id":"proj-1"},{"id":"proj-2"}]}`)
	case "/api/v2/projects/proj-1/endpoints":
		fmt.Fprint(w, `{"endpoints":[{"id":"ep-other-endpoint-999999","branch_id":"br-1"}]}`)
	case "/api/v2/projects/proj-2/endpoints":
		fmt.Fprint(w, `{"endpoints":[{"id":"ep-cool-darkness-123456","branch_id":"br-9"}]}`)
	case "/api/v2/projects/proj-2/connection_uri":
		f.uriCalls.Add(1)
		q := r.URL.Query()
		if got := q.Get("branch_id"); got != "br-9" {
			f.t.Errorf("connection_uri branch_id = %q, want %q", got, "br-9")
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
