package credentialsource

import (
	"context"
	"fmt"
	"testing"
)

type mockGCPSMClient struct {
	value        string
	err          error
	lastResource string
}

func (m *mockGCPSMClient) AccessSecretVersion(_ context.Context, resourceName string) (string, error) {
	m.lastResource = resourceName
	return m.value, m.err
}

func TestGCPSecretManagerSource(t *testing.T) {
	client := &mockGCPSMClient{value: "gcp-secret-123"}
	src := newGCPSecretManagerSourceWithClient("my-project", "my-secret", "latest", client)

	if src.Type() != "gcp-secretmanager" {
		t.Fatalf("Type() = %q, want %q", src.Type(), "gcp-secretmanager")
	}

	val, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}
	if val != "gcp-secret-123" {
		t.Fatalf("Fetch() = %q, want %q", val, "gcp-secret-123")
	}
	wantResource := "projects/my-project/secrets/my-secret/versions/latest"
	if client.lastResource != wantResource {
		t.Fatalf("resourceName = %q, want %q", client.lastResource, wantResource)
	}
}

func TestGCPSecretManagerSourceError(t *testing.T) {
	client := &mockGCPSMClient{err: fmt.Errorf("permission denied")}
	src := newGCPSecretManagerSourceWithClient("my-project", "my-secret", "latest", client)

	_, err := src.Fetch(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "permission denied" {
		t.Fatalf("error = %q, want %q", err.Error(), "permission denied")
	}
}

func TestGCPSecretManagerSourceDefaultVersion(t *testing.T) {
	client := &mockGCPSMClient{value: "versioned-secret"}
	src := newGCPSecretManagerSourceWithClient("my-project", "my-secret", "", client)

	val, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}
	if val != "versioned-secret" {
		t.Fatalf("Fetch() = %q, want %q", val, "versioned-secret")
	}
	wantResource := "projects/my-project/secrets/my-secret/versions/latest"
	if client.lastResource != wantResource {
		t.Fatalf("resourceName = %q, want %q (empty version should default to latest)", client.lastResource, wantResource)
	}
}

func TestGCPSecretManagerSourceCloseNonCloser(t *testing.T) {
	client := &mockGCPSMClient{value: "v"}
	src := newGCPSecretManagerSourceWithClient("p", "s", "latest", client)

	// Mock doesn't implement io.Closer — Close should be a no-op.
	if err := src.(*gcpSMSource).Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}
}

type mockClosableGCPSMClient struct {
	mockGCPSMClient
	closed bool
}

func (m *mockClosableGCPSMClient) Close() error {
	m.closed = true
	return nil
}

func TestGCPSecretManagerSourceCloseCloser(t *testing.T) {
	client := &mockClosableGCPSMClient{}
	client.value = "v"
	src := newGCPSecretManagerSourceWithClient("p", "s", "latest", client)

	if err := src.(*gcpSMSource).Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}
	if !client.closed {
		t.Fatal("expected Close() to be called on underlying client")
	}
}
