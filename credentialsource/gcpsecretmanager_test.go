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
