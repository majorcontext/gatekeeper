package gatekeeper

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveSourceEnv(t *testing.T) {
	const key = "MOAT_TEST_RESOLVE_ENV"
	t.Setenv(key, "token-abc")

	src, err := ResolveSource(SourceConfig{Type: "env", Var: key})
	if err != nil {
		t.Fatalf("ResolveSource() error: %v", err)
	}
	if src.Type() != "env" {
		t.Fatalf("Type() = %q, want %q", src.Type(), "env")
	}
	val, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}
	if val != "token-abc" {
		t.Fatalf("Fetch() = %q, want %q", val, "token-abc")
	}
}

func TestResolveSourceEnvMissingVar(t *testing.T) {
	_, err := ResolveSource(SourceConfig{Type: "env"})
	if err == nil {
		t.Fatal("expected error for missing var field, got nil")
	}
}

func TestResolveSourceStatic(t *testing.T) {
	src, err := ResolveSource(SourceConfig{Type: "static", Value: "my-key"})
	if err != nil {
		t.Fatalf("ResolveSource() error: %v", err)
	}
	if src.Type() != "static" {
		t.Fatalf("Type() = %q, want %q", src.Type(), "static")
	}
	val, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}
	if val != "my-key" {
		t.Fatalf("Fetch() = %q, want %q", val, "my-key")
	}
}

func TestResolveSourceStaticEmptyValue(t *testing.T) {
	_, err := ResolveSource(SourceConfig{Type: "static"})
	if err == nil {
		t.Fatal("expected error for empty static value, got nil")
	}
}

func TestResolveSourceUnknown(t *testing.T) {
	_, err := ResolveSource(SourceConfig{Type: "vault"})
	if err == nil {
		t.Fatal("expected error for unknown type, got nil")
	}
}

func TestResolveSourceAWSMissingSecret(t *testing.T) {
	_, err := ResolveSource(SourceConfig{Type: "aws-secretsmanager"})
	if err == nil {
		t.Fatal("expected error for missing secret field, got nil")
	}
}

func TestResolveSourceExtraneousFields(t *testing.T) {
	tests := []struct {
		name string
		cfg  SourceConfig
	}{
		{"env with value", SourceConfig{Type: "env", Var: "X", Value: "extra"}},
		{"env with secret", SourceConfig{Type: "env", Var: "X", Secret: "extra"}},
		{"env with app_id", SourceConfig{Type: "env", Var: "X", AppID: "extra"}},
		{"static with var", SourceConfig{Type: "static", Value: "v", Var: "extra"}},
		{"static with secret", SourceConfig{Type: "static", Value: "v", Secret: "extra"}},
		{"static with app_id", SourceConfig{Type: "static", Value: "v", AppID: "extra"}},
		{"aws with var", SourceConfig{Type: "aws-secretsmanager", Secret: "s", Var: "extra"}},
		{"aws with value", SourceConfig{Type: "aws-secretsmanager", Secret: "s", Value: "extra"}},
		{"aws with app_id", SourceConfig{Type: "aws-secretsmanager", Secret: "s", AppID: "extra"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ResolveSource(tt.cfg)
			if err == nil {
				t.Fatal("expected error for extraneous fields")
			}
		})
	}
}

func TestResolveSourceGitHubApp(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	keyFile := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}

	src, err := ResolveSource(SourceConfig{
		Type:           "github-app",
		AppID:          "12345",
		InstallationID: "67890",
		PrivateKeyPath: keyFile,
	})
	if err != nil {
		t.Fatalf("ResolveSource: %v", err)
	}
	if src.Type() != "github-app" {
		t.Errorf("Type() = %q, want github-app", src.Type())
	}
}

func TestResolveSourceGitHubAppFromEnv(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	t.Setenv("TEST_GH_APP_KEY", string(keyPEM))

	src, err := ResolveSource(SourceConfig{
		Type:           "github-app",
		AppID:          "12345",
		InstallationID: "67890",
		PrivateKeyEnv:  "TEST_GH_APP_KEY",
	})
	if err != nil {
		t.Fatalf("ResolveSource: %v", err)
	}
	if src.Type() != "github-app" {
		t.Errorf("Type() = %q, want github-app", src.Type())
	}
}

func TestResolveSourceGitHubAppMissingAppID(t *testing.T) {
	_, err := ResolveSource(SourceConfig{
		Type:           "github-app",
		InstallationID: "67890",
		PrivateKeyEnv:  "X",
	})
	if err == nil {
		t.Fatal("expected error for missing app_id")
	}
}

func TestResolveSourceGitHubAppMissingInstallationID(t *testing.T) {
	_, err := ResolveSource(SourceConfig{
		Type:          "github-app",
		AppID:         "12345",
		PrivateKeyEnv: "X",
	})
	if err == nil {
		t.Fatal("expected error for missing installation_id")
	}
}

func TestResolveSourceGitHubAppNoKey(t *testing.T) {
	_, err := ResolveSource(SourceConfig{
		Type:           "github-app",
		AppID:          "12345",
		InstallationID: "67890",
	})
	if err == nil {
		t.Fatal("expected error when neither private_key_path nor private_key_env is set")
	}
}

func TestResolveSourceGitHubAppBothKeys(t *testing.T) {
	_, err := ResolveSource(SourceConfig{
		Type:           "github-app",
		AppID:          "12345",
		InstallationID: "67890",
		PrivateKeyPath: "/some/path",
		PrivateKeyEnv:  "SOME_VAR",
	})
	if err == nil {
		t.Fatal("expected error when both private_key_path and private_key_env are set")
	}
}

func TestResolveSourceGitHubAppExtraneousFields(t *testing.T) {
	tests := []struct {
		name string
		cfg  SourceConfig
	}{
		{"with var", SourceConfig{Type: "github-app", AppID: "1", InstallationID: "2", PrivateKeyEnv: "X", Var: "extra"}},
		{"with value", SourceConfig{Type: "github-app", AppID: "1", InstallationID: "2", PrivateKeyEnv: "X", Value: "extra"}},
		{"with secret", SourceConfig{Type: "github-app", AppID: "1", InstallationID: "2", PrivateKeyEnv: "X", Secret: "extra"}},
		{"with region", SourceConfig{Type: "github-app", AppID: "1", InstallationID: "2", PrivateKeyEnv: "X", Region: "extra"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ResolveSource(tt.cfg)
			if err == nil {
				t.Fatal("expected error for extraneous fields")
			}
		})
	}
}
