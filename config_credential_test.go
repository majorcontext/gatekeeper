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
		{"env with subject_from", SourceConfig{Type: "env", Var: "X", SubjectFrom: "proxy-auth"}},
		{"static with subject_from", SourceConfig{Type: "static", Value: "v", SubjectFrom: "proxy-auth"}},
		{"aws with subject_from", SourceConfig{Type: "aws-secretsmanager", Secret: "s", SubjectFrom: "proxy-auth"}},
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
		{"with subject_from", SourceConfig{Type: "github-app", AppID: "1", InstallationID: "2", PrivateKeyEnv: "X", SubjectFrom: "proxy-auth"}},
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

func TestResolveSourceTokenExchangeMissingEndpoint(t *testing.T) {
	_, _, err := ResolveCredentialSource(CredentialConfig{
		Host: "api.github.com",
		Source: SourceConfig{
			Type:            "token-exchange",
			ClientID:        "gk",
			ClientSecretEnv: "SECRET",
			SubjectHeader:   "X-Subject",
			Resource:        "https://api.github.com",
		},
	})
	if err == nil {
		t.Fatal("expected error for missing endpoint")
	}
}

func TestResolveSourceTokenExchangeMissingClientID(t *testing.T) {
	_, _, err := ResolveCredentialSource(CredentialConfig{
		Host: "api.github.com",
		Source: SourceConfig{
			Type:            "token-exchange",
			Endpoint:        "https://sts.example.com/token",
			ClientSecretEnv: "SECRET",
			SubjectHeader:   "X-Subject",
		},
	})
	if err == nil {
		t.Fatal("expected error for missing client_id")
	}
}

func TestResolveSourceTokenExchangeNoSecret(t *testing.T) {
	_, _, err := ResolveCredentialSource(CredentialConfig{
		Host: "api.github.com",
		Source: SourceConfig{
			Type:          "token-exchange",
			Endpoint:      "https://sts.example.com/token",
			ClientID:      "gk",
			SubjectHeader: "X-Subject",
		},
	})
	if err == nil {
		t.Fatal("expected error when neither client_secret nor client_secret_env is set")
	}
}

func TestResolveSourceTokenExchangeValid(t *testing.T) {
	t.Setenv("TEST_TE_SECRET", "my-secret")
	_, resolver, err := ResolveCredentialSource(CredentialConfig{
		Host: "api.github.com",
		Source: SourceConfig{
			Type:            "token-exchange",
			Endpoint:        "https://sts.example.com/token",
			ClientID:        "gk",
			ClientSecretEnv: "TEST_TE_SECRET",
			SubjectHeader:   "X-Gatekeeper-Subject",
			Resource:        "https://api.github.com",
		},
		Grant: "github",
	})
	if err != nil {
		t.Fatalf("ResolveCredentialSource: %v", err)
	}
	if resolver == nil {
		t.Fatal("expected non-nil resolver for token-exchange type")
	}
}

func TestResolveSourceTokenExchangeSubjectFromProxyAuth(t *testing.T) {
	t.Setenv("TEST_TE_SECRET_PXA", "s")
	_, resolver, err := ResolveCredentialSource(CredentialConfig{
		Host: "api.github.com",
		Source: SourceConfig{
			Type:            "token-exchange",
			Endpoint:        "https://sts.example.com/token",
			ClientID:        "gk",
			ClientSecretEnv: "TEST_TE_SECRET_PXA",
			SubjectFrom:     "proxy-auth",
			Resource:        "https://api.github.com",
		},
		Grant: "github",
	})
	if err != nil {
		t.Fatalf("ResolveCredentialSource: %v", err)
	}
	if resolver == nil {
		t.Fatal("expected non-nil resolver for token-exchange with subject_from")
	}
}

func TestResolveSourceTokenExchangeSubjectFromAndHeaderConflict(t *testing.T) {
	t.Setenv("TEST_TE_SECRET_CONFLICT", "s")
	_, _, err := ResolveCredentialSource(CredentialConfig{
		Host: "api.github.com",
		Source: SourceConfig{
			Type:            "token-exchange",
			Endpoint:        "https://sts.example.com/token",
			ClientID:        "gk",
			ClientSecretEnv: "TEST_TE_SECRET_CONFLICT",
			SubjectHeader:   "X-Subject",
			SubjectFrom:     "proxy-auth",
		},
	})
	if err == nil {
		t.Fatal("expected error when both subject_header and subject_from are set")
	}
}

func TestResolveSourceTokenExchangeSubjectFromInvalid(t *testing.T) {
	t.Setenv("TEST_TE_SECRET_INVALID", "s")
	_, _, err := ResolveCredentialSource(CredentialConfig{
		Host: "api.github.com",
		Source: SourceConfig{
			Type:            "token-exchange",
			Endpoint:        "https://sts.example.com/token",
			ClientID:        "gk",
			ClientSecretEnv: "TEST_TE_SECRET_INVALID",
			SubjectFrom:     "magic-header",
		},
	})
	if err == nil {
		t.Fatal("expected error for unsupported subject_from value")
	}
}

func TestResolveSourceTokenExchangeNoSubjectSource(t *testing.T) {
	t.Setenv("TEST_TE_SECRET_NOSRC", "s")
	_, _, err := ResolveCredentialSource(CredentialConfig{
		Host: "api.github.com",
		Source: SourceConfig{
			Type:            "token-exchange",
			Endpoint:        "https://sts.example.com/token",
			ClientID:        "gk",
			ClientSecretEnv: "TEST_TE_SECRET_NOSRC",
		},
	})
	if err == nil {
		t.Fatal("expected error when neither subject_header nor subject_from is set")
	}
}

func TestResolveSourceTokenExchangeExtraneousFields(t *testing.T) {
	t.Setenv("TEST_TE_SECRET2", "s")
	tests := []struct {
		name string
		cfg  SourceConfig
	}{
		{"with var", SourceConfig{Type: "token-exchange", Endpoint: "http://x", ClientID: "gk", ClientSecretEnv: "TEST_TE_SECRET2", SubjectHeader: "X-S", Var: "extra"}},
		{"with value", SourceConfig{Type: "token-exchange", Endpoint: "http://x", ClientID: "gk", ClientSecretEnv: "TEST_TE_SECRET2", SubjectHeader: "X-S", Value: "extra"}},
		{"with secret", SourceConfig{Type: "token-exchange", Endpoint: "http://x", ClientID: "gk", ClientSecretEnv: "TEST_TE_SECRET2", SubjectHeader: "X-S", Secret: "extra"}},
		{"with region", SourceConfig{Type: "token-exchange", Endpoint: "http://x", ClientID: "gk", ClientSecretEnv: "TEST_TE_SECRET2", SubjectHeader: "X-S", Region: "extra"}},
		{"with app_id", SourceConfig{Type: "token-exchange", Endpoint: "http://x", ClientID: "gk", ClientSecretEnv: "TEST_TE_SECRET2", SubjectHeader: "X-S", AppID: "extra"}},
		{"with installation_id", SourceConfig{Type: "token-exchange", Endpoint: "http://x", ClientID: "gk", ClientSecretEnv: "TEST_TE_SECRET2", SubjectHeader: "X-S", InstallationID: "extra"}},
		{"with private_key_path", SourceConfig{Type: "token-exchange", Endpoint: "http://x", ClientID: "gk", ClientSecretEnv: "TEST_TE_SECRET2", SubjectHeader: "X-S", PrivateKeyPath: "extra"}},
		{"with private_key_env", SourceConfig{Type: "token-exchange", Endpoint: "http://x", ClientID: "gk", ClientSecretEnv: "TEST_TE_SECRET2", SubjectHeader: "X-S", PrivateKeyEnv: "extra"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ResolveCredentialSource(CredentialConfig{
				Host:   "api.github.com",
				Source: tt.cfg,
			})
			if err == nil {
				t.Fatal("expected error for extraneous fields")
			}
		})
	}
}
