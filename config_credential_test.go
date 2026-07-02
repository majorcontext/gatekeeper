package gatekeeper

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestResolveSourceGCPMissingSecret(t *testing.T) {
	_, err := ResolveSource(SourceConfig{Type: "gcp-secretmanager", Project: "my-project"})
	if err == nil {
		t.Fatal("expected error for missing secret field, got nil")
	}
}

func TestResolveSourceGCPMissingProject(t *testing.T) {
	_, err := ResolveSource(SourceConfig{Type: "gcp-secretmanager", Secret: "my-secret"})
	if err == nil {
		t.Fatal("expected error for missing project field, got nil")
	}
}

func TestResolveSourceGCPExtraneousFields(t *testing.T) {
	tests := []struct {
		name string
		cfg  SourceConfig
	}{
		{"with var", SourceConfig{Type: "gcp-secretmanager", Secret: "s", Project: "p", Var: "extra"}},
		{"with value", SourceConfig{Type: "gcp-secretmanager", Secret: "s", Project: "p", Value: "extra"}},
		{"with region", SourceConfig{Type: "gcp-secretmanager", Secret: "s", Project: "p", Region: "extra"}},
		{"with app_id", SourceConfig{Type: "gcp-secretmanager", Secret: "s", Project: "p", AppID: "extra"}},
		{"with installation_id", SourceConfig{Type: "gcp-secretmanager", Secret: "s", Project: "p", InstallationID: "extra"}},
		{"with private_key_path", SourceConfig{Type: "gcp-secretmanager", Secret: "s", Project: "p", PrivateKeyPath: "extra"}},
		{"with private_key_env", SourceConfig{Type: "gcp-secretmanager", Secret: "s", Project: "p", PrivateKeyEnv: "extra"}},
		{"with endpoint", SourceConfig{Type: "gcp-secretmanager", Secret: "s", Project: "p", Endpoint: "extra"}},
		{"with client_id", SourceConfig{Type: "gcp-secretmanager", Secret: "s", Project: "p", ClientID: "extra"}},
		{"with subject_from", SourceConfig{Type: "gcp-secretmanager", Secret: "s", Project: "p", SubjectFrom: "proxy-auth"}},
		{"with actor_token_from", SourceConfig{Type: "gcp-secretmanager", Secret: "s", Project: "p", ActorTokenFrom: "proxy-auth-password"}},
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

func TestResolveSourceExtraneousFields(t *testing.T) {
	tests := []struct {
		name string
		cfg  SourceConfig
	}{
		{"env with value", SourceConfig{Type: "env", Var: "X", Value: "extra"}},
		{"env with secret", SourceConfig{Type: "env", Var: "X", Secret: "extra"}},
		{"env with region", SourceConfig{Type: "env", Var: "X", Region: "extra"}},
		{"static with region", SourceConfig{Type: "static", Value: "v", Region: "extra"}},
		{"env with app_id", SourceConfig{Type: "env", Var: "X", AppID: "extra"}},
		{"env with project", SourceConfig{Type: "env", Var: "X", Project: "extra"}},
		{"env with version", SourceConfig{Type: "env", Var: "X", Version: "extra"}},
		{"static with var", SourceConfig{Type: "static", Value: "v", Var: "extra"}},
		{"static with secret", SourceConfig{Type: "static", Value: "v", Secret: "extra"}},
		{"static with app_id", SourceConfig{Type: "static", Value: "v", AppID: "extra"}},
		{"static with project", SourceConfig{Type: "static", Value: "v", Project: "extra"}},
		{"static with version", SourceConfig{Type: "static", Value: "v", Version: "extra"}},
		{"aws with var", SourceConfig{Type: "aws-secretsmanager", Secret: "s", Var: "extra"}},
		{"aws with value", SourceConfig{Type: "aws-secretsmanager", Secret: "s", Value: "extra"}},
		{"aws with app_id", SourceConfig{Type: "aws-secretsmanager", Secret: "s", AppID: "extra"}},
		{"aws with project", SourceConfig{Type: "aws-secretsmanager", Secret: "s", Project: "extra"}},
		{"aws with version", SourceConfig{Type: "aws-secretsmanager", Secret: "s", Version: "extra"}},
		{"env with subject_from", SourceConfig{Type: "env", Var: "X", SubjectFrom: "proxy-auth"}},
		{"env with actor_token_from", SourceConfig{Type: "env", Var: "X", ActorTokenFrom: "proxy-auth-password"}},
		{"env with actor_token_type", SourceConfig{Type: "env", Var: "X", ActorTokenType: "urn:ietf:params:oauth:token-type:jwt"}},
		{"static with subject_from", SourceConfig{Type: "static", Value: "v", SubjectFrom: "proxy-auth"}},
		{"static with actor_token_from", SourceConfig{Type: "static", Value: "v", ActorTokenFrom: "proxy-auth-password"}},
		{"static with actor_token_type", SourceConfig{Type: "static", Value: "v", ActorTokenType: "urn:ietf:params:oauth:token-type:jwt"}},
		{"aws with subject_from", SourceConfig{Type: "aws-secretsmanager", Secret: "s", SubjectFrom: "proxy-auth"}},
		{"aws with actor_token_from", SourceConfig{Type: "aws-secretsmanager", Secret: "s", ActorTokenFrom: "proxy-auth-password"}},
		{"aws with actor_token_type", SourceConfig{Type: "aws-secretsmanager", Secret: "s", ActorTokenType: "urn:ietf:params:oauth:token-type:jwt"}},
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
		{"with actor_token_from", SourceConfig{Type: "github-app", AppID: "1", InstallationID: "2", PrivateKeyEnv: "X", ActorTokenFrom: "proxy-auth-password"}},
		{"with actor_token_type", SourceConfig{Type: "github-app", AppID: "1", InstallationID: "2", PrivateKeyEnv: "X", ActorTokenType: "urn:ietf:params:oauth:token-type:jwt"}},
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

// testGCPSAKeyJSON builds a GCP service account key JSON with a freshly
// generated RSA key, mirroring the real key file format.
func testGCPSAKeyJSON(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	b, err := json.Marshal(map[string]string{
		"type":         "service_account",
		"client_email": "uploader@my-project.iam.gserviceaccount.com",
		"private_key":  string(keyPEM),
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestResolveSourceGCPServiceAccount(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "sa.json")
	if err := os.WriteFile(keyFile, testGCPSAKeyJSON(t), 0600); err != nil {
		t.Fatal(err)
	}

	src, err := ResolveSource(SourceConfig{
		Type:           "gcp-service-account",
		PrivateKeyPath: keyFile,
		Scopes:         "https://www.googleapis.com/auth/devstorage.read_write",
	})
	if err != nil {
		t.Fatalf("ResolveSource: %v", err)
	}
	if src.Type() != "gcp-service-account" {
		t.Errorf("Type() = %q, want gcp-service-account", src.Type())
	}
}

func TestResolveSourceGCPServiceAccountFromEnv(t *testing.T) {
	t.Setenv("TEST_GCP_SA_KEY", string(testGCPSAKeyJSON(t)))

	src, err := ResolveSource(SourceConfig{
		Type:          "gcp-service-account",
		PrivateKeyEnv: "TEST_GCP_SA_KEY",
	})
	if err != nil {
		t.Fatalf("ResolveSource: %v", err)
	}
	if src.Type() != "gcp-service-account" {
		t.Errorf("Type() = %q, want gcp-service-account", src.Type())
	}
}

func TestResolveSourceGCPServiceAccountNoKey(t *testing.T) {
	_, err := ResolveSource(SourceConfig{Type: "gcp-service-account"})
	if err == nil {
		t.Fatal("expected error when no key location is set")
	}
}

func TestResolveSourceGCPServiceAccountMultipleKeyLocations(t *testing.T) {
	tests := []struct {
		name string
		cfg  SourceConfig
	}{
		{"path and env", SourceConfig{Type: "gcp-service-account", PrivateKeyPath: "/p", PrivateKeyEnv: "E"}},
		{"path and secret", SourceConfig{Type: "gcp-service-account", PrivateKeyPath: "/p", Secret: "s", Project: "pr"}},
		{"env and secret", SourceConfig{Type: "gcp-service-account", PrivateKeyEnv: "E", Secret: "s", Project: "pr"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ResolveSource(tt.cfg)
			if err == nil {
				t.Fatal("expected error for multiple key locations")
			}
		})
	}
}

func TestResolveSourceGCPServiceAccountSecretWithoutProject(t *testing.T) {
	_, err := ResolveSource(SourceConfig{Type: "gcp-service-account", Secret: "s"})
	if err == nil {
		t.Fatal("expected error for secret without project")
	}
}

func TestResolveSourceGCPServiceAccountProjectWithoutSecret(t *testing.T) {
	_, err := ResolveSource(SourceConfig{Type: "gcp-service-account", PrivateKeyEnv: "E", Project: "pr"})
	if err == nil {
		t.Fatal("expected error for project without secret")
	}
}

func TestResolveSourceGCPServiceAccountExtraneousFields(t *testing.T) {
	tests := []struct {
		name string
		cfg  SourceConfig
	}{
		{"with var", SourceConfig{Type: "gcp-service-account", PrivateKeyEnv: "X", Var: "extra"}},
		{"with value", SourceConfig{Type: "gcp-service-account", PrivateKeyEnv: "X", Value: "extra"}},
		{"with region", SourceConfig{Type: "gcp-service-account", PrivateKeyEnv: "X", Region: "extra"}},
		{"with app_id", SourceConfig{Type: "gcp-service-account", PrivateKeyEnv: "X", AppID: "extra"}},
		{"with installation_id", SourceConfig{Type: "gcp-service-account", PrivateKeyEnv: "X", InstallationID: "extra"}},
		{"with endpoint", SourceConfig{Type: "gcp-service-account", PrivateKeyEnv: "X", Endpoint: "extra"}},
		{"with client_id", SourceConfig{Type: "gcp-service-account", PrivateKeyEnv: "X", ClientID: "extra"}},
		{"with subject_from", SourceConfig{Type: "gcp-service-account", PrivateKeyEnv: "X", SubjectFrom: "proxy-auth"}},
		{"with actor_token_from", SourceConfig{Type: "gcp-service-account", PrivateKeyEnv: "X", ActorTokenFrom: "proxy-auth-password"}},
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

func TestResolveSourceScopesExtraneousOnOtherTypes(t *testing.T) {
	tests := []struct {
		name string
		cfg  SourceConfig
	}{
		{"env with scopes", SourceConfig{Type: "env", Var: "X", Scopes: "extra"}},
		{"static with scopes", SourceConfig{Type: "static", Value: "v", Scopes: "extra"}},
		{"aws with scopes", SourceConfig{Type: "aws-secretsmanager", Secret: "s", Scopes: "extra"}},
		{"gcp-secretmanager with scopes", SourceConfig{Type: "gcp-secretmanager", Secret: "s", Project: "p", Scopes: "extra"}},
		{"github-app with scopes", SourceConfig{Type: "github-app", AppID: "1", InstallationID: "2", PrivateKeyEnv: "X", Scopes: "extra"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ResolveSource(tt.cfg)
			if err == nil {
				t.Fatal("expected error for extraneous scopes field")
			}
		})
	}
}

func TestResolveSourceTokenExchangeScopesExtraneous(t *testing.T) {
	_, _, err := ResolveCredentialSource(CredentialConfig{
		Host: "api.github.com",
		Source: SourceConfig{
			Type:          "token-exchange",
			Endpoint:      "https://sts.example.com/token",
			ClientID:      "gk",
			ClientSecret:  "s",
			SubjectHeader: "X-Subject",
			Scopes:        "extra",
		},
	})
	if err == nil {
		t.Fatal("expected error for extraneous scopes field on token-exchange")
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
		{"with command", SourceConfig{Type: "token-exchange", Endpoint: "http://x", ClientID: "gk", ClientSecretEnv: "TEST_TE_SECRET2", SubjectHeader: "X-S", Command: "extra"}},
		{"with ttl", SourceConfig{Type: "token-exchange", Endpoint: "http://x", ClientID: "gk", ClientSecretEnv: "TEST_TE_SECRET2", SubjectHeader: "X-S", TTL: "90s"}},
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

func TestResolveSourceProcess(t *testing.T) {
	src, err := ResolveSource(SourceConfig{Type: "process", Command: "printf 'proc-token'"})
	if err != nil {
		t.Fatalf("ResolveSource() error: %v", err)
	}
	if src.Type() != "process" {
		t.Fatalf("Type() = %q, want %q", src.Type(), "process")
	}
	val, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}
	if val != "proc-token" {
		t.Fatalf("Fetch() = %q, want %q", val, "proc-token")
	}
}

func TestResolveSourceProcessTTL(t *testing.T) {
	src, err := ResolveSource(SourceConfig{Type: "process", Command: "printf 'proc-token'", TTL: "90s"})
	if err != nil {
		t.Fatalf("ResolveSource() error: %v", err)
	}
	if _, err := src.Fetch(context.Background()); err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}
	rs, ok := src.(interface{ TTL() time.Duration })
	if !ok {
		t.Fatal("process source should implement RefreshingSource")
	}
	if got := rs.TTL(); got != 90*time.Second {
		t.Fatalf("TTL() = %v, want configured 90s", got)
	}
}

func TestResolveSourceProcessInvalidTTL(t *testing.T) {
	for _, ttl := range []string{"banana", "-5s", "0s"} {
		t.Run(ttl, func(t *testing.T) {
			_, err := ResolveSource(SourceConfig{Type: "process", Command: "printf x", TTL: ttl})
			if err == nil {
				t.Fatalf("expected error for ttl %q, got nil", ttl)
			}
			if !strings.Contains(err.Error(), "ttl") {
				t.Fatalf("error should mention ttl, got: %v", err)
			}
		})
	}
}

func TestResolveSourceEnvRejectsTTLField(t *testing.T) {
	_, err := ResolveSource(SourceConfig{Type: "env", Var: "SOME_VAR", TTL: "90s"})
	if err == nil {
		t.Fatal("expected error: env source must reject the process-only ttl field")
	}
}

func TestResolveSourceProcessMissingCommand(t *testing.T) {
	_, err := ResolveSource(SourceConfig{Type: "process"})
	if err == nil {
		t.Fatal("expected error for missing command field, got nil")
	}
}

func TestResolveSourceProcessExtraneousField(t *testing.T) {
	_, err := ResolveSource(SourceConfig{Type: "process", Command: "printf x", Var: "SOME_VAR"})
	if err == nil {
		t.Fatal("expected error for extraneous field on process source, got nil")
	}
}

func TestResolveSourceEnvRejectsCommandField(t *testing.T) {
	_, err := ResolveSource(SourceConfig{Type: "env", Var: "SOME_VAR", Command: "printf x"})
	if err == nil {
		t.Fatal("expected error: env source must reject the process-only command field")
	}
}
