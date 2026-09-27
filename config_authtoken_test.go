package gatekeeper

// config_authtoken_test.go tests resolveProxyAuthToken, the pure function
// that resolves proxy.auth_token from either a literal config value or an
// environment variable named by proxy.auth_token_env.

import (
	"strings"
	"testing"
)

func TestResolveProxyAuthToken_NeitherSetReturnsEmpty(t *testing.T) {
	token, err := resolveProxyAuthToken(ProxyConfig{})
	if err != nil {
		t.Fatalf("resolveProxyAuthToken: %v", err)
	}
	if token != "" {
		t.Errorf("token = %q, want empty (no auth required)", token)
	}
}

func TestResolveProxyAuthToken_LiteralOnlyUnchanged(t *testing.T) {
	token, err := resolveProxyAuthToken(ProxyConfig{AuthToken: "literal-token"})
	if err != nil {
		t.Fatalf("resolveProxyAuthToken: %v", err)
	}
	if token != "literal-token" {
		t.Errorf("token = %q, want %q", token, "literal-token")
	}
}

func TestResolveProxyAuthToken_EnvOnlyReadsVariable(t *testing.T) {
	t.Setenv("GK_TEST_PROXY_AUTH_TOKEN", "env-token")

	token, err := resolveProxyAuthToken(ProxyConfig{AuthTokenEnv: "GK_TEST_PROXY_AUTH_TOKEN"})
	if err != nil {
		t.Fatalf("resolveProxyAuthToken: %v", err)
	}
	if token != "env-token" {
		t.Errorf("token = %q, want %q", token, "env-token")
	}
}

func TestResolveProxyAuthToken_BothSetErrors(t *testing.T) {
	t.Setenv("GK_TEST_PROXY_AUTH_TOKEN_BOTH", "env-token")

	_, err := resolveProxyAuthToken(ProxyConfig{
		AuthToken:    "literal-token",
		AuthTokenEnv: "GK_TEST_PROXY_AUTH_TOKEN_BOTH",
	})
	if err == nil {
		t.Fatal("resolveProxyAuthToken: expected error when auth_token and auth_token_env are both set, got nil")
	}
	if !strings.Contains(err.Error(), "auth_token") || !strings.Contains(err.Error(), "auth_token_env") {
		t.Errorf("error = %q, want it to name both 'auth_token' and 'auth_token_env'", err)
	}
	if strings.Contains(err.Error(), "literal-token") || strings.Contains(err.Error(), "env-token") {
		t.Errorf("error = %q, must never contain a token value", err)
	}
}

func TestResolveProxyAuthToken_EnvVarMissingErrors(t *testing.T) {
	const varName = "GK_TEST_PROXY_AUTH_TOKEN_MISSING"

	_, err := resolveProxyAuthToken(ProxyConfig{AuthTokenEnv: varName})
	if err == nil {
		t.Fatal("resolveProxyAuthToken: expected error for a missing env var, got nil")
	}
	if !strings.Contains(err.Error(), varName) {
		t.Errorf("error = %q, want it to name the variable %q", err, varName)
	}
}

func TestResolveProxyAuthToken_EnvVarEmptyErrors(t *testing.T) {
	t.Setenv("GK_TEST_PROXY_AUTH_TOKEN_EMPTY", "")

	_, err := resolveProxyAuthToken(ProxyConfig{AuthTokenEnv: "GK_TEST_PROXY_AUTH_TOKEN_EMPTY"})
	if err == nil {
		t.Fatal("resolveProxyAuthToken: expected error for empty env var, got nil")
	}
	if !strings.Contains(err.Error(), "GK_TEST_PROXY_AUTH_TOKEN_EMPTY") {
		t.Errorf("error = %q, want it to name the variable", err)
	}
}

func TestResolveProxyAuthToken_ExtraneousFieldsRejected(t *testing.T) {
	tests := []struct {
		name string
		cfg  ProxyConfig
	}{
		{"auth_token and auth_token_env both set", ProxyConfig{AuthToken: "a", AuthTokenEnv: "B"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := resolveProxyAuthToken(tt.cfg); err == nil {
				t.Errorf("resolveProxyAuthToken(%+v): expected error, got nil", tt.cfg)
			}
		})
	}
}
