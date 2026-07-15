package gatekeeper

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/majorcontext/gatekeeper/proxy"
)

func TestParseConfig_Full(t *testing.T) {
	yaml := `
proxy:
  port: 8080
  host: 127.0.0.1
  proxy_protocol: true
tls:
  ca_cert: /tmp/ca.crt
  ca_key: /tmp/ca.key
credentials:
  - host: api.github.com
    header: Authorization
    grant: github
    source:
      type: env
      var: GITHUB_TOKEN
  - host: api.anthropic.com
    header: x-api-key
    grant: anthropic
    source:
      type: static
      value: sk-ant-123
  - host: api.example.com
    grant: aws-secret
    source:
      type: aws-secretsmanager
      secret: my-secret
      region: us-east-1
network:
  policy: strict
  allow:
    - "*.github.com"
    - api.anthropic.com
log:
  level: debug
  format: json
  output: stderr
`
	cfg, err := ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}

	// Proxy
	if cfg.Proxy.Port != 8080 {
		t.Errorf("Proxy.Port = %d, want 8080", cfg.Proxy.Port)
	}
	if cfg.Proxy.Host != "127.0.0.1" {
		t.Errorf("Proxy.Host = %q, want 127.0.0.1", cfg.Proxy.Host)
	}
	if !cfg.Proxy.ProxyProtocol {
		t.Error("Proxy.ProxyProtocol = false, want true")
	}

	// TLS
	if cfg.TLS.CACert != "/tmp/ca.crt" {
		t.Errorf("TLS.CACert = %q, want /tmp/ca.crt", cfg.TLS.CACert)
	}
	if cfg.TLS.CAKey != "/tmp/ca.key" {
		t.Errorf("TLS.CAKey = %q, want /tmp/ca.key", cfg.TLS.CAKey)
	}

	// Credentials
	if len(cfg.Credentials) != 3 {
		t.Fatalf("len(Credentials) = %d, want 3", len(cfg.Credentials))
	}
	if cfg.Credentials[0].Host != "api.github.com" {
		t.Errorf("Credentials[0].Host = %q, want api.github.com", cfg.Credentials[0].Host)
	}
	if cfg.Credentials[0].Header != "Authorization" {
		t.Errorf("Credentials[0].Header = %q, want Authorization", cfg.Credentials[0].Header)
	}
	if cfg.Credentials[0].Grant != "github" {
		t.Errorf("Credentials[0].Grant = %q, want github", cfg.Credentials[0].Grant)
	}
	if cfg.Credentials[0].Source.Type != "env" {
		t.Errorf("Credentials[0].Source.Type = %q, want env", cfg.Credentials[0].Source.Type)
	}
	if cfg.Credentials[0].Source.Var != "GITHUB_TOKEN" {
		t.Errorf("Credentials[0].Source.Var = %q, want GITHUB_TOKEN", cfg.Credentials[0].Source.Var)
	}
	if cfg.Credentials[1].Host != "api.anthropic.com" {
		t.Errorf("Credentials[1].Host = %q, want api.anthropic.com", cfg.Credentials[1].Host)
	}
	if cfg.Credentials[1].Header != "x-api-key" {
		t.Errorf("Credentials[1].Header = %q, want x-api-key", cfg.Credentials[1].Header)
	}
	if cfg.Credentials[1].Source.Value != "sk-ant-123" {
		t.Errorf("Credentials[1].Source.Value = %q, want sk-ant-123", cfg.Credentials[1].Source.Value)
	}
	if cfg.Credentials[2].Source.Secret != "my-secret" {
		t.Errorf("Credentials[2].Source.Secret = %q, want my-secret", cfg.Credentials[2].Source.Secret)
	}

	// Network
	if cfg.Network.Policy != "strict" {
		t.Errorf("Network.Policy = %q, want strict", cfg.Network.Policy)
	}
	if len(cfg.Network.Allow) != 2 {
		t.Fatalf("len(Network.Allow) = %d, want 2", len(cfg.Network.Allow))
	}
	if cfg.Network.Allow[0] != "*.github.com" {
		t.Errorf("Network.Allow[0] = %q, want *.github.com", cfg.Network.Allow[0])
	}
	// Log
	if cfg.Log.Level != "debug" {
		t.Errorf("Log.Level = %q, want debug", cfg.Log.Level)
	}
	if cfg.Log.Format != "json" {
		t.Errorf("Log.Format = %q, want json", cfg.Log.Format)
	}
}

func TestParseConfig_Minimal(t *testing.T) {
	yaml := `
proxy:
  port: 9090
`
	cfg, err := ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.Proxy.Port != 9090 {
		t.Errorf("Proxy.Port = %d, want 9090", cfg.Proxy.Port)
	}
	if len(cfg.Credentials) != 0 {
		t.Errorf("len(Credentials) = %d, want 0", len(cfg.Credentials))
	}
	if cfg.Proxy.ProxyProtocol {
		t.Error("Proxy.ProxyProtocol = true, want false when absent from config")
	}
	if cfg.Postgres != nil && cfg.Postgres.ProxyProtocol {
		t.Error("Postgres.ProxyProtocol = true, want false when absent from config")
	}
}

func TestParseConfigPostgres(t *testing.T) {
	yamlData := `
proxy:
  port: 8080
postgres:
  port: 5432
  host: 0.0.0.0
  proxy_protocol: true
credentials:
  - host: "*.neon.tech"
    postgres:
      resolver: neon
      project: falling-river-38863773
    source:
      type: env
      var: NEON_API_KEY
    grant: neon-databases
`
	cfg, err := ParseConfig([]byte(yamlData))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.Postgres == nil {
		t.Fatal("Postgres config is nil")
	}
	if cfg.Postgres.Port != 5432 {
		t.Errorf("Port = %d, want 5432", cfg.Postgres.Port)
	}
	if cfg.Postgres.Host != "0.0.0.0" {
		t.Errorf("Host = %q, want 0.0.0.0", cfg.Postgres.Host)
	}
	if !cfg.Postgres.ProxyProtocol {
		t.Error("Postgres.ProxyProtocol = false, want true")
	}
	if len(cfg.Credentials) != 1 {
		t.Fatalf("credentials = %d, want 1", len(cfg.Credentials))
	}
	pg := cfg.Credentials[0].Postgres
	if pg == nil {
		t.Fatal("credential Postgres block is nil")
	}
	if pg.Resolver != "neon" {
		t.Errorf("Resolver = %q, want neon", pg.Resolver)
	}
	if pg.Project != "falling-river-38863773" {
		t.Errorf("Project = %q, want falling-river-38863773", pg.Project)
	}
}

func TestParseConfigNoPostgres(t *testing.T) {
	// A config without a postgres block leaves Config.Postgres nil and
	// credential Postgres nil (regression: pointer fields default to nil).
	yamlData := `
proxy:
  port: 8080
credentials:
  - host: api.github.com
    source:
      type: env
      var: GH_TOKEN
`
	cfg, err := ParseConfig([]byte(yamlData))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.Postgres != nil {
		t.Error("expected nil Postgres config")
	}
	if cfg.Credentials[0].Postgres != nil {
		t.Error("expected nil credential Postgres block")
	}
}

func TestParseConfig_InvalidYAML(t *testing.T) {
	_, err := ParseConfig([]byte(`{{{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	yaml := `
proxy:
  port: 7070
  host: 0.0.0.0
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Proxy.Port != 7070 {
		t.Errorf("Proxy.Port = %d, want 7070", cfg.Proxy.Port)
	}
}

func TestLoadConfig_NotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestParseConfig_CaptureHeaders(t *testing.T) {
	yaml := `
log:
  capture_headers:
    - X-Workspace-Slug
    - X-Request-Source
`
	cfg, err := ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if len(cfg.Log.CaptureHeaders) != 2 {
		t.Fatalf("CaptureHeaders len = %d, want 2", len(cfg.Log.CaptureHeaders))
	}
	if cfg.Log.CaptureHeaders[0] != "X-Workspace-Slug" {
		t.Errorf("CaptureHeaders[0] = %q, want X-Workspace-Slug", cfg.Log.CaptureHeaders[0])
	}
}

func TestValidateCaptureHeaders_MaxExceeded(t *testing.T) {
	headers := make([]string, 11)
	for i := range headers {
		headers[i] = fmt.Sprintf("X-Header-%d", i)
	}
	err := proxy.ValidateCaptureHeaders(headers)
	if err == nil {
		t.Fatal("expected error for >10 headers")
	}
	if !strings.Contains(err.Error(), "max 10") {
		t.Errorf("error = %q, want mention of max 10", err.Error())
	}
}

func TestValidateCaptureHeaders_SensitiveRejected(t *testing.T) {
	tests := []string{"Authorization", "proxy-authorization", "Cookie"}
	for _, h := range tests {
		t.Run(h, func(t *testing.T) {
			err := proxy.ValidateCaptureHeaders([]string{h})
			if err == nil {
				t.Fatalf("expected error for sensitive header %q", h)
			}
			if !strings.Contains(err.Error(), "sensitive") {
				t.Errorf("error = %q, want mention of sensitive", err.Error())
			}
		})
	}
}

func TestValidateCaptureHeaders_Valid(t *testing.T) {
	err := proxy.ValidateCaptureHeaders([]string{"X-Workspace-Slug", "X-Request-Source"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateCaptureHeaders_Empty(t *testing.T) {
	err := proxy.ValidateCaptureHeaders(nil)
	if err != nil {
		t.Fatalf("unexpected error for nil: %v", err)
	}
	err = proxy.ValidateCaptureHeaders([]string{})
	if err != nil {
		t.Fatalf("unexpected error for empty: %v", err)
	}
}

func TestValidateCaptureHeaders_Duplicate(t *testing.T) {
	err := proxy.ValidateCaptureHeaders([]string{"X-Workspace-Slug", "x-workspace-slug"})
	if err == nil {
		t.Fatal("expected error for duplicate headers")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error = %q, want mention of duplicate", err.Error())
	}
}
