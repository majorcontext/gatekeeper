package gatekeeper

import (
	"context"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/majorcontext/gatekeeper/proxy"
	"gopkg.in/yaml.v3"
)

func TestCredentialConfigSharesProxyCredentialModel(t *testing.T) {
	var yamlCredential CredentialConfig
	var runtimeCredential proxy.CredentialHeader
	yamlCredential = runtimeCredential
	runtimeCredential = yamlCredential
}

func TestParseConfig_Full(t *testing.T) {
	yaml := `
proxy:
  port: 8080
  host: 127.0.0.1
  proxy_protocol: true
  auth_token_env: GATEKEEPER_PROXY_AUTH_TOKEN
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
	if cfg.Proxy.AuthTokenEnv != "GATEKEEPER_PROXY_AUTH_TOKEN" {
		t.Errorf("Proxy.AuthTokenEnv = %q, want GATEKEEPER_PROXY_AUTH_TOKEN", cfg.Proxy.AuthTokenEnv)
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
  - host: "*.other.tech"
    postgres:
      resolver: neon
      project_env: NEON_PROJECT_ID
    source:
      type: env
      var: NEON_API_KEY
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
	if len(cfg.Credentials) != 2 {
		t.Fatalf("credentials = %d, want 2", len(cfg.Credentials))
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
	if got := cfg.Credentials[1].Postgres.ProjectEnv; got != "NEON_PROJECT_ID" {
		t.Errorf("ProjectEnv = %q, want NEON_PROJECT_ID", got)
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

func TestParseConfig_CaptureRequestHeaders(t *testing.T) {
	yaml := `
log:
  capture_request_headers:
    - X-Workspace-Slug
    - X-Request-Source
`
	cfg, err := ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if len(cfg.Log.CaptureRequestHeaders) != 2 {
		t.Fatalf("CaptureRequestHeaders len = %d, want 2", len(cfg.Log.CaptureRequestHeaders))
	}
	if cfg.Log.CaptureRequestHeaders[0] != "X-Workspace-Slug" {
		t.Errorf("CaptureRequestHeaders[0] = %q, want X-Workspace-Slug", cfg.Log.CaptureRequestHeaders[0])
	}
}

func TestParseConfig_RejectsOldCaptureHeadersKey(t *testing.T) {
	if _, err := ParseConfig([]byte("log:\n  capture_headers: [X-Request-Id]\n")); err == nil {
		t.Fatal("ParseConfig accepted capture_headers")
	}
}

func TestParseConfig_CaptureResponseHeaders(t *testing.T) {
	cfg, err := ParseConfig([]byte("log:\n  capture_response_headers:\n    - X-Request-Id\n"))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if len(cfg.Log.CaptureResponseHeaders) != 1 || cfg.Log.CaptureResponseHeaders[0] != "X-Request-Id" {
		t.Fatalf("CaptureResponseHeaders = %v, want [X-Request-Id]", cfg.Log.CaptureResponseHeaders)
	}
}

func TestValidateCaptureResponseHeaders(t *testing.T) {
	tooMany := make([]string, 11)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("X-Response-%d", i)
	}
	for _, tt := range []struct {
		name    string
		headers []string
		want    string
	}{
		{name: "limit", headers: tooMany, want: "max 10"},
		{name: "sensitive", headers: []string{"Authorization"}, want: "sensitive"},
		{name: "case insensitive duplicate", headers: []string{"X-Trace", "x-trace"}, want: "duplicate"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := proxy.ValidateCaptureResponseHeaders(tt.headers)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestValidateCaptureRequestHeaders_MaxExceeded(t *testing.T) {
	headers := make([]string, 11)
	for i := range headers {
		headers[i] = fmt.Sprintf("X-Header-%d", i)
	}
	err := proxy.ValidateCaptureRequestHeaders(headers)
	if err == nil {
		t.Fatal("expected error for >10 headers")
	}
	if !strings.Contains(err.Error(), "max 10") {
		t.Errorf("error = %q, want mention of max 10", err.Error())
	}
}

func TestValidateCaptureRequestHeaders_SensitiveRejected(t *testing.T) {
	tests := []string{"Authorization", "proxy-authorization", "Cookie"}
	for _, h := range tests {
		t.Run(h, func(t *testing.T) {
			err := proxy.ValidateCaptureRequestHeaders([]string{h})
			if err == nil {
				t.Fatalf("expected error for sensitive header %q", h)
			}
			if !strings.Contains(err.Error(), "sensitive") {
				t.Errorf("error = %q, want mention of sensitive", err.Error())
			}
		})
	}
}

func TestValidateCaptureRequestHeaders_Valid(t *testing.T) {
	err := proxy.ValidateCaptureRequestHeaders([]string{"X-Workspace-Slug", "X-Request-Source"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateCaptureRequestHeaders_Empty(t *testing.T) {
	err := proxy.ValidateCaptureRequestHeaders(nil)
	if err != nil {
		t.Fatalf("unexpected error for nil: %v", err)
	}
	err = proxy.ValidateCaptureRequestHeaders([]string{})
	if err != nil {
		t.Fatalf("unexpected error for empty: %v", err)
	}
}

func TestValidateCaptureRequestHeaders_Duplicate(t *testing.T) {
	err := proxy.ValidateCaptureRequestHeaders([]string{"X-Workspace-Slug", "x-workspace-slug"})
	if err == nil {
		t.Fatal("expected error for duplicate headers")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error = %q, want mention of duplicate", err.Error())
	}
}

func TestParseConfig_RejectsBadNetworkPolicy(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{"capitalized policy", "network:\n  policy: Strict\n", `"Strict"`},
		{"unknown policy", "network:\n  policy: deny\n", `"deny"`},
		{"trailing space", "network:\n  policy: \"strict \"\n", `"strict "`},
		{"non-numeric port", "network:\n  policy: strict\n  allow:\n    - host:abc\n", `"host:abc"`},
		{"port out of range", "network:\n  policy: strict\n  allow:\n    - api.example.com:99999\n", `"api.example.com:99999"`},
		{"empty host", "network:\n  policy: strict\n  allow:\n    - \":443\"\n", `":443"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfig([]byte(tt.yaml))
			if err == nil {
				t.Fatalf("ParseConfig accepted %q", tt.yaml)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not name %s", err, tt.wantErr)
			}
		})
	}
}

func TestParseConfig_AcceptsValidNetworkPolicy(t *testing.T) {
	for _, policy := range []string{"", "permissive", "strict"} {
		y := "network:\n  policy: \"" + policy + "\"\n  allow:\n    - api.example.com\n    - \"*.example.com:8443\"\n"
		if _, err := ParseConfig([]byte(y)); err != nil {
			t.Errorf("policy %q: %v", policy, err)
		}
	}
}

func TestNew_RejectsBadNetworkPolicy(t *testing.T) {
	tests := []struct {
		name    string
		network NetworkConfig
	}{
		{"capitalized policy", NetworkConfig{Policy: "Strict"}},
		{"non-numeric port", NetworkConfig{Policy: "strict", Allow: []string{"host:abc"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, err := New(context.Background(), &Config{Network: tt.network}, Options{})
			if err == nil {
				_ = srv.Stop(context.Background())
				t.Fatal("New accepted an invalid network config")
			}
		})
	}
}

func TestParseConfig_RejectsUnknownKeys(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"typo in network", "network:\n  polcy: strict\n", "polcy"},
		{"top level", "netwrk:\n  policy: strict\n", "netwrk"},
		{"credential field", "credentials:\n  - host: a.example.com\n    sorce:\n      type: env\n", "sorce"},
		{"source field", "credentials:\n  - host: a.example.com\n    source:\n      type: env\n      vr: X\n", "vr"},
		{"postgres field", "postgres:\n  prot: 5432\n", "prot"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseConfig([]byte(tt.yaml))
			if err == nil {
				t.Fatalf("ParseConfig accepted unknown key in %q", tt.yaml)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not name %q", err, tt.want)
			}
		})
	}
}

func TestParseConfig_RejectsSecondDocument(t *testing.T) {
	for _, second := range []string{"netwrk:\n  policy: strict\n", "!!null {netwrk: {}}\n"} {
		in := "network:\n  policy: strict\n---\n" + second
		if _, err := ParseConfig([]byte(in)); err == nil {
			t.Errorf("ParseConfig ignored a second YAML document %q", second)
		}
	}
}

func TestParseConfig_EmptyDocuments(t *testing.T) {
	for _, in := range []string{"", "\n", "# only a comment\n", "---\n", "network:\n  policy: strict\n---\n"} {
		cfg, err := ParseConfig([]byte(in))
		if err != nil {
			t.Errorf("ParseConfig(%q): %v", in, err)
			continue
		}
		if cfg == nil {
			t.Errorf("ParseConfig(%q) returned nil config", in)
		}
	}
}

func TestParseConfig_ExampleConfigs(t *testing.T) {
	files, err := filepath.Glob("examples/*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no example configs found: %v", err)
	}
	for _, f := range files {
		if _, err := LoadConfig(f); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func TestParseConfig_DocumentedConfigs(t *testing.T) {
	block := regexp.MustCompile("(?s)```ya?ml\n(.*?)```")
	topLevel := regexp.MustCompile(`(?m)^(proxy|tls|credentials|network|log|postgres):`)
	parsed := 0
	err := filepath.WalkDir("docs/content", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".md") {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, m := range block.FindAllStringSubmatch(string(data), -1) {
			if !topLevel.MatchString(m[1]) {
				continue
			}
			parsed++
			if _, err := ParseConfig([]byte(m[1])); err != nil {
				t.Errorf("%s yaml block %d: %v", path, i+1, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if parsed == 0 {
		t.Fatal("no documented config blocks found")
	}
}

func TestActorTokenFromRequiresSharedProxyToken(t *testing.T) {
	cred := CredentialConfig{
		Host: "api.github.com",
		Source: SourceConfig{
			Type:           "token-exchange",
			Endpoint:       "https://sts.example.com/token",
			ClientID:       "gk-client",
			ClientSecret:   "s",
			SubjectFrom:    "proxy-auth",
			ActorTokenFrom: "proxy-auth-password",
		},
	}
	t.Run("rejected without a token", func(t *testing.T) {
		srv, err := New(context.Background(), &Config{Credentials: []CredentialConfig{cred}}, Options{})
		if err == nil {
			_ = srv.Stop(context.Background())
			t.Fatal("New accepted actor_token_from without proxy.auth_token or proxy.auth_token_env")
		}
		if !strings.Contains(err.Error(), "api.github.com") {
			t.Errorf("error %q does not name the credential host", err)
		}
	})
	t.Run("rejected by ParseConfig", func(t *testing.T) {
		y := "credentials:\n  - host: api.github.com\n    source:\n      type: token-exchange\n      endpoint: https://sts.example.com/token\n      client_id: gk-client\n      client_secret: s\n      subject_from: proxy-auth\n      actor_token_from: proxy-auth-password\n"
		if _, err := ParseConfig([]byte(y)); err == nil || !strings.Contains(err.Error(), "api.github.com") {
			t.Errorf("ParseConfig error = %v, want one naming api.github.com", err)
		}
	})
	for name, proxyCfg := range map[string]ProxyConfig{
		"auth_token":     {AuthToken: "shared"},
		"auth_token_env": {AuthTokenEnv: "GK_ACTOR_TEST_TOKEN"},
	} {
		t.Run("accepted with "+name, func(t *testing.T) {
			if err := (&Config{Proxy: proxyCfg, Credentials: []CredentialConfig{cred}}).validate(); err != nil {
				t.Errorf("validate: %v", err)
			}
		})
	}
}

// Two token-exchange rules on one host left only the second: the proxy keeps
// one resolver per host key, so subscription traffic on api.anthropic.com
// would silently get the other rule's credential.
func TestConfig_RejectsTwoTokenExchangeRulesOnOneHost(t *testing.T) {
	te := func(host, grant string) CredentialConfig {
		return CredentialConfig{Host: host, Grant: grant, Source: SourceConfig{
			Type: "token-exchange", Endpoint: "https://sts.example.com/token", ClientID: "gk", ClientSecret: "s", SubjectHeader: "X-Subject",
		}}
	}
	static := CredentialConfig{Host: "api.anthropic.com", Grant: "anthropic", Header: "x-api-key", Source: SourceConfig{Type: "static", Value: "k"}}
	tests := []struct {
		name    string
		creds   []CredentialConfig
		wantErr bool
	}{
		{"two token-exchange rules on one host", []CredentialConfig{te("api.anthropic.com", "claude-code-user"), te("api.anthropic.com", "claude-api")}, true},
		{"token-exchange beside a static rule", []CredentialConfig{te("api.anthropic.com", "claude-code-user"), static}, false},
		{"token-exchange rules on two hosts", []CredentialConfig{te("api.anthropic.com", "a"), te("chatgpt.com", "b")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, proxyCfg := range []ProxyConfig{{}, {AuthToken: "shared"}} {
				err := (&Config{Proxy: proxyCfg, Credentials: tt.creds}).validate()
				if !tt.wantErr {
					if err != nil {
						t.Errorf("validate (auth token %q): %v", proxyCfg.AuthToken, err)
					}
					continue
				}
				if err == nil {
					t.Fatalf("validate (auth token %q) accepted two token-exchange rules on one host", proxyCfg.AuthToken)
				}
				for _, want := range []string{"api.anthropic.com", "claude-code-user", "claude-api"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error %q does not name %q", err, want)
					}
				}
			}
		})
	}
	t.Run("rejected by ParseConfig", func(t *testing.T) {
		rule := "  - host: api.anthropic.com\n    grant: %s\n    source:\n      type: token-exchange\n      endpoint: https://sts.example.com/token\n      client_id: gk\n      client_secret: s\n      subject_header: X-Subject\n"
		y := "credentials:\n" + fmt.Sprintf(rule, "claude-code-user") + fmt.Sprintf(rule, "claude-api")
		if _, err := ParseConfig([]byte(y)); err == nil || !strings.Contains(err.Error(), "api.anthropic.com") {
			t.Errorf("ParseConfig error = %v, want one naming api.anthropic.com", err)
		}
	})
	t.Run("rejected by New", func(t *testing.T) {
		srv, err := New(context.Background(), &Config{Credentials: []CredentialConfig{te("api.anthropic.com", "claude-code-user"), te("api.anthropic.com", "claude-api")}}, Options{})
		if err == nil {
			_ = srv.Stop(context.Background())
			t.Fatal("New accepted two token-exchange rules on one host")
		}
	})
}

func TestYAMLAndLibraryMatchedCredentialsForwardEquivalentHeaders(t *testing.T) {
	var received http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	backendURL, _ := url.Parse(backend.URL)
	host, port, _ := net.SplitHostPort(backendURL.Host)
	configYAML := fmt.Sprintf(`credentials:
  - host: %s
    header: Authorization
    allow_insecure: true
    match:
      header: x-api-key
      paths: [/v1/]
      methods: [POST]
    set_headers:
      anthropic-beta: oauth-2025-04-20
    remove_headers: [x-client]
    source:
      type: static
      value: test-token
`, host)
	cfg, err := ParseConfig([]byte(configYAML))
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(context.Background(), cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Stop(context.Background()) })
	credential := proxy.CredentialHeader{
		Host: host, Name: "Authorization", Value: "Bearer test-token", AllowInsecure: true,
		Match:         &proxy.RequestMatch{Header: "x-api-key", Paths: []string{"/v1/"}, Methods: []string{"POST"}},
		SetHeaders:    map[string]string{"anthropic-beta": "oauth-2025-04-20"},
		RemoveHeaders: []string{"x-client"},
	}
	direct := proxy.NewProxy()
	direct.SetCredentialEntry(credential)
	run := func(handler http.Handler) http.Header {
		req := httptest.NewRequest("POST", "http://"+net.JoinHostPort(host, port)+"/v1/messages", nil)
		req.Header.Set("x-api-key", "placeholder")
		req.Header.Set("x-client", "remove")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		return received.Clone()
	}
	fromYAML := run(server.proxy)
	fromLibrary := run(direct)
	for _, name := range []string{"Authorization", "x-api-key", "x-client", "anthropic-beta"} {
		if got, want := fromYAML.Get(name), fromLibrary.Get(name); got != want {
			t.Errorf("%s: YAML = %q, library = %q", name, got, want)
		}
	}
	if fromYAML.Get("Authorization") != "Bearer test-token" || fromYAML.Get("x-api-key") != "" || fromYAML.Get("x-client") != "" || fromYAML.Get("anthropic-beta") != "oauth-2025-04-20" {
		t.Errorf("forwarded headers = %v", fromYAML)
	}
}

func TestYAMLMatchedCredentialOrderIncludesTokenExchange(t *testing.T) {
	var received http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	backendURL, _ := url.Parse(backend.URL)
	host, port, _ := net.SplitHostPort(backendURL.Host)
	configYAML := fmt.Sprintf(`credentials:
  - host: %s
    header: Authorization
    allow_insecure: true
    match: {header: x-api-key, paths: [/v1/messages], methods: [GET]}
    source: {type: static, value: static-token}
  - host: %s
    header: Authorization
    allow_insecure: true
    match: {header: x-api-key, paths: [/v1/messages], methods: [GET, POST]}
    source:
      type: token-exchange
      endpoint: https://sts.example.test/token
      client_id: test-client
      client_secret: placeholder
      subject_header: X-Subject
`, host, host)
	cfg, err := ParseConfig([]byte(configYAML))
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(context.Background(), cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Stop(context.Background()) })
	req := httptest.NewRequest("GET", "http://"+net.JoinHostPort(host, port)+"/v1/messages", nil)
	req.Header.Set("x-api-key", "selector")
	req.Header.Set("x-subject", "subject")
	server.proxy.ServeHTTP(httptest.NewRecorder(), req)
	if got := received.Get("Authorization"); got != "Bearer static-token" {
		t.Errorf("Authorization = %q, want first matching static credential", got)
	}
	if received.Get("x-api-key") != "" {
		t.Errorf("selector header reached upstream: %q", received.Get("x-api-key"))
	}
}

func TestConfig_MatchValidation(t *testing.T) {
	te := func(grant string, m *MatchConfig) CredentialConfig {
		return CredentialConfig{Host: "api.anthropic.com", Grant: grant, Match: m, Source: SourceConfig{
			Type: "token-exchange", Endpoint: "https://sts.example.com/token", ClientID: "gk", ClientSecret: "s", SubjectHeader: "X-Subject",
		}}
	}
	static := CredentialConfig{Host: "api.anthropic.com", Grant: "anthropic", Header: "x-api-key", Source: SourceConfig{Type: "static", Value: "k"}}
	staticMatched := static
	staticMatched.Match = &MatchConfig{Header: "x-api-key"}
	postgresMatched := staticMatched
	postgresMatched.Postgres = &PostgresCredentialConfig{Resolver: "static"}
	tests := []struct {
		name    string
		creds   []CredentialConfig
		wantErr string
	}{
		{"match on a static source", []CredentialConfig{staticMatched}, ""},
		{"match on a Postgres credential", []CredentialConfig{postgresMatched}, "postgres"},
		{"empty match header", []CredentialConfig{te("g1", &MatchConfig{Paths: []string{"/v1/"}})}, "header"},
		{"header with a space", []CredentialConfig{te("g1", &MatchConfig{Header: "X Tenant"})}, "header"},
		{"header with a colon", []CredentialConfig{te("g1", &MatchConfig{Header: "x-api:key"})}, "header"},
		{"path without a leading slash", []CredentialConfig{te("g1", &MatchConfig{Header: "x-api-key", Paths: []string{"v1/"}})}, "path"},
		{"lower-case method", []CredentialConfig{te("g1", &MatchConfig{Header: "x-api-key", Methods: []string{"get"}})}, "method"},
		{"unmatched rule beside a matched one", []CredentialConfig{te("g1", &MatchConfig{Header: "x-api-key"}), te("g2", nil)}, ""},
		{"selector equals another rule's subject header", []CredentialConfig{te("g1", &MatchConfig{Header: "x-subject"}), te("g2", &MatchConfig{Header: "x-api-key"})}, ""},
		{"identical match blocks", []CredentialConfig{te("g1", &MatchConfig{Header: "x-api-key", Methods: []string{"GET"}}), te("g2", &MatchConfig{Header: "x-api-key", Methods: []string{"GET"}})}, "identical"},
		{"covered match", []CredentialConfig{
			te("early", &MatchConfig{Header: "x-api-key", Paths: []string{"/v1/", "/v2/"}, Methods: []string{"GET", "POST"}}),
			te("covered", &MatchConfig{Header: "X-API-KEY", Paths: []string{"/v2/messages"}, Methods: []string{"POST"}}),
		}, "covered"},
		{"overlap is not coverage", []CredentialConfig{
			te("early", &MatchConfig{Header: "x-api-key", Paths: []string{"/v1/"}, Methods: []string{"GET"}}),
			te("overlap", &MatchConfig{Header: "x-api-key", Paths: []string{"/v1/messages"}, Methods: []string{"GET", "POST"}}),
		}, ""},
		{"three distinct rules", []CredentialConfig{
			te("admin", &MatchConfig{Header: "x-api-key", Paths: []string{"/v1/organizations/"}, Methods: []string{"GET"}}),
			te("api", &MatchConfig{Header: "x-api-key", Paths: []string{"/v1/messages"}}),
			te("sub", &MatchConfig{Header: "Authorization"}),
		}, ""},
		{"matched rule beside a static rule", []CredentialConfig{te("sub", &MatchConfig{Header: "Authorization"}), static}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check := func(via string, err error) {
				if tt.wantErr == "" {
					if err != nil {
						t.Errorf("%s: %v", via, err)
					}
					return
				}
				if err == nil {
					t.Fatalf("%s accepted the config", via)
				}
				for _, want := range []string{"api.anthropic.com", tt.creds[0].Grant, tt.wantErr} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("%s: error %q does not contain %q", via, err, want)
					}
				}
			}
			check("validate", (&Config{Credentials: tt.creds}).validate())
			y, err := yaml.Marshal(&Config{Credentials: tt.creds})
			if err != nil {
				t.Fatal(err)
			}
			_, err = ParseConfig(y)
			check("ParseConfig", err)
		})
	}
}
