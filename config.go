package gatekeeper

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents a Gate Keeper configuration file.
type Config struct {
	Proxy       ProxyConfig        `yaml:"proxy"`
	TLS         TLSConfig          `yaml:"tls"`
	Credentials []CredentialConfig `yaml:"credentials"`
	Network     NetworkConfig      `yaml:"network"`
	Log         LogConfig          `yaml:"log"`
	Postgres    *PostgresConfig    `yaml:"postgres,omitempty"`
}

// PostgresConfig configures the Postgres data-plane listener. When present,
// gatekeeper starts a Postgres-protocol listener that authenticates clients
// with their run token and injects resolved database credentials upstream.
type PostgresConfig struct {
	Port int    `yaml:"port"`           // listener port (e.g. 5432)
	Host string `yaml:"host,omitempty"` // bind address (default: same as proxy host)

	// ProxyProtocol enables PROXY protocol v1/v2 parsing on the Postgres
	// data-plane listener, mirroring proxy.proxy_protocol: when true, each
	// inbound connection is checked for a leading PROXY protocol header (as
	// prepended by a TCP-terminating load balancer in front of the Postgres
	// port) and, if present, the advertised source address replaces the raw
	// TCP peer address as the connection's client address for logging.
	// Connections that do not open with a PROXY header fall back to the raw
	// TCP peer address (fail-open), so load balancer health checks and
	// direct probes of the port keep working. Default false.
	//
	// Because headers are honored from any peer, a client that can reach
	// this listener directly (bypassing the load balancer) can forge the
	// logged client_ip by prepending its own PROXY header. Only enable this
	// when the port is reachable solely through the load balancer, and never
	// use client_ip for security decisions.
	ProxyProtocol bool `yaml:"proxy_protocol,omitempty"`
}

// ProxyConfig configures the proxy listener.
type ProxyConfig struct {
	Port      int    `yaml:"port"`
	Host      string `yaml:"host"`
	AuthToken string `yaml:"auth_token,omitempty"` // Optional token clients must provide via Proxy-Authorization

	// ProxyProtocol enables PROXY protocol v1/v2 parsing on the HTTP/CONNECT
	// proxy listener. When true, each inbound connection is checked for a
	// leading PROXY protocol header (as prepended by a TCP load balancer,
	// e.g. GCP's global TCP Proxy LB) and, if present, the advertised source
	// address replaces the raw TCP peer address as the connection's client
	// address for logging (the client_ip request-log attribute). Connections
	// that do not open with a PROXY header fall back to the raw TCP peer
	// address (fail-open), so load balancer health checks and direct probes
	// of the port keep working. Default false.
	//
	// Because headers are honored from any peer, a client that can reach the
	// listener directly (bypassing the load balancer) can forge the logged
	// client_ip by prepending its own PROXY header. Only enable this when
	// the port is reachable solely through the load balancer, and never use
	// client_ip for security decisions.
	ProxyProtocol bool `yaml:"proxy_protocol,omitempty"`
}

// TLSConfig configures the CA certificate used for TLS interception.
type TLSConfig struct {
	CACert string `yaml:"ca_cert"`
	CAKey  string `yaml:"ca_key"`
}

// CredentialConfig describes a credential to resolve and inject.
// Host specifies which requests receive the credential. Header names the
// HTTP header to set (defaults to "Authorization"). Grant is an optional
// label used for logging.
//
// When the header is "Authorization", the proxy needs a full header value
// including the auth scheme (e.g., "Bearer token123"). If the source value
// is a bare token without a scheme prefix, the gatekeeper auto-detects the
// correct scheme from known token prefixes (GitHub ghp_/gho_/etc.) or
// defaults to "Bearer". Set Prefix to override the auto-detected scheme.
//
// For hosts that require HTTP Basic authentication (e.g., github.com git
// smart HTTP), set Format to "basic" and Prefix to the Basic auth username.
// The credential value becomes the password: Authorization: Basic base64(prefix:value).
type CredentialConfig struct {
	Host     string                    `yaml:"host"`             // Target host (e.g., "api.github.com")
	Header   string                    `yaml:"header,omitempty"` // Header name (default: "Authorization")
	Prefix   string                    `yaml:"prefix,omitempty"` // Auth scheme prefix (e.g., "Bearer", "token"); auto-detected if omitted
	Format   string                    `yaml:"format,omitempty"` // Auth format: "" (default scheme prefix) or "basic" (HTTP Basic)
	Source   SourceConfig              `yaml:"source"`
	Grant    string                    `yaml:"grant,omitempty"` // Optional label for logging
	Postgres *PostgresCredentialConfig `yaml:"postgres,omitempty"`
}

// PostgresCredentialConfig marks a credential as a Postgres credential and
// selects how the upstream password is resolved. Resolver is "neon" (the
// Source supplies the Neon API key, passwords are minted per branch) or
// "static" (the Source supplies the password directly).
type PostgresCredentialConfig struct {
	Resolver string `yaml:"resolver"`
	Project  string `yaml:"project,omitempty"` // optional Neon project ID; required for project-scoped API keys
}

// SourceConfig describes where to read a credential value from.
//
// SourceConfig is used as a map key to deduplicate identical sources (see
// Server.setCredentials), so it must remain comparable: add list-valued
// fields as delimited strings (like Scopes), never slices, and avoid
// pointer fields, which would compile but silently break deduplication.
type SourceConfig struct {
	Type    string `yaml:"type"`              // "env", "static", "process", "aws-secretsmanager", "gcp-secretmanager", "gcp-service-account", "github-app", "token-exchange"
	Var     string `yaml:"var,omitempty"`     // for env source
	Value   string `yaml:"value,omitempty"`   // for static source
	Command string `yaml:"command,omitempty"` // for process source: host command run with `sh -c`
	TTL     string `yaml:"ttl,omitempty"`     // for process source: refresh interval when output has no expiry (Go duration, default 5m)
	Secret  string `yaml:"secret,omitempty"`  // for aws-secretsmanager, gcp-secretmanager; for gcp-service-account, the secret holding the key JSON
	Region  string `yaml:"region,omitempty"`  // for aws-secretsmanager
	Project string `yaml:"project,omitempty"` // for gcp-secretmanager, gcp-service-account
	Version string `yaml:"version,omitempty"` // for gcp-secretmanager, gcp-service-account (default: "latest")

	AppID          string `yaml:"app_id,omitempty"`           // for github-app source
	InstallationID string `yaml:"installation_id,omitempty"`  // for github-app source
	PrivateKeyPath string `yaml:"private_key_path,omitempty"` // for github-app (PEM key), gcp-service-account (key JSON)
	PrivateKeyEnv  string `yaml:"private_key_env,omitempty"`  // for github-app (PEM key), gcp-service-account (key JSON)
	Scopes         string `yaml:"scopes,omitempty"`           // for gcp-service-account: space-separated OAuth scopes (default: cloud-platform)

	// token-exchange (RFC 8693) fields
	Endpoint         string `yaml:"endpoint,omitempty"`
	ClientID         string `yaml:"client_id,omitempty"`
	ClientSecret     string `yaml:"client_secret,omitempty"`
	ClientSecretEnv  string `yaml:"client_secret_env,omitempty"`
	SubjectHeader    string `yaml:"subject_header,omitempty"`
	SubjectFrom      string `yaml:"subject_from,omitempty"`
	SubjectTokenType string `yaml:"subject_token_type,omitempty"`
	Resource         string `yaml:"resource,omitempty"`
	ActorTokenFrom   string `yaml:"actor_token_from,omitempty"`
	ActorTokenType   string `yaml:"actor_token_type,omitempty"`
}

// NetworkConfig configures network policy.
type NetworkConfig struct {
	Policy string   `yaml:"policy"`
	Allow  []string `yaml:"allow,omitempty"`
}

// LogConfig configures logging.
type LogConfig struct {
	Level          string   `yaml:"level"`                     // Log level (e.g., "debug", "info", "warn", "error")
	Format         string   `yaml:"format"`                    // Output format ("json" or "text")
	Output         string   `yaml:"output"`                    // Destination ("stderr", "stdout", or a file path; default: stderr)
	CaptureHeaders []string `yaml:"capture_headers,omitempty"` // Request headers to log and strip before forwarding
}

// ParseConfig parses a Gate Keeper config from YAML bytes.
func ParseConfig(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// LoadConfig reads and parses a Gate Keeper config from a file path.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(data)
}

// listenTopology is the resolved result of applying gatekeeper's host
// default rules to Config.Proxy and Config.Postgres, and deciding whether
// they collapse onto one shared listener. See resolveListenTopology.
type listenTopology struct {
	proxyHost string
	proxyPort int
	pgHost    string // "" when no Postgres listener is configured
	pgPort    int
	multiplex bool
}

// resolveListenTopology applies gatekeeper's host-default rules
// (proxy.host defaults to defaultProxyHost; postgres.host defaults to the
// resolved proxy host) and decides whether the proxy and Postgres listeners
// collapse onto one shared port. There is no separate flag for this — an
// operator declares "one listener" purely by pointing both configs at the
// same port and host; resolveListenTopology and Server.Start both call this
// function so the declaration and the actual wiring can never disagree.
//
// Multiplexing triggers only when postgres.port is a real, non-zero port
// and it equals proxy.port, and the two configs' hosts resolve to the same
// address. Port 0 (ask the OS for an ephemeral port) never triggers
// multiplexing, even when both sides leave it unset: two independent
// net.Listen(...:0) calls are not "the same port," and treating them as
// such would silently change today's two-listener behavior for every
// config — and every test in this suite — that leaves the port unset on
// both listeners.
//
// It returns a fatal, user-facing error for the two configurations
// gatekeeper refuses to start with once ports are declared equal: different
// hosts (ambiguous — which address should the one shared listener bind?),
// and proxy.proxy_protocol != postgres.proxy_protocol (a single shared
// listener can only have one PROXY protocol setting, owned by
// proxy.proxy_protocol since proxy.proxy_protocol is the listener owner).
func resolveListenTopology(cfg *Config) (listenTopology, error) {
	proxyHost := cfg.Proxy.Host
	if proxyHost == "" {
		proxyHost = defaultProxyHost
	}
	topo := listenTopology{proxyHost: proxyHost, proxyPort: cfg.Proxy.Port}
	if cfg.Postgres == nil {
		return topo, nil
	}

	pgHost := cfg.Postgres.Host
	if pgHost == "" {
		pgHost = proxyHost
	}
	topo.pgHost = pgHost
	topo.pgPort = cfg.Postgres.Port

	if cfg.Postgres.Port == 0 || cfg.Postgres.Port != cfg.Proxy.Port {
		return topo, nil
	}

	// Equal, non-zero ports: this is the multiplex declaration.
	if pgHost != proxyHost {
		return topo, fmt.Errorf("postgres.port (%d) equals proxy.port but postgres.host (%q) differs from proxy.host (%q); a shared listener can only bind one address — use the same host on both, or different ports",
			cfg.Postgres.Port, pgHost, proxyHost)
	}
	if cfg.Postgres.ProxyProtocol != cfg.Proxy.ProxyProtocol {
		return topo, fmt.Errorf("postgres.port (%d) equals proxy.port but postgres.proxy_protocol (%v) differs from proxy.proxy_protocol (%v); a shared listener has one PROXY protocol setting, owned by proxy.proxy_protocol",
			cfg.Postgres.Port, cfg.Postgres.ProxyProtocol, cfg.Proxy.ProxyProtocol)
	}
	topo.multiplex = true
	return topo, nil
}
