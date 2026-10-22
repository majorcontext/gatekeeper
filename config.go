package gatekeeper

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/majorcontext/gatekeeper/proxy"
	"golang.org/x/net/http/httpguts"
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

	// AuthTokenEnv names an environment variable holding the proxy auth
	// token, read once at startup. Mutually exclusive with AuthToken: set
	// one or the other, not both. The named variable must be set and
	// non-empty at startup.
	AuthTokenEnv string `yaml:"auth_token_env,omitempty"`

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

// CredentialConfig is the YAML configuration form of proxy.Credential.
type CredentialConfig = proxy.Credential

// MatchConfig is the request predicate type used by credentials.
type MatchConfig = proxy.RequestMatch

type SourceConfig = proxy.SourceConfig

type PostgresCredentialConfig = proxy.PostgresCredentialConfig

// NetworkConfig configures network policy.
type NetworkConfig struct {
	Policy string   `yaml:"policy"`
	Allow  []string `yaml:"allow,omitempty"`
}

// LogConfig configures logging.
type LogConfig struct {
	Level                  string   `yaml:"level"`  // Log level (e.g., "debug", "info", "warn", "error")
	Format                 string   `yaml:"format"` // Output format ("json" or "text")
	Output                 string   `yaml:"output"` // Destination ("stderr", "stdout", or a file path; default: stderr)
	CaptureRequestHeaders  []string `yaml:"capture_request_headers,omitempty"`
	CaptureResponseHeaders []string `yaml:"capture_response_headers,omitempty"`
}

// resolveProxyAuthToken resolves the effective proxy auth token from
// cfg.AuthToken or cfg.AuthTokenEnv. It returns "" when neither is set,
// meaning the proxy requires no auth token.
func resolveProxyAuthToken(cfg ProxyConfig) (string, error) {
	if cfg.AuthToken != "" && cfg.AuthTokenEnv != "" {
		return "", fmt.Errorf("proxy: set 'auth_token' or 'auth_token_env', not both")
	}
	token := cfg.AuthToken
	if cfg.AuthTokenEnv != "" {
		token = os.Getenv(cfg.AuthTokenEnv)
		if token == "" {
			return "", fmt.Errorf("proxy.auth_token_env: environment variable %q is empty or not set", cfg.AuthTokenEnv)
		}
	}
	return token, nil
}

// ParseConfig parses a Gate Keeper config from YAML bytes.
func ParseConfig(data []byte) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	for {
		var extra yaml.Node
		if err := dec.Decode(&extra); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
		if len(extra.Content) > 0 && (extra.Content[0].Kind != yaml.ScalarNode || extra.Content[0].Tag != "!!null") {
			return nil, errors.New("config must contain a single YAML document")
		}
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	if err := c.Network.validate(); err != nil {
		return err
	}
	if err := c.validateCredentialMatches(); err != nil {
		return err
	}
	if c.Proxy.AuthToken != "" || c.Proxy.AuthTokenEnv != "" {
		return nil
	}
	for _, cred := range c.Credentials {
		if cred.Source.ActorTokenFrom != "" {
			return fmt.Errorf("credential for host %q sets actor_token_from, which requires proxy.auth_token or proxy.auth_token_env", cred.Host)
		}
	}
	return nil
}

// validateCredentialMatches validates request predicates and rejects covered
// matches or multiple unmatched token-exchange credentials on one host.
func (c *Config) validateCredentialMatches() error {
	rules := map[string][]CredentialConfig{}
	for _, cred := range c.Credentials {
		if err := validateCredentialMatch(cred); err != nil {
			return err
		}
		for _, prev := range rules[cred.Host] {
			if prev.Source.Type == "token-exchange" && cred.Source.Type == "token-exchange" && prev.Match == nil && cred.Match == nil {
				return fmt.Errorf("credentials: host %q has two token-exchange rules (grants %q and %q); only one resolver applies per host: add match to every rule", cred.Host, prev.Grant, cred.Grant)
			}
			if prev.Match != nil && cred.Match != nil {
				if prev.Match.Equal(*cred.Match) {
					return fmt.Errorf("credentials: host %q grants %q and %q have identical match blocks", cred.Host, prev.Grant, cred.Grant)
				}
				if matchCovers(*prev.Match, *cred.Match) {
					return fmt.Errorf("credentials: host %q grant %q has a match covered by earlier grant %q", cred.Host, cred.Grant, prev.Grant)
				}
			}
		}
		rules[cred.Host] = append(rules[cred.Host], cred)
	}
	return nil
}

func matchCovers(earlier, later MatchConfig) bool {
	if !strings.EqualFold(earlier.Header, later.Header) {
		return false
	}
	if len(earlier.Paths) > 0 {
		if len(later.Paths) == 0 {
			return false
		}
		for _, laterPath := range later.Paths {
			if !slices.ContainsFunc(earlier.Paths, func(earlierPath string) bool { return strings.HasPrefix(laterPath, earlierPath) }) {
				return false
			}
		}
	}
	if len(earlier.Methods) > 0 {
		if len(later.Methods) == 0 {
			return false
		}
		for _, laterMethod := range later.Methods {
			if !slices.Contains(earlier.Methods, laterMethod) {
				return false
			}
		}
	}
	return true
}

func validateCredentialMatch(c CredentialConfig) error {
	m := c.Match
	if m == nil {
		return nil
	}
	if c.Postgres != nil {
		return fmt.Errorf("credentials: host %q grant %q: match is not valid for postgres credentials", c.Host, c.Grant)
	}
	if m.Header == "" {
		return fmt.Errorf("credentials: host %q grant %q: match.header is required", c.Host, c.Grant)
	}
	if !httpguts.ValidHeaderFieldName(m.Header) {
		return fmt.Errorf("credentials: host %q grant %q: match.header %q is not a valid HTTP header name", c.Host, c.Grant, m.Header)
	}
	for _, p := range m.Paths {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("credentials: host %q grant %q: match.paths entry %q must start with \"/\"", c.Host, c.Grant, p)
		}
	}
	for _, method := range m.Methods {
		if !upperMethod.MatchString(method) {
			return fmt.Errorf("credentials: host %q grant %q: match.methods entry %q must be upper-case letters", c.Host, c.Grant, method)
		}
	}
	return nil
}

var upperMethod = regexp.MustCompile(`^[A-Z]+$`)

func (n NetworkConfig) validate() error {
	switch n.Policy {
	case "", "permissive", "strict":
	default:
		return fmt.Errorf("network.policy %q is not one of \"permissive\" or \"strict\"", n.Policy)
	}
	for _, pattern := range n.Allow {
		if err := proxy.ValidateHostPattern(pattern); err != nil {
			return fmt.Errorf("network.allow: %w", err)
		}
	}
	return nil
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
