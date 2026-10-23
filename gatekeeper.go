// Package gatekeeper provides a standalone credential-injecting TLS proxy.
//
// Credentials are pre-configured in gatekeeper.yaml and injected for all
// proxied requests matching the host. Access control is via network policy
// (who can reach the proxy) and an optional static auth token.
package gatekeeper

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/majorcontext/gatekeeper/credentialsource"
	"github.com/majorcontext/gatekeeper/proxy"
)

// defaultProxyHost is the default bind address when none is configured.
// Binding to localhost prevents accidental exposure on all interfaces.
const defaultProxyHost = "127.0.0.1"

// healthHandler wraps an HTTP handler to add a /healthz endpoint on the proxy port.
type healthHandler struct {
	next http.Handler
}

func (h *healthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		return
	}
	h.next.ServeHTTP(w, r)
}

// pendingRefresh captures a RefreshingSource and all credential configs that
// share it, so a single refresh goroutine updates every host.
type pendingRefresh struct {
	src   credentialsource.RefreshingSource
	creds []CredentialConfig
}

// Server is the Gate Keeper server. It manages a TLS-intercepting proxy
// with statically configured credentials.
type Server struct {
	version string

	proxy *proxy.Proxy
	cfg   *Config

	proxyAddr   string // actual address after Start
	proxyLn     net.Listener
	proxyServer *http.Server
	pgServer    *proxy.PostgresServer // postgres data-plane listener, if configured
	pgAddr      string                // actual postgres listener address after Start
	demux       *proxy.Demux          // non-nil when proxy and postgres share one listener (see resolveListenTopology)
	logger      *slog.Logger          // nil means slog.Default() at each use

	pendingRefreshes []pendingRefresh
	refreshCancel    context.CancelFunc
	refreshWG        sync.WaitGroup
	stopping         bool        // guarded by mu; set once Stop begins
	closers          []io.Closer // credential sources that hold resources

	// resolveSource overrides resolveSource for testing. When non-nil,
	// loadCredentials calls this instead of resolveSource.
	resolveSource func(SourceConfig) (credentialsource.CredentialSource, error)
	// neonBaseURL overrides the Neon API base URL for testing.
	neonBaseURL string

	mu      sync.Mutex
	started bool
}

// Options are the process-level inputs to New that are not part of the
// YAML configuration.
type Options struct {
	// Version is included in the startup log line.
	Version string
	// Logger receives the server's own log lines. Nil means slog.Default().
	// The log.level, log.format, and log.output config keys apply only to
	// the gatekeeper binary, which builds this logger from them.
	Logger *slog.Logger
}

func (s *Server) log() *slog.Logger {
	if s.logger != nil {
		return s.logger
	}
	return slog.Default()
}

// New creates a new Gate Keeper server from the given configuration.
// The context is used for credential fetching (e.g., AWS Secrets Manager)
// and can be used to cancel startup if the process receives a signal.
// New never changes process-global state.
func New(ctx context.Context, cfg *Config, opts Options) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	p := proxy.NewProxy()

	s := &Server{
		version: opts.Version,
		proxy:   p,
		logger:  opts.Logger,
		cfg:     cfg,
	}

	if err := s.loadCA(cfg); err != nil {
		return nil, err
	}

	// The Postgres data-plane listener terminates client TLS with CA-minted
	// certificates, so a CA is mandatory when it is configured.
	if cfg.Postgres != nil && (cfg.TLS.CACert == "" || cfg.TLS.CAKey == "") {
		return nil, fmt.Errorf("postgres listener requires tls.ca_cert and tls.ca_key to be configured")
	}

	// Fail fast on an invalid or ambiguous proxy/postgres listener topology
	// (e.g. equal ports but different hosts) rather than discovering it only
	// once Start tries to bind. Start recomputes the same topology right
	// before wiring listeners, so the two can never disagree.
	if _, err := resolveListenTopology(cfg); err != nil {
		return nil, err
	}

	// Load credentials from config and set directly on the proxy.
	// Credentials are fetched once at startup. For sources like
	// aws-secretsmanager, restart the process to pick up rotated values.
	if err := s.loadCredentials(ctx, cfg); err != nil {
		return nil, fmt.Errorf("loading credentials: %w", err)
	}

	s.installLoggers()

	if err := s.configurePolicy(cfg); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Server) loadCA(cfg *Config) error {
	// Load TLS CA for HTTPS interception. Without a CA, the proxy cannot
	// inject credentials into HTTPS requests (CONNECT tunnels pass through).
	if cfg.TLS.CACert != "" && cfg.TLS.CAKey != "" {
		certPEM, err := os.ReadFile(cfg.TLS.CACert)
		if err != nil {
			return fmt.Errorf("reading CA cert: %w", err)
		}
		keyPEM, err := os.ReadFile(cfg.TLS.CAKey)
		if err != nil {
			return fmt.Errorf("reading CA key: %w", err)
		}
		ca, err := proxy.LoadCA(certPEM, keyPEM)
		if err != nil {
			return fmt.Errorf("loading CA: %w", err)
		}
		s.proxy.SetCA(ca)
	}
	return nil
}

func (s *Server) configurePolicy(cfg *Config) error {
	// Optional defense-in-depth: require a static token for proxy access.
	// Clients provide it via Proxy-Authorization header or
	// HTTP_PROXY=http://user:token@host. The token comes from either the
	// literal auth_token or the environment variable named by
	// auth_token_env; resolveProxyAuthToken rejects setting both.
	authToken, err := resolveProxyAuthToken(cfg.Proxy)
	if err != nil {
		return err
	}
	if authToken != "" {
		s.proxy.SetAuthToken(authToken)
	}

	// actor_token_from requires a non-empty proxy password.
	for _, cred := range cfg.Credentials {
		if cred.Source.ActorTokenFrom != "" {
			if err := s.proxy.SetDelegateAuth(true); err != nil {
				return fmt.Errorf("credential %q: actor_token_from: %w", cred.Host, err)
			}
			break
		}
	}

	if len(cfg.Log.CaptureRequestHeaders) > 0 {
		if err := s.proxy.SetCaptureRequestHeaders(cfg.Log.CaptureRequestHeaders); err != nil {
			return fmt.Errorf("capture_request_headers: %w", err)
		}
	}
	if len(cfg.Log.CaptureResponseHeaders) > 0 {
		if err := s.proxy.SetCaptureResponseHeaders(cfg.Log.CaptureResponseHeaders); err != nil {
			return fmt.Errorf("capture_response_headers: %w", err)
		}
	}

	// Configure network policy if specified.
	if cfg.Network.Policy != "" {
		if err := s.proxy.SetNetworkPolicy(cfg.Network.Policy, cfg.Network.Allow, nil); err != nil {
			return fmt.Errorf("network: %w", err)
		}
	}
	if cfg.Log.ModelExchange.Enabled {
		if err := s.proxy.SetExchangeLog(s.log(), cfg.Log.ModelExchange.Hosts); err != nil {
			return fmt.Errorf("log.model_exchange: %w", err)
		}
	}
	return nil
}

// loadCredentials resolves each credential from config and sets it on the proxy.
//
// Sources are deduped by SourceConfig across header, Postgres, and
// token-exchange credentials: credentials that share a source share one
// instance, one startup Fetch, one background refresh goroutine, and (for
// token exchange) one cache. Sources are built in config order, fetched
// concurrently (each fetch is a network round trip, and a production config
// has about a dozen), and applied in config order. The first fetch failure
// cancels the other fetches. Build errors come before fetch errors, and the
// fetch error reported is the one that caused the cancellation.
func (s *Server) loadCredentials(ctx context.Context, cfg *Config) (err error) {
	type pendingSource struct {
		src   credentialsource.CredentialSource
		fetch bool
		val   string
		err   error
	}
	type credEntry struct {
		cred         CredentialConfig
		header       string
		source       *pendingSource
		pg           bool
		neon         *credentialsource.NeonResolver
		resolver     proxy.CredentialResolver
		stripHeaders []string
	}
	sources := make(map[SourceConfig]*pendingSource)
	exchanges := make(map[SourceConfig]*credentialsource.TokenExchangeSource)
	var unique []*pendingSource
	var entries []credEntry
	var neons []io.Closer
	// New returns no Server on failure, so Stop never runs: release every
	// source and Postgres resolver built here instead.
	defer func() {
		if err == nil {
			return
		}
		for _, ps := range unique {
			if c, ok := ps.src.(io.Closer); ok {
				_ = c.Close()
			}
		}
		for _, c := range neons {
			_ = c.Close()
		}
	}()

	sourceFor := func(cred CredentialConfig) (*pendingSource, error) {
		if ps, ok := sources[cred.Source]; ok {
			return ps, nil
		}
		var (
			src credentialsource.CredentialSource
			err error
		)
		if s.resolveSource != nil {
			src, err = s.resolveSource(cred.Source)
		} else {
			src, err = resolveSource(cred.Source)
		}
		if err != nil {
			return nil, err
		}
		ps := &pendingSource{src: src}
		sources[cred.Source] = ps
		unique = append(unique, ps)
		return ps, nil
	}

	for _, cred := range cfg.Credentials {
		if cred.Host == "" {
			return fmt.Errorf("credential %q: host is required", cred.Grant)
		}

		if cred.Postgres != nil {
			if cred.Postgres.Project != "" && cred.Postgres.ProjectEnv != "" {
				return fmt.Errorf("postgres credential for %s: project and project_env are mutually exclusive", cred.Host)
			}
			project := cred.Postgres.Project
			switch strings.ToLower(cred.Postgres.Resolver) {
			case "neon":
				if envName := cred.Postgres.ProjectEnv; envName != "" {
					if project = os.Getenv(envName); project == "" {
						s.log().Info("postgres credential skipped: project_env is empty", "host", cred.Host, "project_env", envName)
						continue
					}
				}
				ps, err := sourceFor(cred)
				if err != nil {
					return fmt.Errorf("postgres credential for %s: %w", cred.Host, err)
				}
				// Closed on shutdown (before the listener drain) so in-flight
				// Neon API calls are cancelled rather than holding up the drain.
				neon := &credentialsource.NeonResolver{APIKey: ps.src, Project: project, BaseURL: s.neonBaseURL}
				neons = append(neons, neon)
				entries = append(entries, credEntry{cred: cred, source: ps, pg: true, neon: neon})
			case "static":
				ps, err := sourceFor(cred)
				if err != nil {
					return fmt.Errorf("postgres credential for %s: %w", cred.Host, err)
				}
				ps.fetch = true
				entries = append(entries, credEntry{cred: cred, source: ps, pg: true})
			default:
				return fmt.Errorf("postgres credential for %s: unknown resolver %q (valid values: \"neon\", \"static\")", cred.Host, cred.Postgres.Resolver)
			}
			continue
		}

		if cred.Format != "" && !strings.EqualFold(cred.Format, "basic") {
			return fmt.Errorf("credential for %s: unknown format %q (valid values: \"basic\")", cred.Host, cred.Format)
		}

		header := cred.Header
		if header == "" {
			header = "Authorization"
		}

		if err := cred.ValidateRequestPolicy(); err != nil {
			return err
		}

		if cred.Format != "" && !strings.EqualFold(header, "Authorization") {
			return fmt.Errorf("credential for %s: format %q is only supported with the Authorization header", cred.Host, cred.Format)
		}

		if s.resolveSource == nil && cred.Source.Type == "token-exchange" {
			resolver, err := resolveSharedTokenExchange(cred, exchanges)
			if err != nil {
				return fmt.Errorf("credential for %s: %w", cred.Host, err)
			}
			// Declare the subject header so the proxy still strips it
			// when a better-matched static credential outranks (and
			// therefore skips) this resolver.
			resolver = allowInsecureResolver(resolver, cred.AllowInsecure)
			if cred.Match != nil {
				entries = append(entries, credEntry{cred: cred, header: header, resolver: resolver, stripHeaders: tokenExchangeStripHeaders(cred)})
				continue
			}
			policy := credentialHeader(cred, header, "")
			policy.Resolver = resolver
			if err := s.proxy.SetCredentialResolverEntry(policy, tokenExchangeStripHeaders(cred)...); err != nil {
				return fmt.Errorf("credential for %s: %w", cred.Host, err)
			}
			continue
		}

		ps, err := sourceFor(cred)
		if err != nil {
			return fmt.Errorf("credential for %s: %w", cred.Host, err)
		}
		ps.fetch = true
		entries = append(entries, credEntry{cred: cred, header: header, source: ps})
	}

	const maxConcurrentFetches = 16
	fetchCtx, cancelFetches := context.WithCancel(ctx)
	defer cancelFetches()
	var wg sync.WaitGroup
	var firstFailure sync.Once
	var failed *pendingSource
	slots := make(chan struct{}, maxConcurrentFetches)
	for _, ps := range unique {
		if !ps.fetch {
			continue
		}
		slots <- struct{}{}
		if fetchCtx.Err() != nil {
			<-slots
			ps.err = fetchCtx.Err()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			ps.val, ps.err = s.fetchAtStartup(fetchCtx, ps.src)
			if ps.err != nil {
				firstFailure.Do(func() {
					failed = ps
					cancelFetches()
				})
			}
		}()
	}
	wg.Wait()

	for _, e := range entries {
		if e.source != nil && e.source.err != nil && (failed == nil || e.source == failed) {
			return fetchError(e.cred, e.pg, e.source.err)
		}
	}

	refreshMap := make(map[*pendingSource]*pendingRefresh)
	var refreshOrder []*pendingSource
	for _, e := range entries {
		if e.pg {
			var resolver proxy.PostgresCredentialResolver
			if e.neon != nil {
				resolver = e.neon
			} else {
				resolver = proxy.NewStaticPostgresResolver(e.source.val)
			}
			s.proxy.SetPostgresResolver(e.cred.Host, resolver)
			continue
		}

		if e.resolver != nil {
			policy := credentialHeader(e.cred, e.header, "")
			policy.Resolver = e.resolver
			if err := s.proxy.SetCredentialResolverEntry(policy, e.stripHeaders...); err != nil {
				return fmt.Errorf("credential for %s: %w", e.cred.Host, err)
			}
			continue
		}

		// For Authorization headers, ensure the value includes an auth
		// scheme prefix. In the CLI flow, providers handle this (e.g.,
		// GitHub provider prepends "Bearer "). The gatekeeper bypasses
		// providers, so we auto-detect the scheme from the token format.
		val := e.source.val
		if strings.EqualFold(e.header, "Authorization") {
			val = ensureAuthScheme(val, e.cred.Prefix, e.cred.Format)
		}
		if err := s.setCredential(e.cred, e.header, val); err != nil {
			return fmt.Errorf("credential for %s: %w", e.cred.Host, err)
		}

		if rs, ok := e.source.src.(credentialsource.RefreshingSource); ok {
			if pr, ok := refreshMap[e.source]; ok {
				pr.creds = append(pr.creds, e.cred)
			} else {
				refreshMap[e.source] = &pendingRefresh{src: rs, creds: []CredentialConfig{e.cred}}
				refreshOrder = append(refreshOrder, e.source)
			}
		}
	}

	for _, ps := range unique {
		if c, ok := ps.src.(io.Closer); ok {
			s.closers = append(s.closers, c)
		}
	}
	s.closers = append(s.closers, neons...)
	for _, ps := range refreshOrder {
		s.pendingRefreshes = append(s.pendingRefreshes, *refreshMap[ps])
	}
	return nil
}

// startupFetchTimeout bounds one credential fetch during New.
const startupFetchTimeout = 10 * time.Second

// startupRetrier is a credential source whose first fetch can fail for a
// short time after the process starts, such as a source with ambient cloud
// credentials that waits for the GKE metadata server.
type startupRetrier interface {
	// StartupRetryWindow returns how long New keeps retrying a failed
	// fetch.
	StartupRetryWindow() time.Duration
}

// fetchAtStartup fetches src once. When src is a startupRetrier, a failed
// fetch is retried with the refresh loop's backoff until the source's window
// ends, and no Fetch context outlives the window. Work inside Fetch that
// takes no context, such as ADC detection, can still run past it by its own
// timeouts. It returns the last error.
func (s *Server) fetchAtStartup(ctx context.Context, src credentialsource.CredentialSource) (string, error) {
	r, ok := src.(startupRetrier)
	if !ok || r.StartupRetryWindow() <= 0 {
		c, cancel := context.WithTimeout(ctx, startupFetchTimeout)
		defer cancel()
		return src.Fetch(c)
	}
	deadline := time.Now().Add(r.StartupRetryWindow())
	var backoff time.Duration
	for {
		c, cancel := context.WithTimeout(ctx, min(startupFetchTimeout, time.Until(deadline)))
		val, err := src.Fetch(c)
		cancel()
		if err == nil || ctx.Err() != nil {
			return val, err
		}
		backoff = nextBackoff(backoff)
		if backoff >= time.Until(deadline) {
			return "", err
		}
		s.log().Warn("credential fetch failed at startup, retrying",
			"source", src.Type(),
			"backoff", backoff.String(),
			"error", err)
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", err
		case <-timer.C:
		}
	}
}

// maxFetchBackoff caps the wait between failed credential fetches.
const maxFetchBackoff = 60 * time.Second

// nextBackoff returns the wait after another failed fetch, given the
// previous wait (zero after a success): 1s, then double the previous wait
// capped at maxFetchBackoff, plus up to 25% jitter.
func nextBackoff(prev time.Duration) time.Duration {
	next := time.Second
	if prev > 0 {
		next = min(prev*2, maxFetchBackoff)
	}
	return next + time.Duration(rand.Int64N(int64(next)/4))
}

// fetchError never includes the credential value.
func fetchError(cred CredentialConfig, postgres bool, err error) error {
	if postgres {
		return fmt.Errorf("postgres credential for %s: fetch failed: %w", cred.Host, err)
	}
	return fmt.Errorf("credential for %s: fetch failed: %w", cred.Host, err)
}

// startCredentialRefresh starts a background goroutine that periodically
// re-fetches a credential from a RefreshingSource and hot-swaps it on the
// proxy for every host in creds. When multiple hosts share a source (e.g.,
// api.github.com and github.com both using the same github-app), a single
// goroutine refreshes the token and applies it to all of them.
func (s *Server) startCredentialRefresh(ctx context.Context, src credentialsource.RefreshingSource, creds []CredentialConfig) {
	s.refreshWG.Add(1)
	go func() {
		defer s.refreshWG.Done()
		backoff := time.Duration(0)

		for {
			var wait time.Duration
			if backoff > 0 {
				wait = backoff
			} else {
				wait = refreshInterval(src.TTL())
			}

			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}

			fetchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			rawVal, err := src.Fetch(fetchCtx)
			cancel()

			if ctx.Err() != nil {
				return
			}
			if err != nil {
				backoff = nextBackoff(backoff)
				var hosts, grants []string
				for _, c := range creds {
					hosts = append(hosts, c.Host)
					grants = append(grants, c.Grant)
				}
				s.log().Warn("credential refresh failed, retrying",
					"hosts", strings.Join(hosts, ","),
					"grants", strings.Join(grants, ","),
					"backoff", backoff.String(),
					"error", err)
				continue
			}

			backoff = 0
			ttl := src.TTL()
			for _, cred := range creds {
				header := cred.Header
				if header == "" {
					header = "Authorization"
				}
				val := rawVal
				if strings.EqualFold(header, "Authorization") {
					val = ensureAuthScheme(val, cred.Prefix, cred.Format)
				}
				if err := s.updateCredential(cred, header, val); err != nil {
					s.log().Warn("credential refresh produced invalid policy", "host", cred.Host, "grant", cred.Grant, "error", err)
					continue
				}
				s.log().Debug("credential refreshed",
					"host", cred.Host,
					"grant", cred.Grant,
					"ttl", ttl.String())
			}
		}
	}()
}

func (s *Server) setCredential(cred CredentialConfig, header, value string) error {
	return s.proxy.SetCredentialEntry(credentialHeader(cred, header, value))
}

func (s *Server) updateCredential(cred CredentialConfig, header, value string) error {
	return s.proxy.UpdateCredentialEntry(credentialHeader(cred, header, value))
}

func credentialHeader(cred CredentialConfig, header, value string) proxy.CredentialHeader {
	entry := proxy.CredentialHeader{
		Host: cred.Host, Header: cred.Header, Name: header, Value: value,
		Prefix: cred.Prefix, Format: cred.Format, Source: cred.Source, Postgres: cred.Postgres,
		Grant: cred.Grant, AllowInsecure: cred.AllowInsecure,
		AddHeaders: cred.AddHeaders, RemoveHeaders: cred.RemoveHeaders,
	}
	if cred.Match != nil {
		match := proxy.RequestMatch(*cred.Match)
		entry.Match = &match
	}
	return entry
}

func allowInsecureResolver(r proxy.CredentialResolver, allow bool) proxy.CredentialResolver {
	if !allow {
		return r
	}
	return func(ctx context.Context, proxyReq, innerReq *http.Request, host string) ([]proxy.CredentialHeader, error) {
		creds, err := r(ctx, proxyReq, innerReq, host)
		for i := range creds {
			creds[i].AllowInsecure = true
		}
		return creds, err
	}
}

var refreshFloor = 30 * time.Second

// refreshInterval returns 75% of TTL, floored at refreshFloor.
func refreshInterval(ttl time.Duration) time.Duration {
	return max(ttl*3/4, refreshFloor)
}

// ensureAuthScheme ensures a credential value has an auth scheme prefix
// suitable for an Authorization header.
//
// When format is "basic", the value is encoded as HTTP Basic auth:
// "Basic base64(prefix:value)". The prefix field is the username
// (e.g., "x-access-token" for GitHub git smart HTTP).
//
// Otherwise, if the value already contains a scheme (e.g., "Bearer xxx",
// "token xxx"), it is returned unchanged. If prefix is set explicitly,
// it is used as the scheme. Otherwise the scheme is auto-detected from
// known GitHub token prefixes, defaulting to "Bearer".
func ensureAuthScheme(val, prefix, format string) string {
	if strings.EqualFold(format, "basic") {
		encoded := base64.StdEncoding.EncodeToString([]byte(prefix + ":" + val))
		return "Basic " + encoded
	}

	// If the value already has a scheme prefix, leave it alone.
	// Auth schemes are a single token followed by a space (RFC 7235).
	if i := strings.IndexByte(val, ' '); i > 0 {
		scheme := val[:i]
		// Looks like "Bearer xxx" or "token xxx" — already prefixed.
		if isAuthScheme(scheme) {
			return val
		}
	}

	if prefix != "" {
		return prefix + " " + val
	}

	// Auto-detect from known GitHub token prefixes.
	switch {
	case strings.HasPrefix(val, "ghp_"), strings.HasPrefix(val, "ghs_"):
		// Classic PAT and App installation tokens use "token" scheme.
		return "token " + val
	case strings.HasPrefix(val, "gho_"), strings.HasPrefix(val, "github_pat_"):
		// OAuth and fine-grained PAT tokens use "Bearer" scheme.
		return "Bearer " + val
	default:
		return "Bearer " + val
	}
}

// isAuthScheme returns true if s looks like a valid HTTP auth scheme.
// Auth schemes start with a letter and contain only letters, digits, hyphens,
// and underscores (token68 subset per RFC 7235).
func isAuthScheme(s string) bool {
	if len(s) == 0 {
		return false
	}
	// Must start with a letter.
	c := s[0]
	if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
		return false
	}
	for _, c := range s[1:] {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// Start starts the proxy. It blocks until the context is canceled.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return fmt.Errorf("server already started")
	}
	s.started = true
	s.mu.Unlock()

	// Resolve host defaults and decide whether proxy and postgres share one
	// listener (see resolveListenTopology's doc comment): equal, non-zero
	// ports on matching hosts is the entire declaration — there's no
	// separate flag. New already validated this at construction time from
	// the same function, so an error here would only surface if cfg were
	// mutated after New returned.
	topology, err := resolveListenTopology(s.cfg)
	if err != nil {
		return err
	}
	host := topology.proxyHost

	// Start proxy listener.
	addr := fmt.Sprintf("%s:%d", host, s.cfg.Proxy.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("starting proxy listener: %w", err)
	}

	// GCE deployments sit behind a GCP global TCP Proxy load balancer, which
	// terminates the client TCP connection and dials gatekeeper from its own
	// front-end IP (35.191.0.0/16) — so without this, the client_ip request-log
	// attribute always shows the LB, never the real client. When enabled, the
	// LB prepends a PROXY protocol v1/v2 header naming the real source
	// address; wrapping the listener here rewrites each accepted conn's
	// RemoteAddr() to that address before http.Server (and therefore every
	// request-logging path, including CONNECT-intercepted inner requests,
	// which all log from the outer request's RemoteAddr) ever sees it. See
	// proxy.WrapProxyProtocolListener for the fail-open USE policy, the 10s
	// header-read timeout, and the malformed-header debug log — the Postgres
	// data-plane listener (or, when topology.multiplex is true, this same
	// shared listener) uses this exact same helper.
	if s.cfg.Proxy.ProxyProtocol {
		ln = proxy.WrapProxyProtocolListener(ln)
	}

	if topology.multiplex {
		s.log().Info("proxy and postgres multiplexed on one listener", "addr", ln.Addr().String(), "version", s.version)
	} else {
		s.log().Info("gatekeeper listening", "addr", ln.Addr().String(), "version", s.version)
	}

	s.mu.Lock()
	s.proxyLn = ln
	s.proxyAddr = ln.Addr().String()
	s.mu.Unlock()

	otelHandler, err := proxy.NewOTelHandler(&healthHandler{next: s.proxy}, proxy.OTelOptions{})
	if err != nil {
		s.log().Warn("some otel instruments are disabled", "error", err)
	}

	// Start proxy HTTP server with health check wrapper.
	s.proxyServer = &http.Server{
		Handler:           otelHandler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// WriteTimeout is intentionally omitted for the proxy server.
		// CONNECT tunnels are long-lived, and a write timeout would kill
		// idle but valid connections.
	}

	if topology.multiplex {
		// resolveListenTopology already confirmed proxy.port == postgres.port,
		// matching hosts, and matching proxy_protocol settings, so ln alone
		// (already PROXY-protocol-wrapped above if configured) carries both
		// planes. NewDemux classifies each connection by its first bytes
		// (proxy/demux.go) and routes it to one of two virtual listeners;
		// http.Server.Serve and PostgresServer.StartListener run completely
		// unmodified against those, unaware they aren't backed by a real
		// socket.
		dx := proxy.NewDemux(ln)
		s.demux = dx

		go func() { _ = s.proxyServer.Serve(dx.HTTPListener()) }()

		pg := proxy.NewPostgresServer(s.proxy)
		if err := pg.StartListener(dx.PostgresListener()); err != nil {
			// Tear down the already-running HTTP server and the demux's real
			// listener so a postgres wiring failure doesn't leak either.
			_ = dx.Close()
			s.abortProxyServer()
			return fmt.Errorf("starting postgres listener: %w", err)
		}
		s.mu.Lock()
		s.pgServer = pg
		s.pgAddr = pg.Addr()
		s.mu.Unlock()
		s.log().Info("gatekeeper postgres listener", "addr", pg.Addr(), "subsystem", "proxy")
	} else {
		go func() { _ = s.proxyServer.Serve(ln) }()

		// Start the Postgres data-plane listener if configured.
		if s.cfg.Postgres != nil {
			pgAddr := fmt.Sprintf("%s:%d", topology.pgHost, s.cfg.Postgres.Port)
			pgLn, err := net.Listen("tcp", pgAddr)
			if err != nil {
				// Tear down the already-running HTTP server so a postgres bind
				// failure doesn't leak the HTTP listener. http.Server.Shutdown
				// closes the listener it was Serve-ing, so closing the server is
				// sufficient — closing ln again here would race the Serve goroutine.
				s.abortProxyServer()
				return fmt.Errorf("starting postgres listener: %w", err)
			}
			// Wrap before StartListener: the PROXY header arrives as the very
			// first bytes on the wire, ahead of the client's SSLRequest, so the
			// listener must be PROXY-protocol-aware from the first Accept. See
			// proxy.WrapProxyProtocolListener — same fail-open USE policy, 10s
			// header-read timeout, and malformed-header debug log as the HTTP
			// listener above.
			if s.cfg.Postgres.ProxyProtocol {
				pgLn = proxy.WrapProxyProtocolListener(pgLn)
			}
			pg := proxy.NewPostgresServer(s.proxy)
			if err := pg.StartListener(pgLn); err != nil {
				_ = pgLn.Close()
				s.abortProxyServer()
				return fmt.Errorf("starting postgres listener: %w", err)
			}
			s.mu.Lock()
			s.pgServer = pg
			s.pgAddr = pg.Addr()
			s.mu.Unlock()
			s.log().Info("gatekeeper postgres listener", "addr", pg.Addr(), "subsystem", "proxy")
		}
	}

	// Start background refresh goroutines for any RefreshingSource credentials.
	s.mu.Lock()
	if !s.stopping {
		refreshCtx, refreshCancel := context.WithCancel(context.Background())
		s.refreshCancel = refreshCancel
		for _, pr := range s.pendingRefreshes {
			s.startCredentialRefresh(refreshCtx, pr.src, pr.creds)
		}
	}
	s.mu.Unlock()
	s.pendingRefreshes = nil

	// Block until context canceled, then shut down.
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.Stop(shutdownCtx)
}

// Stop gracefully shuts down the proxy server and all background refresh
// goroutines. It waits for in-flight refreshes before closing credential
// sources, up to ctx; if ctx expires first the sources stay open.
func (s *Server) Stop(ctx context.Context) error {
	if s.proxy != nil {
		defer s.proxy.CloseIdleConnections()
		defer s.proxy.CloseExchangeLog(ctx)
	}
	s.mu.Lock()
	s.stopping = true
	cancelRefresh := s.refreshCancel
	s.mu.Unlock()
	if cancelRefresh != nil {
		cancelRefresh()
	}
	drained := make(chan struct{})
	go func() {
		s.refreshWG.Wait()
		close(drained)
	}()
	select {
	case <-drained:
		for _, c := range s.closers {
			if err := c.Close(); err != nil {
				s.log().Warn("credential source close failed", "error", err)
			}
		}
	case <-ctx.Done():
		s.log().Warn("credential refresh did not stop before the shutdown deadline; sources left open")
	}
	if s.demux != nil {
		// Stop accepting new connections on the shared listener immediately.
		// This deliberately does not close the demux's virtual listeners
		// (Demux.StopAccepting, not Close): pgServer.Shutdown and
		// proxyServer.Shutdown below each close the virtual listener they own
		// as part of their own graceful drain, and closing it out from under
		// them here first would race their own closed-flag bookkeeping — see
		// StopAccepting's doc comment in proxy/demux.go.
		_ = s.demux.StopAccepting()
	}
	// Drain both planes concurrently so each gets the full ctx budget rather
	// than the Postgres drain eating into the HTTP server's deadline.
	var wg sync.WaitGroup
	var httpErr error
	if s.pgServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.pgServer.Shutdown(ctx); err != nil {
				s.log().Warn("postgres listener shutdown timed out; active connections were closed", "error", err)
			}
		}()
	}
	if s.proxyServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			httpErr = s.proxyServer.Shutdown(ctx)
		}()
	}
	var connsErr error
	if s.proxy != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			connsErr = s.proxy.CloseConnections(ctx)
		}()
	}
	wg.Wait()
	if httpErr == nil {
		httpErr = connsErr
	}
	return httpErr
}

// abortProxyServer tears down the HTTP server and its hijacked connections
// after a failed Start.
func (s *Server) abortProxyServer() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.proxyServer.Shutdown(ctx)
	_ = s.proxy.CloseConnections(ctx)
}

// ProxyAddr returns the proxy listener's actual address (host:port).
// Returns empty string if the proxy has not started.
func (s *Server) ProxyAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.proxyAddr
}

// PostgresAddr returns the Postgres data-plane listener's actual address
// (host:port). Returns empty string if no Postgres listener is configured or
// it has not started.
func (s *Server) PostgresAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pgAddr
}
