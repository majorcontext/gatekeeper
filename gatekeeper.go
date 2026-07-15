// Package gatekeeper provides a standalone credential-injecting TLS proxy.
//
// Credentials are pre-configured in gatekeeper.yaml and injected for all
// proxied requests matching the host. Access control is via network policy
// (who can reach the proxy) and an optional static auth token.
//
// For per-caller credential isolation (run registration, token-scoped
// credentials), use the daemon package, which provides a management API
// over a Unix socket.
package gatekeeper

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/majorcontext/gatekeeper/credentialsource"
	"github.com/majorcontext/gatekeeper/proxy"

	"github.com/pires/go-proxyproto"
	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// defaultProxyHost is the default bind address when none is configured.
// Binding to localhost prevents accidental exposure on all interfaces.
const defaultProxyHost = "127.0.0.1"

// configureLogging sets up slog based on the LogConfig.
// Returns a cleanup function to close any opened log file and an error.
func configureLogging(cfg LogConfig) (func(), error) {
	var level slog.Level
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	var (
		w       *os.File
		cleanup func()
	)
	switch strings.ToLower(cfg.Output) {
	case "", "stderr":
		w = os.Stderr
	case "stdout":
		w = os.Stdout
	default:
		f, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("opening log output %q: %w", cfg.Output, err)
		}
		w = f
		cleanup = func() { f.Close() }
	}

	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if strings.ToLower(cfg.Format) == "json" {
		handler = slog.NewJSONHandler(w, opts)
	} else {
		handler = slog.NewTextHandler(w, opts)
	}
	handler = newMultiHandler(handler, newOTelDiagnosticFilter(otelslog.NewHandler("gatekeeper")))
	slog.SetDefault(slog.New(handler))
	return cleanup, nil
}

// OTelDiagnosticKey marks a log record as gatekeeper's own diagnostic about
// the OTel pipeline itself — currently, the OTel SDK/export error records
// cmd/gatekeeper's logOTelError logs at DEBUG. configureLogging's otelslog
// bridge handler excludes any record carrying this attribute (see
// newOTelDiagnosticFilter): without the exclusion, a failed OTel log export
// produces a DEBUG diagnostic that is itself fanned out to the same OTel
// log-export pipeline that just failed, so it gets queued, fails on the
// next export attempt, produces another diagnostic, and so on indefinitely
// while a collector is unreachable. The console/file handler still receives
// every record regardless of this marker.
const OTelDiagnosticKey = "otel_diagnostic"

// otelDiagnosticFilter wraps a slog.Handler — the otelslog bridge — and
// drops any record carrying OTelDiagnosticKey before it reaches the wrapped
// handler, keeping gatekeeper's own OTel diagnostics out of the OTel log
// export pipeline. Records without the marker pass through unchanged.
type otelDiagnosticFilter struct {
	slog.Handler
}

func newOTelDiagnosticFilter(h slog.Handler) slog.Handler {
	return &otelDiagnosticFilter{Handler: h}
}

func (f *otelDiagnosticFilter) Handle(ctx context.Context, record slog.Record) error {
	marked := false
	record.Attrs(func(a slog.Attr) bool {
		if a.Key == OTelDiagnosticKey {
			marked = true
			return false
		}
		return true
	})
	if marked {
		return nil
	}
	return f.Handler.Handle(ctx, record)
}

func (f *otelDiagnosticFilter) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &otelDiagnosticFilter{Handler: f.Handler.WithAttrs(attrs)}
}

func (f *otelDiagnosticFilter) WithGroup(name string) slog.Handler {
	return &otelDiagnosticFilter{Handler: f.Handler.WithGroup(name)}
}

// multiHandler fans out log records to multiple slog handlers.
type multiHandler struct {
	handlers []slog.Handler
}

func newMultiHandler(handlers ...slog.Handler) *multiHandler {
	return &multiHandler{handlers: handlers}
}

func (m *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range m.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (m *multiHandler) Handle(ctx context.Context, record slog.Record) error {
	var errs []error
	for _, h := range m.handlers {
		if h.Enabled(ctx, record.Level) {
			if err := h.Handle(ctx, record); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (m *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		handlers[i] = h.WithAttrs(attrs)
	}
	return &multiHandler{handlers: handlers}
}

func (m *multiHandler) WithGroup(name string) slog.Handler {
	handlers := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		handlers[i] = h.WithGroup(name)
	}
	return &multiHandler{handlers: handlers}
}

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
	logCleanup  func()                // closes log file if output is a file path

	pendingRefreshes []pendingRefresh
	refreshCancel    context.CancelFunc
	closers          []io.Closer // credential sources that hold resources

	// resolveSource overrides ResolveSource for testing. When non-nil,
	// loadCredentials calls this instead of ResolveSource.
	resolveSource func(SourceConfig) (credentialsource.CredentialSource, error)

	mu      sync.Mutex
	started bool
}

// New creates a new Gate Keeper server from the given configuration.
// The context is used for credential fetching (e.g., AWS Secrets Manager)
// and can be used to cancel startup if the process receives a signal.
// The version string is included in the startup log line; pass "" if unknown.
func New(ctx context.Context, cfg *Config, version string) (*Server, error) {
	// Configure structured logging before anything else.
	logCleanup, err := configureLogging(cfg.Log)
	if err != nil {
		return nil, err
	}

	p := proxy.NewProxy()

	s := &Server{
		version:    version,
		proxy:      p,
		logCleanup: logCleanup,
		cfg:        cfg,
	}

	// Load TLS CA for HTTPS interception. Without a CA, the proxy cannot
	// inject credentials into HTTPS requests (CONNECT tunnels pass through).
	if cfg.TLS.CACert != "" && cfg.TLS.CAKey != "" {
		certPEM, err := os.ReadFile(cfg.TLS.CACert)
		if err != nil {
			return nil, fmt.Errorf("reading CA cert: %w", err)
		}
		keyPEM, err := os.ReadFile(cfg.TLS.CAKey)
		if err != nil {
			return nil, fmt.Errorf("reading CA key: %w", err)
		}
		ca, err := proxy.LoadCA(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("loading CA: %w", err)
		}
		p.SetCA(ca)
	}

	// The Postgres data-plane listener terminates client TLS with CA-minted
	// certificates, so a CA is mandatory when it is configured.
	if cfg.Postgres != nil && (cfg.TLS.CACert == "" || cfg.TLS.CAKey == "") {
		return nil, fmt.Errorf("postgres listener requires tls.ca_cert and tls.ca_key to be configured")
	}

	// Load credentials from config and set directly on the proxy.
	// Credentials are fetched once at startup. For sources like
	// aws-secretsmanager, restart the process to pick up rotated values.
	if err := s.loadCredentials(ctx, cfg); err != nil {
		return nil, fmt.Errorf("loading credentials: %w", err)
	}

	// Canonical log line: one wide structured entry per request at completion.
	// Accumulates all request context (method, host, status, duration,
	// credentials, policy decisions, sizes) into a single log line for
	// grep-ability and dashboard extraction.
	p.SetLogger(func(data proxy.RequestLogData) {
		durationMS := float64(data.Duration.Nanoseconds()) / 1e6
		attrs := []slog.Attr{
			slog.String("request_id", data.RequestID),
			slog.String("http_method", data.Method),
			slog.String("http_host", data.Host),
			slog.String("http_path", data.Path),
			slog.Int("http_status", data.StatusCode),
			slog.Float64("duration_ms", durationMS),
			slog.String("proxy_type", data.RequestType),
		}
		if data.RunID != "" {
			attrs = append(attrs, slog.String("run_id", data.RunID))
		}
		if data.UserID != "" {
			attrs = append(attrs, slog.String("user_id", data.UserID))
		}
		if data.ClientAddr != "" {
			clientIP := data.ClientAddr
			if host, _, err := net.SplitHostPort(clientIP); err == nil {
				clientIP = host
			}
			attrs = append(attrs, slog.String("client_ip", clientIP))
		}
		if data.AuthInjected {
			attrs = append(attrs, slog.Bool("credential_injected", true))
			var headerNames []string
			for name := range data.InjectedHeaders {
				headerNames = append(headerNames, name)
			}
			slices.Sort(headerNames)
			attrs = append(attrs, slog.String("injected_headers", strings.Join(headerNames, ",")))
			if len(data.Grants) > 0 {
				sortedGrants := slices.Clone(data.Grants)
				slices.Sort(sortedGrants)
				attrs = append(attrs, slog.String("grants", strings.Join(sortedGrants, ",")))
			}
		}
		if data.Denied {
			attrs = append(attrs, slog.Bool("denied", true))
			attrs = append(attrs, slog.String("deny_reason", data.DenyReason))
		}
		if data.RequestSize >= 0 {
			attrs = append(attrs, slog.Int64("request_size", data.RequestSize))
		}
		if data.ResponseSize >= 0 {
			attrs = append(attrs, slog.Int64("response_size", data.ResponseSize))
		}
		if data.RequestMessages > 0 {
			attrs = append(attrs, slog.Int64("request_messages", data.RequestMessages))
		}
		if data.ResponseMessages > 0 {
			attrs = append(attrs, slog.Int64("response_messages", data.ResponseMessages))
		}
		if data.Err != nil {
			attrs = append(attrs, slog.String("error", data.Err.Error()))
		}

		// Append captured request headers as structured log attributes.
		if data.RequestHeaders != nil {
			for _, h := range cfg.Log.CaptureHeaders {
				if v := data.RequestHeaders.Get(h); v != "" {
					if len(v) > 256 {
						// Truncate at a valid UTF-8 boundary to avoid splitting multi-byte characters.
						v = v[:256]
						for len(v) > 0 && !utf8.ValidString(v) {
							v = v[:len(v)-1]
						}
					}
					key := strings.ReplaceAll(strings.ToLower(h), "-", "_")
					attrs = append(attrs, slog.String(key, v))
				}
			}
		}

		level := slog.LevelInfo
		if data.Err != nil || data.StatusCode >= 500 {
			level = slog.LevelError
		} else if data.Denied || data.StatusCode >= 400 {
			level = slog.LevelWarn
		}

		logCtx := context.Background()
		if data.Ctx != nil {
			logCtx = data.Ctx
		}
		args := make([]any, len(attrs))
		for i, a := range attrs {
			args[i] = a
		}
		slog.Log(logCtx, level, "request", args...)

		// OpenTelemetry span enrichment
		if data.Ctx != nil {
			span := trace.SpanFromContext(data.Ctx)
			if span.SpanContext().IsValid() {
				spanAttrs := []attribute.KeyValue{
					attribute.String("request_id", data.RequestID),
					attribute.Float64("duration_ms", durationMS),
					attribute.Bool("credential_injected", data.AuthInjected),
					attribute.String("proxy.request.type", data.RequestType),
					attribute.String("http.host", data.Host),
				}
				if data.RunID != "" {
					spanAttrs = append(spanAttrs, attribute.String("run_id", data.RunID))
				}
				if data.UserID != "" {
					spanAttrs = append(spanAttrs, attribute.String("user_id", data.UserID))
				}
				var headerNames []string
				for name := range data.InjectedHeaders {
					headerNames = append(headerNames, name)
				}
				slices.Sort(headerNames)
				if len(headerNames) > 0 {
					spanAttrs = append(spanAttrs, attribute.StringSlice("injected_headers", headerNames))
				}
				if len(data.Grants) > 0 {
					sortedGrants := slices.Clone(data.Grants)
					slices.Sort(sortedGrants)
					spanAttrs = append(spanAttrs, attribute.StringSlice("grants", sortedGrants))
				}
				if data.Denied {
					spanAttrs = append(spanAttrs, attribute.Bool("denied", true))
					spanAttrs = append(spanAttrs, attribute.String("deny_reason", data.DenyReason))
				}
				span.AddEvent("request.complete", trace.WithAttributes(spanAttrs...))
				if data.Err != nil {
					span.RecordError(data.Err)
				}

				if data.AuthInjected {
					for name := range data.InjectedHeaders {
						proxy.RecordCredentialInjection(data.Ctx, data.Host, name)
					}
				}
			}
		}
	})

	p.SetPolicyLogger(func(data proxy.PolicyLogData) {
		slog.Warn("policy denial",
			"run_id", data.RunID,
			"scope", data.Scope,
			"operation", data.Operation,
			"rule", data.Rule,
			"message", data.Message,
		)

		if data.Ctx != nil {
			span := trace.SpanFromContext(data.Ctx)
			if span.SpanContext().IsValid() {
				span.AddEvent("policy.denial", trace.WithAttributes(
					attribute.String("scope", data.Scope),
					attribute.String("operation", data.Operation),
					attribute.String("rule", data.Rule),
					attribute.String("message", data.Message),
				))
				proxy.RecordPolicyDenial(data.Ctx, data.Scope, data.Rule)
			}
		}
	})

	// Optional defense-in-depth: require a static token for proxy access.
	// Clients provide it via Proxy-Authorization header or
	// HTTP_PROXY=http://user:token@host.
	if cfg.Proxy.AuthToken != "" {
		p.SetAuthToken(cfg.Proxy.AuthToken)
	}

	// When actor_token_from is configured, each caller has a unique proxy
	// auth password validated by the STS — skip the static authToken check.
	for _, cred := range cfg.Credentials {
		if cred.Source.ActorTokenFrom != "" {
			p.SetDelegateAuth(true)
			break
		}
	}

	// Configure capture headers if specified.
	if len(cfg.Log.CaptureHeaders) > 0 {
		if err := p.SetCaptureHeaders(cfg.Log.CaptureHeaders); err != nil {
			return nil, fmt.Errorf("capture_headers: %w", err)
		}
	}

	// Configure network policy if specified.
	if cfg.Network.Policy != "" {
		p.SetNetworkPolicy(cfg.Network.Policy, cfg.Network.Allow, nil)
	}

	return s, nil
}

// loadCredentials resolves each credential from config and sets it on the proxy.
//
// Sources are deduped by SourceConfig: when multiple credentials share the same
// source (e.g., two hosts using the same github-app), a single Fetch is made at
// startup and a single background refresh goroutine is registered. The token is
// applied to all hosts that share the source.
func (s *Server) loadCredentials(ctx context.Context, cfg *Config) error {
	// Dedup sources: same SourceConfig → one Fetch, one refresh goroutine.
	type fetchedSource struct {
		src credentialsource.CredentialSource
		val string
	}
	fetched := make(map[SourceConfig]*fetchedSource)
	refreshMap := make(map[SourceConfig]*pendingRefresh)

	for _, cred := range cfg.Credentials {
		if cred.Host == "" {
			return fmt.Errorf("credential %q: host is required", cred.Grant)
		}

		// Postgres credentials use the data-plane listener, not HTTP header
		// injection, so they bypass the header/format logic below.
		if cred.Postgres != nil {
			if err := s.loadPostgresCredential(ctx, cred); err != nil {
				return err
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

		if cred.Format != "" && !strings.EqualFold(header, "Authorization") {
			return fmt.Errorf("credential for %s: format %q is only supported with the Authorization header", cred.Host, cred.Format)
		}

		// Reuse a previously fetched source with the same config, avoiding
		// redundant source construction (e.g., os.ReadFile for github-app keys).
		if fs, ok := fetched[cred.Source]; ok {
			val := fs.val
			if strings.EqualFold(header, "Authorization") {
				val = ensureAuthScheme(val, cred.Prefix, cred.Format)
			}
			s.proxy.SetCredentialWithGrant(cred.Host, header, val, cred.Grant)
			if _, ok := fs.src.(credentialsource.RefreshingSource); ok {
				refreshMap[cred.Source].creds = append(refreshMap[cred.Source].creds, cred)
			}
			continue
		}

		var src credentialsource.CredentialSource
		if s.resolveSource != nil {
			var err error
			src, err = s.resolveSource(cred.Source)
			if err != nil {
				return fmt.Errorf("credential for %s: %w", cred.Host, err)
			}
		} else {
			var resolver proxy.CredentialResolver
			var err error
			src, resolver, err = ResolveCredentialSource(cred)
			if err != nil {
				return fmt.Errorf("credential for %s: %w", cred.Host, err)
			}
			if resolver != nil {
				// Declare the subject header so the proxy still strips it
				// when a better-matched static credential outranks (and
				// therefore skips) this resolver.
				s.proxy.SetCredentialResolverWithStripHeaders(cred.Host, resolver, credentialResolverStripHeaders(cred)...)
				continue
			}
		}

		fetchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		val, fetchErr := src.Fetch(fetchCtx)
		cancel()
		if fetchErr != nil {
			return fmt.Errorf("credential for %s: fetch failed: %w", cred.Host, fetchErr)
		}
		fetched[cred.Source] = &fetchedSource{src: src, val: val}
		if c, ok := src.(io.Closer); ok {
			s.closers = append(s.closers, c)
		}

		// For Authorization headers, ensure the value includes an auth
		// scheme prefix. In the CLI flow, providers handle this (e.g.,
		// GitHub provider prepends "Bearer "). The gatekeeper bypasses
		// providers, so we auto-detect the scheme from the token format.
		if strings.EqualFold(header, "Authorization") {
			val = ensureAuthScheme(val, cred.Prefix, cred.Format)
		}

		s.proxy.SetCredentialWithGrant(cred.Host, header, val, cred.Grant)

		if rs, ok := src.(credentialsource.RefreshingSource); ok {
			refreshMap[cred.Source] = &pendingRefresh{src: rs, creds: []CredentialConfig{cred}}
		}
	}

	for _, pr := range refreshMap {
		s.pendingRefreshes = append(s.pendingRefreshes, *pr)
	}
	return nil
}

// loadPostgresCredential resolves a Postgres credential and registers a
// resolver for its host pattern on the proxy's data-plane listener.
//
// The "neon" resolver mints per-branch passwords lazily from the Neon API
// using the configured Source as the API key; nothing secret is fetched here.
// The "static" resolver fetches the password once at startup — that value is
// the database password and must never be logged.
func (s *Server) loadPostgresCredential(ctx context.Context, cred CredentialConfig) error {
	buildSource := func() (credentialsource.CredentialSource, error) {
		if s.resolveSource != nil {
			return s.resolveSource(cred.Source)
		}
		return ResolveSource(cred.Source)
	}

	var resolver proxy.PostgresCredentialResolver
	switch strings.ToLower(cred.Postgres.Resolver) {
	case "neon":
		src, err := buildSource()
		if err != nil {
			return fmt.Errorf("postgres credential for %s: %w", cred.Host, err)
		}
		if c, ok := src.(io.Closer); ok {
			s.closers = append(s.closers, c)
		}
		neon := &credentialsource.NeonResolver{APIKey: src, Project: cred.Postgres.Project}
		// Closed on shutdown (before the listener drain) so in-flight Neon API
		// calls are cancelled rather than holding up the drain.
		s.closers = append(s.closers, neon)
		resolver = neon
	case "static":
		src, err := buildSource()
		if err != nil {
			return fmt.Errorf("postgres credential for %s: %w", cred.Host, err)
		}
		if c, ok := src.(io.Closer); ok {
			s.closers = append(s.closers, c)
		}
		fetchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		val, fetchErr := src.Fetch(fetchCtx)
		cancel()
		if fetchErr != nil {
			// Never include the credential value in the error.
			return fmt.Errorf("postgres credential for %s: fetch failed: %w", cred.Host, fetchErr)
		}
		resolver = proxy.NewStaticPostgresResolver(val)
	default:
		return fmt.Errorf("postgres credential for %s: unknown resolver %q (valid values: \"neon\", \"static\")", cred.Host, cred.Postgres.Resolver)
	}

	s.proxy.SetPostgresResolver(cred.Host, resolver)
	return nil
}

// startCredentialRefresh starts a background goroutine that periodically
// re-fetches a credential from a RefreshingSource and hot-swaps it on the
// proxy for every host in creds. When multiple hosts share a source (e.g.,
// api.github.com and github.com both using the same github-app), a single
// goroutine refreshes the token and applies it to all of them.
func (s *Server) startCredentialRefresh(ctx context.Context, src credentialsource.RefreshingSource, creds []CredentialConfig) {
	go func() {
		backoff := time.Duration(0)
		const maxBackoff = 60 * time.Second

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

			if err != nil {
				if backoff == 0 {
					backoff = time.Second
				} else {
					backoff *= 2
					if backoff > maxBackoff {
						backoff = maxBackoff
					}
				}
				jitter := time.Duration(rand.Int64N(int64(backoff) / 4))
				backoff += jitter
				var hosts, grants []string
				for _, c := range creds {
					hosts = append(hosts, c.Host)
					grants = append(grants, c.Grant)
				}
				slog.Warn("credential refresh failed, retrying",
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
				s.proxy.SetCredentialWithGrant(cred.Host, header, val, cred.Grant)
				slog.Debug("credential refreshed",
					"host", cred.Host,
					"grant", cred.Grant,
					"ttl", ttl.String())
			}
		}
	}()
}

// refreshInterval returns 75% of TTL, floored at 30 seconds.
func refreshInterval(ttl time.Duration) time.Duration {
	return max(ttl*3/4, 30*time.Second)
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

	// Default to localhost if no host is configured.
	host := s.cfg.Proxy.Host
	if host == "" {
		host = defaultProxyHost
	}

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
	// which all log from the outer request's RemoteAddr) ever sees it.
	//
	// The policy is pinned to USE (rather than left at the library default)
	// so a connection without a PROXY header still passes through using its
	// real TCP peer address instead of being rejected — fail-open, so LB
	// health checks and direct probes of the port keep working.
	if s.cfg.Network.ProxyProtocol {
		ln = &proxyproto.Listener{
			Listener:          ln,
			ReadHeaderTimeout: 10 * time.Second,
			ConnPolicy: func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
				return proxyproto.USE, nil
			},
		}
		// go-proxyproto has no error-callback hook for header parse failures
		// in this version: ValidateHeader only runs against a *successfully*
		// parsed header, and header parsing itself is lazy — it happens
		// inside the returned Conn on the first Read/RemoteAddr, not in
		// Accept. A malformed header (as opposed to a merely absent one,
		// which is the correct, silent USE-policy fallback) therefore
		// surfaces only as an error from Conn.Read, which net/http treats as
		// a dead connection and closes without a trace. Wrap the listener so
		// that case gets one DEBUG log line instead of vanishing silently.
		ln = &proxyProtoLogListener{Listener: ln}
	}

	slog.Info("gatekeeper listening", "addr", ln.Addr().String(), "version", s.version)

	s.mu.Lock()
	s.proxyLn = ln
	s.proxyAddr = ln.Addr().String()
	s.mu.Unlock()

	// Start proxy HTTP server with health check wrapper.
	s.proxyServer = &http.Server{
		Handler:           proxy.OTelHandler(&healthHandler{next: s.proxy}),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// WriteTimeout is intentionally omitted for the proxy server.
		// CONNECT tunnels are long-lived, and a write timeout would kill
		// idle but valid connections.
	}
	go func() { _ = s.proxyServer.Serve(ln) }()

	// Start the Postgres data-plane listener if configured.
	if s.cfg.Postgres != nil {
		pgHost := s.cfg.Postgres.Host
		if pgHost == "" {
			pgHost = host // same default the HTTP listener resolved
		}
		pg := proxy.NewPostgresServer(s.proxy)
		pgAddr := fmt.Sprintf("%s:%d", pgHost, s.cfg.Postgres.Port)
		if err := pg.Start(pgAddr); err != nil {
			// Tear down the already-running HTTP server so a postgres bind
			// failure doesn't leak the HTTP listener. http.Server.Shutdown
			// closes the listener it was Serve-ing, so closing the server is
			// sufficient — closing ln again here would race the Serve goroutine.
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = s.proxyServer.Shutdown(shutdownCtx)
			cancel()
			return fmt.Errorf("starting postgres listener: %w", err)
		}
		s.mu.Lock()
		s.pgServer = pg
		s.pgAddr = pg.Addr()
		s.mu.Unlock()
		slog.Info("gatekeeper postgres listener", "addr", pg.Addr(), "subsystem", "proxy")
	}

	// Start background refresh goroutines for any RefreshingSource credentials.
	refreshCtx, refreshCancel := context.WithCancel(context.Background())
	s.refreshCancel = refreshCancel
	for _, pr := range s.pendingRefreshes {
		s.startCredentialRefresh(refreshCtx, pr.src, pr.creds)
	}
	s.pendingRefreshes = nil

	// Block until context canceled, then shut down.
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.Stop(shutdownCtx)
}

// proxyProtoLogListener wraps a *proxyproto.Listener so that a connection
// whose PROXY header fails to parse gets a single DEBUG log line before it's
// dropped. See the comment where this is constructed in Start for why the
// hook is needed at all.
type proxyProtoLogListener struct {
	net.Listener
}

func (l *proxyProtoLogListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	// Prefer the raw underlying TCP conn's address over conn.RemoteAddr():
	// on a *proxyproto.Conn, RemoteAddr() itself triggers header processing,
	// which would force a blocking header read here in Accept before the
	// peer has necessarily sent anything. Raw() has no such side effect.
	peer := conn.RemoteAddr()
	if pc, ok := conn.(*proxyproto.Conn); ok {
		peer = pc.Raw().RemoteAddr()
	}
	return &proxyProtoLogConn{Conn: conn, peer: peer}, nil
}

// proxyProtoLogConn wraps an accepted connection to detect and log genuine
// PROXY header parse failures. Header parsing is lazy: it happens inside the
// wrapped proxyproto.Conn on the first Read, not in Accept, and a parse
// failure surfaces only as an error from that Read. A connection that simply
// has no PROXY header at all is not an error here (proxyproto's USE policy
// falls back to the real peer address for it) and must stay quiet.
type proxyProtoLogConn struct {
	net.Conn
	peer net.Addr
	once sync.Once
}

func (c *proxyProtoLogConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil && !errors.Is(err, proxyproto.ErrNoProxyProtocol) && strings.HasPrefix(err.Error(), "proxyproto:") {
		c.once.Do(func() {
			slog.Debug("dropping connection: malformed PROXY protocol header", "peer", c.peer.String(), "err", err)
		})
	}
	return n, err
}

// Stop gracefully shuts down the proxy server and all background refresh goroutines.
func (s *Server) Stop(ctx context.Context) error {
	if s.refreshCancel != nil {
		s.refreshCancel()
	}
	for _, c := range s.closers {
		if err := c.Close(); err != nil {
			slog.Warn("credential source close failed", "error", err)
		}
	}
	if s.logCleanup != nil {
		defer s.logCleanup()
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
				slog.Warn("postgres listener shutdown timed out; active connections were closed", "error", err)
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
	wg.Wait()
	return httpErr
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
