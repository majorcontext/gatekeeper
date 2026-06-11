package proxy

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/majorcontext/gatekeeper/credentialsource"
)

// Compile-time check that the Neon resolver satisfies the proxy-side interface.
var _ PostgresCredentialResolver = (*credentialsource.NeonResolver)(nil)

func TestPostgresResolverLookup(t *testing.T) {
	p := NewProxy()
	neon := NewStaticPostgresResolver("neon-pass")
	other := NewStaticPostgresResolver("other-pass")
	p.SetPostgresResolver("*.neon.tech", neon)
	p.SetPostgresResolver("db.internal", other)

	tests := []struct {
		host string
		want PostgresCredentialResolver
	}{
		{"ep-foo-123.us-east-2.aws.neon.tech", neon},
		{"ep-foo.aws.neon.tech:5432", neon}, // host:port input — port is stripped before matching
		{"db.internal", other},
		{"example.com", nil},
	}
	for _, tt := range tests {
		got := p.postgresResolverForHost(nil, tt.host)
		if got != tt.want {
			t.Errorf("postgresResolverForHost(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestPostgresResolverRunContextOverridesProxy(t *testing.T) {
	p := NewProxy()
	proxyLevel := NewStaticPostgresResolver("proxy-pass")
	runLevel := NewStaticPostgresResolver("run-pass")
	p.SetPostgresResolver("*.neon.tech", proxyLevel)

	rc := &RunContextData{
		PostgresResolvers: []PostgresResolverEntry{{Pattern: "*.neon.tech", Resolver: runLevel}},
	}
	if got := p.postgresResolverForHost(rc, "ep-foo.aws.neon.tech"); got != runLevel {
		t.Errorf("run context resolver not preferred: got %v", got)
	}
	if got := p.postgresResolverForHost(rc, "db.other.com"); got != nil {
		t.Errorf("expected nil for unmatched host with run context, got %v", got)
	}
}

func TestPostgresResolverRunContextWithoutResolversBlocksProxyLevel(t *testing.T) {
	p := NewProxy()
	p.SetPostgresResolver("*.neon.tech", NewStaticPostgresResolver("proxy-pass"))

	// A run context with no Postgres resolvers means the run was granted no
	// Postgres access — it must not inherit proxy-level resolvers.
	for _, rc := range []*RunContextData{
		{},
		{PostgresResolvers: []PostgresResolverEntry{}},
	} {
		if got := p.postgresResolverForHost(rc, "ep-foo.aws.neon.tech"); got != nil {
			t.Errorf("run context without resolvers fell back to proxy-level resolver: got %v", got)
		}
	}
}

func TestStaticPostgresResolver(t *testing.T) {
	r := NewStaticPostgresResolver("pw")
	got, err := r.ResolvePassword(context.Background(), "any.host", "u", "d")
	if err != nil || got != "pw" {
		t.Fatalf("ResolvePassword = %q, %v; want \"pw\", nil", got, err)
	}
	r.InvalidatePassword("any.host", "u", "d") // must not panic
}

func TestConnectPostgresUpstreamSCRAM(t *testing.T) {
	fake := startFakePostgres(t, "ep-foo-123.aws.neon.tech", "app_rw", "real-password")
	up, err := connectPostgresUpstream(context.Background(), upstreamParams{
		dialAddr:          fake.addr,
		serverName:        "ep-foo-123.aws.neon.tech",
		rootCAs:           fake.certPool,
		user:              "app_rw",
		password:          "real-password",
		startupParameters: map[string]string{"user": "app_rw", "database": "appdb"},
	})
	if err != nil {
		t.Fatalf("connectPostgresUpstream: %v", err)
	}
	defer up.conn.Close()
	if len(up.postAuthFrames) == 0 {
		t.Error("expected buffered post-auth frames")
	}
	// last frame must be ReadyForQuery: type byte 'Z'
	last := up.postAuthFrames[len(up.postAuthFrames)-1]
	if len(last) == 0 || last[0] != 'Z' {
		t.Errorf("last frame type = %q, want 'Z' (ReadyForQuery)", last[0])
	}
	// first frame must be AuthenticationOk: type byte 'R'
	first := up.postAuthFrames[0]
	if len(first) == 0 || first[0] != 'R' {
		t.Errorf("first frame type = %q, want 'R' (AuthenticationOk)", first[0])
	}
}

func TestConnectPostgresUpstreamBadPassword(t *testing.T) {
	fake := startFakePostgres(t, "ep-foo-123.aws.neon.tech", "app_rw", "real-password")
	_, err := connectPostgresUpstream(context.Background(), upstreamParams{
		dialAddr: fake.addr, serverName: "ep-foo-123.aws.neon.tech", rootCAs: fake.certPool,
		user: "app_rw", password: "wrong",
		startupParameters: map[string]string{"user": "app_rw", "database": "appdb"},
	})
	if !errors.Is(err, errUpstreamAuthFailed) {
		t.Fatalf("err = %v, want errUpstreamAuthFailed", err)
	}
}

func TestConnectPostgresUpstreamUnknownUser(t *testing.T) {
	// fake sends 28000 for unknown role — must also map to errUpstreamAuthFailed
	fake := startFakePostgres(t, "ep-foo-123.aws.neon.tech", "app_rw", "real-password")
	_, err := connectPostgresUpstream(context.Background(), upstreamParams{
		dialAddr: fake.addr, serverName: "ep-foo-123.aws.neon.tech", rootCAs: fake.certPool,
		user: "other_user", password: "real-password",
		startupParameters: map[string]string{"user": "other_user", "database": "appdb"},
	})
	if !errors.Is(err, errUpstreamAuthFailed) {
		t.Fatalf("err = %v, want errUpstreamAuthFailed", err)
	}
}

func TestConnectPostgresUpstreamNonAuthError(t *testing.T) {
	// The upstream completes TLS and SCRAM successfully, then reports a
	// non-auth failure (53300 too_many_connections) before AuthenticationOk.
	// Task 8's retry logic only re-resolves credentials for auth failures, so
	// this must NOT be classified as errUpstreamAuthFailed — otherwise the proxy
	// would needlessly invalidate a valid cached password and retry.
	fake := startFakePostgres(t, "ep-foo-123.aws.neon.tech", "app_rw", "real-password",
		withFailPostAuth("53300"))
	_, err := connectPostgresUpstream(context.Background(), upstreamParams{
		dialAddr: fake.addr, serverName: "ep-foo-123.aws.neon.tech", rootCAs: fake.certPool,
		user: "app_rw", password: "real-password",
		startupParameters: map[string]string{"user": "app_rw", "database": "appdb"},
	})
	if err == nil {
		t.Fatal("expected a non-auth upstream error, got nil")
	}
	if errors.Is(err, errUpstreamAuthFailed) {
		t.Fatalf("non-auth upstream error misclassified as auth failure: %v", err)
	}
}

func TestConnectPostgresUpstreamNoSupportedSASLMechanism(t *testing.T) {
	// The upstream advertises only a mechanism the proxy cannot perform. The
	// proxy must return an error rather than panicking or treating the missing
	// mechanism as either success or an auth failure.
	fake := startFakePostgres(t, "ep-foo-123.aws.neon.tech", "app_rw", "real-password",
		withAuthMechanisms("SCRAM-SHA-256-PLUS"))
	_, err := connectPostgresUpstream(context.Background(), upstreamParams{
		dialAddr: fake.addr, serverName: "ep-foo-123.aws.neon.tech", rootCAs: fake.certPool,
		user: "app_rw", password: "real-password",
		startupParameters: map[string]string{"user": "app_rw", "database": "appdb"},
	})
	if err == nil {
		t.Fatal("expected an error when upstream offers no supported SASL mechanism, got nil")
	}
	if errors.Is(err, errUpstreamAuthFailed) {
		t.Fatalf("missing-mechanism error must not be classified as auth failure: %v", err)
	}
}

func TestConnectPostgresUpstreamRejectsUntrustedCert(t *testing.T) {
	fake := startFakePostgres(t, "ep-foo-123.aws.neon.tech", "app_rw", "real-password")
	_, err := connectPostgresUpstream(context.Background(), upstreamParams{
		dialAddr: fake.addr, serverName: "ep-foo-123.aws.neon.tech", rootCAs: x509.NewCertPool(),
		user: "app_rw", password: "real-password",
		startupParameters: map[string]string{"user": "app_rw", "database": "appdb"},
	})
	if err == nil {
		t.Fatal("expected TLS verification failure")
	}
	if errors.Is(err, errUpstreamAuthFailed) {
		t.Fatal("TLS failure must not be classified as auth failure")
	}
}
