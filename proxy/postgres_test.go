package proxy

import (
	"context"
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
