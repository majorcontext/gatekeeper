package proxy

import (
	"context"
	"net"
)

// postgresDefaultPort is the port used when matching Postgres host patterns.
const postgresDefaultPort = 5432

// PostgresCredentialResolver resolves a Postgres password for a specific
// upstream host, role, and database at connection time. Implementations
// must never log password values.
type PostgresCredentialResolver interface {
	// ResolvePassword returns the password the proxy should present to the
	// upstream server for the given host, user, and database.
	ResolvePassword(ctx context.Context, host, user, database string) (string, error)
	// InvalidatePassword drops any cached password for the tuple. The proxy
	// calls it after an upstream authentication failure, then retries once.
	InvalidatePassword(host, user, database string)
}

// PostgresResolverEntry binds a host pattern (hosts.go glob syntax) to a
// resolver. Patterns match hostname only; a pattern with an explicit port
// other than 5432 (e.g. "db.internal:5433") will never match.
type PostgresResolverEntry struct {
	Pattern  string
	Resolver PostgresCredentialResolver
}

// StaticPostgresResolver returns a fixed password for every connection.
type StaticPostgresResolver struct {
	password string
}

// NewStaticPostgresResolver creates a resolver that always returns password.
func NewStaticPostgresResolver(password string) *StaticPostgresResolver {
	return &StaticPostgresResolver{password: password}
}

// ResolvePassword returns the fixed password.
func (s *StaticPostgresResolver) ResolvePassword(ctx context.Context, host, user, database string) (string, error) {
	return s.password, nil
}

// InvalidatePassword is a no-op: static passwords are never cached.
func (s *StaticPostgresResolver) InvalidatePassword(host, user, database string) {}

// SetPostgresResolver registers a proxy-level Postgres credential resolver
// for hosts matching pattern. Calling again with the same pattern replaces
// the previous resolver. Patterns match hostname only; a pattern with an
// explicit port other than 5432 will never match.
func (p *Proxy) SetPostgresResolver(pattern string, r PostgresCredentialResolver) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, entry := range p.postgresResolvers {
		if entry.Pattern == pattern {
			p.postgresResolvers[i].Resolver = r
			return
		}
	}
	p.postgresResolvers = append(p.postgresResolvers, PostgresResolverEntry{Pattern: pattern, Resolver: r})
}

// postgresResolverForHost returns the Postgres credential resolver for host.
// When a run context is present, only its per-run resolvers are consulted —
// proxy-level resolvers are never used as fallback, even when the run has no
// resolvers at all (matching the credential scoping rule in
// getCredentialsForRequest). Matching is on hostname only: any port in host
// is stripped before matching, and patterns match against the Postgres
// default port (5432).
func (p *Proxy) postgresResolverForHost(rc *RunContextData, host string) PostgresCredentialResolver {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if rc != nil {
		return postgresResolverFromEntries(rc.PostgresResolvers, host)
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return postgresResolverFromEntries(p.postgresResolvers, host)
}

// postgresResolverFromEntries returns the resolver of the first entry whose
// pattern matches host, or nil when none match.
func postgresResolverFromEntries(entries []PostgresResolverEntry, host string) PostgresCredentialResolver {
	for _, entry := range entries {
		pattern := parseHostPattern(entry.Pattern)
		// Patterns without an explicit port match the Postgres default port
		// instead of matchesPattern's HTTP defaults (80/443).
		if pattern.port == 0 {
			pattern.port = postgresDefaultPort
		}
		if matchesPattern(pattern, host, postgresDefaultPort) {
			return entry.Resolver
		}
	}
	return nil
}
