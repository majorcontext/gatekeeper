package proxy

import (
	"log/slog"
	"testing"
)

// prefixWildcardCases are hosts checked against pr-*.meetneptune.dev on every
// path that matches host patterns.
var prefixWildcardCases = []struct {
	name string
	host string
	want bool
}{
	{"pr number", "pr-6301.meetneptune.dev", true},
	{"one character after prefix", "pr-1.meetneptune.dev", true},
	{"case-insensitive", "PR-6301.MeetNeptune.dev", true},
	{"empty after prefix", "pr-.meetneptune.dev", false},
	{"extra label", "pr-1.x.meetneptune.dev", false},
	{"prefix not at label start", "xpr-1.meetneptune.dev", false},
	{"trailing suffix", "pr-1.meetneptune.dev.evil.com", false},
	{"bare domain", "meetneptune.dev", false},
	{"other first label", "www.meetneptune.dev", false},
	{"other domain", "pr-1.example.com", false},
}

func TestValidateHostPattern_PrefixWildcard(t *testing.T) {
	tests := []struct {
		pattern string
		valid   bool
	}{
		{"pr-*.meetneptune.dev", true},
		{"pr-*.meetneptune.dev:8443", true},
		{"a*.example.com", true},
		{"*.meetneptune.dev", true},
		{"api.meetneptune.dev", true},
		{"*foo.example.com", false},
		{"*.*.example.com", false},
		{"pr-*-x.example.com", false},
		{"pr-**.example.com", false},
		{"a.pr-*.example.com", false},
		{"api.*.example.com", false},
		{"pr-*", false},
		{"pr-*.com", false},
		{"pr-*.*.example.com", false},
		{"pr-*.example.com:abc", false},
		{"*", false},
	}
	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			err := ValidateHostPattern(tt.pattern)
			if (err == nil) != tt.valid {
				t.Errorf("ValidateHostPattern(%q) = %v, want valid=%v", tt.pattern, err, tt.valid)
			}
		})
	}
}

func TestParseHostPattern_PrefixWildcard(t *testing.T) {
	got := parseHostPattern("PR-*.MeetNeptune.dev:8443")
	want := HostPattern{pattern: "PR-*.MeetNeptune.dev:8443", host: "meetneptune.dev", port: 8443, prefix: "pr-"}
	if got != want {
		t.Errorf("parseHostPattern = %+v, want %+v", got, want)
	}
}

func TestMatchHost_PrefixWildcard(t *testing.T) {
	patterns := []HostPattern{parseHostPattern("pr-*.meetneptune.dev")}
	for _, tt := range prefixWildcardCases {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchHost(patterns, tt.host, 443); got != tt.want {
				t.Errorf("matchHost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestMatchHost_PrefixWildcardPort(t *testing.T) {
	tests := []struct {
		pattern string
		port    int
		want    bool
	}{
		{"pr-*.meetneptune.dev", 443, true},
		{"pr-*.meetneptune.dev", 80, true},
		{"pr-*.meetneptune.dev", 8443, false},
		{"pr-*.meetneptune.dev:8443", 8443, true},
		{"pr-*.meetneptune.dev:8443", 443, false},
	}
	for _, tt := range tests {
		got := matchHost([]HostPattern{parseHostPattern(tt.pattern)}, "pr-6301.meetneptune.dev", tt.port)
		if got != tt.want {
			t.Errorf("matchHost(%q, port %d) = %v, want %v", tt.pattern, tt.port, got, tt.want)
		}
	}
}

func TestExchangeLogMatches_PrefixWildcard(t *testing.T) {
	l := &exchangeLog{patterns: []HostPattern{parseHostPattern("pr-*.meetneptune.dev")}}
	for _, tt := range prefixWildcardCases {
		t.Run(tt.name, func(t *testing.T) {
			if got := l.matches(tt.host); got != tt.want {
				t.Errorf("matches(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestSetExchangeLog_RejectsBadWildcard(t *testing.T) {
	lg := slog.New(slog.DiscardHandler)
	if err := NewProxy().SetExchangeLog(lg, []string{"pr-*-x.example.com"}); err == nil {
		t.Error("SetExchangeLog accepted pr-*-x.example.com")
	}
}

func TestCredentialLookup_PrefixWildcard(t *testing.T) {
	p := NewProxy()
	p.SetCredentialWithGrant("pr-*.meetneptune.dev", "Authorization", "Bearer prefix", "prefix")
	for _, tt := range prefixWildcardCases {
		t.Run(tt.name, func(t *testing.T) {
			if got := len(p.getCredentials(tt.host)) > 0; got != tt.want {
				t.Errorf("getCredentials(%q) found = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
	if got := len(p.getCredentials("pr-6301.meetneptune.dev:443")); got != 1 {
		t.Errorf("getCredentials with a port found %d, want 1", got)
	}
	if got := len(p.getCredentials("pr-1.x.meetneptune.dev:443")); got != 0 {
		t.Errorf("getCredentials of a two-label host with a port found %d, want 0", got)
	}
}

func TestLookupHostKeyed_PrefixWildcardWithPortKey(t *testing.T) {
	// SetCredential* rejects a key with a port, but embedder-built
	// RunContextData maps can hold one.
	m := map[string][]string{"pr-*.meetneptune.dev:8443": {"pinned"}}
	tests := []struct {
		host string
		want bool
	}{
		{"pr-1.meetneptune.dev:8443", true},
		{"pr-1.meetneptune.dev:443", false},
		{"pr-1.meetneptune.dev", false},
		{"pr-1.x.meetneptune.dev:8443", false},
	}
	for _, tt := range tests {
		got, _ := lookupHostKeyed(m, tt.host, nonEmptySlice)
		if (len(got) > 0) != tt.want {
			t.Errorf("lookupHostKeyed(%q) found = %v, want %v", tt.host, len(got) > 0, tt.want)
		}
	}
}

func TestCredentialLookup_PrefixWildcardRanking(t *testing.T) {
	// An exact host beats a prefix pattern, which beats a "*." pattern, even
	// when the "*." key has the longer domain part.
	tests := []struct {
		name string
		keys []string
		host string
		want string
	}{
		{"prefix over suffix", []string{"*.meetneptune.dev", "pr-*.meetneptune.dev"}, "pr-1.meetneptune.dev", "pr-*.meetneptune.dev"},
		{"prefix over suffix, other order", []string{"pr-*.meetneptune.dev", "*.meetneptune.dev"}, "pr-1.meetneptune.dev", "pr-*.meetneptune.dev"},
		{"exact over prefix", []string{"pr-*.meetneptune.dev", "pr-1.meetneptune.dev", "*.meetneptune.dev"}, "pr-1.meetneptune.dev", "pr-1.meetneptune.dev"},
		{"suffix when prefix misses", []string{"pr-*.meetneptune.dev", "*.meetneptune.dev"}, "www.meetneptune.dev", "*.meetneptune.dev"},
		{"longer prefix over shorter", []string{"p*.meetneptune.dev", "pr-*.meetneptune.dev"}, "pr-1.meetneptune.dev", "pr-*.meetneptune.dev"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := map[string][]string{}
			for _, k := range tt.keys {
				m[k] = []string{k}
			}
			got, _ := lookupHostKeyed(m, tt.host, nonEmptySlice)
			if len(got) != 1 || got[0] != tt.want {
				t.Errorf("lookupHostKeyed(%q) = %v, want %q", tt.host, got, tt.want)
			}
		})
	}
}

func TestHostMatchOutranks_PrefixWildcard(t *testing.T) {
	suffix := hostMatch{hostMatchWildcard, "*.meetneptune.dev"}
	prefix := hostMatch{hostMatchPrefixWildcard, "pr-*.meetneptune.dev"}
	exact := hostMatch{hostMatchExactFold, "pr-1.meetneptune.dev"}
	if !prefix.outranks(suffix) || suffix.outranks(prefix) {
		t.Error("a prefix pattern must outrank a suffix pattern")
	}
	if !exact.outranks(prefix) || prefix.outranks(exact) {
		t.Error("an exact host must outrank a prefix pattern")
	}
}
