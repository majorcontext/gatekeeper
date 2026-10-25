package proxy

import (
	"fmt"
	"testing"
)

func TestAuthorityMatchesConnect(t *testing.T) {
	tests := []struct {
		name    string
		connect string
		inner   string
		want    bool
	}{
		{"same", "pr-1.meetneptune.dev:443", "pr-1.meetneptune.dev", true},
		{"same with default port", "pr-1.meetneptune.dev:443", "pr-1.meetneptune.dev:443", true},
		{"empty inner (HTTP/1.0)", "pr-1.meetneptune.dev:443", "", true},
		{"case", "pr-1.meetneptune.dev:443", "PR-1.MeetNeptune.DEV:443", true},
		{"connect in upper case", "PR-1.MEETNEPTUNE.DEV:443", "pr-1.meetneptune.dev", true},
		{"trailing root dot", "pr-1.meetneptune.dev:443", "pr-1.meetneptune.dev.:443", true},
		{"ideographic full stop", "pr-1.meetneptune.dev:443", "pr-1" + ideographicFullStop + "meetneptune.dev", true},
		{"other host", "pr-1.meetneptune.dev:443", "attacker.example", false},
		{"other host, same port", "pr-1.meetneptune.dev:443", "attacker.example:443", false},
		{"sibling", "pr-1.meetneptune.dev:443", "pr-2.meetneptune.dev", false},
		{"suffix of the host", "pr-1.meetneptune.dev:443", "meetneptune.dev", false},
		{"other port", "pr-1.meetneptune.dev:443", "pr-1.meetneptune.dev:8443", false},
		{"non-default connect port", "pr-1.meetneptune.dev:8443", "pr-1.meetneptune.dev:8443", true},
		{"non-default connect port, default inner port", "pr-1.meetneptune.dev:8443", "pr-1.meetneptune.dev:443", false},
		{"bad inner label", "pr-1.meetneptune.dev:443", "pr-1..meetneptune.dev", false},
		{"IPv6", "[::1]:443", "[::1]:443", true},
		{"IPv6 without port", "[::1]:443", "[::1]", true},
		{"IPv6 spelled out", "[::1]:443", "[0:0:0:0:0:0:0:1]:443", true},
		{"other IPv6", "[::1]:443", "[::2]:443", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := authorityMatchesConnect(tt.connect, tt.inner); got != tt.want {
				t.Errorf("authorityMatchesConnect(%q, %q) = %v, want %v", tt.connect, tt.inner, got, tt.want)
			}
		})
	}
}

func TestCanonicalTargetHost(t *testing.T) {
	tests := []struct {
		host    string
		want    string
		wantErr bool
	}{
		{"pr-1.meetneptune.dev", "pr-1.meetneptune.dev", false},
		{"PR-1.MeetNeptune.DEV", "PR-1.MeetNeptune.DEV", false},
		{"pr-1.meetneptune.dev.", "pr-1.meetneptune.dev", false},
		{"pr-1" + ideographicFullStop + "evil.meetneptune.dev", "pr-1.evil.meetneptune.dev", false},
		{"pr-1" + fullwidthFullStop + "evil.meetneptune.dev", "pr-1.evil.meetneptune.dev", false},
		{"pr-1" + halfwidthFullStop + "evil.meetneptune.dev", "pr-1.evil.meetneptune.dev", false},
		{"München.DE", "xn--mnchen-3ya.de", false},
		{"a.aİ.com", "a.xn--ai-sub.com", false},
		{"::1", "::1", false},
		{"fe80::1%eth0", "fe80::1%eth0", false},
		{"127.0.0.1", "127.0.0.1", false},
		{"", "", true},
		{".", "", true},
		{"a..b", "", true},
		{".a.b", "", true},
		{"a.b..", "", true},
		{"a\u202eb.com", "", true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.host), func(t *testing.T) {
			got, err := canonicalTargetHost(tt.host)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Errorf("canonicalTargetHost(%q) = %q, %v; want %q, error=%v", tt.host, got, err, tt.want, tt.wantErr)
			}
		})
	}
}
