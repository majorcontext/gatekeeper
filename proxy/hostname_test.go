package proxy

import (
	"fmt"
	"testing"
)

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
		{"a‮b.com", "", true},
		{"", "", true},
		{"a..b", "", true},
		{".a.b", "", true},
		{"a.b..", "", true},
		{"127.0.0.1", "127.0.0.1", false},
		{"127.0.0.1.", "127.0.0.1", false},
		{"0:0:0:0:0:0:0:1", "::1", false},
		{"2001:DB8::1", "2001:db8::1", false},
		{"::ffff:192.0.2.1", "::ffff:192.0.2.1", false},
		{"fe80::1%eth0", "", true},
		{"::ffff:192.0.2.1%x.example.com", "", true},
		{"example.com1", "example.com1", false},
		// libc reads each of these as an IPv4 address; so must we refuse them.
		{"0177.0.0.1", "", true},
		{"127.1", "", true},
		{"0x7f.1", "", true},
		{"017700000001", "", true},
		{"2130706433", "", true},
		{"127.000.000.001", "", true},
		{"example.123", "", true},
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

func TestAuthorityMatchesConnect(t *testing.T) {
	tests := []struct {
		name    string
		connect string
		inner   string
		want    bool
	}{
		{"no port", "pr-1.meetneptune.dev:443", "pr-1.meetneptune.dev", true},
		{"same port", "pr-1.meetneptune.dev:443", "pr-1.meetneptune.dev:443", true},
		{"empty (HTTP/1.0)", "pr-1.meetneptune.dev:443", "", true},
		{"case", "PR-1.MEETNEPTUNE.DEV:443", "pr-1.meetneptune.dev:443", true},
		{"trailing root dot", "pr-1.meetneptune.dev:443", "pr-1.meetneptune.dev.:443", true},
		{"ideographic full stop", "pr-1.meetneptune.dev:443", "pr-1" + ideographicFullStop + "meetneptune.dev", true},
		{"other host", "pr-1.meetneptune.dev:443", "attacker.example:443", false},
		{"sibling", "pr-1.meetneptune.dev:443", "pr-2.meetneptune.dev", false},
		{"suffix of the host", "pr-1.meetneptune.dev:443", "meetneptune.dev", false},
		{"other port", "pr-1.meetneptune.dev:443", "pr-1.meetneptune.dev:8443", false},
		{"default port against a non-default connect port", "pr-1.meetneptune.dev:8443", "pr-1.meetneptune.dev:443", false},
		{"bad inner label", "pr-1.meetneptune.dev:443", "pr-1..meetneptune.dev", false},
		{"IPv6 without port", "[::1]:443", "[::1]", true},
		{"IPv6 spelled out", "[::1]:443", "[0:0:0:0:0:0:0:1]:443", true},
		{"IPv4 and IPv4-mapped", "127.0.0.1:443", "[::ffff:127.0.0.1]:443", true},
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

func TestValidateHostPattern_Rejections(t *testing.T) {
	tests := []struct {
		pattern string
		valid   bool
	}{
		{"pr-*.meetneptune.dev", true},
		{"*.example.com", true},
		{"example.com", true},
		{"192.0.2.1:8443", true},
		// empty labels and trailing dots
		{"pr-*.com.", false},
		{"pr-*..com", false},
		{"pr-*...", false},
		{"pr-*.example.com.:8443", false},
		{"*.example.com.", false},
		{"*..example.com", false},
		{"example..com", false},
		{"example.com.", false},
		{".example.com", false},
		// Unicode names: requests are matched in their ASCII form
		{"münchen.de", false},
		{"*.münchen.de", false},
		{"pr-*.münchen.de", false},
		// numeric hosts libc may read as IPv4, including wildcards over an IP
		{"0177.0.0.1", false},
		{"127.1", false},
		{"2130706433", false},
		{"*.0.0.1", false},
		{"19*.0.2.1", false},
		// brackets belong to IP literals, which are not patterns
		{"[999.0.0.1]", false},
		{"[::1]", false},
		{"[example.com]:443", false},
	}
	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			if err := ValidateHostPattern(tt.pattern); (err == nil) != tt.valid {
				t.Errorf("ValidateHostPattern(%q) = %v, want valid=%v", tt.pattern, err, tt.valid)
			}
		})
	}
}
