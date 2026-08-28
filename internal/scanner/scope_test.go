package scanner

import "testing"

func TestURLInScope(t *testing.T) {
	origins := []string{"https://app.example.com"}
	cases := []struct {
		url  string
		want bool
	}{
		{"https://example.com/api/x", true},           // target domain
		{"https://api.example.com/api/x", true},       // subdomain of registrable
		{"https://app.example.com/me", true},          // identity origin
		{"https://attacker.com/steal", false},         // OUT: exfil host
		{"http://localhost:8080/x", false},            // blocked internal
		{"http://127.0.0.1/x", false},                 // blocked loopback
		{"http://169.254.169.254/latest/meta", false}, // cloud metadata
		{"http://10.0.0.5/x", false},                  // private range
		{"ftp://example.com/x", false},                // non-http scheme
		{"https://example.com.evil.com/x", false},     // suffix trick must fail
	}
	for _, c := range cases {
		if got := URLInScope("example.com", origins, c.url); got != c.want {
			t.Errorf("URLInScope(%q)=%v want %v", c.url, got, c.want)
		}
	}
}

// The old "last two labels" heuristic treated example.co.uk and evil.co.uk as the
// same registrable domain ("co.uk"), a real scope bypass. With the PSL, multi-
// label public suffixes are handled correctly.
func TestURLInScopePublicSuffixList(t *testing.T) {
	cases := []struct {
		target string
		url    string
		want   bool
	}{
		// eTLD+1 over multi-label suffixes: same registrable → in scope.
		{"example.co.uk", "https://api.example.co.uk/x", true},
		{"example.com.au", "https://app.example.com.au/x", true},
		{"example.co.jp", "https://www.example.co.jp/x", true},
		// Different registrable under the SAME multi-label suffix → OUT of scope
		// (this is the bug the old lastTwo() heuristic got wrong).
		{"example.co.uk", "https://evil.co.uk/x", false},
		{"example.com.au", "https://evil.com.au/x", false},
		{"example.co.jp", "https://evil.co.jp/x", false},
		// github.io is itself a public suffix, so each *.github.io is its OWN
		// registrable domain — a sibling pages site must NOT be in scope.
		{"foo.github.io", "https://foo.github.io/x", true},
		{"foo.github.io", "https://a.foo.github.io/x", true},
		{"foo.github.io", "https://bar.github.io/x", false},
		// lookalike / substring domains are never the same scope.
		{"example.com", "https://evil-example.com/x", false},
		{"example.com", "https://example.com.attacker.net/x", false},
	}
	for _, c := range cases {
		if got := URLInScope(c.target, nil, c.url); got != c.want {
			t.Errorf("URLInScope(target=%q, %q)=%v want %v", c.target, c.url, got, c.want)
		}
	}
}

// Hostnames are normalized before comparison: case-insensitive, trailing dot,
// IPv6 brackets, and IDN/punycode equivalence.
func TestHostNormalizationInScope(t *testing.T) {
	cases := []struct {
		target string
		url    string
		want   bool
	}{
		{"example.com", "https://Example.COM/x", true},
		{"example.com", "https://API.Example.Com/x", true},
		{"example.com", "https://example.com./x", true}, // fully-qualified trailing dot
		{"Example.Com", "https://example.com/x", true},  // mixed-case target
	}
	for _, c := range cases {
		if got := URLInScope(c.target, nil, c.url); got != c.want {
			t.Errorf("URLInScope(target=%q, %q)=%v want %v", c.target, c.url, got, c.want)
		}
	}
	// IDN: the unicode host and its punycode form must normalize equal.
	if a, b := normalizeHost("münchen.example"), normalizeHost("xn--mnchen-3ya.example"); a != b {
		t.Errorf("IDN normalization mismatch: %q vs %q", a, b)
	}
}

func TestRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"api.example.com":     "example.com",
		"example.co.uk":       "example.co.uk",
		"a.b.example.co.uk":   "example.co.uk",
		"foo.github.io":       "foo.github.io",
		"a.foo.github.io":     "foo.github.io",
		"127.0.0.1":           "", // IP has no registrable domain
		"co.uk":               "", // bare public suffix
	}
	for host, want := range cases {
		if got := registrableDomain(host); got != want {
			t.Errorf("registrableDomain(%q)=%q want %q", host, got, want)
		}
	}
}
