package scanner

import "testing"

func TestNormalizeScopeIdentifier(t *testing.T) {
	cases := []struct {
		raw  string
		want string
		ok   bool
	}{
		{"Example.COM.", "example.com", true},
		{"https://Example.com/", "example.com", true},
		{"*.Example.COM", "example.com", true},
		{"example.com:8443", "example.com", true},  // port stripped for matching
		{"https://example.com/api/v1/", "", false}, // path-scoped: not landable
		{"example.com/api", "", false},
		{"*example.com", "", false},      // missing dot
		{"sub.*.example.com", "", false}, // mid-domain glob
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := normalizeScopeIdentifier(tc.raw)
		if ok != tc.ok || got != tc.want {
			t.Errorf("normalizeScopeIdentifier(%q) = (%q,%v), want (%q,%v)", tc.raw, got, ok, tc.want, tc.ok)
		}
	}
}

func TestNormalizeWatchHost(t *testing.T) {
	cases := []struct {
		raw       string
		wantValue string
		wantHost  string
		wantPort  string
		ok        bool
	}{
		{"Sub.Example.COM.", "sub.example.com", "sub.example.com", "", true},
		{"https://sub.example.com/", "sub.example.com", "sub.example.com", "", true},
		{"example.com:80", "example.com", "example.com", "80", true},
		{"example.com:8443", "example.com:8443", "example.com", "8443", true},
		{"example.com:443", "example.com", "example.com", "443", true},
	}
	for _, tc := range cases {
		got, ok := normalizeWatchHost(tc.raw)
		if ok != tc.ok || got.Value != tc.wantValue || got.Host != tc.wantHost || got.Port != tc.wantPort {
			t.Errorf("normalizeWatchHost(%q) = (%+v,%v), want value=%q host=%q port=%q ok=%v",
				tc.raw, got, ok, tc.wantValue, tc.wantHost, tc.wantPort, tc.ok)
		}
	}
}

func TestMatchWatchHost(t *testing.T) {
	entries := []WatchScopeEntry{
		{Identifier: "*.example.com", IsWildcard: true, host: "example.com"},
		{Identifier: "exact.test", host: "exact.test"},
	}
	host := func(s string) WatchScopeHost { h, _ := normalizeWatchHost(s); return h }

	cases := []struct {
		name  string
		query string
		want  string // matched identifier, "" for no match
	}{
		{"wildcard one level", "a.example.com", "*.example.com"},
		{"wildcard two levels", "a.b.example.com", "*.example.com"},
		{"wildcard does not match apex", "example.com", ""},
		{"wildcard does not match other base", "a.notexample.com", ""},
		{"exact match", "exact.test", "exact.test"},
		{"exact wins over wildcard", "exact.example.com", "*.example.com"},
		{"port does not block match", "a.example.com:8443", "*.example.com"},
		{"unmatched", "random.org", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := matchWatchHost(entries, host(tc.query))
			if tc.want == "" {
				if ok {
					t.Fatalf("unexpected match: %+v", got)
				}
				return
			}
			if !ok || got.Identifier != tc.want {
				t.Fatalf("matchWatchHost(%q) = (%+v,%v), want identifier %q", tc.query, got, ok, tc.want)
			}
		})
	}
}

func TestNormalizeScopeIdentifierRejectsPunycodeHost(t *testing.T) {
	got, ok := normalizeScopeIdentifier("BÜCHER.example")
	if !ok || got != "xn--bcher-kva.example" {
		t.Fatalf("punycode = (%q,%v), want xn--bcher-kva.example", got, ok)
	}
}
