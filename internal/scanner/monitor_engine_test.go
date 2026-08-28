package scanner

import "testing"

func TestClassifyChangeSeverity(t *testing.T) {
	cases := map[string]string{
		"security_header_removed": "high",
		"security:script_added":   "high",
		"status":                  "medium",
		"js_change":               "medium",
		"http_change":             "low",
		"body_tweak":              "info",
	}
	for in, want := range cases {
		if got := classifyChangeSeverity(in); got != want {
			t.Errorf("classifyChangeSeverity(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestDiffSecurityHeadersRemoval(t *testing.T) {
	old := map[string]string{
		"strict-transport-security": "max-age=63072000",
		"content-security-policy":   "default-src 'self'",
		"x-frame-options":           "DENY",
	}
	cur := map[string]string{
		"content-security-policy": "default-src 'self'",
	}
	removed := diffSecurityHeaders(old, cur)
	if len(removed) != 2 {
		t.Fatalf("expected 2 removed headers, got %d: %v", len(removed), removed)
	}
	// Adding headers must NOT report as a regression.
	if r := diffSecurityHeaders(cur, old); len(r) != 0 {
		t.Errorf("adding headers should not be a regression, got %v", r)
	}
}

func TestExtractSecurityHeaders(t *testing.T) {
	hdr := map[string]string{
		"strict-transport-security": "max-age=1",
		"x-content-type-options":    "nosniff",
		"server":                    "nginx", // not a tracked security header
	}
	get := func(k string) string {
		for hk, hv := range hdr {
			if hk == k {
				return hv
			}
		}
		return ""
	}
	out := extractSecurityHeaders(get)
	if len(out) != 2 {
		t.Fatalf("expected 2 tracked headers, got %d: %v", len(out), out)
	}
	if _, ok := out["server"]; ok {
		t.Error("server should not be tracked as a security header")
	}
}
