package scanner

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

// TestLooksLikeEndpointURL proves endpoint URLs (with a path and/or query) are
// distinguished from bare hosts.
func TestLooksLikeEndpointURL(t *testing.T) {
	endpoints := []string{
		"https://example.com/appointment?h=x",
		"https://example.com/appointment",
		"http://x.com/a/b/c",
		"x.com/path?q=1",
	}
	for _, e := range endpoints {
		if !looksLikeEndpointURL(e) {
			t.Errorf("expected endpoint URL: %s", e)
		}
	}
	hosts := []string{"example.com", "https://example.com", "https://example.com/", "sub.example.com"}
	for _, h := range hosts {
		if looksLikeEndpointURL(h) {
			t.Errorf("expected bare host (not endpoint): %s", h)
		}
	}
}

// TestInjectPathSegment proves a path segment is replaced while the query, host
// and scheme are preserved, and payload metacharacters survive raw.
func TestInjectPathSegment(t *testing.T) {
	got := injectPathSegment("https://x.com/user/123/profile?a=1", 1, "PAYLOAD")
	want := "https://x.com/user/PAYLOAD/profile?a=1"
	if got != want {
		t.Errorf("path segment 1: got %q want %q", got, want)
	}
	// index 0 = first segment: segment replaced, host + query preserved.
	got0 := injectPathSegment("https://x.com/appointment?h=1", 0, "PAY")
	if !strings.HasPrefix(got0, "https://x.com/PAY") || !strings.HasSuffix(got0, "?h=1") || strings.Contains(got0, "appointment") {
		t.Errorf("path segment 0 replace failed: %q", got0)
	}
	// out-of-range index → unchanged
	if u := injectPathSegment("https://x.com/a?b=1", 9, "X"); u != "https://x.com/a?b=1" {
		t.Errorf("out-of-range should be unchanged, got %q", u)
	}
	meta := injectPathSegment("https://x.com/a/seed", 1, `<img src=x onerror=alert(1)>`)
	parsed, err := url.Parse(meta)
	if err != nil || parsed.Path != `/a/<img src=x onerror=alert(1)>` || strings.Contains(meta, "%2520") {
		t.Fatalf("path payload was not encoded exactly once: url=%q path=%q err=%v", meta, parsed.Path, err)
	}
}

// TestIsPathLocation parses the path:<index> location encoding.
func TestIsPathLocation(t *testing.T) {
	if idx, ok := isPathLocation("path:2"); !ok || idx != 2 {
		t.Errorf("path:2 → (%d,%v)", idx, ok)
	}
	if _, ok := isPathLocation("query"); ok {
		t.Errorf("query must not be a path location")
	}
	if _, ok := isPathLocation(""); ok {
		t.Errorf("empty must not be a path location")
	}
}

// TestEndpointScope proves single-endpoint confinement: URLs under the seed
// prefix are in scope; siblings and other hosts are out.
func TestEndpointScope(t *testing.T) {
	ctx := WithEndpointScope(context.Background(), []string{"https://x.com/app/appointment?h=1"})
	in := []string{
		"https://x.com/app/appointment?h=payload",
		"https://x.com/app/appointment/sub?z=1",
		"https://x.com/app/other?q=1", // same directory prefix /app/
	}
	for _, u := range in {
		if !urlInEndpointScope(ctx, u) {
			t.Errorf("expected in scope: %s", u)
		}
	}
	out := []string{
		"https://x.com/billing?q=1", // different directory
		"https://y.com/app/appointment?h=1",
	}
	for _, u := range out {
		if urlInEndpointScope(ctx, u) {
			t.Errorf("expected OUT of scope: %s", u)
		}
	}
	// No confinement (plain ctx) → everything in scope.
	if !urlInEndpointScope(context.Background(), "https://anything.com/x") {
		t.Errorf("plain context must place everything in scope")
	}
}
