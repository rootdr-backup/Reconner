package scanner

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
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

// TestInjectablePathSegmentsIncludesImageAndStaticLookingPaths proves a
// static-asset-LOOKING path segment (photo.jpg, report.pdf) is still returned
// as an injectable candidate. This used to be silently skipped — exactly the
// classic image/file-serving LFI vector (/images/<name>, /download/<name>)
// where the filename-shaped segment is resolved against the filesystem, not
// served as a genuinely immutable static asset.
func TestInjectablePathSegmentsIncludesImageAndStaticLookingPaths(t *testing.T) {
	u, err := url.Parse("https://x.test/images/photo.jpg")
	if err != nil {
		t.Fatal(err)
	}
	idxs, vals := injectablePathSegments(u)
	found := false
	for i, idx := range idxs {
		if idx == 1 && vals[i] == "photo.jpg" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected photo.jpg to be an injectable path segment, got idxs=%v vals=%v", idxs, vals)
	}

	u2, _ := url.Parse("https://x.test/static/report.pdf")
	idxs2, vals2 := injectablePathSegments(u2)
	found2 := false
	for i, idx := range idxs2 {
		if idx == 1 && vals2[i] == "report.pdf" {
			found2 = true
		}
	}
	if !found2 {
		t.Fatalf("expected report.pdf to be an injectable path segment, got idxs=%v vals=%v", idxs2, vals2)
	}
}

// TestSeedPathSegmentsFromURLsRoutesToLFI proves the general crawl-wide
// path-segment seeder (not just the single-explicit-endpoint case) produces
// insertion points that LFI's own loader (loadRoutedInsertionPoints,
// ClassLFI) actually picks up — closing the gap where the overwhelming bulk
// of a scan's crawled surface only ever contributed query parameters.
func TestSeedPathSegmentsFromURLsRoutesToLFI(t *testing.T) {
	db, err := database.New(t.TempDir() + "/seedpath.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	targetID := uuid.New().String()
	if _, err := db.Exec(`INSERT INTO targets (id, domain) VALUES (?, 'x.test')`, targetID); err != nil {
		t.Fatal(err)
	}

	urls := []string{
		"https://x.test/images/avatar123.jpg",
		"https://x.test/download/report.pdf",
		"https://x.test/", // no real path — must be skipped without error
	}
	seeded := seedPathSegmentsFromURLs(ctx, db, targetID, urls, 0)
	if seeded == 0 {
		t.Fatal("expected at least one path-segment parameter to be seeded")
	}

	points := loadRoutedInsertionPoints(ctx, db, targetID, ClassLFI, 1000, 32)
	var sawImage, sawDownload bool
	for _, p := range points {
		if p.URL == "https://x.test/images/avatar123.jpg" && strings.HasPrefix(p.Location, "path:") {
			sawImage = true
		}
		if p.URL == "https://x.test/download/report.pdf" && strings.HasPrefix(p.Location, "path:") {
			sawDownload = true
		}
	}
	if !sawImage {
		t.Error("expected the image path segment to reach LFI's own insertion-point loader")
	}
	if !sawDownload {
		t.Error("expected the download/report.pdf path segment to reach LFI's own insertion-point loader")
	}
}
