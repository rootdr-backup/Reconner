package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
)

func TestParseRobotsTxt(t *testing.T) {
	body := `# comment
User-agent: *
Disallow: /admin/
Disallow: /search?q=*
Allow: /public/
Disallow: /
Disallow:
Sitemap: https://ex.com/sitemap.xml
`
	paths, sitemaps := parseRobotsTxt(body)
	got := strings.Join(paths, ",")
	if !strings.Contains(got, "/admin/") || !strings.Contains(got, "/search?q=") || !strings.Contains(got, "/public/") {
		t.Fatalf("expected admin/search/public paths, got %v", paths)
	}
	for _, p := range paths {
		if p == "/" || p == "" {
			t.Fatalf("bare / or empty path must be dropped, got %v", paths)
		}
	}
	if len(sitemaps) != 1 || sitemaps[0] != "https://ex.com/sitemap.xml" {
		t.Fatalf("expected the declared sitemap, got %v", sitemaps)
	}
}

func TestParseSitemapLocs(t *testing.T) {
	xml := `<?xml version="1.0"?><urlset>
	  <url><loc>https://ex.com/a?id=1</loc></url>
	  <url><loc>https://ex.com/b&amp;c</loc></url>
	</urlset>`
	locs := parseSitemapLocs(xml)
	if len(locs) != 2 || locs[0] != "https://ex.com/a?id=1" || locs[1] != "https://ex.com/b&c" {
		t.Fatalf("unexpected locs (entity-decoding?): %v", locs)
	}
}

// End-to-end: robots.txt advertises a sitemap; the sitemap is an INDEX pointing at
// a child sitemap; the child lists real URLs. The harvester must follow the index
// one level and emit both the robots Disallow endpoints and the sitemap URLs.
func TestHarvestWellKnownFollowsSitemapIndex(t *testing.T) {
	withLoopbackAllowed(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("User-agent: *\nDisallow: /admin/panel?debug=1\nSitemap: " + baseOf(r) + "/sitemap.xml\n"))
	})
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(`<sitemapindex><sitemap><loc>` + baseOf(r) + `/sitemap-1.xml</loc></sitemap></sitemapindex>`))
	})
	mux.HandleFunc("/sitemap-1.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(`<urlset><url><loc>` + baseOf(r) + `/api/v1/orders?id=42</loc></url></urlset>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var mu sync.Mutex
	var got []string
	addURL := func(u string) { mu.Lock(); got = append(got, u); mu.Unlock() }

	s := &ParamScanner{}
	n := s.harvestWellKnown(context.Background(), []string{srv.URL}, addURL)
	if n == 0 {
		t.Fatal("harvester emitted nothing")
	}
	sort.Strings(got)
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "/admin/panel?debug=1") {
		t.Fatalf("robots Disallow endpoint missing: %v", got)
	}
	if !strings.Contains(joined, "/api/v1/orders?id=42") {
		t.Fatalf("sitemap-index child URL missing (index not followed?): %v", got)
	}
}

func baseOf(r *http.Request) string { return "http://" + r.Host }
