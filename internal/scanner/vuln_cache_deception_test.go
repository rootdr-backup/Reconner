package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/pkg/logger"
)

func newCacheDecScanner(t *testing.T) *VulnScanner {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	return &VulnScanner{db: db, cfg: &config.Config{}, logger: logger.New("error")}
}

func cacheDecFindings(t *testing.T, s *VulnScanner, targetID string) []string {
	rows, err := s.db.Query(`SELECT url FROM vuln_findings WHERE target_id=? AND type='cache_deception'`, targetID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		rows.Scan(&u)
		out = append(out, u)
	}
	return out
}

// A SPA / catch-all site returns the SAME app shell for EVERY path (even a bogus
// one) and even caches it. The old detector flagged this on every subdomain; the
// negative-control gate must now suppress it entirely.
func TestCacheDeceptionSPACatchAllNoFP(t *testing.T) {
	spa := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Cache-Control", "public, max-age=9963")
		w.Header().Set("CF-Cache-Status", "HIT") // even a cache hit — but it's the shell for ALL paths
		w.Write([]byte("<html><body>APP SHELL — same for every route</body></html>"))
	}))
	defer spa.Close()

	s := newCacheDecScanner(t)
	s.db.Exec(`INSERT INTO targets (id, domain) VALUES ('t1','spa.example')`)
	s.db.Exec(`INSERT INTO http_services (id, target_id, url, status_code) VALUES ('h1','t1',?,200)`, spa.URL+"/signin")
	s.db.Exec(`INSERT INTO http_services (id, target_id, url, status_code) VALUES ('h2','t1',?,200)`, spa.URL+"/api/users")

	if err := s.RunCacheDeception(context.Background(), "t1", func(_, _, _ string) {}); err != nil {
		t.Fatal(err)
	}
	if f := cacheDecFindings(t, s, "t1"); len(f) != 0 {
		t.Fatalf("SPA catch-all must NOT produce cache_deception findings, got %v", f)
	}
}

// A genuinely vulnerable site: the real page is served AND cached under a fake
// .css path, while a bogus path returns something different (404-style). This must
// still be detected.
func TestCacheDeceptionRealPositive(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// bogus/non-existent control path → 404 with different content
		if strings.Contains(r.URL.Path, "notreal") {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(404)
			w.Write([]byte("<html>404 not found</html>"))
			return
		}
		// the real (sensitive) page, cached under the .css path
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Cache-Control", "public, max-age=600")
		w.Header().Set("CF-Cache-Status", "HIT")
		w.Write([]byte("<html><body>ACCOUNT for bob — balance 1000, token abc123</body></html>"))
	}))
	defer vuln.Close()

	s := newCacheDecScanner(t)
	s.db.Exec(`INSERT INTO targets (id, domain) VALUES ('t2','vuln.example')`)
	s.db.Exec(`INSERT INTO http_services (id, target_id, url, status_code) VALUES ('h3','t2',?,200)`, vuln.URL+"/account")

	if err := s.RunCacheDeception(context.Background(), "t2", func(_, _, _ string) {}); err != nil {
		t.Fatal(err)
	}
	f := cacheDecFindings(t, s, "t2")
	if len(f) != 1 {
		t.Fatalf("real cache deception must be detected exactly once, got %v", f)
	}
}

// Cache-Control directives WITHOUT an actual cache hit are not proof; a page that
// is merely "cacheable" but never served from cache must not be flagged.
func TestCacheDeceptionNoRealHitNoFinding(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "notreal") {
			w.WriteHeader(404)
			w.Write([]byte("nope"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Cache-Control", "public, max-age=600") // directive only, NO hit header, no Age
		w.Write([]byte("<html><body>a unique page</body></html>"))
	}))
	defer site.Close()

	s := newCacheDecScanner(t)
	s.db.Exec(`INSERT INTO targets (id, domain) VALUES ('t3','x.example')`)
	s.db.Exec(`INSERT INTO http_services (id, target_id, url, status_code) VALUES ('h4','t3',?,200)`, site.URL+"/account")

	if err := s.RunCacheDeception(context.Background(), "t3", func(_, _, _ string) {}); err != nil {
		t.Fatal(err)
	}
	if f := cacheDecFindings(t, s, "t3"); len(f) != 0 {
		t.Fatalf("a merely-cacheable page (no real cache hit) must NOT be flagged, got %v", f)
	}
}
