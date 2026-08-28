package scanner

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/pkg/logger"
)

// Broken-link hijacking must scan DISCOVERED deep pages, not only host roots —
// that is where dead external links live. loadPages must union http_services,
// crawled parameters URLs, and directory_findings (deduped).
func TestBLHLoadPagesCoversDiscoveredSurface(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "blh.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	tid := uuid.New().String()
	_, _ = db.Exec(`INSERT INTO targets (id, domain) VALUES (?,?)`, tid, "example.com")
	// A live root, a crawled deep page (parameters), and a discovered directory.
	_, _ = db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,source) VALUES (?,?,?,200,'probe')`, uuid.New().String(), tid, "https://example.com/")
	_, _ = db.Exec(`INSERT INTO parameters (id,target_id,url,parameter,source) VALUES (?,?,?, 'q','crawl')`, uuid.New().String(), tid, "https://example.com/blog/post?q=1")
	_, _ = db.Exec(`INSERT INTO directory_findings (id,target_id,url,status_code) VALUES (?,?,?,200)`, uuid.New().String(), tid, "https://example.com/team")

	s := &BLHScanner{db: db, cfg: &config.Config{}, logger: logger.New("error")}
	pages := s.loadPages(context.Background(), tid)

	want := map[string]bool{
		"https://example.com/":              false,
		"https://example.com/blog/post?q=1": false, // deep crawled page — the key gain
		"https://example.com/team":          false, // discovered directory
	}
	for _, p := range pages {
		if _, ok := want[p]; ok {
			want[p] = true
		}
	}
	for u, seen := range want {
		if !seen {
			t.Errorf("BLH loadPages must include discovered page %q; got %v", u, pages)
		}
	}
}
