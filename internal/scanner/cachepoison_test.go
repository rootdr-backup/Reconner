package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
)

func cachePoisonTestScanner(t *testing.T) (*CachePoisonScanner, *database.DB, string) {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "cache-poison.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	const targetID = "cache-target"
	_, _ = db.Exec(`INSERT INTO targets(id,domain) VALUES(?,?)`, targetID, "cache.example")
	return &CachePoisonScanner{db: db, cfg: &config.Config{}}, db, targetID
}

func TestCachePoisonRejectsCachedWAFReflection(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Cache", "HIT")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "request blocked by WAF: %s", r.Header.Get("X-Forwarded-Host"))
	}))
	defer srv.Close()
	s, db, targetID := cachePoisonTestScanner(t)
	if s.testURL(context.Background(), targetID, srv.URL, nil, func(_, _, _ string) {}) {
		t.Fatal("a cached WAF block-page reflection must not be confirmed")
	}
	var count int
	_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='cache_poisoning'`, targetID).Scan(&count)
	if count != 0 {
		t.Fatalf("cached WAF reflection produced %d rows", count)
	}
}

func TestCachePoisonRequiresTwoCleanHitReplays(t *testing.T) {
	withLoopbackAllowed(t)
	var mu sync.Mutex
	stored := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.String()
		mu.Lock()
		defer mu.Unlock()
		if host := r.Header.Get("X-Forwarded-Host"); host != "" {
			stored[key] = host
			fmt.Fprint(w, "canonical="+host)
			return
		}
		if host := stored[key]; host != "" {
			w.Header().Set("X-Cache", "HIT")
			fmt.Fprint(w, "canonical="+host)
			return
		}
		fmt.Fprint(w, "clean")
	}))
	defer srv.Close()
	s, db, targetID := cachePoisonTestScanner(t)
	if !s.testURL(context.Background(), targetID, srv.URL, nil, func(_, _, _ string) {}) {
		t.Fatal("stable canary replay from a shared-cache hit should be confirmed")
	}
	var count, confidence int
	_ = db.QueryRow(`SELECT COUNT(*),MAX(confidence) FROM vuln_findings WHERE target_id=? AND type='cache_poisoning' AND status='finding'`, targetID).Scan(&count, &confidence)
	if count != 1 || confidence < ConfEvidence {
		t.Fatalf("confirmed cache finding count/confidence=%d/%d", count, confidence)
	}
}

func TestCachePotentiallySharedRejectsPrivate(t *testing.T) {
	if cachePotentiallyShared(http.Header{"Cache-Control": {"private, max-age=600"}, "X-Cache": {"MISS"}}) {
		t.Fatal("private responses must not become cache-poison candidates")
	}
	if !cachePotentiallyShared(http.Header{"Cache-Control": {"public, s-maxage=60"}}) {
		t.Fatal("public shared-cache directives should remain candidate signal")
	}
}
