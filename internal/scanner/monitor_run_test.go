package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
)

func newMonitorTestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "monitor.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestMonitorEstablishesEmptyJSBaselineThenDetectsChange(t *testing.T) {
	var mu sync.RWMutex
	body := "console.log('v1')"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		mu.RLock()
		defer mu.RUnlock()
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	db := newMonitorTestDB(t)
	targetID := uuid.NewString()
	_, _ = db.Exec(`INSERT INTO targets(id,domain) VALUES(?,?)`, targetID, srv.URL)
	_, _ = db.Exec(`INSERT INTO js_files(id,target_id,url,hash) VALUES(?,?,?,'')`, uuid.NewString(), targetID, srv.URL+"/app.js")

	s := &MonitorScanner{db: db}
	logFn := func(string, string, string) {}
	if err := s.Run(context.Background(), targetID, logFn); err != nil {
		t.Fatal(err)
	}
	var baseline string
	if err := db.QueryRow(`SELECT hash FROM js_files WHERE target_id=?`, targetID).Scan(&baseline); err != nil {
		t.Fatal(err)
	}
	if baseline == "" {
		t.Fatal("first monitor pass did not establish the JavaScript hash baseline")
	}
	var changes int
	_ = db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=?`, targetID).Scan(&changes)
	if changes != 0 {
		t.Fatalf("first baseline pass raised %d changes, want 0", changes)
	}

	mu.Lock()
	body = "console.log('v2')"
	mu.Unlock()
	if err := s.Run(context.Background(), targetID, logFn); err != nil {
		t.Fatal(err)
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=? AND change_type='js_change'`, targetID).Scan(&changes)
	if changes != 1 {
		t.Fatalf("changed JavaScript produced %d js_change rows, want 1", changes)
	}
}

func TestMonitorURLKeyDeduplicatesEquivalentURLs(t *testing.T) {
	a := monitorURLKey("HTTPS://Example.COM:443#fragment")
	b := monitorURLKey("https://example.com/")
	if a != b {
		t.Fatalf("equivalent URLs have different monitor keys: %q != %q", a, b)
	}
	if monitorURLKey("https://example.com/a?x=1") == monitorURLKey("https://example.com/a?x=2") {
		t.Fatal("query-distinct endpoints must not be deduplicated")
	}
}

func TestMonitorBareAssetFallsBackToHTTP(t *testing.T) {
	candidates := monitorAssetCandidates("example.com", "domain", "")
	if len(candidates) != 2 || candidates[0] != "https://example.com" || candidates[1] != "http://example.com" {
		t.Fatalf("unexpected bare-domain monitor candidates: %v", candidates)
	}
}

func TestMonitorSecurityHostComparisonUsesParsedHosts(t *testing.T) {
	if got := hostOf("https://[2001:db8::1]:8443/path"); got != "2001:db8::1" {
		t.Fatalf("IPv6 monitor host=%q", got)
	}
	if !isExternalResource("https://cdn.example.com/app.js", "www.example.com") {
		t.Fatal("a different subdomain is a distinct browser origin and must be tracked")
	}
	if isExternalResource("https://www.example.com:8443/app.js", "www.example.com") {
		t.Fatal("the same hostname with a different port should not be classified as a third-party host")
	}
}

func TestMonitorRejectsHTMLAtJavaScriptURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><html><body>login</body></html>"))
	}))
	defer srv.Close()
	_, _, err := (&MonitorScanner{}).fetchHash(context.Background(), srv.URL+"/app.js")
	if err == nil || !strings.Contains(err.Error(), "HTML") {
		t.Fatalf("HTML error/login page must not become a JS baseline: %v", err)
	}
}

func TestMonitorIgnoresUnstableOneOffContent(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1)%2 == 1 {
			_, _ = w.Write([]byte("temporary edge response A"))
		} else {
			_, _ = w.Write([]byte("temporary edge response B"))
		}
	}))
	defer srv.Close()

	db := newMonitorTestDB(t)
	targetID := uuid.NewString()
	serviceID := uuid.NewString()
	oldHash := normalizedHash("stable baseline")
	_, _ = db.Exec(`INSERT INTO targets(id,domain) VALUES(?,?)`, targetID, srv.URL)
	_, _ = db.Exec(`INSERT INTO http_services(id,target_id,url,status_code,title,norm_hash,source) VALUES(?,?,?,200,'',?,'probe')`, serviceID, targetID, srv.URL, oldHash)

	if err := (&MonitorScanner{db: db}).Run(context.Background(), targetID, func(string, string, string) {}); err != nil {
		t.Fatal(err)
	}
	var changes int
	_ = db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=?`, targetID).Scan(&changes)
	if changes != 0 {
		t.Fatalf("unstable response raised %d monitoring changes", changes)
	}
	var storedHash string
	_ = db.QueryRow(`SELECT norm_hash FROM http_services WHERE id=?`, serviceID).Scan(&storedHash)
	if storedHash != oldHash {
		t.Fatalf("unstable response replaced baseline: got %q want %q", storedHash, oldHash)
	}
}
