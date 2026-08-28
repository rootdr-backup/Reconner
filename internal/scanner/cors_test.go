package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
)

// TestCORSCriticalReflectedWithCreds verifies the critical case: an endpoint
// that reflects an arbitrary Origin AND allows credentials is a confirmed
// finding.
func TestCORSCriticalReflectedWithCreds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin) // reflects ANY origin
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	db, err := database.New(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	tid := uuid.New().String()
	_, _ = db.Exec(`INSERT INTO targets (id,domain,priority,kind) VALUES (?,?, 'medium','web')`, tid, "x.example")
	_, _ = db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,source) VALUES (?,?,?,200,'probe')`, uuid.New().String(), tid, srv.URL)

	s := &CORSScanner{db: db, cfg: &config.Config{}}
	if err := s.Run(context.Background(), tid, func(string, string, string) {}); err != nil {
		t.Fatal(err)
	}
	var sev, status string
	var conf int
	err = db.QueryRow(`SELECT severity, status, confidence FROM vuln_findings WHERE target_id=? AND type='cors_misconfig'`, tid).Scan(&sev, &status, &conf)
	if err != nil {
		t.Fatalf("expected a cors_misconfig finding: %v", err)
	}
	if sev != "critical" || status != StatusFinding {
		t.Errorf("got severity=%q status=%q, want critical/finding", sev, status)
	}
}

// TestCORSWildcardNotReported verifies the biggest false-positive class is
// suppressed: ACAO: * (with or without credentials) is NOT browser-exploitable
// and must not produce a finding.
func TestCORSWildcardNotReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	db, err := database.New(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	tid := uuid.New().String()
	_, _ = db.Exec(`INSERT INTO targets (id,domain,priority,kind) VALUES (?,?, 'medium','web')`, tid, "x.example")
	_, _ = db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,source) VALUES (?,?,?,200,'probe')`, uuid.New().String(), tid, srv.URL)

	s := &CORSScanner{db: db, cfg: &config.Config{}}
	_ = s.Run(context.Background(), tid, func(string, string, string) {})
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='cors_misconfig'`, tid).Scan(&n)
	if n != 0 {
		t.Errorf("ACAO:* must NOT be reported, got %d findings", n)
	}
}

// TestReconnerTemplatePackMaterializes verifies the embedded template pack is
// non-empty and writes to disk.
func TestReconnerTemplatePackMaterializes(t *testing.T) {
	if reconnerTemplateCount() < 5 {
		t.Fatalf("expected the embedded template pack to carry several templates, got %d", reconnerTemplateCount())
	}
	dir := materializeReconnerTemplates(t.TempDir())
	if dir == "" {
		t.Fatal("materializeReconnerTemplates returned empty dir")
	}
	if !dirHasTemplates(dir) {
		t.Errorf("materialized pack dir %q has no templates", dir)
	}
}
