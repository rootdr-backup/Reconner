package api

import (
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/pkg/logger"
)

func TestRequireIDORIdentities(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	h := &Handler{db: db, logger: logger.New("error")}

	tid := uuid.New().String()
	if _, err := db.Exec(`INSERT INTO targets (id, domain, priority) VALUES (?,?, 'medium')`, tid, "t.local"); err != nil {
		t.Fatal(err)
	}

	// No idor in the module list → never gated, regardless of identities.
	if err := h.requireIDORIdentities(tid, []string{"http_probe", "nuclei"}); err != nil {
		t.Fatalf("non-idor scan must not be gated: %v", err)
	}

	// idor selected, zero identities → rejected.
	if err := h.requireIDORIdentities(tid, []string{"http_probe", "idor"}); err == nil {
		t.Fatal("idor with 0 identities must be rejected")
	}

	// one identity → still rejected (need two).
	addIdentity(t, db, tid, true)
	if err := h.requireIDORIdentities(tid, []string{"idor"}); err == nil {
		t.Fatal("idor with 1 identity must be rejected")
	}

	// two identities → allowed.
	addIdentity(t, db, tid, false)
	if err := h.requireIDORIdentities(tid, []string{"idor"}); err != nil {
		t.Fatalf("idor with 2 identities must be allowed: %v", err)
	}
}

func addIdentity(t *testing.T, db *database.DB, targetID string, baseline bool) {
	t.Helper()
	b := 0
	if baseline {
		b = 1
	}
	if _, err := db.Exec(
		`INSERT INTO identities (id, target_id, label, headers_json, is_baseline) VALUES (?,?,?,?,?)`,
		uuid.New().String(), targetID, "u", `{"Cookie":"x=y"}`, b); err != nil {
		t.Fatal(err)
	}
}
