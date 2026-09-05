package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
)

func TestAdaptiveWordlistMinesAndPersistsSafeTargetVocabulary(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "adaptive.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	const targetID = "adaptive-target"
	_, err = db.Exec(`INSERT INTO targets(id,domain,name,description) VALUES(?,?,?,?)`,
		targetID, "acme.example", "Acme Inventory", "Responsible security testing")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = db.Exec(`INSERT INTO assets(id,target_id,name,value,approval_status) VALUES('a1',?,?,?,'approved')`, targetID, "Billing Portal", "billing.acme.example")
	_, _ = db.Exec(`INSERT INTO http_services(id,target_id,url,status_code,title) VALUES('h1',?,?,200,'Inventory Console')`, targetID, "https://app.acme.example/inventory/dashboard")
	_, _ = db.Exec(`INSERT INTO parameters(id,target_id,url,parameter) VALUES('p1',?,?,?)`, targetID, "https://app.acme.example/api/invoices", "tenant_id")
	_, _ = db.Exec(`INSERT INTO directory_findings(id,target_id,url,status_code) VALUES('d1',?,?,200)`, targetID, "https://app.acme.example/fulfillment/jobs")

	dir := filepath.Join(t.TempDir(), "wordlists")
	cfg := &config.Config{WordlistsDir: dir}
	words := buildAdaptiveWordlist(context.Background(), db, cfg, targetID, []string{
		"https://app.acme.example/api/warehouse/stock?region_code=eu",
		"https://app.acme.example/static/0123456789abcdef0123456789abcdef.js",
	})
	contains := func(want string) bool {
		for _, word := range words {
			if word == want {
				return true
			}
		}
		return false
	}
	for _, want := range []string{"inventory", "tenant_id", "warehouse", "region_code", "fulfillment"} {
		if !contains(want) {
			t.Errorf("adaptive wordlist missing target-specific word %q: %v", want, words)
		}
	}
	if contains("0123456789abcdef0123456789abcdef") {
		t.Fatal("hash-like values must never be persisted as adaptive words")
	}
	path := adaptiveWordlistPath(dir, "acme.example")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("adaptive wordlist was not persisted: %v", err)
	}
	loaded := loadAdaptiveWordlist(dir, "acme.example", 1200)
	if len(loaded) != len(words) {
		t.Fatalf("persisted wordlist length=%d, want %d", len(loaded), len(words))
	}

	dirPaths := adaptiveDirectoryPaths([]string{"inventory"}, 1)
	if len(dirPaths) != 2 || dirPaths[0] != "/inventory" || dirPaths[1] != "/api/inventory" {
		t.Fatalf("unexpected adaptive directory paths: %v", dirPaths)
	}
	backupPaths := generateAdaptiveBackupCandidates([]string{"inventory"}, 1)
	if len(backupPaths) != 4 || backupPaths[1] != "/inventory.sql" {
		t.Fatalf("unexpected bounded adaptive backup paths: %v", backupPaths)
	}
}

func TestNormalizeAdaptiveWordRejectsNoise(t *testing.T) {
	for _, bad := range []string{"ab", "12345", "0123456789abcdef0123456789abcdef", "../../etc/passwd", "https"} {
		if got := normalizeAdaptiveWord(bad); got != "" {
			t.Errorf("normalizeAdaptiveWord(%q)=%q, want rejection", bad, got)
		}
	}
}
