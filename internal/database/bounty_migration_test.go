package database

import (
	"path/filepath"
	"testing"
)

func TestBountyProjectMigrationsAreCompleteAndIdempotent(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "bounty.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"bounty_programs", "bounty_program_assets", "bounty_sync_state", "project_programs", "bounty_scope_events"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Errorf("missing table %s", table)
		}
	}
	required := map[string]bool{"asset_type": false, "source": false, "source_id": false, "approval_status": false, "monitor_enabled": false, "metadata": false}
	rows, err := db.Query(`PRAGMA table_info(assets)`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var cid, notNull, pk int
		var name, typ string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			t.Fatal(err)
		}
		if _, ok := required[name]; ok {
			required[name] = true
		}
	}
	_ = rows.Close()
	for name, found := range required {
		if !found {
			t.Errorf("assets.%s migration missing", name)
		}
	}
	if err := RunMigrations(db); err != nil {
		t.Fatalf("bounty migrations are not idempotent: %v", err)
	}
}
