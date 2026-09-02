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

func TestBountyMigrationUpgradesNonEmptyLegacyAssets(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "legacy-assets.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Reproduce a pre-1.3 database: assets exists and contains user data before
	// the new catalog columns are added. SQLite rejects a non-constant default in
	// exactly this state.
	if _, err := db.Exec(createTargetsTable); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(createAssetsTable); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO targets(id,domain) VALUES('legacy-target','example.test')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO assets(id,target_id,name,value,kind)
		VALUES('legacy-asset','legacy-target','root','example.test','web')`); err != nil {
		t.Fatal(err)
	}
	if err := RunMigrations(db); err != nil {
		t.Fatalf("non-empty legacy migration failed: %v", err)
	}
	var value, updated string
	if err := db.QueryRow(`SELECT value,updated_at FROM assets WHERE id='legacy-asset'`).Scan(&value, &updated); err != nil {
		t.Fatal(err)
	}
	if value != "example.test" || updated == "" {
		t.Fatalf("legacy asset was not preserved/backfilled: value=%q updated_at=%q", value, updated)
	}
	if err := RunMigrations(db); err != nil {
		t.Fatalf("upgraded migration is not idempotent: %v", err)
	}
}
