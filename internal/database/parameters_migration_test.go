package database

import (
	"path/filepath"
	"testing"
)

func TestParametersMigrationPreservesRequestVariants(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "migration.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO targets (id,domain) VALUES ('t1','example.test')`); err != nil {
		t.Fatal(err)
	}
	// Recreate the legacy table exactly as an upgraded installation would have it.
	if _, err := db.Exec(`DROP TABLE parameters`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE parameters (
		id TEXT PRIMARY KEY,target_id TEXT NOT NULL,url TEXT NOT NULL,parameter TEXT NOT NULL,
		value TEXT DEFAULT '',source TEXT DEFAULT '',is_reflected INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,method TEXT DEFAULT 'GET',
		content_type TEXT DEFAULT '',location TEXT DEFAULT 'query',
		UNIQUE(target_id,url,parameter))`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO parameters (id,target_id,url,parameter,value,method,location) VALUES ('p1','t1','https://example.test/search','q','one','GET','query')`); err != nil {
		t.Fatal(err)
	}
	if err := RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	// Same URL/name, different request contract: both must coexist after upgrade.
	if _, err := db.Exec(`INSERT INTO parameters (id,target_id,url,parameter,value,method,content_type,location)
		VALUES ('p2','t1','https://example.test/search','q','two','POST','application/json','json')`); err != nil {
		t.Fatalf("request variants still collide after migration: %v", err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM parameters WHERE target_id='t1' AND url='https://example.test/search' AND parameter='q'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("migration lost/collapsed request variants: count=%d", count)
	}
	// Idempotence: every server startup runs RunMigrations.
	if err := RunMigrations(db); err != nil {
		t.Fatalf("request-identity migration is not idempotent: %v", err)
	}
}
