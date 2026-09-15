package database

import (
	"path/filepath"
	"testing"
)

func TestTaskPhaseMigrationBackfillsExecutionOnlyAndIsIdempotent(t *testing.T) {
	db, err := New(filepath.Join(t.TempDir(), "phases.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO targets(id,domain) VALUES('target','example.com')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tasks(id,target_id,type,status,modules,completed_modules,total,progress)
		VALUES('legacy-finished','target','full_scan','finished',?,'["http_probe","xss"]',4,4),
		('legacy-pending','target','full_scan','pending',?,'[]',3,0),
		('legacy-network','target','network','finished','["network"]','["network"]',1,1),
		('legacy-failed','target','full_scan','failed','["http_probe","verify"]','["http_probe"]',2,1)`,
		`["http_probe","speed_fast","xss","no_subdomain_brute"]`,
		`["http_probe","speed_normal","verify"]`); err != nil {
		t.Fatal(err)
	}
	if err := RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	// Run a third time to prove INSERT OR IGNORE doesn't duplicate phase rows.
	if err := RunMigrations(db); err != nil {
		t.Fatal(err)
	}

	var phases, total, progress int
	if err := db.QueryRow(`SELECT COUNT(*) FROM task_phases WHERE task_id='legacy-finished'`).Scan(&phases); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT total,progress FROM tasks WHERE id='legacy-finished'`).Scan(&total, &progress); err != nil {
		t.Fatal(err)
	}
	if phases != 2 || total != 2 || progress != 2 {
		t.Fatalf("finished migration phases=%d total=%d progress=%d, want 2/2/2", phases, total, progress)
	}
	var nonCompleted int
	if err := db.QueryRow(`SELECT COUNT(*) FROM task_phases WHERE task_id='legacy-finished' AND status!='completed'`).Scan(&nonCompleted); err != nil {
		t.Fatal(err)
	}
	if nonCompleted != 0 {
		t.Fatalf("finished legacy task has %d non-completed phase rows", nonCompleted)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM task_phases WHERE task_id='legacy-pending'`).Scan(&phases); err != nil {
		t.Fatal(err)
	}
	if phases != 2 {
		t.Fatalf("pending migration phases=%d, want 2", phases)
	}
	var status, reason string
	if err := db.QueryRow(`SELECT status,reason FROM task_phases WHERE task_id='legacy-network'`).Scan(&status, &reason); err != nil {
		t.Fatal(err)
	}
	if status != "unsupported" || reason == "" {
		t.Fatalf("legacy network phase=(%q,%q), want explicit unsupported reason", status, reason)
	}
	var unresolved int
	if err := db.QueryRow(`SELECT COUNT(*) FROM task_phases WHERE task_id='legacy-failed' AND status IN ('pending','running')`).Scan(&unresolved); err != nil {
		t.Fatal(err)
	}
	if unresolved != 0 {
		t.Fatalf("terminal legacy task retained %d unresolved phases", unresolved)
	}
}
