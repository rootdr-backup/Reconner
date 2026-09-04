package scheduler

import (
	"database/sql"
	"testing"
	"time"

	"github.com/recon-platform/internal/models"
)

// A watch pass that discovers new subdomains must enqueue a heavier escalation
// task (backup discovery + nuclei); an unchanged pass must stay quiet.
func TestEscalateIfChanged(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets (id, domain, subdomain_count) VALUES ('t','ex.com',10)`); err != nil {
		t.Fatalf("insert target: %v", err)
	}

	// No change: baseline 10 == current 10, no monitoring_changes → no task.
	s.escalateIfChanged("t", "ex.com", 10, time.Now().Add(-time.Minute))
	if n := countTasks(t, s, monitorEscalationType); n != 0 {
		t.Fatalf("no-change escalation created %d tasks, want 0", n)
	}

	// New subdomains appeared since the pass started (10 → 15) → escalate once.
	if _, err := s.db.Exec(`UPDATE targets SET subdomain_count=15 WHERE id='t'`); err != nil {
		t.Fatal(err)
	}
	s.escalateIfChanged("t", "ex.com", 10, time.Now().Add(-time.Minute))
	if n := countTasks(t, s, monitorEscalationType); n != 1 {
		t.Fatalf("changed escalation created %d tasks, want 1", n)
	}

	// The escalation task must include nuclei + backup discovery.
	var modules string
	if err := s.db.QueryRow(`SELECT modules FROM tasks WHERE type=? LIMIT 1`, monitorEscalationType).Scan(&modules); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{ModuleNuclei, ModuleBackupDiscovery} {
		found := false
		for _, m := range []string{ModuleHTTPProbe, ModuleBackupDiscovery, ModuleDirDiscovery, ModuleNuclei} {
			if m == want && contains(modules, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("escalation modules %q missing %q", modules, want)
		}
	}
}

func TestScheduledMonitorIsSnapshotFirstAndDeduplicated(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets(id,domain,monitor_enabled,monitor_interval_hours)
		VALUES('watch-target','example.com',1,1)`); err != nil {
		t.Fatal(err)
	}

	s.runDueMonitors()
	var modulesJSON string
	if err := s.db.QueryRow(`SELECT modules FROM tasks WHERE target_id='watch-target' AND type=?`, monitorWatchType).Scan(&modulesJSON); err != nil {
		t.Fatal(err)
	}
	modules := models.JSONToStringSlice(modulesJSON)
	position := func(want string) int {
		for i, m := range modules {
			if m == want {
				return i
			}
		}
		return -1
	}
	if position(ModuleMonitor) < 0 || position(ModuleHTTPProbe) < 0 || position(ModuleMonitor) > position(ModuleHTTPProbe) {
		t.Fatalf("watch must snapshot before HTTP refresh, got %v", modules)
	}
	var last sql.NullTime
	if err := s.db.QueryRow(`SELECT monitor_last_run FROM targets WHERE id='watch-target'`).Scan(&last); err != nil {
		t.Fatal(err)
	}
	if last.Valid {
		t.Fatal("enqueue time was incorrectly recorded as a successful monitor run")
	}

	// Re-running the due check while this task is pending must not create a twin.
	s.runDueMonitors()
	if got := countTasks(t, s, monitorWatchType); got != 1 {
		t.Fatalf("due scheduler created %d duplicate watch tasks, want 1", got)
	}
}

func TestTargetStatusDoesNotGoIdleWhileSiblingTaskRuns(t *testing.T) {
	s := newTestScheduler(t)
	_, _ = s.db.Exec(`INSERT INTO targets(id,domain,scan_status) VALUES('t-status','example.com','running')`)
	_, _ = s.db.Exec(`INSERT INTO tasks(id,target_id,type,status) VALUES
		('done','t-status','full_scan','finished'),('live','t-status','full_scan','running')`)

	s.refreshTargetScanStatus("t-status", "idle", true)
	var status string
	_ = s.db.QueryRow(`SELECT scan_status FROM targets WHERE id='t-status'`).Scan(&status)
	if status != "running" {
		t.Fatalf("finishing one task hid its running sibling: status=%q", status)
	}

	_, _ = s.db.Exec(`UPDATE tasks SET status='failed' WHERE id='live'`)
	s.refreshTargetScanStatus("t-status", "failed", true)
	_ = s.db.QueryRow(`SELECT scan_status FROM targets WHERE id='t-status'`).Scan(&status)
	if status != "failed" {
		t.Fatalf("last failed task must remain visible for resume UI: status=%q", status)
	}
}

func countTasks(t *testing.T, s *Scheduler, typ string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM tasks WHERE type=?`, typ).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func contains(hay, needle string) bool {
	return len(hay) >= len(needle) && (indexOf(hay, needle) >= 0)
}

func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
