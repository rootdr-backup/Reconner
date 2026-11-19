package scheduler

import (
	"context"
	"database/sql"
	"testing"
)

// Finalizing an operator-cancelled monitor watch pass must count it as an
// attempt for the due scheduler. runDueMonitors used to re-create cancelled
// watch passes because monitor_last_run never moved — the "cancel doesn't
// work, it re-probes and scans again" loop.
func TestCancelledMonitorWatchCountsAsRunForDueScheduler(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets(id,domain,monitor_enabled,monitor_interval_hours)
		VALUES('mc-target','example.com',1,1)`); err != nil {
		t.Fatal(err)
	}
	// Empty-module watch fixture keeps executeTask at the finalization path.
	if _, err := s.db.Exec(`INSERT INTO tasks(id,target_id,type,status,modules,total)
		VALUES('mc-cancel-watch','mc-target',?,'pending','[]',0)`, monitorWatchType); err != nil {
		t.Fatal(err)
	}

	// The operator cancels the pass.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancel()
	s.executeTask(ctx, "mc-cancel-watch")

	var taskStatus string
	if err := s.db.QueryRow(`SELECT status FROM tasks WHERE id='mc-cancel-watch'`).Scan(&taskStatus); err != nil {
		t.Fatal(err)
	}
	if taskStatus != "cancelled" {
		t.Fatalf("watch task status = %q, want cancelled", taskStatus)
	}
	var last sql.NullTime
	if err := s.db.QueryRow(`SELECT monitor_last_run FROM targets WHERE id='mc-target'`).Scan(&last); err != nil {
		t.Fatal(err)
	}
	if !last.Valid {
		t.Fatal("cancelled watch pass did not stamp monitor_last_run")
	}

	// Expire the 30-minute creation guard, then re-run the due check so only
	// the stamped monitor_last_run can hold the scheduler back.
	if _, err := s.db.Exec(`UPDATE tasks SET created_at=datetime('now','-31 minutes') WHERE id='mc-cancel-watch'`); err != nil {
		t.Fatal(err)
	}
	s.runDueMonitors()
	if got := countTasks(t, s, monitorWatchType); got != 1 {
		t.Fatalf("due scheduler re-created the cancelled watch pass: %d watch task(s)", got)
	}
}

// Graceful-shutdown interruptions are owned by auto-resume and must NOT be
// counted as a monitor attempt.
func TestInterruptedMonitorWatchDoesNotCountAsRun(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets(id,domain,monitor_enabled,monitor_interval_hours)
		VALUES('mc-interrupted','example.com',1,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO tasks(id,target_id,type,status,modules,total)
		VALUES('mc-interrupted-watch','mc-interrupted',?,'interrupted','[]',0)`, monitorWatchType); err != nil {
		t.Fatal(err)
	}

	// Context cancellation alone must not override the parked 'interrupted' row.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancel()
	s.executeTask(ctx, "mc-interrupted-watch")

	var last sql.NullTime
	if err := s.db.QueryRow(`SELECT monitor_last_run FROM targets WHERE id='mc-interrupted'`).Scan(&last); err != nil {
		t.Fatal(err)
	}
	if last.Valid {
		t.Fatal("interrupted watch pass was counted as a monitor attempt; auto-resume would lose its restart window")
	}

	s.runDueMonitors()
	if got := countTasks(t, s, monitorWatchType); got != 1 {
		t.Fatalf("due scheduler must keep the interrupted watch pass guarded: %d watch task(s)", got)
	}
}
