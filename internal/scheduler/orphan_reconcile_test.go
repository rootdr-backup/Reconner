package scheduler

import "testing"

// After a crash/restart the zombie task is cancelled, but the OWNING TARGET used
// to keep scan_status='running' forever — so the UI showed the target scanning
// while SkipCurrentPhase reported "no running scan". recoverPendingTasks must now
// reconcile that: a target claiming running/paused with no live task is reset to
// idle.
func TestRecoverResetsOrphanedTargetStatus(t *testing.T) {
	s := newTestScheduler(t)

	// A target that looks like it's still scanning, with a zombie 'running' task.
	if _, err := s.db.Exec(`INSERT INTO targets (id, domain, scan_status) VALUES ('t1','example.com','running')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO tasks (id, target_id, type, status) VALUES ('task1','t1','full_scan','running')`); err != nil {
		t.Fatal(err)
	}
	// A second target that is genuinely idle must be left alone.
	if _, err := s.db.Exec(`INSERT INTO targets (id, domain, scan_status) VALUES ('t2','idle.example','idle')`); err != nil {
		t.Fatal(err)
	}

	s.recoverPendingTasks()

	var taskStatus, t1Status, t2Status string
	s.db.QueryRow(`SELECT status FROM tasks WHERE id='task1'`).Scan(&taskStatus)
	s.db.QueryRow(`SELECT scan_status FROM targets WHERE id='t1'`).Scan(&t1Status)
	s.db.QueryRow(`SELECT scan_status FROM targets WHERE id='t2'`).Scan(&t2Status)

	if taskStatus != "cancelled" {
		t.Errorf("zombie task status=%q, want cancelled", taskStatus)
	}
	if t1Status != "idle" {
		t.Errorf("orphaned target scan_status=%q, want idle", t1Status)
	}
	if t2Status != "idle" {
		t.Errorf("untouched idle target scan_status=%q, want idle", t2Status)
	}
}

// The on-demand escape hatch: an operator clicking Skip on a target that is stuck
// showing 'running' (no live task behind it) heals it instead of just erroring.
func TestSkipReconcilesOrphanedTarget(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets (id, domain, scan_status) VALUES ('t1','example.com','running')`); err != nil {
		t.Fatal(err)
	}
	// No task rows at all → nothing running, but the target claims 'running'.
	err := s.SkipCurrentPhase("t1")
	if err == nil {
		t.Fatal("expected a message that the stale state was cleared")
	}
	var status string
	s.db.QueryRow(`SELECT scan_status FROM targets WHERE id='t1'`).Scan(&status)
	if status != "idle" {
		t.Errorf("after skip on orphaned target, scan_status=%q, want idle", status)
	}
}

// A target with a live pending task must NOT be reconciled away — that scan is
// legitimately queued.
func TestReconcileLeavesPendingTargetAlone(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets (id, domain, scan_status) VALUES ('t1','example.com','running')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO tasks (id, target_id, type, status) VALUES ('task1','t1','full_scan','pending')`); err != nil {
		t.Fatal(err)
	}
	if healed := s.reconcileOrphanedTarget("t1"); healed {
		t.Error("target with a pending task must not be reconciled to idle")
	}
	var status string
	s.db.QueryRow(`SELECT scan_status FROM targets WHERE id='t1'`).Scan(&status)
	if status != "running" {
		t.Errorf("target with pending task scan_status=%q, want running (untouched)", status)
	}
}
