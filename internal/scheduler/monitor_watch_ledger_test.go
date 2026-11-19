package scheduler

import (
	"context"
	"testing"
)

// A store-only target has no scannable DNS roots. The worker prunes
// subdomain_enum from the run list, but must still resolve its ledger row.
// Otherwise the terminal backstop rewrites an otherwise finished watch pass
// to "failed" with the phase ledger invariant error.
func TestMonitorWatchNoRootsLeavesNoPendingPhase(t *testing.T) {
	s := newTestScheduler(t)
	// play.google.com is an app-listing host. loadSubdomainRoots rejects it
	// even as the fallback scope, so subdomainRoots is empty and the prune
	// at executeTask fires.
	if _, err := s.db.Exec(`INSERT INTO targets(id,domain) VALUES('ledger-store-target','play.google.com')`); err != nil {
		t.Fatal(err)
	}
	task, err := s.CreateTaskTyped("ledger-store-target", []string{ModuleSubdomainEnum, ModuleVerify}, 3, monitorWatchType)
	if err != nil {
		t.Fatal(err)
	}

	// Both modules start with a pending phase row, and total counts both.
	var totalPhases int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM task_phases WHERE task_id=?`, task.ID).Scan(&totalPhases); err != nil {
		t.Fatal(err)
	}
	if task.Total != 2 || totalPhases != 2 {
		t.Fatalf("task.Total=%d, phase rows=%d, want 2 and 2", task.Total, totalPhases)
	}

	s.executeTask(context.Background(), task.ID)

	var taskStatus, taskError string
	if err := s.db.QueryRow(`SELECT status,error FROM tasks WHERE id=?`, task.ID).Scan(&taskStatus, &taskError); err != nil {
		t.Fatal(err)
	}
	if taskStatus != "finished" {
		t.Fatalf("task status = %q (error=%q), want finished", taskStatus, taskError)
	}

	var phaseStatus, phaseReason string
	if err := s.db.QueryRow(`SELECT status,reason FROM task_phases WHERE task_id=? AND module=?`,
		task.ID, ModuleSubdomainEnum).Scan(&phaseStatus, &phaseReason); err != nil {
		t.Fatal(err)
	}
	if phaseStatus != "skipped" {
		t.Fatalf("subdomain_enum phase status = %q, want skipped", phaseStatus)
	}
	const wantReason = "no scannable web roots (store and app assets excluded)"
	if phaseReason != wantReason {
		t.Fatalf("subdomain_enum phase reason = %q, want %q", phaseReason, wantReason)
	}

	var unresolved int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM task_phases WHERE task_id=? AND status IN ('pending','running')`,
		task.ID).Scan(&unresolved); err != nil {
		t.Fatal(err)
	}
	if unresolved != 0 {
		t.Fatalf("%d phase(s) still unresolved — the ledger invariant would fail", unresolved)
	}

	// The phase row must not be deleted; total still equals the row count.
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM task_phases WHERE task_id=?`, task.ID).Scan(&totalPhases); err != nil {
		t.Fatal(err)
	}
	if totalPhases != 2 {
		t.Fatalf("phase rows after run = %d, want 2", totalPhases)
	}

	// The other module still completes normally.
	var verifyStatus string
	if err := s.db.QueryRow(`SELECT status FROM task_phases WHERE task_id=? AND module=?`,
		task.ID, ModuleVerify).Scan(&verifyStatus); err != nil {
		t.Fatal(err)
	}
	if verifyStatus != "completed" {
		t.Fatalf("verify phase status = %q, want completed", verifyStatus)
	}
}

// A target with a normal scannable domain does not take the prune path. Its
// phases stay unchanged: no module is marked skipped and the task finishes.
// This uses ModuleVerify only so the test needs no network.
func TestMonitorWatchWithRootsLeavesPhasesUnchanged(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets(id,domain) VALUES('ledger-web-target','example.com')`); err != nil {
		t.Fatal(err)
	}
	task, err := s.CreateTaskTyped("ledger-web-target", []string{ModuleVerify}, 3, monitorWatchType)
	if err != nil {
		t.Fatal(err)
	}
	s.executeTask(context.Background(), task.ID)

	var taskStatus, phaseStatus string
	if err := s.db.QueryRow(`SELECT status FROM tasks WHERE id=?`, task.ID).Scan(&taskStatus); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT status FROM task_phases WHERE task_id=? AND module=?`,
		task.ID, ModuleVerify).Scan(&phaseStatus); err != nil {
		t.Fatal(err)
	}
	if taskStatus != "finished" || phaseStatus != "completed" {
		t.Fatalf("task=%q phase=%q, want finished/completed", taskStatus, phaseStatus)
	}
}
