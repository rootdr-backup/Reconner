package scheduler

import (
	"context"
	"testing"
)

func TestCancelTaskPersistsPausedTaskAndClearsControls(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets(id,domain,scan_status) VALUES('target','example.test','paused')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO tasks(id,target_id,type,status,modules,total) VALUES('task','target','full_scan','paused','[]',0)`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.cancelMap["task"] = cancel
	s.running["task"] = true
	s.taskTargets["task"] = "target"
	s.mu.Unlock()
	s.pauseMu.Lock()
	s.paused["task"] = true
	s.skipReq["task"] = true
	s.pauseMu.Unlock()

	if err := s.CancelTask("task"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("paused task context was not cancelled")
	}
	var taskStatus, targetStatus string
	if err := s.db.QueryRow(`SELECT status FROM tasks WHERE id='task'`).Scan(&taskStatus); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT scan_status FROM targets WHERE id='target'`).Scan(&targetStatus); err != nil {
		t.Fatal(err)
	}
	if taskStatus != "cancelled" || targetStatus != "idle" {
		t.Fatalf("cancel state task=%q target=%q", taskStatus, targetStatus)
	}
	if s.isPaused("task") {
		t.Fatal("cancelled task retained its pause gate")
	}
	s.pauseMu.Lock()
	_, retainedSkip := s.skipReq["task"]
	s.pauseMu.Unlock()
	if retainedSkip {
		t.Fatal("cancelled task retained its skip state")
	}
}

func TestCancelTasksForTargetIncludesPausedScans(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets(id,domain,scan_status) VALUES('target','example.test','paused')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO tasks(id,target_id,type,status,modules,total) VALUES('paused-task','target','full_scan','paused','[]',0)`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.cancelMap["paused-task"] = cancel
	s.running["paused-task"] = true
	s.taskTargets["paused-task"] = "target"
	s.mu.Unlock()
	s.pauseMu.Lock()
	s.paused["paused-task"] = true
	s.pauseMu.Unlock()

	if err := s.CancelTasksForTarget("target"); err != nil {
		t.Fatal(err)
	}

	select {
	case <-ctx.Done():
	default:
		t.Fatal("target cancellation left paused context alive")
	}
	var status string
	if err := s.db.QueryRow(`SELECT status FROM tasks WHERE id='paused-task'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "cancelled" {
		t.Fatalf("paused task status=%q want cancelled", status)
	}
}

func TestCancelTaskRejectsMissingOrTerminalTask(t *testing.T) {
	s := newTestScheduler(t)
	if err := s.CancelTask("missing"); err == nil {
		t.Fatal("missing task cancellation reported success")
	}
	if _, err := s.db.Exec(`INSERT INTO targets(id,domain) VALUES('target','example.test')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO tasks(id,target_id,type,status,modules,total) VALUES('done','target','full_scan','finished','[]',0)`); err != nil {
		t.Fatal(err)
	}
	if err := s.CancelTask("done"); err == nil {
		t.Fatal("terminal task cancellation reported success")
	}
}
