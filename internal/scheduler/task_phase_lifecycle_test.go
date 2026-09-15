package scheduler

import (
	"context"
	"strings"
	"testing"

	"github.com/recon-platform/internal/models"
)

func TestExecuteTaskFinishesOnlyWithTerminalPhaseLedger(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets(id,domain) VALUES('ledger-target','example.com')`); err != nil {
		t.Fatal(err)
	}
	task, err := s.CreateTask("ledger-target", []string{ModuleVerify, "speed_fast"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	s.executeTask(context.Background(), task.ID)

	var taskStatus, phaseStatus string
	var total, progress, attempts int
	if err := s.db.QueryRow(`SELECT status,total,progress FROM tasks WHERE id=?`, task.ID).Scan(&taskStatus, &total, &progress); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT status,attempt_count FROM task_phases WHERE task_id=?`, task.ID).Scan(&phaseStatus, &attempts); err != nil {
		t.Fatal(err)
	}
	if taskStatus != "finished" || phaseStatus != "completed" || total != 1 || progress != 1 || attempts != 1 {
		t.Fatalf("task=%s phase=%s total=%d progress=%d attempts=%d", taskStatus, phaseStatus, total, progress, attempts)
	}
}

func TestLegacyUnsupportedModuleCannotFinishGreen(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets(id,domain,kind) VALUES('legacy-network-target','10.0.0.1','network')`); err != nil {
		t.Fatal(err)
	}
	modules := models.StringSliceToJSON([]string{ModuleNetwork})
	if _, err := s.db.Exec(`INSERT INTO tasks(id,target_id,type,status,modules,total)
		VALUES('legacy-network-task','legacy-network-target','network','pending',?,1)`, modules); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO task_phases(task_id,phase_index,module,status)
		VALUES('legacy-network-task',0,?,'pending')`, ModuleNetwork); err != nil {
		t.Fatal(err)
	}
	s.executeTask(context.Background(), "legacy-network-task")

	var taskStatus, taskError, phaseStatus, phaseReason string
	if err := s.db.QueryRow(`SELECT status,error FROM tasks WHERE id='legacy-network-task'`).Scan(&taskStatus, &taskError); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT status,reason FROM task_phases WHERE task_id='legacy-network-task'`).Scan(&phaseStatus, &phaseReason); err != nil {
		t.Fatal(err)
	}
	if taskStatus != "failed" || phaseStatus != "failed" {
		t.Fatalf("phantom module task=%q phase=%q, want failed/failed", taskStatus, phaseStatus)
	}
	if !strings.Contains(taskError, "invalid module selection") || !strings.Contains(phaseReason, "invalid module selection") {
		t.Fatalf("failure reason was not explicit: task=%q phase=%q", taskError, phaseReason)
	}
}

func TestBlockedCapabilityIsVisibleWithoutFailingIndependentTask(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets(id,domain) VALUES('blocked-target','example.com')`); err != nil {
		t.Fatal(err)
	}
	modules := models.StringSliceToJSON([]string{ModuleOAST})
	if _, err := s.db.Exec(`INSERT INTO tasks(id,target_id,type,status,modules,total)
		VALUES('blocked-task','blocked-target','full_scan','pending',?,1)`, modules); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO task_phases(task_id,phase_index,module,status)
		VALUES('blocked-task',0,?,'pending')`, ModuleOAST); err != nil {
		t.Fatal(err)
	}

	s.executeTask(context.Background(), "blocked-task")

	var taskStatus, completedJSON, phaseStatus, reason string
	if err := s.db.QueryRow(`SELECT status,completed_modules FROM tasks WHERE id='blocked-task'`).Scan(&taskStatus, &completedJSON); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT status,reason FROM task_phases WHERE task_id='blocked-task'`).Scan(&phaseStatus, &reason); err != nil {
		t.Fatal(err)
	}
	if taskStatus != "finished" || phaseStatus != "blocked" {
		t.Fatalf("task=%q phase=%q, want finished/blocked", taskStatus, phaseStatus)
	}
	if completed := models.JSONToStringSlice(completedJSON); len(completed) != 0 {
		t.Fatalf("blocked module was incorrectly marked complete: %v", completed)
	}
	if !strings.Contains(reason, "callback URL") {
		t.Fatalf("blocked reason is not actionable: %q", reason)
	}
}
