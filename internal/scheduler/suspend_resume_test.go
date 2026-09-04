package scheduler

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/models"
	"github.com/recon-platform/internal/websocket"
	"github.com/recon-platform/pkg/logger"
)

func newTestScheduler(t *testing.T) *Scheduler {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := database.RunMigrations(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	hub := websocket.NewHub()
	go hub.Run()
	// No Start(): we drive the methods directly and don't want worker goroutines
	// draining the queue or recoverPendingTasks touching our fixture rows.
	return New(db, hub, &config.Config{}, logger.New("error"))
}

func TestSuspendActiveForShutdownCancelsLiveTask(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets (id, domain, scan_status) VALUES ('tgt-live','example.com','pending')`); err != nil {
		t.Fatalf("insert target: %v", err)
	}
	if _, err := s.db.Exec(`INSERT INTO tasks (id, target_id, type, status, priority, modules, total)
		VALUES ('task-live','tgt-live','full_scan','pending',2,'[]',0)`); err != nil {
		t.Fatalf("insert task: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.cancelMap["task-live"] = cancel
	s.running["task-live"] = true
	s.taskTargets["task-live"] = "tgt-live"
	s.mu.Unlock()

	n, err := s.SuspendActiveForShutdown()
	if err != nil || n != 1 {
		t.Fatalf("SuspendActiveForShutdown = (%d,%v), want (1,nil)", n, err)
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("live task context was not cancelled")
	}

	var taskStatus, targetStatus string
	if err := s.db.QueryRow(`SELECT status FROM tasks WHERE id='task-live'`).Scan(&taskStatus); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT scan_status FROM targets WHERE id='tgt-live'`).Scan(&targetStatus); err != nil {
		t.Fatal(err)
	}
	if taskStatus != InterruptedStatus || targetStatus != "paused" {
		t.Fatalf("parked state task=%q target=%q, want interrupted/paused", taskStatus, targetStatus)
	}
	if _, err := s.CreateTask("tgt-live", []string{ModuleHTTPProbe}, 1); err == nil {
		t.Fatal("scheduler accepted a new task after shutdown admission closed")
	}
}

// A scan that is running when the service stops must be parked as 'interrupted'
// and then, on the next startup, resumed for ONLY the modules it hadn't finished.
func TestSuspendThenResumeInterrupted(t *testing.T) {
	s := newTestScheduler(t)

	if _, err := s.db.Exec(`INSERT INTO targets (id, domain) VALUES ('tgt1','example.com')`); err != nil {
		t.Fatalf("insert target: %v", err)
	}
	// A running scan of [a,b,c] that already finished module a.
	_, err := s.db.Exec(`INSERT INTO tasks (id, target_id, type, status, priority, modules, total, completed_modules)
		VALUES ('task1','tgt1','full_scan','running',2,?,3,?)`,
		models.StringSliceToJSON([]string{"a", "b", "c"}),
		models.StringSliceToJSON([]string{"a"}))
	if err != nil {
		t.Fatalf("insert task: %v", err)
	}

	// Stop: park active scans.
	n, err := suspendActive(s.db)
	if err != nil || n != 1 {
		t.Fatalf("SuspendActive = (%d,%v), want (1,nil)", n, err)
	}
	var status string
	if err := s.db.QueryRow(`SELECT status FROM tasks WHERE id='task1'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != InterruptedStatus {
		t.Fatalf("after suspend status=%q, want %q", status, InterruptedStatus)
	}

	// Start: auto-resume.
	if resumed := s.ResumeInterrupted(); resumed != 1 {
		t.Fatalf("ResumeInterrupted = %d, want 1", resumed)
	}

	// The original is retired, and a fresh pending task covers only [b,c].
	if err := s.db.QueryRow(`SELECT status FROM tasks WHERE id='task1'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "cancelled" {
		t.Fatalf("original task status=%q, want cancelled", status)
	}

	var modsJSON, newStatus string
	err = s.db.QueryRow(`SELECT modules, status FROM tasks WHERE id != 'task1' AND target_id='tgt1'`).Scan(&modsJSON, &newStatus)
	if err != nil {
		t.Fatalf("no resume task created: %v", err)
	}
	got := models.JSONToStringSlice(modsJSON)
	want := []string{"b", "c"}
	if len(got) != len(want) || got[0] != "b" || got[1] != "c" {
		t.Fatalf("resume modules=%v, want %v (must skip completed 'a')", got, want)
	}
	if newStatus != "pending" {
		t.Fatalf("resume task status=%q, want pending", newStatus)
	}
}

// Idempotence + the nothing-to-resume path: a fully-completed interrupted task is
// retired without spawning an empty resume.
func TestResumeInterruptedNothingLeft(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets (id, domain) VALUES ('tgt2','example2.com')`); err != nil {
		t.Fatalf("insert target: %v", err)
	}
	_, err := s.db.Exec(`INSERT INTO tasks (id, target_id, type, status, priority, modules, total, completed_modules)
		VALUES ('t2','tgt2','full_scan','interrupted',2,?,2,?)`,
		models.StringSliceToJSON([]string{"a", "b"}),
		models.StringSliceToJSON([]string{"a", "b"}))
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if resumed := s.ResumeInterrupted(); resumed != 0 {
		t.Fatalf("ResumeInterrupted = %d, want 0 (nothing left)", resumed)
	}
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM tasks WHERE target_id='tgt2'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("task count=%d, want 1 (no empty resume spawned)", count)
	}
}
