package scheduler

import (
	"testing"

	"github.com/recon-platform/internal/scanner"
	"github.com/recon-platform/pkg/logger"
)

// TestCheckTargetFullyBlockedPausesOnlyWhenEveryKnownHostIsUnreachable is the
// end-to-end contract for the operator-requested "auto-pause on IP block"
// feature: a scan whose target has gone completely unreachable is PAUSED
// (resumable, nothing discarded) — but only once every host http_services
// actually knows about for this target is unreachable, never on a partial or
// WAF-filtered signal.
func TestCheckTargetFullyBlockedPausesOnlyWhenEveryKnownHostIsUnreachable(t *testing.T) {
	s := newTestScheduler(t)
	log := logger.New("error")
	logFn := func(level, source, msg string) { log.Info(msg, "level", level, "source", source) }

	if _, err := s.db.Exec(`INSERT INTO targets (id, domain) VALUES ('target','example.com')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO tasks(id,target_id,type,status,modules,total) VALUES('task','target','full_scan','running','[]',0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO http_services (id, target_id, url) VALUES
		('h1','target','https://a.example.com/'), ('h2','target','https://b.example.com/x')`); err != nil {
		t.Fatal(err)
	}

	hostA, hostB := "a.example.com", "b.example.com"
	observeUnreachable := func(host string) {
		for i := 0; i < 8; i++ {
			scanner.ObserveHostUnreachable(host)
		}
	}

	// Only host A is dead so far — must NOT pause yet.
	observeUnreachable(hostA)
	s.checkTargetFullyBlocked("target", "task", "example.com", logFn)
	var status string
	if err := s.db.QueryRow(`SELECT status FROM tasks WHERE id='task'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "running" {
		t.Fatalf("task status=%q, want still running (only one of two hosts is unreachable)", status)
	}

	// Now host B goes dead too — every known host is unreachable: must pause.
	observeUnreachable(hostB)
	s.checkTargetFullyBlocked("target", "task", "example.com", logFn)
	if err := s.db.QueryRow(`SELECT status FROM tasks WHERE id='task'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "paused" {
		t.Fatalf("task status=%q, want paused once every known host is unreachable", status)
	}

	var notifCount int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM notifications WHERE target_id='target' AND type='scan_auto_paused'`).Scan(&notifCount); err != nil {
		t.Fatal(err)
	}
	if notifCount != 1 {
		t.Fatalf("scan_auto_paused notifications=%d, want exactly 1", notifCount)
	}
}

// TestCheckTargetFullyBlockedNoopsWithoutAnyKnownHosts covers a target with
// no http_services rows yet (very early in a scan) — must never pause on an
// empty asset set.
func TestCheckTargetFullyBlockedNoopsWithoutAnyKnownHosts(t *testing.T) {
	s := newTestScheduler(t)
	log := logger.New("error")
	logFn := func(level, source, msg string) { log.Info(msg, "level", level, "source", source) }

	if _, err := s.db.Exec(`INSERT INTO targets (id, domain) VALUES ('target','example.com')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO tasks(id,target_id,type,status,modules,total) VALUES('task','target','full_scan','running','[]',0)`); err != nil {
		t.Fatal(err)
	}

	s.checkTargetFullyBlocked("target", "task", "example.com", logFn)
	var status string
	if err := s.db.QueryRow(`SELECT status FROM tasks WHERE id='task'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "running" {
		t.Fatalf("task status=%q, want running — no known hosts yet means nothing to judge unreachable", status)
	}
}
