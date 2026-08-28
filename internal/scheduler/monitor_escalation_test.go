package scheduler

import (
	"testing"
	"time"
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
