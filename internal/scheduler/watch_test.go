package scheduler

import (
	"context"
	"reflect"
	"testing"
	"time"
)

func TestWatchScanModules(t *testing.T) {
	got := watchScanModules()
	want := []string{ModuleSubdomainEnum, ModuleHTTPProbe, "no_subdomain_brute"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("watchScanModules()=%v, want %v", got, want)
	}
}

func TestResumeTypeTag(t *testing.T) {
	cases := []struct{ in, want string }{
		{watchScanType, watchScanType},
		{monitorWatchType, monitorWatchType},
		{monitorEscalationType, monitorEscalationType},
		{"full_scan", ""},
		{"subdomain_enum", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := resumeTypeTag(tc.in); got != tc.want {
			t.Errorf("resumeTypeTag(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestWatchTerminalRulesFinished(t *testing.T) {
	s := newTestScheduler(t)
	s.cfg.WatchRoundsMinGap = 30
	s.cfg.WatchRoundIntervalHours = 12
	s.cfg.WatchFailLimit = 3
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain,watch_only,watch_fail_count) VALUES ('w1','w1.example',1,2)`); err != nil {
		t.Fatal(err)
	}

	s.applyWatchTerminalRules("w1", "finished")

	var failCount int
	var lastRun, nextRun string
	if err := s.db.QueryRow(`SELECT watch_fail_count, COALESCE(watch_last_run,''), COALESCE(watch_next_run,'') FROM targets WHERE id='w1'`).Scan(&failCount, &lastRun, &nextRun); err != nil {
		t.Fatal(err)
	}
	if failCount != 0 {
		t.Fatalf("finished did not reset fail count: %d", failCount)
	}
	if lastRun == "" || nextRun == "" {
		t.Fatalf("finished did not stamp timestamps: last=%q next=%q", lastRun, nextRun)
	}
	next, err := time.Parse("2006-01-02 15:04:05", nextRun)
	if err != nil {
		t.Fatalf("bad next_run layout: %v", err)
	}
	if until := time.Until(next); until <= 11*time.Hour+50*time.Minute || until > 12*time.Hour+10*time.Minute {
		t.Fatalf("next_run gap=%v, want ~12 h", until)
	}
}

func TestWatchTerminalRulesFailureRetriesQuickly(t *testing.T) {
	s := newTestScheduler(t)
	s.cfg.WatchRoundsMinGap = 30
	s.cfg.WatchRoundIntervalHours = 12
	s.cfg.WatchFailLimit = 3
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain,watch_only,watch_fail_count) VALUES ('w6','w6.example',1,0)`); err != nil {
		t.Fatal(err)
	}

	s.applyWatchTerminalRules("w6", "failed")

	var nextRun string
	if err := s.db.QueryRow(`SELECT COALESCE(watch_next_run,'') FROM targets WHERE id='w6'`).Scan(&nextRun); err != nil {
		t.Fatal(err)
	}
	next, err := time.Parse("2006-01-02 15:04:05", nextRun)
	if err != nil {
		t.Fatalf("bad next_run layout: %v", err)
	}
	if until := time.Until(next); until <= 25*time.Minute || until > 31*time.Minute {
		t.Fatalf("failed next_run gap=%v, want ~30 min retry", until)
	}
}

func TestWatchRoundIntervalFallback(t *testing.T) {
	s := newTestScheduler(t)
	s.cfg.WatchRoundIntervalHours = 0
	if got := s.watchRoundIntervalMinutes(); got != 720 {
		t.Fatalf("watchRoundIntervalMinutes()=%d, want 720", got)
	}
}

func TestWatchTerminalRulesFailureChainStopsAtLimit(t *testing.T) {
	s := newTestScheduler(t)
	s.cfg.WatchFailLimit = 2
	s.cfg.WatchRoundsMinGap = 30
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain,watch_only,watch_fail_count,watch_paused) VALUES ('w2','w2.example',1,1,0)`); err != nil {
		t.Fatal(err)
	}

	s.applyWatchTerminalRules("w2", "failed")

	var fails, paused int
	var nextRun *string
	if err := s.db.QueryRow(`SELECT watch_fail_count, COALESCE(watch_paused,0), watch_next_run FROM targets WHERE id='w2'`).Scan(&fails, &paused, &nextRun); err != nil {
		t.Fatal(err)
	}
	if fails != 2 || paused != 1 || nextRun != nil {
		t.Fatalf("failure limit: fails=%d paused=%d next=%v, want 2/1/NULL", fails, paused, nextRun)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM notifications WHERE target_id='w2' AND type='watch_failed'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("watch_failed notification count=%d err=%v, want 1", n, err)
	}
}

func TestWatchTerminalRulesCancelledStopsChain(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain,watch_only,watch_paused,watch_next_run) VALUES ('w3','w3.example',1,0,'2020-01-01 00:00:00')`); err != nil {
		t.Fatal(err)
	}
	s.applyWatchTerminalRules("w3", "cancelled")
	var paused int
	var nextRun *string
	if err := s.db.QueryRow(`SELECT COALESCE(watch_paused,0), watch_next_run FROM targets WHERE id='w3'`).Scan(&paused, &nextRun); err != nil {
		t.Fatal(err)
	}
	if paused != 1 || nextRun != nil {
		t.Fatalf("cancelled: paused=%d next=%v, want 1/NULL", paused, nextRun)
	}
}

func TestWatchRoundKeepsAllRoots(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain,watch_only,watch_root_index) VALUES ('w4','w4.example',1,1)`); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "c"} {
		if _, err := s.db.Exec(`INSERT INTO assets (id,target_id,name,value,kind,asset_type,approval_status) VALUES (?,'w4','',?,'web','domain','approved')`, id, id+".example"); err != nil {
			t.Fatal(err)
		}
	}
	roots := s.loadSubdomainRoots(context.Background(), "w4", "w4.example", "")
	if len(roots) != 3 {
		t.Fatalf("roots=%v, want all 3", roots)
	}
}

func TestWatchOnlyTargetsExcludeDeepProjects(t *testing.T) {
	s := newTestScheduler(t)
	// w5: only watch tasks -> eligible for prune.
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain,watch_only) VALUES ('w5','w5.example',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO tasks (id,target_id,type,status) VALUES ('t1','w5','watch_scan','finished')`); err != nil {
		t.Fatal(err)
	}
	// w6: has a deep task -> NOT eligible (keeps every row).
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain,watch_only) VALUES ('w6','w6.example',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO tasks (id,target_id,type,status) VALUES ('t2','w6','full_scan','finished')`); err != nil {
		t.Fatal(err)
	}
	got := s.watchOnlyTargets()
	want := []string{"w5"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("watchOnlyTargets=%v, want %v", got, want)
	}
}

func TestWatchKindGuardNotifiesOnce(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain,watch_only,kind) VALUES ('w7','w7.example',1,'mixed')`); err != nil {
		t.Fatal(err)
	}
	s.checkWatchKindGuard()
	s.checkWatchKindGuard() // second call must not duplicate
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM notifications WHERE target_id='w7' AND type='watch_kind_conflict'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("watch_kind_conflict count=%d err=%v, want 1", n, err)
	}
}

func TestRecoverWatchTaskAdvancesSchedule(t *testing.T) {
	s := newTestScheduler(t)
	s.cfg.WatchRoundsMinGap = 30
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain,watch_only,watch_next_run,watch_paused) VALUES ('w8','w8.example',1,'2020-01-01 00:00:00',0)`); err != nil {
		t.Fatal(err)
	}
	s.recoverWatchTask("w8")
	var fails int
	var next string
	if err := s.db.QueryRow(`SELECT watch_fail_count, watch_next_run FROM targets WHERE id='w8'`).Scan(&fails, &next); err != nil {
		t.Fatal(err)
	}
	if fails != 1 || next == "2020-01-01 00:00:00" {
		t.Fatalf("recover: fails=%d next=%q", fails, next)
	}
}
