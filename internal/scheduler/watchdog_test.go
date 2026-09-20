package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/recon-platform/internal/config"
)

func TestWatchdogIsResetForEveryPhase(t *testing.T) {
	s := newTestScheduler(t)
	const budget = time.Hour

	firstCtx, finishFirst := s.beginPhase(context.Background(), "task", budget)
	firstDeadline, ok := firstCtx.Deadline()
	if !ok {
		t.Fatal("first phase has no watchdog deadline")
	}
	if skipped, timedOut := finishFirst(); skipped || timedOut {
		t.Fatalf("completed first phase reported skipped=%v timedOut=%v", skipped, timedOut)
	}

	secondCtx, finishSecond := s.beginPhase(context.Background(), "task", budget)
	defer finishSecond()
	secondDeadline, ok := secondCtx.Deadline()
	if !ok {
		t.Fatal("second phase has no watchdog deadline")
	}
	if !secondDeadline.After(firstDeadline) {
		t.Fatalf("watchdog was not reset: first=%v second=%v", firstDeadline, secondDeadline)
	}
}

func TestWatchdogUsesSubdomainsDiscoveredDuringCurrentScan(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets (id, domain, subdomain_count) VALUES ('target','example.com',0)`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2000; i++ {
		if _, err := s.db.Exec(`INSERT INTO subdomains (id, target_id, subdomain) VALUES (?, 'target', ?)`, i, i); err != nil {
			t.Fatal(err)
		}
	}

	known := s.currentSubdomainCount("target", 0)
	if known != 2000 {
		t.Fatalf("live subdomain count=%d, want 2000", known)
	}
	got := effectiveWatchdog(&config.Config{ScanWatchdogHours: 24}, known)
	if want := 30 * time.Hour; got != want {
		t.Fatalf("adaptive phase watchdog=%v, want %v", got, want)
	}
}

func TestPhaseWatchdogReportsTimeoutSeparatelyFromSkip(t *testing.T) {
	s := newTestScheduler(t)
	ctx, finish := s.beginPhase(context.Background(), "task", time.Millisecond)
	<-ctx.Done()
	skipped, timedOut := finish()
	if skipped || !timedOut {
		t.Fatalf("expired phase reported skipped=%v timedOut=%v", skipped, timedOut)
	}
}

func TestCollectPhaseResultsForceReleasesStuckWorkerAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	results := make(chan phaseRunResult, 1)
	cancel()
	started := time.Now()
	got, forced := collectPhaseResults(ctx, []string{"js_analysis"}, results, 20*time.Millisecond)
	if !forced {
		t.Fatal("stuck worker was not force-released")
	}
	if time.Since(started) > time.Second {
		t.Fatal("force-release exceeded its cancellation grace")
	}
	if len(got) != 1 || got[0].module != "js_analysis" || !errors.Is(got[0].err, errPhaseStopGrace) {
		t.Fatalf("forced result=%+v", got)
	}
}

func TestCollectPhaseResultsAcceptsWorkerThatStopsWithinGrace(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	results := make(chan phaseRunResult, 1)
	cancel()
	go func() {
		time.Sleep(10 * time.Millisecond)
		results <- phaseRunResult{module: "js_analysis", err: context.Canceled}
	}()
	got, forced := collectPhaseResults(ctx, []string{"js_analysis"}, results, time.Second)
	if forced || len(got) != 1 || got[0].module != "js_analysis" {
		t.Fatalf("results=%+v forced=%v", got, forced)
	}
}
