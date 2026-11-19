package scheduler

import (
	"runtime"
	"testing"

	"github.com/recon-platform/internal/config"
)

// TestComputeAdmissionCapsHealthyHonorsConfigured checks the headline behavior:
// on the target 2 CPU / 2304 MB box, the operator's 4/1/3 setting is honored
// exactly. Watch gets three light slots even though deep gets one heavy slot.
func TestComputeAdmissionCapsHealthyHonorsConfigured(t *testing.T) {
	global, deep, watch := computeAdmissionCaps(4, 1, 3, 2, 2304, 0, 0)
	if global != 4 || deep != 1 || watch != 3 {
		t.Fatalf("computeAdmissionCaps(4,1,3,2CPU,2304MB,healthy)=(%d,%d,%d) want (4,1,3)", global, deep, watch)
	}
}

// TestComputeAdmissionCapsHighConfigCappedByEnvelope proves the CRITICAL review
// finding is closed: a huge configured value cannot admit more than the hardware
// envelope, even on a healthy box.
func TestComputeAdmissionCapsHighConfigCappedByEnvelope(t *testing.T) {
	global, deep, watch := computeAdmissionCaps(32, 16, 16, 2, 2304, 0, 0)
	// global is the TOTAL ceiling; deep+watch fit inside it, they are not additive.
	if global != 4 || deep != 1 || watch != 3 || deep+watch > global {
		t.Fatalf("high config not bounded by envelope: (%d,%d,%d) want (4,1,3) with deep+watch<=global", global, deep, watch)
	}
}

func TestComputeAdmissionCapsPressureBrake(t *testing.T) {
	cases := []struct {
		name                            string
		level, running                  int
		wantGlobal, wantDeep, wantWatch int
	}{
		{"moderate running", 1, 1, 2, 1, 1},
		{"severe running", 2, 1, 1, 1, 0},
		{"severe idle", 2, 0, 0, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			global, deep, watch := computeAdmissionCaps(4, 1, 3, 2, 2304, tc.level, tc.running)
			if global != tc.wantGlobal || deep != tc.wantDeep || watch != tc.wantWatch {
				t.Fatalf("level=%d running=%d got (%d,%d,%d) want (%d,%d,%d)",
					tc.level, tc.running, global, deep, watch, tc.wantGlobal, tc.wantDeep, tc.wantWatch)
			}
		})
	}
}

func TestComputeAdmissionCapsWatchZeroDisablesLane(t *testing.T) {
	global, deep, watch := computeAdmissionCaps(4, 1, 0, 2, 2304, 0, 0)
	if global != 4 || deep != 1 || watch != 0 {
		t.Fatalf("watch=0 got (%d,%d,%d) want (4,1,0)", global, deep, watch)
	}
}

func TestComputeAdmissionCapsDeepAboveGlobal(t *testing.T) {
	// Use a large host so the deep envelope itself is >=2; otherwise the deep
	// envelope (not global) is what caps it and this test proves nothing.
	// On 8 CPU / 8192 MB: envelope deep=4, watch=13, global=17.
	// global=2 then clamps deep from 4 down to 2, leaving no watch remainder.
	global, deep, watch := computeAdmissionCaps(2, 8, 3, 8, 8192, 0, 0)
	if global != 2 || deep != 2 || watch != 0 {
		t.Fatalf("got (%d,%d,%d) want (2,2,0)", global, deep, watch)
	}
}

func TestComputeAdmissionCapsZeroGlobalAndDeepFallback(t *testing.T) {
	// Plain int cannot distinguish absent from explicit 0. Global/deep fall back
	// to 2/1; watch 0 stays an explicit disable.
	global, deep, watch := computeAdmissionCaps(0, 0, 0, 2, 2304, 0, 0)
	if global != 2 || deep != 1 || watch != 0 {
		t.Fatalf("got (%d,%d,%d) want (2,1,0)", global, deep, watch)
	}
}

func TestClassifyCPUPressureBoundaries(t *testing.T) {
	cases := []struct {
		load1 float64
		want  int
	}{
		{0.99, 0},
		{1.0, 1},
		{1.59, 1},
		{1.6, 2},
	}
	for _, tc := range cases {
		if got := classifyCPUPressure(tc.load1, 1); got != tc.want {
			t.Errorf("classifyCPUPressure(%.2f,1)=%d want %d", tc.load1, got, tc.want)
		}
	}
}

func TestHardwareEnvelopeHelpers(t *testing.T) {
	if got := watchHardwareCeiling(2, 2304); got != 3 {
		t.Errorf("watchHardwareCeiling(2,2304)=%d want 3", got)
	}
	if got := resourceTargetCeiling(2, 2304, 32); got != 1 {
		t.Errorf("resourceTargetCeiling(2,2304,32)=%d want 1", got)
	}
	global, deep, watch := hardwareEnvelope(2, 2304, 0, 0)
	if global != 4 || deep != 1 || watch != 3 {
		t.Errorf("hardwareEnvelope healthy=(%d,%d,%d) want (4,1,3)", global, deep, watch)
	}
}

// TestAdmissionCapsWithRealConfigWatchZero exercises the integration path that
// a pure-helper test misses: an explicit zero in a real Config disables watch.
func TestAdmissionCapsWithRealConfigWatchZero(t *testing.T) {
	s := newTestScheduler(t)
	s.cfg = &config.Config{Limits: config.ResourceLimits{
		MaxConcurrentScans:      4,
		MaxConcurrentDeepScans:  1,
		MaxConcurrentWatchScans: 0,
		MaxMemoryMB:             2304,
	}}
	_, _, watch := s.admissionCaps(0)
	if watch != 0 {
		t.Fatalf("real Config with watch=0 gave watch cap %d, want 0", watch)
	}
}

// TestPressureLevelReadFailureFallsBackToHealthy documents that a monitoring
// failure never blocks admission. It cannot inject a load.Avg() error, but it
// asserts the function is callable with a minimal config and returns a valid
// level (0..2) rather than a sentinel that stops scans.
func TestPressureLevelReturnsValidLevel(t *testing.T) {
	s := newTestScheduler(t)
	s.cfg = &config.Config{Limits: config.ResourceLimits{MaxMemoryMB: 2304}}
	if lvl := s.pressureLevel(); lvl < 0 || lvl > 2 {
		t.Fatalf("pressureLevel()=%d want 0..2", lvl)
	}
	if n := runtime.NumCPU(); n < 1 {
		t.Fatal("runtime.NumCPU()<1")
	}
}

// seedDueWatchTarget inserts a web project that is due for a watch round.
func seedDueWatchTarget(t *testing.T, s *Scheduler, id string) {
	t.Helper()
	_, err := s.db.Exec(`INSERT INTO targets (id, domain, watch_only, watch_paused, watch_next_run, kind)
		VALUES (?, ?, 1, 0, datetime('now','-1 hour'), 'web')`, id, id+".example.com")
	if err != nil {
		t.Fatalf("seed target: %v", err)
	}
}

func watchTaskCount(t *testing.T, s *Scheduler, targetID string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM tasks WHERE type=? AND target_id=?`, watchScanType, targetID).Scan(&n); err != nil {
		t.Fatalf("count watch tasks: %v", err)
	}
	return n
}

// TestRunDueWatchRoundsDisabledWhenWatchCapZero proves the early-return in
// runDueWatchRounds stops pending-task accumulation when the lane is disabled.
func TestRunDueWatchRoundsDisabledWhenWatchCapZero(t *testing.T) {
	s := newTestScheduler(t)
	s.cfg = &config.Config{Limits: config.ResourceLimits{
		MaxConcurrentScans:      4,
		MaxConcurrentDeepScans:  1,
		MaxConcurrentWatchScans: 0,
		MaxMemoryMB:             2304,
	}}
	seedDueWatchTarget(t, s, "tgt-disabled")
	s.runDueWatchRounds()
	if n := watchTaskCount(t, s, "tgt-disabled"); n != 0 {
		t.Fatalf("watch cap 0 created %d task(s), want 0", n)
	}
}

// TestRunDueWatchRoundsCreatesTaskWhenEnabled is the positive control: with a
// healthy watch lane the same due project gets exactly one watch round.
func TestRunDueWatchRoundsCreatesTaskWhenEnabled(t *testing.T) {
	s := newTestScheduler(t)
	s.cfg = &config.Config{Limits: config.ResourceLimits{
		MaxConcurrentScans:      4,
		MaxConcurrentDeepScans:  1,
		MaxConcurrentWatchScans: 3,
		MaxMemoryMB:             2304,
	}}
	seedDueWatchTarget(t, s, "tgt-enabled")
	s.runDueWatchRounds()
	if n := watchTaskCount(t, s, "tgt-enabled"); n != 1 {
		t.Fatalf("watch cap 3 created %d task(s), want 1", n)
	}
}
