package scanner

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/recon-platform/internal/config"
)

func TestSQLmapVerificationWorkersStayBounded(t *testing.T) {
	if got := sqlmapVerificationWorkers(&config.Config{Limits: config.ResourceLimits{MaxToolExecutions: 8, MaxMemoryMB: 2048}}, 20); got != 2 {
		t.Fatalf("workers=%d want bounded maximum 2", got)
	}
	if got := sqlmapVerificationWorkers(&config.Config{Limits: config.ResourceLimits{MaxToolExecutions: 8, MaxMemoryMB: 1024}}, 20); got != 1 {
		t.Fatalf("low-memory workers=%d want 1", got)
	}
	if got := sqlmapVerificationWorkers(&config.Config{Limits: config.ResourceLimits{MaxToolExecutions: 1, MaxMemoryMB: 4096}}, 20); got != 1 {
		t.Fatalf("tool-limited workers=%d want 1", got)
	}
}

func TestRunSQLmapCandidatesIsBoundedAndCancellationAware(t *testing.T) {
	candidates := make([]sqlmapCandidate, 8)
	var active, peak atomic.Int32
	processed := runSQLmapCandidates(context.Background(), candidates, 2, func(sqlmapCandidate) {
		now := active.Add(1)
		for {
			old := peak.Load()
			if now <= old || peak.CompareAndSwap(old, now) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		active.Add(-1)
	})
	if processed != len(candidates) || peak.Load() != 2 {
		t.Fatalf("processed=%d peak=%d, want %d/2", processed, peak.Load(), len(candidates))
	}

	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	processed = runSQLmapCandidates(ctx, make([]sqlmapCandidate, 50), 2, func(sqlmapCandidate) {
		if calls.Add(1) == 2 {
			cancel()
		}
		time.Sleep(time.Millisecond)
	})
	if processed >= 50 || calls.Load() >= 50 {
		t.Fatalf("cancellation drained the queue: processed=%d calls=%d", processed, calls.Load())
	}
}
