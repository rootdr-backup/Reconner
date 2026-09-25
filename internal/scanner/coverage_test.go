package scanner

import (
	"context"
	"sync"
	"testing"
)

func TestCoverageReporterAccumulatesConcurrentDeltas(t *testing.T) {
	var mu sync.Mutex
	counts := map[CoverageMetric]int64{}
	ctx := WithCoverageReporter(context.Background(), func(metric CoverageMetric, delta int64) {
		mu.Lock()
		counts[metric] += delta
		mu.Unlock()
	})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); RecordCoverage(ctx, CoverageAttempted, 1) }()
	}
	wg.Wait()
	if counts[CoverageAttempted] != 20 {
		t.Fatalf("attempted=%d, want 20", counts[CoverageAttempted])
	}
}
