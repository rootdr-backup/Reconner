package scanner

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestXSSBrowserBudgetNeverUnderflowsUnderConcurrency(t *testing.T) {
	s := &DASTScanner{}
	s.browserBudget.Store(7)
	var admitted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.takeBrowserBudget() {
				admitted.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := admitted.Load(); got != 7 {
		t.Fatalf("admitted browser work=%d, want exactly 7", got)
	}
	if got := s.browserBudget.Load(); got != 0 {
		t.Fatalf("remaining browser budget=%d, want 0", got)
	}
}
