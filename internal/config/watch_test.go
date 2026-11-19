package config

import "testing"

func TestWatchRoundIntervalMinutesFallback(t *testing.T) {
	if got := (&Config{}).WatchRoundIntervalMinutes(); got != 720 {
		t.Fatalf("fallback=%d, want 720", got)
	}
}
