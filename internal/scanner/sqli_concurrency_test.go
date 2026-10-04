package scanner

import (
	"testing"

	"github.com/recon-platform/internal/config"
)

// TestSQLiConcurrencyRespectsGlobalBudget mirrors
// TestDirectoryToolConcurrencyRespectsGlobalBudget (directory_external_test.go):
// an operator who has not touched the rate-limit config must see today's
// effective flat concurrency (8), while one who has explicitly configured a
// higher HTTP request budget must get more candidates probed in parallel —
// bounded by the same floor/ceiling clamps (1..20) directoryToolThreads uses.
func TestSQLiConcurrencyRespectsGlobalBudget(t *testing.T) {
	tests := []struct {
		name string
		rate int
		want int
	}{
		{"a configured-but-zero rate falls back to the default budget", 0, 8},
		{"default/floor budget (150) reproduces today's flat 8", 150, 8},
		{"a tiny explicit budget still gets at least one worker", 10, 1},
		{"a modest raised budget scales up", 300, 16},
		{"a very large budget is capped at the ceiling", 2000, 20},
	}
	for _, tt := range tests {
		s := &SQLiScanner{cfg: &config.Config{Limits: config.ResourceLimits{HTTPRateLimit: tt.rate}}}
		if got := s.concurrency(); got != tt.want {
			t.Errorf("%s: rate=%d concurrency=%d want %d", tt.name, tt.rate, got, tt.want)
		}
	}

	// A scanner with no Config at all (unit tests / standalone callers, per
	// sqliFallbackMaxParams's own doc comment) must land on the same default as
	// an operator who left HTTPRateLimit untouched — no behavior change for
	// every caller that predates this budget-aware helper.
	nilCfg := &SQLiScanner{}
	if got := nilCfg.concurrency(); got != 8 {
		t.Errorf("nil config: concurrency=%d want 8 (today's historical flat default)", got)
	}
}

// TestSQLiConcurrencyNeverBypassesHostGovernor asserts the derived ceiling
// never exceeds a bound that would make raising it meaningless: the shared
// per-host adaptive governor (hostMaxInFlight, throttle.go) already caps real
// concurrent requests to any one host, so this just documents the ceiling
// stays sane relative to it instead of growing unbounded with an extreme
// configured rate.
func TestSQLiConcurrencyNeverBypassesHostGovernor(t *testing.T) {
	s := &SQLiScanner{cfg: &config.Config{Limits: config.ResourceLimits{HTTPRateLimit: 1_000_000}}}
	if got := s.concurrency(); got > 20 {
		t.Errorf("concurrency=%d must stay clamped at the 20 ceiling regardless of an extreme configured rate", got)
	}
}

// TestSQLiTimingConcurrencyStaysProportionallyLower verifies timingConcurrency
// keeps the historical "half of the main pool" relationship (8/4 before this
// change) while still scaling with the configured budget, because each
// time-based confirmation holds a connection open for several seconds and
// must stay more conservative than the main quick-probe pool.
func TestSQLiTimingConcurrencyStaysProportionallyLower(t *testing.T) {
	tests := []struct {
		rate     int
		wantMain int
		wantTime int
	}{
		{150, 8, 4},
		{300, 16, 8},
		{10, 1, 1}, // floor: never zero even when halved
	}
	for _, tt := range tests {
		s := &SQLiScanner{cfg: &config.Config{Limits: config.ResourceLimits{HTTPRateLimit: tt.rate}}}
		if got := s.concurrency(); got != tt.wantMain {
			t.Errorf("rate=%d: concurrency=%d want %d", tt.rate, got, tt.wantMain)
		}
		if got := s.timingConcurrency(); got != tt.wantTime {
			t.Errorf("rate=%d: timingConcurrency=%d want %d", tt.rate, got, tt.wantTime)
		}
		if s.timingConcurrency() > s.concurrency() {
			t.Errorf("rate=%d: timingConcurrency (%d) must never exceed the main pool (%d)", tt.rate, s.timingConcurrency(), s.concurrency())
		}
	}
}
