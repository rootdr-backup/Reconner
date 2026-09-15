package scanner

import (
	"errors"
	"testing"
)

func TestBlockedPhaseIsTypedAndKeepsReason(t *testing.T) {
	err := BlockedPhase("dependency unavailable")
	if !IsPhaseBlocked(err) || !errors.Is(err, ErrPhaseBlocked) {
		t.Fatalf("BlockedPhase() = %v, want typed blocked error", err)
	}
	if got, want := err.Error(), "phase blocked: dependency unavailable"; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}

func TestBlockedPhaseSuppliesSafeDefaultReason(t *testing.T) {
	if got := BlockedPhase("  ").Error(); got != "phase blocked: required prerequisite is unavailable" {
		t.Fatalf("unexpected default reason: %q", got)
	}
}
