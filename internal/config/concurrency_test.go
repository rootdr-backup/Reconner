package config

import "testing"

func TestConcurrencyLimitsSnapshot(t *testing.T) {
	c := &Config{Limits: ResourceLimits{
		MaxConcurrentScans:      4,
		MaxConcurrentDeepScans:  1,
		MaxConcurrentWatchScans: 3,
	}}

	g, d, w := c.ConcurrencyLimits()
	if g != 4 || d != 1 || w != 3 {
		t.Fatalf("ConcurrencyLimits() = (%d,%d,%d), want (4,1,3)", g, d, w)
	}

	c.SetConcurrencyLimits(8, 2, 6)
	g, d, w = c.ConcurrencyLimits()
	if g != 8 || d != 2 || w != 6 {
		t.Fatalf("after SetConcurrencyLimits: got (%d,%d,%d), want (8,2,6)", g, d, w)
	}

	// An explicit zero (disabled watch lane) must survive the round-trip.
	c.SetConcurrencyLimits(4, 1, 0)
	g, d, w = c.ConcurrencyLimits()
	if g != 4 || d != 1 || w != 0 {
		t.Fatalf("zero watch: got (%d,%d,%d), want (4,1,0)", g, d, w)
	}
}
