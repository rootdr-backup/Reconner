package scanner

import (
	"testing"
	"time"
)

func ms(n int) time.Duration { return time.Duration(n) * time.Millisecond }

func TestTimingSeparated(t *testing.T) {
	slack := 2 * time.Second
	expected := 8 * time.Second

	cases := []struct {
		name  string
		base  []time.Duration
		probe []time.Duration
		want  bool
	}{
		{
			name:  "clean scaling → confirmed",
			base:  []time.Duration{ms(200), ms(240), ms(210), ms(230)},
			probe: []time.Duration{ms(8200), ms(8300), ms(8250), ms(8400)},
			want:  true,
		},
		{
			// The classic FP: a constant-slow endpoint. Base is slow too, so the
			// distributions overlap → must NOT confirm.
			name:  "constant-slow endpoint → rejected",
			base:  []time.Duration{ms(7800), ms(8100), ms(8000), ms(8200)},
			probe: []time.Duration{ms(8100), ms(8300), ms(8200), ms(8400)},
			want:  false,
		},
		{
			// One base sample spiked high → raises max(base) above probe floor,
			// so non-overlap fails. Kills the single-spike false positive.
			name:  "one baseline spike → rejected",
			base:  []time.Duration{ms(200), ms(9000), ms(210), ms(230)},
			probe: []time.Duration{ms(8200), ms(8300), ms(8250), ms(8400)},
			want:  false,
		},
		{
			// Delayed, but far less than the injected 8s (only ~1s) — doesn't track
			// the requested sleep → rejected.
			name:  "delay too small to track sleep → rejected",
			base:  []time.Duration{ms(200), ms(240), ms(210), ms(230)},
			probe: []time.Duration{ms(1200), ms(1300), ms(1250), ms(1400)},
			want:  false,
		},
		{
			// A random huge stall (~20s) is not clean 8s scaling → rejected.
			name:  "absurd stall → rejected",
			base:  []time.Duration{ms(200), ms(240), ms(210), ms(230)},
			probe: []time.Duration{ms(20000), ms(21000), ms(20500), ms(22000)},
			want:  false,
		},
		{
			name:  "too few samples → rejected",
			base:  []time.Duration{ms(200), ms(240)},
			probe: []time.Duration{ms(8200), ms(8300)},
			want:  false,
		},
	}
	for _, c := range cases {
		if got := timingSeparated(c.base, c.probe, expected, slack); got != c.want {
			t.Errorf("%s: timingSeparated = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestMedianMinMaxDur(t *testing.T) {
	ds := []time.Duration{ms(300), ms(100), ms(200)}
	if medianDur(ds) != ms(200) {
		t.Errorf("median = %v, want 200ms", medianDur(ds))
	}
	if minDur(ds) != ms(100) || maxDur(ds) != ms(300) {
		t.Errorf("min/max = %v/%v, want 100ms/300ms", minDur(ds), maxDur(ds))
	}
	// median must not mutate the caller's slice order.
	if ds[0] != ms(300) {
		t.Errorf("medianDur mutated input: %v", ds)
	}
}
