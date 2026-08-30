package scanner

import (
	"strings"
	"testing"
	"time"
)

// TestTimingScalingConfirmed proves the anti-false-positive core: a time-based
// verdict is returned ONLY when the delay scales linearly with the injected sleep,
// and every noise class (fixed-slow endpoint, WAF tarpit that ignores the sleep
// value, jittery baseline, sub-linear delay) is rejected.
func TestTimingScalingConfirmed(t *testing.T) {
	ms := time.Millisecond
	s := time.Second
	cases := []struct {
		name                             string
		base, baseMax, i0, i2, i5, i5min time.Duration
		want                             bool
	}{
		{"real linear sleep", 200 * ms, 300 * ms, 210 * ms, 2200 * ms, 5200 * ms, 5000 * ms, true},
		{"real sleep with modest jitter", 300 * ms, 500 * ms, 320 * ms, 2400 * ms, 5300 * ms, 5100 * ms, true},
		// FP: the payload structure itself is slow (control sleep(0) already high).
		{"payload inherently slow", 200 * ms, 300 * ms, 4000 * ms, 4200 * ms, 5200 * ms, 5000 * ms, false},
		// FP: WAF/endpoint adds a FIXED delay on any injection, ignoring the number.
		{"fixed delay, no scaling", 200 * ms, 300 * ms, 210 * ms, 4000 * ms, 4100 * ms, 3900 * ms, false},
		// FP: injected sleep(5) overlaps the baseline distribution (jittery host).
		{"overlaps baseline", 200 * ms, 5 * s, 210 * ms, 2200 * ms, 5200 * ms, 4000 * ms, false},
		// FP: sub-linear — sleep(2) barely moved, so not a real 1:1 sleep.
		{"sub-linear step", 200 * ms, 300 * ms, 210 * ms, 700 * ms, 5200 * ms, 5000 * ms, false},
	}
	for _, c := range cases {
		got := timingScalingConfirmed(c.base, c.baseMax, c.i0, c.i2, c.i5, c.i5min)
		if got != c.want {
			t.Errorf("%s: timingScalingConfirmed = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestTimingPayloadsCoverDBMS makes sure every major DBMS has a sleep vector.
func TestTimingPayloadsCoverDBMS(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range timingPayloads() {
		seen[p.dbms] = true
		pl := p.build("1", 5)
		if !strings.Contains(pl, "SLEEP(5)") && !strings.Contains(pl, "pg_sleep(5)") &&
			!strings.Contains(pl, "WAITFOR DELAY '0:0:5'") && !strings.Contains(pl, "RECEIVE_MESSAGE(CHR(65),5)") {
			t.Errorf("payload for %s does not encode a 5s sleep: %s", p.dbms, pl)
		}
	}
	for _, d := range []string{"mysql", "postgresql", "mssql", "oracle"} {
		if !seen[d] {
			t.Errorf("no time-based payload for DBMS %q", d)
		}
	}
}
