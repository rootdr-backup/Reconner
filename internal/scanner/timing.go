package scanner

import (
	"context"
	"sort"
	"time"
)

// Centralized statistical timing analysis for blind/time-based confirmation
// (CMDi, blind SQLi, time-based SSTI). A single "slow response" is the #1 false
// positive in time-based detection: any endpoint hiccup, GC pause, or cold cache
// looks like a SLEEP() firing. This turns "one request looked slow" into a
// distribution test that only passes on an UNAMBIGUOUS, sleep-tracking delay.

// medianDur returns the median of a duration sample (input is copied, not
// mutated). Empty → 0.
func medianDur(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	c := append([]time.Duration(nil), ds...)
	sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
	return c[len(c)/2]
}

func maxDur(ds []time.Duration) time.Duration {
	m := time.Duration(0)
	for _, d := range ds {
		if d > m {
			m = d
		}
	}
	return m
}

func minDur(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	m := ds[0]
	for _, d := range ds[1:] {
		if d < m {
			m = d
		}
	}
	return m
}

// timingSeparated reports whether the `probe` timing distribution is delayed by
// ~expected relative to the `base` distribution with enough confidence to call it
// a real, injected delay. It requires (all must hold):
//
//  1. Enough samples on each side (≥ minTimingSamples) — no single-shot verdicts.
//  2. FULL DISTRIBUTION SEPARATION: min(probe) > max(base). With n≥3 per side the
//     probability of this happening by chance under "same distribution" is tiny
//     (n=4 → 1/C(8,4) ≈ 1.4%), so non-overlap is our significance proxy — and it
//     structurally kills a constant-slow endpoint (its base samples are slow too,
//     so they overlap the probe) and one-off spikes (a single slow base sample
//     raises max(base) above the probe floor).
//  3. The median delay TRACKS the injected sleep: expected-slack ≤ Δmedian, so a
//     merely-slower endpoint isn't enough — the delay must be ~expected.
//  4. The delay isn't absurdly larger than requested (Δmedian ≤ expected + 4·slack),
//     so a random long stall can't masquerade as clean scaling.
func timingSeparated(base, probe []time.Duration, expected, slack time.Duration) bool {
	if len(base) < minTimingSamples || len(probe) < minTimingSamples {
		return false
	}
	if minDur(probe) <= maxDur(base) {
		return false // distributions overlap → not a reliable, injected delay
	}
	delta := medianDur(probe) - medianDur(base)
	if delta < expected-slack {
		return false // delay doesn't track the requested sleep
	}
	if delta > expected+4*slack {
		return false // wildly off → a stall, not clean scaling
	}
	return true
}

// minTimingSamples is the floor for a time-based verdict — 3–5 samples per side,
// per the FP policy. We collect 4 by default (a good jitter/latency trade-off).
const (
	minTimingSamples     = 3
	defaultTimingSamples = 4
)

// collectTimings sends the same payload n times and returns every observed
// duration (not just the median), so callers can run the distribution test above.
// Aborts early (returns what it has) on context cancellation.
func collectTimings(ctx context.Context, client timingSender, ip insertionPoint, payload string, auth map[string]string, n int) []time.Duration {
	out := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			return out
		}
		_, d := client(ctx, ip, payload, auth)
		out = append(out, d)
	}
	return out
}

// timingSender abstracts "send this injected payload, return elapsed" so the
// timing engine is unit-testable without real HTTP.
type timingSender func(ctx context.Context, ip insertionPoint, payload string, auth map[string]string) (string, time.Duration)
