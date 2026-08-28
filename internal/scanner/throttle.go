package scanner

import (
	"context"
	"sync"
	"time"
)

// Adaptive per-host throttle governor.
//
// Every active web module funnels its requests through sendInjectedFull, and each
// runs its own worker pool, so a single fragile or WAF-fronted host can be hit by
// many modules at once. Two bad things follow: the host starts timing out (→
// false NEGATIVES, because a detector reads a dropped response as "no signal"),
// and its WAF starts issuing block/challenge pages (→ false POSITIVES on the
// differential detectors, and wasted requests). A fixed global rate limit would
// throttle healthy hosts too and cost scan speed.
//
// This governor instead paces PER HOST, adaptively (AIMD, the TCP-congestion
// idea): a healthy host carries ZERO added delay (full speed), but the moment a
// host returns timeouts / 429 / 503 its per-request delay ramps up multiplicatively
// and eases back down additively as it recovers. Crucially the wait happens
// BEFORE the timing window in sendInjectedFull, so it never corrupts a time-based
// SQLi/RCE measurement.

type hostThrottleState struct {
	mu      sync.Mutex
	backoff time.Duration
}

const (
	throttleMax      = 2 * time.Second       // hard ceiling on per-request delay
	throttleBumpBase = 60 * time.Millisecond // added on each unhealthy response
	throttleEase     = 30 * time.Millisecond // removed on each healthy response
)

var hostThrottles sync.Map // host -> *hostThrottleState

func throttleFor(host string) *hostThrottleState {
	if v, ok := hostThrottles.Load(host); ok {
		return v.(*hostThrottleState)
	}
	v, _ := hostThrottles.LoadOrStore(host, &hostThrottleState{})
	return v.(*hostThrottleState)
}

// hostThrottleWait sleeps the host's current adaptive backoff (0 for a healthy
// host), honouring ctx. Call BEFORE starting any timing measurement.
func hostThrottleWait(ctx context.Context, host string) {
	if host == "" {
		return
	}
	st := throttleFor(host)
	st.mu.Lock()
	d := st.backoff
	st.mu.Unlock()
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

// hostThrottleObserve updates a host's backoff from one response: multiplicative
// increase when it looks overloaded/blocked (transport error/timeout, 429, 503),
// additive decrease when it answered cleanly. status 0 with unhealthy=true marks
// a transport failure.
func hostThrottleObserve(host string, status int, transportErr bool) {
	if host == "" {
		return
	}
	unhealthy := transportErr || status == 429 || status == 503
	st := throttleFor(host)
	st.mu.Lock()
	defer st.mu.Unlock()
	if unhealthy {
		// multiplicative increase (double, plus a floor bump) up to the ceiling.
		next := st.backoff*2 + throttleBumpBase
		if next > throttleMax {
			next = throttleMax
		}
		st.backoff = next
		return
	}
	// additive decrease toward zero.
	st.backoff -= throttleEase
	if st.backoff < 0 {
		st.backoff = 0
	}
}
