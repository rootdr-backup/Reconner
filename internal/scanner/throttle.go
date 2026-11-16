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
	slots   chan struct{}
	// consecutiveTransportFails counts IN-A-ROW transport-level failures
	// (connection refused/reset, dial timeout — "can't even reach the host"),
	// reset to 0 by ANY response that got a real status code back, including
	// a 429/503. This is deliberately a DIFFERENT, stricter signal than the
	// backoff/AIMD state above: a WAF returning 403/429 means the host is
	// reachable but filtering, which the backoff already handles; a run of
	// transport failures means the host (or this scanner's egress IP) is
	// actually unreachable — the specific condition an operator wants the
	// whole scan paused for, not just one ladder skipped. See
	// hostUnreachable/AllKnownHostsUnreachable below.
	consecutiveTransportFails int
}

const (
	throttleMax      = 2 * time.Second       // hard ceiling on per-request delay
	throttleBumpBase = 60 * time.Millisecond // added on each unhealthy response
	throttleEase     = 30 * time.Millisecond // removed on each healthy response
	// Independent modules used to multiply their private worker pools into dozens
	// of simultaneous requests to one app. Twelve keeps a healthy DAST worker pool
	// fully busy while bounding cross-module bursts that cause 429/challenges and
	// timeout-driven misses. This is shared per host across every target/module.
	hostMaxInFlight = 12
)

var hostThrottles sync.Map // host -> *hostThrottleState

func throttleFor(host string) *hostThrottleState {
	if v, ok := hostThrottles.Load(host); ok {
		return v.(*hostThrottleState)
	}
	v, _ := hostThrottles.LoadOrStore(host, &hostThrottleState{slots: make(chan struct{}, hostMaxInFlight)})
	return v.(*hostThrottleState)
}

// hostRequestAcquire reserves one shared per-host request slot. Waiting occurs
// before any detector timing window, and cancellation releases waiters promptly.
func hostRequestAcquire(ctx context.Context, host string) (func(), bool) {
	if host == "" {
		return func() {}, true
	}
	st := throttleFor(host)
	select {
	case st.slots <- struct{}{}:
		return func() { <-st.slots }, true
	case <-ctx.Done():
		return nil, false
	}
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

// hostThrottleSevere reports whether a host's adaptive backoff has already
// ramped to (or near) the hard ceiling — i.e. this host has been repeatedly
// unhealthy (timeouts / 429 / 503) very recently, observed by ANY module
// against ANY target. A detector with a large, multi-request proof ladder
// (SQLi's error-forced/boolean/OR-based extraction easily runs 40-80+ requests
// per candidate) should skip that ladder entirely on such a host rather than
// grinding through it: the extra requests just add more load to an already
// struggling host, the differential signal is unreliable behind a WAF/rate-
// limiter to begin with (this is what looksLikeBlockPage/bodyLooksLikeWAFBlock
// already guard against per-response), and on a large multi-hundred-endpoint
// target this is the dominant real-world cause of a scan taking many hours
// longer than it needs to.
func hostThrottleSevere(host string) bool {
	if host == "" {
		return false
	}
	st := throttleFor(host)
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.backoff >= throttleMax*3/4
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
	// ANY real status code — even a 429/503 — proves the host is reachable;
	// only a genuine transport failure keeps the unreachable streak alive.
	if transportErr {
		st.consecutiveTransportFails++
	} else {
		st.consecutiveTransportFails = 0
	}
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

// hostUnreachableThreshold is how many IN-A-ROW transport failures (not
// WAF/rate-limit responses — see consecutiveTransportFails) a host needs
// before it is reported unreachable. High enough that a couple of dropped
// connections during a noisy scan never trips it, low enough to react within
// a handful of requests to a real network-level block.
const hostUnreachableThreshold = 6

// HostUnreachable reports whether host currently has a sustained run of
// transport-level failures (as opposed to a reachable-but-filtering WAF
// response). Reflects every module's real request outcomes against this
// host, shared target-wide and across the whole process — the same
// observation stream hostThrottleObserve already feeds.
func HostUnreachable(host string) bool {
	if host == "" {
		return false
	}
	st := throttleFor(host)
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.consecutiveTransportFails >= hostUnreachableThreshold
}

// AllKnownHostsUnreachable reports whether EVERY host in hosts currently
// reads unreachable — the deliberately narrow condition for auto-pausing a
// whole scan (an operator-reported IP block): never on one WAF-filtered
// path, never on one unlucky host, only when the entire known asset set for
// the target has gone dark. A host this scan has never actually probed yet
// reads as reachable (no observations ⇒ zero fail streak), so an empty or
// not-yet-observed host list correctly never triggers a pause.
func AllKnownHostsUnreachable(hosts []string) bool {
	if len(hosts) == 0 {
		return false
	}
	for _, h := range hosts {
		if !HostUnreachable(h) {
			return false
		}
	}
	return true
}

// HostOfURL exports the same hostname normalization hostThrottleObserve's
// callers already key the shared throttle/reachability state by — so a
// caller outside this package (the scheduler, checking whether every known
// asset of a target is unreachable) derives the identical key, never a
// near-miss from reimplementing URL/host parsing a second time.
func HostOfURL(rawURL string) string { return hostOfURL(rawURL) }

// ObserveHostUnreachable records one transport-level failure observation for
// host directly (connection refused/reset, dial timeout — no real response),
// without performing a request. The normal path is hostThrottleObserve, fed
// by every module through sendInjectedFull's own request outcome; this is
// for a caller (a lightweight connectivity probe, a test) that already knows
// a host is unreachable by some other means and needs to feed that into the
// same shared state HostUnreachable/AllKnownHostsUnreachable read.
func ObserveHostUnreachable(host string) { hostThrottleObserve(host, 0, true) }
