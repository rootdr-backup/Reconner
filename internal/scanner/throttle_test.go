package scanner

import (
	"context"
	"testing"
	"time"
)

func TestHostThrottleAIMD(t *testing.T) {
	host := "aimd-test.example:8080"
	// reset any prior state.
	hostThrottles.Delete(host)

	// Healthy host: backoff stays at zero (full speed, no pacing).
	for i := 0; i < 3; i++ {
		hostThrottleObserve(host, 200, false)
	}
	if got := throttleFor(host).backoff; got != 0 {
		t.Fatalf("healthy host backoff = %v, want 0", got)
	}

	// Unhealthy responses ramp the backoff up multiplicatively.
	hostThrottleObserve(host, 429, false)
	b1 := throttleFor(host).backoff
	if b1 <= 0 {
		t.Fatalf("after 429 backoff should be > 0, got %v", b1)
	}
	hostThrottleObserve(host, 0, true) // transport error/timeout
	b2 := throttleFor(host).backoff
	if b2 <= b1 {
		t.Fatalf("backoff should increase after a second failure: %v -> %v", b1, b2)
	}

	// It is capped at the ceiling.
	for i := 0; i < 20; i++ {
		hostThrottleObserve(host, 503, false)
	}
	if got := throttleFor(host).backoff; got != throttleMax {
		t.Fatalf("backoff should saturate at %v, got %v", throttleMax, got)
	}

	// Recovery: healthy responses ease it back down additively toward zero.
	before := throttleFor(host).backoff
	hostThrottleObserve(host, 200, false)
	after := throttleFor(host).backoff
	if after != before-throttleEase {
		t.Fatalf("healthy response should ease backoff by %v: %v -> %v", throttleEase, before, after)
	}
	for i := 0; i < 200; i++ {
		hostThrottleObserve(host, 200, false)
	}
	if got := throttleFor(host).backoff; got != 0 {
		t.Fatalf("backoff should return to 0 after sustained health, got %v", got)
	}
}

func TestHostThrottleWaitHealthyIsInstant(t *testing.T) {
	host := "fast.example"
	hostThrottles.Delete(host)
	start := time.Now()
	hostThrottleWait(context.Background(), host) // no backoff → must not sleep
	if el := time.Since(start); el > 20*time.Millisecond {
		t.Fatalf("healthy host wait should be instant, took %v", el)
	}
}

// hostThrottleSevere is what SQLi's expensive proof ladders check before
// running: it must stay false on a healthy host and flip true once the
// adaptive backoff has ramped close to its ceiling (repeated 429/503/timeout),
// so a large multi-request ladder skips a host that's already struggling
// instead of piling on.
func TestHostThrottleSevere(t *testing.T) {
	host := "severe-test.example"
	hostThrottles.Delete(host)

	if hostThrottleSevere(host) {
		t.Fatalf("a fresh host must not be reported severe")
	}
	for i := 0; i < 3; i++ {
		hostThrottleObserve(host, 200, false)
	}
	if hostThrottleSevere(host) {
		t.Fatalf("a healthy host must not be reported severe")
	}

	// Ramp it to the ceiling via repeated unhealthy responses.
	for i := 0; i < 10; i++ {
		hostThrottleObserve(host, 503, false)
	}
	if throttleFor(host).backoff != throttleMax {
		t.Fatalf("expected backoff to saturate at the ceiling before asserting severity")
	}
	if !hostThrottleSevere(host) {
		t.Fatalf("a host saturated at the backoff ceiling must be reported severe")
	}

	// Recovery: enough healthy responses must bring it back below the severe
	// threshold (severe is 3/4 of the ceiling; throttleEase easing needs several
	// healthy responses to cross back under that bar).
	for i := 0; i < 20; i++ {
		hostThrottleObserve(host, 200, false)
	}
	if hostThrottleSevere(host) {
		t.Fatalf("a host that has recovered with sustained healthy responses must no longer be severe")
	}
}

// TestHostUnreachableRequiresTransportFailuresNotJustWAFResponses is the
// correctness contract behind the auto-pause feature: a WAF/rate-limiter
// returning 403/429/503 means the host is reachable (just filtering), which
// must NEVER be confused with the host actually being unreachable. Only a
// sustained run of genuine transport failures (connection refused/reset,
// dial timeout) may report a host unreachable.
func TestHostUnreachableRequiresTransportFailuresNotJustWAFResponses(t *testing.T) {
	host := "waf-not-unreachable.example"
	hostThrottles.Delete(host)

	for i := 0; i < 20; i++ {
		hostThrottleObserve(host, 403, false) // a real response — WAF block page
	}
	if HostUnreachable(host) {
		t.Fatalf("a host answering with WAF block pages (real HTTP responses) must never read as unreachable")
	}

	for i := 0; i < 20; i++ {
		hostThrottleObserve(host, 429, false)
	}
	if HostUnreachable(host) {
		t.Fatalf("a host answering 429 (rate-limited but reachable) must never read as unreachable")
	}
}

func TestHostUnreachableAfterSustainedTransportFailures(t *testing.T) {
	host := "dead-host.example"
	hostThrottles.Delete(host)

	if HostUnreachable(host) {
		t.Fatalf("a never-observed host must not read as unreachable")
	}
	for i := 0; i < hostUnreachableThreshold-1; i++ {
		hostThrottleObserve(host, 0, true)
	}
	if HostUnreachable(host) {
		t.Fatalf("must not report unreachable before the threshold is actually reached")
	}
	hostThrottleObserve(host, 0, true) // reaches the threshold
	if !HostUnreachable(host) {
		t.Fatalf("must report unreachable once the consecutive-transport-failure threshold is reached")
	}

	// A single real response (even an error status) breaks the streak — the
	// host answered, so it is reachable again.
	hostThrottleObserve(host, 500, false)
	if HostUnreachable(host) {
		t.Fatalf("one real response must reset the unreachable streak")
	}
}

func TestAllKnownHostsUnreachable(t *testing.T) {
	healthy, dead1, dead2 := "healthy.example", "dead1.example", "dead2.example"
	for _, h := range []string{healthy, dead1, dead2} {
		hostThrottles.Delete(h)
	}
	for i := 0; i < hostUnreachableThreshold; i++ {
		hostThrottleObserve(dead1, 0, true)
		hostThrottleObserve(dead2, 0, true)
	}
	hostThrottleObserve(healthy, 200, false)

	if AllKnownHostsUnreachable(nil) || AllKnownHostsUnreachable([]string{}) {
		t.Fatalf("an empty host list must never report fully blocked — nothing to pause for")
	}
	if !AllKnownHostsUnreachable([]string{dead1, dead2}) {
		t.Fatalf("a target whose every known host is unreachable must report fully blocked")
	}
	if AllKnownHostsUnreachable([]string{dead1, healthy, dead2}) {
		t.Fatalf("even one reachable host must prevent the fully-blocked verdict — this must never trip on a single bad host")
	}
}

func TestHostOfURL(t *testing.T) {
	// hostOfURL (scope.go) returns the lower-cased hostname without port — fine for
	// throttle keying, where a host's health is shared across its ports.
	cases := map[string]string{
		"https://Example.com/path?q=1": "example.com",
		"http://10.0.0.5:8080/x":       "10.0.0.5",
	}
	for in, want := range cases {
		if got := hostOfURL(in); got != want {
			t.Errorf("hostOfURL(%q) = %q, want %q", in, got, want)
		}
	}
}
