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
