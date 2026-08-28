package api

import (
	"testing"
	"time"
)

// TestLoginLimiter verifies the per-IP login throttle: the first loginMaxAttempts
// failures are allowed, the next is blocked, a successful login (reset) clears the
// block, and different IPs are tracked independently.
func TestLoginLimiter(t *testing.T) {
	l := &loginLimiter{hits: make(map[string][]time.Time)}
	const ip = "203.0.113.7"

	for i := 0; i < loginMaxAttempts; i++ {
		if !l.allowed(ip) {
			t.Fatalf("attempt %d should be allowed (limit is %d)", i+1, loginMaxAttempts)
		}
		l.recordFailure(ip)
	}
	if l.allowed(ip) {
		t.Fatalf("attempt %d should be blocked after %d failures", loginMaxAttempts+1, loginMaxAttempts)
	}

	// A successful login clears the counter.
	l.reset(ip)
	if !l.allowed(ip) {
		t.Fatal("after reset the IP should be allowed again")
	}

	// A different IP is unaffected by another IP's failures.
	other := "198.51.100.9"
	for i := 0; i < loginMaxAttempts+2; i++ {
		l.recordFailure(ip)
	}
	if !l.allowed(other) {
		t.Fatal("a different IP must not be throttled by another IP's failures")
	}
}
