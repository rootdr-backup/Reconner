package scanner

import "context"

// Per-scan speed/stealth profile for WEB scans — the bug-bounty analogue of the
// network speed profile. It reuses the same ScanSpeed enum (see network.go) but
// is carried on its own context key and scales the WEB request knobs (nuclei
// concurrency / bulk-size / rate-limit): "slow" is low-and-slow to stay under WAF
// rate limits and avoid bans, "fast" pushes maximum throughput.

type webSpeedKey struct{}

// WithWebSpeed marks a context with a web scan speed profile.
func WithWebSpeed(ctx context.Context, sp ScanSpeed) context.Context {
	return context.WithValue(ctx, webSpeedKey{}, sp)
}

func webSpeedFromCtx(ctx context.Context) ScanSpeed {
	if v, ok := ctx.Value(webSpeedKey{}).(ScanSpeed); ok {
		return v
	}
	return SpeedNormal
}

// applyWebSpeed scales nuclei's concurrency, bulk-size and rate-limit for the
// active profile. Normal is a no-op (the tuned defaults). Slow throttles hard to
// keep a target's WAF happy; fast overshoots for speed when bans aren't a worry.
func applyWebSpeed(sp ScanSpeed, conc, bulk, rl int) (int, int, int) {
	atLeast := func(v, floor int) int {
		if v < floor {
			return floor
		}
		return v
	}
	switch sp {
	case SpeedSlow:
		return atLeast(conc/3, 10), atLeast(bulk/2, 10), atLeast(rl/5, 15)
	case SpeedFast:
		return conc * 2, bulk * 2, rl * 3
	default: // SpeedNormal
		return conc, bulk, rl
	}
}
