package scanner

import "context"

// Scan speed / stealth profile — shared web-scanning knob (formerly defined in
// the now-removed network module). Detectors read it from the scan context to
// scale concurrency and request rate.

type ScanSpeed int

const (
	SpeedNormal ScanSpeed = iota // balanced defaults
	SpeedSlow                    // low-and-slow / stealth
	SpeedFast                    // maximum throughput
)

type scanSpeedKey string

const ctxSpeed scanSpeedKey = "scan_speed"

// WithNetworkSpeed marks a scan context with a speed/stealth profile. The name is
// retained for source compatibility with existing callers.
func WithNetworkSpeed(ctx context.Context, sp ScanSpeed) context.Context {
	return context.WithValue(ctx, ctxSpeed, sp)
}

func speedFromCtx(ctx context.Context) ScanSpeed {
	v, _ := ctx.Value(ctxSpeed).(ScanSpeed)
	return v
}
