package config

import "testing"

func TestClampInt(t *testing.T) {
	cases := []struct{ v, lo, hi, want int }{
		{5, 10, 100, 10},    // below floor
		{500, 10, 100, 100}, // above ceiling
		{50, 10, 100, 50},   // inside
	}
	for _, c := range cases {
		if got := clampInt(c.v, c.lo, c.hi); got != c.want {
			t.Errorf("clampInt(%d,%d,%d)=%d want %d", c.v, c.lo, c.hi, got, c.want)
		}
	}
}

// A tiny container must keep worker compatibility while its memory budget stays
// below the real cgroup/host capacity (the old hard 3072 MB floor caused OOMs).
func TestAutoTuneSmallHostRespectsMemory(t *testing.T) {
	w := autoTunedWorkers(1)
	if w.SubdomainEnumeration != 25 || w.HTTPProbing != 40 || w.Nuclei != 6 {
		t.Fatalf("small-host workers regressed below floor: %+v", w)
	}
	l := autoTunedLimits(1, 512)
	if l.MaxConcurrentTargets != 7 || l.HTTPRateLimit != 150 || l.MaxMemoryMB != 384 {
		t.Fatalf("small-host limits ignore available memory: %+v", l)
	}
}

func TestHeavyVerificationDefaultsAreOptIn(t *testing.T) {
	t.Setenv("RECON_NO_AUTOTUNE", "1")
	cfg := defaultConfig()
	if cfg.EnableSQLmap || cfg.NucleiDAST {
		t.Fatalf("heavy verification must default off: sqlmap=%v nuclei_dast=%v", cfg.EnableSQLmap, cfg.NucleiDAST)
	}
}

func TestFixedDefaultsStillRespectSmallMemory(t *testing.T) {
	if got := memoryBudgetMB(512, 3072); got != 384 {
		t.Fatalf("fixed default budget=%d want 384", got)
	}
	if got := memoryBudgetMB(64, 3072); got != 64 {
		t.Fatalf("tiny-environment budget=%d must not exceed available 64 MB", got)
	}
	if got := memoryBudgetMB(131072, 3072); got != 3072 {
		t.Fatalf("fixed-default ceiling=%d want 3072", got)
	}
}

// A big 32-core / 128GB server must open the throttles well past the floors,
// but never past the safety ceilings.
func TestAutoTuneLargeHostScalesUpBounded(t *testing.T) {
	w := autoTunedWorkers(32)
	if w.HTTPProbing <= 40 || w.HTTPProbing > 400 {
		t.Fatalf("HTTPProbing not scaled/bounded: %d", w.HTTPProbing)
	}
	if w.Nuclei <= 6 || w.Nuclei > 48 {
		t.Fatalf("Nuclei not scaled/bounded: %d", w.Nuclei)
	}
	l := autoTunedLimits(32, 131072)
	if l.MaxConcurrentTargets <= 7 || l.MaxConcurrentTargets > 64 {
		t.Fatalf("MaxConcurrentTargets not scaled/bounded: %d", l.MaxConcurrentTargets)
	}
	if l.HTTPRateLimit <= 150 || l.HTTPRateLimit > 2000 {
		t.Fatalf("HTTPRateLimit not scaled/bounded: %d", l.HTTPRateLimit)
	}
	// 75% of 128GB, capped at the 64GB ceiling.
	if l.MaxMemoryMB != 65536 {
		t.Fatalf("MaxMemoryMB ceiling = %d want 65536", l.MaxMemoryMB)
	}
}
