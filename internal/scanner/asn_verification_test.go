package scanner

import "testing"

// TestFilterASNSweepExcludesKnownSharedCDNInfrastructure is the regression
// test for ASN/CIDR discovery's verification layer 1: an address an ASN
// lookup surfaced is never treated as the organisation's own network when
// cdncheck's bundled dataset identifies it as shared CDN/WAF infrastructure
// — 173.245.48.12 is a known Cloudflare range, matching the same fixture
// TestFilterCDNWAFBlocksKnownCloudflareRangeButKeepsPrivate already relies
// on, so this stays deterministic in CI with no network access.
func TestFilterASNSweepExcludesKnownSharedCDNInfrastructure(t *testing.T) {
	kept, excludedProviders := filterASNSweepToOrgOwnedCandidates([]string{"173.245.48.12", "192.168.1.1"})
	if len(kept) != 1 || kept[0] != "192.168.1.1" {
		t.Fatalf("kept=%v, want only the non-CDN address", kept)
	}
	if len(excludedProviders) != 1 {
		t.Fatalf("excludedProviders=%v, want exactly one provider name", excludedProviders)
	}
}

// TestFilterASNSweepKeepsEverythingWhenNothingIsSharedInfrastructure covers
// the common case — a genuinely dedicated netblock — where the filter must
// be a true no-op: every address survives and no provider names are
// reported.
func TestFilterASNSweepKeepsEverythingWhenNothingIsSharedInfrastructure(t *testing.T) {
	in := []string{"192.168.1.1", "192.168.1.2", "10.0.0.5"}
	kept, excludedProviders := filterASNSweepToOrgOwnedCandidates(in)
	if len(kept) != len(in) {
		t.Fatalf("kept=%v, want all %d addresses unchanged", kept, len(in))
	}
	if len(excludedProviders) != 0 {
		t.Fatalf("excludedProviders=%v, want none", excludedProviders)
	}
}

// TestFilterASNSweepIgnoresUnparsableEntriesRatherThanPanicking guards the
// defensive net.ParseIP check: a malformed entry is silently dropped, never
// a panic or a spurious "kept" result.
func TestFilterASNSweepIgnoresUnparsableEntriesRatherThanPanicking(t *testing.T) {
	kept, excludedProviders := filterASNSweepToOrgOwnedCandidates([]string{"not-an-ip", "192.168.1.1"})
	if len(kept) != 1 || kept[0] != "192.168.1.1" {
		t.Fatalf("kept=%v, want only the valid address", kept)
	}
	if len(excludedProviders) != 0 {
		t.Fatalf("excludedProviders=%v, want none", excludedProviders)
	}
}
