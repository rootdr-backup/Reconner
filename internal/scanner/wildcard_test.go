package scanner

import (
	"net"
	"sort"
	"testing"
)

func mustIP(t *testing.T, raw string) net.IPAddr {
	t.Helper()
	ip := net.ParseIP(raw)
	if ip == nil {
		t.Fatalf("bad test IP %q", raw)
	}
	return net.IPAddr{IP: ip}
}

func TestCandidateBranchSuffixCounts(t *testing.T) {
	apex := "realestate.com.au"
	var candidates []string
	for i := 0; i < 6; i++ {
		candidates = append(candidates,
			"junk"+string(rune('a'+i))+".git.realestate.com.au")
	}
	// Nested junk below a deeper label: counts both branch suffixes.
	candidates = append(candidates, "word.es.git.realestate.com.au", "word2.es.git.realestate.com.au")
	// Unrelated legitimate names must not create branch suffixes.
	candidates = append(candidates, "mail.realestate.com.au", "api.realestate.com.au")
	// The branch parent itself must not count (it equals the suffix, not a name under it).
	candidates = append(candidates, "git.realestate.com.au")
	candidates = append(candidates, "wikileaks.not-the-apex.org", "junk.evil-realestate.com.au")

	counts := candidateBranchSuffixCounts(candidates, apex)
	if counts["git.realestate.com.au"] != 8 {
		t.Fatalf("expected 8 candidates under git.realestate.com.au (nested es.git names counted too), got %d (%v)", counts["git.realestate.com.au"], counts)
	}
	if counts["es.git.realestate.com.au"] != 2 {
		t.Fatalf("expected 2 candidates under es.git.realestate.com.au, got %d", counts["es.git.realestate.com.au"])
	}
	for _, forbidden := range []string{"com.au", "realestate.com.au", "not-the-apex.org"} {
		if counts[forbidden] != 0 {
			t.Fatalf("suffix %q must never be counted as a branch of the apex, got %d", forbidden, counts[forbidden])
		}
	}
}

func TestWildcardProfileMatching(t *testing.T) {
	profile := &wildcardProfile{
		apex: wildcardZone{
			ips: map[string]bool{"1.1.1.1": true},
			cnames: map[string]bool{
				"shared-target.realestate.com.au": true,
			},
		},
		branches: []wildcardZone{
			{suffix: "git.realestate.com.au", ips: map[string]bool{"2.2.2.2": true}, cnames: map[string]bool{"git-target.realestate.com.au": true}},
			{suffix: "es.git.realestate.com.au", ips: map[string]bool{"3.3.3.3": true}},
		},
	}

	if got := profile.firstNonWildcardIP("mail.realestate.com.au", []string{"1.1.1.1"}); got != "" {
		t.Fatalf("apex wildcard IP must reject, got %q", got)
	}
	if got := profile.firstNonWildcardIP("x.es.git.realestate.com.au", []string{"3.3.3.3"}); got != "" {
		t.Fatalf("deeper branch IP must reject names under the deeper zone, got %q", got)
	}
	if got := profile.firstNonWildcardIP("x.git.realestate.com.au", []string{"3.3.3.3"}); got != "3.3.3.3" {
		t.Fatalf("deeper-zone IP must NOT reject names outside the deeper zone, got %q", got)
	}
	if got := profile.firstNonWildcardIP("x.git.realestate.com.au", []string{"2.2.2.2"}); got != "" {
		t.Fatalf("branch wildcard IP must reject, got %q", got)
	}
	if got := profile.firstNonWildcardIP("x.other.realestate.com.au", []string{"2.2.2.2"}); got != "2.2.2.2" {
		t.Fatalf("branch IP must NOT reject names outside the branch, got %q", got)
	}
	// Label-boundary safety: "evil-git" is one label — not under *.git.
	if got := profile.firstNonWildcardIP("asdf-garbage.git.realestate.com.au", []string{"9.9.9.9"}); got != "9.9.9.9" {
		t.Fatalf("unrelated IP under a wildcard branch must still admit (needs HTTP proof), got %q", got)
	}
	if got := profile.firstNonWildcardIP("evil-git.realestate.com.au", []string{"2.2.2.2"}); got != "2.2.2.2" {
		t.Fatalf("hyphenated label must not match the branch suffix, got %q (rejected would mean a false wildcard hit)", got)
	}

	if profile.isWildcardCNAME("x.realestate.com.au", "shared-Target.Realestate.com.au") != true {
		t.Fatalf("apex CNAME target must match case-insensitively")
	}
	if profile.isWildcardCNAME("x.git.realestate.com.au", "git-target.realestate.com.au") != true {
		t.Fatalf("branch CNAME target must match for names under the branch")
	}
	if profile.isWildcardCNAME("x.other.realestate.com.au", "git-target.realestate.com.au") != false {
		t.Fatalf("branch CNAME target must NOT match for names outside the branch")
	}
	if profile.isWildcardCNAME("x.realestate.com.au", "") != false {
		t.Fatalf("empty target must never be a wildcard hit")
	}

	if !profile.apexWildcard() {
		t.Fatalf("apex evidence must mark the profile as apex-wildcard")
	}
	if !profile.hasAnyWildcard() {
		t.Fatalf("branch evidence must keep the profile flagged")
	}
}

func TestWildcardProfileNilAndBoundary(t *testing.T) {
	var nilProfile *wildcardProfile
	if got := nilProfile.firstNonWildcardIP("a.realestate.com.au", []string{"1.1.1.1"}); got != "1.1.1.1" {
		t.Fatalf("nil profile must admit, got %q", got)
	}
	if nilProfile.overlapsWildcardIPs("a.realestate.com.au", []string{"1.1.1.1"}) {
		t.Fatalf("nil profile must never report overlaps")
	}
	if nilProfile.apexWildcard() || nilProfile.hasAnyWildcard() {
		t.Fatalf("nil profile must not claim evidence")
	}

	empty := &wildcardProfile{}
	if got := empty.firstNonWildcardIP("a.realestate.com.au", []string{"1.1.1.1", "2.2.2.2"}); got != "1.1.1.1" {
		t.Fatalf("empty profile must admit first IP, got %q", got)
	}
}

func TestDecideWildcardZone(t *testing.T) {
	pool := map[string]bool{"10.0.0.1": true, "10.0.0.2": true, "10.0.0.3": true, "10.0.0.4": true}
	cnames := map[string]int{"edge.realestate.com.au": 4}

	zone, needsMore := decideWildcardZone(3, 0, pool, cnames, "git.realestate.com.au")
	if needsMore {
		t.Fatalf("3 resolving probes must settle the zone")
	}
	if len(zone.ips) != 4 {
		t.Fatalf("rotating pool: all probe IPs belong to the wildcard pool, got %v", zone.ips)
	}
	if len(zone.cnames) != 1 {
		t.Fatalf("4 aggressive CNAME agreements must produce the CNAME pool, got %v", zone.cnames)
	}

	zone, needsMore = decideWildcardZone(0, 3, pool, cnames, "git.realestate.com.au")
	if needsMore || zone.hasEvidence() {
		t.Fatalf("3 definitive NXDOMAINs must settle an empty zone (needsMore=%v evidence=%v)", needsMore, zone.hasEvidence())
	}

	_, needsMore = decideWildcardZone(2, 0, pool, cnames, "git.realestate.com.au")
	if !needsMore {
		t.Fatalf("below agreement threshold must request a second batch")
	}

	_, needsMore = decideWildcardZone(2, 1, map[string]bool{}, map[string]int{}, "git.realestate.com.au")
	if !needsMore {
		t.Fatalf("2 resolved + 1 NX is still inconclusive")
	}

	zone, needsMore = decideWildcardZone(1, 3, pool, cnames, "git.realestate.com.au")
	if needsMore {
		t.Fatalf("3 NX dominate a single resolve — that resolver disagrees, majority NX wins")
	}
	if zone.hasEvidence() {
		t.Fatalf("majority-NX verdict must not create an answer pool")
	}
}

func TestSummarizeWildcardProbes(t *testing.T) {
	probes := []wildcardProbe{
		{verdict: probeResolved, ips: []net.IPAddr{mustIP(t, "10.1.1.1"), mustIP(t, "10.1.1.2")}, cname: "a.realestate.com.au"},
		{verdict: probeResolved, ips: []net.IPAddr{mustIP(t, "10.1.1.1")}},
		{verdict: probeNX},
		{verdict: probeNX},
		{verdict: probeNX},
		{verdict: probeAmbiguous, cname: "b.realestate.com.au"},
	}
	resolved, nx, ambiguous, allIPs, cnameCounts := summarizeWildcardProbes(probes)
	if resolved != 2 || nx != 3 || ambiguous != 1 {
		t.Fatalf("verdict histogram mismatch: resolved=%d nx=%d ambiguous=%d", resolved, nx, ambiguous)
	}
	if len(allIPs) != 2 || !allIPs["10.1.1.1"] || !allIPs["10.1.1.2"] {
		t.Fatalf("IP union mismatch: %v", allIPs)
	}
	if cnameCounts["a.realestate.com.au"] != 1 || cnameCounts["b.realestate.com.au"] != 1 {
		t.Fatalf("CNAME counts mismatch: %v", cnameCounts)
	}
}

func TestDetectBranchWildcardsOrderAndCap(t *testing.T) {
	apex := "realestate.com.au"
	var candidates []string
	for i := 0; i < 9; i++ {
		candidates = append(candidates, "junk"+string(rune('a'+i))+".git.realestate.com.au")
	}
	counts := candidateBranchSuffixCounts(candidates, apex)
	if len(counts) != 1 || counts["git.realestate.com.au"] != 9 {
		t.Fatalf("cluster must reduce to one suffix: %v", counts)
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if keys[0] != "git.realestate.com.au" {
		t.Fatalf("unexpected suffix: %v", keys)
	}
}

func TestResolverServerAddress(t *testing.T) {
	cases := map[string]string{
		"1.1.1.1":                   "1.1.1.1:53",
		"8.8.8.8:5353":              "8.8.8.8:5353",
		"2606:4700:4700::1111":      "[2606:4700:4700::1111]:53",
		"[2606:4700:4700::1111]":    "[2606:4700:4700::1111]:53",
		"[2606:4700:4700::1111]:53": "[2606:4700:4700::1111]:53",
		"  ":                        "",
	}
	for in, want := range cases {
		if got := resolverServerAddress(in); got != want {
			t.Fatalf("resolverServerAddress(%q) = %q, want %q", in, got, want)
		}
	}
}
