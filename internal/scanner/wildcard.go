package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// The wildcard gate answers one question for a DNS zone: "does a random
// hostname under this suffix resolve anyway?" If it does, every passive/
// brute "discovery" under that suffix may be a fabricated name served by the
// wildcard instead of a real asset, and the resolution gate has to prove each
// name against the wildcard's answer pool before admitting it.
//
// Reconner previously ran a single batch of 5 fixed probes and treated any
// DNS error like NXDOMAIN. Three failure modes slipped through:
//
//  1. A flaky answer (SERVFAIL, rate limit, timeout) looked identical to
//     NXDOMAIN. Fewer than 3 probes resolved => no wildcard evidence => the
//     whole junk namespace was admitted (the "sometimes everything looks like
//     a subdomain" bug).
//  2. Rotating CDN pools can answer more than 5 probes' worth of IPs, and
//     CNAME-target rotation needs more samples for the >=3 agreement rule.
//  3. Branch wildcards (e.g. *.git.example.com under example.com) never got
//     probed at all — the apex probes test only the apex. A junk fleet under
//     a deeper wildcard (asdf-garbage.git.example.com) was admitted wholesale.
//
// This file fixes all three: cross-resolver retry with an explicit NXDOMAIN
// verdict (net.DNSError.IsNotFound), a second independent probe batch when
// the first is inconclusive, and branch probes generated from clustered
// candidate suffixes.

// probeVerdict classifies one random-label lookup. The distinction matters:
// probeNX is definitive proof the label does not exist, while probeAmbiguous
// (SERVFAIL/timeouts) proves nothing and must trigger more sampling.
type probeVerdict int

const (
	probeResolved probeVerdict = iota
	probeNX
	probeAmbiguous
)

// fixedWildcardProbeStems are the original five probe labels. They are kept
// byte-for-byte so a scan reacts to the same zones previous releases
// detected, and so tests are deterministic. The second (adaptive) batch uses
// fresh random labels instead, in case an operator's zone matches the fixed
// stems for some exotic reason.
var fixedWildcardProbeStems = []string{
	"zz9z3k7q1wildcard",
	"qx84jd02noexist",
	"a1b2c3d4e5random",
	"rcn7f4a9neverexists",
	"nohost2c8e1b6d",
}

// wildcardProbeMinAgreement is how many probes must agree before a verdict is
// trusted: 3 resolving labels prove a wildcard, 3 definitive NXDOMAINs prove
// the absence of one, 3 identical CNAME targets prove a CNAME-only wildcard.
const wildcardProbeMinAgreement = 3

// wildcardZone carries the answer-pool evidence for ONE suffix of DNS space.
// suffix == "" marks the apex zone (covers every candidate under the target
// domain); anything else marks a strictly deeper branch zone.
type wildcardZone struct {
	suffix string // "" = apex; else e.g. "git.example.com"
	ips    map[string]bool
	cnames map[string]bool
}

// hasEvidence reports whether the zone is a proven wildcard (any shared IP or
// CNAME answer pool). An empty zone is NOT a wildcard, including the
// "definitively NXDOMAIN" verdict.
func (z wildcardZone) hasEvidence() bool {
	return len(z.ips) > 0 || len(z.cnames) > 0
}

// wildcardProfile bundles the apex zone with any confirmed branch zones and
// answers the admission-gate questions per candidate name. A nil profile
// behaves like "no wildcard evidence", which keeps test paths simple.
type wildcardProfile struct {
	apex     wildcardZone
	branches []wildcardZone
}

// normalizeSubdomainName lowercases and trims a trailing dot so wildcard
// matching is case/format insensitive.
func normalizeSubdomainName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// mapKeys returns the key set of a candidate map as a slice.
func mapKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// zonesFor returns every zone whose suffix covers name: the apex zone always
// applies, plus each branch zone whose suffix the name sits strictly under
// (name != suffix). Branch suffixes are matched on full-suffix boundaries so
// "es.git.example.com" cannot satisfy a "git.example.com" zone via a partial
// label match.
func (p *wildcardProfile) zonesFor(name string) []wildcardZone {
	name = normalizeSubdomainName(name)
	zones := make([]wildcardZone, 0, 3)
	if p != nil {
		zones = append(zones, p.apex)
		for i := range p.branches {
			if strings.HasSuffix(name, "."+p.branches[i].suffix) {
				zones = append(zones, p.branches[i])
			}
		}
	}
	return zones
}

// overlapsWildcardIPs reports whether ANY address of the record set belongs to
// a wildcard answer pool applicable to this name. The "any" rule mirrors
// rotating-pool behavior: one old-pool IP plus one unfamiliar IP is still a
// wildcard answer, so the whole RRset is treated as wildcard.
func (p *wildcardProfile) overlapsWildcardIPs(name string, ips []string) bool {
	if len(ips) == 0 {
		return false
	}
	for _, zone := range p.zonesFor(name) {
		if len(zone.ips) == 0 {
			continue
		}
		for _, ip := range ips {
			if zone.ips[ip] {
				return true
			}
		}
	}
	return false
}

// firstNonWildcardIP returns the first address of the record set unless the
// set overlaps a wildcard pool applicable to the name, in which case it
// returns "" (the entire RRset is rejected, matching the pre-branch behavior).
func (p *wildcardProfile) firstNonWildcardIP(name string, ips []string) string {
	if p == nil {
		for _, ip := range ips {
			return ip
		}
		return ""
	}
	if p.overlapsWildcardIPs(name, ips) {
		return ""
	}
	for _, ip := range ips {
		return ip
	}
	return ""
}

// isWildcardCNAME reports whether a candidate's CNAME target matches a
// wildcard answer pool applicable to the name.
func (p *wildcardProfile) isWildcardCNAME(name, cname string) bool {
	if cname == "" {
		return false
	}
	cname = normalizeSubdomainName(cname)
	for _, zone := range p.zonesFor(name) {
		if zone.cnames[cname] {
			return true
		}
	}
	return false
}

// apexWildcard reports whether the APEX zone alone is a wildcard. Only an apex
// wildcard makes active brute-force meaningless; a branch wildcard still
// leaves the rest of the zone worth enumerating (branch hits are filtered
// per-name by the admission gate).
func (p *wildcardProfile) apexWildcard() bool {
	return p != nil && p.apex.hasEvidence()
}

// hasAnyWildcard reports whether ANY zone carries evidence (used for the
// operator-facing warning line).
func (p *wildcardProfile) hasAnyWildcard() bool {
	if p == nil {
		return false
	}
	if p.apex.hasEvidence() {
		return true
	}
	for _, z := range p.branches {
		if z.hasEvidence() {
			return true
		}
	}
	return false
}

// singleServerResolver builds a resolver pinned to ONE upstream server so a
// retry genuinely asks a DIFFERENT resolver — buildDNSResolver rotates per
// connection, which is usually enough, but an explicit pin gives the retry
// loop a guarantee.
func singleServerResolver(server string) *net.Resolver {
	res := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 4 * time.Second}
			return d.DialContext(ctx, network, server)
		},
	}
	return res
}

// resolveProbeWithRetry resolves one probe name, retrying ambiguous answers
// (SERVFAIL/timeout/refused) on DIFFERENT upstream resolvers. A definitive
// NXDOMAIN (dnsErr.IsNotFound) is recorded and, once seen, a later attempt
// that succeeds still wins — a resolver badly configured for the zone must not
// mask an existing name.
func resolveProbeWithRetry(r *net.Resolver, name string, servers []string, startOffset int) ([]net.IPAddr, probeVerdict) {
	attempts := len(servers)
	if attempts == 0 {
		attempts = 1 // system resolver only; r carries it
	}
	if attempts > 3 {
		attempts = 3
	}
	var sawNX, sawAmbiguous bool
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			// Small backoff between attempts: a rate-limited resolver answered
			// the first query instantly, so give its budget a beat to recover.
			time.Sleep(time.Duration(attempt) * 150 * time.Millisecond)
		}
		var res *net.Resolver
		if attempt == 0 {
			// First attempt uses the shared resolver (exactly the resolver the
			// candidate admission gate re-checks against), then explicitly
			// pinned servers for retries.
			res = r
		} else {
			idx := (startOffset + attempt) % len(servers)
			res = singleServerResolver(servers[idx])
		}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		result, err := res.LookupIPAddr(ctx, name)
		cancel()
		if err == nil {
			return result, probeResolved
		}
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			sawNX = true
			continue
		}
		sawAmbiguous = true
	}
	switch {
	case sawNX && !sawAmbiguous:
		return nil, probeNX
	case sawNX && sawAmbiguous:
		// One resolver says "no such name", another errored. The disagreement
		// is exactly what extra probes are for; count it ambiguous so the
		// caller runs a second batch instead of trusting either answer.
		return nil, probeAmbiguous
	default:
		return nil, probeAmbiguous
	}
}

type wildcardProbe struct {
	name    string
	ips     []net.IPAddr
	cname   string
	verdict probeVerdict
}

// runWildcardProbes probes every name concurrently and returns the verdicts.
// CNAME lookups run only for names that were not definitively NXDOMAIN —
// LookupCNAME on an NXDOMAIN just burns its 3s timeout for nothing.
func runWildcardProbes(names []string, r *net.Resolver, servers []string) []wildcardProbe {
	results := make([]wildcardProbe, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			ips, verdict := resolveProbeWithRetry(r, name, servers, i)
			probe := wildcardProbe{name: name, ips: ips, verdict: verdict}
			if verdict != probeNX {
				probe.cname = lookupExplicitCNAME(context.Background(), name, r)
			}
			results[i] = probe
		}(i, name)
	}
	wg.Wait()
	return results
}

// summarizeWildcardProbes aggregates probe verdicts into the counts and answer
// pools the wildcard decision needs.
func summarizeWildcardProbes(probes []wildcardProbe) (resolved, nxDomain, ambiguous int, allIPs map[string]bool, cnameCounts map[string]int) {
	allIPs = map[string]bool{}
	cnameCounts = map[string]int{}
	for _, probe := range probes {
		switch probe.verdict {
		case probeResolved:
			resolved++
		case probeNX:
			nxDomain++
		default:
			ambiguous++
		}
		for _, ip := range probe.ips {
			if value := ip.IP.String(); value != "" {
				allIPs[value] = true
			}
		}
		if probe.cname != "" {
			cnameCounts[probe.cname]++
		}
	}
	return resolved, nxDomain, ambiguous, allIPs, cnameCounts
}

// decideWildcardZone turns probe aggregates into a zone. The bool reports
// whether the batch was inconclusive (neither side reached agreement) and a
// second batch should run. IP/CNAME pools stored in the zone are the union of
// all answers seen, guarded by the agreement threshold.
func decideWildcardZone(resolved, nxDomain int, allIPs map[string]bool, cnameCounts map[string]int, suffix string) (wildcardZone, bool) {
	zone := wildcardZone{suffix: suffix, ips: map[string]bool{}, cnames: map[string]bool{}}
	if resolved >= wildcardProbeMinAgreement {
		// At least three independent random labels resolved: everything they
		// answered is part of the wildcard's answer pool. Union all addresses
		// so rotating CDN pools are captured even when no single IP repeats.
		for ip := range allIPs {
			zone.ips[ip] = true
		}
		for cname, n := range cnameCounts {
			if n >= wildcardProbeMinAgreement {
				zone.cnames[cname] = true
			}
		}
		return zone, false
	}
	if nxDomain >= wildcardProbeMinAgreement {
		// At least three labels are definitively nonexistent: this suffix is
		// NOT a wildcard. An empty zone keeps the old "no evidence" behavior
		// but now with proof, and the caller skips the second batch.
		return zone, false
	}
	return zone, true
}

// randomProbeLabel returns a hex label from crypto/rand. Probe labels are not
// security tokens, but they must be unpredictable per scan (a cached wildcard
// answer for a guessed label would poison the verdict), which crypto/rand
// guarantees for free.
func randomProbeLabel() string {
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("rcnfallback%d", time.Now().UnixNano()&0xffff)
	}
	return hex.EncodeToString(buf)
}

// probeWildcardZone runs the five fixed probes (plus a second random batch
// when the first is inconclusive) for one DNS suffix and returns the zone.
// fullSuffix is the target domain for the apex zone, or a deeper suffix (e.g.
// "git.example.com") for a branch zone. Zone.suffix stays "" for the apex so
// zonesFor matches it unconditionally.
func probeWildcardZone(fullSuffix, zoneSuffix string, r *net.Resolver, servers []string, logFn LogFunc) wildcardZone {
	apex := zoneSuffix == ""
	probes := runWildcardProbes(functionProbeNames(fixedWildcardProbeStems, fullSuffix), r, servers)
	resolved, nxDomain, ambiguous, allIPs, cnameCounts := summarizeWildcardProbes(probes)

	zone, needsMore := decideWildcardZone(resolved, nxDomain, allIPs, cnameCounts, zoneSuffix)
	if !needsMore {
		if ambiguous > 0 && logFn != nil {
			logFn("info", "subdomain_enum", fmt.Sprintf(
				"Wildcard probes under %s settled: %d resolved, %d NXDOMAIN, %d errored — verdict reached anyway",
				fullSuffix, resolved, nxDomain, ambiguous))
		}
		return zone
	}

	// Inconclusive: sample five fresh labels. If the resolver was rate-limiting
	// or a CDN node was flaky, the new batch answers through the same retry
	// logic with a fresh transaction budget.
	if logFn != nil {
		logFn("info", "subdomain_enum", fmt.Sprintf(
			"Wildcard probes under %s inconclusive (%d resolved, %d NXDOMAIN, %d errored) — probing a second batch",
			fullSuffix, resolved, nxDomain, ambiguous))
	}
	second := make([]string, 0, len(fixedWildcardProbeStems))
	for range fixedWildcardProbeStems {
		second = append(second, randomProbeLabel()+"."+fullSuffix)
	}
	probes = append(probes, runWildcardProbes(second, r, servers)...)
	resolved, nxDomain, ambiguous, allIPs, cnameCounts = summarizeWildcardProbes(probes)
	zone, _ = decideWildcardZone(resolved, nxDomain, allIPs, cnameCounts, zoneSuffix)
	if !zone.hasEvidence() && logFn != nil && apex {
		logFn("info", "subdomain_enum", fmt.Sprintf(
			"Wildcard probes under %s inconclusive after both batches (%d resolved, %d NXDOMAIN, %d errored) — treating as non-wildcard",
			fullSuffix, resolved, nxDomain, ambiguous))
	}
	return zone
}

// functionProbeNames joins probe stems with a DNS suffix.
func functionProbeNames(stems []string, suffix string) []string {
	names := make([]string, len(stems))
	for i, stem := range stems {
		names[i] = stem + "." + suffix
	}
	return names
}

// Branch wildcard detection (the *.git.example.com case).
//
// A wildcard can live at ANY depth, not only at the apex. Junk fleets cluster:
// hundreds of candidates share "git." as their second label. Group the
// candidate list by intermediate suffix and probe the clusters that are large
// enough to smell like wildcard junk, but small enough to bound the DNS
// traffic.

const (
	branchMinCandidates = 5 // junk fleets are large; 5 clustered labels justify up to ~15 DNS queries
	branchMaxProbes     = 8 // hard cap of branch probes per detection call
	branchMaxDepth      = 3 // examine candidate suffixes formed by dropping up to 3 leading labels
)

// candidateBranchSuffixCounts counts candidates per intermediate suffix. A
// suffix qualifies structurally when it is strictly deeper than the apex
// (matched on label boundaries) — "com.au" alone is never probed.
func candidateBranchSuffixCounts(candidates []string, apex string) map[string]int {
	apex = normalizeSubdomainName(apex)
	apexLabels := strings.Split(apex, ".")
	counts := map[string]int{}
	for _, cand := range candidates {
		name := normalizeSubdomainName(cand)
		if name == "" || !strings.HasSuffix(name, "."+apex) {
			continue
		}
		for drop := 1; drop <= branchMaxDepth; drop++ {
			labels := strings.Split(name, ".")
			if len(labels)-drop <= len(apexLabels) {
				break
			}
			suffix := strings.Join(labels[drop:], ".")
			counts[suffix]++
		}
	}
	return counts
}

// detectBranchWildcards probes the largest clustered candidate suffixes and
// returns the confirmed branch wildcard zones (never nil; empty when nothing
// was probed or confirmed). maxBranches bounds the DNS traffic per call — the
// apex scan uses the full budget, recursion levels a smaller one.
func detectBranchWildcards(ctx context.Context, apex string, candidates []string, r *net.Resolver, servers []string, maxBranches int, logFn LogFunc) []wildcardZone {
	if maxBranches <= 0 {
		maxBranches = branchMaxProbes
	}
	counts := candidateBranchSuffixCounts(candidates, apex)

	type branchCandidate struct {
		suffix string
		count  int
	}
	sorted := make([]branchCandidate, 0, len(counts))
	for suffix, count := range counts {
		if count >= branchMinCandidates {
			sorted = append(sorted, branchCandidate{suffix: suffix, count: count})
		}
	}
	if len(sorted) == 0 {
		return nil
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].count != sorted[j].count {
			return sorted[i].count > sorted[j].count
		}
		return sorted[i].suffix < sorted[j].suffix
	})
	if len(sorted) > maxBranches {
		sorted = sorted[:maxBranches]
	}

	var confirmed []wildcardZone
	probed := 0
	for _, bc := range sorted {
		if ctx.Err() != nil {
			break
		}
		probed++
		zone := probeWildcardZone(bc.suffix, bc.suffix, r, servers, logFn)
		if zone.hasEvidence() {
			confirmed = append(confirmed, zone)
		}
	}
	if probed > 0 && logFn != nil {
		logFn("info", "subdomain_enum", fmt.Sprintf(
			"Branch wildcard probes: %d clustered suffix(es) probed, %d confirmed as wildcards (candidates clustered e.g. *.git.%s)",
			probed, len(confirmed), apex))
		for _, zone := range confirmed {
			logFn("warn", "subdomain_enum", fmt.Sprintf(
				"Wildcard branch confirmed: *.%s (%d answer IP(s), %d CNAME target(s)) — names under it need DNS proof",
				zone.suffix, len(zone.ips), len(zone.cnames)))
		}
	}
	return confirmed
}

// detectWildcard builds the full wildcard profile for a scan: the apex zone
// (probes under the target domain) with branch zones filled in separately by
// detectBranchWildcards once the candidate list is known.
func detectWildcard(domain string, r *net.Resolver, servers []string, logFn LogFunc) *wildcardProfile {
	profile := &wildcardProfile{
		apex: probeWildcardZone(domain, "", r, servers, logFn),
	}
	if profile.apex.hasEvidence() {
		logFn("warn", "subdomain_enum", fmt.Sprintf(
			"Wildcard DNS detected (%d answer IP(s), %d CNAME target(s)) — passive results will be verified by resolution",
			len(profile.apex.ips), len(profile.apex.cnames)))
	}
	return profile
}

// detectBranches fills a profile with branch zones probed from the candidate
// list. It mutates the profile in place so the caller keeps one reference.
func (p *wildcardProfile) detectBranches(ctx context.Context, apex string, candidates []string, r *net.Resolver, servers []string, maxBranches int, logFn LogFunc) {
	if p == nil || len(candidates) == 0 {
		return
	}
	p.branches = detectBranchWildcards(ctx, apex, candidates, r, servers, maxBranches, logFn)
}
