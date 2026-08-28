package scheduler

import "sort"

// ─────────────────────────────────────────────────────────────────────────────
// Capability planner — turns a user's vulnerability SELECTION into a complete,
// executable pipeline.
//
// The scanner's modules fall into two kinds:
//
//   • CAPABILITIES — reconnaissance/enabling steps that populate the shared
//     state every detector reads (subdomains → http_services → parameters/js).
//     They are NOT vulnerability objectives; a user does not "want" param
//     discovery, they want the SQLi it enables.
//
//   • DETECTORS — the user-facing vulnerability objectives (sqli, xss/dast,
//     ssrf, …). Each one consumes capabilities and emits findings of its class.
//
// Historically the scheduler ran the selected module list verbatim, so choosing
// only a detector (e.g. "sqli") ran that detector against EMPTY input tables —
// no recon had populated them. PlanModules fixes this at the selection boundary:
// it expands a selection to
//
//     detectors ∪ requiredCapabilities(detectors) ∪ {verify}
//
// adding ONLY capabilities — never another detector — so a single-vulnerability
// scan automatically performs exactly the recon it needs and nothing unrelated.
// Ordering follows the canonical recon→injection→verify sequence so the
// scheduler's data dependencies (parameters populated before injection) hold.
// ─────────────────────────────────────────────────────────────────────────────

// capabilitySet is the set of PURE enabling steps: modules that populate shared
// state (subdomains → http_services → parameters/JS) or post-process findings,
// and that emit no vulnerability findings of their own. It is disjoint from the
// detector set (moduleRequires keys). No vulnerability DETECTOR is a member here,
// and — after the OAST/Open-Redirect decoupling — no detector is used as another
// detector's prerequisite either: every moduleRequires value is one of these.
var capabilitySet = map[string]bool{
	ModuleSubdomainEnum:   true,
	ModuleHTTPProbe:       true,
	ModuleJSAnalysis:      true,
	ModuleJSEndpoints:     true,
	ModuleParamDiscovery:  true,
	ModuleHeadlessCrawl:   true, // browser-rendered SPA surface → parameters (heavy; opt-in)
	ModuleTimeMachine:     true,
	ModuleParamReflection: true,
	ModuleParamFuzz:       true,
	ModuleVerify:          true, // post-processing re-confirmation of findings
}

// Capability bundles, expressed in terms of the state they populate.
//
//	coreWeb  → http_services (probe the target host directly; the scheduler seeds
//	           the operator-supplied host(s) so NO subdomain enumeration is needed
//	           or auto-run — a focused scan stays confined to the given target).
//	           subdomain_enum is NEVER auto-added by any objective (takeover
//	           included): it runs only when the operator explicitly ticks it.
//	params   → coreWeb + everything that fills the `parameters` table and the
//	           JS/API endpoint surface, maximising candidate coverage for any
//	           parameter/endpoint-driven detector.
var capCoreWeb = []string{ModuleHTTPProbe}

// capParams is the LEAN input-mining closure auto-run for a single vulnerability
// objective. It deliberately EXCLUDES the two slowest recon modules —
// timemachine (Wayback/gau/waymore historical mining, minutes of external calls)
// and paramfuzz (Arjun-style hidden-parameter brute force, hundreds of active
// requests) — so a focused scan (e.g. "just XSS") stays fast. Those heavy modules
// still run in a full scan (they remain in AllModules); they are opt-in coverage,
// not a prerequisite for the objective to work. What remains — subdomain →
// http_probe → JS analysis/endpoints → crawl-based param_discovery →
// param_reflection — is the essential attack surface every param detector needs.
var capParams = []string{
	ModuleHTTPProbe,
	ModuleJSAnalysis, ModuleJSEndpoints,
	ModuleParamDiscovery, ModuleParamReflection,
}

// moduleRequires maps each DETECTOR to the capabilities it needs to run against a
// fresh target. Derived from each detector's Run() input query (which shared
// table it reads): parameter/endpoint-driven detectors need the full params
// bundle; http_services-only detectors need just coreWeb; takeover needs only
// subdomain enumeration.
//
// IMPORTANT — every value here is a pure CAPABILITY, never another vulnerability
// DETECTOR. Earlier revisions had ssrf/xxe/cmdi depend on the OAST module and ato
// depend on the Open Redirect module; both broke single-objective isolation
// (OAST plants SQLi/SSTI/Log4Shell probes; the Open Redirect module emits
// open_redirect findings). Those detectors now own the primitive internally:
//   - blind SSRF/RCE/XXE confirmation lives in the SSRF/CMDi/XXE detectors via the
//     shared oobCapability (scanner.oob_capability.go),
//   - ATO runs redirect analysis internally via checkOpenRedirectURL,
//
// so their closures reference the params bundle only.
var moduleRequires = map[string][]string{
	// parameter / endpoint driven
	ModuleSQLi:         capParams,
	ModuleNoSQLi:       capParams,
	ModuleLFI:          capParams,
	ModuleSSTI:         capParams,
	ModuleDAST:         capParams,
	ModuleXSS:          capParams, // standalone reflected-XSS objective
	ModuleVulnScan:     capParams,
	ModuleIDOR:         capParams,
	ModuleJWT:          capParams,
	ModuleOpenRedirect: capParams,
	ModuleRace:         capParams,
	ModuleAuthz:        capParams,
	ModuleATO:          capParams, // redirect analysis is internal (checkOpenRedirectURL)
	// blind classes own their OOB confirmation internally (shared oobCapability),
	// so they need only the params bundle — NOT a multi-class OAST detector module.
	ModuleSSRF: capParams,
	ModuleXXE:  capParams,
	ModuleCmdi: capParams,
	ModuleOAST: capParams,
	// http_services-only (probe live hosts; no parameter mining needed)
	ModuleCORS:            capCoreWeb,
	ModuleCachePoison:     capCoreWeb,
	ModuleExposure:        capCoreWeb,
	ModuleIntel:           capCoreWeb,
	ModulePassive:         capCoreWeb,
	ModuleCSRF:            capCoreWeb,
	ModuleSmuggling:       capCoreWeb,
	ModuleNuclei:          capCoreWeb,
	ModuleOriginIP:        capCoreWeb,
	ModuleShodan:          capCoreWeb,
	ModuleDirDiscovery:    capCoreWeb, // content discovery probes paths on live hosts
	ModuleBackupDiscovery: capCoreWeb, // backup/config-leak probes on live hosts
	// broken-link hijacking scans DISCOVERED pages' outbound links, so it wants the
	// full crawl surface (deep pages are where dead external links hide), not just
	// the host roots.
	ModuleBLH: capParams,
	// change monitor re-probes hosts AND re-analyses JS to diff against the baseline
	ModuleMonitor: {ModuleHTTPProbe, ModuleJSAnalysis},
	// subdomain takeover hunts dangling CNAMEs over the subdomains ALREADY known for
	// the target (the seeded host(s) plus anything a prior/explicit enumeration
	// discovered). It does NOT auto-run subdomain_enum: the operator's rule is
	// absolute — subdomain enumeration runs ONLY when subdomain_enum is explicitly
	// ticked, never as a side effect of selecting another objective (this used to
	// fire on "select all", which includes takeover, and enumerate unexpectedly).
	// To takeover across freshly-discovered subdomains, tick subdomain_enum too.
	ModuleTakeover: capCoreWeb,
}

// passthroughModule reports whether a token must be preserved verbatim and never
// trigger web-capability planning: the per-scan speed tokens and the entire
// network pipeline (which has its own dependency chain in executeTask).
func passthroughModule(m string) bool {
	switch m {
	case "speed_slow", "speed_normal", "speed_fast",
		"nuclei_only", "bruteforce", "ingram", "initial_access", "full_ports":
		return true
	}
	if len(m) >= 7 && m[:7] == "network" {
		return true
	}
	return m == ModuleNetworkNucleiOnly || m == ModuleNetworkIngram ||
		m == ModuleNetworkInitialAccess || m == ModuleNetworkBrute
}

// canonicalOrder gives each module its position in the reference recon→injection
// →verify pipeline (AllModules), so a planned set can be sorted back into a
// dependency-correct order regardless of the order the user clicked things.
var canonicalOrder = func() map[string]int {
	m := make(map[string]int, len(AllModules))
	for i, mod := range AllModules {
		m[mod] = i
	}
	return m
}()

// PlanModules expands a raw module selection into a complete, dependency-ordered
// pipeline: every selected detector plus the capabilities required to feed it,
// plus a final verification pass — and NOTHING ELSE. If the selection contains no
// plan-aware detector (e.g. capabilities only, or a purely network scan), it is
// returned unchanged. The planner is purely additive over CAPABILITIES: it never
// introduces a detector the user did not select, which is what preserves
// single-vulnerability isolation.
func PlanModules(selected []string) []string {
	if len(selected) == 0 {
		return selected
	}

	inSel := make(map[string]bool, len(selected))
	var passthrough []string
	sawDetector := false
	for _, m := range selected {
		if passthroughModule(m) {
			passthrough = append(passthrough, m)
			continue
		}
		inSel[m] = true
		if _, isDetector := moduleRequires[m]; isDetector {
			sawDetector = true
		}
	}

	// No detector to plan for (capabilities-only or network-only selection) →
	// respect the operator's explicit choice untouched.
	if !sawDetector {
		return selected
	}

	planned := make(map[string]bool)
	for m := range inSel {
		planned[m] = true // keep everything the user picked (detectors + any caps)
	}
	for m := range inSel {
		for _, cap := range moduleRequires[m] { // add required capabilities only
			planned[cap] = true
		}
	}
	planned[ModuleVerify] = true // always re-confirm what the detectors produced

	out := make([]string, 0, len(planned))
	for m := range planned {
		out = append(out, m)
	}
	sort.SliceStable(out, func(i, j int) bool {
		oi, iok := canonicalOrder[out[i]]
		oj, jok := canonicalOrder[out[j]]
		if iok && jok {
			return oi < oj
		}
		if iok != jok {
			return iok // known-ordered modules first, unknown ones trail
		}
		return out[i] < out[j]
	})
	// Preserve any passthrough tokens (speed/network) after the web plan.
	return append(out, passthrough...)
}
