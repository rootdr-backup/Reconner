package scheduler

import (
	"testing"

	"github.com/recon-platform/internal/models"
)

func has(mods []string, m string) bool {
	for _, x := range mods {
		if x == m {
			return true
		}
	}
	return false
}

// The set of every DETECTOR module — used to prove single-vulnerability isolation
// (no OTHER detector is ever auto-added by the planner).
func allDetectors() []string {
	out := make([]string, 0, len(moduleRequires))
	for d := range moduleRequires {
		out = append(out, d)
	}
	return out
}

// TestPlanSingleVulnerabilityExpandsPipeline: selecting exactly one detector must
// pull in the reconnaissance capabilities that feed it, plus verify, and must NOT
// introduce any OTHER detector.
func TestPlanSingleVulnerabilityExpandsPipeline(t *testing.T) {
	// detector → capabilities that MUST appear once it is selected alone.
	wantCaps := map[string][]string{
		ModuleSQLi:         {ModuleHTTPProbe, ModuleParamDiscovery, ModuleParamReflection},
		ModuleSSRF:         {ModuleHTTPProbe, ModuleParamDiscovery, ModuleJSAnalysis, ModuleJSEndpoints},
		ModuleXSS:          {ModuleHTTPProbe, ModuleParamDiscovery, ModuleParamReflection},
		ModuleDAST:         {ModuleHTTPProbe, ModuleParamDiscovery},
		ModuleLFI:          {ModuleHTTPProbe, ModuleParamDiscovery},
		ModuleSSTI:         {ModuleHTTPProbe, ModuleParamDiscovery},
		ModuleNoSQLi:       {ModuleHTTPProbe, ModuleParamDiscovery},
		ModuleXXE:          {ModuleHTTPProbe, ModuleParamDiscovery},
		ModuleCmdi:         {ModuleHTTPProbe, ModuleParamDiscovery},
		ModuleOpenRedirect: {ModuleHTTPProbe, ModuleParamDiscovery},
		ModuleIDOR:         {ModuleHTTPProbe, ModuleParamDiscovery},
		ModuleJWT:          {ModuleHTTPProbe, ModuleParamDiscovery},
		ModuleCORS:         {ModuleHTTPProbe},
		ModuleCachePoison:  {ModuleHTTPProbe},
		// takeover no longer auto-runs subdomain_enum; it works over already-known
		// subdomains and needs only live-host probing.
		ModuleTakeover: {ModuleHTTPProbe},
	}

	for det, caps := range wantCaps {
		plan := PlanModules([]string{det})

		// 1) the objective detector itself is present.
		if !has(plan, det) {
			t.Errorf("[%s alone] plan is missing the selected detector; got %v", det, plan)
		}
		// 2) all its required capabilities are present.
		for _, c := range caps {
			if !has(plan, c) {
				t.Errorf("[%s alone] plan missing required capability %q; got %v", det, c, plan)
			}
		}
		// 3) verify runs to re-confirm findings.
		if !has(plan, ModuleVerify) {
			t.Errorf("[%s alone] plan missing verify; got %v", det, plan)
		}
		// 4) NEGATIVE ISOLATION: no OTHER detector was pulled in.
		for _, other := range allDetectors() {
			if other == det {
				continue
			}
			// Guard for the general case: if a detector ever legitimately lists
			// another as a prerequisite, that is allowed. After the OAST/Open-Redirect
			// decoupling no such edge remains, so this simply enforces pure isolation.
			allowed := false
			for _, req := range moduleRequires[det] {
				if req == other {
					allowed = true
					break
				}
			}
			if allowed {
				continue
			}
			if has(plan, other) {
				t.Errorf("[%s alone] ISOLATION VIOLATION: unrelated detector %q was planned; got %v", det, other, plan)
			}
		}
	}
}

// TestPlanReconBeforeInjection: capabilities must be ordered before the detector
// so the scheduler's data dependencies (parameters populated first) hold.
func TestPlanReconBeforeInjection(t *testing.T) {
	plan := PlanModules([]string{ModuleSQLi})
	idx := func(m string) int {
		for i, x := range plan {
			if x == m {
				return i
			}
		}
		return -1
	}
	if idx(ModuleHTTPProbe) < 0 || idx(ModuleParamDiscovery) < 0 || idx(ModuleSQLi) < 0 {
		t.Fatalf("plan incomplete: %v", plan)
	}
	// subdomain_enum is NOT auto-planned (the scheduler seeds the target host), so
	// recon starts at http_probe; the dependency order is http_probe → params →
	// injection → verify.
	if has(plan, ModuleSubdomainEnum) {
		t.Errorf("subdomain_enum must NOT be auto-added for a focused SQLi scan: %v", plan)
	}
	if !(idx(ModuleHTTPProbe) < idx(ModuleParamDiscovery) &&
		idx(ModuleParamDiscovery) < idx(ModuleSQLi)) {
		t.Errorf("recon must precede injection: order was %v", plan)
	}
	if idx(ModuleVerify) < idx(ModuleSQLi) {
		t.Errorf("verify must run after the detector: %v", plan)
	}
}

// TestPlanMultiSelectUnion: selecting two detectors merges their capability
// graphs without duplication and without adding a third detector.
func TestPlanMultiSelectUnion(t *testing.T) {
	plan := PlanModules([]string{ModuleSQLi, ModuleSSRF})
	for _, m := range []string{ModuleSQLi, ModuleSSRF, ModuleParamDiscovery, ModuleHTTPProbe, ModuleVerify} {
		if !has(plan, m) {
			t.Errorf("union plan missing %q; got %v", m, plan)
		}
	}
	// no duplicates
	seen := map[string]bool{}
	for _, m := range plan {
		if seen[m] {
			t.Errorf("duplicate module %q in plan %v", m, plan)
		}
		seen[m] = true
	}
	// no unrelated detector, AND specifically NOT the multi-class OAST module
	// (ssrf owns its blind confirmation internally now).
	for _, other := range []string{ModuleCORS, ModuleJWT, ModuleIDOR, ModuleLFI, ModuleOAST} {
		if has(plan, other) {
			t.Errorf("sqli+ssrf must not pull in %q; got %v", other, plan)
		}
	}
}

// TestPlanCapabilitiesOnlyUntouched: a selection with no detector is respected
// verbatim (the operator explicitly wants just recon).
func TestPlanCapabilitiesOnlyUntouched(t *testing.T) {
	in := []string{ModuleHTTPProbe, ModuleParamDiscovery}
	plan := PlanModules(in)
	if len(plan) != len(in) {
		t.Errorf("capabilities-only selection must be untouched; in=%v out=%v", in, plan)
	}
	if has(plan, ModuleVerify) {
		t.Errorf("no detector selected → verify must NOT be force-added; got %v", plan)
	}
}

// TestPlanNetworkPassthrough: network pipeline tokens are preserved and never
// trigger web-capability planning.
func TestPlanNetworkPassthrough(t *testing.T) {
	in := []string{ModuleNetwork, "bruteforce", "ingram"}
	plan := PlanModules(in)
	for _, m := range in {
		if !has(plan, m) {
			t.Errorf("network token %q must be preserved; got %v", m, plan)
		}
	}
	// no web capability injected for a pure-network scan
	if has(plan, ModuleParamDiscovery) || has(plan, ModuleHTTPProbe) {
		t.Errorf("network-only scan must not gain web recon; got %v", plan)
	}
}

// TestPlanFullSelectionStable: expanding the full AllModules set adds nothing new
// (it already contains every capability) and keeps every module.
// TestPlanManyDetectorsNoSubdomainEnum reproduces the operator's report: selecting
// a big batch of injection/analysis scanners (but NOT subdomain_enum and NOT
// takeover) must never enumerate subdomains — the scan stays on the seeded host.
func TestPlanManyDetectorsNoSubdomainEnum(t *testing.T) {
	sel := []string{
		ModuleXSS, ModuleSQLi, ModuleSSRF, ModuleLFI, ModuleSSTI, ModuleXXE,
		ModuleCmdi, ModuleIDOR, ModuleJWT, ModuleOpenRedirect, ModuleNuclei,
		ModuleExposure, ModuleIntel, ModulePassive, ModuleCachePoison, ModuleOAST,
	}
	plan := PlanModules(sel)
	if has(plan, ModuleSubdomainEnum) {
		t.Fatalf("selecting many detectors (no subdomain_enum, no takeover) must NOT enumerate subdomains: %v", plan)
	}
	// but the capabilities the detectors truly need are present
	if !has(plan, ModuleHTTPProbe) || !has(plan, ModuleParamDiscovery) || !has(plan, ModuleVerify) {
		t.Fatalf("required capabilities missing from plan: %v", plan)
	}
}

// TestPlanTakeoverDoesNotEnumerate: the operator's rule is absolute — no objective
// may auto-run subdomain_enum. Takeover included: selecting takeover alone hunts
// dangling CNAMEs over already-known subdomains and must NOT enumerate.
func TestPlanTakeoverDoesNotEnumerate(t *testing.T) {
	plan := PlanModules([]string{ModuleTakeover})
	if has(plan, ModuleSubdomainEnum) {
		t.Fatalf("takeover must NOT auto-run subdomain_enum (operator rule): %v", plan)
	}
	if !has(plan, ModuleTakeover) || !has(plan, ModuleHTTPProbe) {
		t.Fatalf("takeover plan must still include takeover + http_probe: %v", plan)
	}
}

// TestPlanSelectAllExceptSubdomainEnum is the EXACT operator scenario: the UI's
// "select all" with subdomain_enum unticked. That set includes takeover; before the
// fix takeover pulled subdomain_enum and the scan enumerated anyway. It must not.
func TestPlanSelectAllExceptSubdomainEnum(t *testing.T) {
	var sel []string
	for _, m := range AllModules {
		if m == ModuleSubdomainEnum {
			continue // the operator deliberately left this unticked
		}
		sel = append(sel, m)
	}
	plan := PlanModules(sel)
	if has(plan, ModuleSubdomainEnum) {
		t.Fatalf("select-all-except-subdomain_enum must NOT enumerate subdomains: %v", plan)
	}
	// everything else the operator DID tick is preserved.
	for _, m := range sel {
		if !has(plan, m) {
			t.Errorf("plan dropped a selected module %q: %v", m, plan)
		}
	}
}

func TestPlanFullSelectionStable(t *testing.T) {
	plan := PlanModules(AllModules)
	for _, m := range AllModules {
		if !has(plan, m) {
			t.Errorf("full-scan expansion dropped %q", m)
		}
	}
}

// TestPlanSpeedTokenPreserved: a single-detector scan with a speed token keeps
// the token and still expands the pipeline.
func TestPlanSpeedTokenPreserved(t *testing.T) {
	plan := PlanModules([]string{ModuleXSSDetectorAlias(), "speed_fast"})
	if !has(plan, "speed_fast") {
		t.Errorf("speed token dropped: %v", plan)
	}
	if !has(plan, ModuleParamDiscovery) {
		t.Errorf("detector+speed selection must still expand recon: %v", plan)
	}
}

// ModuleXSSDetectorAlias returns the module that represents reflected-XSS
// detection in this build (the standalone XSS objective), so the test reads
// intention-first.
func ModuleXSSDetectorAlias() string { return ModuleXSS }

// sanity: the capability and detector sets must be disjoint (a module is either
// an enabling step or an objective, never both) — the core architectural split.
func TestCapabilityDetectorDisjoint(t *testing.T) {
	for m := range moduleRequires {
		if capabilitySet[m] {
			t.Errorf("module %q is classified as BOTH a detector and a capability", m)
		}
	}
	// every capability referenced by a requires-bundle must be a known capability
	// (or a detector legitimately used as a prerequisite, e.g. open_redirect/oast).
	for det, reqs := range moduleRequires {
		for _, r := range reqs {
			if !capabilitySet[r] {
				if _, isDet := moduleRequires[r]; !isDet {
					t.Errorf("requires[%s] references unknown module %q", det, r)
				}
			}
		}
	}
}

// ── Scheduler-level integration: the planner is wired into task creation ─────
//
// Proves the guarantee end-to-end at the SELECTION boundary, from the STORED task
// (not logs): creating a scan with only "sqli" selected persists a task whose
// module list is the full SQLi pipeline (recon capabilities + sqli + verify) and
// contains NO unrelated detector.
func TestCreateTaskExpandsSingleVulnPipeline(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets (id, domain) VALUES ('t1','example.com')`); err != nil {
		t.Fatalf("insert target: %v", err)
	}

	task, err := s.CreateTask("t1", []string{ModuleSQLi}, 1)
	if err != nil {
		t.Fatalf("create task: %v", err)
	}

	// Read the STORED module list back from the DB (authoritative, not the log).
	var modulesJSON, typ string
	if err := s.db.QueryRow(`SELECT modules, type FROM tasks WHERE id=?`, task.ID).Scan(&modulesJSON, &typ); err != nil {
		t.Fatalf("read task: %v", err)
	}
	stored := models.JSONToStringSlice(modulesJSON)

	// The scan is still LABELLED by the objective the user picked.
	if typ != ModuleSQLi {
		t.Errorf("task type must remain the chosen objective %q, got %q", ModuleSQLi, typ)
	}
	// Required recon capabilities + the detector + verify are all present.
	for _, m := range []string{ModuleHTTPProbe, ModuleParamDiscovery, ModuleParamReflection, ModuleSQLi, ModuleVerify} {
		if !has(stored, m) {
			t.Errorf("stored SQLi-only scan is missing %q; got %v", m, stored)
		}
	}
	// NEGATIVE ISOLATION from stored state: no unrelated detector was scheduled.
	for _, other := range []string{ModuleSSRF, ModuleCORS, ModuleJWT, ModuleIDOR, ModuleLFI, ModuleSSTI, ModuleXXE, ModuleNoSQLi, ModuleCmdi, ModuleCachePoison} {
		if has(stored, other) {
			t.Errorf("SQLi-only scan must not schedule unrelated detector %q; got %v", other, stored)
		}
	}
}

// TestCreateTaskIsolatesBlindAndChainDetectors proves, from the STORED task, that
// the two decoupled objectives no longer schedule a multi-vulnerability module:
//   - SSRF/XXE/CMDi must NOT schedule the OAST module (they own blind confirmation
//     internally), and must not schedule each other or any other detector.
//   - ATO must NOT schedule the Open Redirect module (it runs redirect analysis
//     internally), and must not schedule any other detector.
func TestCreateTaskIsolatesBlindAndChainDetectors(t *testing.T) {
	// objective → detectors that must be ABSENT from the planned+stored task.
	forbidden := map[string][]string{
		ModuleSSRF: {ModuleOAST, ModuleXXE, ModuleCmdi, ModuleSQLi, ModuleDAST, ModuleLFI, ModuleSSTI, ModuleNoSQLi, ModuleCORS, ModuleJWT, ModuleIDOR, ModuleOpenRedirect},
		ModuleXXE:  {ModuleOAST, ModuleSSRF, ModuleCmdi, ModuleSQLi, ModuleDAST, ModuleCORS, ModuleOpenRedirect},
		ModuleCmdi: {ModuleOAST, ModuleSSRF, ModuleXXE, ModuleSQLi, ModuleDAST, ModuleCORS, ModuleOpenRedirect},
		ModuleATO:  {ModuleOpenRedirect, ModuleSSRF, ModuleXXE, ModuleCmdi, ModuleSQLi, ModuleDAST, ModuleCORS, ModuleJWT},
	}
	// objective → capabilities + itself that MUST be present.
	required := map[string][]string{
		ModuleSSRF: {ModuleHTTPProbe, ModuleParamDiscovery, ModuleSSRF, ModuleVerify},
		ModuleXXE:  {ModuleHTTPProbe, ModuleParamDiscovery, ModuleXXE, ModuleVerify},
		ModuleCmdi: {ModuleHTTPProbe, ModuleParamDiscovery, ModuleCmdi, ModuleVerify},
		ModuleATO:  {ModuleHTTPProbe, ModuleParamDiscovery, ModuleATO, ModuleVerify},
	}

	for _, objective := range []string{ModuleSSRF, ModuleXXE, ModuleCmdi, ModuleATO} {
		s := newTestScheduler(t)
		if _, err := s.db.Exec(`INSERT INTO targets (id, domain) VALUES ('t1','example.com')`); err != nil {
			t.Fatalf("insert target: %v", err)
		}
		task, err := s.CreateTask("t1", []string{objective}, 1)
		if err != nil {
			t.Fatalf("create task: %v", err)
		}
		var modulesJSON string
		if err := s.db.QueryRow(`SELECT modules FROM tasks WHERE id=?`, task.ID).Scan(&modulesJSON); err != nil {
			t.Fatalf("read task: %v", err)
		}
		stored := models.JSONToStringSlice(modulesJSON)

		for _, m := range required[objective] {
			if !has(stored, m) {
				t.Errorf("[%s-only] stored plan missing required %q; got %v", objective, m, stored)
			}
		}
		for _, m := range forbidden[objective] {
			if has(stored, m) {
				t.Errorf("[%s-only] ISOLATION VIOLATION: stored plan scheduled %q; got %v", objective, m, stored)
			}
		}
	}
}

// TestEveryModuleIsPlannable is the completeness invariant: EVERY module the
// scheduler can run (AllModules) must be classified so that selecting it alone
// yields a real pipeline — it is either a CAPABILITY (pure enabling step),
// a DETECTOR (has a capability closure in moduleRequires), or a network/speed
// PASSTHROUGH token. A module that is none of these would, when selected alone,
// run with no reconnaissance (empty input tables) — the exact single-objective
// gap this planner exists to prevent. If this test fails, add the new module to
// capabilitySet or moduleRequires.
func TestEveryModuleIsPlannable(t *testing.T) {
	for _, m := range AllModules {
		_, isCap := capabilitySet[m]
		_, isDet := moduleRequires[m]
		if !isCap && !isDet && !passthroughModule(m) {
			t.Errorf("module %q is UNCLASSIFIED: selecting it alone would run with no recon (add to capabilitySet or moduleRequires)", m)
		}
	}
}

// TestNewlyPlannedDetectorsExpand proves the four modules that were previously
// gaps (dir_discovery, backup_discovery, blh, monitor) now expand into a real
// pipeline when selected alone: recon runs, the module runs, no unrelated
// detector is scheduled.
func TestNewlyPlannedDetectorsExpand(t *testing.T) {
	want := map[string][]string{
		ModuleDirDiscovery:    {ModuleHTTPProbe, ModuleDirDiscovery},
		ModuleBackupDiscovery: {ModuleHTTPProbe, ModuleBackupDiscovery},
		ModuleBLH:             {ModuleHTTPProbe, ModuleBLH},
		ModuleMonitor:         {ModuleHTTPProbe, ModuleJSAnalysis, ModuleMonitor},
	}
	for m, need := range want {
		plan := PlanModules([]string{m})
		for _, r := range need {
			if !has(plan, r) {
				t.Errorf("[%s alone] plan missing %q; got %v", m, r, plan)
			}
		}
		// must not schedule an unrelated injection detector
		for _, other := range []string{ModuleSQLi, ModuleDAST, ModuleSSRF, ModuleCORS, ModuleJWT} {
			if has(plan, other) {
				t.Errorf("[%s alone] must not schedule unrelated detector %q; got %v", m, other, plan)
			}
		}
	}
}

// TestNoAutoSubdomainEnumeration is the operator's explicit guarantee: NO objective
// — not even takeover — may trigger subdomain enumeration. The scan is confined to
// the target host(s) the scheduler seeds. subdomain_enum runs ONLY when ticked.
func TestNoAutoSubdomainEnumeration(t *testing.T) {
	for _, det := range []string{ModuleXSS, ModuleSQLi, ModuleSSRF, ModuleLFI, ModuleCORS, ModuleNuclei, ModuleIDOR, ModuleJWT, ModuleTakeover} {
		plan := PlanModules([]string{det})
		if has(plan, ModuleSubdomainEnum) {
			t.Errorf("[%s alone] must NOT auto-run subdomain_enum; got %v", det, plan)
		}
		if !has(plan, ModuleHTTPProbe) {
			t.Errorf("[%s alone] must still http_probe the target host; got %v", det, plan)
		}
	}
	// explicit selection is always honoured.
	if !has(PlanModules([]string{ModuleXSS, ModuleSubdomainEnum}), ModuleSubdomainEnum) {
		t.Error("explicitly selected subdomain_enum must be kept")
	}
}
