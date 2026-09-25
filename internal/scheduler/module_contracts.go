package scheduler

// ModuleContract is the v3 release contract for one executable module. It is
// deliberately code, not marketing copy: the companion test requires an exact
// one-to-one mapping with AllModules and a checked-in regression suite.
type ModuleContract struct {
	Kind           string
	Prerequisites  string
	Completion     string
	Proof          string
	RegressionFile string
}

// V3ModuleContracts freezes the supported web capability surface. A module may
// complete with zero observations only after its prerequisites were available
// and its declared eligible inputs were attempted. Missing external/runtime
// prerequisites must return scanner.BlockedPhase instead of clean success.
var V3ModuleContracts = map[string]ModuleContract{
	ModuleSubdomainEnum:   {"discovery", "valid web domain; explicit selection", "admitted DNS names persisted", "DNS/admission evidence", "scanner/subdomain_admission_test.go"},
	ModuleHTTPProbe:       {"discovery", "seeded web host", "reachable HTTP services attempted", "status/TLS/response metadata", "scanner/vhost_catchall_test.go"},
	ModuleJSAnalysis:      {"discovery", "live HTTP service", "bounded JavaScript assets analyzed", "asset provenance and content-derived observations", "scanner/js_dependency_graph_test.go"},
	ModuleJSEndpoints:     {"discovery", "JavaScript assets", "in-scope endpoint candidates extracted", "source asset and normalized endpoint", "scanner/endpoint_seed_test.go"},
	ModuleParamDiscovery:  {"discovery", "live/crawled web surface", "supported request shapes persisted", "method, location, content type and sibling values", "scanner/params_form_test.go"},
	ModuleHeadlessCrawl:   {"discovery", "Chromium and HTML seed", "bounded rendered pages attempted", "rendered link/form provenance", "scanner/headless_crawl_contract_test.go"},
	ModuleTimeMachine:     {"discovery", "Wayback service and valid domain", "in-scope archived URLs processed", "archive provenance; strict hostname scope", "scanner/enrichment_contract_test.go"},
	ModuleParamReflection: {"discovery", "parameter inventory", "eligible parameters checked", "MIME-aware reflected marker", "scanner/reflect_redirect_test.go"},
	ModuleParamFuzz:       {"discovery", "stable live endpoint", "bounded hidden names compared", "repeatable differential with controls", "scanner/paramfuzz_reliability_test.go"},
	ModuleDirDiscovery:    {"detector", "live HTTP service", "bounded path corpus attempted", "soft-404 and content-family differential", "scanner/directory_softnoise_test.go"},
	ModuleBackupDiscovery: {"detector", "live HTTP service", "bounded backup corpus attempted", "file-type signature beyond status/length", "scanner/directory_test.go"},
	ModuleOpenRedirect:    {"detector", "routable insertion point", "supported points tested", "external destination plus encoded/sibling controls", "scanner/open_redirect_encoding_test.go"},
	ModuleNuclei:          {"detector", "nuclei binary and live targets", "selected template run parsed", "template evidence with noise/reflection guards", "scanner/nuclei_fp_test.go"},
	ModuleXSS:             {"detector", "HTML-capable insertion surface", "eligible contexts attempted", "browser execution with independent marker", "scanner/xss_verify_confirm_test.go"},
	ModuleVulnScan:        {"detector", "live/parameter surface", "native vulnerability families attempted", "family-specific differential or candidate state", "scanner/vulnengine_upgrade_test.go"},
	ModuleSQLi:            {"detector", "routable insertion point", "eligible points and controls attempted", "multi-signal boolean/error/timing proof", "scanner/sqli_fp_test.go"},
	ModuleSSRF:            {"detector", "routable insertion point; callback for blind proof", "eligible points attempted", "controlled response or attributed OOB callback", "scanner/injection_engines_v3_test.go"},
	ModuleLFI:             {"detector", "routable insertion point", "eligible points attempted", "known-file signature plus sibling replay", "scanner/injection_engines_v3_test.go"},
	ModuleSSTI:            {"detector", "routable insertion point", "eligible points attempted", "two independent server-evaluated expressions", "scanner/injection_engines_v3_test.go"},
	ModuleCSTI:            {"detector", "Chromium and reflected HTML point", "eligible rendered points attempted", "two independent client-rendered expressions", "scanner/csti_test.go"},
	ModuleCmdi:            {"detector", "routable insertion point", "eligible points attempted", "shell-computed marker replay or attributed OOB", "scanner/detector_coverage_test.go"},
	ModulePassive:         {"detector", "fetchable live response", "bounded responses inspected", "response/header signatures with host dedupe", "scanner/detector_coverage_test.go"},
	ModuleTakeover:        {"detector", "known subdomain DNS state", "eligible DNS chains checked", "provider-specific dangling-resource fingerprint", "scanner/takeover_fp_test.go"},
	ModuleBLH:             {"detector", "discovered HTML pages", "bounded outbound links checked", "dead link plus reclaimability evidence", "scanner/blh_pages_test.go"},
	ModuleCSRF:            {"detector", "authenticated state-changing forms", "eligible forms classified", "candidate only until browser/side-effect proof", "scanner/injection_engines_v3_test.go"},
	ModuleCORS:            {"detector", "live HTTP service", "origin controls attempted", "credentialed origin differential and content replay", "scanner/cors_test.go"},
	ModuleExposure:        {"detector", "live HTTP service", "bounded exposure probes attempted", "artifact-specific content signature", "scanner/exposure_v3_test.go"},
	ModuleIntel:           {"detector", "persisted discovery observations", "correlations evaluated", "multi-source evidence with stable fingerprint", "scanner/benchmark_realrecon_test.go"},
	ModuleOAST:            {"detector", "public callback URL and insertion surface", "probes registered and sent", "token-attributed callback only", "scanner/oast_test.go"},
	ModuleXXE:             {"detector", "XML-capable request or callback", "eligible requests attempted", "controlled file marker or attributed OOB", "scanner/injection_engines_v3_test.go"},
	ModuleFileUpload:      {"detector", "scoped multipart or file-like structured insertion point", "bounded bypass matrix attempted", "retrieval execution, browser proof, traversal retrieval or attributed OOB callback", "scanner/file_upload_test.go"},
	ModuleIDOR:            {"detector", "baseline owner and attacker identities", "owned-object reads compared", "owner/unauth/attacker same-object matrix", "scanner/idor_sameobject_test.go"},
	ModuleJWT:             {"detector", "captured JWT", "supported token mutations attempted", "cryptographic acceptance differential", "scanner/jwt_test.go"},
	ModuleAuthz:           {"detector", "two identities and owned-object traffic", "read candidates replayed; writes remain hypotheses", "relationship-aware cross-identity matrix", "scanner/authz_verify_test.go"},
	ModuleATO:             {"detector", "authentication/recovery surface", "eligible takeover chains evaluated", "chain-specific proof; weak signals remain candidates", "scanner/ato_isolation_test.go"},
	ModuleNoSQLi:          {"detector", "routable structured insertion point", "eligible points attempted", "operator/type differential with sibling controls", "scanner/injection_engines_v3_test.go"},
	ModuleCachePoison:     {"detector", "cacheable live service", "header/query variants replayed", "clean baseline plus two stable poisoned hits", "scanner/cachepoison_test.go"},
	ModuleOriginIP:        {"detector", "SecurityTrails key and fetchable baseline", "historical public IPs compared", "target-matching direct-vhost response", "scanner/enrichment_contract_test.go"},
	ModuleShodan:          {"discovery", "Shodan key and resolved target IP", "every unique IP query resolved or blocked", "provider response provenance", "scanner/enrichment_contract_test.go"},
	ModuleRace:            {"detector", "race-prone state-changing request", "bounded synchronized burst sent", "multiple successes plus conflicting outcomes; candidate", "scanner/detector_coverage_test.go"},
	ModuleSmuggling:       {"detector", "explicit opt-in live HTTP service", "CL.TE and TE.CL controls attempted", "fast baselines plus reproducible framing delay; candidate", "scanner/detector_coverage_test.go"},
	ModuleVerify:          {"postprocess", "pending verifiable candidates", "bounded verifier queue drained", "class-specific independent verification", "scanner/candidate_verify_test.go"},
	ModuleMonitor:         {"monitor", "live baseline or prior snapshot", "bounded snapshot/diff completed", "stable repeated change against persisted baseline", "scanner/monitor_run_test.go"},
}
