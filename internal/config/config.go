package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type WorkerConfig struct {
	SubdomainEnumeration int `json:"subdomain_enumeration"`
	HTTPProbing          int `json:"http_probing"`
	Crawling             int `json:"crawling"`
	JSAnalysis           int `json:"js_analysis"`
	DirectoryDiscovery   int `json:"directory_discovery"`
	Nuclei               int `json:"nuclei"`
}

type ResourceLimits struct {
	MaxConcurrentTargets int `json:"max_concurrent_targets"`
	MaxScansPerTarget    int `json:"max_scans_per_target"`
	MaxToolExecutions    int `json:"max_tool_executions"`
	MaxMemoryMB          int `json:"max_memory_mb"`
	// MaxURLsPerModule caps how many URLs/params a single module processes.
	// 0 means "no cap" (process everything via pagination).
	MaxURLsPerModule int `json:"max_urls_per_module"`
	// ParallelModules runs independent modules concurrently in dependency-safe
	// groups (recon group: js/param/dir/backup; injection group: sqli/ssrf/lfi/
	// ssti/cmdi/xxe/nosqli/cache/race/idor/vuln_scan). Big wall-clock win.
	ParallelModules bool `json:"parallel_modules"`
	// HTTPRateLimit caps requests/sec for httpx & nuclei to avoid WAF bans
	// (0 = tool default).
	HTTPRateLimit int `json:"http_rate_limit"`
}

type Config struct {
	Host            string `json:"host"`
	Port            int    `json:"port"`
	DatabasePath    string `json:"database_path"`
	DataDir         string `json:"data_dir"`
	ToolsDir        string `json:"tools_dir"`
	ScreenshotsDir  string `json:"screenshots_dir"`
	WordlistsDir    string `json:"wordlists_dir"`
	NucleiTemplates string `json:"nuclei_templates"`
	SessionSecret   string `json:"session_secret"`
	AdminUsername   string `json:"admin_username"`
	AdminPassword   string `json:"admin_password"`
	LogLevel        string `json:"log_level"`

	// UpdateCheckEnabled turns the in-app "new version available" checker on/off.
	// GitHubRepo is the "owner/name" the checker queries for the latest release.
	UpdateCheckEnabled bool           `json:"update_check_enabled"`
	GitHubRepo         string         `json:"github_repo"`
	Workers            WorkerConfig   `json:"workers"`
	Limits             ResourceLimits `json:"limits"`
	CSRFSecret         string         `json:"csrf_secret"`
	InteractshServer   string         `json:"interactsh_server"`
	// BlindXSSCallbackURL is the public base URL of THIS platform, reachable from
	// a victim's browser (e.g. https://recon.example.com:8080). When set, the
	// stored/blind-XSS module injects XSS-Hunter-style beacons that call back to
	// /bx/<token>; a hit proves out-of-band execution (stored/blind XSS) even on
	// pages the scanner never sees, like an admin log viewer. Empty → blind XSS
	// injection is skipped (stored XSS still runs, it needs no callback). No
	// third-party service required: the callback is served by this app itself.
	BlindXSSCallbackURL string `json:"blind_xss_callback_url"`
	// SecurityTrailsAPIKey enables historical-DNS origin-IP discovery (finding the
	// real server IP behind a CDN/WAF by checking which historical A-record IPs
	// are still serving the site). Optional: empty → the origin_ip module is
	// skipped. Never hardcode a key here — set it per deployment in config.json.
	SecurityTrailsAPIKey string `json:"securitytrails_api_key"`
	// ShodanAPIKey enables passive third-party host intel (open ports, banners,
	// hostnames) via Shodan's InternetDB/host API. Optional: empty → the shodan
	// module is skipped. Never hardcode a key here — set it per deployment.
	ShodanAPIKey string `json:"shodan_api_key"`
	// ── Optional passive-intelligence providers ─────────────────────────────
	// Each enables an extra passive subdomain/host source. All optional: an empty
	// key skips that source. Set via the System → API Keys page (written to
	// config.json) or the matching RECON_* env var (env wins). Never commit a key.
	CensysAPIKey     string `json:"censys_api_key"`     // format "API_ID:API_SECRET"
	FOFAAPIKey       string `json:"fofa_api_key"`       // format "email:key"
	QuakeAPIKey      string `json:"quake_api_key"`      // 360 Quake token
	ZoomEyeAPIKey    string `json:"zoomeye_api_key"`    // ZoomEye API key
	VirusTotalAPIKey string `json:"virustotal_api_key"` // VirusTotal v3 key
	// NucleiIncludeLowInfo opts the nuclei module back into the noisy info/low
	// severity tiers. Off by default per the scanning spec: only medium/high/
	// critical are scanned and persisted, keeping findings actionable.
	NucleiIncludeLowInfo bool `json:"nuclei_include_low_info"`
	// VerifySecrets enables active verification of discovered API keys against
	// their providers (AWS, Slack, GitHub, Stripe, SendGrid). This uses the
	// keys LEAKED ON THE TARGET — it never requires any key from you. Off by
	// default since it sends requests to third-party services.
	VerifySecrets bool `json:"verify_secrets"`
	// EnableSQLmap lets the SQLi verifier invoke sqlmap to PROVE a strong internal
	// SQLi candidate (positive sqlmap injection = confirmation; failure =
	// INCONCLUSIVE, never false). Off by default: sqlmap is heavy and active. Only
	// runs on in-scope, high-confidence candidates.
	EnableSQLmap bool `json:"enable_sqlmap"`
	// SQLiTimeBased enables the statistical time-based SQLi pass (linear-scaling
	// proof). On by default; set false to skip the slower timing stage entirely.
	SQLiTimeBased bool `json:"sqli_time_based"`
	// NucleiVerify routes nuclei's verifiable findings (sqli/xss/open-redirect)
	// through Reconner's verification orchestrator before they count as findings:
	// a REJECTED result (e.g. a reflected-but-encoded XSS template hit) is dropped
	// to a candidate, a VERIFIED one is promoted into the main findings/report.
	// On by default — this is the biggest nuclei false-positive killer. Opt out
	// with "nuclei_verify": false.
	NucleiVerify bool `json:"nuclei_verify"`
	// NucleiExtraTargets widens nuclei's scan surface beyond the probed hosts to
	// also include the distinct parameterized URLs discovered by param discovery
	// (deduped + capped), so DAST/injection templates actually reach the app's
	// real attack surface instead of only the site roots. On by default; opt out
	// with "nuclei_extra_targets": false.
	NucleiExtraTargets bool `json:"nuclei_extra_targets"`
	// NucleiDAST enables nuclei's DAST mode (-dast) so the fuzzing-templates
	// (XSS/SQLi/SSRF/LFI/redirect/… parameter-fuzzing) that syncExtraTemplates
	// already clones into NucleiTemplates ACTUALLY run against parameterized
	// URLs — without -dast, nuclei loads but never executes them. Off by default:
	// DAST fuzzing multiplies request volume per parameterized URL. Opt in with
	// "nuclei_dast": true.
	NucleiDAST bool `json:"nuclei_dast"`
	// NucleiMaxSurfaces caps how many CANONICAL nuclei surfaces a single target may
	// scan after logical-endpoint deduplication (P0). It bounds the worst case so a
	// param-heavy site can't hand nuclei tens of thousands of near-equivalent URLs.
	// 0 ⇒ a sane built-in default is used. Distinct from URLLimit (raw row cap).
	NucleiMaxSurfaces int `json:"nuclei_max_surfaces"`
	// NucleiMaxPerHost caps how many canonical surfaces a SINGLE host may contribute
	// to the nuclei run. On a huge param/slug-heavy site (e.g. a video portal whose
	// Wayback history is tens of thousands of /v/<slug> and /profile/<user> URLs)
	// one host would otherwise consume the entire NucleiMaxSurfaces budget and stall
	// the scan. 0 ⇒ built-in default. Works together with adaptive path-segment
	// folding, which collapses high-cardinality slug/id segments to one surface.
	NucleiMaxPerHost int `json:"nuclei_max_per_host"`
	// DirDiscoveryMaxHosts caps how many alive HTTP hosts directory/backup
	// discovery will scan per target — content-discovery is memory-heavy per
	// host, so this stays a real cap, but it's now a config knob instead of a
	// silent hardcoded 150 with no way to raise it for a large target. 0 ⇒
	// built-in default (150). The dir_discovery/backup_discovery modules log a
	// warning when this cap actually drops hosts.
	DirDiscoveryMaxHosts int `json:"dir_discovery_max_hosts"`
	// NucleiBulkSize is nuclei's -bulk-size (hosts scanned in parallel per
	// template). 0 ⇒ built-in default (80, was a hardcoded 40).
	NucleiBulkSize int `json:"nuclei_bulk_size"`
	// NucleiParallelProcesses caps how many nuclei PROCESSES run concurrently
	// when the target surface is large enough to split (see nuclei.go's
	// regroupIntoChunks) — real wall-clock parallelism beyond what a single
	// process's -c/-bulk-size alone can give on a multi-core box. The
	// configured rate-limit is DIVIDED across processes, so raising this
	// doesn't multiply total request rate, just overlaps it more. 0 ⇒ 4.
	NucleiParallelProcesses int `json:"nuclei_parallel_processes"`
	// NucleiChunkSize is the target-count threshold that triggers splitting
	// into another parallel process (up to NucleiParallelProcesses). 0 ⇒ 500.
	NucleiChunkSize int `json:"nuclei_chunk_size"`
	// NucleiExtraTemplateRepos are extra git repos synced into cfg.NucleiTemplates
	// (see nuclei.go's syncExtraTemplates) on top of nuclei's own default store —
	// broadens coverage well past CVE-only templates into network/IoT/private-
	// range-relevant fuzzing and community templates. Empty ⇒ a curated default
	// set (official nuclei-templates + fuzzing-templates + two well-established,
	// actively-maintained community collections known for templates ahead of the
	// official upstream merge). Add your OWN repos here too — public or private
	// (the server's configured git credentials/SSH key apply, same as any other
	// git clone). Deliberately NOT "clone everything on GitHub tagged nuclei":
	// a template is YAML with matchers/extractors/DSL expressions that RUN on
	// this box, so an unvetted repo is a real supply-chain surface, not just
	// noise — curate this list, don't maximize it blindly.
	NucleiExtraTemplateRepos []string `json:"nuclei_extra_template_repos"`
	// NucleiIncludeStaticAssets, when true, lets nuclei scan static presentational
	// assets (.css/.js/.map/images/fonts/media) and the synthetic path-fuzzed URLs
	// derived from them. OFF by default: those files are the #1 nuclei false-
	// positive source — generic templates (jwt-confusion, cache-poisoning, cookie/
	// state-confusion, …) fire on a stylesheet or on nonsense paths like
	// "/style.min.css/api/user", flooding findings with issues that can't exist on
	// a static file. Reconner's own js_analysis + exposure modules already cover
	// real JS/source-map/secret findings, so excluding assets from the nuclei
	// surface loses no genuine coverage while killing the noise. Set true to
	// restore the old behavior.
	NucleiIncludeStaticAssets bool `json:"nuclei_include_static_assets"`
	// NucleiExcludeTemplateIDs are template IDs to hard-exclude from EVERY
	// nuclei run (web and network), ON TOP OF a small built-in curated
	// blocklist of templates proven to be false-positive generators or
	// operator-rejected (see nuclei_intel.go's blockedTemplateIDs) — e.g. a
	// template with a broken matcher that fires on any input. Additive: this
	// never replaces the built-in list, only extends it. Passed as nuclei's
	// -eid flag.
	NucleiExcludeTemplateIDs []string `json:"nuclei_exclude_template_ids"`
	// ScanWatchdogHours bounds a single scan so a wedged module can never hold
	// its concurrency slot forever (the actual purpose — see scheduler.go). It
	// is NOT meant to cut off a legitimately large bug-bounty target early: a
	// domain with tens of thousands of subdomains can genuinely need well past
	// a working day to crawl/probe/fuzz. 0 ⇒ built-in default (24h). The
	// scheduler also ADDS adaptive headroom on top of this base for targets
	// with a large known subdomain count from a prior scan (see
	// scheduler.go's effectiveWatchdog) — this field is the FLOOR, not a hard
	// ceiling that ignores target size.
	ScanWatchdogHours int `json:"scan_watchdog_hours"`
	// NetworkFullPortScan makes naabu scan all 65535 ports instead of the curated
	// high-signal set. Slower but exhaustive; off by default.
	// NetworkBasicAuthCheck enables the DEFAULT-credential check against exposed
	// HTTP Basic-auth panels found during a network scan, using a curated set
	// compiled from the well-known public datasets (SecLists default-passwords +
	// DefaultCreds cheat-sheet). On by default.
	// NetworkBruteforce turns on Reconner's native credential brute-force for
	// exposed SSH/RDP/SMB/VNC services (our own Go engines — no hydra). ACTIVE and
	// aggressive: OFF by default so it never runs by accident or locks out
	// accounts. Only enable against in-scope network targets you're authorized to
	// test. Paced + capped + stop-on-first-success.
	// NetworkBruteUsersFile / NetworkBrutePassFile optionally point at wordlist
	// files (e.g. SecLists) that OVERRIDE the built-in curated lists for a full
	// brute-force run. Empty ⇒ use the built-in high-signal defaults.
	// NetworkBruteDebug writes a per-host handshake DIAGNOSTIC trace (raw bytes,
	// NT/CredSSP status codes, TLS stages) for the native SMB/RDP/VNC engines to
	// <DataDir>/brute-debug.log — hand that file back to debug a protocol edge
	// case. Off by default.
	// Brute-force concurrency knobs. Higher = faster, but too high gets you blocked
	// or locks out accounts (RDP is the sensitive one — keep it modest). 0 ⇒ the
	// balanced built-in default is used.
	//   ssh/vnc: native Go worker count.  smb/rdp: hydra parallel tasks.
	// Tuned for aggressive network-range spraying (many hosts, short password
	// list) rather than a single-host deep wordlist run. STILL bounded — RDP in
	// particular can trip Windows account-lockout policy or connection-flood
	// protections above roughly 20-30 concurrent NLA attempts per host; going
	// higher risks locking out real accounts (an availability/ROE issue, not
	// just noise). Tune down per-engagement if the target's lockout threshold
	// is tight.
	// NetworkBruteHostConcurrency bounds how many DIFFERENT host:port brute
	// targets run in parallel across the whole BruteRun phase (the cross-host
	// spray fan-out — the main lever for "spray a /24 fast" rather than
	// per-host thread count). 0 ⇒ built-in default.
	// NetworkVerifyFindings re-confirms every cracked network credential with a
	// fresh, independent second attempt before it is written as a CONFIRMED finding
	// — the anti-false-positive backstop for the brute-force phase. A hit that does
	// not reproduce is recorded as UNVERIFIED (lower severity/confidence) instead of
	// a confirmed critical. On by default; turn off only for speed on trusted paths.
	// IngramEnabled turns on the bundled third-party "Ingram" IP-camera/DVR/NVR
	// vulnerability scanner (github.com/jorhelp/Ingram — a separate Python tool
	// the operator installs alongside Reconner, NOT vendored into this repo) as
	// part of the network module pipeline. It fingerprints ~15 camera/DVR
	// vendors (Dahua/Hikvision/Xiongmai/Uniview/Avtech/...) against every live
	// host and, for each match, runs vendor-specific PoCs: mostly weak/default
	// credential checks (same class as NetworkBruteforce) plus a handful of
	// known-CVE auth-bypass/RCE confirmations. ACTIVE and aggressive, same as
	// NetworkBruteforce: off by default, only enable against network targets
	// you're authorized to test.
	// IngramPath is the absolute path to Ingram's run_ingram.py entrypoint.
	// Empty ⇒ Ingram is skipped even if IngramEnabled is true (nothing to run).
	// IngramPythonPath is the Python 3 interpreter used to run Ingram. Empty ⇒
	// "python3" from PATH. Point this at a venv interpreter if Ingram's deps
	// (see its requirements.txt) are installed in one.
	// IngramThreads / IngramTimeoutMinutes tune Ingram's own concurrency and
	// bound how long a single network target's Ingram pass can run for (phase
	// timeout, mirrors BruteRun's 2h cap) so it can't approach the overall scan
	// watchdog. 0 ⇒ built-in defaults (100 threads, adaptive up to 360 minutes).
	// A NEGATIVE IngramTimeoutMinutes removes the phase bound entirely so a
	// camera/DVR sweep runs to completion in a single pass instead of being cut
	// off and resumed on the next run.
	// NetworkInitialAccess turns on Reconner's initial-access engine: for every
	// discovered service it actively confirms the ones that grant access with NO
	// credentials (unauthenticated Redis/Docker/Kubernetes/MongoDB/Elasticsearch/
	// etcd/Jenkins-console/Portainer/Jupyter/…, anonymous FTP/LDAP/rsync, no-auth
	// VNC) plus a curated set of pre-auth file-read / auth-bypass CVEs on edge
	// gear (Fortinet CVE-2018-13379, F5 CVE-2020-5902, Citrix CVE-2019-19781,
	// Apache CVE-2021-41773). Every check is read-only and gated by a strong
	// positive signature, so a hit is a real, reproducible foothold. ACTIVE and
	// opt-in, same posture as NetworkBruteforce/Ingram: OFF by default — only
	// enable against network targets you're authorized to test.
	// NetworkInitialAccessTimeoutMinutes bounds the initial-access phase (mirrors
	// BruteRun's 2h / Ingram's cap) so it can't approach the scan watchdog. 0 ⇒
	// built-in default (30 minutes); the checks are short single round-trips, so
	// this covers a large range comfortably.
	// NetworkADRealm optionally sets the Active Directory Kerberos realm (e.g.
	// "CORP.LOCAL") used by the AS-REP roasting pass. When empty the realm is
	// derived automatically from an anonymous LDAP rootDSE on the same host; set
	// this only when anonymous LDAP is blocked but Kerberos (88) is reachable.
	// NetworkBruteSpray switches the credential engine from per-service depth
	// (user×password, stop on first hit) to PASSWORD SPRAYING: one password tried
	// across every user before moving to the next, with a delay between rounds, and
	// EVERY valid pair collected. This is the lockout-safe, AD-appropriate strategy
	// for a red-team engagement. Only meaningful when NetworkBruteforce is on.
	// NetworkBruteSprayDelaySeconds is the pause between spray rounds (each round =
	// one password against all users). 0 ⇒ built-in default (5s). Raise it to stay
	// well under a domain's lockout observation window.
	// OOBRawPort is the TCP port the watchtower's raw out-of-band listener binds
	// (in `reconner serve`) to catch NON-HTTP callbacks — specifically the
	// LDAP/JNDI connection a Log4Shell (CVE-2021-44228) payload makes back to us.
	// The initial-access engine injects ${jndi:ldap://<public-host>:<port>/<token>}
	// and a hit here proves blind RCE, correlated by token. 0 ⇒ the canonical JNDI
	// port 1389. Needs BlindXSSCallbackURL set (for the reachable host) and this
	// port open to the target. Only bound in serve mode.
	OOBRawPort int `json:"oob_raw_port"`
	// IngramSnapshotsDisabled turns OFF camera-snapshot capture. Snapshots are
	// ON by default (this flag is inverted so the zero-value = enabled): for every
	// device Ingram cracks it grabs one still image from the live feed and
	// Reconner stores it as a screenshot linked to the finding's evidence. Set
	// "ingram_snapshots_disabled": true to skip the extra image download.
	// EnableDAST turns on Reconner's native context-aware DAST engine — per-
	// parameter reflection-context classification + differential markup-injection
	// confirmation (XSS) and broken-quote error-differential (SQLi candidates for
	// sqlmap). Covers GET/POST/JSON insertion points, the class of bugs template
	// matchers structurally miss. On by default; opt out with "enable_dast": false.
	EnableDAST bool `json:"enable_dast"`
	// AIEnabled turns on the autonomous AI orchestrator: a Claude tool-use loop
	// that drives Reconner's OWN engines (recon/DAST/nuclei/OAST/verify) toward a
	// proven bug, optionally seeded with an operator hypothesis, and can focus on
	// Watchtower (monitoring) changes. Off by default — it is active and spends
	// API tokens. The API key is read from the ANTHROPIC_API_KEY environment
	// variable ONLY, never from this file (never commit a key to the repo).
	AIEnabled bool `json:"ai_enabled"`
	// AIModel is the Claude model id the orchestrator uses. Defaults to the latest
	// Opus. AIMaxIterations caps the agent loop so a runaway can't burn tokens.
	AIModel         string `json:"ai_model"`
	AIMaxIterations int    `json:"ai_max_iterations"`

	// AuthzMode bounds the two-identity BOLA/IDOR/BFLA engine + deep authenticated
	// crawl: "safe"|"balanced"(default)|"deep". AuthzDestructive gates cross-user
	// DELETE (off by default).
	AuthzMode        string `json:"authz_mode"`
	AuthzDestructive bool   `json:"authz_destructive"`

	// path is the on-disk config.json this Config was loaded from (unexported, so
	// it is never marshaled back into the file). Save() writes here.
	path string
}

// Save marshals the config back to the file it was loaded from (0600), so
// settings edited at runtime — e.g. API keys entered in the System page —
// persist across restarts. No-op with an error if the path is unknown.
func (c *Config) Save() error {
	if c.path == "" {
		return fmt.Errorf("config path unknown; cannot save")
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0750); err != nil {
		return err
	}
	return os.WriteFile(c.path, data, 0600)
}

// AnthropicAPIKey returns the Claude API key, sourced ONLY from the environment
// (never persisted in config.json, which lives in a public repo).
func (c *Config) AnthropicAPIKey() string {
	return os.Getenv("ANTHROPIC_API_KEY")
}

// URLLimit returns the SQL LIMIT to use for a module. When MaxURLsPerModule is
// 0 it returns a very high number (effectively "all rows").
func (c *Config) URLLimit() int {
	if c.Limits.MaxURLsPerModule <= 0 {
		return 1000000
	}
	return c.Limits.MaxURLsPerModule
}

// DefaultAdminPassword is the password the admin account is seeded with on a
// fresh install. It is intentionally an obvious placeholder — the UI forces the
// operator to change it on first login (see handleMe's must_change_password).
const DefaultAdminPassword = "change_m)_e"

// clampInt bounds v to [lo, hi].
func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// detectTotalMemMB returns total physical RAM in MB, best-effort. Reads
// /proc/meminfo on Linux; falls back to 4096 when it can't be determined so a
// container without /proc still gets today's conservative sizing.
func detectTotalMemMB() int {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 4096
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line) // "MemTotal:  16342234 kB"
			if len(fields) >= 2 {
				if kb, err := strconv.Atoi(fields[1]); err == nil && kb > 0 {
					return kb / 1024
				}
			}
		}
	}
	return 4096
}

// autoTunedWorkers/Limits scale concurrency to the host's real capacity. Floors
// equal the historical conservative defaults, so a small VM behaves exactly as
// before; ceilings keep a very large server from spraying an unbounded number of
// sockets. Operators can still override any single field in config.json (a
// present key wins over these defaults), or disable auto-tuning entirely with
// RECON_NO_AUTOTUNE=1.
func autoTunedWorkers(cpu int) WorkerConfig {
	return WorkerConfig{
		SubdomainEnumeration: clampInt(cpu*4, 25, 200),
		HTTPProbing:          clampInt(cpu*6, 40, 400),
		Crawling:             clampInt(cpu*2, 10, 60),
		JSAnalysis:           clampInt(cpu*3, 16, 120),
		DirectoryDiscovery:   clampInt(cpu, 6, 40),
		Nuclei:               clampInt(cpu, 6, 48),
	}
}

func autoTunedLimits(cpu, memMB int) ResourceLimits {
	return ResourceLimits{
		MaxConcurrentTargets: clampInt(cpu/2, 7, 64),
		MaxScansPerTarget:    2,
		MaxToolExecutions:    clampInt(cpu/2, 6, 48),
		MaxMemoryMB:          clampInt(memMB*3/4, 3072, 65536),
		MaxURLsPerModule:     0,
		ParallelModules:      true,
		HTTPRateLimit:        clampInt(cpu*40, 150, 2000),
	}
}

func defaultConfig() *Config {
	home, _ := os.UserHomeDir()
	dataDir := filepath.Join(home, ".recon-platform")

	// Size concurrency to the host unless explicitly opted out. On an 8-core/4GB
	// VM this reproduces the previous fixed defaults; on a 32-core/128GB server it
	// opens the throttles wide so the extra capacity is actually used.
	autoTune := os.Getenv("RECON_NO_AUTOTUNE") == ""
	cpu := runtime.NumCPU()
	memMB := detectTotalMemMB()
	workers := WorkerConfig{
		SubdomainEnumeration: 25,
		HTTPProbing:          40,
		Crawling:             10,
		JSAnalysis:           16,
		DirectoryDiscovery:   6,
		Nuclei:               6,
	}
	limits := ResourceLimits{
		MaxConcurrentTargets: 7,
		MaxScansPerTarget:    2,
		MaxToolExecutions:    6,
		MaxMemoryMB:          3072,
		MaxURLsPerModule:     0,
		ParallelModules:      true,
		HTTPRateLimit:        150,
	}
	if autoTune {
		workers = autoTunedWorkers(cpu)
		limits = autoTunedLimits(cpu, memMB)
	}

	return &Config{
		Host:                        "127.0.0.1", // safe default: local-only. Set to 0.0.0.0 to expose (behind a firewall/VPN only).
		Port:                        8080,
		DatabasePath:                filepath.Join(dataDir, "recon.db"),
		DataDir:                     dataDir,
		ToolsDir:                    filepath.Join(dataDir, "tools"),
		ScreenshotsDir:              filepath.Join(dataDir, "screenshots"),
		WordlistsDir:                filepath.Join(dataDir, "wordlists"),
		NucleiTemplates:             filepath.Join(dataDir, "nuclei-templates"),
		SessionSecret:               "change-me-in-production-32-bytes!",
		AdminUsername:               "admin",
		AdminPassword:               DefaultAdminPassword,
		UpdateCheckEnabled:          true,
		GitHubRepo:                  "rootdr-backup/reconner",
		LogLevel:                    "info",
		CSRFSecret:                  "change-me-csrf-secret-32-bytes!!",
		EnableSQLmap:                true, // prove SQLi candidates with sqlmap by default (scope-guarded)
		SQLiTimeBased:               true, // statistical time-based SQLi (linear-scaling proof)
		NucleiVerify:                true, // route nuclei sqli/xss/redirect hits through the verifier
		NucleiExtraTargets:          true, // scan discovered parameterized URLs, not just site roots
		NucleiDAST:                  true, // run nuclei's fuzzing-templates (XSS/SQLi/SSRF/LFI/SSTI) against params — was off, so nuclei did no active injection
		NucleiMaxSurfaces:           8000, // cap canonical nuclei surfaces per target (post-dedup safety bound)
		NucleiMaxPerHost:            2000, // cap canonical surfaces contributed by any single host
		ScanWatchdogHours:           24,   // base watchdog floor; scheduler adds adaptive headroom for large targets
		EnableDAST:                  true,                        // native context-aware DAST (XSS/SQLi) over all insertion points
		AIModel:                     "claude-opus-4-8",           // latest Opus; used only when AIEnabled and a key is set
		AIMaxIterations:             40,                          // hard cap on the agent loop
		AuthzMode:                   "balanced",                  // two-identity BOLA: deep auth crawl + read/write differential
		AuthzDestructive:            false,                       // cross-user DELETE stays opt-in
		Workers:                     workers,                     // auto-scaled to host CPU (floors = previous fixed defaults)
		Limits:                      limits,                      // auto-scaled to host CPU/RAM
	}
}

func Load() (*Config, error) {
	cfg := defaultConfig()

	configPath := os.Getenv("RECON_CONFIG")
	if configPath == "" {
		home, _ := os.UserHomeDir()
		configPath = filepath.Join(home, ".recon-platform", "config.json")
	}
	cfg.path = configPath

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(filepath.Dir(configPath), 0750); err != nil {
				return cfg, nil
			}
			data, _ := json.MarshalIndent(cfg, "", "  ")
			_ = os.WriteFile(configPath, data, 0600)
			return cfg, nil
		}
		return nil, err
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	cfg.applyEnvOverrides()
	cfg.ensureDirs()
	return cfg, nil
}

// applyEnvOverrides lets secrets be supplied via environment variables instead
// of being written into config.json — the safe way to configure a deployment
// whose source lives in a PUBLIC repo (never commit an API key). An env var wins
// over the file when set.
func (c *Config) applyEnvOverrides() {
	if v := os.Getenv("RECON_SECURITYTRAILS_KEY"); v != "" {
		c.SecurityTrailsAPIKey = v
	}
	for env, dst := range map[string]*string{
		"RECON_CENSYS_KEY":     &c.CensysAPIKey,
		"RECON_FOFA_KEY":       &c.FOFAAPIKey,
		"RECON_QUAKE_KEY":      &c.QuakeAPIKey,
		"RECON_ZOOMEYE_KEY":    &c.ZoomEyeAPIKey,
		"RECON_VIRUSTOTAL_KEY": &c.VirusTotalAPIKey,
		"RECON_SHODAN_KEY":     &c.ShodanAPIKey,
	} {
		if v := os.Getenv(env); v != "" {
			*dst = v
		}
	}
	if v := os.Getenv("RECON_BLIND_XSS_CALLBACK_URL"); v != "" {
		c.BlindXSSCallbackURL = v
	}
	if v := os.Getenv("RECON_SHODAN_KEY"); v != "" {
		c.ShodanAPIKey = v
	}
}

func (c *Config) ensureDirs() {
	dirs := []string{c.DataDir, c.ToolsDir, c.ScreenshotsDir, c.WordlistsDir, c.NucleiTemplates}
	for _, d := range dirs {
		_ = os.MkdirAll(d, 0750)
	}
}
