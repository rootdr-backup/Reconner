package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/models"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

type NucleiScanner struct {
	db     *database.DB
	exec   *tools.Executor
	cfg    *config.Config
	logger *logger.Logger
}

func NewNucleiScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger) *NucleiScanner {
	return &NucleiScanner{db: db, exec: exec, cfg: cfg, logger: log}
}

type nucleiOutput struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
	} `json:"info"`
	MatchedAt        string            `json:"matched-at"`
	ExtractedResults []string          `json:"extracted-results"`
	Meta             map[string]string `json:"meta"`
	Timestamp        string            `json:"timestamp"`
	// PoC fields — curl-command is emitted by default for HTTP-protocol
	// matches; request/response need `-irr` (include-request-response) on the
	// nuclei invocation, which both nuclei.go and network.go's nucleiRun pass.
	CurlCommand string `json:"curl-command"`
	Request     string `json:"request"`
	Response    string `json:"response"`
}

// isMediumPlus reports whether a nuclei severity string is medium or above —
// the threshold above which we store full PoC evidence (curl command + raw
// request/response), since low/info findings are far more numerous and
// storing their raw HTTP bodies too would bloat the DB for little value.
func isMediumPlus(severity string) bool {
	switch strings.ToLower(severity) {
	case "medium", "high", "critical":
		return true
	}
	return false
}

func (s *NucleiScanner) Run(ctx context.Context, targetID string, severity []string, tags []string, logFn LogFunc) error {
	if !s.exec.IsToolAvailable("nuclei") {
		logFn("warn", "nuclei", "nuclei not available, skipping vulnerability scan")
		return nil
	}
	if strings.TrimSpace(targetID) == "" {
		return nil // no target → nothing to store (avoids FK failures)
	}

	logFn("info", "nuclei", "Loading targets for nuclei scan...")

	// Only real probed hosts — NOT the thousands of JS-derived endpoints the
	// js_endpoints module injects (scanning each of those with nuclei made a big
	// target take hours). nuclei on the real hosts still covers the surface.
	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services WHERE target_id = ? AND COALESCE(source,'probe') IN ('probe','seed')
		ORDER BY url LIMIT ?
	`, targetID, s.cfg.URLLimit())
	if err != nil {
		return fmt.Errorf("query http services: %w", err)
	}

	// Collect the RAW candidate URLs first; logical-surface deduplication runs
	// once, below, so a param-heavy site's tens of thousands of near-equivalent
	// URLs (…?id=1, …?id=2, …/order/1699…, …?utm_source=x) collapse to ONE
	// representative target each instead of exploding the nuclei workload.
	var rawURLs []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err == nil {
			if u = strings.TrimSpace(u); u != "" {
				rawURLs = append(rawURLs, u)
			}
		}
	}
	rows.Close()

	// Widen the surface (opt-out): also feed the distinct parameterized URLs
	// discovered by param discovery, so DAST/injection templates reach the app's
	// real attack surface — not just site roots. These are the biggest source of
	// duplication, which the surface-fingerprint dedup below now folds properly.
	if s.cfg.NucleiExtraTargets {
		prows, perr := s.db.QueryContext(ctx, `
			SELECT DISTINCT url FROM parameters WHERE target_id = ? AND url LIKE 'http%'
			ORDER BY url LIMIT ?`, targetID, s.cfg.URLLimit())
		if perr == nil {
			for prows.Next() {
				var u string
				if prows.Scan(&u) == nil {
					if u = strings.TrimSpace(u); u != "" {
						rawURLs = append(rawURLs, u)
					}
				}
			}
			prows.Close()
		}
	}

	// Per-asset host scope
	if hostScopeSet(ctx) != nil {
		kept := rawURLs[:0]
		for _, u := range rawURLs {
			if urlHostInScope(ctx, u) {
				kept = append(kept, u)
			}
		}
		rawURLs = kept
	}

	if len(rawURLs) == 0 {
		logFn("info", "nuclei", "No HTTP services to scan with nuclei")
		return nil
	}

	// Drop static presentational assets (.css/.js/.map/images/fonts/media) and the
	// nonsense path-fuzzed URLs derived from them (e.g. "/style.min.css/api/user")
	// from the nuclei surface — the #1 false-positive source. Off only when the
	// operator opts back in via nuclei_include_static_assets.
	if !s.cfg.NucleiIncludeStaticAssets {
		kept := rawURLs[:0]
		dropped := 0
		for _, u := range rawURLs {
			if isStaticAssetURL(u) {
				dropped++
				continue
			}
			kept = append(kept, u)
		}
		rawURLs = kept
		if dropped > 0 {
			logFn("info", "nuclei", fmt.Sprintf("Skipped %d static-asset URL(s) (css/js/images/fonts/media) — set nuclei_include_static_assets=true to scan them.", dropped))
		}
		if len(rawURLs) == 0 {
			logFn("info", "nuclei", "No non-static HTTP services to scan with nuclei")
			return nil
		}
	}

	// Logical-surface dedup + safety cap. One representative real URL per
	// fingerprint; distinct paths/hosts/meaningful-param-sets stay distinct.
	surfaceCap := s.cfg.NucleiMaxSurfaces
	if surfaceCap <= 0 {
		surfaceCap = 8000
	}
	perHostCap := s.cfg.NucleiMaxPerHost
	if perHostCap <= 0 {
		perHostCap = 2000
	}
	targets, collapsed := dedupeNucleiSurfaces(rawURLs, surfaceCap, perHostCap)
	if len(targets) == 0 {
		logFn("info", "nuclei", "No HTTP services to scan with nuclei")
		return nil
	}
	ratio := 0
	if len(rawURLs) > 0 {
		ratio = 100 * collapsed / len(rawURLs)
	}
	logFn("info", "nuclei", fmt.Sprintf(
		"Nuclei surface: %d discovered URL(s) → %d canonical surface(s) (%d redundant folded, %d%% dedup).",
		len(rawURLs), len(targets), collapsed, ratio))
	if len(rawURLs) > surfaceCap && len(targets) >= surfaceCap {
		logFn("warn", "nuclei", fmt.Sprintf("Surface capped at %d (NucleiMaxSurfaces) — raise it if you need more coverage.", surfaceCap))
	}

	// Performance: template concurrency, bulk-size, AND running multiple
	// nuclei PROCESSES in parallel are the throughput knobs that matter (the
	// same lever already proven in the network module's nucleiNetwork). The
	// config default (Workers.Nuclei) was only 4 → very slow; floor it much
	// higher than nuclei's own 25 default. Split a large surface across
	// several concurrent processes instead of one giant single-process run —
	// more real overlap on a multi-core box, same total request budget
	// (rate-limit divided across processes so the TOTAL stays what was
	// configured, never multiplied).
	conc := s.cfg.Workers.Nuclei
	if conc < 100 {
		conc = 100 // higher template concurrency = much faster on many hosts
	}
	bulkSize := 80
	if s.cfg.NucleiBulkSize > 0 {
		bulkSize = s.cfg.NucleiBulkSize
	}
	// Nuclei runs FAST by default (500 req/s — its single biggest throughput knob).
	// The gentle global HTTPRateLimit exists to keep httpx PROBING polite; clamping
	// the vuln scan to it (the 150 default) throttled nuclei ~3x and made large
	// surfaces crawl for a very long time. HTTPRateLimit may RAISE nuclei's rate
	// above the fast default but never lowers it below — use the "slow" speed
	// profile (applyWebSpeed, below) for an explicitly WAF-safe, low-rate scan.
	rl := 500 // req/s
	if s.cfg.Limits.HTTPRateLimit > rl {
		rl = s.cfg.Limits.HTTPRateLimit
	}
	maxProcs := 4
	if s.cfg.NucleiParallelProcesses > 0 {
		maxProcs = s.cfg.NucleiParallelProcesses
	}
	chunkSize := 500
	if s.cfg.NucleiChunkSize > 0 {
		chunkSize = s.cfg.NucleiChunkSize
	}

	// Apply the per-scan web speed/stealth profile (slow = WAF-safe low rate,
	// fast = max throughput). Normal leaves the tuned defaults untouched.
	if sp := webSpeedFromCtx(ctx); sp != SpeedNormal {
		conc, bulkSize, rl = applyWebSpeed(sp, conc, bulkSize, rl)
		label := map[ScanSpeed]string{SpeedSlow: "slow (WAF-safe)", SpeedFast: "fast"}[sp]
		logFn("info", "nuclei", fmt.Sprintf("Web scan speed: %s — nuclei rate-limit %d req/s, concurrency %d.", label, rl, conc))
	}

	chunks := regroupIntoChunks(targets, chunkSize, maxProcs)
	if len(chunks) > 1 {
		logFn("info", "nuclei", fmt.Sprintf("Running nuclei against %d targets, split into %d parallel process(es) (~%d each)...",
			len(targets), len(chunks), len(targets)/len(chunks)))
	} else {
		logFn("info", "nuclei", fmt.Sprintf("Running nuclei against %d targets...", len(targets)))
	}
	perProcRL := rl / len(chunks)
	if perProcRL < 20 {
		perProcRL = 20
	}

	// Materialize Reconner's embedded custom template pack once and pass it as an
	// extra -t so our own curated checks ALWAYS run alongside the official set.
	packDir := ""
	if s.cfg != nil {
		packDir = materializeReconnerTemplates(s.cfg.DataDir)
	}

	// COVERAGE GUARD — the single biggest silent "miss": a fresh install whose
	// template store was never populated (the update button was never pressed).
	// With no -t dir AND an empty built-in store, nuclei loads zero templates and
	// reports "0 vulnerabilities" on a genuinely vulnerable target — a false
	// negative across the ENTIRE official CVE/exposure set, with nothing in the log
	// to say why. Detect the empty store up front and provision it once,
	// best-effort and time-boxed, so a first-ever scan actually has templates to
	// run. Skipped silently when git is unavailable (offline appliance) — the
	// operator can still populate the store via the update-templates button.
	if s.cfg != nil && s.cfg.NucleiTemplates != "" && s.exec.IsToolAvailable("git") &&
		!dirHasTemplates(s.cfg.NucleiTemplates) {
		logFn("info", "nuclei", "Nuclei template store is empty (never provisioned) — syncing the official + fuzzing template set now (one-time; this first scan will take longer)...")
		s.syncExtraTemplates(ctx, logFn)
	}
	// DAST needs the official fuzzing-templates (XSS/SQLi/SSRF/LFI/SSTI param
	// fuzzers) — which `nuclei -update-templates` does NOT pull. If DAST is on but
	// they were never synced (fresh install, template-update button never pressed),
	// -dast would load nothing and silently find no injection. Provision them once,
	// best-effort, so nuclei's active fuzzing actually runs.
	if s.cfg != nil && s.cfg.NucleiDAST && s.cfg.NucleiTemplates != "" && s.exec.IsToolAvailable("git") {
		fuzzDir := filepath.Join(s.cfg.NucleiTemplates, "fuzzing-templates")
		if !dirHasTemplates(fuzzDir) {
			logFn("info", "nuclei", "DAST enabled but fuzzing-templates missing — syncing them now (one-time)...")
			s.syncExtraTemplates(ctx, logFn)
		}
	}
	if packDir != "" {
		logFn("info", "nuclei", fmt.Sprintf("Loaded Reconner custom template pack (%d templates).", reconnerTemplateCount()))
	}

	var findingCount atomic.Int64
	var fkWarned atomic.Bool
	var wg sync.WaitGroup
	for _, chunk := range chunks {
		wg.Add(1)
		go func(chunk []string) {
			defer wg.Done()
			s.runNucleiProcess(ctx, targetID, chunk, severity, tags, conc, bulkSize, perProcRL, packDir, &findingCount, &fkWarned, logFn)
		}(chunk)
	}
	wg.Wait()

	logFn("info", "nuclei", fmt.Sprintf("Nuclei scan complete. Found %d vulnerabilities.", findingCount.Load()))
	return nil
}

// regroupIntoChunks splits items into at most maxChunks roughly-equal groups,
// targeting ~chunkSize items per group. A small surface (fits in one chunk)
// stays a single process — splitting a handful of targets into several tiny
// nuclei processes would just add startup overhead for no real parallelism
// gain.
func regroupIntoChunks(items []string, chunkSize, maxChunks int) [][]string {
	if len(items) == 0 {
		return nil
	}
	n := (len(items) + chunkSize - 1) / chunkSize
	if n < 1 {
		n = 1
	}
	if n > maxChunks {
		n = maxChunks
	}
	if n <= 1 {
		return [][]string{items}
	}
	size := (len(items) + n - 1) / n
	var out [][]string
	for i := 0; i < len(items); i += size {
		end := i + size
		if end > len(items) {
			end = len(items)
		}
		out = append(out, items[i:end])
	}
	return out
}

// runNucleiProcess executes ONE nuclei process against a chunk of targets and
// streams matches into findings/candidates — the callback logic is unchanged
// from before the parallel-chunking split, just parameterized so multiple
// chunks can run this concurrently with shared atomic counters.
func (s *NucleiScanner) runNucleiProcess(ctx context.Context, targetID string, targets, severity, tags []string,
	conc, bulkSize, rateLimit int, packDir string, findingCount *atomic.Int64, fkWarned *atomic.Bool, logFn LogFunc) {
	input := strings.Join(targets, "\n")
	reader := strings.NewReader(input)

	args := []string{
		"-l", "/dev/stdin",
		"-j",
		"-silent",
		"-c", fmt.Sprintf("%d", conc),
		"-bulk-size", fmt.Sprintf("%d", bulkSize),
		"-timeout", "6",
		// retries 2 (was 1): a template that misses on a single transient
		// failure — a dropped connection, a momentary 5xx, a rate-limit blip —
		// is a SILENT missed finding. One extra attempt recovers those without
		// meaningfully slowing the common path (the rate-limit still caps total
		// throughput, so retries only cost time on endpoints that actually flap).
		"-retries", "2",
		"-disable-update-check",
		// max-host-error 30 (was 20): after this many errors nuclei ABANDONS a
		// host for the rest of the run — every remaining template against it is
		// then a missed finding. A host that briefly rate-limits or 5xxes early
		// used to be dropped wholesale at 20; 30 keeps flaky-but-real hosts in
		// scope. -no-mhe would disable the guard entirely, but that lets one
		// truly-dead host burn the whole timeout, so we raise the ceiling instead.
		"-max-host-error", "30",
		"-irr", // include-request-response: PoC evidence (see isMediumPlus below)
	}
	args = append(args, nucleiExcludeIDFlag(s.cfg)...)
	args = append(args, "-rate-limit", fmt.Sprintf("%d", rateLimit))
	// OOB: use a configured interactsh server if present; otherwise DISABLE
	// interactsh entirely. The default polls interactsh.com and adds real
	// latency at start/end — and Reconner already has its own self-hosted OAST
	// module for blind SSRF/XXE/RCE, so nuclei's is redundant here.
	if s.cfg.InteractshServer != "" {
		args = append(args, "-interactsh-server", s.cfg.InteractshServer)
	} else {
		args = append(args, "-no-interactsh")
	}

	if len(severity) > 0 {
		args = append(args, "-severity", strings.Join(severity, ","))
	} else if s.cfg.NucleiIncludeLowInfo {
		// Operator explicitly opted back in to the noisy info+low tiers.
		args = append(args, "-severity", "info,low,medium,high,critical")
	} else {
		// Default: medium/high/critical ONLY. Low was dropped per operator
		// request — the low tier is dominated by best-practice/informational
		// noise (missing headers, weak ciphers, SSL posture, verbose banners)
		// that buried the real findings. Re-enable low+info with
		// NucleiIncludeLowInfo ("nuclei_include_low_info": true) if needed.
		args = append(args, "-severity", "medium,high,critical")
	}

	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}

	// Only pass -t when our custom template dir actually contains templates.
	// Otherwise omit it so nuclei uses its own default template store (which the
	// operator keeps updated via `nuclei -update-templates`). Passing an empty
	// dir makes nuclei exit 1 and scan nothing.
	if s.cfg.NucleiTemplates != "" && dirHasTemplates(s.cfg.NucleiTemplates) {
		args = append(args, "-t", s.cfg.NucleiTemplates)
	}
	// Reconner's own embedded template pack (always available, no install step).
	if packDir != "" {
		args = append(args, "-t", packDir)
	}
	// DAST mode: run the cloned fuzzing-templates against parameterized URLs.
	// Without -dast nuclei loads but never executes them (they're skipped),
	// so this flag is what actually turns on parameter fuzzing.
	if s.cfg.NucleiDAST {
		args = append(args, "-dast")
	}
	args = append(args, ToolRequestIdentityArgs(ctx, "nuclei")...)

	// FIX: feed targets via real stdin. Previously RunWithCallback never set
	// cmd.Stdin, so `-l /dev/stdin` read EOF and nuclei scanned nothing.
	err := s.exec.RunWithInputCallback(ctx, reader, targetID, func(line string) {
		var out nucleiOutput
		if err := json.Unmarshal([]byte(line), &out); err != nil {
			return
		}
		if nucleiBlockedTemplate(out.TemplateID, out.Info.Name) {
			// Known false-positive/rejected template — no finding, no
			// candidate, no trace at all (see nuclei_intel.go). -eid already
			// asks nuclei to skip it entirely; this is the backstop.
			return
		}
		// Reflected-URL guard: an injection/RCE "proof" that is really just the
		// requested path echoed back into the page (og:url/canonical/search) is a
		// false positive — drop it outright (no finding, no candidate).
		if nucleiURLReflectionFP(out.TemplateID, out.Info.Name, out.Info.Tags, out.Request, out.Response) {
			return
		}
		// Static-asset backstop: even if a template self-generates a static or
		// static-derived URL (e.g. "/app.js" or "/style.css/api/user"), drop it —
		// a finding on a stylesheet/script/image is the noise class we exclude. The
		// concatenator check adds the WordPress load-scripts.php/load-styles.php
		// catch-all-200 endpoints, whose URL carries no static extension but which
		// return JS/CSS for any appended path (the JWT-on-a-JS-bundle FP class).
		if !s.cfg.NucleiIncludeStaticAssets &&
			(isStaticAssetURL(out.MatchedAt) || isConcatenatorNoiseURL(out.MatchedAt)) {
			return
		}
		// Catch-all-200 guard by RESPONSE type: an injection/auth finding whose
		// response was actually served as static JS/CSS/an image means the server
		// never processed our input as an application — it handed back a static file
		// with 200. That is a false positive regardless of the URL. Exposure/secret/
		// misconfig templates (which can legitimately match inside a static file) are
		// left alone because they don't assert app-processing behaviour.
		if !s.cfg.NucleiIncludeStaticAssets &&
			responseIsStaticAsset(out.Response) &&
			nucleiAssertsAppBehavior(out.TemplateID, out.Info.Name, out.Info.Tags) {
			return
		}

		sev := strings.ToLower(out.Info.Severity)
		actionableSev := !(sev == "info" || sev == "low" || sev == "unknown" || sev == "")
		typ, _ := classifyNucleiTemplate(out.TemplateID, out.Info.Tags)

		// MISS NOTHING: capture every hit that is either an actionable severity OR
		// maps to a real vulnerability class as a normalized candidate — even an
		// info/low template that actually hit a sqli/xss/ssrf/lfi/rce/ssti/redirect
		// class is preserved (queryable, fingerprint-deduped) so nothing real is
		// ever silently dropped by the severity policy.
		if actionableSev || typ != "nuclei" {
			_ = StoreCandidate(ctx, s.db,
				nucleiToCandidate(targetID, out.TemplateID, out.Info.Name, out.Info.Severity, out.MatchedAt, out.Info.Tags))
		}

		// FINDINGS stay HIGH-SIGNAL: skip the info/low tiers unless opted in, and
		// drop detection-only noise (tech/waf/tls/dns/header fingerprints) — those
		// live as candidates, never as standalone findings. This is the biggest
		// nuclei false-positive cut.
		if !s.cfg.NucleiIncludeLowInfo && !actionableSev {
			return
		}
		if nucleiNoisyTemplate(out.TemplateID, out.Info.Tags) {
			return
		}

		finding := &models.NucleiFinding{
			ID:           uuid.New().String(),
			TargetID:     targetID,
			TemplateID:   out.TemplateID,
			TemplateName: out.Info.Name,
			Severity:     out.Info.Severity,
			MatchedURL:   out.MatchedAt,
			Description:  out.Info.Description,
			Tags:         out.Info.Tags,
			Meta:         out.Meta,
		}
		// PoC evidence for medium+ only — see isMediumPlus.
		if isMediumPlus(out.Info.Severity) {
			finding.CurlCommand = out.CurlCommand
			finding.Request = out.Request
			finding.Response = out.Response
		}

		if finding.Meta == nil {
			finding.Meta = make(map[string]string)
		}

		if err := s.storeFinding(finding); err != nil {
			// A FOREIGN KEY failure means the target row is gone (deleted
			// mid-scan, ON DELETE CASCADE). That's expected on cancellation —
			// log it once at info, not a scary repeated ERROR, and keep going.
			if strings.Contains(err.Error(), "FOREIGN KEY") {
				if !fkWarned.Swap(true) {
					logFn("info", "nuclei", "Target no longer exists (deleted/cancelled) — skipping nuclei finding storage.")
				}
				return
			}
			s.logger.Error("Store nuclei finding failed", "error", err)
			return
		}

		findingCount.Add(1)
		logFn("warn", "nuclei", fmt.Sprintf("[%s] %s - %s",
			strings.ToUpper(out.Info.Severity), out.TemplateID, out.MatchedAt))
	}, "nuclei", args...)

	if err != nil && ctx.Err() == nil {
		logFn("warn", "nuclei", fmt.Sprintf("nuclei process error: %v", err))
	}
}

// dirHasTemplates reports whether dir contains at least one .yaml/.yml template.
func dirHasTemplates(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}
	found := false
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || found {
			return nil
		}
		if !d.IsDir() {
			l := strings.ToLower(d.Name())
			if strings.HasSuffix(l, ".yaml") || strings.HasSuffix(l, ".yml") {
				found = true
				return filepath.SkipAll
			}
		}
		return nil
	})
	return found
}

// nucleiStaticExts are the presentational-asset extensions nuclei should not
// scan by default. Deliberately excludes .json/.xml/.txt/.pdf/.zip — those can be
// sensitive API responses or exposed files that real templates legitimately flag.
var nucleiStaticExts = map[string]bool{
	".css": true, ".scss": true, ".less": true,
	".js": true, ".mjs": true, ".cjs": true, ".map": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true,
	".ico": true, ".webp": true, ".bmp": true, ".tiff": true, ".avif": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".otf": true,
	".mp4": true, ".webm": true, ".mp3": true, ".wav": true, ".ogg": true,
	".avi": true, ".mov": true, ".m4v": true, ".flv": true, ".m4a": true,
}

// isStaticAssetURL reports whether a URL targets a static presentational asset —
// OR is a nonsense path built on top of one (e.g. "/style.min.css/api/user").
// It checks EVERY path segment, so a static extension appearing anywhere (not
// just the final segment) marks the URL as asset-derived. Query string is
// ignored. This is the filter for the nuclei false-positive class where generic
// templates fuzz stylesheets/scripts/images.
func isStaticAssetURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	p := u.Path
	if p == "" {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" {
			continue
		}
		if dot := strings.LastIndexByte(seg, '.'); dot >= 0 {
			if nucleiStaticExts[strings.ToLower(seg[dot:])] {
				return true
			}
		}
	}
	return false
}

// isConcatenatorNoiseURL reports whether a matched URL points at a WordPress
// script/style CONCATENATOR (load-scripts.php / load-styles.php). These return
// HTTP 200 with static JS/CSS for ANY appended path segment or bogus query param
// (they act on the load[] list and ignore everything else, including the
// Authorization header), which makes them a notorious catch-all-200 false-positive
// amplifier: a presence/200-based template appends "/api/profile" or sends a
// crafted token, gets the concatenated script back with 200, and wrongly reports a
// bug (e.g. the "JWT Algorithm Confusion Attack Detection" fired on a ClipboardJS
// bundle). A finding matched here is never real — it's the loader echoing scripts.
func isConcatenatorNoiseURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	p := strings.ToLower(u.Path)
	return strings.Contains(p, "/load-scripts.php") || strings.Contains(p, "/load-styles.php")
}

// staticAssetContentTypes are response Content-Type prefixes that prove the server
// returned a static asset rather than an application/API response.
var staticAssetContentTypes = []string{
	"javascript", "ecmascript", "text/css", "image/", "font/",
	"application/font", "application/x-font", "audio/", "video/",
	"application/octet-stream",
}

// responseIsStaticAsset reports whether a raw nuclei HTTP response (status line +
// headers + body, captured via -irr) was served with a static-asset Content-Type.
// A server that answers with JavaScript/CSS/an image did NOT process the request as
// a dynamic app call, so an injection/auth "match" on it is a catch-all-200 FP.
func responseIsStaticAsset(rawResponse string) bool {
	ct := strings.ToLower(rawResponseHeader(rawResponse, "content-type"))
	if ct == "" {
		return false
	}
	for _, m := range staticAssetContentTypes {
		if strings.Contains(ct, m) {
			return true
		}
	}
	return false
}

// rawResponseHeader extracts a header value from a raw HTTP response text. It stops
// at the blank line ending the header block so a "content-type:" string inside the
// body can never be mistaken for the real header.
func rawResponseHeader(raw, name string) string {
	name = strings.ToLower(name)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			break // end of headers
		}
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			continue
		}
		if strings.ToLower(strings.TrimSpace(line[:i])) == name {
			return strings.TrimSpace(line[i+1:])
		}
	}
	return ""
}

// nucleiAssertsAppBehavior reports whether a template asserts the server PROCESSED
// the request as a dynamic app/API (an injection, auth, or logic class). These are
// exactly the findings that are meaningless on a static JS/CSS/image response —
// paired with responseIsStaticAsset to drop catch-all-200 false positives while
// leaving exposure/secret/misconfig templates (which can legitimately match inside
// a static file) untouched.
func nucleiAssertsAppBehavior(templateID, name string, tags []string) bool {
	hay := strings.ToLower(templateID + " " + name + " " + strings.Join(tags, " "))
	for _, k := range []string{
		"jwt", "auth", "sqli", "sql injection", "xss", "ssrf", "lfi", "rfi",
		"rce", "ssti", "idor", "redirect", "injection", "traversal",
		"deserial", "xxe", "csrf", "prototype", "command", "confusion",
	} {
		if strings.Contains(hay, k) {
			return true
		}
	}
	return false
}

func (s *NucleiScanner) storeFinding(f *models.NucleiFinding) error {
	tags := models.StringSliceToJSON(f.Tags)
	meta := models.MapToJSON(f.Meta)

	// Deduplicate on the LOGICAL finding identity (target + template + matched
	// URL). The previous `ON CONFLICT DO NOTHING` was dead code — the only unique
	// key is the PRIMARY KEY on the always-fresh uuid, so it never fired and every
	// re-scan/restart inserted duplicate rows. INSERT…WHERE NOT EXISTS makes the
	// dedup real without a risky unique-index migration over existing dupes.
	_, err := s.db.Exec(`
		INSERT INTO nuclei_findings (id, target_id, template_id, template_name, severity, matched_url, description, tags, meta, curl_command, request, response)
		SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
		WHERE NOT EXISTS (
			SELECT 1 FROM nuclei_findings
			WHERE target_id = ? AND template_id = ? AND matched_url = ?
		)
	`, f.ID, f.TargetID, f.TemplateID, f.TemplateName, f.Severity, f.MatchedURL, f.Description, tags, meta, f.CurlCommand, f.Request, f.Response,
		f.TargetID, f.TemplateID, f.MatchedURL)
	return err
}

func (s *NucleiScanner) UpdateTemplates(ctx context.Context, logFn LogFunc) error {
	if !s.exec.IsToolAvailable("nuclei") {
		return nil
	}

	logFn("info", "nuclei", "Updating nuclei templates...")

	result, err := s.exec.Run(ctx, "nuclei", "-update-templates", "-silent")
	if err != nil {
		logFn("warn", "nuclei", fmt.Sprintf("Template update warning: %v", err))
	} else {
		logFn("info", "nuclei", fmt.Sprintf("Templates updated: %s", result.Stdout))
	}

	s.syncExtraTemplates(ctx, logFn)
	return nil
}

// defaultNucleiExtraRepos is the curated fallback when
// cfg.NucleiExtraTemplateRepos is empty. Picked for being actively
// maintained/well-established, not "every nuclei-tagged repo on GitHub" (see
// the config field's doc comment on why that would be an unvetted
// supply-chain surface — a template is YAML with matchers/extractors/DSL
// expressions that RUN on this box):
//   - projectdiscovery/nuclei-templates: full official CVE/exposure set.
//   - projectdiscovery/fuzzing-templates: official param-fuzzing templates
//     (XSS/SQLi/SSRF/LFI/SSTI/...) that -update-templates does not pull.
//   - geeknik/the-nuclei-templates: long-running community aggregator with
//     heavy network/IoT/device-panel coverage beyond the official CVE set —
//     the main lever for private/internal-range bug-bounty scope (routers,
//     cameras, NAS, industrial/ICS panels, ...).
//   - dwisiswant0/nuclei-templates: active contributor's staging repo,
//     frequently has templates ahead of the official upstream merge.
//   - h0tak88r/nuclei_templates: actively maintained aggregator.
//   - daffainfo/my-nuclei-templates: well-known contributor, many of whose
//     templates have historically been merged into the official upstream.
//   - NitinYadav00/My-Nuclei-Templates, 0xPugal/my-nuclei-templates: sizeable,
//     reasonably-established personal collections with real CVE coverage.
//
// Deliberately EXCLUDED after review: 0xKayala/Custom-Nuclei-Templates (its
// own issue tracker documents templates that hard-code an attacker-controlled
// OOB domain, leaking scan-result signals to a third party — a real
// supply-chain risk, not a style objection); pikpikcu/my-nuclei-templates
// (its own issue tracker flags a disputed/likely-false SQLi hit); the
// ARPSyndicate/Elsfa7-110 kenzer-templates pair (archived + a fork frozen at
// the same commit — stale duplicates); and several tiny (2-17 commit),
// unmaintained-since-2020-2022, unlicensed personal repos whose marginal
// content isn't worth the added unvetted-YAML surface.
// Default: the TWO official, actively-maintained, low-false-positive
// ProjectDiscovery stores only. The community/personal repos that used to be
// here (geeknik/the-nuclei-templates, h0tak88r, daffainfo, NitinYadav00,
// 0xPugal, dwisiswant0) were the dominant false-positive source in the field —
// obscure presence-only CGI checks (IRIX nph-publish, LISTSERV wa-abbvie.exe)
// and AI-generated "…Detection" templates (CHIPS/WebAuthn/JWT "confusion")
// that fire CRITICAL/HIGH on any 200 response. Operators who want them can still
// opt back in per deployment via config's nuclei_extra_template_repos.
var defaultNucleiExtraRepos = []string{
	"https://github.com/projectdiscovery/nuclei-templates",
	"https://github.com/projectdiscovery/fuzzing-templates",
}

// syncExtraTemplates git-clones/pulls every repo in
// cfg.NucleiExtraTemplateRepos (or defaultNucleiExtraRepos when unset) into
// cfg.NucleiTemplates, on top of whatever -update-templates above already
// maintains in nuclei's own internal store. dirHasTemplates() (which drives
// whether -t cfg.NucleiTemplates gets passed at all) then sees the UNION of
// every repo here. A clone/pull failure for any ONE repo (offline box, no
// git, repo renamed/gone) only skips that repo and logs it — never removes
// templates or blocks a scan.
func (s *NucleiScanner) syncExtraTemplates(ctx context.Context, logFn LogFunc) {
	if s.cfg == nil || s.cfg.NucleiTemplates == "" || !s.exec.IsToolAvailable("git") {
		return
	}
	sctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()

	repoURLs := s.cfg.NucleiExtraTemplateRepos
	if len(repoURLs) == 0 {
		repoURLs = defaultNucleiExtraRepos
	}
	logFn("info", "nuclei", fmt.Sprintf("Syncing %d extra template repo(s)...", len(repoURLs)))

	for _, repoURL := range repoURLs {
		repoURL = strings.TrimSpace(repoURL)
		if repoURL == "" {
			continue
		}
		name := repoDirName(repoURL)
		dir := filepath.Join(s.cfg.NucleiTemplates, name)
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			if res, err := s.exec.Run(sctx, "git", "-C", dir, "pull", "--ff-only"); err != nil {
				logFn("info", "nuclei", fmt.Sprintf("%s update skipped: %v", name, err))
			} else {
				logFn("info", "nuclei", fmt.Sprintf("%s updated: %s", name, strings.TrimSpace(res.Stdout)))
			}
			continue
		}
		if err := os.MkdirAll(s.cfg.NucleiTemplates, 0o755); err != nil {
			continue
		}
		if _, err := s.exec.Run(sctx, "git", "clone", "--depth", "1", repoURL, dir); err != nil {
			logFn("info", "nuclei", fmt.Sprintf("%s clone skipped (offline, no git access, or repo unavailable): %v", name, err))
			continue
		}
		logFn("info", "nuclei", fmt.Sprintf("%s cloned into %s.", name, dir))
	}

	// Prune previously-cloned repos that are no longer configured — e.g. the junk
	// community/personal template repos dropped from the defaults. Only removes a
	// direct subdirectory that is itself a git clone (has .git) and isn't in the
	// active repo set, so the official store and any user files are never touched.
	// This auto-cleans installs that already pulled the false-positive repos.
	expected := map[string]bool{}
	for _, r := range repoURLs {
		expected[repoDirName(strings.TrimSpace(r))] = true
	}
	if entries, err := os.ReadDir(s.cfg.NucleiTemplates); err == nil {
		for _, e := range entries {
			if !e.IsDir() || expected[e.Name()] {
				continue
			}
			d := filepath.Join(s.cfg.NucleiTemplates, e.Name())
			if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
				if os.RemoveAll(d) == nil {
					logFn("info", "nuclei", fmt.Sprintf("Removed unconfigured template repo %q (dropped from defaults to cut false positives).", e.Name()))
				}
			}
		}
	}
}

// repoDirName derives a filesystem-safe directory name from a git URL — the
// last path segment with a trailing ".git" stripped, e.g.
// "https://github.com/geeknik/the-nuclei-templates" -> "the-nuclei-templates".
func repoDirName(repoURL string) string {
	u := strings.TrimSuffix(strings.TrimRight(repoURL, "/"), ".git")
	if i := strings.LastIndexAny(u, "/:"); i >= 0 && i+1 < len(u) {
		return u[i+1:]
	}
	return "repo"
}
