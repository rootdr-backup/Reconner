package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/secret"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

// VerifyScanner is the verification & prioritisation layer. It runs LAST, after
// every detection module, and does two things the rest of the pipeline cannot:
//
//  1. Re-verifies high-value active findings by replaying the exact payload and
//     re-checking the confirmation signature. Transient/heuristic hits that no
//     longer reproduce get their confidence slashed — this is the single biggest
//     false-positive killer.
//  2. Assigns every finding a confidence (0-100) and a priority score derived
//     from severity × confidence × exploitability, so the operator triages the
//     genuinely exploitable issues first instead of by raw severity alone.
type VerifyScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewVerifyScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *VerifyScanner {
	return &VerifyScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

type sqlmapCandidate struct {
	id, url, method, param, loc, subtype string
	conf                                 int
}

func sqlmapVerificationWorkers(cfg *config.Config, candidates int) int {
	if candidates <= 1 {
		return candidates
	}
	workers := 2 // deliberately small: overlap I/O without multiplying target load
	if cfg == nil || cfg.Limits.MaxToolExecutions == 1 || (cfg.Limits.MaxMemoryMB > 0 && cfg.Limits.MaxMemoryMB < 1536) {
		workers = 1
	} else if cfg.Limits.MaxToolExecutions > 0 && cfg.Limits.MaxToolExecutions < workers {
		workers = cfg.Limits.MaxToolExecutions
	}
	if workers > candidates {
		workers = candidates
	}
	return workers
}

// runSQLmapCandidates bounds concurrency and stops feeding work immediately on
// cancellation. A candidate already inside Verify observes the same context and
// the executor kills its process group, so cancellation cannot leave sqlmap
// children running or silently drain the remaining queue.
func runSQLmapCandidates(ctx context.Context, candidates []sqlmapCandidate, workers int, verify func(sqlmapCandidate)) int {
	if workers < 1 || len(candidates) == 0 || ctx.Err() != nil {
		return 0
	}
	jobs := make(chan sqlmapCandidate)
	var wg sync.WaitGroup
	var processed atomic.Int64
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for candidate := range jobs {
				if ctx.Err() != nil {
					return
				}
				verify(candidate)
				processed.Add(1)
			}
		}()
	}

feed:
	for _, candidate := range candidates {
		select {
		case jobs <- candidate:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	return int(processed.Load())
}

// verifySQLiWithSQLmap proves high-confidence internal SQLi candidates with the
// scope-checked sqlmap adapter, updating candidate + finding status. Only runs
// when cfg.EnableSQLmap and sqlmap is installed.
func (s *VerifyScanner) verifySQLiWithSQLmap(ctx context.Context, targetID string, logFn LogFunc) {
	var domain string
	_ = s.db.QueryRow(`SELECT domain FROM targets WHERE id=?`, targetID).Scan(&domain)
	// Full baseline identity (Cookie, Authorization and custom headers) for
	// authenticated SQLi. Keeping only Cookie made protected JSON/API candidates
	// unreachable to sqlmap.
	authHeaders := map[string]string{}
	var origins []string
	for _, id := range LoadIdentities(ctx, s.db, targetID, secret.New(s.cfg.SessionSecret)) {
		if id.Origin != "" {
			origins = append(origins, id.Origin)
		}
		if id.IsBaseline {
			for k, v := range id.Headers {
				authHeaders[k] = v
			}
		}
	}
	verifier := NewSQLmapVerifier(s.exec, s.cfg, s.logger, domain, origins, authHeaders)
	verifier.db = s.db

	limit := 100
	if s.cfg != nil {
		limit = s.cfg.URLLimit()
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, url, method, parameter, location, subtype, confidence FROM candidates
		 WHERE target_id=? AND type='sqli' AND status IN ('DETECTED','TRIAGED') AND confidence>=70
		 ORDER BY confidence DESC, created_at ASC LIMIT ?`, targetID, limit)
	if err != nil {
		return
	}
	var cands []sqlmapCandidate
	for rows.Next() {
		var c sqlmapCandidate
		if rows.Scan(&c.id, &c.url, &c.method, &c.param, &c.loc, &c.subtype, &c.conf) == nil {
			cands = append(cands, c)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		logFn("warn", "verify", "Unable to load the complete sqlmap candidate set: "+err.Error())
		return
	}
	rows.Close()
	if len(cands) == 0 {
		return
	}
	first := VulnerabilityCandidate{Type: "sqli"}
	if ctx.Err() != nil || !verifier.CanVerify(first) {
		return
	}
	workers := sqlmapVerificationWorkers(s.cfg, len(cands))
	logFn("info", "verify", fmt.Sprintf("sqlmap proof pass on %d SQLi candidate(s), %d bounded worker(s)...", len(cands), workers))

	var confirmed atomic.Int64
	processed := runSQLmapCandidates(ctx, cands, workers, func(c sqlmapCandidate) {
		vc := VulnerabilityCandidate{ID: c.id, TargetID: targetID, Type: "sqli", Subtype: c.subtype,
			URL: c.url, Method: c.method, Parameter: c.param, Location: c.loc}
		r := verifier.Verify(ctx, vc)
		if ctx.Err() != nil {
			return // cancelled sqlmap output is not a meaningful verification result
		}
		if _, err := RecordCandidateResult(ctx, s.db, vc, r, FindingMeta{Actor: "sqlmap"}); err != nil {
			logFn("warn", "verify", fmt.Sprintf("sqlmap result for %s could not be persisted and remains eligible for retry: %v", c.url, err))
			return
		}
		if r.Verdict == VerifyVerified {
			confirmed.Add(1)
			logFn("warn", "verify", fmt.Sprintf("SQLi CONFIRMED by sqlmap: %s param=%s", c.url, c.param))
		}
	})
	if ctx.Err() != nil && processed < len(cands) {
		logFn("info", "verify", fmt.Sprintf("sqlmap proof pass cancelled after %d/%d candidate(s); unprocessed candidates remain eligible for resume.", processed, len(cands)))
	} else {
		logFn("info", "verify", fmt.Sprintf("sqlmap proof pass complete: processed %d candidate(s), confirmed %d.", processed, confirmed.Load()))
	}
}

// verifyReflectedXSS runs the context-aware reflected-XSS verifier over reflected
// parameters. Only an EXECUTABLE reflection becomes a finding; a safely-encoded
// reflection is explicitly REJECTED (recorded as a candidate, not a finding).
func (s *VerifyScanner) verifyReflectedXSS(ctx context.Context, targetID string, logFn LogFunc) {
	// Native XSS/DOM has already tested the complete surface. This final verifier
	// should resolve only reflected points that remain non-terminal; re-running a
	// full Chromium ladder over CONFIRMED/REJECTED params (and 120 raw-negative
	// params) duplicated the most expensive part of the scan. DOM-only discovery is
	// owned by the signal-driven browser pass in DAST/VerifyDOMXSSOnPages.
	limit := 60
	if getXSSBrowser() != nil {
		limit = 120
	}
	query := `SELECT DISTINCT p.url, p.parameter FROM parameters p
		WHERE p.target_id=? AND COALESCE(p.is_reflected,0)=1
		  AND NOT EXISTS (
			SELECT 1 FROM candidates c
			WHERE c.target_id=p.target_id AND c.type='xss'
			  AND c.url=p.url AND COALESCE(c.parameter,'')=p.parameter
			  AND c.status IN ('CONFIRMED','REJECTED','DUPLICATE')
		  )
		LIMIT ?`
	rows, err := s.db.QueryContext(ctx, query, targetID, limit)
	if err != nil {
		return
	}
	type pp struct{ url, param string }
	var pts []pp
	for rows.Next() {
		var p pp
		if rows.Scan(&p.url, &p.param) == nil && p.param != "" {
			pts = append(pts, p)
		}
	}
	rows.Close()
	if len(pts) == 0 {
		return
	}
	verifier := NewXSSContextVerifier(nil)
	confirmed := 0
	// Browser confirmation is expensive (a handful of real page loads per
	// parameter, up to 12s each on a slow host). Across 120 candidates that could
	// run for hours and make the whole scan look "stuck on xss". Cap the phase at a
	// wall-clock budget when a browser is in play; the browserless verifier alone
	// has no such cost so it runs the full set.
	var deadline time.Time
	if getXSSBrowser() != nil {
		deadline = time.Now().Add(8 * time.Minute)
	}
	tested := 0
	for _, p := range pts {
		if ctx.Err() != nil {
			break
		}
		if !deadline.IsZero() && time.Now().After(deadline) {
			logFn("info", "verify", fmt.Sprintf("Browser-XSS phase hit its %d-minute budget after %d/%d parameter(s); moving on.", 8, tested, len(pts)))
			break
		}
		tested++
		c := VulnerabilityCandidate{TargetID: targetID, Type: "xss", Subtype: "reflected",
			URL: p.url, Method: "GET", Parameter: p.param, Location: "query",
			DetectionSource: "internal", DetectionMethod: "reflection", Severity: "high"}
		r := verifier.Verify(ctx, c)
		if r.Verdict == VerifyVerified {
			c.Payload = contextPayloadFor(r.Evidence)
		}
		_, _ = RecordCandidateResult(ctx, s.db, c, r, FindingMeta{Actor: "xss-context"})
		if r.Verdict == VerifyVerified {
			confirmed++
		}
	}
	if confirmed > 0 {
		logFn("warn", "verify", fmt.Sprintf("Reflected XSS CONFIRMED on %d parameter(s) via context analysis.", confirmed))
	}
}

// verifyNucleiCandidates re-proves nuclei's verifiable hits (sqli/xss/open-
// redirect) with Reconner's own deterministic verifiers before they count as
// findings — nuclei's matchers are precise but not infallible, and a template
// that only proved reflection (not execution) or a redirect that stays same-
// origin is a false positive we must not report. A VERIFIED hit is promoted into
// the main vuln_findings (so it reaches the report with real proof); a REJECTED
// one is marked rejected on the nuclei row and demoted to a candidate; an
// INCONCLUSIVE one is kept but flagged. Non-verifiable classes are left untouched.
func (s *VerifyScanner) verifyNucleiCandidates(ctx context.Context, targetID string, logFn LogFunc) {
	// lfi/ssrf added: both already have a deterministic signature check (the
	// same ones the native lfi.go/ssrf.go findings replay through reVerifiable
	// below) — nuclei's own LFI/SSRF templates previously got NO independent
	// re-proof at all despite that machinery already existing.
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, type, url, method, parameter, location, severity, confidence FROM candidates
		 WHERE target_id=? AND detection_source='nuclei'
		   AND type IN ('sqli','xss','open_redirect','lfi','ssrf')
		   AND status IN ('DETECTED','TRIAGED') LIMIT 100`, targetID)
	if err != nil {
		return
	}
	type cand struct {
		id, typ, url, method, param, loc, sev string
		conf                                  int
	}
	var cands []cand
	for rows.Next() {
		var c cand
		if rows.Scan(&c.id, &c.typ, &c.url, &c.method, &c.param, &c.loc, &c.sev, &c.conf) == nil {
			cands = append(cands, c)
		}
	}
	rows.Close()
	if len(cands) == 0 {
		return
	}

	// Shared verifiers (built once). sqlmap needs the target domain + identity.
	var domain string
	authHeaders := map[string]string{}
	var origins []string
	_ = s.db.QueryRow(`SELECT domain FROM targets WHERE id=?`, targetID).Scan(&domain)
	for _, id := range LoadIdentities(ctx, s.db, targetID, secret.New(s.cfg.SessionSecret)) {
		if id.Origin != "" {
			origins = append(origins, id.Origin)
		}
		if id.IsBaseline {
			for k, v := range id.Headers {
				authHeaders[k] = v
			}
		}
	}
	xssV := NewXSSContextVerifier(nil)
	var sqlmapV *SQLmapVerifier
	if s.cfg != nil && s.cfg.EnableSQLmap {
		sqlmapV = NewSQLmapVerifier(s.exec, s.cfg, s.logger, domain, origins, authHeaders)
		sqlmapV.db = s.db
	}

	verified, rejected := 0, 0
	for _, c := range cands {
		if ctx.Err() != nil {
			break
		}
		vc := VulnerabilityCandidate{ID: c.id, TargetID: targetID, Type: c.typ, URL: c.url,
			Method: c.method, Parameter: c.param, Location: c.loc, DetectionSource: "nuclei"}

		var r VerifyResult
		switch c.typ {
		case "xss":
			if c.param == "" {
				continue // nothing to drive the context verifier with
			}
			r = xssV.Verify(ctx, vc)
		case "sqli":
			if sqlmapV == nil || !sqlmapV.CanVerify(vc) {
				continue // sqlmap off/unavailable → leave nuclei hit as-is
			}
			r = sqlmapV.Verify(ctx, vc)
		case "open_redirect":
			r = verifyNucleiOpenRedirect(c.url, c.param)
		case "lfi":
			r = verifyNucleiSignatureReplay(c.url, "lfi-replay", reVerifiable["lfi"])
		case "ssrf":
			r = verifyNucleiSignatureReplay(c.url, "ssrf-replay", reVerifiable["ssrf"])
		default:
			continue
		}

		vc.ID = c.id
		vc.Severity = c.sev
		if _, err := RecordCandidateResult(ctx, s.db, vc, r, FindingMeta{Actor: "nuclei"}); err != nil {
			continue
		}
		switch r.Verdict {
		case VerifyVerified:
			s.markNucleiVerification(targetID, c.url, "verified", r.Confidence)
			verified++
		case VerifyRejected:
			s.markNucleiVerification(targetID, c.url, "rejected", 0)
			rejected++
		default:
			s.markNucleiVerification(targetID, c.url, "inconclusive", c.conf)
		}
	}
	if verified > 0 || rejected > 0 {
		logFn("warn", "verify", fmt.Sprintf("Nuclei verification: %d confirmed, %d rejected as false positives.", verified, rejected))
	}
}

// verifyNucleiOpenRedirect re-proves an open-redirect nuclei hit by actually
// following the injected redirect chain: an external final destination is
// VERIFIED, a same-origin/relative redirect is REJECTED (nuclei's redirect
// templates commonly fire on harmless same-site redirects), and no parameter to
// test is INCONCLUSIVE.
func verifyNucleiOpenRedirect(rawURL, param string) VerifyResult {
	if param == "" {
		return VerifyResult{Verdict: VerifyInconclusive, Reason: "no query parameter to test", Method: "redirect-replay"}
	}
	res, ok := checkOpenRedirectURL(rawURL, param)
	if !ok {
		return VerifyResult{Verdict: VerifyRejected, Reason: "no redirect reproduced on replay", Method: "redirect-replay"}
	}
	if res.class == redirectExternal {
		return VerifyResult{Verdict: VerifyVerified, Confidence: 90, Method: "redirect-replay",
			Evidence: "external redirect proven: " + res.finalLoc + "\n" + res.chain}
	}
	return VerifyResult{Verdict: VerifyRejected, Reason: "redirect stays same-origin (not exploitable)", Method: "redirect-replay"}
}

// verifyNucleiSignatureReplay re-requests a nuclei-matched URL (which for a
// query-based LFI/SSRF template already carries the payload in the URL
// itself) and checks it against the SAME deterministic signature nuclei
// matched on (shared with the native lfi.go/ssrf.go replay verifiers via
// reVerifiable). Reproduces → VERIFIED; doesn't → REJECTED (nuclei's own
// match was likely transient/WAF-mangled); a request error is never treated
// as a rejection — that would punish a network hiccup, not the finding.
func verifyNucleiSignatureReplay(rawURL, method string, check func(string) bool) VerifyResult {
	if check == nil || rawURL == "" {
		return VerifyResult{Verdict: VerifyInconclusive, Reason: "no signature check available", Method: method}
	}
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return VerifyResult{Verdict: VerifyInconclusive, Reason: "invalid matched URL", Method: method}
	}
	resp, err := verifyClient.Do(req)
	if err != nil {
		return VerifyResult{Verdict: VerifyInconclusive, Reason: "replay request failed: " + err.Error(), Method: method}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if check(string(body)) {
		return VerifyResult{Verdict: VerifyVerified, Confidence: 96, Method: method,
			Evidence: "signature reproduced on replay of the matched URL"}
	}
	return VerifyResult{Verdict: VerifyRejected, Reason: "signature did not reproduce on replay", Method: method}
}

// markNucleiVerification records the verifier verdict on the matching nuclei_findings
// row(s) so the UI/report can hide rejected false positives and surface proven ones.
func (s *VerifyScanner) markNucleiVerification(targetID, matchedURL, verification string, confidence int) {
	_, _ = s.db.Exec(`UPDATE nuclei_findings SET verification=?, confidence=? WHERE target_id=? AND matched_url=?`,
		verification, confidence, targetID, matchedURL)
}

// contextPayloadFor pulls the example payload out of the verifier evidence line
// so the finding carries an exact executable payload.
func contextPayloadFor(evidence string) string {
	for _, prefix := range []string{"Executable payload: ", "Executable payload example: "} {
		if i := strings.Index(evidence, prefix); i >= 0 {
			payload := evidence[i+len(prefix):]
			if end := strings.Index(payload, " | "); end >= 0 {
				payload = payload[:end]
			}
			return strings.TrimSpace(payload)
		}
	}
	return `<svg onload=alert(document.domain)>`
}

var verifyClient = newPooledClient(15*time.Second, false)

// baseConfidence reflects HOW a finding was detected. Signature-confirmed and
// server-side-evaluated classes are near-certain; heuristic/passive ones lower.
var baseConfidence = map[string]int{
	"ssti":                     90,
	"csti":                     99,
	"lfi":                      90,
	"ssrf":                     88,
	"command_injection":        88,
	"sqli":                     75,
	"xss":                      70,
	"subdomain_takeover":       85,
	"open_bucket":              85,
	"jwt_weak_secret":          95,
	"jwt_alg_none":             70,
	"graphql_introspection":    90,
	"api_spec_exposed":         85,
	"exposed_git":              92,
	"exposed_svn":              88,
	"exposed_hg":               85,
	"spring_heapdump_exposed":  95,
	"spring_actuator_env":      90,
	"laravel_env_exposed":      95,
	"laravel_ignition_exposed": 70,
	"nextjs_image_ssrf":        90,
	"wordpress_user_enum":      85,
	"cache_deception":          55,
	"prototype_pollution":      60,
	"403_bypass":               55,
	"host_header_injection":    50,
	"cors":                     60,
	"open_redirect":            70,
	"crlf":                     65,
	// newer modules — sensible confidence floors (never downgraded below the
	// value the module itself computed; see Run()).
	"nosql_injection":             80,
	"cache_poisoning":             80,
	"origin_ip_disclosure":        70,
	"exposed_backup":              90,
	"request_smuggling":           75,
	"dom_xss":                     92,
	"stored_xss":                  90,
	"blind_xss":                   95,
	"blind_ssrf":                  92,
	"blind_rce":                   95,
	"blind_sqli":                  98,
	"blind_xxe":                   90,
	"xxe":                         90,
	"idor":                        72,
	"race_condition":              45,
	"jwt_alg_confusion_candidate": 55,
	"jwt_jku_header":              80,
	"jwt_x5u_header":              80,
	"jwt_kid_injectable":          55,
	"jwt_sensitive_claims":        55,
	"jwt_no_expiry":               40,
}

// severityWeight drives the priority score.
var severityWeight = map[string]int{
	"critical": 100, "high": 75, "medium": 50, "low": 25, "info": 10,
}

// reVerifiable maps a finding type to a signature check on a replayed response.
// Only types with a deterministic signature are re-played (SQLi/XSS use timing/
// context and are scored by detection method instead).
var reVerifiable = map[string]func(body string) bool{
	"lfi": func(b string) bool {
		return reEtcPasswd.MatchString(b) || reWinIni.MatchString(b) || reDaemon.MatchString(b)
	},
	"ssti": func(b string) bool {
		return strings.Contains(b, "rcnA49rcnB") || strings.Contains(b, "rcnA7777777rcnB")
	},
	"ssrf": func(b string) bool {
		for _, s := range ssrfMetadataSignatures {
			if s.MatchString(b) {
				return true
			}
		}
		return false
	},
	// Reflection-proof: require the shell-COMPUTED marker (1337 from $((1000+337)))
	// and reject if the un-evaluated literal is present (that would be mere
	// reflection, not execution).
	"command_injection": func(b string) bool {
		return strings.Contains(b, cmdiEchoMarker) && !strings.Contains(b, "$((1000+337))")
	},
}

func (s *VerifyScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "verify", "Verifying findings and computing confidence/priority...")

	rows, err := s.db.QueryContext(ctx, `
		SELECT vf.id, vf.type, vf.severity, vf.url, vf.parameter, vf.payload,
		       COALESCE(p.method,'GET'), COALESCE(vf.confidence,0), COALESCE(vf.status,'finding'),
		       COALESCE(vf.lifecycle,'LEGACY'), COALESCE(vf.candidate_id,'')
		FROM vuln_findings vf
		LEFT JOIN parameters p ON p.target_id = vf.target_id AND p.url = vf.url AND p.parameter = vf.parameter
		WHERE vf.target_id = ?
	`, targetID)
	if err != nil {
		// method join is best-effort; fall back to a plain select
		rows, err = s.db.QueryContext(ctx, `SELECT id, type, severity, url, parameter, payload, 'GET', COALESCE(confidence,0), COALESCE(status,'finding'), COALESCE(lifecycle,'LEGACY'), COALESCE(candidate_id,'') FROM vuln_findings WHERE target_id = ?`, targetID)
		if err != nil {
			return err
		}
	}
	type finding struct {
		id, typ, sev, url, param, payload, method string
		lifecycle, candidateID                    string
		existingConf                              int
		existingStatus                            string
	}
	var findings []finding
	for rows.Next() {
		var f finding
		if err := rows.Scan(&f.id, &f.typ, &f.sev, &f.url, &f.param, &f.payload, &f.method, &f.existingConf, &f.existingStatus, &f.lifecycle, &f.candidateID); err == nil {
			findings = append(findings, f)
		}
	}
	rows.Close()
	if len(findings) == 0 {
		return nil
	}

	auth := loadAuthHeaders(ctx, s.db, targetID)
	reproduced, downgraded := 0, 0

	for _, f := range findings {
		if ctx.Err() != nil {
			break
		}
		// Start from the known baseline for the type, but NEVER downgrade a
		// confidence a module already computed for this finding (e.g. a
		// magic-byte-confirmed backup at 95, an OOB-confirmed blind bug at 100).
		// Only an active re-verification below is allowed to lower it.
		canonicalPending := f.candidateID != "" && f.lifecycle != CandConfirmed && f.lifecycle != CandVerified
		canonicalRejected := f.candidateID != "" && (f.lifecycle == CandRejected || f.lifecycle == CandDuplicate)
		// DOM XSS has a deliberately higher proof bar: legacy rows without a
		// canonical runtime-execution candidate are also pending. A fresh scan can
		// re-confirm them in Chromium; until then they must not carry a green badge.
		if f.typ == "dom_xss" && (f.candidateID == "" || (f.lifecycle != CandConfirmed && f.lifecycle != CandVerified)) {
			canonicalPending = true
		}
		if canonicalRejected {
			_, _ = s.db.Exec(`UPDATE vuln_findings SET confidence=0, priority=0, status='rejected' WHERE id=?`, f.id)
			continue
		}
		conf := baseConfidence[f.typ]
		// The lifecycle is authoritative. A scorer must never turn DETECTED static
		// analysis into a finding merely because a type-wide confidence floor is
		// high (this was promoting unexecuted DOM-XSS JS leads to green findings).
		if canonicalPending {
			conf = f.existingConf
		}
		if f.existingConf > conf {
			conf = f.existingConf
		}
		if conf == 0 {
			conf = 40 // truly unknown/heuristic type with no prior score
		}

		replayed := false

		// Re-verify replayable classes by replaying the payload — this is an
		// active check, so it is authoritative (may raise to 99 or lower to 45).
		if check, ok := reVerifiable[f.typ]; ok && f.payload != "" && f.param != "" {
			ip := insertionPoint{URL: f.url, Param: f.param, Method: f.method}
			body, _ := sendInjected(ctx, verifyClient, ip, f.payload, auth)
			replayed = true
			if body != "" && check(body) {
				conf = 99
				reproduced++
			} else {
				conf = 45 // did not reproduce → likely transient FP
				downgraded++
			}
		}

		// Status by the spec's confidence bands: >=90 is a confirmed Finding,
		// anything lower is a Candidate (kept, but out of the Findings view and
		// severity counts). This automatically routes noisy heuristic classes
		// (403-bypass, CORS, host-header, CRLF, prototype-pollution, jwt-no-exp…)
		// to Candidates while a replay-confirmed bug stays a Finding.
		status := StatusCandidate
		if conf >= ConfEvidence && !canonicalPending {
			status = StatusFinding
		}
		if replayed && conf == 45 {
			status = StatusCandidate
		}

		priority := severityWeight[strings.ToLower(f.sev)] * conf / 100

		_, _ = s.db.Exec(`UPDATE vuln_findings SET confidence = ?, priority = ?, status = ? WHERE id = ?`, conf, priority, status, f.id)
	}

	logFn("info", "verify", fmt.Sprintf("Verification done. %d findings re-confirmed, %d downgraded, %d scored.",
		reproduced, downgraded, len(findings)))

	// SQLmap proof pass (opt-in): PROVE strong internal SQLi candidates. A positive
	// sqlmap injection promotes the finding to sqlmap-confirmed; a non-positive run
	// is INCONCLUSIVE (never downgraded to "not vulnerable").
	if s.cfg != nil && s.cfg.EnableSQLmap {
		s.verifySQLiWithSQLmap(ctx, targetID, logFn)
	}

	// Reflected-XSS context proof: deterministically confirm/reject reflected
	// parameters by whether breakout chars survive UNENCODED in an executable
	// context (kills the "reflected == XSS" false positive).
	s.verifyReflectedXSS(ctx, targetID, logFn)

	// Nuclei intelligence: re-prove nuclei's verifiable hits (sqli/xss/open-
	// redirect) so a template that only proved reflection or a same-origin
	// redirect is REJECTED, and a genuinely exploitable one is promoted into the
	// findings/report with real proof.
	if s.cfg == nil || s.cfg.NucleiVerify {
		s.verifyNucleiCandidates(ctx, targetID, logFn)
	}

	// Correlate/dedup: group findings by root cause (type + endpoint template) so
	// N affected resources collapse into one root issue (evidence preserved).
	if groups := CorrelateFindings(ctx, s.db, targetID); groups > 0 {
		logFn("info", "verify", fmt.Sprintf("Correlation: %d root issue group(s) across the findings.", groups))
	}
	return nil
}
