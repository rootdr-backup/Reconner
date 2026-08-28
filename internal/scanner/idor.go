package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/secret"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

// IDORScanner detects Insecure Direct Object Reference / Broken Access Control —
// the highest-value, hardest-to-automate bug class. Without a second account we
// cannot prove object ownership, so the detection is differential and
// conservative:
//
//   - It finds endpoints carrying an enumerable identifier (a numeric path
//     segment like /orders/1052, or a numeric/id-ish parameter).
//   - It fetches the baseline object, then neighbouring IDs (±1, ±2) with the
//     SAME session. IDOR is flagged only when a neighbour returns 200 with a
//     DISTINCT but structurally-similar object (same content-type, comparable
//     size, different body, not an error page) — i.e. you just read a different
//     record by changing the ID.
//   - If per-target auth headers are configured, it additionally re-requests the
//     readable neighbour WITHOUT auth. If that still returns the object, it's a
//     missing-authentication / broken-access-control bug and is escalated.
//
// Findings carry an honest confidence (70) and evidence listing which IDs were
// readable, because single-account differential testing strongly indicates but
// cannot fully prove horizontal IDOR — the human confirms ownership.
type IDORScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewIDORScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *IDORScanner {
	return &IDORScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

var idorClient = newPooledClient(12*time.Second, false)

// lastNumericSegment matches a numeric path segment (>=2 digits) so /api/user/1052 is enumerable.
var lastNumericSegment = regexp.MustCompile(`^(.*/)(\d{2,})(/?[^/]*)$`)

// errorish signatures that mean "access controlled / not a real object".
var idorErrorSignatures = []string{
	"not found", "forbidden", "access denied", "unauthorized", "permission",
	"404", "403", "401", "please log in", "sign in", "login required",
}

type idorTarget struct {
	kind     string // "path" | "param"
	template string // path template with %d, or base URL for param
	param    string // for param kind
	baseID   int64
}

func (s *IDORScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	// Authorization testing needs identities. Load the first-class identity
	// registry (falls back to the legacy single auth_headers blob). Without at
	// least one identity we can't tell a real IDOR from public content, so skip.
	identities := LoadIdentities(ctx, s.db, targetID, secret.New(s.cfg.SessionSecret))
	if len(identities) == 0 {
		logFn("info", "idor", "IDOR skipped — no identities configured. Add User A (+ optionally User B) to arm cross-identity BOLA testing.")
		return nil
	}
	baseline, _ := baselineIdentity(identities)
	// Any non-baseline identity becomes the "attacker" B for cross-identity BOLA.
	var attacker *Identity
	for i := range identities {
		if !identities[i].IsBaseline {
			attacker = &identities[i]
			break
		}
	}
	if attacker != nil {
		logFn("info", "idor", fmt.Sprintf("Cross-identity BOLA armed: baseline=%q attacker=%q — proving one user can read another's objects.", baseline.Label, attacker.Label))
	} else {
		logFn("info", "idor", "Single-identity IDOR (heuristic). Add a second identity (User B) for provable cross-user BOLA.")
	}

	// PRIMARY path: selecting IDOR triggers a Deep Authenticated Authorization
	// Crawl. With two identities Reconner crawls the app independently as each user
	// from the target ORIGIN — no prior browsing/captured traffic required.
	if attacker != nil {
		n := s.runAuthzCrawlPipeline(ctx, targetID, baseline, *attacker, logFn)
		logFn("info", "idor", fmt.Sprintf("Deep authenticated authorization crawl produced %d confirmed finding(s).", n))
	}

	targets := s.collectTargets(ctx, targetID)
	if len(targets) == 0 {
		if attacker == nil {
			logFn("info", "idor", "No enumerable object identifiers found for IDOR testing")
		}
		return nil
	}
	logFn("info", "idor", fmt.Sprintf("Additional source: testing %d ID-bearing endpoint(s) from recorded traffic...", len(targets)))

	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(t idorTarget) {
			defer wg.Done()
			defer func() { <-sem }()
			var hit bool
			if attacker != nil {
				hit = s.testCrossIdentity(ctx, targetID, t, baseline, *attacker, logFn)
			} else {
				hit = s.testTarget(ctx, targetID, t, baseline.Headers, logFn)
			}
			if hit {
				found.Add(1)
			}
		}(t)
	}
	wg.Wait()
	logFn("info", "idor", fmt.Sprintf("IDOR done. %d access-control issue(s).", found.Load()))
	return nil
}

// testCrossIdentity performs a PROVABLE BOLA check: the baseline user owns an
// object; the attacker identity fetches that SAME object URL. If the attacker
// receives the baseline's object (same substantial body) while an unauthenticated
// request is denied, that is confirmed cross-user object access — the gold
// standard evidence a bug-bounty report needs. Confidence 95 (multi-identity).
func (s *IDORScanner) testCrossIdentity(ctx context.Context, targetID string, t idorTarget, baseline, attacker Identity, logFn LogFunc) bool {
	url := t.buildURL(t.baseID)

	// 1) baseline must actually own a real object here.
	owner := fetchAs(ctx, url, &baseline)
	if !looksLikeAuthObject(owner) {
		return false
	}
	// 2) the object must be access-controlled: unauth must be denied.
	unauth := fetchAs(ctx, url, nil)
	if !deniesAccess(unauth) {
		return false // public data, not an authz bug
	}
	if publicResourceLikely(owner, unauth) {
		return false
	}
	writeHit := s.testCrossIdentityMethods(ctx, targetID, url, t.param, baseline, attacker, owner, logFn)
	// 3) the attacker (different user) reads the SAME url.
	att := fetchAs(ctx, url, &attacker)
	// Record the canonical interactions (request-intelligence layer).
	RecordInteraction(ctx, s.db, targetID, CanonRequest{Method: "GET", URL: url, IdentityLabel: baseline.Label, Scanner: "idor"},
		CanonResponse{Status: owner.Status, CT: owner.CT, Len: owner.Len, Body: owner.Body})
	RecordInteraction(ctx, s.db, targetID, CanonRequest{Method: "GET", URL: url, IdentityLabel: attacker.Label, Scanner: "idor"},
		CanonResponse{Status: att.Status, CT: att.CT, Len: att.Len, Body: att.Body})
	if !looksLikeAuthObject(att) {
		return writeHit // attacker's READ denied; a write finding may still stand
	}
	// 4) prove the attacker got the OWNER'S object, not their own equivalent:
	// require a strong body match (identical, or near-identical length + shared
	// object fingerprint). Different-but-both-200 could be each user's own object.
	if !bodiesSameObject(owner.Body, att.Body) {
		return writeHit
	}

	evidence := fmt.Sprintf(
		"CONFIRMED BOLA / cross-user object access at %s (param %s). "+
			"Owner identity %q: HTTP %d, %dB object. Unauthenticated: denied (proves access control exists). "+
			"Attacker identity %q: HTTP %d, %dB — returned the OWNER'S object (bodies match). "+
			"A different authenticated user can read another user's object by its identifier.",
		url, t.param, baseline.Label, owner.Status, owner.Len, attacker.Label, att.Status, att.Len)

	findingID := s.store(targetID, "idor", "critical", url, t.param, evidence, 95)
	// Structured, redacted, reproducible evidence: the full per-identity matrix.
	StoreEvidence(ctx, s.db, findingID, targetID, "cross_identity",
		"Expected: attacker denied. Actual: attacker received the owner's object. Comparison: bodies match (same object).",
		[]EvidenceItem{
			withComparison(evidenceFromResponse("GET", url, baseline, owner), "OWNER — baseline user's own object (authorized)"),
			withComparison(evidenceFromResponse("GET", url, Identity{Label: "unauthenticated"}, unauth), "CONTROL — no session: access denied (proves the resource is protected)"),
			withComparison(evidenceFromResponse("GET", url, attacker, att), "ATTACKER — different user received the OWNER'S object (BOLA)"),
		})
	logFn("warn", "idor", fmt.Sprintf("BOLA CONFIRMED [critical]: %s — %q read %q's object", url, attacker.Label, baseline.Label))
	if s.broadcast != nil {
		s.broadcast("new_vuln_finding", map[string]any{
			"target_id": targetID, "type": "idor", "url": url, "parameter": t.param,
		})
	}
	return true
}

// testCrossIdentityMethods runs the two-identity METHOD differential on one object
// (BFLA), each success confirmed by an owner-side post-condition read.
func (s *IDORScanner) testCrossIdentityMethods(ctx context.Context, targetID, url, param string,
	baseline, attacker Identity, ownerResp IdentityResponse, logFn LogFunc) bool {
	prof := ParseAuthzProfile(s.cfg.AuthzMode)
	if !prof.allowsWrite() {
		return false
	}
	safeBody, contentType := "", ""
	if strings.Contains(strings.ToLower(ownerResp.CT), "json") && len(ownerResp.Body) > 0 && len(ownerResp.Body) < 64*1024 {
		safeBody, contentType = ownerResp.Body, "application/json"
	}
	ownerRefs := extractObjectRefs(url, ownerResp.CT, ownerResp.Body, nil)
	results := crossUserMethodDifferential(ctx, url, baseline, attacker,
		[]string{"PUT", "PATCH", "POST", "DELETE"}, prof, s.cfg.AuthzDestructive, ownerRefs, safeBody, contentType)
	stored := false
	for _, r := range results {
		if !r.Vulnerable || r.Confidence < ConfEvidence {
			continue
		}
		sev := "high"
		if r.WriteVerified {
			sev = "critical"
		}
		evidence := fmt.Sprintf("CONFIRMED broken function-level authorization (BFLA) at %s. Owner %q holds the object; "+
			"unauthenticated access is denied. Attacker %q issued %s and it was accepted (%s). %s",
			url, baseline.Label, attacker.Label, r.Method,
			map[bool]string{true: "owner-side post-condition CONFIRMS the state change", false: "not confirmed by post-condition"}[r.WriteVerified], r.Evidence)
		findingID := s.store(targetID, "idor", sev, url, param+" ["+r.Method+"]", evidence, r.Confidence)
		StoreEvidence(ctx, s.db, findingID, targetID, "cross_identity_method",
			authzReproSteps(r.Method, url, baseline.Label, attacker.Label, "", true),
			[]EvidenceItem{
				withComparison(evidenceFromResponse("GET", url, baseline, ownerResp), "OWNER — holds the object (authorized)"),
				withComparison(EvidenceItem{IdentityLabel: attacker.Label,
					Request: r.Method + " " + url + " HTTP/1.1  (attacker session; secret headers redacted)", Response: r.Evidence},
					"ATTACKER — a DIFFERENT user's "+r.Method+" was accepted (BFLA)")})
		logFn("warn", "idor", fmt.Sprintf("BFLA CONFIRMED [%s]: %s — %q performed %s on %q's object", sev, url, attacker.Label, r.Method, baseline.Label))
		stored = true
	}
	return stored
}

// runAuthzCrawlPipeline drives the Deep Authenticated Authorization Crawl and
// persists findings. Seeds: target origin + identity origins (primary); recorded
// http_services roots are an OPTIONAL extra source.
func (s *IDORScanner) runAuthzCrawlPipeline(ctx context.Context, targetID string, baseline, attacker Identity, logFn LogFunc) int {
	var domain string
	_ = s.db.QueryRowContext(ctx, `SELECT COALESCE(domain,'') FROM targets WHERE id = ?`, targetID).Scan(&domain)
	origins := []string{}
	seen := map[string]bool{}
	addOrigin := func(o string) {
		o = strings.TrimSpace(o)
		if o != "" && !seen[o] {
			seen[o] = true
			origins = append(origins, o)
		}
	}
	if domain != "" {
		addOrigin("https://" + domain)
		addOrigin("http://" + domain)
	}
	addOrigin(baseline.Origin)
	addOrigin(attacker.Origin)
	seeds := append([]string{}, origins...)
	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services WHERE target_id = ? AND status_code BETWEEN 200 AND 399
		ORDER BY url LIMIT 25`, targetID)
	if err == nil {
		for rows.Next() {
			var u string
			if rows.Scan(&u) == nil {
				seeds = append(seeds, u)
			}
		}
		rows.Close()
	}
	if len(seeds) == 0 {
		logFn("info", "idor", "Deep authz crawl skipped — no target origin/scope available.")
		return 0
	}
	res := RunAuthzPipeline(ctx, AuthzPipelineInput{
		TargetDomain: domain, Origins: origins, Seeds: seeds,
		IdentityA: &baseline, IdentityB: &attacker,
		Profile: ParseAuthzProfile(s.cfg.AuthzMode), Destructive: s.cfg.AuthzDestructive,
		Log: func(stage, msg string) { logFn("info", "idor:authz", stage+": "+msg) }})
	confirmed := 0
	for _, f := range res.Findings {
		param := f.VictimObject
		if f.Method != "" && f.Method != "GET" {
			param += " [" + f.Method + "]"
		}
		findingID := s.store(targetID, "idor", f.Severity, f.URL, param, f.Evidence+"\n\n"+f.Repro, f.Confidence)
		StoreEvidence(ctx, s.db, findingID, targetID, "deep_authz_crawl",
			fmt.Sprintf("Discovered from: %s. Owner=%s Attacker=%s.", f.DiscoverySource, f.OwnerLabel, f.AttackerLabel),
			[]EvidenceItem{{IdentityLabel: f.AttackerLabel, Request: f.Method + " " + f.URL, Response: f.Evidence, Comparison: f.Repro}})
		if f.Status == StatusFinding {
			confirmed++
			if s.broadcast != nil {
				s.broadcast("new_vuln_finding", map[string]any{"target_id": targetID, "type": "idor", "url": f.URL, "parameter": param})
			}
		}
	}
	logFn("info", "idor", fmt.Sprintf("Authz pipeline: A=%d req, B=%d req, %d objects (%d owned), %d pairs, %d tests, %d findings, %d candidates, %d FP suppressed.",
		res.Stats.ACrawled, res.Stats.BCrawled, res.Stats.Objects, res.Stats.Ownerships,
		res.Stats.PairsGenerated, res.Stats.TestsExecuted, res.Stats.Findings, res.Stats.Candidates, res.Stats.FPSuppressed))
	return confirmed
}

// bodiesSameObject reports whether two response bodies represent the same
// underlying object: identical, or same length with a high shared-token overlap.
func bodiesSameObject(a, b string) bool {
	if a == b {
		return true
	}
	// length within 2% and both non-trivial → likely the same object with a
	// volatile field (timestamp/csrf). Cheap fingerprint: compare a trimmed core.
	la, lb := len(a), len(b)
	if la == 0 || lb == 0 {
		return false
	}
	diff := la - lb
	if diff < 0 {
		diff = -diff
	}
	if diff*50 > la { // >2% length difference → different object
		return false
	}
	// Mask volatile fields (rotating csrf/nonce/token/timestamps) so they don't
	// count as content differences, then compare the bodies in equal CHUNKS. The
	// SAME object differs in only a few localized spots; two DIFFERENT objects that
	// merely share a page template (header/nav/footer) differ across MANY chunks.
	// Requiring a high fraction of identical chunks fixes the template-collision
	// false positive the previous PREFIX-ONLY comparison produced — e.g. two users'
	// profile pages that share the chrome but hold different personal data would
	// match on their common header and be wrongly reported as one BOLA object.
	na, nb := blurVolatile(a), blurVolatile(b)
	if na == nb {
		return true
	}
	n := len(na)
	if len(nb) < n {
		n = len(nb)
	}
	const chunks = 16
	csz := n / chunks
	if csz == 0 {
		return false // too small to chunk, and not equal after blurring
	}
	match := 0
	for i := 0; i < chunks; i++ {
		s := i * csz
		if na[s:s+csz] == nb[s:s+csz] {
			match++
		}
	}
	return match >= 14 // ≥ ~87% identical (tolerates a couple of localized diffs)
}

// allSameBody reports whether every body in the slice is byte-identical to the
// first — the signature of one generic template (soft-404 / empty state) served
// for multiple IDs rather than a distinct object per ID.
func allSameBody(bodies []string) bool {
	for i := 1; i < len(bodies); i++ {
		if bodies[i] != bodies[0] {
			return false
		}
	}
	return len(bodies) > 0
}

func (s *IDORScanner) testTarget(ctx context.Context, targetID string, t idorTarget, auth map[string]string, logFn LogFunc) bool {
	baseURL := t.buildURL(t.baseID)
	baseStatus, baseCT, baseBody := s.fetch(ctx, baseURL, auth)
	// Baseline must be a real, substantial object response.
	if baseStatus != 200 || len(baseBody) < 120 || isStaticCT(baseCT) || matchAny(strings.ToLower(baseBody), idorErrorSignatures) != "" {
		return false
	}
	baseLen := len(baseBody)

	// Gate on the resource being AUTH-PROTECTED: fetch the baseline WITHOUT the
	// session. If it's still readable (200 object), the data is public — that is
	// NOT an IDOR, so we skip it. We only proceed when removing the session
	// breaks access (401/403/redirect/empty/error), proving auth is required.
	uStatus, _, uBody := s.fetch(ctx, baseURL, nil)
	publicallyReadable := uStatus == 200 && len(uBody) >= 80 &&
		matchAny(strings.ToLower(uBody), idorErrorSignatures) == ""
	if publicallyReadable {
		return false // public content, not authenticated IDOR
	}

	var readable []string
	var neighborBodies []string
	for _, nid := range neighbors(t.baseID) {
		if ctx.Err() != nil {
			break
		}
		nURL := t.buildURL(nid)
		st, ct, body := s.fetch(ctx, nURL, auth)
		if !idorObjectLike(st, ct, body, baseCT, baseLen) {
			continue
		}
		if body == baseBody {
			continue // same object returned regardless of ID → not IDOR (static)
		}
		readable = append(readable, fmt.Sprintf("%d(%dB)", nid, len(body)))
		neighborBodies = append(neighborBodies, body)
	}

	if len(readable) == 0 {
		return false
	}

	// Soft-404 / empty-state guard: if EVERY readable neighbour returned the SAME
	// body as the others (differing from baseline but identical to each other), the
	// endpoint is serving one generic page — an "item not found" / empty-state
	// template — for non-existent IDs, NOT a distinct per-user object each time.
	// That is the classic single-account IDOR false positive. Real horizontal IDOR
	// returns genuinely different objects for different IDs, so their bodies differ
	// from one another and this guard does not trip.
	if len(neighborBodies) >= 2 && allSameBody(neighborBodies) {
		return false
	}

	severity, confidence := "high", 75
	evidence := fmt.Sprintf(
		"Authenticated IDOR: %s requires a session (fails without it), yet with YOUR session, changing the object ID returned DISTINCT objects for neighbouring IDs [%s] (baseline ID %d, %dB) — cross-user object access. Verify the objects belong to other users.",
		baseURL, strings.Join(readable, ", "), t.baseID, baseLen)

	s.store(targetID, "idor", severity, baseURL, t.param, evidence, confidence)
	logFn("warn", "idor", fmt.Sprintf("IDOR [%s]: %s (neighbours readable: %s)", severity, baseURL, strings.Join(readable, ", ")))
	if s.broadcast != nil {
		s.broadcast("new_vuln_finding", map[string]any{
			"target_id": targetID, "type": "idor", "url": baseURL, "parameter": t.param,
		})
	}
	return true
}

// collectTargets finds enumerable ID endpoints from services (path IDs) and
// parameters (id-ish params with numeric values).
func (s *IDORScanner) collectTargets(ctx context.Context, targetID string) []idorTarget {
	seen := map[string]bool{}
	var out []idorTarget
	add := func(t idorTarget) {
		key := t.kind + "|" + t.template + "|" + t.param
		if !seen[key] && len(out) < 100 {
			seen[key] = true
			out = append(out, t)
		}
	}

	// Path-based numeric IDs from alive services.
	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services
		WHERE target_id = ? AND status_code BETWEEN 200 AND 399
		ORDER BY url LIMIT ?`, targetID, s.cfg.URLLimit())
	if err == nil {
		for rows.Next() {
			var u string
			if rows.Scan(&u) != nil {
				continue
			}
			if m := lastNumericSegment.FindStringSubmatch(stripQuery(u)); m != nil {
				id, err := strconv.ParseInt(m[2], 10, 64)
				if err == nil && id > 0 && id < 1<<40 {
					add(idorTarget{kind: "path", template: m[1] + "\x00" + m[3], baseID: id})
				}
			}
		}
		rows.Close()
	}

	// Param-based numeric IDs.
	prows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT url, parameter, value FROM parameters
		WHERE target_id = ? LIMIT 400`, targetID)
	if err == nil {
		for prows.Next() {
			var u, p, v string
			if prows.Scan(&u, &p, &v) != nil {
				continue
			}
			// Route via the unified classifier (superset of the old idParamNames
			// exact-match): catches orderId / invoice_id / objectId / uuid-valued
			// refs the literal list missed. A numeric baseID is still required to
			// enumerate neighbours below.
			if !paramProneTo(ClassIDOR, p, v) {
				continue
			}
			id, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil || id <= 0 || id >= 1<<40 {
				continue
			}
			add(idorTarget{kind: "param", template: u, param: p, baseID: id})
		}
		prows.Close()
	}
	return out
}

// buildURL substitutes an ID into the target template.
func (t idorTarget) buildURL(id int64) string {
	if t.kind == "path" {
		parts := strings.SplitN(t.template, "\x00", 2)
		if len(parts) == 2 {
			return parts[0] + strconv.FormatInt(id, 10) + parts[1]
		}
		return t.template
	}
	return injectParam(t.template, t.param, strconv.FormatInt(id, 10))
}

func neighbors(id int64) []int64 {
	cand := []int64{id - 1, id + 1, id - 2, id + 2}
	var out []int64
	for _, c := range cand {
		if c > 0 && c != id {
			out = append(out, c)
		}
	}
	return out
}

func (s *IDORScanner) fetch(ctx context.Context, u string, auth map[string]string) (int, string, string) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", u, nil)
	if err != nil {
		return 0, "", ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
	for k, v := range auth {
		req.Header.Set(k, v)
	}
	resp, err := idorClient.Do(req)
	if err != nil {
		return 0, "", ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()
	return resp.StatusCode, strings.ToLower(resp.Header.Get("Content-Type")), string(body)
}

// idorObjectLike decides whether a neighbour response looks like a valid object
// of the same shape as the baseline (same content-type class, comparable size).
func idorObjectLike(status int, ct, body, baseCT string, baseLen int) bool {
	if status != 200 || len(body) < 80 || isStaticCT(ct) {
		return false
	}
	if ctClass(ct) != ctClass(baseCT) {
		return false
	}
	l := len(body)
	// comparable size band — same endpoint returning different records.
	return float64(l) >= float64(baseLen)*0.25 && float64(l) <= float64(baseLen)*4.0
}

func ctClass(ct string) string {
	switch {
	case strings.Contains(ct, "json"):
		return "json"
	case strings.Contains(ct, "html"):
		return "html"
	case strings.Contains(ct, "xml"):
		return "xml"
	default:
		return "other"
	}
}

func isStaticCT(ct string) bool {
	for _, s := range []string{"image/", "font/", "text/css", "javascript", "octet-stream", "video/", "audio/"} {
		if strings.Contains(ct, s) {
			return true
		}
	}
	return false
}

func (s *IDORScanner) store(targetID, typ, sev, url, param, evidence string, confidence int) string {
	priority := confidence * severityWeightIDOR(sev)
	// Derive status from confidence: a proven cross-identity BOLA (95) is a finding;
	// the single-account differential heuristic (75) — which cannot itself prove the
	// neighbouring objects belong to OTHER users — is only a candidate. Without this
	// the column default ('finding') promoted the heuristic case to a confirmed
	// finding, a steady source of "verify manually" noise in the main findings list.
	status := StatusCandidate
	if confidence >= ConfEvidence {
		status = StatusFinding
	}
	newID := uuid.New().String()
	_, _ = s.db.Exec(`
		INSERT INTO vuln_findings (id, target_id, type, severity, url, parameter, payload, evidence, confidence, priority, status)
		VALUES (?, ?, ?, ?, ?, ?, '', ?, ?, ?, ?)
		ON CONFLICT(target_id, type, url, parameter) DO UPDATE SET
			severity = excluded.severity, evidence = excluded.evidence,
			confidence = excluded.confidence, priority = excluded.priority, status = excluded.status
	`, newID, targetID, typ, sev, url, param, evidence, confidence, priority, status)
	// Resolve the stable finding id (on-conflict keeps the original row id).
	var id string
	_ = s.db.QueryRow(`SELECT id FROM vuln_findings WHERE target_id=? AND type=? AND url=? AND parameter=?`,
		targetID, typ, url, param).Scan(&id)
	if id == "" {
		id = newID
	}
	return id
}

func severityWeightIDOR(sev string) int {
	switch sev {
	case "critical":
		return 5
	case "high":
		return 4
	default:
		return 2
	}
}
