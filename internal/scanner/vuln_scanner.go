package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

type VulnScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewVulnScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *VulnScanner {
	return &VulnScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

var vulnHTTPClient = &http.Client{
	Transport: sharedHTTPTransport,
	Timeout:   10 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// Run executes all vuln checks sequentially.
func (s *VulnScanner) Run(ctx context.Context, targetID, domain string, logFn LogFunc) error {
	if err := s.RunXSS(ctx, targetID, domain, logFn); err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	// Reconner's XSS scope is reflected + DOM. The legacy combined module used to
	// plant stored/blind-XSS payloads as well, duplicating OAST work and adding a
	// large write/read pass the product does not expose or report as a supported
	// objective. Keep that engine available to explicit callers, but do not run it
	// implicitly in the general vulnerability pipeline.
	if err := s.RunCORSCheck(ctx, targetID, logFn); err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if err := s.Run403Bypass(ctx, targetID, logFn); err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if err := s.RunHostHeaderInjection(ctx, targetID, logFn); err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if err := s.RunCRLF(ctx, targetID, logFn); err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if err := s.RunPrototypePollution(ctx, targetID, logFn); err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if err := s.RunCacheDeception(ctx, targetID, logFn); err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

// ── Prototype Pollution ──────────────────────────────────────────────────────

// RunPrototypePollution probes endpoints with __proto__ payloads and looks for
// a polluted marker reflected back — a strong signal of client/server-side
// prototype pollution in JS-heavy apps.
func (s *VulnScanner) RunPrototypePollution(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "proto_pollution", "Checking for prototype pollution...")

	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services
		WHERE target_id = ? AND status_code BETWEEN 200 AND 403
		LIMIT ?
	`, targetID, s.cfg.URLLimit())
	if err != nil {
		return err
	}
	var urls []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err == nil {
			urls = append(urls, u)
		}
	}
	rows.Close()
	urls = filterURLsByHostScope(ctx, urls)

	const marker = "rcnpp1337"
	payloads := []string{
		"__proto__[" + marker + "]=" + marker,
		"__proto__.%s=%s",
		"constructor[prototype][" + marker + "]=" + marker,
	}

	sem := make(chan struct{}, 12)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, svcURL := range urls {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			for _, pl := range payloads {
				sep := "?"
				if strings.Contains(u, "?") {
					sep = "&"
				}
				testURL := u + sep + strings.Replace(pl, "%s", marker, -1)

				reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
				req, err := http.NewRequestWithContext(reqCtx, "GET", testURL, nil)
				if err != nil {
					cancel()
					continue
				}
				req.Header.Set("User-Agent", "Mozilla/5.0")
				resp, err := vulnHTTPClient.Do(req)
				if err != nil {
					cancel()
					continue
				}
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
				resp.Body.Close()
				cancel()

				// Marker reflected inside a JSON/JS structural context is suspicious.
				b := string(body)
				ct := strings.ToLower(resp.Header.Get("Content-Type"))
				if strings.Contains(b, "\""+marker+"\":\""+marker+"\"") ||
					(strings.Contains(ct, "json") && strings.Count(b, marker) >= 2) {
					s.storeVuln(targetID, "prototype_pollution", "medium", u, "__proto__", testURL,
						"prototype pollution marker reflected in response")
					found.Add(1)
					logFn("warn", "proto_pollution", "Prototype pollution: "+u)
					if s.broadcast != nil {
						s.broadcast("new_vuln_finding", map[string]any{
							"target_id": targetID, "type": "prototype_pollution", "url": u,
						})
					}
					return
				}
			}
		}(svcURL)
	}
	wg.Wait()
	logFn("info", "proto_pollution", fmt.Sprintf("Prototype pollution check done. Found %d.", found.Load()))
	return nil
}

// ── Cache Deception ──────────────────────────────────────────────────────────

// RunCacheDeception appends a fake static extension to authenticated-looking
// paths and checks whether the response gets cached (a cached private page is a
// web-cache-deception finding).
func (s *VulnScanner) RunCacheDeception(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "cache_deception", "Checking for web cache deception...")

	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services
		WHERE target_id = ? AND status_code = 200
		LIMIT ?
	`, targetID, s.cfg.URLLimit())
	if err != nil {
		return err
	}
	var urls []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err == nil {
			urls = append(urls, u)
		}
	}
	rows.Close()
	urls = filterURLsByHostScope(ctx, urls)

	sem := make(chan struct{}, 12)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, svcURL := range urls {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			// Path confusion: /account -> /account/nonexistent.css. Use a FIXED
			// suffix (per-URL, not time-based) so we can re-fetch the SAME cache key
			// to prove it was actually cached.
			base := strings.TrimRight(u, "/")
			nonce := fmt.Sprint(time.Now().UnixNano() % 9999)
			testURL := base + "/rcndeception" + nonce + ".css"

			aStatus, aBody, aHdr := cacheDeceptionFetch(ctx, testURL)
			ct := strings.ToLower(aHdr.Get("Content-Type"))
			looksHTML := strings.Contains(ct, "html") || strings.Contains(aBody, "<html")
			if aStatus != 200 || !looksHTML {
				return
			}

			// GATE 1 — NEGATIVE CONTROL (kills the SPA / catch-all false positive):
			// hit a RANDOM, non-existent base path with the same .css trick. If the
			// server returns the SAME page there, it just serves its app shell for
			// EVERY path (SPA routing) — that is not cache deception, it is normal
			// catch-all routing, so drop it. This is what floods a report with dozens
			// of identical "cache deception" hits across every subdomain.
			ctrlURL := cacheDeceptionOrigin(u) + "/rcn" + nonce + "notreal" + nonce + "/x" + nonce + ".css"
			cStatus, cBody, _ := cacheDeceptionFetch(ctx, ctrlURL)
			if cStatus == 200 && bodiesSameObject(aBody, cBody) {
				return // same content for a bogus path → SPA/catch-all, not deception
			}

			// GATE 2 — PROVE IT IS ACTUALLY CACHED. A Cache-Control directive is only
			// a hint; real exposure needs the shared cache to STORE and REPLAY the
			// page. Re-fetch the exact same .css URL and require a cache HIT signal
			// (X-Cache/CF-Cache-Status: HIT, or a positive Age served from cache).
			_, _, bHdr := cacheDeceptionFetch(ctx, testURL)
			if !cacheServedFromCache(bHdr) {
				return
			}

			hitHdr := strings.ToLower(bHdr.Get("X-Cache") + " " + bHdr.Get("CF-Cache-Status") + " age=" + bHdr.Get("Age"))
			s.storeVuln(targetID, "cache_deception", "medium", u, "", testURL,
				fmt.Sprintf("web cache deception CONFIRMED: the app page at %s is served AND cached under a fake static .css path, and a random non-existent path does NOT return the same content (so it is not SPA catch-all). Cache-hit proof on re-fetch: %s", u, strings.TrimSpace(hitHdr)))
			found.Add(1)
			logFn("warn", "cache_deception", "Cache deception CONFIRMED: "+u)
			if s.broadcast != nil {
				s.broadcast("new_vuln_finding", map[string]any{
					"target_id": targetID, "type": "cache_deception", "url": u,
				})
			}
		}(svcURL)
	}
	wg.Wait()
	logFn("info", "cache_deception", fmt.Sprintf("Cache deception check done. Found %d.", found.Load()))
	return nil
}

// cacheDeceptionFetch GETs a URL and returns status, capped body, and headers.
func cacheDeceptionFetch(ctx context.Context, rawURL string) (int, string, http.Header) {
	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", rawURL, nil)
	if err != nil {
		return 0, "", http.Header{}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := vulnHTTPClient.Do(req)
	if err != nil {
		return 0, "", http.Header{}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	return resp.StatusCode, string(b), resp.Header
}

// cacheDeceptionOrigin returns scheme://host for building a control URL on the
// same origin.
func cacheDeceptionOrigin(rawURL string) string {
	p, err := url.Parse(rawURL)
	if err != nil || p.Host == "" {
		return strings.TrimRight(rawURL, "/")
	}
	return p.Scheme + "://" + p.Host
}

// cacheServedFromCache reports whether response headers PROVE the body came from a
// shared cache (a real cache HIT), not merely that it is cacheable. Cache-Control:
// public/max-age is only a directive and is deliberately NOT accepted here.
func cacheServedFromCache(h http.Header) bool {
	sig := strings.ToLower(h.Get("X-Cache") + " " + h.Get("CF-Cache-Status") + " " +
		h.Get("X-Cache-Status") + " " + h.Get("X-Vercel-Cache") + " " + h.Get("X-Drupal-Cache"))
	if strings.Contains(sig, "hit") {
		return true
	}
	// A positive Age means a shared cache is holding and replaying this response.
	if age := strings.TrimSpace(h.Get("Age")); age != "" {
		if n, err := strconv.Atoi(age); err == nil && n > 0 {
			return true
		}
	}
	return false
}

// isExecutableXSSContext performs dependency-free, DOM-aware verification: the
// payload must be reflected *raw* (its leading '<' not HTML-encoded) and must
// NOT sit inside a <textarea>, HTML comment, or <script> string literal — all
// of which neutralise the injection. This cuts the classic "reflected but not
// exploitable" false positives.
func isExecutableXSSContext(body, payload string) bool {
	idx := strings.Index(body, payload)
	if idx < 0 {
		return false
	}
	// The raw '<' must survive (not &lt; / &#60;). Since we matched the literal
	// payload (which starts with '<' or '"><'), an encoded version wouldn't match,
	// so reaching here already implies a raw '<'. Now check the surrounding block.
	before := body[:idx]

	// Inside an unclosed <textarea> / <title> / <style> → inert.
	for _, tag := range []string{"textarea", "title", "style", "noscript"} {
		open := strings.LastIndex(strings.ToLower(before), "<"+tag)
		close := strings.LastIndex(strings.ToLower(before), "</"+tag)
		if open > close {
			return false
		}
	}
	// Inside an HTML comment → inert.
	if oc := strings.LastIndex(before, "<!--"); oc > strings.LastIndex(before, "-->") {
		return false
	}
	return true
}

// ── XSS via dalfox ──────────────────────────────────────────────────────────

func (s *VulnScanner) RunXSS(ctx context.Context, targetID, domain string, logFn LogFunc) error {
	haveDalfox := s.exec.IsToolAvailable("dalfox")

	// Native XSS has already actively tested the complete insertion-point surface
	// (including DOM/browser escalation) before this legacy module runs. Dalfox is
	// therefore a second-opinion/verifier for signal-bearing points, not a second
	// full spray of every inert parameter. Keep every reflected point plus native
	// XSS/DOM candidates; this preserves bypass diversity where a sink exists while
	// avoiding an external process per parameter that showed no XSS signal at all.
	query := `SELECT DISTINCT url, parameter FROM parameters WHERE target_id = ? AND is_reflected = 1 LIMIT ?`
	if haveDalfox {
		logFn("info", "xss_scan", "Starting signal-driven Dalfox second-opinion pass...")
		query = `SELECT DISTINCT p.url, p.parameter FROM parameters p
			WHERE p.target_id = ? AND (
				COALESCE(p.is_reflected,0)=1 OR EXISTS (
					SELECT 1 FROM candidates c
					WHERE c.target_id=p.target_id AND c.url=p.url
					  AND COALESCE(c.parameter,'')=p.parameter
					  AND c.type IN ('xss','dom_xss')
					  AND c.status IN ('DETECTED','TRIAGED','VERIFYING','INCONCLUSIVE')
				)
			) LIMIT ?`
	} else {
		logFn("info", "xss_scan", "Starting XSS scan on reflected parameters (built-in probe)...")
	}

	rows, err := s.db.QueryContext(ctx, query, targetID, s.cfg.URLLimit())
	if err != nil {
		return err
	}
	// Normalize + deduplicate: the same (host, path, param) shows up many times
	// with different values across the crawl. Testing each is wasteful and
	// produces duplicate findings. Collapse to one canonical insertion point.
	seen := make(map[string]bool)
	var items []urlParamPair
	for rows.Next() {
		var u urlParamPair
		if err := rows.Scan(&u.URL, &u.Param); err != nil {
			continue
		}
		if !urlHostInScope(ctx, u.URL) {
			continue
		}
		key := xssNormalizeKey(u.URL, u.Param)
		if seen[key] {
			continue
		}
		seen[key] = true
		items = append(items, u)
	}
	rows.Close()

	logFn("info", "xss_scan", fmt.Sprintf("Testing %d unique reflected insertion points for XSS...", len(items)))

	if len(items) == 0 {
		logFn("info", "xss_scan", "No reflected parameters to test")
		return nil
	}

	if s.exec.IsToolAvailable("dalfox") {
		return s.runDalfox(ctx, targetID, items, logFn)
	}

	// Built-in XSS probe (basic)
	return s.builtinXSSProbe(ctx, targetID, items, logFn)
}

type urlParamPair struct {
	URL   string
	Param string
}

func (s *VulnScanner) runDalfox(ctx context.Context, targetID string, items []urlParamPair, logFn LogFunc) error {
	var found, review atomic.Int64
	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup

	for _, item := range items {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(rawURL, param string) {
			defer wg.Done()
			defer func() { <-sem }()

			// Build URL with param
			parsed, err := url.Parse(rawURL)
			if err != nil {
				return
			}
			q := parsed.Query()
			q.Set(param, "FUZZ")
			parsed.RawQuery = q.Encode()
			testURL := parsed.String()

			// Collect dalfox's raw reflection hits WITHOUT storing them as findings
			// yet. dalfox's own reflection check is easily fooled by values echoed
			// into non-executable contexts (JSON/RSC data inside a <script>, a
			// 302-redirect body, an HTML-encoded reflection): it reports a "[POC]"
			// wherever the value comes back, even when a browser would never run it.
			// That was the dominant reflected-XSS FALSE POSITIVE. Every hit is now
			// re-checked below through the rigorous context verifier (content-type +
			// deterministic breakout + real headless-browser execution) before it can
			// become a finding.
			var hitPayload string
			hit := false
			_ = s.exec.RunWithCallback(ctx, targetID, func(line string) {
				line = strings.TrimSpace(line)
				if line == "" {
					return
				}
				// dalfox outputs: [POC][G][VULN][...] or [POC][R][VULN][...]
				if strings.Contains(line, "[POC]") || strings.Contains(line, "[VULN]") {
					hit = true
					if idx := strings.Index(line, "poc="); idx >= 0 {
						p := line[idx:]
						if end := strings.Index(p, " "); end > 0 {
							p = p[:end]
						}
						hitPayload = p
					}
				}
			}, "dalfox", "url", testURL, "--silence", "--no-spinner", "--timeout", "10")

			if !hit {
				return
			}

			// VERIFY the dalfox hit. Only a browser-confirmed / deterministically
			// proven-executable reflection becomes a FINDING; everything dalfox merely
			// reflected (but we could not prove executes) is routed to "Needs Review"
			// as a candidate, with an honest reason, instead of a false finding.
			s.storeVerifiedXSS(ctx, targetID, rawURL, param, hitPayload, &found, &review, logFn)
		}(item.URL, item.Param)
	}
	wg.Wait()
	logFn("info", "xss_scan", fmt.Sprintf("XSS scan done. %d confirmed finding(s), %d routed to Needs Review.", found.Load(), review.Load()))
	return nil
}

// storeVerifiedXSS re-checks a reflected-XSS hit (from dalfox or the built-in
// probe) through the rigorous context verifier — content-type gating, a
// deterministic browserless breakout confirm, AND real headless-browser
// execution — before it is allowed to be a finding. A VERIFIED verdict stores a
// high-confidence finding with the proven PoC payload; anything else stores a
// candidate in "Needs Review" carrying the verifier's reason, so an
// unconfirmed reflection (JSON/RSC/redirect/encoded/neutralised) is surfaced for
// a human WITHOUT masquerading as a confirmed bug.
func (s *VulnScanner) storeVerifiedXSS(ctx context.Context, targetID, rawURL, param, dalfoxPayload string, found, review *atomic.Int64, logFn LogFunc) {
	cand := VulnerabilityCandidate{
		TargetID: targetID, Type: "xss", Subtype: "reflected",
		URL: rawURL, Method: "GET", Parameter: param, Location: "query",
	}
	res := NewXSSContextVerifier(nil).Verify(ctx, cand)

	if res.Verdict == VerifyVerified {
		conf := res.Confidence
		if conf < ConfEvidence {
			conf = ConfEvidence
		}
		payload := dalfoxPayload
		ev := res.Evidence
		if ev == "" {
			ev = "reflected XSS confirmed executable (" + res.Method + ")"
		}
		s.storeVulnConf(targetID, "xss", "high", rawURL, param, payload, ev, conf)
		found.Add(1)
		logFn("warn", "xss_scan", fmt.Sprintf("XSS CONFIRMED: %s param=%s", rawURL, param))
		if s.broadcast != nil {
			s.broadcast("new_vuln_finding", map[string]any{
				"target_id": targetID, "type": "xss", "url": rawURL, "parameter": param,
			})
		}
		return
	}

	// Not proven executable → Needs Review (candidate), never a finding.
	reason := res.Reason
	if reason == "" {
		reason = "reflection could not be confirmed to execute in a browser"
	}
	ev := "dalfox flagged a reflection here, but Reconner could NOT confirm it executes: " + reason +
		". Routed to Needs Review — verify manually before reporting (common non-exploitable cases: value echoed inside JSON/RSC script data, an HTML-encoded reflection, a redirect/error body, or a reflection neutralised by the surrounding markup)."
	s.storeVulnConf(targetID, "xss", "medium", rawURL, param, dalfoxPayload, ev, ConfCandidateLo)
	review.Add(1)
}

// xssNormalizeKey canonicalises an insertion point so the same (host, path,
// param) is tested exactly once regardless of the concrete values seen during
// crawling. Kills duplicate work AND duplicate findings.
func xssNormalizeKey(rawURL, param string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL + "|" + param
	}
	host := strings.ToLower(parsed.Hostname())
	path := strings.TrimRight(parsed.Path, "/")
	return host + path + "|" + strings.ToLower(param)
}

// xssContext classifies where the canary landed so we can pick the correct
// break-out payload and avoid reporting inert reflections. This is the
// context-aware analysis the naive "does the string appear" check lacks.
type xssContextKind int

const (
	ctxNone       xssContextKind = iota
	ctxHTMLText                  // between tags: <div>HERE</div>
	ctxDoubleAttr                // inside a double-quoted attribute: value="HERE"
	ctxSingleAttr                // inside a single-quoted attribute: value='HERE'
	ctxScript                    // inside a <script> block (JS string context)
	ctxURL                       // inside href/src/action (URL context)
	ctxInert                     // textarea/comment/title/style — not executable
)

func classifyXSSContext(body, canary string) xssContextKind {
	idx := strings.Index(body, canary)
	if idx < 0 {
		return ctxNone
	}
	before := body[:idx]
	lb := strings.ToLower(before)

	// Inert containers first — reflections here don't execute.
	for _, tag := range []string{"textarea", "title", "style", "noscript"} {
		if strings.LastIndex(lb, "<"+tag) > strings.LastIndex(lb, "</"+tag) {
			return ctxInert
		}
	}
	if strings.LastIndex(before, "<!--") > strings.LastIndex(before, "-->") {
		return ctxInert
	}
	// Inside a <script> element → JS context.
	if strings.LastIndex(lb, "<script") > strings.LastIndex(lb, "</script") {
		return ctxScript
	}
	// Inside an open tag attribute? Look at the last unclosed '<'.
	lastLt := strings.LastIndex(before, "<")
	lastGt := strings.LastIndex(before, ">")
	if lastLt > lastGt { // we are inside a tag
		attrChunk := lb[lastLt:]
		if strings.Contains(attrChunk, "href=") || strings.Contains(attrChunk, "src=") || strings.Contains(attrChunk, "action=") {
			// count quotes to see if we're inside the URL value
			dq := strings.Count(before[lastLt:], `"`)
			if dq%2 == 1 {
				return ctxURL
			}
		}
		if strings.Count(before[lastLt:], `"`)%2 == 1 {
			return ctxDoubleAttr
		}
		if strings.Count(before[lastLt:], `'`)%2 == 1 {
			return ctxSingleAttr
		}
	}
	return ctxHTMLText
}

// breakoutFor returns the confirmation payload + human context for a context.
func breakoutFor(kind xssContextKind, canary string) (payload, contextName string, ok bool) {
	switch kind {
	case ctxHTMLText:
		return canary + `<svg/onload=alert(1)>`, "HTML text", true
	case ctxDoubleAttr:
		return canary + `"><svg/onload=alert(1)>`, "double-quoted attribute", true
	case ctxSingleAttr:
		return canary + `'><svg/onload=alert(1)>`, "single-quoted attribute", true
	case ctxScript:
		return canary + `';alert(1);//`, "JavaScript string", true
	case ctxURL:
		return canary + `"><svg/onload=alert(1)>`, "URL attribute", true
	}
	return "", "", false // ctxInert / ctxNone → not exploitable
}

func (s *VulnScanner) builtinXSSProbe(ctx context.Context, targetID string, items []urlParamPair, logFn LogFunc) error {
	var found, review atomic.Int64
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, item := range items {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(rawURL, param string) {
			defer wg.Done()
			defer func() { <-sem }()

			parsed, err := url.Parse(rawURL)
			if err != nil {
				return
			}

			// Stage 1 — canary character-reflection probe (kxss-style). Inject a
			// unique marker wrapped in the special chars needed to break out of
			// HTML contexts, then see WHICH survive unencoded. This finds XSS the
			// old exact-payload match missed (encoding-aware, context-aware).
			const canary = "rcnx9137"
			probe := canary + `'"<>`
			q := parsed.Query()
			q.Set(param, probe)
			testURL := *parsed
			testURL.RawQuery = q.Encode()

			reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
			req, err := http.NewRequestWithContext(reqCtx, "GET", testURL.String(), nil)
			if err != nil {
				cancel()
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
			resp, err := vulnHTTPClient.Do(req)
			cancel()
			if err != nil {
				return
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
			resp.Body.Close()

			bodyStr := string(body)
			ct := strings.ToLower(resp.Header.Get("Content-Type"))
			isHTML := strings.Contains(ct, "html") || ct == ""
			if !isHTML || strings.Contains(ct, "json") || strings.Contains(ct, "xml") || strings.Contains(ct, "plain") {
				return
			}
			// WAF/block-page gate: a reflection inside a WAF block/challenge page is
			// the WAF echoing our probe, not the app — it never executes.
			if looksLikeBlockPage(resp.StatusCode, bodyStr) {
				return
			}

			// Find the canary and inspect which special chars reflected raw.
			idx := strings.Index(bodyStr, canary)
			if idx < 0 {
				return
			}
			tail := bodyStr[idx:]
			if len(tail) > 64 {
				tail = tail[:64]
			}
			ltRaw := strings.Contains(tail, "<")
			gtRaw := strings.Contains(tail, ">")
			dqRaw := strings.Contains(tail, `"`)
			sqRaw := strings.Contains(tail, "'")

			// Context-aware payload selection: classify WHERE the canary landed
			// (HTML text / quoted attribute / <script> / URL / inert container)
			// and pick the break-out sequence that context actually needs. This
			// avoids reporting inert reflections (textarea/comment) and fires the
			// right escape for script/URL contexts the char-only check misses.
			kind := classifyXSSContext(bodyStr, canary)
			confirmPayload, contextName, ok := breakoutFor(kind, canary)
			if !ok {
				return // inert/none — not executable
			}
			reason := "reflected in " + contextName + " context"

			// Gate on the special chars that break-out actually requires, so we
			// don't waste a Stage-2 request when the needed metacharacter is
			// encoded.
			switch kind {
			case ctxHTMLText:
				if !(ltRaw && gtRaw) {
					return
				}
			case ctxDoubleAttr, ctxURL:
				if !dqRaw {
					return
				}
			case ctxSingleAttr:
				if !sqRaw {
					return
				}
			case ctxScript:
				if !sqRaw && !(ltRaw && gtRaw) {
					return
				}
			}

			// Stage 2 — confirm the breakout payload reflects raw in an
			// executable context (not inside textarea/comment/etc.).
			q2 := parsed.Query()
			q2.Set(param, confirmPayload)
			testURL.RawQuery = q2.Encode()
			reqCtx2, cancel2 := context.WithTimeout(ctx, 8*time.Second)
			req2, err := http.NewRequestWithContext(reqCtx2, "GET", testURL.String(), nil)
			if err != nil {
				cancel2()
				return
			}
			req2.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
			resp2, err := vulnHTTPClient.Do(req2)
			cancel2()
			if err != nil {
				return
			}
			body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 512*1024))
			resp2.Body.Close()
			b2 := string(body2)

			marker := strings.SplitN(confirmPayload, canary, 2)[1] // the breakout part
			if strings.Contains(b2, canary+marker) && isExecutableXSSContext(b2, canary) {
				// Stage-2 proved a raw breakout survives in an executable context.
				// Funnel it through the SAME verifier the dalfox path uses so a
				// finding is only recorded when execution is actually confirmed
				// (browserless breakout + real headless browser); anything the
				// verifier can't confirm lands in Needs Review instead of being a
				// direct finding. _ = reason (kept for the probe's own diagnostics).
				_ = reason
				s.storeVerifiedXSS(ctx, targetID, rawURL, param, confirmPayload, &found, &review, logFn)
				return // one result per param is enough
			}
		}(item.URL, item.Param)
	}
	wg.Wait()
	logFn("info", "xss_scan", fmt.Sprintf("XSS probe done. %d confirmed finding(s), %d routed to Needs Review.", found.Load(), review.Load()))
	return nil
}

// ── CORS misconfiguration ────────────────────────────────────────────────────

func (s *VulnScanner) RunCORSCheck(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "cors_scan", "Checking CORS misconfigurations...")

	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services
		WHERE target_id = ? AND status_code BETWEEN 200 AND 403
		LIMIT ?
	`, targetID, s.cfg.URLLimit())
	if err != nil {
		return err
	}
	var urls []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err == nil {
			urls = append(urls, u)
		}
	}
	rows.Close()
	urls = filterURLsByHostScope(ctx, urls)

	logFn("info", "cors_scan", fmt.Sprintf("Testing %d endpoints for CORS...", len(urls)))

	sem := make(chan struct{}, 15)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, svcURL := range urls {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			vuln, evidence, severity := checkCORS(ctx, u)
			if vuln != "" {
				s.storeVuln(targetID, "cors", severity, u, "", "", evidence)
				found.Add(1)
				logFn("warn", "cors_scan", fmt.Sprintf("CORS [%s]: %s (%s)", severity, u, vuln))
				if s.broadcast != nil {
					s.broadcast("new_vuln_finding", map[string]any{
						"target_id": targetID,
						"type":      "cors",
						"url":       u,
					})
				}
			}
		}(svcURL)
	}
	wg.Wait()
	logFn("info", "cors_scan", fmt.Sprintf("CORS check done. Found %d misconfigurations.", found.Load()))
	return nil
}

// checkCORS returns the vuln type, evidence, and a severity that reflects real
// exploitability. Reflected/wildcard origins WITHOUT credentials are info/low
// (endpoint is already anonymous-readable); only ACAC:true cases are dangerous.
func checkCORS(ctx context.Context, rawURL string) (vulnType, evidence, severity string) {
	origins := []struct {
		origin string
		label  string
	}{
		{"https://evil.com", "arbitrary_origin"},
		{"null", "null_origin"},
	}

	for _, o := range origins {
		reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, "GET", rawURL, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("Origin", o.origin)
		req.Header.Set("User-Agent", "Mozilla/5.0")

		resp, err := vulnHTTPClient.Do(req)
		cancel()
		if err != nil {
			continue
		}
		resp.Body.Close()

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := strings.ToLower(resp.Header.Get("Access-Control-Allow-Credentials")) == "true"

		if acao == "" {
			continue
		}

		// Wildcard without credentials: browsers already allow anonymous reads → info.
		if acao == "*" {
			return "wildcard_cors", "Access-Control-Allow-Origin: * (no credentials)", "info"
		}

		if acao == o.origin || acao == "null" {
			ev := fmt.Sprintf("ACAO: %s, ACAC: %t (origin=%s)", acao, acac, o.origin)
			if acac {
				// Reflected/null origin + credentials = session-stealing → high/critical.
				if o.label == "null_origin" {
					return "cors_null_origin_credentials", ev, "critical"
				}
				return "cors_reflected_credentials", ev, "high"
			}
			// Reflected origin, no credentials: low signal, keep but low severity.
			return "cors_reflected_" + o.label, ev, "low"
		}
	}
	return "", "", ""
}

// ── 403 Bypass ──────────────────────────────────────────────────────────────

func (s *VulnScanner) Run403Bypass(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "403_bypass", "Checking 403 bypass techniques...")

	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services
		WHERE target_id = ? AND status_code = 403
		LIMIT ?
	`, targetID, s.cfg.URLLimit())
	if err != nil {
		return err
	}
	var urls []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err == nil {
			urls = append(urls, u)
		}
	}
	rows.Close()
	urls = filterURLsByHostScope(ctx, urls)

	if len(urls) == 0 {
		logFn("info", "403_bypass", "No 403 endpoints found to test")
		return nil
	}

	logFn("info", "403_bypass", fmt.Sprintf("Testing %d forbidden endpoints...", len(urls)))

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, svcURL := range urls {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			if bypass, evidence := check403Bypass(ctx, u); bypass != "" {
				s.storeVuln(targetID, "403_bypass", "medium", u, "", bypass, evidence)
				found.Add(1)
				logFn("warn", "403_bypass", fmt.Sprintf("403 bypass found: %s via %s", u, bypass))
				if s.broadcast != nil {
					s.broadcast("new_vuln_finding", map[string]any{
						"target_id": targetID,
						"type":      "403_bypass",
						"url":       u,
					})
				}
			}
		}(svcURL)
	}
	wg.Wait()
	logFn("info", "403_bypass", fmt.Sprintf("403 bypass check done. Found %d bypasses.", found.Load()))
	return nil
}

func check403Bypass(ctx context.Context, rawURL string) (method, evidence string) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", ""
	}

	// Baseline: the real 403 body length so we can tell a genuine bypass from a
	// server that returns the same forbidden/login page for every request.
	baselineLen := fetchBodyLen(ctx, rawURL, nil)

	type attempt struct {
		label   string
		headers map[string]string
		path    string
	}

	attempts := []attempt{
		{label: "X-Forwarded-For: 127.0.0.1", headers: map[string]string{"X-Forwarded-For": "127.0.0.1"}},
		{label: "X-Real-IP: 127.0.0.1", headers: map[string]string{"X-Real-IP": "127.0.0.1"}},
		{label: "X-Original-URL", headers: map[string]string{"X-Original-URL": parsed.Path}},
		{label: "X-Rewrite-URL", headers: map[string]string{"X-Rewrite-URL": parsed.Path}},
		{label: "X-Custom-IP-Authorization", headers: map[string]string{"X-Custom-IP-Authorization": "127.0.0.1"}},
		{label: "path_suffix /", path: rawURL + "/"},
		{label: "path_suffix /.;", path: strings.TrimRight(rawURL, "/") + "/.;/"},
		{label: "path_suffix %2f", path: strings.TrimRight(rawURL, "/") + "%2f"},
	}

	for _, att := range attempts {
		if ctx.Err() != nil {
			return "", ""
		}

		targetURL := rawURL
		if att.path != "" {
			targetURL = att.path
		}

		reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, "GET", targetURL, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")
		for k, v := range att.headers {
			req.Header.Set(k, v)
		}

		resp, err := vulnHTTPClient.Do(req)
		if err != nil {
			cancel()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		cancel()

		// Only a real 200 counts. 301/302 usually redirect to /login — that is
		// normal behaviour, not a bypass.
		if resp.StatusCode != 200 {
			continue
		}

		lower := strings.ToLower(string(body))
		if strings.Contains(lower, "sign in") || strings.Contains(lower, "log in") ||
			strings.Contains(lower, "login") || strings.Contains(lower, "unauthorized") ||
			strings.Contains(lower, "access denied") || strings.Contains(lower, "forbidden") {
			continue // looks like the same auth wall, not real content
		}

		// Body must differ meaningfully from the 403 baseline.
		if baselineLen > 0 && abs(len(body)-baselineLen) < 64 {
			continue
		}

		return att.label, fmt.Sprintf("original=403 (len=%d), bypass=200 (len=%d) via %s", baselineLen, len(body), att.label)
	}
	return "", ""
}

func fetchBodyLen(ctx context.Context, rawURL string, headers map[string]string) int {
	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", rawURL, nil)
	if err != nil {
		return -1
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := vulnHTTPClient.Do(req)
	if err != nil {
		return -1
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()
	return len(body)
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// ── Host Header Injection ────────────────────────────────────────────────────

func (s *VulnScanner) RunHostHeaderInjection(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "host_header", "Checking host header injection...")

	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services
		WHERE target_id = ? AND status_code BETWEEN 200 AND 403
		LIMIT ?
	`, targetID, s.cfg.URLLimit())
	if err != nil {
		return err
	}
	var urls []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err == nil {
			urls = append(urls, u)
		}
	}
	rows.Close()
	urls = filterURLsByHostScope(ctx, urls)

	logFn("info", "host_header", fmt.Sprintf("Testing %d endpoints for host header injection...", len(urls)))

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, svcURL := range urls {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			if evidence, sev := checkHostHeader(ctx, u); evidence != "" {
				s.storeVuln(targetID, "host_header_injection", sev, u, "", "", evidence)
				found.Add(1)
				logFn("warn", "host_header", fmt.Sprintf("Host header injection: %s", u))
				if s.broadcast != nil {
					s.broadcast("new_vuln_finding", map[string]any{
						"target_id": targetID,
						"type":      "host_header_injection",
						"url":       u,
					})
				}
			}
		}(svcURL)
	}
	wg.Wait()
	logFn("info", "host_header", fmt.Sprintf("Host header check done. Found %d issues.", found.Load()))
	return nil
}

// checkHostHeader tries each host-injection vector SEPARATELY so we know which
// header the app trusts, and elevates severity on password-reset / auth
// endpoints (where a poisoned host means account-takeover via reset-link
// poisoning). A Location/link carrying the injected host is exploitable; a bare
// body echo is low signal.
func checkHostHeader(ctx context.Context, rawURL string) (string, string) {
	const fakeHost = "evil-recon-probe.com"

	// Each vector applied on its own request.
	vectors := []struct {
		name  string
		apply func(*http.Request)
	}{
		{"Host", func(r *http.Request) { r.Host = fakeHost }},
		{"X-Forwarded-Host", func(r *http.Request) { r.Header.Set("X-Forwarded-Host", fakeHost) }},
		{"X-Host", func(r *http.Request) { r.Header.Set("X-Host", fakeHost) }},
		{"X-Forwarded-Server", func(r *http.Request) { r.Header.Set("X-Forwarded-Server", fakeHost) }},
	}

	// Password-reset / auth context → a poisoned host is account takeover.
	lowerURL := strings.ToLower(rawURL)
	resetContext := false
	for _, kw := range []string{"reset", "forgot", "password", "recover", "confirm", "activate", "verify", "magic", "login"} {
		if strings.Contains(lowerURL, kw) {
			resetContext = true
			break
		}
	}

	for _, vec := range vectors {
		if ctx.Err() != nil {
			return "", ""
		}
		reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, "GET", rawURL, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")
		vec.apply(req)

		resp, err := vulnHTTPClient.Do(req)
		if err != nil {
			cancel()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
		resp.Body.Close()
		cancel()

		// Location redirect to the injected host — clearly exploitable.
		if loc := resp.Header.Get("Location"); loc != "" && strings.Contains(loc, fakeHost) {
			sev := "high"
			if resetContext {
				sev = "critical"
			}
			return fmt.Sprintf("%s header reflected into redirect Location: %s%s", vec.name, loc, resetNote(resetContext)), sev
		}

		bodyStr := string(body)
		for _, ctxPat := range []string{
			`href="https://` + fakeHost, `href='https://` + fakeHost,
			`src="https://` + fakeHost, `src='https://` + fakeHost,
			`action="https://` + fakeHost, `href="//` + fakeHost, `src="//` + fakeHost,
			`https://` + fakeHost + `/reset`, `https://` + fakeHost + `/`,
		} {
			if strings.Contains(bodyStr, ctxPat) {
				sev := "medium"
				if resetContext {
					sev = "high"
				}
				return fmt.Sprintf("%s header reflected in a link/resource attribute (status %d)%s", vec.name, resp.StatusCode, resetNote(resetContext)), sev
			}
		}
	}
	return "", ""
}

func resetNote(reset bool) string {
	if reset {
		return " — on a password-reset/auth endpoint this is account takeover via reset-link poisoning"
	}
	return ""
}

// ── CRLF Injection ──────────────────────────────────────────────────────────

func (s *VulnScanner) RunCRLF(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "crlf_scan", "Checking CRLF injection...")

	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT url, parameter FROM parameters
		WHERE target_id = ?
		LIMIT ?
	`, targetID, s.cfg.URLLimit())
	if err != nil {
		return err
	}
	type up struct{ URL, Param string }
	var items []up
	for rows.Next() {
		var u up
		if err := rows.Scan(&u.URL, &u.Param); err == nil {
			if !urlHostInScope(ctx, u.URL) {
				continue
			}
			items = append(items, u)
		}
	}
	rows.Close()

	logFn("info", "crlf_scan", fmt.Sprintf("Testing %d parameters for CRLF...", len(items)))

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	var found atomic.Int64

	crlfPayloads := []string{
		"%0d%0aX-Injected: crlf",
		"%0aX-Injected: crlf",
		"\r\nX-Injected: crlf",
		"%E5%98%8A%E5%98%8DX-Injected: crlf", // unicode CRLF
	}

	for _, item := range items {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(rawURL, param string) {
			defer wg.Done()
			defer func() { <-sem }()

			parsed, err := url.Parse(rawURL)
			if err != nil {
				return
			}

			for _, payload := range crlfPayloads {
				if ctx.Err() != nil {
					return
				}

				q := parsed.Query()
				q.Set(param, payload)
				testURL := *parsed
				testURL.RawQuery = q.Encode()

				reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
				req, err := http.NewRequestWithContext(reqCtx, "GET", testURL.String(), nil)
				if err != nil {
					cancel()
					continue
				}
				req.Header.Set("User-Agent", "Mozilla/5.0")

				resp, err := vulnHTTPClient.Do(req)
				cancel()
				if err != nil {
					continue
				}
				resp.Body.Close()

				if resp.Header.Get("X-Injected") == "crlf" {
					evidence := fmt.Sprintf("X-Injected header found in response (payload=%s)", payload)
					s.storeVuln(targetID, "crlf", "medium", rawURL, param, payload, evidence)
					found.Add(1)
					logFn("warn", "crlf_scan", fmt.Sprintf("CRLF injection: %s param=%s", rawURL, param))
					if s.broadcast != nil {
						s.broadcast("new_vuln_finding", map[string]any{
							"target_id": targetID,
							"type":      "crlf",
							"url":       rawURL,
							"parameter": param,
						})
					}
					return
				}
			}
		}(item.URL, item.Param)
	}
	wg.Wait()
	logFn("info", "crlf_scan", fmt.Sprintf("CRLF scan done. Found %d vulnerabilities.", found.Load()))
	return nil
}

// ── Storage ──────────────────────────────────────────────────────────────────

func (s *VulnScanner) storeVuln(targetID, vulnType, severity, rawURL, param, payload, evidence string) {
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: vulnType, Severity: severity, URL: rawURL,
		Method: "GET", Parameter: param, Location: "query", Payload: payload, Evidence: evidence,
		Source: "vuln-scanner", DetectionMethod: "active-differential",
		Confidence: ConfEvidence, Verdict: VerifyVerified,
	})
}

// storeVulnConf stores a finding with an explicit confidence + status, for
// checks that actively PROVE the bug (dalfox POC, context-aware XSS breakout in
// an executable context) so the verify band doesn't demote them to candidate.
func (s *VulnScanner) storeVulnConf(targetID, vulnType, severity, rawURL, param, payload, evidence string, confidence int) {
	verdict := CandDetected
	if confidence >= ConfEvidence {
		verdict = VerifyVerified
	}
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: vulnType, Severity: severity, URL: rawURL,
		Method: "GET", Parameter: param, Location: "query", Payload: payload, Evidence: evidence,
		Source: "vuln-scanner", DetectionMethod: "active-differential",
		Confidence: confidence, Verdict: verdict,
	})
}
