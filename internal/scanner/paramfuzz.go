package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

// ParamFuzzScanner mines HIDDEN parameters (Arjun-style). Crawling and Wayback
// only reveal parameters the app already exposes in links; the interesting ones
// (debug, admin, test, id overrides, feature flags) are undocumented. This
// module fuzzes a wordlist of likely names against each endpoint and keeps the
// ones that measurably change the response — then stores them so every active
// module (XSS/SQLi/SSRF/LFI/SSTI/CMDi) tests them too.
type ParamFuzzScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewParamFuzzScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *ParamFuzzScanner {
	return &ParamFuzzScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

var paramFuzzClient = &http.Client{
	Transport: sharedHTTPTransport,
	Timeout:   12 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

const (
	pfCanary       = "rcnfz9137"
	pfChunkSize    = 25 // params per request (bisected when a hit is detected)
	pfMaxHosts     = 60 // endpoints to mine per scan
	pfLenTolerance = 24 // body-length noise tolerance (baseline; learned per page)
)

// Regexes that harvest candidate parameter names from a response body
// (param-miner technique): form fields, JSON keys, and JS identifier assignments.
var (
	reFormField = regexp.MustCompile(`(?i)<(?:input|select|textarea|button)[^>]*\bname\s*=\s*["']([a-zA-Z0-9_\-.\[\]]{1,40})["']`)
	reJSONKey   = regexp.MustCompile(`["']([a-zA-Z_][a-zA-Z0-9_\-]{1,39})["']\s*:`)
	reJSAssign  = regexp.MustCompile(`(?:var|let|const)\s+([a-zA-Z_][a-zA-Z0-9_]{1,39})\s*=`)
)

// High-signal hidden-parameter wordlist (compact but curated — the names that
// most often gate debug/admin/idor/redirect behaviour).
var paramFuzzWords = []string{
	"debug", "test", "admin", "id", "user", "userid", "user_id", "uid", "account",
	"page", "action", "cmd", "exec", "command", "func", "function", "method",
	"file", "path", "dir", "folder", "download", "read", "include", "template",
	"url", "uri", "redirect", "redirect_url", "return", "returnurl", "next", "dest",
	"callback", "webhook", "proxy", "fetch", "image", "img", "src", "source",
	"q", "query", "search", "s", "keyword", "term", "filter", "sort", "order",
	"lang", "language", "locale", "country", "region", "currency", "format",
	"type", "mode", "view", "show", "display", "layout", "theme", "style",
	"token", "auth", "key", "apikey", "api_key", "access", "secret", "session",
	"role", "is_admin", "isadmin", "admin_mode", "superuser", "root", "sudo",
	"enable", "disable", "active", "status", "state", "flag", "feature",
	"preview", "draft", "test_mode", "dev", "development", "staging", "sandbox",
	"limit", "offset", "count", "size", "start", "end", "from", "to", "range",
	"email", "mail", "phone", "name", "username", "login", "password", "pass",
	"code", "otp", "pin", "verify", "confirm", "validate", "check",
	"data", "json", "xml", "body", "content", "payload", "input", "value", "val",
	"ref", "referrer", "origin", "host", "domain", "site", "target", "server",
	"cache", "nocache", "refresh", "reload", "force", "bypass", "override",
	"version", "v", "api", "endpoint", "resource", "object", "item", "product",
	"category", "cat", "tag", "group", "list", "index", "num", "number", "no",
	"date", "time", "year", "month", "day", "timestamp", "ts",
	"log", "logs", "trace", "verbose", "output", "response", "result", "error",
	"internal", "private", "public", "hidden", "secure", "unsafe", "raw",
}

// Run mines hidden params on a bounded set of endpoints and stores hits.
func (s *ParamFuzzScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "paramfuzz", "Mining hidden parameters (query + body + JSON, response-guided)...")

	endpoints := s.selectEndpoints(ctx, targetID)
	if len(endpoints) == 0 {
		logFn("info", "paramfuzz", "No endpoints to fuzz")
		return nil
	}
	auth := loadAuthHeaders(ctx, s.db, targetID)

	// CROSS-URL: every parameter name already discovered ANYWHERE on this target —
	// most valuably the ones pulled out of JavaScript (js_analysis / js_endpoints)
	// and historical URLs — is fed into the wordlist for EVERY endpoint. A param
	// that appears in one bundle's fetch() call ("?debug=", "?admin=", "?uid=") is
	// then brute-forced against every other URL, which is exactly how a hidden
	// param on an unrelated handler gets found (the x8 "personal wordlist" idea).
	extra := s.discoveredParamNames(ctx, targetID)
	logFn("info", "paramfuzz", fmt.Sprintf("Fuzzing %d endpoints × (%d static + %d discovered) candidate params...",
		len(endpoints), len(paramFuzzWords), len(extra)))

	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, ep := range endpoints {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(endpoint string) {
			defer wg.Done()
			defer func() { <-sem }()
			hits := s.mine(ctx, endpoint, auth, extra)
			for _, p := range hits {
				if s.storeParam(targetID, endpoint, p) {
					found.Add(1)
				}
			}
		}(ep)
	}
	wg.Wait()

	logFn("info", "paramfuzz", fmt.Sprintf("Parameter mining done. Discovered %d hidden parameters.", found.Load()))
	return nil
}

// pfLoc is WHERE a candidate parameter is injected. x8's key advantage over
// Arjun is mining multiple locations — a parameter the app only reads from the
// POST body is invisible to query-string fuzzing.
type pfLoc int

const (
	pfQuery pfLoc = iota // GET ?name=canary
	pfBody               // POST body name=canary (x-www-form-urlencoded)
	pfJSON               // POST JSON body {"name":"canary"}
)

type minedParam struct {
	name string
	loc  pfLoc
}

// mine returns the hidden parameters that change the endpoint's response,
// consolidating the best of Arjun + param-miner + x8:
//   - x8: three injection locations — query, form body, JSON body.
//   - param-miner: candidate names harvested from the endpoint's OWN response
//     (form fields, id attributes, JSON keys, JS identifiers) merged into the
//     wordlist — finds app-specific params no static list contains.
//   - Arjun: a learned response-noise baseline so dynamic pages don't false-positive.
func (s *ParamFuzzScanner) mine(ctx context.Context, endpoint string, auth map[string]string, extra []string) []minedParam {
	// Build the per-endpoint wordlist: static list + names harvested from the page
	// + names discovered elsewhere on this target (JS/historical — cross-URL).
	words := s.buildWordlist(ctx, endpoint, auth, extra)

	var hits []minedParam
	for _, loc := range []pfLoc{pfQuery, pfBody, pfJSON} {
		if ctx.Err() != nil {
			break
		}
		// Learn the response-length noise for THIS location: two identical empty
		// probes; if the page is dynamic (length varies), widen the tolerance.
		s1, l1, c1 := s.probe(ctx, endpoint, nil, loc, auth)
		if s1 == 0 {
			continue
		}
		_, l2, _ := s.probe(ctx, endpoint, nil, loc, auth)
		tol := pfLenTolerance
		if d := abs(l1 - l2); d*2 > tol {
			tol = d*2 + pfLenTolerance
		}

		var locHits []string
		for i := 0; i < len(words); i += pfChunkSize {
			end := i + pfChunkSize
			if end > len(words) {
				end = len(words)
			}
			chunk := words[i:end]
			locHits = append(locHits, s.bisect(ctx, endpoint, chunk, s1, l1, c1, tol, loc, auth)...)
			if len(locHits) > 20 { // safety cap per endpoint/location
				break
			}
		}
		for _, name := range locHits {
			hits = append(hits, minedParam{name, loc})
		}
	}
	return hits
}

// buildWordlist merges the static wordlist with candidate parameter names mined
// from the endpoint's own response (the param-miner idea). Bounded and deduped.
func (s *ParamFuzzScanner) buildWordlist(ctx context.Context, endpoint string, auth map[string]string, extra []string) []string {
	seen := make(map[string]bool, len(paramFuzzWords)+len(extra)+64)
	out := make([]string, 0, len(paramFuzzWords)+len(extra)+64)
	add := func(n string) {
		n = strings.TrimSpace(n)
		if n == "" || len(n) > 40 || seen[n] {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	for _, w := range paramFuzzWords {
		add(w)
	}
	// Cross-URL names discovered elsewhere on the target (JS, historical URLs).
	for _, w := range extra {
		add(w)
	}
	// Harvest candidate names from the page body.
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if req, err := http.NewRequestWithContext(reqCtx, "GET", endpoint, nil); err == nil {
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
		for k, v := range auth {
			req.Header.Set(k, v)
		}
		if resp, err := paramFuzzClient.Do(req); err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
			resp.Body.Close()
			n := 0
			for _, name := range harvestParamNames(string(body)) {
				add(name)
				if n++; n >= 60 { // cap harvested names
					break
				}
			}
		}
	}
	return out
}

// discoveredParamNames returns the distinct parameter names already found
// anywhere on this target — the output of param discovery over JS files
// (js_analysis / js_endpoints) and historical/crawled URLs. Feeding these into
// every endpoint's wordlist is the cross-URL brute force: a name seen in one
// place is probed everywhere. Bounded, and skips pure-numeric / oversized tokens.
func (s *ParamFuzzScanner) discoveredParamNames(ctx context.Context, targetID string) []string {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT parameter FROM parameters
		WHERE target_id = ? AND parameter != '' AND LENGTH(parameter) <= 40
		LIMIT 600`, targetID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if rows.Scan(&name) != nil {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "" || isAllDigits(name) {
			continue
		}
		out = append(out, name)
	}
	return out
}

// isAllDigits reports whether s is non-empty and only ASCII digits — such a
// "parameter" (e.g. an array index harvested from a URL) is noise to cross-apply.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// bisect isolates which params in a chunk affect the response, recursively.
func (s *ParamFuzzScanner) bisect(ctx context.Context, endpoint string, chunk []string, baseStatus, baseLen int, baseHasCanary bool, tol int, loc pfLoc, auth map[string]string) []string {
	if len(chunk) == 0 || ctx.Err() != nil {
		return nil
	}
	status, length, hasCanary := s.probe(ctx, endpoint, chunk, loc, auth)
	if status == 0 {
		return nil
	}
	// Did this chunk change anything meaningful vs the learned baseline?
	reflected := hasCanary && !baseHasCanary
	statusDiff := status != baseStatus
	lenDiff := abs(length-baseLen) > tol
	if !reflected && !statusDiff && !lenDiff {
		return nil // nothing in this chunk matters
	}
	if len(chunk) == 1 {
		return chunk // isolated a single influential param
	}
	mid := len(chunk) / 2
	left := s.bisect(ctx, endpoint, chunk[:mid], baseStatus, baseLen, baseHasCanary, tol, loc, auth)
	right := s.bisect(ctx, endpoint, chunk[mid:], baseStatus, baseLen, baseHasCanary, tol, loc, auth)
	return append(left, right...)
}

// harvestParamNames extracts likely parameter names from a response body:
// form fields, id attributes, JSON keys, and JS identifiers assigned values.
func harvestParamNames(body string) []string {
	seen := map[string]bool{}
	var out []string
	push := func(m [][]string) {
		for _, g := range m {
			if len(g) > 1 {
				n := g[1]
				if n != "" && !seen[n] {
					seen[n] = true
					out = append(out, n)
				}
			}
		}
	}
	push(reFormField.FindAllStringSubmatch(body, 200))
	push(reJSONKey.FindAllStringSubmatch(body, 200))
	push(reJSAssign.FindAllStringSubmatch(body, 200))
	return out
}

// probe sends the endpoint with the given params set to the canary in the given
// location and returns status, body length, and whether the canary reflected.
func (s *ParamFuzzScanner) probe(ctx context.Context, endpoint string, params []string, loc pfLoc, auth map[string]string) (int, int, bool) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return 0, 0, false
	}

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var req *http.Request
	switch loc {
	case pfBody:
		form := url.Values{}
		for _, p := range params {
			form.Set(p, pfCanary)
		}
		req, err = http.NewRequestWithContext(reqCtx, "POST", parsed.String(), strings.NewReader(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	case pfJSON:
		// {"p1":"canary","p2":"canary"}
		var sb strings.Builder
		sb.WriteByte('{')
		for i, p := range params {
			if i > 0 {
				sb.WriteByte(',')
			}
			fmt.Fprintf(&sb, "%q:%q", p, pfCanary)
		}
		sb.WriteByte('}')
		req, err = http.NewRequestWithContext(reqCtx, "POST", parsed.String(), strings.NewReader(sb.String()))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	default: // pfQuery
		q := parsed.Query()
		for _, p := range params {
			q.Set(p, pfCanary)
		}
		parsed.RawQuery = q.Encode()
		req, err = http.NewRequestWithContext(reqCtx, "GET", parsed.String(), nil)
	}
	if err != nil {
		return 0, 0, false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
	for k, v := range auth {
		req.Header.Set(k, v)
	}
	resp, err := paramFuzzClient.Do(req)
	if err != nil {
		return 0, 0, false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	resp.Body.Close()
	return resp.StatusCode, len(body), strings.Contains(string(body), pfCanary)
}

// selectEndpoints picks distinct parameter-less endpoints to mine (adding
// params only makes sense on pages that don't already carry them).
func (s *ParamFuzzScanner) selectEndpoints(ctx context.Context, targetID string) []string {
	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services
		WHERE target_id = ? AND status_code BETWEEN 200 AND 403
		ORDER BY url LIMIT ?
	`, targetID, pfMaxHosts)
	if err != nil {
		return nil
	}
	defer rows.Close()
	// Skip hosts fingerprinted as a heavy CMS (WordPress/Joomla/Drupal): hidden-
	// param mining on CMS core routes is almost all noise (the framework reflects
	// or 200s on unknown params), and it's where the biggest FP volume came from.
	cmsSkip := loadCMSSkipHosts(s.db, targetID)
	seen := make(map[string]bool)
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			continue
		}
		if hostSkippedByCMS(u, cmsSkip) {
			continue
		}
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		key := parsed.Host + parsed.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, u)
	}
	return out
}

func (s *ParamFuzzScanner) storeParam(targetID, endpoint string, p minedParam) bool {
	method, contentType := "GET", ""
	switch p.loc {
	case pfBody:
		method, contentType = "POST", "application/x-www-form-urlencoded"
	case pfJSON:
		method, contentType = "POST", "application/json"
	}
	id := uuid.New().String()
	res, err := s.db.Exec(`
		INSERT INTO parameters (id, target_id, url, parameter, value, source, method, content_type)
		VALUES (?, ?, ?, ?, '', 'fuzz', ?, ?)
		ON CONFLICT(target_id, url, parameter) DO NOTHING
	`, id, targetID, endpoint, p.name, method, contentType)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}
