package scanner

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
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
	pfCanary          = "rcnfz9137"
	pfChunkSizeQuery  = 64 // stays below common request-line limits with typical names
	pfChunkSizeBody   = 96 // bodies tolerate a larger batch, reducing total requests
	pfMaxHosts        = 60 // endpoint contracts to mine per scan
	pfEndpointPool    = 4000
	pfBaselineSamples = 3  // Arjun/Param-Miner style stability calibration
	pfLenTolerance    = 24 // body-length noise tolerance (baseline; learned per page)
)

// Regexes that harvest candidate parameter names from a response body
// (param-miner technique): form fields, JSON keys, and JS identifier assignments.
var (
	reFormField = regexp.MustCompile(`(?i)<(?:input|select|textarea|button)[^>]*\bname\s*=\s*["']([a-zA-Z0-9_\-.\[\]]{1,40})["']`)
	reJSONKey   = regexp.MustCompile(`["']([a-zA-Z_][a-zA-Z0-9_\-]{1,39})["']\s*:`)
	reJSAssign  = regexp.MustCompile(`(?:var|let|const)\s+([a-zA-Z_][a-zA-Z0-9_]{1,39})\s*=`)
	reParamName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-\[\]]{0,63}$`)
	reCamelName = regexp.MustCompile(`[a-z][A-Z]`)
)

// High-signal hidden-parameter wordlist (compact but curated — the names that
// most often gate debug/admin/idor/redirect behaviour).
var paramFuzzWords = []string{
	"debug", "test", "admin", "id", "user", "userid", "user_id", "uid", "account",
	"account_id", "object_id", "tenant_id", "org_id", "organization_id", "project_id",
	"resource_id", "record_id", "profile_id", "order_id", "invoice_id", "document_id",
	"page", "action", "cmd", "exec", "command", "func", "function", "method",
	"file", "path", "dir", "folder", "download", "read", "include", "template",
	"template_id", "template_name", "renderer", "render_mode",
	"url", "uri", "redirect", "redirect_url", "return", "returnurl", "next", "dest",
	"redirect_uri", "redirect_to", "return_url", "return_to", "continue_url", "success_url", "cancel_url",
	"callback", "webhook", "proxy", "fetch", "image", "img", "src", "source",
	"callback_url", "callback_uri", "webhook_url",
	"q", "query", "search", "s", "keyword", "term", "filter", "sort", "order",
	"lang", "language", "locale", "country", "region", "currency", "format",
	"type", "mode", "view", "show", "display", "layout", "theme", "style",
	"token", "auth", "key", "apikey", "api_key", "access", "secret", "session",
	"role", "is_admin", "isadmin", "admin_mode", "superuser", "root", "sudo",
	"enable", "disable", "active", "status", "state", "flag", "feature",
	"preview", "draft", "debug_mode", "preview_mode", "test_mode", "dev", "development", "staging", "sandbox",
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
	adaptive := buildAdaptiveWordlist(ctx, s.db, s.cfg, targetID, nil)
	if len(adaptive) > 100 {
		adaptive = adaptive[:100]
	}
	extra = append(extra, adaptive...)
	staticWords := s.parameterCorpus()
	logFn("info", "paramfuzz", fmt.Sprintf("Fuzzing %d endpoints × (%d static + %d discovered) candidate params...",
		len(endpoints), len(staticWords), len(extra)))

	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, ep := range endpoints {
		if ctx.Err() != nil {
			break
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return ctx.Err()
		}
		wg.Add(1)
		go func(endpoint pfEndpoint) {
			defer wg.Done()
			defer func() { <-sem }()
			hits := s.mine(ctx, endpoint, auth, extra)
			for _, p := range hits {
				if s.storeParam(targetID, endpoint.url, p) {
					found.Add(1)
				}
			}
		}(ep)
	}
	wg.Wait()

	logFn("info", "paramfuzz", fmt.Sprintf("Parameter mining done. Discovered %d hidden parameters.", found.Load()))
	return ctx.Err()
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
	name     string
	contract pfContract
}

// pfContract is the request shape that must be replayed while looking for an
// undocumented field. Reusing the real method, content type and sibling fields
// avoids the deterministic validation failures caused by turning every endpoint
// into an empty POST/JSON request.
type pfContract struct {
	loc          pfLoc
	method       string
	contentType  string
	siblings     map[string]string
	siblingTypes map[string]string
}

// pfEndpoint groups the known request contracts for one URL. score is used only
// to spend the bounded mining budget on observed API/form contracts before
// generic HTML roots.
type pfEndpoint struct {
	url       string
	contracts []pfContract
	score     int
}

// mine returns the hidden parameters that change the endpoint's response,
// consolidating the best of Arjun + param-miner + x8:
//   - x8: three injection locations — query, form body, JSON body.
//   - param-miner: candidate names harvested from the endpoint's OWN response
//     (form fields, id attributes, JSON keys, JS identifiers) merged into the
//     wordlist — finds app-specific params no static list contains.
//   - Arjun: a learned response-noise baseline so dynamic pages don't false-positive.
func (s *ParamFuzzScanner) mine(ctx context.Context, endpoint pfEndpoint, auth map[string]string, extra []string) []minedParam {
	// Build the per-endpoint wordlist: static list + names harvested from the page
	// + names discovered elsewhere on this target (JS/historical — cross-URL).
	words := s.buildWordlist(ctx, endpoint.url, auth, extra)

	var hits []minedParam
	for _, contract := range endpoint.contracts {
		if ctx.Err() != nil {
			break
		}
		baseline, ok := s.learnBaseline(ctx, endpoint.url, contract, auth)
		if !ok {
			continue
		}

		// Existing fields belong to the baseline request, not the unknown-name
		// search. Mutating them here can invalidate required fields for an entire
		// batch before the hidden parameter is evaluated.
		candidates := make([]string, 0, len(words))
		u, _ := url.Parse(endpoint.url)
		for _, name := range words {
			if _, exists := contract.siblings[name]; exists {
				continue
			}
			if contract.loc == pfQuery && u != nil && u.Query().Has(name) {
				continue
			}
			candidates = append(candidates, name)
		}
		var locHits []string
		chunkSize := pfChunkSizeQuery
		if contract.loc != pfQuery {
			chunkSize = pfChunkSizeBody
		}
		for i := 0; i < len(candidates); i += chunkSize {
			end := i + chunkSize
			if end > len(candidates) {
				end = len(candidates)
			}
			chunk := candidates[i:end]
			locHits = append(locHits, s.bisect(ctx, endpoint.url, chunk, baseline, contract, auth)...)
			if len(locHits) > 20 { // safety cap per endpoint/location
				break
			}
		}
		for _, name := range locHits {
			hits = append(hits, minedParam{name: name, contract: contract})
		}
	}
	return hits
}

// buildWordlist merges the static wordlist with candidate parameter names mined
// from the endpoint's own response (the param-miner idea). Bounded and deduped.
func (s *ParamFuzzScanner) buildWordlist(ctx context.Context, endpoint string, auth map[string]string, extra []string) []string {
	staticWords := s.parameterCorpus()
	seen := make(map[string]bool, len(staticWords)+len(extra)+64)
	out := make([]string, 0, len(staticWords)+len(extra)+64)
	add := func(n string) {
		n = strings.TrimSpace(n)
		key := n // HTTP parameter names may be case-sensitive.
		if !usableParamName(n) || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, n)
	}
	for _, w := range staticWords {
		add(w)
	}
	// Cross-URL names discovered elsewhere on the target (JS, historical URLs).
	for _, w := range extra {
		add(w)
	}
	for _, w := range parameterConventionWords(extra) {
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

func (s *ParamFuzzScanner) parameterCorpus() []string {
	corpusDir := ""
	if s.cfg != nil {
		corpusDir = s.cfg.WordlistsDir
	}
	return LoadCorpus(corpusDir, "parameters", paramFuzzWords)
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
		if !usableParamName(name) {
			continue
		}
		out = append(out, name)
	}
	return out
}

func usableParamName(name string) bool {
	name = strings.TrimSpace(name)
	return reParamName.MatchString(name) && !isAllDigits(name) && !isTrackingParam(name)
}

// parameterConventionWords mirrors a small, high-value concept set into the
// target's observed naming convention. It does not add values or payloads; it
// only avoids missing accountId on a camelCase API when the static list happens
// to contain account_id.
func parameterConventionWords(observed []string) []string {
	camel, snake, kebab := 0, 0, 0
	for _, name := range observed {
		switch {
		case strings.Contains(name, "_"):
			snake++
		case strings.Contains(name, "-"):
			kebab++
		case reCamelName.MatchString(name):
			camel++
		}
	}
	style := "snake"
	if camel > snake && camel >= kebab {
		style = "camel"
	} else if kebab > snake && kebab > camel {
		style = "kebab"
	}
	concepts := []string{
		"account_id", "user_id", "object_id", "tenant_id", "organization_id",
		"project_id", "resource_id", "record_id", "redirect_uri", "return_url",
		"callback_url", "webhook_url", "template_id", "template_name", "debug_mode",
	}
	out := make([]string, 0, len(concepts))
	for _, concept := range concepts {
		switch style {
		case "camel":
			parts := strings.Split(concept, "_")
			var b strings.Builder
			b.WriteString(parts[0])
			for _, p := range parts[1:] {
				if p != "" {
					b.WriteString(strings.ToUpper(p[:1]))
					b.WriteString(p[1:])
				}
			}
			out = append(out, b.String())
		case "kebab":
			out = append(out, strings.ReplaceAll(concept, "_", "-"))
		default:
			out = append(out, concept)
		}
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

type pfProbe struct {
	status      int
	body        string
	contentType string
	location    string
	headerShape string
}

type pfBaseline struct {
	status, minLen, maxLen, tolerance int
	contentType, location, headers    string
	bodyHash                          string
	stableStatus, stableContentType   bool
	stableLocation, stableHeaders     bool
	stableBody                        bool
}

const (
	pfSignalStatus uint32 = 1 << iota
	pfSignalContentType
	pfSignalLocation
	pfSignalHeaders
	pfSignalBody
	pfSignalLength
	pfSignalReflection
)

func (s *ParamFuzzScanner) learnBaseline(ctx context.Context, endpoint string, contract pfContract, auth map[string]string) (pfBaseline, bool) {
	probes := make([]pfProbe, 0, pfBaselineSamples)
	for i := 0; i < pfBaselineSamples; i++ {
		p := s.probe(ctx, endpoint, nil, "", contract, auth)
		if !usableParamProbe(p) {
			return pfBaseline{}, false
		}
		probes = append(probes, p)
	}
	b := pfBaseline{
		status:            probes[0].status,
		contentType:       probes[0].contentType,
		location:          probes[0].location,
		headers:           probes[0].headerShape,
		bodyHash:          canonicalBodyHash(probes[0].body, nil, ""),
		minLen:            len(probes[0].body),
		maxLen:            len(probes[0].body),
		stableStatus:      true,
		stableContentType: true,
		stableLocation:    true,
		stableHeaders:     true,
		stableBody:        true,
	}
	for _, p := range probes[1:] {
		if p.status != b.status {
			b.stableStatus = false
		}
		if p.contentType != b.contentType {
			b.stableContentType = false
		}
		if p.location != b.location {
			b.stableLocation = false
		}
		if p.headerShape != b.headers {
			b.stableHeaders = false
		}
		if canonicalBodyHash(p.body, nil, "") != b.bodyHash {
			b.stableBody = false
		}
		if len(p.body) < b.minLen {
			b.minLen = len(p.body)
		}
		if len(p.body) > b.maxLen {
			b.maxLen = len(p.body)
		}
	}
	spread := b.maxLen - b.minLen
	b.tolerance = pfLenTolerance + spread*2
	return b, true
}

// bisect isolates which params in a chunk affect the response. Every positive
// batch is first compared with a same-size, same-shape set of nonsense names;
// this rejects catch-all echo/validation behaviour before recursion creates a
// row for every word in the dictionary.
func (s *ParamFuzzScanner) bisect(ctx context.Context, endpoint string, chunk []string, baseline pfBaseline, contract pfContract, auth map[string]string) []string {
	if len(chunk) == 0 || ctx.Err() != nil {
		return nil
	}
	candidate := s.probe(ctx, endpoint, chunk, pfCanary, contract, auth)
	if signalAgainstBaseline(candidate, baseline, chunk, pfCanary) == 0 {
		return nil
	}
	controls := controlParamNames(chunk, endpoint+"|batch")
	control := s.probe(ctx, endpoint, controls, pfCanary, contract, auth)
	if discriminatedSignals(candidate, control, baseline, chunk, controls, pfCanary) == 0 {
		return nil
	}
	if len(chunk) == 1 {
		if s.verifyParam(ctx, endpoint, chunk[0], baseline, contract, auth) {
			return chunk
		}
		return nil
	}
	mid := len(chunk) / 2
	left := s.bisect(ctx, endpoint, chunk[:mid], baseline, contract, auth)
	right := s.bisect(ctx, endpoint, chunk[mid:], baseline, contract, auth)
	return append(left, right...)
}

func (s *ParamFuzzScanner) verifyParam(ctx context.Context, endpoint, name string, baseline pfBaseline, contract pfContract, auth map[string]string) bool {
	var shared uint32
	for round := 0; round < 2; round++ {
		marker := verificationMarker(endpoint, name, round)
		controlNames := controlParamNames([]string{name}, fmt.Sprintf("%s|verify|%d", endpoint, round))
		candidate := s.probe(ctx, endpoint, []string{name}, marker, contract, auth)
		control := s.probe(ctx, endpoint, controlNames, marker, contract, auth)
		signals := discriminatedSignals(candidate, control, baseline, []string{name}, controlNames, marker)
		if signals == 0 {
			return false
		}
		if round == 0 {
			shared = signals
		} else if shared&signals == 0 {
			return false
		}
	}
	return shared != 0
}

func verificationMarker(endpoint, name string, round int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d\x00%d", endpoint, name, round, time.Now().UnixNano())))
	return fmt.Sprintf("rcnfz%x", sum[:6])
}

func controlParamNames(names []string, salt string) []string {
	out := make([]string, 0, len(names))
	reserved := make(map[string]bool, len(paramFuzzWords)+len(names))
	for _, name := range paramFuzzWords {
		reserved[strings.ToLower(name)] = true
	}
	for _, name := range names {
		reserved[strings.ToLower(name)] = true
	}
	for i, name := range names {
		var control string
		for attempt := 0; attempt < 32; attempt++ {
			sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d\x00%d", salt, name, i, attempt)))
			letters := "abcdefghijklmnopqrstuvwxyz"
			digits := "0123456789"
			buf := []byte(name)
			for j, c := range buf {
				switch {
				case c >= 'A' && c <= 'Z':
					buf[j] = letters[int(sum[j%len(sum)])%len(letters)] - ('a' - 'A')
				case c >= 'a' && c <= 'z':
					buf[j] = letters[int(sum[j%len(sum)])%len(letters)]
				case c >= '0' && c <= '9':
					buf[j] = digits[int(sum[j%len(sum)])%len(digits)]
				}
			}
			// A high, attempt-varying leading letter keeps controls away from
			// common names while retaining the original length/separator layout.
			if len(buf) > 0 && ((buf[0] >= 'a' && buf[0] <= 'z') || (buf[0] >= 'A' && buf[0] <= 'Z')) {
				lead := byte('z' - (attempt+i)%20)
				if buf[0] >= 'A' && buf[0] <= 'Z' {
					lead -= 'a' - 'A'
				}
				buf[0] = lead
			}
			candidate := string(buf)
			if candidate != name && reParamName.MatchString(candidate) && !reserved[strings.ToLower(candidate)] {
				control = candidate
				break
			}
		}
		if control == "" {
			sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d", salt, name, i)))
			control = "z" + fmt.Sprintf("%x", sum[:5])
		}
		reserved[strings.ToLower(control)] = true
		out = append(out, control)
	}
	return out
}

func usableParamProbe(p pfProbe) bool {
	if p.status == 0 || p.status == http.StatusRequestTimeout || p.status == http.StatusTooManyRequests || p.status >= 500 {
		return false
	}
	return true
}

func signalAgainstBaseline(p pfProbe, b pfBaseline, names []string, marker string) uint32 {
	if !usableParamProbe(p) {
		return 0
	}
	var out uint32
	if b.stableStatus && p.status != b.status {
		out |= pfSignalStatus
	}
	if b.stableContentType && p.contentType != b.contentType {
		out |= pfSignalContentType
	}
	if b.stableLocation && canonicalText(p.location, names, marker) != b.location {
		out |= pfSignalLocation
	}
	if b.stableHeaders && p.headerShape != b.headers {
		out |= pfSignalHeaders
	}
	if b.stableBody && canonicalBodyHash(p.body, names, marker) != b.bodyHash {
		out |= pfSignalBody
	}
	if len(p.body) < b.minLen-b.tolerance || len(p.body) > b.maxLen+b.tolerance {
		out |= pfSignalLength
	}
	if marker != "" && strings.Contains(p.body, marker) {
		out |= pfSignalReflection
	}
	return out
}

func discriminatedSignals(candidate, control pfProbe, b pfBaseline, candidateNames, controlNames []string, marker string) uint32 {
	if !usableParamProbe(candidate) || !usableParamProbe(control) {
		return 0
	}
	signals := signalAgainstBaseline(candidate, b, candidateNames, marker)
	var out uint32
	if signals&pfSignalStatus != 0 && candidate.status != control.status {
		out |= pfSignalStatus
	}
	if signals&pfSignalContentType != 0 && candidate.contentType != control.contentType {
		out |= pfSignalContentType
	}
	candidateLocation := canonicalText(candidate.location, candidateNames, marker)
	controlLocation := canonicalText(control.location, controlNames, marker)
	if signals&pfSignalLocation != 0 && candidateLocation != controlLocation {
		out |= pfSignalLocation
	}
	if signals&pfSignalHeaders != 0 && candidate.headerShape != control.headerShape {
		out |= pfSignalHeaders
	}
	candidateHash := canonicalBodyHash(candidate.body, candidateNames, marker)
	controlHash := canonicalBodyHash(control.body, controlNames, marker)
	if signals&pfSignalBody != 0 && candidateHash != controlHash {
		out |= pfSignalBody
	}
	if signals&pfSignalLength != 0 && abs(len(candidate.body)-len(control.body)) > b.tolerance {
		out |= pfSignalLength
	}
	if signals&pfSignalReflection != 0 && !strings.Contains(control.body, marker) {
		out |= pfSignalReflection
	}
	return out
}

func canonicalBodyHash(body string, names []string, marker string) string {
	return normalizedHash(canonicalText(body, names, marker))
}

func canonicalText(value string, names []string, marker string) string {
	if marker != "" {
		for _, variant := range []string{marker, url.QueryEscape(marker)} {
			value = strings.ReplaceAll(value, variant, "<VALUE>")
		}
	}
	ordered := append([]string(nil), names...)
	sort.SliceStable(ordered, func(i, j int) bool { return len(ordered[i]) > len(ordered[j]) })
	for _, name := range ordered {
		value = replaceParamToken(value, name)
		if escaped := url.QueryEscape(name); escaped != name {
			value = strings.ReplaceAll(value, escaped, "<PARAM>")
		}
	}
	return value
}

func replaceParamToken(value, name string) string {
	if name == "" {
		return value
	}
	// Parameter characters on either side mean this occurrence belongs to a
	// larger word in ordinary page content. Replacing only complete tokens avoids
	// making one-letter candidates (q/s/id) manufacture body differences.
	re := regexp.MustCompile(`(^|[^A-Za-z0-9_.\-\[\]])` + regexp.QuoteMeta(name) + `([^A-Za-z0-9_.\-\[\]]|$)`)
	return re.ReplaceAllString(value, `${1}<PARAM>${2}`)
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

// probe replays one known request contract, adding only the inert parameter
// names/marker supplied by the miner. Existing query values and required body
// siblings are retained.
func (s *ParamFuzzScanner) probe(ctx context.Context, endpoint string, params []string, marker string, contract pfContract, auth map[string]string) pfProbe {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return pfProbe{}
	}

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var req *http.Request
	method := strings.ToUpper(strings.TrimSpace(contract.method))
	if method == "" {
		if contract.loc == pfQuery {
			method = http.MethodGet
		} else {
			method = http.MethodPost
		}
	}
	switch contract.loc {
	case pfBody:
		form := url.Values{}
		for name, value := range contract.siblings {
			form.Set(name, value)
		}
		for _, p := range params {
			form.Set(p, marker)
		}
		req, err = http.NewRequestWithContext(reqCtx, method, parsed.String(), strings.NewReader(form.Encode()))
		if err == nil {
			contentType := strings.TrimSpace(contract.contentType)
			if contentType == "" {
				contentType = "application/x-www-form-urlencoded"
			}
			req.Header.Set("Content-Type", contentType)
		}
	case pfJSON:
		fields := make(map[string]string, len(contract.siblings)+len(params))
		for name, value := range contract.siblings {
			fields[name] = value
		}
		for _, p := range params {
			fields[p] = marker
		}
		body := buildJSONFieldsTyped(fields, contract.siblingTypes, "")
		req, err = http.NewRequestWithContext(reqCtx, method, parsed.String(), strings.NewReader(body))
		if err == nil {
			contentType := strings.TrimSpace(contract.contentType)
			if contentType == "" {
				contentType = "application/json"
			}
			req.Header.Set("Content-Type", contentType)
		}
	default: // pfQuery
		q := parsed.Query()
		for name, value := range contract.siblings {
			if !q.Has(name) {
				q.Set(name, value)
			}
		}
		for _, p := range params {
			q.Set(p, marker)
		}
		parsed.RawQuery = q.Encode()
		req, err = http.NewRequestWithContext(reqCtx, method, parsed.String(), nil)
	}
	if err != nil {
		return pfProbe{}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
	for k, v := range auth {
		req.Header.Set(k, v)
	}
	resp, err := paramFuzzClient.Do(req)
	if err != nil {
		return pfProbe{}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	resp.Body.Close()
	return pfProbe{
		status:      resp.StatusCode,
		body:        string(body),
		contentType: normalizeMediaType(resp.Header.Get("Content-Type")),
		location:    resp.Header.Get("Location"),
		headerShape: stableHeaderShape(resp.Header),
	}
}

func normalizeMediaType(contentType string) string {
	if i := strings.IndexByte(contentType, ';'); i >= 0 {
		contentType = contentType[:i]
	}
	return strings.ToLower(strings.TrimSpace(contentType))
}

func stableHeaderShape(header http.Header) string {
	volatile := map[string]bool{
		"age": true, "content-length": true, "date": true, "etag": true,
		"expires": true, "last-modified": true, "set-cookie": true,
		"server-timing": true, "timing-allow-origin": true, "x-request-id": true,
		"x-correlation-id": true, "traceparent": true,
	}
	keys := make([]string, 0, len(header))
	for key := range header {
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" || volatile[key] {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return strings.Join(keys, "\n")
}

func defaultPFContract(loc pfLoc) pfContract {
	switch loc {
	case pfBody:
		return pfContract{loc: pfBody, method: http.MethodPost, contentType: "application/x-www-form-urlencoded"}
	case pfJSON:
		return pfContract{loc: pfJSON, method: http.MethodPost, contentType: "application/json"}
	default:
		return pfContract{loc: pfQuery, method: http.MethodGet}
	}
}

func contractKey(c pfContract) string {
	return fmt.Sprintf("%d|%s|%s", c.loc, strings.ToUpper(c.method), normalizeMediaType(c.contentType))
}

func appendContract(ep *pfEndpoint, contract pfContract) {
	contract.method = strings.ToUpper(strings.TrimSpace(contract.method))
	if contract.method == "" {
		contract = defaultPFContract(contract.loc)
	}
	for i := range ep.contracts {
		if contractKey(ep.contracts[i]) != contractKey(contract) {
			continue
		}
		for name, value := range contract.siblings {
			if ep.contracts[i].siblings == nil {
				ep.contracts[i].siblings = map[string]string{}
			}
			ep.contracts[i].siblings[name] = value
		}
		for name, typ := range contract.siblingTypes {
			if ep.contracts[i].siblingTypes == nil {
				ep.contracts[i].siblingTypes = map[string]string{}
			}
			ep.contracts[i].siblingTypes[name] = typ
		}
		return
	}
	ep.contracts = append(ep.contracts, contract)
}

func endpointPriority(rawURL, contentType string, observedContract bool) int {
	score := 0
	u, err := url.Parse(rawURL)
	if err == nil {
		path := strings.ToLower(u.Path)
		if path != "" && path != "/" {
			score += 10
		}
		if strings.Contains(path, "/api/") || strings.HasPrefix(path, "/api") || strings.Contains(path, "/graphql") {
			score += 35
		}
		if u.RawQuery != "" {
			score += 10
		}
	}
	if strings.Contains(strings.ToLower(contentType), "json") {
		score += 30
	}
	if observedContract {
		score += 100
	}
	return score
}

// selectEndpoints builds request-aware endpoint contracts and ranks them before
// applying the cap. This prevents an alphabetic page list from crowding an
// observed API/form request out of the scan budget.
func (s *ParamFuzzScanner) selectEndpoints(ctx context.Context, targetID string) []pfEndpoint {
	if s.db == nil {
		return nil
	}
	cmsSkip := loadCMSSkipHosts(s.db, targetID)
	byURL := map[string]*pfEndpoint{}
	contentTypes := map[string]string{}
	ensure := func(rawURL string) *pfEndpoint {
		rawURL = strings.TrimSpace(rawURL)
		u, err := url.Parse(rawURL)
		if err != nil || u.Scheme == "" || u.Host == "" || isStaticAssetPath(u.Path) ||
			hostSkippedByCMS(rawURL, cmsSkip) || !urlHostInScope(ctx, rawURL) || !urlInEndpointScope(ctx, rawURL) {
			return nil
		}
		u.Fragment = ""
		rawURL = u.String()
		if byURL[rawURL] == nil {
			byURL[rawURL] = &pfEndpoint{url: rawURL}
		}
		return byURL[rawURL]
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT url,COALESCE(content_type,'') FROM http_services
		WHERE target_id=? AND status_code BETWEEN 200 AND 403
		ORDER BY CASE WHEN LOWER(content_type) LIKE '%json%' THEN 0 ELSE 1 END,
			LENGTH(url),url LIMIT ?`, targetID, pfEndpointPool)
	if err == nil {
		for rows.Next() {
			var rawURL, contentType string
			if rows.Scan(&rawURL, &contentType) != nil {
				continue
			}
			if ep := ensure(rawURL); ep != nil {
				contentTypes[ep.url] = contentType
			}
		}
		rows.Close()
	}

	// Parameter rows represent requests already observed in crawl/OpenAPI/form
	// discovery. Grouping them reconstructs all required sibling values and JSON
	// scalar types for the mining request.
	rows, err = s.db.QueryContext(ctx, `
		SELECT url,parameter,COALESCE(value,''),COALESCE(method,'GET'),
			COALESCE(content_type,''),COALESCE(location,'query')
		FROM parameters WHERE target_id=?
		ORDER BY LENGTH(url),url,method,content_type,location,parameter
		LIMIT ?`, targetID, pfEndpointPool*2)
	if err == nil {
		for rows.Next() {
			var rawURL, name, value, method, contentType, location string
			if rows.Scan(&rawURL, &name, &value, &method, &contentType, &location) != nil {
				continue
			}
			ep := ensure(rawURL)
			if ep == nil {
				continue
			}
			loc := pfQuery
			normalizedLocation := strings.ToLower(strings.TrimSpace(location))
			if strings.Contains(strings.ToLower(contentType), "json") || strings.HasPrefix(normalizedLocation, "json") {
				loc = pfJSON
			} else if normalizedLocation == "body" || strings.Contains(strings.ToLower(contentType), "x-www-form-urlencoded") {
				loc = pfBody
			} else if normalizedLocation != "" && normalizedLocation != "query" {
				continue
			}
			contract := pfContract{
				loc:          loc,
				method:       method,
				contentType:  contentType,
				siblings:     map[string]string{name: value},
				siblingTypes: map[string]string{},
			}
			if loc == pfJSON {
				if typ := insertionJSONType(location); typ != "" {
					contract.siblingTypes[name] = typ
				}
			}
			appendContract(ep, contract)
			if score := endpointPriority(ep.url, contentType, true); score > ep.score {
				ep.score = score
			}
		}
		rows.Close()
	}

	out := make([]pfEndpoint, 0, len(byURL))
	for _, ep := range byURL {
		contentType := contentTypes[ep.url]
		appendContract(ep, defaultPFContract(pfQuery))
		// Preserve blind body coverage for API-looking endpoints without turning
		// every ordinary HTML page into two speculative POST requests.
		hasJSONContract := false
		for _, contract := range ep.contracts {
			if contract.loc == pfJSON {
				hasJSONContract = true
				break
			}
		}
		if !hasJSONContract && endpointPriority(ep.url, contentType, false) >= 35 {
			appendContract(ep, defaultPFContract(pfJSON))
		}
		if score := endpointPriority(ep.url, contentType, false); score > ep.score {
			ep.score = score
		}
		out = append(out, *ep)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].score != out[j].score {
			return out[i].score > out[j].score
		}
		return out[i].url < out[j].url
	})

	// Collapse value variants of the same route after ranking, retaining the
	// representative with the strongest observed request contract.
	seenRoutes := map[string]bool{}
	selected := make([]pfEndpoint, 0, minInt(pfMaxHosts, len(out)))
	for _, ep := range out {
		u, err := url.Parse(ep.url)
		if err != nil {
			continue
		}
		var queryNames, contracts []string
		for name := range u.Query() {
			queryNames = append(queryNames, name)
		}
		for _, contract := range ep.contracts {
			contracts = append(contracts, contractKey(contract))
		}
		sort.Strings(queryNames)
		sort.Strings(contracts)
		route := strings.ToLower(u.Scheme+"://"+u.Host) + u.EscapedPath() +
			"?" + strings.Join(queryNames, "&") + "|" + strings.Join(contracts, ";")
		if seenRoutes[route] {
			continue
		}
		seenRoutes[route] = true
		selected = append(selected, ep)
		if len(selected) >= pfMaxHosts {
			break
		}
	}
	return selected
}

func (s *ParamFuzzScanner) storeParam(targetID, endpoint string, p minedParam) bool {
	method := strings.ToUpper(strings.TrimSpace(p.contract.method))
	contentType := strings.TrimSpace(p.contract.contentType)
	location := "query"
	if method == "" {
		method = http.MethodGet
	}
	switch p.contract.loc {
	case pfBody:
		location = "body"
		if contentType == "" {
			contentType = "application/x-www-form-urlencoded"
		}
	case pfJSON:
		location = "json:string"
		if contentType == "" {
			contentType = "application/json"
		}
	}
	id := uuid.New().String()
	res, err := s.db.Exec(`
		INSERT INTO parameters (id,target_id,url,parameter,value,source,method,content_type,location)
		VALUES (?,?,?,?,'','fuzz',?,?,?)
		ON CONFLICT(target_id,url,parameter,method,location,content_type) DO NOTHING
	`, id, targetID, endpoint, p.name, method, contentType, location)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}
