package scanner

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"math"
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
	"github.com/recon-platform/internal/models"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

type JSScanner struct {
	broadcast BroadcastFunc
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
}

func NewJSScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *JSScanner {
	return &JSScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

type jsPattern struct {
	Type     string
	Severity string
	Pattern  *regexp.Regexp
}

var jsPatterns = []jsPattern{
	// Endpoints
	{"endpoint", "info", regexp.MustCompile(`["'` + "`" + `](\/api\/[a-zA-Z0-9_\-\/:.?=&%]+)["'` + "`" + `]`)},
	{"endpoint", "info", regexp.MustCompile(`["'` + "`" + `](\/v[0-9]+\/[a-zA-Z0-9_\-\/:.?=&%]+)["'` + "`" + `]`)},
	{"endpoint", "info", regexp.MustCompile(`["'` + "`" + `](\/rest\/[a-zA-Z0-9_\-\/:.?=&%]+)["'` + "`" + `]`)},
	// GraphQL
	{"graphql", "info", regexp.MustCompile(`(?i)["'` + "`" + `](\/graphql[\/a-zA-Z0-9_\-?=]*)["'` + "`" + `]`)},
	// WebSocket
	{"websocket", "medium", regexp.MustCompile(`(?i)(wss?:\/\/[a-zA-Z0-9\-._:\/]+)`)},
	// API URLs
	{"api_url", "info", regexp.MustCompile(`(?i)https?:\/\/[a-z0-9\-._]+\.[a-z]{2,}(?:\/[^\s"'` + "`" + `<>]{1,100})?\/(?:api|rest|graphql|gql)[^\s"'` + "`" + `<>]*`)},
	// Secrets
	{"secret", "high", regexp.MustCompile(`(?i)(?:api[_\-]?key|apikey|api_secret|app_secret)["\s]*[:=]["\s]*["'` + "`" + `]([a-zA-Z0-9_\-]{16,})["'` + "`" + `]`)},
	{"secret", "high", regexp.MustCompile(`(?i)(?:secret|private_key|client_secret)["\s]*[:=]["\s]*["'` + "`" + `]([a-zA-Z0-9_\-\/+]{20,})["'` + "`" + `]`)},
	{"password", "critical", regexp.MustCompile(`(?i)(?:password|passwd|pwd)["\s]*[:=]["\s]*["'` + "`" + `]([^\s"'` + "`" + `]{6,})["'` + "`" + `]`)},
	{"token", "high", regexp.MustCompile(`(?i)(?:access_token|auth_token|bearer)["\s]*[:=]["\s]*["'` + "`" + `]([a-zA-Z0-9_\-\.]{20,})["'` + "`" + `]`)},
	// AWS
	{"aws_key", "critical", regexp.MustCompile(`(?:AKIA|ASIA|AROA|AIDA|ANPA|ANVA|AIPA)[0-9A-Z]{16}`)},
	{"aws_secret", "critical", regexp.MustCompile(`(?i)aws.{0,20}secret.{0,20}["'` + "`" + `]([a-zA-Z0-9\/+]{40})["'` + "`" + `]`)},
	// JWT
	{"jwt", "high", regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{4,}\.eyJ[a-zA-Z0-9_-]{4,}\.[a-zA-Z0-9_-]{4,}`)},
	// Private keys
	{"private_key", "critical", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)},
	// Internal URLs
	{"internal_url", "medium", regexp.MustCompile(`(?i)["'` + "`" + `](https?:\/\/(?:localhost|127\.[0-9.]+|10\.[0-9.]+|192\.168\.[0-9.]+|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9.]+)[^\s"'` + "`" + `<>]*)["'` + "`" + `]`)},
	// Config vars
	{"config", "info", regexp.MustCompile(`(?i)(?:baseUrl|base_url|apiUrl|api_url|serverUrl|server_url|backendUrl|backend_url)\s*[:=]\s*["'` + "`" + `]([^"'` + "`" + `\s]{8,})["'` + "`" + `]`)},
	// S3 buckets
	{"s3_bucket", "medium", regexp.MustCompile(`(?i)[a-z0-9\-._]{3,63}\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com`)},
	// Firebase
	{"firebase", "medium", regexp.MustCompile(`(?i)[a-z0-9\-]{3,30}\.firebaseio\.com`)},
	// Google API key
	{"google_api", "high", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)},
	// Stripe
	{"stripe_key", "critical", regexp.MustCompile(`(?:sk_live_|pk_live_|rk_live_)[a-zA-Z0-9]{24,}`)},
	// Slack
	{"slack_token", "high", regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z\-]{10,50}`)},
	// SendGrid
	{"sendgrid", "high", regexp.MustCompile(`SG\.[a-zA-Z0-9_\-.]{20,}`)},
	// Twilio
	{"twilio", "high", regexp.MustCompile(`SK[0-9a-fA-F]{32}`)},
	// Debug endpoints
	{"debug_endpoint", "medium", regexp.MustCompile(`(?i)["'` + "`" + `](\/debug[\/a-zA-Z0-9_\-?=]*)["'` + "`" + `]`)},
	{"debug_endpoint", "medium", regexp.MustCompile(`(?i)["'` + "`" + `](\/test[\/a-zA-Z0-9_\-?=]*)["'` + "`" + `]`)},
	// Auth endpoints
	{"auth_endpoint", "info", regexp.MustCompile(`(?i)["'` + "`" + `](\/(?:auth|oauth|login|logout|signin|signup|register|token|refresh)[\/a-zA-Z0-9_\-?=]*)["'` + "`" + `]`)},
	// Source maps
	{"sourcemap", "low", regexp.MustCompile(`sourceMappingURL=([^\s"'` + "`" + `]+\.map)`)},
}

func (s *JSScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "js_analysis", "Collecting JavaScript files from HTTP services...")

	// Clear STATIC (unverified) DOM-XSS candidates from a previous run so a re-scan
	// replaces them with the current, precise set instead of accumulating. Confirmed
	// dom_xss findings (browser-proven) and operator-triaged rows are preserved.
	_, _ = s.db.ExecContext(ctx, `
		DELETE FROM vuln_findings
		WHERE target_id = ? AND type = 'dom_xss' AND COALESCE(triage,'') = ''
		  AND (
			COALESCE(status,'') = 'candidate'
			OR candidate_id IN (
				SELECT id FROM candidates
				WHERE target_id=? AND type='dom_xss' AND subtype='static-flow'
				  AND status NOT IN ('CONFIRMED','VERIFIED')
			)
		  )`, targetID, targetID)
	_, _ = s.db.ExecContext(ctx, `DELETE FROM js_findings WHERE target_id=? AND type='dom_param'`, targetID)

	var targetDomain string
	_ = s.db.QueryRowContext(ctx, `SELECT domain FROM targets WHERE id = ?`, targetID).Scan(&targetDomain)

	// Only crawl REAL probed hosts, not the JS-derived endpoints that the
	// js_endpoints module later injects into http_services — otherwise a re-scan
	// would crawl thousands of endpoint URLs and take far too long.
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT url FROM http_services WHERE target_id = ? AND COALESCE(source,'probe') IN ('probe','seed') ORDER BY url`, targetID)
	if err != nil {
		return fmt.Errorf("query http services: %w", err)
	}
	var serviceURLs []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err == nil {
			serviceURLs = append(serviceURLs, u)
		}
	}
	rows.Close()

	// Per-asset host scope
	if hostScopeSet(ctx) != nil {
		kept := serviceURLs[:0]
		for _, u := range serviceURLs {
			if urlHostInScope(ctx, u) {
				kept = append(kept, u)
			}
		}
		serviceURLs = kept
	}

	if len(serviceURLs) == 0 {
		logFn("info", "js_analysis", "No HTTP services found")
		return nil
	}

	addInScope := func(u string, m *sync.Mutex, files map[string]bool) {
		parsed, err := url.Parse(strings.TrimSpace(u))
		// Tool crawlers can emit third-party assets found several hops away. Admit
		// only the target domain here; discoverJSFromHTML separately permits a
		// non-tracker CDN bundle when the target page references it directly.
		if err == nil && (targetDomain == "" || isTargetDomainHost(parsed.Hostname(), targetDomain)) {
			m.Lock()
			files[u] = true
			m.Unlock()
		}
	}

	jsFiles := make(map[string]bool)
	var jsMu sync.Mutex

	// Crawl hosts CONCURRENTLY with a hard per-host time budget. The old code
	// ran katana sequentially at depth 3 with no timeout, so ~60 hosts took 15+
	// minutes. Now: bounded worker pool + per-host crawl-duration cap (-ct) so
	// total time is roughly (hosts / concurrency) * budget.
	const crawlConcurrency = 8
	if s.exec.IsToolAvailable("katana") {
		logFn("info", "js_analysis", fmt.Sprintf("Discovering JS files with katana (%d hosts, parallel)...", len(serviceURLs)))
		sem := make(chan struct{}, crawlConcurrency)
		var wg sync.WaitGroup
		for _, svcURL := range serviceURLs {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(u string) {
				defer wg.Done()
				defer func() { <-sem }()
				// -ct 30: stop crawling a host after 30s; -depth 2; -timeout 8.
				hostCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
				defer cancel()
				args := []string{"-u", u, "-jc", "-silent", "-depth", "2", "-ct", "30", "-timeout", "8", "-kf", "all"}
				args = append(args, ToolRequestIdentityArgs(hostCtx, "katana")...)
				_ = s.exec.RunWithCallback(hostCtx, targetID, func(line string) {
					line = strings.TrimSpace(line)
					if isJSURL(line) {
						addInScope(line, &jsMu, jsFiles)
					}
				}, "katana", args...)
			}(svcURL)
		}
		wg.Wait()
	}

	if s.exec.IsToolAvailable("hakrawler") {
		logFn("info", "js_analysis", "Discovering JS files with hakrawler (parallel)...")
		sem := make(chan struct{}, crawlConcurrency)
		var wg sync.WaitGroup
		for _, svcURL := range serviceURLs {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(u string) {
				defer wg.Done()
				defer func() { <-sem }()
				hostCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				defer cancel()
				args := []string{"-url", u, "-js", "-insecure"}
				args = append(args, ToolRequestIdentityArgs(hostCtx, "hakrawler")...)
				result, err := s.exec.Run(hostCtx, "hakrawler", args...)
				if err != nil {
					return
				}
				sc := bufio.NewScanner(strings.NewReader(result.Stdout))
				for sc.Scan() {
					line := strings.TrimSpace(sc.Text())
					if isJSURL(line) {
						addInScope(line, &jsMu, jsFiles)
					}
				}
			}(svcURL)
		}
		wg.Wait()
	}

	// Also find inline JS links from HTTP service HTML pages
	logFn("info", "js_analysis", "Discovering JS files from HTML pages...")
	for _, svcURL := range serviceURLs {
		if ctx.Err() != nil {
			break
		}
		s.discoverJSFromHTML(ctx, svcURL, targetDomain, &jsFiles, &jsMu)
	}

	jsMu.Lock()
	seeds := make([]string, 0, len(jsFiles))
	for jsURL := range jsFiles {
		seeds = append(seeds, jsURL)
	}
	jsMu.Unlock()
	logFn("info", "js_analysis", fmt.Sprintf("Found %d seed JS files. Traversing same-site dependency graph...", len(seeds)))
	analyzed := s.analyzeJSGraph(ctx, targetID, targetDomain, seeds, logFn)

	// Static source→sink flows are internal leads only. Immediately route them to
	// the real-browser verifier so a user sees a DOM-XSS finding only when an
	// attacker-controlled URL/window/message source actually executes. The stored
	// PoC is the alert(document.domain) equivalent of the nonce payload Chromium
	// proved; a failed/inert lead remains hidden in candidates.
	var pendingDOM int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM candidates
		WHERE target_id=? AND type='dom_xss' AND subtype='static-flow'
		  AND status IN ('DETECTED','TRIAGED','INCONCLUSIVE')`, targetID).Scan(&pendingDOM)
	if pendingDOM > 0 && ctx.Err() == nil {
		logFn("info", "dom_xss", fmt.Sprintf("Routing %d static DOM-XSS lead(s) to runtime browser proof...", pendingDOM))
		VerifyDOMXSSOnPages(ctx, s.db, targetID, logFn)
	}

	// Optional active verification of discovered credentials.
	if s.cfg.VerifySecrets {
		s.verifySecrets(ctx, targetID, logFn)
	}

	logFn("info", "js_analysis", fmt.Sprintf("JS analysis complete. Analyzed %d files.", analyzed))
	return nil
}

// verifySecrets actively checks discovered API keys against their providers and
// flags the ones that are live (verified=1, severity bumped to critical). Keys
// that fail verification are downgraded to info to cut triage noise.
func (s *JSScanner) verifySecrets(ctx context.Context, targetID string, logFn LogFunc) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, type, value FROM js_findings
		WHERE target_id = ? AND type IN ('aws_key','slack_token','google_api','stripe_key','sendgrid','github_token','secret')
	`, targetID)
	if err != nil {
		return
	}
	type row struct{ id, typ, val string }
	var items []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.typ, &r.val); err == nil {
			items = append(items, r)
		}
	}
	rows.Close()

	if len(items) == 0 {
		return
	}
	logFn("info", "js_analysis", fmt.Sprintf("Verifying %d candidate secrets against providers...", len(items)))

	verified := 0
	for _, it := range items {
		if ctx.Err() != nil {
			return
		}
		ok := verifySecretValue(ctx, it.typ, it.val)
		if ok {
			_, _ = s.db.Exec(`UPDATE js_findings SET verified = 1, severity = 'critical' WHERE id = ?`, it.id)
			verified++
			logFn("warn", "js_analysis", fmt.Sprintf("VERIFIED live secret: %s", it.typ))
			if s.broadcast != nil {
				s.broadcast("new_vuln_finding", map[string]any{
					"target_id": targetID, "type": "verified_secret_" + it.typ, "url": "",
				})
			}
		} else {
			// Unverifiable → likely placeholder/expired; lower the noise.
			_, _ = s.db.Exec(`UPDATE js_findings SET severity = 'info' WHERE id = ? AND verified = 0`, it.id)
		}
	}
	logFn("info", "js_analysis", fmt.Sprintf("Secret verification done. %d live secrets confirmed.", verified))
}

var secretHTTPClient = &http.Client{Timeout: 10 * time.Second, Transport: sharedHTTPTransport}

// verifySecretValue makes a minimal, read-only auth call to the provider.
func verifySecretValue(ctx context.Context, typ, value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	switch typ {
	case "slack_token":
		return verifyHTTP(ctx, "GET", "https://slack.com/api/auth.test",
			map[string]string{"Authorization": "Bearer " + value}, `"ok":true`)
	case "github_token":
		return verifyHTTP(ctx, "GET", "https://api.github.com/user",
			map[string]string{"Authorization": "Bearer " + value, "User-Agent": "ReconBot"}, `"login"`)
	case "sendgrid":
		return verifyHTTP(ctx, "GET", "https://api.sendgrid.com/v3/scopes",
			map[string]string{"Authorization": "Bearer " + value}, `"scopes"`)
	case "stripe_key":
		return verifyHTTP(ctx, "GET", "https://api.stripe.com/v1/balance",
			map[string]string{"Authorization": "Bearer " + value}, `"available"`)
	case "google_api":
		// Maps Geocode endpoint returns a status that isn't REQUEST_DENIED for valid keys.
		u := "https://maps.googleapis.com/maps/api/geocode/json?address=test&key=" + value
		return verifyHTTP(ctx, "GET", u, nil, `"results"`)
	}
	return false
}

func verifyHTTP(ctx context.Context, method, url string, headers map[string]string, wantSubstr string) bool {
	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, method, url, nil)
	if err != nil {
		return false
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := secretHTTPClient.Do(req)
	if err != nil {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	resp.Body.Close()
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return false
	}
	return strings.Contains(string(body), wantSubstr)
}

func isJSURL(u string) bool {
	lower := strings.ToLower(strings.Split(u, "?")[0])
	return strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".mjs") || strings.HasSuffix(lower, ".cjs")
}

// thirdPartyJSHosts are well-known analytics / ads / public-library CDN hosts.
// JavaScript served from them is not the target's application code, so analyzing
// it is pure noise. Everything NOT on this list that a target's own pages
// reference is treated as first-party-ish and worth analyzing.
var thirdPartyJSHosts = []string{
	"google-analytics.com", "googletagmanager.com", "googlesyndication.com", "doubleclick.net",
	"gstatic.com", "googleapis.com", "gtag", "google.com/recaptcha", "recaptcha.net",
	"facebook.net", "connect.facebook", "fbcdn.net",
	"cdnjs.cloudflare.com", "jsdelivr.net", "unpkg.com", "jquery.com", "bootstrapcdn.com",
	"polyfill.io", "typekit.net", "use.fontawesome.com", "cdn.ampproject.org",
	"hotjar.com", "segment.com", "segment.io", "mixpanel.com", "amplitude.com",
	"sentry.io", "sentry-cdn.com", "cloudflareinsights.com", "newrelic.com", "nr-data.net",
	"optimizely.com", "clarity.ms", "mc.yandex", "criteo", "taboola", "outbrain",
	"intercom", "intercomcdn.com", "zendesk", "zdassets.com", "drift.com", "tawk.to",
	"cookiebot.com", "onetrust.com", "cookielaw.org", "gravatar.com",
}

func isThirdPartyJSHost(host string) bool {
	for _, t := range thirdPartyJSHosts {
		if strings.Contains(host, t) {
			return true
		}
	}
	return false
}

// isInScope decides whether a discovered JS file is worth analyzing. First-party
// JS (the target domain or a subdomain) always qualifies. Crucially, so does
// off-domain JS that isn't a known third-party tracker/library host — modern apps
// (SPAs, Next.js, etc.) ship their OWN bundle from a separate static/CDN domain,
// and the old "must be a subdomain of the target" rule discarded exactly those
// bundles, so a site like snapp.cab yielded ZERO JS findings. Analyzing them
// (while still skipping analytics/ads/public-lib CDNs) is what surfaces the app's
// real endpoints and secrets.
func isInScope(jsURL, targetDomain string) bool {
	parsed, err := url.Parse(jsURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(strings.TrimPrefix(parsed.Hostname(), "www."))
	if isTargetDomainHost(host, targetDomain) {
		return true
	}
	return !isThirdPartyJSHost(host)
}

var jsLinkRE = regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']([^"']+\.(?:js|mjs|cjs)(?:[?#][^"']*)?)["']`)

func (s *JSScanner) discoverJSFromHTML(ctx context.Context, pageURL, targetDomain string, jsFiles *map[string]bool, mu *sync.Mutex) {
	client := &http.Client{Timeout: 10 * time.Second, Transport: sharedHTTPTransport}
	req, err := http.NewRequestWithContext(ctx, "GET", pageURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if targetDomain != "" && !isTargetDomainHost(resp.Request.URL.Hostname(), targetDomain) {
		return // redirect left target scope; do not trust its script inventory
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	matches := jsLinkRE.FindAllStringSubmatch(string(body), -1)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		jsURL := resolveJSReference(resp.Request.URL.String(), m[1])
		if jsURL == "" {
			continue
		}
		if targetDomain == "" || isInScope(jsURL, targetDomain) {
			mu.Lock()
			(*jsFiles)[jsURL] = true
			mu.Unlock()
		}
	}
}

type jsVisitState uint8

const (
	jsDiscovered jsVisitState = iota + 1
	jsVisiting
	jsDone
)

const (
	jsDependencyMaxDepth = 12
	jsDependencyMaxFiles = 5000
)

var jsDependencyPatterns = []*regexp.Regexp{
	regexp.MustCompile("(?m)\\b(?:import|export)\\s+(?:[^;\\n]*?\\s+from\\s*)?[\\\"'`]([^\\\"'`]+)[\\\"'`]"),
	regexp.MustCompile("(?m)\\b(?:import|require)\\s*\\(\\s*[\\\"'`]([^\\\"'`]+)[\\\"'`]\\s*\\)"),
	regexp.MustCompile("(?m)\\bimportScripts\\s*\\(\\s*[\\\"'`]([^\\\"'`]+)[\\\"'`]"),
	regexp.MustCompile("[\\\"'`]([^\\\"'`\\s]+\\.(?:js|mjs|cjs)(?:[?#][^\\\"'`\\s]*)?)[\\\"'`]"),
}

// analyzeJSGraph follows JavaScript-to-JavaScript dependencies to a bounded depth
// with an explicit state map. Cycles such as a→b→a are visited once, redirects and
// bodies are re-validated, and each accepted file is fetched/analyzed only once.
func (s *JSScanner) analyzeJSGraph(ctx context.Context, targetID, targetDomain string, seeds []string, logFn LogFunc) int {
	workers := 16
	if s.cfg != nil && s.cfg.Workers.JSAnalysis > 0 {
		workers = s.cfg.Workers.JSAnalysis
	}
	if workers < 4 {
		workers = 4
	}
	if workers > 32 {
		workers = 32
	}
	maxFiles := jsDependencyMaxFiles
	if s.cfg != nil && s.cfg.Limits.MaxURLsPerModule > 0 && s.cfg.Limits.MaxURLsPerModule < maxFiles {
		maxFiles = s.cfg.Limits.MaxURLsPerModule
	}

	states := map[string]jsVisitState{}
	var stateMu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	var analyzed atomic.Int64
	var schedule func(string, string, int)

	schedule = func(raw, parent string, depth int) {
		if ctx.Err() != nil || depth > jsDependencyMaxDepth {
			return
		}
		u := normalizeJSURL(raw)
		if u == "" || !isJSURL(u) {
			return
		}
		if parent == "" {
			if targetDomain != "" && !isInScope(u, targetDomain) {
				return
			}
		} else if !jsDependencyInScope(u, parent, targetDomain) {
			return
		}

		stateMu.Lock()
		if states[u] != 0 || len(states) >= maxFiles {
			stateMu.Unlock()
			return
		}
		states[u] = jsDiscovered
		stateMu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			stateMu.Lock()
			states[u] = jsVisiting
			stateMu.Unlock()
			content, finalURL, client, fetchErr := fetchJSContent(ctx, u)
			if fetchErr == nil && !jsRedirectInScope(finalURL, u, parent, targetDomain) {
				fetchErr = fmt.Errorf("JS redirect left the accepted scope")
			}
			if fetchErr == nil && finalURL != u {
				stateMu.Lock()
				if states[finalURL] != 0 {
					fetchErr = fmt.Errorf("JS redirect target already visited")
				} else {
					states[finalURL] = jsVisiting
				}
				stateMu.Unlock()
			}
			if fetchErr == nil {
				if err := s.analyzeJSContent(ctx, targetID, finalURL, content, client); err == nil {
					n := analyzed.Add(1)
					if n%25 == 0 {
						logFn("info", "js_analysis", fmt.Sprintf("Analyzed %d JS dependency files...", n))
					}
				}
			}
			<-sem

			if fetchErr == nil {
				for _, dep := range extractJSDependencies(finalURL, string(content)) {
					schedule(dep, finalURL, depth+1)
				}
			} else {
				s.logger.Debug("JS dependency rejected", "url", u, "error", fetchErr)
			}
			stateMu.Lock()
			states[u] = jsDone
			if finalURL != "" {
				states[finalURL] = jsDone
			}
			stateMu.Unlock()
		}()
	}

	for _, seed := range seeds {
		schedule(seed, "", 0)
	}
	wg.Wait()
	if len(states) >= maxFiles {
		logFn("warn", "js_analysis", fmt.Sprintf("JS dependency safety cap reached (%d files); narrow the target or raise max_urls_per_module for a deeper pass", maxFiles))
	}
	return int(analyzed.Load())
}

func normalizeJSURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return ""
	}
	u.Fragment = ""
	u.Host = strings.ToLower(u.Host)
	return u.String()
}

func resolveJSReference(baseURL, ref string) string {
	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return ""
	}
	r, err := url.Parse(strings.TrimSpace(ref))
	if err != nil {
		return ""
	}
	return normalizeJSURL(base.ResolveReference(r).String())
}

func extractJSDependencies(baseURL, content string) []string {
	seen := map[string]bool{}
	var out []string
	for _, re := range jsDependencyPatterns {
		for _, m := range re.FindAllStringSubmatch(content, -1) {
			if len(m) < 2 {
				continue
			}
			dep := resolveJSReference(baseURL, m[1])
			if dep != "" && isJSURL(dep) && !seen[dep] {
				seen[dep] = true
				out = append(out, dep)
			}
		}
	}
	return out
}

func jsDependencyInScope(child, parent, targetDomain string) bool {
	cu, cerr := url.Parse(child)
	pu, perr := url.Parse(parent)
	if cerr != nil || perr != nil || isThirdPartyJSHost(strings.ToLower(cu.Hostname())) {
		return false
	}
	if targetDomain == "" || isTargetDomainHost(cu.Hostname(), targetDomain) {
		return true
	}
	// A page may legitimately load its own bundle from a separate first-party CDN
	// hostname. Permit recursion only within that already-observed host; never let
	// an import jump from it into an arbitrary third-party dependency graph.
	return strings.EqualFold(cu.Hostname(), pu.Hostname())
}

func isTargetDomainHost(host, targetDomain string) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}
	scopes, _ := SplitScope(targetDomain)
	for _, scope := range scopes {
		scope = strings.TrimPrefix(strings.TrimSpace(scope), "*.")
		if scopeHost := hostOfURL(scope); scopeHost != "" && hostInDomainScope(host, scopeHost) {
			return true
		}
	}
	return false
}

func jsRedirectInScope(finalURL, requested, parent, targetDomain string) bool {
	if finalURL == "" {
		return false
	}
	if parent == "" {
		return targetDomain == "" || isInScope(finalURL, targetDomain)
	}
	return jsDependencyInScope(finalURL, parent, targetDomain) && jsDependencyInScope(finalURL, requested, targetDomain)
}

func fetchJSContent(ctx context.Context, jsURL string) ([]byte, string, *http.Client, error) {
	client := &http.Client{Timeout: 20 * time.Second, Transport: sharedHTTPTransport}
	req, err := http.NewRequestWithContext(ctx, "GET", jsURL, nil)
	if err != nil {
		return nil, "", client, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", client, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", client, fmt.Errorf("JS HTTP status %d", resp.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024+1))
	if err != nil {
		return nil, "", client, err
	}
	if len(content) == 0 || len(content) > 10*1024*1024 || strings.TrimSpace(string(content)) == "" {
		return nil, "", client, fmt.Errorf("empty or oversized JS body")
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	prefix := strings.ToLower(strings.TrimSpace(string(content[:minInt(len(content), 512)])))
	if strings.Contains(ct, "text/html") || strings.Contains(ct, "application/json") ||
		strings.HasPrefix(ct, "image/") || strings.Contains(ct, "text/css") || strings.Contains(ct, "font/") ||
		strings.HasPrefix(prefix, "<!doctype html") ||
		strings.HasPrefix(prefix, "<html") || strings.HasPrefix(prefix, "<head") || strings.HasPrefix(prefix, "<body") {
		return nil, "", client, fmt.Errorf("non-JavaScript HTML response")
	}
	return content, normalizeJSURL(resp.Request.URL.String()), client, nil
}

func parseBase(rawURL string) (string, error) {
	idx := strings.Index(rawURL[8:], "/")
	if idx == -1 {
		return rawURL, nil
	}
	return rawURL[:8+idx], nil
}

func (s *JSScanner) analyzeJSFile(ctx context.Context, targetID, jsURL string) error {
	content, finalURL, client, err := fetchJSContent(ctx, jsURL)
	if err != nil {
		return err
	}
	return s.analyzeJSContent(ctx, targetID, finalURL, content, client)
}

func (s *JSScanner) analyzeJSContent(ctx context.Context, targetID, jsURL string, content []byte, client *http.Client) error {

	hash := fmt.Sprintf("%x", sha256.Sum256(content))
	jsFileID := uuid.New().String()

	_, err := s.db.Exec(`
		INSERT INTO js_files (id, target_id, url, size, hash, analyzed, last_seen)
		VALUES (?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
		ON CONFLICT(target_id, url) DO UPDATE SET
			size = excluded.size,
			hash = excluded.hash,
			analyzed = 1,
			last_seen = CURRENT_TIMESTAMP
	`, jsFileID, targetID, jsURL, len(content), hash)
	if err != nil {
		return err
	}

	var existingID string
	_ = s.db.QueryRow("SELECT id FROM js_files WHERE target_id = ? AND url = ?", targetID, jsURL).Scan(&existingID)
	if existingID != "" {
		jsFileID = existingID
	}
	s.storeDOMParamHints(ctx, targetID, jsFileID, string(content))

	findings := s.extractFindings(string(content), jsURL)

	// DEEP DOM-XSS: scan the JS for attacker source → dangerous sink flows (the class
	// reflection-based XSS misses). Runs on both the shipped bundle and, below, the
	// source-map-recovered original (where the un-minified names make flows clearer).
	s.storeDOMXSSFindings(ctx, targetID, jsURL, string(content), false)

	// SOURCE-MAP RECOVERY: if the bundle references a .map with original
	// sources, recover them and scan the UN-MINIFIED code too — secrets and
	// internal endpoints are readable there. (jsrecon idea.) One-hop taint runs
	// here (fromSourceMap=true) because the recovered names are real.
	if recovered := recoverSourceMapSources(ctx, client, jsURL, string(content)); recovered != "" {
		findings = append(findings, s.extractFindings(recovered, jsURL+" (source-map)")...)
		s.storeDOMXSSFindings(ctx, targetID, jsURL+" (source-map)", recovered, true)
		s.storeDOMParamHints(ctx, targetID, jsFileID, recovered)
	}

	for _, f := range findings {
		f.ID = uuid.New().String()
		f.TargetID = targetID
		f.JSFileID = jsFileID
		_ = s.storeFinding(f)
	}

	// LIBRARY FINGERPRINT → KNOWN-CVE: flag outdated front-end libs with public
	// CVEs. Version-based ⇒ surfaced as a CANDIDATE, never a confirmed finding.
	for _, lib := range fingerprintVulnerableLibraries(string(content)) {
		s.storeLibraryCVE(targetID, jsURL, lib)
	}

	return nil
}

// storeLibraryCVE records an outdated-library finding as a candidate (heuristic,
// version-based) in vuln_findings so it shows in the Candidates view.
func (s *JSScanner) storeLibraryCVE(targetID, jsURL string, lib jsLibHit) {
	evidence := lib.Name + " " + lib.Version + " — " + lib.Note
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: "vulnerable_js_library", Subtype: lib.Name, Severity: lib.Severity,
		URL: jsURL, Method: "STATIC", Parameter: lib.Name, Location: "javascript",
		Payload: lib.Version, Evidence: evidence, Source: "js-analysis", DetectionMethod: "library-version",
		Confidence: 75, Verdict: CandDetected,
	})
}

func isSecretType(t string) bool {
	switch t {
	case "secret", "password", "token", "aws_secret", "google_api",
		"stripe_key", "slack_token", "sendgrid", "twilio":
		return true
	}
	return false
}

var placeholderNeedles = []string{
	"changeme", "change_me", "your", "example", "test", "dummy", "sample",
	"placeholder", "xxxx", "0000", "1234", "password", "secret", "apikey",
	"api_key", "null", "undefined", "none", "todo", "fixme", "<", "{{", "${",
	"foobar", "abcdef", "aaaa", "insert", "replace",
}

// isPlaceholderSecret reports whether a matched value is an obvious
// placeholder/example rather than a real credential.
func isPlaceholderSecret(v string) bool {
	lv := strings.ToLower(v)
	for _, n := range placeholderNeedles {
		if strings.Contains(lv, n) {
			return true
		}
	}
	// All-same-character or trivially repetitive values.
	if len(v) > 0 {
		allSame := true
		for i := 1; i < len(v); i++ {
			if v[i] != v[0] {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}
	}
	return false
}

// shannonEntropy returns bits-per-character; real secrets are high-entropy.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}
	n := float64(len(s))
	var e float64
	for _, c := range freq {
		p := c / n
		e -= p * math.Log2(p)
	}
	return e
}

func (s *JSScanner) extractFindings(content, sourceURL string) []*models.JSFinding {
	var findings []*models.JSFinding
	seen := make(map[string]bool)

	lines := strings.Split(content, "\n")
	for lineNum, line := range lines {
		if lineNum > 20000 {
			break
		}
		for _, pat := range jsPatterns {
			matches := pat.Pattern.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				value := match[0]
				if len(match) > 1 && match[1] != "" {
					value = match[1]
				}
				value = strings.TrimSpace(value)
				if value == "" || len(value) < 4 {
					continue
				}

				key := pat.Type + ":" + value
				if seen[key] {
					continue
				}
				seen[key] = true

				// Secret-class findings: filter placeholders/low-entropy values
				// that flood results (i18n strings, SDK docs, dev configs).
				severity := pat.Severity
				if isSecretType(pat.Type) {
					if isPlaceholderSecret(value) {
						continue // discard obvious non-secrets entirely
					}
					if shannonEntropy(value) < 3.0 {
						severity = "info" // low-entropy → likely not a real secret
					}
				}
				// A well-known demo/example JWT (jwt.io default and variants) is
				// bundled verbatim into countless JS libraries — not a live token.
				// Demote to info so it doesn't sit in results as a high-severity leak.
				if pat.Type == "jwt" {
					if p := strings.Split(value, "."); len(p) == 3 && isDemoJWT(p) {
						severity = "info"
					}
				}

				ctx := strings.TrimSpace(line)
				if len(ctx) > 300 {
					ctx = ctx[:300]
				}

				findings = append(findings, &models.JSFinding{
					Type:     pat.Type,
					Value:    value,
					Context:  ctx,
					Severity: severity,
				})
			}
		}
	}

	return findings
}

func (s *JSScanner) storeFinding(f *models.JSFinding) error {
	res, err := s.db.Exec(`
		INSERT OR IGNORE INTO js_findings (id, target_id, js_file_id, type, value, context, severity)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, f.ID, f.TargetID, f.JSFileID, f.Type, f.Value, f.Context, f.Severity)
	if err == nil && s.broadcast != nil {
		if n, _ := res.RowsAffected(); n > 0 {
			s.broadcast("new_js_finding", map[string]any{
				"target_id": f.TargetID,
				"type":      f.Type,
				"value":     f.Value,
				"severity":  f.Severity,
			})
		}
	}
	return err
}
