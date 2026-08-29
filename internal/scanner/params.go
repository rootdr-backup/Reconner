package scanner

import (
	"bufio"
	"context"
	"fmt"
	"html"
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

type ParamScanner struct {
	broadcast BroadcastFunc
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
}

func NewParamScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *ParamScanner {
	return &ParamScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

// belongsToDomain returns true if the URL's host is the domain itself or a subdomain of it.
func belongsToDomain(rawURL, domain string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	domain = strings.ToLower(domain)
	// Normalise the scope the SAME way the URL host was: a target scope may carry a
	// port (host:port, [ipv6]:port) while parsed.Hostname() has already stripped the
	// URL's port. Comparing a bare host against a port-bearing scope rejects every
	// in-scope URL, silently starving parameter discovery for port-bearing targets.
	if d, e := url.Parse("//" + domain); e == nil && d.Hostname() != "" {
		domain = d.Hostname()
	}
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func (s *ParamScanner) Run(ctx context.Context, targetID, domain string, logFn LogFunc) error {
	logFn("info", "param_discovery", "Starting parameter discovery...")

	rows, err := s.db.QueryContext(ctx, `SELECT url FROM http_services WHERE target_id = ? AND COALESCE(source,'probe') IN ('probe','seed') LIMIT ?`, targetID, s.cfg.URLLimit())
	if err != nil {
		return err
	}
		var targetURLs []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err == nil {
			targetURLs = append(targetURLs, u)
		}
	}
	rows.Close()

	// Per-asset host scope
	if hostScopeSet(ctx) != nil {
		kept := targetURLs[:0]
		for _, u := range targetURLs {
			if urlHostInScope(ctx, u) {
				kept = append(kept, u)
			}
		}
		targetURLs = kept
	}

	allURLs := make(map[string]bool)
	var urlMu sync.Mutex

	// Single-scope targets (CLI --single) restrict gathering to the EXACT host,
	// so wayback/gau don't drag in URLs from other subdomains.
	var scope string
	_ = s.db.QueryRow(`SELECT COALESCE(scope,'full') FROM targets WHERE id=?`, targetID).Scan(&scope)
	singleScope := scope == "single"

	// accepts only URLs that belong to the target domain/subdomains and have query params
	addURL := func(line string) {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "?") {
			return
		}
				// Single-endpoint mode: only keep URLs under the seed endpoint prefix — a
		// whole-domain wayback/gau dump would otherwise drag the scan far off the one
		// URL the operator asked for.
		if !urlInEndpointScope(ctx, line) {
			return
		}
		if !urlHostInScope(ctx, line) {
			return
		}
		if singleScope {
			// Lowercase BEFORE stripping "www." — TrimPrefix is case-sensitive, so
			// trimming first would leave an uppercase "WWW." prefix in place and make
			// "WWW.example.com" compare unequal to "www.example.com" (a scope-match bug).
			if h := hostOf(line); strings.TrimPrefix(strings.ToLower(h), "www.") != strings.TrimPrefix(strings.ToLower(domain), "www.") {
				return
			}
		} else if !belongsToDomain(line, domain) {
			return
		}
		urlMu.Lock()
		allURLs[line] = true
		urlMu.Unlock()
	}

	// Historical-URL sources (gau, waybackurls, waymore) hit DIFFERENT external
	// services (not the target), and addURL is mutex-protected — so run them
	// CONCURRENTLY. Previously they ran back-to-back and dominated scan time
	// (~15 min on a big domain). In parallel the total is bounded by the slowest
	// one (~one source's time), not their sum. Each is also given a hard timeout
	// so a single slow/​stuck source can't stall the whole scan.
	var passiveWg sync.WaitGroup

	// Fast mode trims the (external, minutes-long) historical-URL sources: their
	// tail is deep-but-slow coverage, so a "fast" scan caps each to a short budget
	// and skips the deepest aggregator (waymore) entirely. The pure-Go, on-target
	// sources (robots/sitemap/OpenAPI/GraphQL + the native crawl) still run in
	// full, so the real attack surface is still discovered — just without the
	// multi-minute wait on archive services.
	fast := webSpeedFromCtx(ctx) == SpeedFast
	histBudget := 5 * time.Minute
	if fast {
		histBudget = 45 * time.Second
	}

	if s.exec.IsToolAvailable("gau") {
		passiveWg.Add(1)
		go func() {
			defer passiveWg.Done()
			gauCtx, cancel := context.WithTimeout(ctx, histBudget)
			defer cancel()
			logFn("info", "param_discovery", "Fetching historical URLs with gau...")
			_ = s.exec.RunWithCallback(gauCtx, targetID, func(line string) {
				addURL(line)
			}, "gau", domain, "--threads", "5", "--subs")
			// A big domain can have far more Wayback/CommonCrawl history than 5m
			// can pull — say so explicitly instead of a plain "done" that reads
			// as complete when it was actually cut off mid-stream.
			if gauCtx.Err() == context.DeadlineExceeded {
				logFn("warn", "param_discovery", "gau hit its 5m budget — results are PARTIAL, not exhaustive, for this large a target.")
			} else {
				logFn("info", "param_discovery", "gau done")
			}
		}()
	}

	if s.exec.IsToolAvailable("waybackurls") {
		passiveWg.Add(1)
		go func() {
			defer passiveWg.Done()
			// waybackurls has no built-in timeout and can run many minutes on a
			// big domain — bound it so it can't stall the scan.
			wbCtx, cancel := context.WithTimeout(ctx, histBudget)
			defer cancel()
			logFn("info", "param_discovery", "Fetching Wayback Machine URLs...")
			_ = s.exec.RunWithCallback(wbCtx, targetID, func(line string) {
				addURL(line)
			}, "waybackurls", domain)
			if wbCtx.Err() == context.DeadlineExceeded {
				logFn("warn", "param_discovery", "waybackurls hit its 5m budget — results are PARTIAL, not exhaustive, for this large a target.")
			} else {
				logFn("info", "param_discovery", "waybackurls done")
			}
		}()
	}

	// waymore: the deepest historical URL source (aggregates Wayback + Common
	// Crawl + URLScan + VirusTotal + AlienVault). Far more coverage than gau
	// alone; skipped gracefully when not installed — and skipped in fast mode,
	// where its multi-minute deep harvest is exactly the latency we're trimming.
	if !fast && s.exec.IsToolAvailable("waymore") {
		passiveWg.Add(1)
		go func() {
			defer passiveWg.Done()
			logFn("info", "param_discovery", "Deep URL harvest with waymore...")
			waymoreCtx, cancel := context.WithTimeout(ctx, 4*time.Minute)
			defer cancel()
			_ = s.exec.RunWithCallback(waymoreCtx, targetID, func(line string) {
				addURL(strings.TrimSpace(line))
			}, "waymore", "-i", domain, "-mode", "U", "-oU", "/dev/stdout")
			if waymoreCtx.Err() == context.DeadlineExceeded {
				logFn("warn", "param_discovery", "waymore hit its 4m budget — results are PARTIAL, not exhaustive, for this large a target.")
			} else {
				logFn("info", "param_discovery", "waymore done")
			}
		}()
	}

	// robots.txt + sitemap.xml — a PURE-GO, always-available endpoint source (no
	// external tool needed, so it still works when katana/hakrawler/gau are absent).
	// It reaches paths a link-following crawler never sees: Disallow rules and
	// sitemap <loc> entries routinely expose hidden admin/api endpoints. Runs in
	// the passive group since it hits the target hosts directly.
	passiveWg.Add(1)
	go func() {
		defer passiveWg.Done()
		logFn("info", "param_discovery", "Harvesting robots.txt + sitemap.xml endpoints...")
		n := s.harvestWellKnown(ctx, targetURLs, addURL)
		logFn("info", "param_discovery", fmt.Sprintf("robots/sitemap harvest done, %d in-scope candidate URL(s).", n))
	}()

	// OpenAPI/Swagger + GraphQL introspection — a documented API describes its
	// whole surface (paths, methods, params) in one file, reaching endpoints no
	// link crawler sees. Both store parameters directly, so run them concurrently.
	passiveWg.Add(1)
	go func() {
		defer passiveWg.Done()
		logFn("info", "param_discovery", "Probing for OpenAPI/Swagger specs...")
		if n := s.harvestAPISpecs(ctx, targetID, targetURLs, logFn); n == 0 {
			logFn("info", "param_discovery", "No OpenAPI/Swagger spec exposed.")
		}
	}()
	passiveWg.Add(1)
	go func() {
		defer passiveWg.Done()
		logFn("info", "param_discovery", "Probing for GraphQL introspection...")
		if n := s.harvestGraphQL(ctx, targetID, targetURLs, logFn); n == 0 {
			logFn("info", "param_discovery", "No GraphQL endpoint with introspection enabled.")
		}
	}()

	passiveWg.Wait()
	logFn("info", "param_discovery", fmt.Sprintf("Historical URL sources done, total: %d parameterized URLs", len(allURLs)))

	// Crawl hosts concurrently with a hard per-host time budget (was sequential
	// at depth 3 with no timeout — the main cause of multi-minute scans).
	const crawlConcurrency = 8
	if s.exec.IsToolAvailable("katana") {
		logFn("info", "param_discovery", fmt.Sprintf("Crawling with katana (%d hosts, parallel)...", len(targetURLs)))
		sem := make(chan struct{}, crawlConcurrency)
		var wg sync.WaitGroup
		for _, targetURL := range targetURLs {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(u string) {
				defer wg.Done()
				defer func() { <-sem }()
				hostCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
				defer cancel()
				_ = s.exec.RunWithCallback(hostCtx, targetID, func(line string) {
					addURL(line)
				}, "katana", "-u", u, "-silent", "-depth", "2", "-c", "10", "-ct", "30", "-timeout", "8", "-jc")
			}(targetURL)
		}
		wg.Wait()
		logFn("info", "param_discovery", fmt.Sprintf("katana done, total: %d", len(allURLs)))
	}

	if s.exec.IsToolAvailable("hakrawler") {
		logFn("info", "param_discovery", "Crawling with hakrawler (parallel)...")
		sem := make(chan struct{}, crawlConcurrency)
		var wg sync.WaitGroup
		for _, targetURL := range targetURLs {
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
				result, err := s.exec.Run(hostCtx, "hakrawler", "-url", u, "-depth", "2", "-insecure")
				if err != nil {
					return
				}
				sc := bufio.NewScanner(strings.NewReader(result.Stdout))
				for sc.Scan() {
					addURL(sc.Text())
				}
			}(targetURL)
		}
		wg.Wait()
	}

	if s.exec.IsToolAvailable("uro") && len(allURLs) > 0 {
		logFn("info", "param_discovery", "Deduplicating URLs with uro...")
		rawURLs := make([]string, 0, len(allURLs))
		for u := range allURLs {
			rawURLs = append(rawURLs, u)
		}
		input := strings.NewReader(strings.Join(rawURLs, "\n"))
		result, err := s.exec.RunWithInput(ctx, input, "uro")
		if err == nil {
			filtered := make(map[string]bool)
			sc := bufio.NewScanner(strings.NewReader(result.Stdout))
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line != "" && belongsToDomain(line, domain) {
					filtered[line] = true
				}
			}
			urlMu.Lock()
			allURLs = filtered
			urlMu.Unlock()
		}
	}

	logFn("info", "param_discovery", fmt.Sprintf("Extracting parameters from %d URLs...", len(allURLs)))
	params := s.extractParameters(allURLs)
	logFn("info", "param_discovery", fmt.Sprintf("Found %d unique params. Storing...", len(params)))

	stored := 0
	for _, p := range params {
		if err := s.storeParameter(targetID, p); err == nil {
			stored++
		}
	}
	logFn("info", "param_discovery", fmt.Sprintf("Stored %d parameters.", stored))

	// Discover HTML forms → POST/body insertion points (covers login, search,
	// contact forms etc. that GET-only crawling never reaches).
	formCount := s.discoverForms(ctx, targetID, domain, logFn)
	logFn("info", "param_discovery", fmt.Sprintf("Discovered %d form-body parameters.", formCount))
	return nil
}

var (
	formRE    = regexp.MustCompile(`(?is)<form\b[^>]*>.*?</form>`)
	actionRE  = regexp.MustCompile(`(?i)action\s*=\s*["']([^"']*)["']`)
	methodRE  = regexp.MustCompile(`(?i)method\s*=\s*["']([^"']*)["']`)
	fieldRE   = regexp.MustCompile(`(?i)<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["']([^"']+)["'][^>]*>`)
	enctypeRE = regexp.MustCompile(`(?i)enctype\s*=\s*["']([^"']*)["']`)
)

// discoverForms fetches alive HTML pages, parses <form> elements, and stores
// each named field as a POST parameter so the active modules test request
// bodies too.
func (s *ParamScanner) discoverForms(ctx context.Context, targetID, domain string, logFn LogFunc) int {
	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services
		WHERE target_id = ? AND status_code BETWEEN 200 AND 399
		ORDER BY url LIMIT ?
	`, targetID, s.cfg.URLLimit())
	if err != nil {
		return 0
	}
	var pages []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err == nil {
			pages = append(pages, u)
		}
	}
	rows.Close()
	pages = filterURLsByHostScope(ctx, pages)

	client := &http.Client{Timeout: 12 * time.Second, Transport: sharedHTTPTransport}
	stored := 0
	for _, page := range pages {
		if ctx.Err() != nil {
			break
		}
		req, err := http.NewRequestWithContext(ctx, "GET", page, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		ct := strings.ToLower(resp.Header.Get("Content-Type"))
		if !strings.Contains(ct, "html") {
			resp.Body.Close()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		resp.Body.Close()

		for _, form := range formRE.FindAllString(string(body), -1) {
			method := "GET"
			if m := methodRE.FindStringSubmatch(form); len(m) > 1 && strings.EqualFold(m[1], "post") {
				method = "POST"
			}
			if method != "POST" {
				continue // GET forms are already covered by query-param testing
			}
			action := page
			if a := actionRE.FindStringSubmatch(form); len(a) > 1 && a[1] != "" {
				action = resolveURL(page, a[1])
			}
			contentType := "application/x-www-form-urlencoded"
			if e := enctypeRE.FindStringSubmatch(form); len(e) > 1 && strings.Contains(strings.ToLower(e[1]), "json") {
				contentType = "application/json"
			}
			for _, f := range fieldRE.FindAllStringSubmatch(form, -1) {
				name := strings.TrimSpace(f[1])
				if name == "" {
					continue
				}
				if s.storeFormParameter(targetID, action, name, method, contentType) {
					stored++
				}
			}
		}
	}
	return stored
}

func (s *ParamScanner) storeFormParameter(targetID, action, name, method, contentType string) bool {
	id := uuid.New().String()
	_, err := s.db.Exec(`
		INSERT INTO parameters (id, target_id, url, parameter, value, source, method, content_type)
		VALUES (?, ?, ?, ?, '', 'form', ?, ?)
		ON CONFLICT(target_id, url, parameter) DO UPDATE SET
			method = excluded.method, content_type = excluded.content_type
	`, id, targetID, action, name, method, contentType)
	return err == nil
}

// ── robots.txt + sitemap.xml harvesting (pure Go) ──────────────────────────

var sitemapLocRE = regexp.MustCompile(`(?is)<loc>\s*(.*?)\s*</loc>`)

// parseRobotsTxt extracts Disallow/Allow paths and declared Sitemap URLs from a
// robots.txt body. Wildcard globs (`*`, `$`) are stripped so the residual prefix
// is a fetchable path. Returns (paths, sitemapURLs).
func parseRobotsTxt(body string) (paths, sitemaps []string) {
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:colon]))
		val := strings.TrimSpace(line[colon+1:])
		switch key {
		case "disallow", "allow":
			// Keep only real path prefixes; a lone "/" or "" is not an endpoint.
			p := strings.TrimRight(strings.ReplaceAll(strings.ReplaceAll(val, "*", ""), "$", ""), "*")
			if p == "" || p == "/" {
				continue
			}
			paths = append(paths, p)
		case "sitemap":
			if val != "" {
				sitemaps = append(sitemaps, val)
			}
		}
	}
	return paths, sitemaps
}

// parseSitemapLocs extracts every <loc> value from a sitemap or sitemap-index
// document, HTML-unescaping entities. A sitemap index yields child sitemap URLs
// (also inside <loc>), so callers distinguish by whether the loc ends in .xml.
func parseSitemapLocs(body string) []string {
	var out []string
	for _, m := range sitemapLocRE.FindAllStringSubmatch(body, -1) {
		loc := strings.TrimSpace(html.UnescapeString(m[1]))
		if loc != "" {
			out = append(out, loc)
		}
	}
	return out
}

// harvestWellKnown fetches /robots.txt and /sitemap.xml for each in-scope origin
// and feeds discovered URLs to addURL. Sitemap indexes are followed ONE level.
// Everything is bounded (origin count, sitemap fetches, per-request timeout) so a
// pathological site cannot stall the scan. Returns the number of candidate URLs
// emitted to addURL (addURL itself applies the domain + query-param filter).
func (s *ParamScanner) harvestWellKnown(ctx context.Context, targetURLs []string, addURL func(string)) int {
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: sharedHTTPTransport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	get := func(u string) string {
		reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, "GET", u, nil)
		if err != nil {
			return ""
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
		resp, err := client.Do(req)
		if err != nil {
			return ""
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			return ""
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 3*1024*1024))
		return string(b)
	}

	// Unique origins (scheme://host) from the probe URLs, capped.
	origins := map[string]bool{}
	for _, u := range targetURLs {
		if p, err := url.Parse(u); err == nil && p.Host != "" {
			origins[p.Scheme+"://"+p.Host] = true
		}
	}

	emitted := 0
	emit := func(raw string) {
		if raw == "" {
			return
		}
		addURL(raw)
		emitted++
	}

	const maxOrigins = 60
	const maxSitemaps = 20
	sitemapQueue := []string{}
	seenSitemap := map[string]bool{}
	oCount := 0
	for origin := range origins {
		if ctx.Err() != nil {
			return emitted
		}
		if oCount++; oCount > maxOrigins {
			break
		}
		// robots.txt
		if body := get(origin + "/robots.txt"); body != "" {
			paths, sitemaps := parseRobotsTxt(body)
			for _, p := range paths {
				emit(resolveURL(origin+"/", p))
			}
			for _, sm := range sitemaps {
				if !seenSitemap[sm] {
					seenSitemap[sm] = true
					sitemapQueue = append(sitemapQueue, sm)
				}
			}
		}
		// Conventional sitemap location even when robots.txt didn't advertise one.
		def := origin + "/sitemap.xml"
		if !seenSitemap[def] {
			seenSitemap[def] = true
			sitemapQueue = append(sitemapQueue, def)
		}
	}

	// Drain the sitemap queue, following index → child sitemaps one level deep.
	fetched := 0
	for len(sitemapQueue) > 0 && fetched < maxSitemaps {
		if ctx.Err() != nil {
			return emitted
		}
		sm := sitemapQueue[0]
		sitemapQueue = sitemapQueue[1:]
		body := get(sm)
		fetched++
		if body == "" {
			continue
		}
		isIndex := strings.Contains(strings.ToLower(body), "<sitemapindex")
		for _, loc := range parseSitemapLocs(body) {
			if isIndex || strings.HasSuffix(strings.ToLower(loc), ".xml") {
				if !seenSitemap[loc] && len(seenSitemap) < maxSitemaps*4 {
					seenSitemap[loc] = true
					sitemapQueue = append(sitemapQueue, loc)
				}
				continue
			}
			emit(loc)
		}
	}
	return emitted
}

// resolveURL resolves a possibly-relative form action against the page URL.
func resolveURL(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ref
	}
	r, err := url.Parse(ref)
	if err != nil {
		return base
	}
	return b.ResolveReference(r).String()
}

type paramEntry struct {
	URL    string
	Param  string
	Value  string
	Source string
}

func (s *ParamScanner) extractParameters(urlMap map[string]bool) []paramEntry {
	seen := make(map[string]bool)
	var params []paramEntry

	for rawURL := range urlMap {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		// Skip static assets entirely: a request like
		// /js/app.js?v=1342 has no server-side parameter worth testing — the
		// "v" is just a cache-buster. These flooded the Parameters tab with
		// hundreds of useless rows.
		if isStaticAssetPath(parsed.Path) {
			continue
		}
		for param, values := range parsed.Query() {
			// Skip cache-busting / non-actionable parameter names.
			if isJunkParam(param) {
				continue
			}
			val := ""
			if len(values) > 0 {
				val = values[0]
			}
			key := parsed.Scheme + "://" + parsed.Host + parsed.Path + "?" + param
			if seen[key] {
				continue
			}
			seen[key] = true
			params = append(params, paramEntry{
				URL:    rawURL,
				Param:  param,
				Value:  val,
				Source: "crawl",
			})
		}
	}
	return params
}

// staticAssetExts are file types that are served statically — parameters on them
// (typically cache-busting version strings) are not real, testable inputs.
var staticAssetExts = []string{
	".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
	".webp", ".ico", ".bmp", ".woff", ".woff2", ".ttf", ".eot", ".otf",
	".mp4", ".webm", ".mp3", ".wav", ".ogg", ".pdf", ".zip", ".gz",
}

func isStaticAssetPath(path string) bool {
	p := strings.ToLower(path)
	for _, ext := range staticAssetExts {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

// junkParams are cache-buster / analytics / click-attribution / framework-plumbing
// names with no server-side application meaning — useless (and misleading) for
// injection/reflection testing. Dropping them at discovery keeps the parameter
// table (and every downstream detector's budget) focused on real attack surface.
var junkParams = map[string]bool{
	// cache-busters / build hashes
	"v": true, "ver": true, "version": true, "_": true, "cb": true,
	"cache": true, "cachebuster": true, "t": true, "ts": true, "time": true,
	"timestamp": true, "rev": true, "hash": true, "build": true, "nocache": true,
	// analytics / click attribution (utm_* handled by prefix below)
	"__cf_chl_rt_tk": true, "_ga": true, "_gl": true, "fbclid": true, "gclid": true,
	"gclsrc": true, "dclid": true, "msclkid": true, "yclid": true, "igshid": true,
	"mc_eid": true, "mc_cid": true, "twclid": true, "wickedid": true, "s_kwcid": true,
	"vero_id": true, "oly_enc_id": true, "oly_anon_id": true, "spm": true, "scm": true,
	"ref_src": true, "ref_url": true,
	// WordPress / CMS plumbing params that are not application input worth fuzzing
	// (nonces, cache/version keys, feed/format switches, oEmbed, AMP, pagination).
	"_wpnonce": true, "wpnonce": true, "_wp_http_referer": true, "doing_wp_cron": true,
	"ver_": true, "wc-ajax": true, "wc_cache": true, "et_fb": true, "elementor-preview": true,
	"replytocom": true, "feed": true, "format": true, "amp": true, "print": true,
	"customize_changeset_uuid": true, "customize_theme": true, "customize_messenger_channel": true,
	"epslug": true, "wpe-login": true, "unapproved": true, "moderation-hash": true,
}

// isJunkParam reports whether a parameter name is analytics/cache/CMS plumbing —
// never worth reflection/injection testing. Covers the utm_* family by prefix.
func isJunkParam(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if strings.HasPrefix(n, "utm_") {
		return true
	}
	return junkParams[n]
}

func (s *ParamScanner) storeParameter(targetID string, p paramEntry) error {
	id := uuid.New().String()
	_, err := s.db.Exec(`
		INSERT INTO parameters (id, target_id, url, parameter, value, source)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(target_id, url, parameter) DO NOTHING
	`, id, targetID, p.URL, p.Param, p.Value, p.Source)
	return err
}

// CheckReflection actively checks parameter reflection using built-in HTTP client.
func (s *ParamScanner) CheckReflection(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "param_reflection", "Checking parameter reflection (active probe)...")

	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT url, parameter FROM parameters
		WHERE target_id = ? AND is_reflected = 0
		LIMIT ?
	`, targetID, s.cfg.URLLimit())
	if err != nil {
		return err
	}

	type urlParam struct {
		URL   string
		Param string
	}
	// Skip stock WordPress/Joomla/Drupal hosts: reflected-parameter probing on a
	// patched CMS core is noise (the reflection is almost always a harmless
	// template echo, and every downstream module that consumes is_reflected already
	// skips these hosts), so don't even mark params reflected there.
	cmsSkip := loadCMSSkipHosts(s.db, targetID)
	var items []urlParam
	for rows.Next() {
		var up urlParam
		if err := rows.Scan(&up.URL, &up.Param); err == nil {
			if hostSkippedByCMS(up.URL, cmsSkip) {
				continue
			}
			items = append(items, up)
		}
	}
	rows.Close()

	logFn("info", "param_reflection", fmt.Sprintf("Probing %d parameters for reflection...", len(items)))

	markReflected := func(u, param string) {
		_, _ = s.db.Exec(`
			UPDATE parameters SET is_reflected = 1
			WHERE target_id = ? AND url = ? AND parameter = ?
		`, targetID, u, param)
		if s.broadcast != nil {
			s.broadcast("new_reflected_param", map[string]any{
				"target_id": targetID, "url": u, "parameter": param,
			})
		}
	}

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	var reflected atomic.Int64
	// HTML-sink params that did NOT reflect in raw HTML — candidates for a bounded
	// browser (SPA/DOM) pass afterwards.
	var domMu sync.Mutex
	var domCandidates []urlParam

	for _, item := range items {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(u, param string) {
			defer wg.Done()
			defer func() { <-sem }()

			r, htmlSink := checkParamReflection(u, param)
			if r {
				markReflected(u, param)
				reflected.Add(1)
			} else if htmlSink {
				domMu.Lock()
				domCandidates = append(domCandidates, urlParam{u, param})
				domMu.Unlock()
			}
		}(item.URL, item.Param)
	}
	wg.Wait()

	// SPA / DOM reflection: for HTML pages where the raw body didn't echo the canary,
	// the reflection is often written into the DOM by JavaScript after load. Confirm a
	// BOUNDED sample in a real headless browser (serialized on one tab), so
	// client-rendered apps stop looking "0 reflected". No-op when no browser exists.
	if b := getXSSBrowser(); b != nil && len(domCandidates) > 0 && ctx.Err() == nil {
		budget := reflectDOMBudget
		logFn("info", "param_reflection", fmt.Sprintf("Raw-HTML reflection missed %d HTML param(s) — checking up to %d in a headless browser (SPA/DOM)...", len(domCandidates), budget))
		domReflected := 0
		for _, up := range domCandidates {
			if ctx.Err() != nil || budget <= 0 {
				break
			}
			budget--
			if b.DOMReflects(ctx, up.URL, up.Param) {
				markReflected(up.URL, up.Param)
				reflected.Add(1)
				domReflected++
			}
		}
		if domReflected > 0 {
			logFn("info", "param_reflection", fmt.Sprintf("Browser DOM reflection found %d additional reflected param(s).", domReflected))
		}
	}

	logFn("info", "param_reflection", fmt.Sprintf("Reflection check done. Found %d reflected parameters.", reflected.Load()))
	return nil
}

// reflectDOMBudget caps how many HTML-but-not-raw-reflected params get the headless
// browser DOM-reflection check per scan (the single tab serializes navigations).
const reflectDOMBudget = 150
