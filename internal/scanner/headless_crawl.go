package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/pkg/logger"
)

// HeadlessCrawler renders pages in a REAL headless browser and harvests the attack
// surface a raw-HTTP crawler structurally cannot see: links the framework injects
// into the DOM after hydration (SPA client-side routing), form fields, and
// parameterized URLs that only exist once JavaScript runs. Everything it discovers
// is stored as parameters, so the XSS/DAST engines test the REAL rendered surface,
// not just the shipped HTML. It is deliberately bounded (page budget + depth) since
// each page is a full browser navigation.
type HeadlessCrawler struct {
	db     *database.DB
	cfg    *config.Config
	logger *logger.Logger
}

func NewHeadlessCrawler(db *database.DB, cfg *config.Config, log *logger.Logger) *HeadlessCrawler {
	return &HeadlessCrawler{db: db, cfg: cfg, logger: log}
}

// crawl bounds — kept modest because every page is a real render.
const (
	headlessMaxPages = 80
	headlessMaxDepth = 2
	headlessSeedCap  = 25
	headlessNavWait  = 1100 * time.Millisecond
)

// formInfo is a discovered HTML form (rendered).
type formInfo struct {
	Action string   `json:"action"`
	Method string   `json:"method"`
	Inputs []string `json:"inputs"`
}

// pageSurface is what one rendered page yields.
type pageSurface struct {
	Links []string   `json:"links"`
	Forms []formInfo `json:"forms"`
}

// extractJS runs in the page to collect rendered links + forms. It reads the LIVE
// DOM (post-hydration), so SPA-injected anchors and dynamically-built forms are
// captured — exactly what an HTTP crawl misses.
const extractJS = `(() => {
  const links = [...document.querySelectorAll('a[href]')].map(a => a.href).filter(Boolean);
  const forms = [...document.forms].map(f => ({
    action: f.action || location.href,
    method: (f.method || 'get').toLowerCase(),
    inputs: [...f.elements].map(e => e.name).filter(Boolean)
  }));
  return JSON.stringify({links: [...new Set(links)].slice(0,500), forms: forms.slice(0,50)});
})()`

// Run drives the bounded headless crawl for a target.
func (c *HeadlessCrawler) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	chromePath := findChromePath()
	if chromePath == "" {
		logFn("info", "headless_crawl", "No headless Chromium available — skipping rendered crawl.")
		return nil
	}

	domain := c.targetDomain(ctx, targetID)
	if domain == "" {
		return nil
	}

	seeds := c.seedURLs(ctx, targetID)
	if len(seeds) == 0 {
		logFn("info", "headless_crawl", "No HTML hosts to render — skipping.")
		return nil
	}
	logFn("info", "headless_crawl", fmt.Sprintf("Rendering up to %d page(s) from %d seed(s) in a headless browser (SPA-aware surface discovery)...", headlessMaxPages, len(seeds)))

	// dedicated, isolated browser for the crawl (does not share the XSS confirmer's tab).
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(chromePath),
		chromedp.Flag("headless", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("blink-settings", "imagesEnabled=false"), // faster: skip images
		chromedp.NoDefaultBrowserCheck,
	)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()
	noop := func(string, ...interface{}) {}
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx, chromedp.WithErrorf(noop), chromedp.WithLogf(noop))
	defer cancelBrowser()
	if err := chromedp.Run(browserCtx); err != nil {
		logFn("info", "headless_crawl", "Headless browser failed to start — skipping rendered crawl.")
		return nil
	}
	headerActions, stopHeaders := scopedBrowserHeaderSession(browserCtx, browserCtx, ctx, seeds, nil)
	defer stopHeaders()
	if len(headerActions) > 0 {
		if err := chromedp.Run(browserCtx, headerActions...); err != nil {
			logFn("warn", "headless_crawl", "Could not configure scoped request identity; skipping rendered crawl.")
			return nil
		}
	}

	type qi struct {
		url   string
		depth int
	}
	seen := map[string]bool{}
	var queue []qi
	for _, s := range seeds {
		if !seen[s] {
			seen[s] = true
			queue = append(queue, qi{s, 0})
		}
	}

	pages := 0
	var params []paramEntry
	pushParam := func(u, name, source string) {
		params = append(params, paramEntry{URL: u, Param: name, Value: "", Source: source})
	}

	for len(queue) > 0 && pages < headlessMaxPages {
		if ctx.Err() != nil {
			break
		}
		cur := queue[0]
		queue = queue[1:]
		pages++

		surf, ok := c.renderPage(browserCtx, cur.url)
		if !ok {
			continue
		}
		if pages%10 == 0 {
			logFn("info", "headless_crawl", fmt.Sprintf("Rendered %d/%d page(s)...", pages, headlessMaxPages))
		}

		// links → in-scope, enqueue for deeper crawl, and harvest their query params.
		for _, l := range surf.Links {
			lu, err := url.Parse(l)
			if err != nil {
				continue
			}
			lu.Fragment = ""
			if !c.inScope(lu.Hostname(), domain) {
				continue
			}
			for name := range lu.Query() {
				if name != "" && !isJunkParam(name) {
					pushParam(lu.String(), name, "headless")
				}
			}
			norm := lu.String()
			if !seen[norm] && cur.depth < headlessMaxDepth && len(seen) < headlessMaxPages*4 {
				seen[norm] = true
				queue = append(queue, qi{norm, cur.depth + 1})
			}
		}
		// forms → each named input is an insertion point (with the form's method).
		for _, f := range surf.Forms {
			fa, err := url.Parse(f.Action)
			if err != nil || !c.inScope(fa.Hostname(), domain) {
				continue
			}
			src := "headless-form"
			for _, in := range f.Inputs {
				if in != "" && !isJunkParam(in) {
					pushParam(fa.String(), in, src)
				}
			}
		}
	}

	stored := c.storeParams(ctx, targetID, params)
	logFn("warn", "headless_crawl", fmt.Sprintf("Headless crawl done. Rendered %d page(s), harvested %d parameter insertion point(s) from the live DOM.", pages, stored))
	return nil
}

// renderPage navigates to url, waits for hydration, and extracts links + forms.
func (c *HeadlessCrawler) renderPage(parent context.Context, pageURL string) (pageSurface, bool) {
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	var raw string
	err := chromedp.Run(ctx,
		chromedp.Navigate(pageURL),
		chromedp.Sleep(headlessNavWait),
		chromedp.Evaluate(extractJS, &raw),
	)
	if err != nil || raw == "" {
		return pageSurface{}, false
	}
	var surf pageSurface
	if json.Unmarshal([]byte(raw), &surf) != nil {
		return pageSurface{}, false
	}
	return surf, true
}

// seedURLs returns the HTML hosts to start the render crawl from (probe sources).
func (c *HeadlessCrawler) seedURLs(ctx context.Context, targetID string) []string {
	rows, err := c.db.QueryContext(ctx, `
		SELECT url FROM http_services
		WHERE target_id = ? AND COALESCE(source,'probe') IN ('probe','seed')
		ORDER BY LENGTH(url) ASC LIMIT ?`, targetID, headlessSeedCap)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) == nil && strings.HasPrefix(u, "http") {
			out = append(out, u)
		}
	}
	return out
}

func (c *HeadlessCrawler) targetDomain(ctx context.Context, targetID string) string {
	var d string
	_ = c.db.QueryRowContext(ctx, "SELECT domain FROM targets WHERE id = ?", targetID).Scan(&d)
	return strings.ToLower(strings.TrimSpace(d))
}

// inScope keeps the crawl on the target's registrable domain (or a subdomain).
func (c *HeadlessCrawler) inScope(host, domain string) bool {
	host = normalizeHost(host)
	if host == "" || isBlockedHost(host) {
		return false
	}
	d := normalizeHost(domain)
	return host == d || strings.HasSuffix(host, "."+d) || sameRegistrable(host, d)
}

// storeParams inserts the harvested insertion points (batched, ON CONFLICT no-op).
func (c *HeadlessCrawler) storeParams(ctx context.Context, targetID string, params []paramEntry) int {
	if len(params) == 0 {
		return 0
	}
	stored := 0
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return 0
	}
	for _, p := range params {
		// Single-endpoint mode: only keep insertion points under the seed URL.
		if !urlInEndpointScope(ctx, p.URL) {
			continue
		}
		method, contentType, location := "GET", "", "query"
		if strings.Contains(p.Source, "form") {
			method, contentType, location = "POST", "application/x-www-form-urlencoded", "body"
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO parameters (id,target_id,url,parameter,value,source,method,content_type,location)
			VALUES (?,?,?,?,?,?,?,?,?)
			ON CONFLICT(target_id,url,parameter,method,location,content_type) DO NOTHING`,
			uuid.New().String(), targetID, p.URL, p.Param, p.Value, p.Source, method, contentType, location); err == nil {
			stored++
		}
	}
	if tx.Commit() != nil {
		return 0
	}
	return stored
}
