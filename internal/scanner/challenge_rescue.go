package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/chromedp/chromedp"
)

// maxChallengeRescueHosts bounds how many hosts get a headless-browser retry
// per scan. A target that is challenge-protected on every host would
// otherwise force a slow, serial Chromium render across the whole asset
// list; this keeps the cost predictable while still covering the common
// case (a handful of edge-fronted hosts among many plain ones).
const maxChallengeRescueHosts = 25

// challengeRescueNavWait gives a CDN's non-interactive JS/browser-integrity
// check (Cloudflare's ordinary "I'm Under Attack Mode" check is the dominant
// real-world case) time to run and auto-redirect to the real page. A hard
// challenge that needs human interaction (an actual CAPTCHA) will not clear
// in this window, and is correctly left alone rather than raced.
const challengeRescueNavWait = 6 * time.Second

// challengedHost is one http_services row whose stored probe result already
// reads as a CDN/WAF bot-challenge page.
type challengedHost struct {
	url, title string
	status     int
}

// challengedCandidates returns the in-scope http_services rows for target
// whose stored title/status already reads as a CDN/WAF bot-challenge page
// (via waf.go's looksLikeWAFBlock), capped at maxChallengeRescueHosts. Pure
// DB logic, deliberately kept free of any chromedp/browser dependency so
// the candidate-selection contract — which hosts are even considered for a
// browser retry — is unit-testable without a real browser.
func (s *HTTPScanner) challengedCandidates(ctx context.Context, targetID string) []challengedHost {
	rows, err := s.db.QueryContext(ctx, `
		SELECT url, status_code, title FROM http_services
		WHERE target_id = ? AND status_code > 0 AND COALESCE(source,'probe')='probe'`, targetID)
	if err != nil {
		return nil
	}
	var candidates []challengedHost
	for rows.Next() {
		var c challengedHost
		if rows.Scan(&c.url, &c.status, &c.title) == nil && looksLikeWAFBlock(c.status, c.title) {
			candidates = append(candidates, c)
		}
	}
	rows.Close()
	if len(candidates) == 0 {
		return nil
	}

	urls := make([]string, len(candidates))
	for i, c := range candidates {
		urls[i] = c.url
	}
	inScope := map[string]bool{}
	for _, u := range filterURLsByHostScope(ctx, urls) {
		inScope[u] = true
	}
	kept := candidates[:0]
	for _, c := range candidates {
		if inScope[c.url] {
			kept = append(kept, c)
		}
	}
	if len(kept) > maxChallengeRescueHosts {
		kept = kept[:maxChallengeRescueHosts]
	}
	return kept
}

// rescueChallengedHosts looks for http_services rows whose probe already
// reads as a CDN/WAF bot-challenge page (see waf.go's looksLikeWAFBlock —
// Cloudflare's "Just a moment...", Akamai, Incapsula, etc. all carry a
// distinctive title/body) and retries those specific hosts through the same
// headless Chromium this codebase already ships for XSS/DOM proof and
// rendered crawling (see headless_crawl.go). A real browser engine executes
// a CDN's ordinary automatic JS check exactly as any real visitor's browser
// does, which clears the dominant no-interaction challenge and recovers the
// actual page. This is not CAPTCHA-solving or anti-bot evasion for
// unauthorized access — it is passing the same automated check every
// legitimate visitor passes; a harder challenge that genuinely requires
// human interaction is not solved by this, and such a host is simply left
// exactly as httpx originally saw it.
//
// On success only title and content_length are corrected — status_code and
// technologies are left as httpx originally recorded them, since this does
// not re-run tech detection. A host that clears is reported with a log line
// naming the original probe status alongside the recovered title, so the
// discrepancy (e.g. "403 but now titled X") is visible rather than silently
// overwritten.
func (s *HTTPScanner) rescueChallengedHosts(ctx context.Context, targetID string, logFn LogFunc) {
	candidates := s.challengedCandidates(ctx, targetID)
	if len(candidates) == 0 {
		return
	}

	chromePath := findChromePath()
	if chromePath == "" {
		return // no headless Chromium available — nothing this step can do
	}

	logFn("info", "http_probe", fmt.Sprintf("%d host(s) returned a bot-challenge page to the probe — retrying via headless browser...", len(candidates)))

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(chromePath),
		chromedp.Flag("headless", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.NoDefaultBrowserCheck,
	)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, opts...)
	defer cancelAlloc()
	noop := func(string, ...interface{}) {}
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx, chromedp.WithErrorf(noop), chromedp.WithLogf(noop))
	defer cancelBrowser()
	if err := chromedp.Run(browserCtx); err != nil {
		logFn("info", "http_probe", "Headless browser failed to start — bot-challenge retry skipped.")
		return
	}

	rescueURLs := make([]string, len(candidates))
	for i, c := range candidates {
		rescueURLs[i] = c.url
	}
	headerActions, stopHeaders := scopedBrowserHeaderSession(browserCtx, browserCtx, ctx, rescueURLs, nil)
	defer stopHeaders()
	if len(headerActions) > 0 {
		if err := chromedp.Run(browserCtx, headerActions...); err != nil {
			logFn("info", "http_probe", "Could not configure scoped browser request identity — bot-challenge retry skipped.")
			return
		}
	}

	rescued := 0
	for _, c := range candidates {
		if ctx.Err() != nil {
			break
		}
		title, body, ok := renderChallengedPage(browserCtx, c.url)
		if !ok {
			continue
		}
		if looksLikeWAFBlock(0, title) || bodyLooksLikeWAFBlock(body) {
			continue // still challenged — likely needs human interaction; leave as httpx saw it
		}
		if _, err := s.db.Exec(`UPDATE http_services SET title=?, content_length=? WHERE target_id=? AND url=?`,
			title, len(body), targetID, c.url); err == nil {
			rescued++
			logFn("info", "http_probe", fmt.Sprintf("Recovered real content behind bot-challenge on %s (probe saw status %d): now titled %q", c.url, c.status, title))
		}
	}
	if rescued > 0 {
		logFn("info", "http_probe", fmt.Sprintf("Bot-challenge retry recovered real content on %d/%d host(s).", rescued, len(candidates)))
	} else {
		logFn("info", "http_probe", "Bot-challenge retry did not recover any host — remaining challenges likely need human interaction (e.g. a CAPTCHA) and were left as probed.")
	}
}

// renderChallengedPage navigates to pageURL in the given headless-browser
// context and returns the resulting document title and outer HTML.
func renderChallengedPage(parent context.Context, pageURL string) (title, body string, ok bool) {
	rctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	err := chromedp.Run(rctx,
		chromedp.Navigate(pageURL),
		chromedp.Sleep(challengeRescueNavWait),
		chromedp.Evaluate(`document.title`, &title),
		chromedp.Evaluate(`document.documentElement.outerHTML`, &body),
	)
	if err != nil {
		return "", "", false
	}
	return title, body, true
}
