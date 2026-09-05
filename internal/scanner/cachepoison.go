package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
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

// CachePoisonScanner detects web cache poisoning via UNKEYED header inputs — a
// high-impact bug where an attacker-controlled header (not part of the cache
// key) is reflected into a cached response, so the poisoned response is served
// to every other visitor.
//
// Methodology (PortSwigger-standard, low false-positive and NON-destructive):
//  1. Use a unique cache-buster query value so we only ever poison OUR OWN cache
//     entry, never a real one.
//  2. Send the request with an unkeyed header (X-Forwarded-Host, etc.) set to a
//     unique canary and confirm the canary is REFLECTED in the response.
//  3. Send two CLEAN requests to the same cache-busted URL WITHOUT the header.
//     Only if both cache-hit responses retain the canary is poisoning confirmed.
//     Reflection alone is only a lower "unkeyed input reflected" candidate.
type CachePoisonScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewCachePoisonScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *CachePoisonScanner {
	return &CachePoisonScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

var cachePoisonClient = newPooledClient(12*time.Second, false)

// Unkeyed headers that frameworks/CDNs commonly reflect into responses (links,
// redirects, canonical tags) while omitting them from the cache key.
var cachePoisonHeaders = []string{
	"X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto", "X-Host",
	"X-Forwarded-Server", "X-Forwarded-Port", "X-Original-URL", "X-Rewrite-URL",
	"X-Forwarded-For", "Forwarded",
}

const cachePoisonMaxURLs = 60

func (s *CachePoisonScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	urls := s.candidateURLs(ctx, targetID)
	if len(urls) == 0 {
		logFn("info", "cache_poison", "No cacheable pages to test")
		return nil
	}
	logFn("info", "cache_poison", fmt.Sprintf("Testing %d page(s) for web cache poisoning (unkeyed headers)...", len(urls)))

	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, u := range urls {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()
			if s.testURL(ctx, targetID, u, nil, logFn) {
				found.Add(1)
			}
		}(u)
	}
	wg.Wait()
	logFn("info", "cache_poison", fmt.Sprintf("Cache poisoning done. Found %d.", found.Load()))
	return nil
}

func (s *CachePoisonScanner) testURL(ctx context.Context, targetID, baseURL string, auth map[string]string, logFn LogFunc) bool {
	candidateStored := false
	for _, hdr := range cachePoisonHeaders {
		if ctx.Err() != nil {
			return false
		}
		canary := "rcncp" + uuid.New().String()[:8] + ".example.com"
		cb := fmt.Sprintf("rcncb=%d", time.Now().UnixNano())
		testURL := baseURL
		if strings.Contains(testURL, "?") {
			testURL += "&" + cb
		} else {
			testURL += "?" + cb
		}

		// 1) Poisoning request WITH the unkeyed header.
		body1, status1, poisonHeaders := s.fetch(ctx, testURL, map[string]string{hdr: canary}, auth)
		if status1 < 200 || status1 >= 400 || looksLikeBlockPage(status1, body1) || !strings.Contains(body1, canary) {
			continue // header not reflected → not exploitable via this header
		}

		// 2) Clean request to the SAME cache-busted URL, no header.
		body2, status2, cacheHeaders := s.fetch(ctx, testURL, nil, nil)
		if strings.Contains(body2, canary) {
			if status2 == status1 && !looksLikeBlockPage(status2, body2) && cacheServedFromCache(cacheHeaders) {
				// Reproduce the unauthenticated cache replay once more. A single
				// transient edge response or application session cannot become a finding.
				body3, status3, cacheHeaders2 := s.fetch(ctx, testURL, nil, nil)
				if status3 != status2 || !strings.Contains(body3, canary) ||
					!cacheServedFromCache(cacheHeaders2) || !bodiesSameObject(body2, body3) {
					continue
				}
				// The poisoned value survived into an unauthenticated request that
				// never sent it AND carries a cache-hit signal twice: shared-cache replay.
				poc := fmt.Sprintf("%s: %s", hdr, canary)
				s.store(targetID, "high", baseURL, hdr, poc,
					fmt.Sprintf("Web cache poisoning CONFIRMED by two clean shared-cache replays. Seed: curl -sk %q -H %q; then request %q twice without that header. Both clean responses retained %q (cache: %s / %s).",
						testURL, poc, testURL, canary, orNone(cacheHeaderSummary(cacheHeaders)), orNone(cacheHeaderSummary(cacheHeaders2))), 95)
				logFn("warn", "cache_poison", fmt.Sprintf("Cache poisoning CONFIRMED: %s via %s", baseURL, hdr))
				s.broadcastFinding(targetID, baseURL, hdr)
				return true
			}
			// Persistence without an observable shared-cache hit can be application
			// state or a private cache. Keep it reviewable, never verified.
			if !candidateStored {
				s.store(targetID, "medium", baseURL, hdr, fmt.Sprintf("%s: %s", hdr, canary),
					fmt.Sprintf("Header %q persisted into a clean response, but no shared-cache HIT/Age proof was present.", hdr), 75)
				candidateStored = true
			}
			continue
		}

		// Reflected but not (yet) proven cached — lower-confidence candidate.
		// Do not create cache-poison candidates for ordinary header reflection on
		// an explicitly private/non-cacheable page. Keep at most one candidate per
		// URL to avoid ten near-identical rows from the header family.
		if !candidateStored && (cachePotentiallyShared(poisonHeaders) || cachePotentiallyShared(cacheHeaders)) {
			s.store(targetID, "medium", baseURL, hdr, fmt.Sprintf("%s: %s", hdr, canary),
				fmt.Sprintf("Unkeyed header %q is reflected and the endpoint has shared-cache signals, but clean replay did not retain it (cache: %s).", hdr, orNone(cacheHeaderSummary(cacheHeaders))), 55)
			candidateStored = true
		}
		// Reflecting X-Forwarded-Host and friends is extremely common and is NOT a
		// vulnerability without a proven cache hit, so this stays a CANDIDATE (see
		// store: confidence 55 < ConfEvidence) and does NOT fire a "new finding"
		// broadcast — surfacing it as a confirmed high was a major cache-poison noise source.
		logFn("info", "cache_poison", fmt.Sprintf("Unkeyed header reflected (candidate): %s via %s (caching not proven)", baseURL, hdr))
	}
	return false
}

func (s *CachePoisonScanner) fetch(ctx context.Context, u string, extraHeaders, auth map[string]string) (string, int, http.Header) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", u, nil)
	if err != nil {
		return "", 0, http.Header{}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
	for k, v := range auth {
		req.Header.Set(k, v)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	resp, err := cachePoisonClient.Do(req)
	if err != nil {
		return "", 0, http.Header{}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	resp.Body.Close()
	return string(body), resp.StatusCode, resp.Header.Clone()
}

func cacheHeaderSummary(h http.Header) string {
	return strings.TrimSpace(h.Get("X-Cache") + " " + h.Get("CF-Cache-Status") + " " + h.Get("X-Cache-Status") + " age=" + h.Get("Age") + " " + h.Get("Cache-Control"))
}

func cachePotentiallyShared(h http.Header) bool {
	cc := strings.ToLower(h.Get("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") {
		return false
	}
	if strings.Contains(cc, "s-maxage") || strings.Contains(cc, "public") {
		return true
	}
	for _, name := range []string{"X-Cache", "CF-Cache-Status", "X-Cache-Status", "X-Vercel-Cache", "X-Drupal-Cache"} {
		v := strings.ToLower(strings.TrimSpace(h.Get(name)))
		if v != "" && !strings.Contains(v, "bypass") && !strings.Contains(v, "dynamic") {
			return true
		}
	}
	return false
}

// candidateURLs picks alive HTML pages worth testing (real hosts only).
func (s *CachePoisonScanner) candidateURLs(ctx context.Context, targetID string) []string {
	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services
		WHERE target_id = ? AND status_code = 200
		  AND (content_type LIKE '%html%' OR content_type = '')
		ORDER BY url LIMIT ?`, targetID, cachePoisonMaxURLs)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) == nil {
			out = append(out, u)
		}
	}
	return filterURLsByHostScope(ctx, out)
}

func (s *CachePoisonScanner) store(targetID, sev, url, param, payload, evidence string, confidence int) {
	priority := confidence * severityWeightIDOR(sev)
	// Derive status from confidence: a proven cache hit (90) is a finding; a bare
	// unkeyed-header reflection (55) is only a candidate. Without this, the column
	// default ('finding') silently promoted every reflection to a confirmed finding.
	verdict := CandDetected
	if confidence >= ConfEvidence {
		verdict = VerifyVerified
	}
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: "cache_poisoning", Severity: sev, URL: url, Method: "GET",
		Parameter: param, Location: "header", Payload: payload, Evidence: evidence,
		Source: "cache-poison", DetectionMethod: "cache-replay", Confidence: confidence,
		Priority: priority, Verdict: verdict,
	})
}

func (s *CachePoisonScanner) broadcastFinding(targetID, url, param string) {
	if s.broadcast != nil {
		s.broadcast("new_vuln_finding", map[string]any{
			"target_id": targetID, "type": "cache_poisoning", "url": url, "parameter": param,
		})
	}
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "none"
	}
	return s
}
