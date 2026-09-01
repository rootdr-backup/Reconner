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
//  3. Send a SECOND, CLEAN request to the same cache-busted URL WITHOUT the
//     header. If the canary is STILL present, the poisoned response was cached —
//     confirmed cache poisoning. (Reflection alone is only reported as a lower
//     "unkeyed input reflected" candidate.)
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
	observed := false
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
		body1, _ := s.fetch(ctx, testURL, map[string]string{hdr: canary}, auth)
		if !strings.Contains(body1, canary) {
			continue // header not reflected → not exploitable via this header
		}

		// 2) Clean request to the SAME cache-busted URL, no header.
		body2, cacheHeaders := s.fetch(ctx, testURL, nil, nil)
		if strings.Contains(body2, canary) {
			if cacheServedFromCache(cacheHeaders) {
				// The poisoned value survived into an unauthenticated request that
				// never sent it AND carries a cache-hit signal: shared-cache replay.
				s.store(targetID, "high", baseURL, hdr,
					fmt.Sprintf("Web cache poisoning CONFIRMED: unkeyed header %q persisted into a clean unauthenticated cache-hit response (cache: %s).", hdr, orNone(cacheHeaderSummary(cacheHeaders))), 95)
				logFn("warn", "cache_poison", fmt.Sprintf("Cache poisoning CONFIRMED: %s via %s", baseURL, hdr))
				s.broadcastFinding(targetID, baseURL, hdr)
				return true
			}
			// Persistence without an observable shared-cache hit can be application
			// state or a private cache. Keep it reviewable, never verified.
			s.store(targetID, "medium", baseURL, hdr,
				fmt.Sprintf("Header %q persisted into a clean response, but no shared-cache HIT/Age proof was present.", hdr), 75)
			observed = true
			continue
		}

		// Reflected but not (yet) proven cached — lower-confidence candidate.
		s.store(targetID, "medium", baseURL, hdr,
			fmt.Sprintf("Unkeyed header %q is reflected in the response. If the endpoint is cached, this may be exploitable as web cache poisoning (cache header seen: %s).", hdr, orNone(cacheHeaderSummary(cacheHeaders))), 55)
		// Reflecting X-Forwarded-Host and friends is extremely common and is NOT a
		// vulnerability without a proven cache hit, so this stays a CANDIDATE (see
		// store: confidence 55 < ConfEvidence) and does NOT fire a "new finding"
		// broadcast — surfacing it as a confirmed high was a major cache-poison noise source.
		logFn("info", "cache_poison", fmt.Sprintf("Unkeyed header reflected (candidate): %s via %s (caching not proven)", baseURL, hdr))
		observed = true
	}
	return observed
}

func (s *CachePoisonScanner) fetch(ctx context.Context, u string, extraHeaders, auth map[string]string) (string, http.Header) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", u, nil)
	if err != nil {
		return "", http.Header{}
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
		return "", http.Header{}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	resp.Body.Close()
	return string(body), resp.Header.Clone()
}

func cacheHeaderSummary(h http.Header) string {
	return strings.TrimSpace(h.Get("X-Cache") + " " + h.Get("CF-Cache-Status") + " " + h.Get("X-Cache-Status") + " age=" + h.Get("Age") + " " + h.Get("Cache-Control"))
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

func (s *CachePoisonScanner) store(targetID, sev, url, param, evidence string, confidence int) {
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
		Parameter: param, Location: "header", Payload: param + ": <canary>", Evidence: evidence,
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
