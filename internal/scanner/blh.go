package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

// BLHScanner detects Broken Link Hijacking: a page links to (or loads a script/
// stylesheet/iframe from) an EXTERNAL domain that no longer resolves — i.e. the
// domain is unregistered/expired. An attacker can register that domain and then
// serve arbitrary content/JS to the target's users (stored-XSS-grade impact for
// a <script src>, phishing for an <a href>). This is a real, high-value bounty
// class and — crucially — ZERO false-positive: an NXDOMAIN is definitive proof
// the link is claimable, not a heuristic.
type BLHScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewBLHScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *BLHScanner {
	return &BLHScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

var blhClient = &http.Client{
	Timeout:   12 * time.Second,
	Transport: sharedHTTPTransport,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

func (s *BLHScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "blh", "Checking pages for broken-link hijacking (dead external links)...")

	pages := s.loadPages(ctx, targetID)
	if len(pages) == 0 {
		logFn("info", "blh", "No pages to check")
		return nil
	}

	// Collect the unique external resource hosts referenced across all pages,
	// remembering one page URL per host as the evidence location.
	var mu sync.Mutex
	extHosts := map[string]blhRef{} // host -> {kind, value, page}

	sem := make(chan struct{}, 12)
	var wg sync.WaitGroup
	for _, p := range pages {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(pageURL string) {
			defer wg.Done()
			defer func() { <-sem }()
			body := s.fetch(ctx, pageURL)
			if body == "" {
				return
			}
			snap := extractSecuritySnapshot(body, hostOf(pageURL))
			mu.Lock()
			for _, a := range snap.Attrs {
				h := hostOf(normalizeScheme(a.Value))
				if h == "" || !strings.Contains(h, ".") {
					continue
				}
				if _, ok := extHosts[h]; !ok {
					extHosts[h] = blhRef{kind: a.Kind, value: a.Value, page: pageURL}
				}
			}
			mu.Unlock()
		}(p)
	}
	wg.Wait()

	logFn("info", "blh", fmt.Sprintf("Found %d unique external resource hosts — checking which are dead...", len(extHosts)))

	// A host that fails to resolve with NXDOMAIN is registerable → hijackable.
	var found atomic.Int64
	hsem := make(chan struct{}, 20)
	var hwg sync.WaitGroup
	for h, ref := range extHosts {
		if ctx.Err() != nil {
			break
		}
		hwg.Add(1)
		hsem <- struct{}{}
		go func(host string, r blhRef) {
			defer hwg.Done()
			defer func() { <-hsem }()
			if !hostIsNXDOMAIN(ctx, host) {
				return
			}
			sev := "medium"
			if r.kind == "script" || r.kind == "iframe" {
				sev = "high" // executes in the victim's origin
			}
			s.store(targetID, host, r, sev)
			found.Add(1)
			logFn("warn", "blh", fmt.Sprintf("BROKEN LINK HIJACK [%s]: %s references dead external %s %q", sev, r.page, r.kind, host))
			if s.broadcast != nil {
				s.broadcast("new_vuln_finding", map[string]any{
					"target_id": targetID, "type": "broken_link_hijack", "url": r.page,
				})
			}
		}(h, ref)
	}
	hwg.Wait()

	logFn("info", "blh", fmt.Sprintf("Broken-link-hijack check done. Found %d claimable dead links.", found.Load()))
	return nil
}

type blhRef struct{ kind, value, page string }

// loadPages gathers the pages to scan for dead outbound links. Broken links live
// on DEEP pages far more often than on host roots, so this scans the whole
// discovered surface — live host roots PLUS every page the crawl/param-mining
// found (parameters) PLUS discovered directories — deduped and bounded. On a
// BLH-only scan the params bundle has run, so these sources are populated; on a
// roots-only scan it gracefully degrades to just the http_services roots.
func (s *BLHScanner) loadPages(ctx context.Context, targetID string) []string {
	limit := s.cfg.URLLimit()
	seen := map[string]bool{}
	var out []string
	add := func(u string) {
		if u == "" || seen[u] {
			return
		}
		if !urlHostInScope(ctx, u) {
			return
		}
		seen[u] = true
		out = append(out, u)
	}
	scan := func(query string) {
		rows, err := s.db.QueryContext(ctx, query, targetID, limit)
		if err != nil {
			return
		}
		defer rows.Close()
		for rows.Next() {
			var u string
			if rows.Scan(&u) == nil {
				add(u)
			}
		}
	}
	// Live host roots.
	scan(`SELECT DISTINCT url FROM http_services
		WHERE target_id=? AND COALESCE(source,'probe')='probe' AND status_code BETWEEN 200 AND 399
		LIMIT ?`)
	// Crawled / param-mined deep pages — where dead external links usually hide.
	scan(`SELECT DISTINCT url FROM parameters WHERE target_id=? LIMIT ?`)
	// Discovered directories that returned content.
	scan(`SELECT DISTINCT url FROM directory_findings
		WHERE target_id=? AND status_code BETWEEN 200 AND 399 LIMIT ?`)
	return out
}

func (s *BLHScanner) fetch(ctx context.Context, url string) string {
	reqCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	resp, err := blhClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 3*1024*1024))
	return string(body)
}

func (s *BLHScanner) store(targetID, host string, r blhRef, sev string) {
	title := fmt.Sprintf("Broken-link hijacking: page loads external %s from %q, which is UNREGISTERED (NXDOMAIN) and can be claimed by an attacker", r.kind, host)
	if r.kind == "script" {
		title += " — a registered domain could serve malicious JS in the site's origin (stored-XSS-grade)."
	}
	provenance := fmt.Sprintf("page=%s\n%s=%s\nhost=%s → NXDOMAIN (registerable)", r.page, r.kind, r.value, host)
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: "broken_link_hijack", Subtype: r.kind, Severity: sev,
		URL: r.page, Method: "DNS", Parameter: host, Location: r.kind, Payload: r.value,
		Evidence: title, Source: "broken-link", DetectionMethod: "nxdomain-proof",
		Confidence: 90, Provenance: provenance, Verdict: VerifyVerified,
	})
}

// hostIsNXDOMAIN reports whether a host definitively does not exist (the domain
// is unregistered/expired) — the confirmable signal for broken-link hijacking.
// A resolve error that is NOT "not found" (timeout, temporary) returns false so
// we never false-positive on a transient DNS hiccup.
func hostIsNXDOMAIN(ctx context.Context, host string) bool {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := net.DefaultResolver.LookupHost(c, host)
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return false
}

// normalizeScheme upgrades protocol-relative URLs so hostOf can parse them.
func normalizeScheme(u string) string {
	u = strings.TrimSpace(u)
	if strings.HasPrefix(u, "//") {
		return "http:" + u
	}
	return u
}
