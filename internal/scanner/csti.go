package scanner

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

// CSTIScanner proves client-side template evaluation without attempting a
// sandbox escape or JavaScript execution. It reuses the existing SSTI arithmetic
// probe and requires two independent results to appear only after browser render.
type CSTIScanner struct {
	db        *database.DB
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewCSTIScanner(db *database.DB, _ *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *CSTIScanner {
	return &CSTIScanner{db: db, cfg: cfg, logger: log, broadcast: broadcast}
}

type cstiCandidate struct {
	ip    insertionPoint
	probe sstiProbe
	raw   string
}

func cstiEvaluationProven(raw, payload, expected, rendered string) bool {
	return strings.Contains(raw, payload) && !strings.Contains(raw, expected) && strings.Contains(rendered, expected)
}

func (s *CSTIScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	browser := getXSSBrowser()
	if browser == nil {
		logFn("info", "csti", "CSTI skipped: Chromium is unavailable, so client-side evaluation cannot be proven safely")
		return nil
	}
	limit := 160
	if s.cfg != nil && s.cfg.URLLimit() < limit {
		limit = s.cfg.URLLimit()
	}
	points := loadRoutedInsertionPoints(ctx, s.db, targetID, ClassCSTI, limit, 32)
	if len(points) == 0 {
		logFn("info", "csti", "No suitable HTML insertion points to test")
		return nil
	}
	auth := loadAuthHeaders(ctx, s.db, targetID)
	logFn("info", "csti", fmt.Sprintf("Pre-screening %d insertion point(s) for reflected client-template expressions...", len(points)))

	// Cheap HTTP reflection/MIME screen first. Only a raw reflected template
	// expression is allowed to consume one of the serialized browser navigations.
	var candidates []cstiCandidate
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)
	for _, ip := range points {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip insertionPoint) {
			defer wg.Done()
			defer func() { <-sem }()
			token := newXSSToken("rcncsti")
			probe := sstiProbeSet(token, 7, 7)[0] // existing benign {{7*7}} probe
			resp := sendInjectedResponse(ctx, sstiHTTPClient, ip, probe.payload, auth)
			if !browserRendersResponse(resp.Status, resp.ContentType, resp.Body, resp.NoSniff) ||
				looksLikeBlockPage(resp.Status, resp.Body) ||
				!strings.Contains(resp.Body, probe.payload) ||
				strings.Contains(resp.Body, probe.expect) {
				return
			}
			mu.Lock()
			candidates = append(candidates, cstiCandidate{ip: ip, probe: probe, raw: resp.Body})
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	sort.Slice(candidates, func(i, j int) bool { return insertionIdentity(candidates[i].ip) < insertionIdentity(candidates[j].ip) })
	const browserBudget = 40
	if len(candidates) > browserBudget {
		logFn("info", "csti", fmt.Sprintf("CSTI browser budget: verifying the first %d of %d raw-reflected candidates", browserBudget, len(candidates)))
		candidates = candidates[:browserBudget]
	}

	found := 0
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			break
		}
		rendered := browser.renderInsertion(ctx, candidate.ip, auth, candidate.probe.payload)
		if !cstiEvaluationProven(candidate.raw, candidate.probe.payload, candidate.probe.expect, rendered) {
			continue
		}
		// Reproduce with a fresh marker while keeping the exact same safe
		// arithmetic expression. This makes the observations independent without
		// expanding the payload set beyond {{7*7}}.
		secondToken := newXSSToken("rcncsti")
		second := sstiProbeSet(secondToken, 7, 7)[0]
		resp2 := sendInjectedResponse(ctx, sstiHTTPClient, candidate.ip, second.payload, auth)
		rendered2 := browser.renderInsertion(ctx, candidate.ip, auth, second.payload)
		if !browserRendersResponse(resp2.Status, resp2.ContentType, resp2.Body, resp2.NoSniff) ||
			!cstiEvaluationProven(resp2.Body, second.payload, second.expect, rendered2) {
			continue
		}
		evidence := fmt.Sprintf("Client-side template evaluation reproduced twice in Chromium with independent markers: raw HTML contained the independently tagged inert expressions %q and %q but not their results; after each render it became a uniquely tagged 49 marker [%s %s]. No script execution or sandbox escape was attempted.",
			candidate.probe.payload, second.payload, strings.ToUpper(candidate.ip.Method), insertionLocation(candidate.ip))
		_, _ = RecordDetectorObservation(ctx, s.db, DetectorObservation{
			TargetID: targetID, Type: "csti", Subtype: "client-template-arithmetic", Severity: "medium",
			URL: candidate.ip.URL, Method: candidate.ip.Method, Parameter: candidate.ip.Param,
			Location: insertionLocation(candidate.ip), Payload: candidate.probe.payload, Evidence: evidence,
			Source: "csti-native", DetectionMethod: "dual-browser-arithmetic-render", Confidence: 99,
			Verdict: VerifyVerified,
		})
		found++
		logFn("warn", "csti", fmt.Sprintf("CSTI CONFIRMED: %s param=%s", candidate.ip.URL, candidate.ip.Param))
		if s.broadcast != nil {
			s.broadcast("new_vuln_finding", map[string]any{"target_id": targetID, "type": "csti", "url": candidate.ip.URL, "parameter": candidate.ip.Param})
		}
	}
	logFn("info", "csti", fmt.Sprintf("CSTI check done. Confirmed %d client-rendered template injection(s).", found))
	return nil
}
