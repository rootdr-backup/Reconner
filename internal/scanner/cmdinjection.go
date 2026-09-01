package scanner

import (
	"context"
	"fmt"
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

type CmdiScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewCmdiScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *CmdiScanner {
	return &CmdiScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

var cmdiHTTPClient = &http.Client{
	Transport: sharedHTTPTransport,
	Timeout:   20 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// Echo-based detection that is REFLECTION-PROOF. A naive `echo MARKER` test
// false-positives on any app that reflects input (search terms, breadcrumbs,
// canonical URLs…), because the literal payload — including MARKER — shows up in
// the HTML without any command running. Instead we make the SHELL COMPUTE the
// marker with arithmetic expansion: $((1000+337)). Only an actually-executed
// command yields the contiguous string "RCNZZ1337ZZ"; a reflected payload shows
// the literal "RCNZZ$((1000+337))ZZ", which never contains 1337. So a match is
// proof of execution, not reflection.
const cmdiEchoMarker = "RCNZZ1337ZZ"

var cmdiEchoPayloads = []string{
	";echo RCNZZ$((1000+337))ZZ",
	"|echo RCNZZ$((1000+337))ZZ",
	"||echo RCNZZ$((1000+337))ZZ",
	"&&echo RCNZZ$((1000+337))ZZ",
	"`echo RCNZZ$((1000+337))ZZ`",
	"$(echo RCNZZ$((1000+337))ZZ)",
	"%0aecho RCNZZ$((1000+337))ZZ",
	"\necho RCNZZ$((1000+337))ZZ",
	// Space-filter WAF bypass (${IFS}) — same reflection-proof marker, no spaces.
	";echo${IFS}RCNZZ$((1000+337))ZZ",
	"|echo${IFS}RCNZZ$((1000+337))ZZ",
	"`echo${IFS}RCNZZ$((1000+337))ZZ`",
}

// Params more likely to hit a shell (kept broad but weighted). We still cap.
var cmdiProneParams = map[string]bool{
	"cmd": true, "exec": true, "command": true, "run": true, "ping": true,
	"host": true, "ip": true, "domain": true, "query": true, "search": true,
	"name": true, "file": true, "path": true, "dir": true, "action": true,
	"do": true, "func": true, "arg": true, "args": true, "option": true,
	"target": true, "url": true, "data": true, "input": true, "code": true,
	"process": true, "task": true, "job": true, "system": true, "shell": true,
}

const cmdiMaxParams = 120

// Run tests parameters for OS command injection via reflection-proof echo-based
// execution (in-band) and out-of-band shell callbacks (blind). No time-based
// checks. Targeted (prone params first) + bounded to keep scans fast.
func (s *CmdiScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "cmdi", "Starting OS command injection checks...")

	points := s.selectCandidates(ctx, targetID)
	logFn("info", "cmdi", fmt.Sprintf("Testing %d insertion points for command injection...", len(points)))
	if len(points) == 0 {
		// No in-band candidates, but blind RCE may still be planted out-of-band.
		s.plantBlindRCE(ctx, targetID, logFn)
		return nil
	}
	auth := loadAuthHeaders(ctx, s.db, targetID)

	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, ip := range points {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip insertionPoint) {
			defer wg.Done()
			defer func() { <-sem }()

			// 1) echo-based (fast, definitive when it works). REFLECTION-PROOF:
			// the marker only exists if the shell evaluated $((1000+337))=1337.
			base, _ := sendInjected(ctx, cmdiHTTPClient, ip, "rcnbase", auth)
			if strings.Contains(base, cmdiEchoMarker) {
				// The app already emits the marker (e.g. contains "1337"): skip to
				// avoid any chance of a coincidental match.
			} else {
				for _, pl := range cmdiEchoPayloads {
					body, _ := sendInjected(ctx, cmdiHTTPClient, ip, "x"+pl, auth)
					if !strings.Contains(body, cmdiEchoMarker) {
						continue
					}
					// Guard: the literal, unevaluated payload must NOT be what we
					// matched — if the raw "$((1000+337))" is present, it was merely
					// reflected, not executed.
					if strings.Contains(body, "$((1000+337))") {
						continue
					}
					// Confirm with a second request to drop flukes.
					body2, _ := sendInjected(ctx, cmdiHTTPClient, ip, "x"+pl, auth)
					if !strings.Contains(body2, cmdiEchoMarker) || strings.Contains(body2, "$((1000+337))") {
						continue
					}
					s.store(targetID, "command_injection", "critical", ip, pl,
						"OS command executed: shell-computed marker "+cmdiEchoMarker+" (from $((1000+337))) returned in response — reflection-proof ["+ip.Method+"]")
					found.Add(1)
					logFn("warn", "cmdi", fmt.Sprintf("RCE (echo) CONFIRMED: %s param=%s [%s]", ip.URL, ip.Param, ip.Method))
					s.notify(targetID, ip.URL, ip.Param)
					return
				}
			}

			// Time-based confirmation was removed on purpose: even with 3-point
			// linear-scaling proofs it produced false positives on tarpitting WAFs,
			// value-dependent slow backends, and jittery links. Blind (no-echo)
			// command injection is now proven ONLY out-of-band below, where a real
			// shell callback is deterministic and free of timing false positives.
		}(ip)
	}
	wg.Wait()

	// Blind (out-of-band) RCE — the command-injection objective OWNS its blind
	// payloads via the shared OOB capability (a callback proves shell execution
	// with no visible response signal), so a single-objective CMDi scan is complete
	// without a multi-class OAST module.
	s.plantBlindRCE(ctx, targetID, logFn)

	logFn("info", "cmdi", fmt.Sprintf("Command injection check done. Found %d.", found.Load()))
	return nil
}

// plantBlindRCE plants shell-metacharacter payloads that curl our OOB host across
// every insertion point (no-op without a configured callback URL). A callback is
// reported as a blind_rce finding via RecordOOBHit.
func (s *CmdiScanner) plantBlindRCE(ctx context.Context, targetID string, logFn LogFunc) {
	o, ok := newOOBCapability(s.cfg)
	if !ok {
		return
	}
	limit := cmdiMaxParams
	if s.cfg != nil && s.cfg.URLLimit() > 0 && s.cfg.URLLimit() < limit {
		limit = s.cfg.URLLimit()
	}
	points := loadRoutedInsertionPoints(ctx, s.db, targetID, ClassCMDi, limit, 48)
	if len(points) == 0 {
		return
	}
	auth := loadAuthHeaders(ctx, s.db, targetID)
	n := o.plantClass(ctx, s.db, targetID, points, auth, "rce",
		nil, // shell-metacharacter payloads are injected on every param, as before
		func(_ insertionPoint, cb string) []string { return rceOOBPayloads(cb) })
	if n > 0 {
		logFn("info", "cmdi", fmt.Sprintf("Planted %d blind-RCE OOB probe(s); execution reported via callback.", n))
	}
}

// selectCandidates prioritises shell-prone params (incl. POST form fields) but
// includes a bounded slice of others too (command injection can hide anywhere).
func (s *CmdiScanner) selectCandidates(ctx context.Context, targetID string) []insertionPoint {
	limit := cmdiMaxParams
	if s.cfg != nil && s.cfg.URLLimit() > 0 && s.cfg.URLLimit() < limit {
		limit = s.cfg.URLLimit()
	}
	return loadRoutedInsertionPoints(ctx, s.db, targetID, ClassCMDi, limit, 48)
}

func (s *CmdiScanner) store(targetID, vulnType, severity string, ip insertionPoint, payload, evidence string) {
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: vulnType, Subtype: "in-band", Severity: severity,
		URL: ip.URL, Method: ip.Method, Parameter: ip.Param, Location: insertionLocation(ip), Payload: payload,
		Evidence: evidence, Source: "cmdi-native", DetectionMethod: "computed-marker-replay",
		Confidence: 99, Verdict: VerifyVerified,
	})
}

func (s *CmdiScanner) notify(targetID, rawURL, param string) {
	if s.broadcast != nil {
		s.broadcast("new_vuln_finding", map[string]any{
			"target_id": targetID, "type": "command_injection", "url": rawURL, "parameter": param,
		})
	}
}
