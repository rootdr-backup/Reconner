package scanner

import (
	"context"
	"fmt"
	"io"
	"sort"
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

// RaceScanner probes for race conditions (TOCTOU / limit-overrun) on
// state-changing endpoints — coupon reuse, one-vote-per-user, balance/withdraw
// races, OTP brute-force. It fires a burst of IDENTICAL requests released as
// simultaneously as possible (all goroutines block on one barrier, then go), so
// they hit the server inside the same tiny window before state is committed.
//
// Automatic race detection is inherently heuristic, so this is conservative: it
// only tests endpoints whose path/param looks state-changing and race-prone, and
// only reports when the simultaneous identical requests produce INCONSISTENT
// outcomes (a mix of statuses, e.g. some 200 and some 409/429) with more than one
// success. That inconsistency is the observable fingerprint of a non-atomic
// check — a human then confirms the business impact. Findings are low-severity /
// modest-confidence by design so they never crowd out confirmed criticals.
type RaceScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewRaceScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *RaceScanner {
	return &RaceScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

var raceClient = newPooledClient(12*time.Second, false)

// tokens that suggest a state-changing / limited action worth racing.
var raceProneTokens = []string{
	"coupon", "promo", "voucher", "gift", "redeem", "discount", "code",
	"vote", "like", "follow", "referral", "invite", "claim", "apply",
	"withdraw", "transfer", "payout", "purchase", "order", "checkout",
	"otp", "verify", "confirm", "reset", "balance", "credit", "wallet",
}

const raceBurst = 20

func (s *RaceScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	points := s.candidatePoints(ctx, targetID)
	if len(points) == 0 {
		logFn("info", "race", "No race-prone state-changing endpoints found")
		return nil
	}
	auth := loadAuthHeaders(ctx, s.db, targetID)
	logFn("info", "race", fmt.Sprintf("Race-testing %d state-changing endpoint(s) with %d simultaneous requests each...", len(points), raceBurst))

	var found atomic.Int64
	// Endpoints tested sequentially (each burst is itself highly concurrent);
	// avoids hammering the whole target at once.
	for _, ip := range points {
		if ctx.Err() != nil {
			break
		}
		if s.testPoint(ctx, targetID, ip, auth, logFn) {
			found.Add(1)
		}
	}
	logFn("info", "race", fmt.Sprintf("Race testing done. %d endpoint(s) showed race-indicative inconsistency.", found.Load()))
	return nil
}

func (s *RaceScanner) testPoint(ctx context.Context, targetID string, ip insertionPoint, auth map[string]string, logFn LogFunc) bool {
	type result struct {
		status int
		length int
	}
	results := make([]result, raceBurst)

	var wg sync.WaitGroup
	start := make(chan struct{}) // barrier: all requests released together
	for i := 0; i < raceBurst; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req, err := buildInjectedRequest(ctx, ip, "1", auth)
			if err != nil {
				return
			}
			<-start // wait for the barrier
			resp, err := raceClient.Do(req)
			if err != nil {
				return
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
			resp.Body.Close()
			results[idx] = result{resp.StatusCode, len(body)}
		}(i)
	}
	// Give goroutines a moment to reach the barrier, then release.
	time.Sleep(120 * time.Millisecond)
	close(start)
	wg.Wait()

	// Tally outcomes by status code.
	counts := map[int]int{}
	successes := 0
	responded := 0
	for _, r := range results {
		if r.status == 0 {
			continue
		}
		responded++
		counts[r.status]++
		if r.status == 200 || r.status == 201 || r.status == 302 {
			successes++
		}
	}
	// Need a real sample and a genuine MIX of outcomes with >1 success.
	if responded < raceBurst/2 || len(counts) < 2 || successes < 2 {
		return false
	}

	sev, confidence := "low", 45
	ev := fmt.Sprintf(
		"%d simultaneous identical requests to %s (param %s) returned INCONSISTENT outcomes %s. A non-atomic limit/uniqueness check is a strong race-condition signal (e.g. coupon reuse, double-spend, limit bypass) — verify the business impact manually.",
		raceBurst, ip.URL, ip.Param, formatCounts(counts))
	s.store(targetID, ip.URL, ip.Param, sev, ev, confidence)
	logFn("warn", "race", fmt.Sprintf("Race signal: %s param=%s outcomes=%s", ip.URL, ip.Param, formatCounts(counts)))
	if s.broadcast != nil {
		s.broadcast("new_vuln_finding", map[string]any{
			"target_id": targetID, "type": "race_condition", "url": ip.URL, "parameter": ip.Param,
		})
	}
	return true
}

// candidatePoints returns POST/state-changing insertion points whose URL or
// parameter name looks race-prone. GET endpoints are excluded — racing an
// idempotent read is meaningless and noisy.
func (s *RaceScanner) candidatePoints(ctx context.Context, targetID string) []insertionPoint {
	all := loadInsertionPoints(ctx, s.db, targetID, s.cfg.URLLimit())
	seen := map[string]bool{}
	var out []insertionPoint
	for _, ip := range all {
		method := strings.ToUpper(ip.Method)
		if method != "POST" && method != "PUT" && method != "PATCH" {
			continue
		}
		hay := strings.ToLower(ip.URL + " " + ip.Param)
		if !containsAny(hay, raceProneTokens) {
			continue
		}
		key := xssNormalizeKey(ip.URL, ip.Param)
		if seen[key] || len(out) >= 40 {
			continue
		}
		seen[key] = true
		out = append(out, ip)
	}
	return out
}

func (s *RaceScanner) store(targetID, url, param, sev, evidence string, confidence int) {
	priority := confidence * 2
	_, _ = s.db.Exec(`
		INSERT INTO vuln_findings (id, target_id, type, severity, url, parameter, payload, evidence, confidence, priority)
		VALUES (?, ?, 'race_condition', ?, ?, ?, '', ?, ?, ?)
		ON CONFLICT(target_id, type, url, parameter) DO UPDATE SET
			severity = excluded.severity, evidence = excluded.evidence,
			confidence = excluded.confidence, priority = excluded.priority
	`, uuid.New().String(), targetID, sev, url, param, evidence, confidence, priority)
}

func containsAny(hay string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

func formatCounts(counts map[int]int) string {
	keys := make([]int, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%dx HTTP %d", counts[k], k))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
