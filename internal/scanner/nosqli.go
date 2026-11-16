package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

// NoSQLiScanner detects NoSQL (MongoDB-style) injection — an extremely common,
// high-impact bug in modern JS/Python/PHP stacks that classic SQLi checks miss.
// Two low-false-positive techniques:
//
//   - BOOLEAN operator injection: sending param[$ne]=x (matches everything) vs
//     param[$eq]=x (matches nothing) yields two SUBSTANTIALLY different responses
//     ONLY if the backend actually interpreted the operator. If the app treats
//     "param[$ne]" as a literal unknown parameter, both responses equal the
//     baseline and nothing is reported.
//   - ERROR-based: an injected quote/brace surfaces a MongoDB/driver error string
//     (MongoError, E11000, $where, BSON, mongoose CastError…) not present in the
//     baseline.
//
// Covers both query-string (param[$ne]=) and JSON body ({"param":{"$ne":...}})
// injection points.
type NoSQLiScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewNoSQLiScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *NoSQLiScanner {
	return &NoSQLiScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

var nosqliClient = newPooledClient(12*time.Second, false)

// MongoDB / NoSQL driver error signatures (specific enough to avoid FPs).
var nosqlErrorSignatures = []string{
	"mongoerror", "mongoservererror", "mongonetworkerror", "e11000 duplicate key",
	"bsonobj", "com.mongodb", "mongoose", "casterror", "pymongo",
	"unknown top level operator", "unknown operator", "badvalue:", "bson field",
}

const nosqliMaxPoints = 150

func (s *NoSQLiScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	limit := nosqliMaxPoints
	if s.cfg != nil && s.cfg.URLLimit() > 0 && s.cfg.URLLimit() < limit {
		limit = s.cfg.URLLimit()
	}
	points := loadRoutedInsertionPoints(ctx, s.db, targetID, ClassNoSQLi, limit, 64)
	if len(points) == 0 {
		logFn("info", "nosqli", "No insertion points for NoSQL injection")
		return nil
	}
	auth := loadAuthHeaders(ctx, s.db, targetID)
	logFn("info", "nosqli", fmt.Sprintf("Testing %d insertion points for NoSQL injection...", len(points)))

	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	var found atomic.Int64

	var flaggedMu sync.Mutex
	flagged := make(map[string]bool)
	for _, ip := range points {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip insertionPoint) {
			defer wg.Done()
			defer func() { <-sem }()
			if s.testPoint(ctx, targetID, ip, auth, logFn) {
				found.Add(1)
				flaggedMu.Lock()
				flagged[insertionIdentity(ip)] = true
				flaggedMu.Unlock()
			}
		}(ip)
	}
	wg.Wait()

	// Statistical time-based pass ($where): the one NoSQLi technique with NO
	// visible differential at all when the handler ignores the query result
	// (a logging/audit write, a fire-and-forget filter) — boolean/error-based
	// detection above structurally cannot see it. Runs only on candidates the
	// deterministic/boolean pass did not already flag.
	s.whereTimeBasedPass(ctx, targetID, points, flagged, auth, &found, logFn)

	logFn("info", "nosqli", fmt.Sprintf("NoSQL injection done. Found %d.", found.Load()))
	return nil
}

func (s *NoSQLiScanner) testPoint(ctx context.Context, targetID string, ip insertionPoint, auth map[string]string, logFn LogFunc) bool {
	isJSON := insertionLocation(ip) == "json"

	// Baseline with the original value.
	baseStatus, baseBody := s.send(ctx, ip, valuePlain, "", auth, isJSON)
	if baseStatus == 0 {
		return false
	}
	baseLower := strings.ToLower(baseBody)
	if s.customErrorProbe(ctx, targetID, ip, auth, isJSON, baseLower, logFn) {
		return true
	}

	// 1) Error-based: a bare quote/brace surfaces a driver error.
	_, errBody := s.send(ctx, ip, valueErr, "", auth, isJSON)
	if sig := firstNewSignature(strings.ToLower(errBody), baseLower, nosqlErrorSignatures); sig != "" {
		_, replay := s.send(ctx, ip, valueErr, "", auth, isJSON)
		if !strings.Contains(strings.ToLower(replay), sig) || bodyLooksLikeWAFBlock(errBody) || bodyLooksLikeWAFBlock(replay) {
			return false
		}
		s.store(targetID, "critical", ip, ip.Param+"="+valueErr, fmt.Sprintf("NoSQL error triggered by injected metacharacter — response leaked %q (not in baseline)", sig), 95)
		s.report(targetID, ip, logFn, "error", 95)
		return true
	}

	// Adaptive baseline + WAF gate: scale the "material difference" bar off THIS
	// endpoint's own measured noise floor rather than a fixed 200 bytes, and bail
	// out if a security intermediary is answering with block/challenge pages.
	vol := measureVolatility(ctx, nosqliClient, ip, auth, valuePlain)
	if vol.blocked {
		return false
	}

	// 2) Boolean operator injection. Two independent vectors:
	//   a) $ne (matches everything) vs $eq (matches nothing) — the classic.
	//   b) $regex ".*" (matches everything) vs $regex "^…nomatch…$" (matches
	//      nothing) — the exact operator behind the pre-auth Rocket.Chat NoSQLi
	//      (CVE-2021-22911) and the most common modern NoSQLi in disclosed reports.
	//      A regex-matched login/search filter can be bypassed with $regex even
	//      where $ne semantics leave the output unchanged, so it's real added reach.
	if tl, fl, ok := s.booleanOpDiff(ctx, ip, auth, isJSON, vol, "rcnnope", "$ne", "rcnnope", "$eq"); ok {
		s.store(targetID, "high", ip, ip.Param+"[$ne]=rcnnope",
			fmt.Sprintf("NoSQL boolean injection: [$ne] response (%dB) differs materially from [$eq] (%dB), reproduced with a stable direction across two request pairs — the operator was interpreted by the database.", tl, fl), 80)
		s.report(targetID, ip, logFn, "boolean", 80)
		return true
	}
	if tl, fl, ok := s.booleanOpDiff(ctx, ip, auth, isJSON, vol, ".*", "$regex", "^rcnZZnomatch$", "$regex"); ok {
		s.store(targetID, "high", ip, ip.Param+`[$regex]=.*`,
			fmt.Sprintf("NoSQL boolean injection ($regex): a match-all [$regex '.*'] response (%dB) differs materially from a match-none [$regex '^…$'] (%dB), reproduced with a stable direction — the regex operator was interpreted by the database (Rocket.Chat CVE-2021-22911 class).", tl, fl), 80)
		s.report(targetID, ip, logFn, "boolean-regex", 80)
		return true
	}
	return false
}

func (s *NoSQLiScanner) customErrorProbe(ctx context.Context, targetID string, ip insertionPoint, auth map[string]string, isJSON bool, baseline string, logFn LogFunc) bool {
	if s.cfg == nil {
		return false
	}
	payloads := CustomCorpus(s.cfg.WordlistsDir, "nosqli")
	if len(payloads) > 64 {
		payloads = payloads[:64]
	}
	for _, payload := range payloads {
		_, body := s.send(ctx, ip, payload, "", auth, isJSON)
		sig := firstNewSignature(strings.ToLower(body), baseline, nosqlErrorSignatures)
		if sig == "" || bodyLooksLikeWAFBlock(body) {
			continue
		}
		_, replay := s.send(ctx, ip, payload, "", auth, isJSON)
		if !strings.Contains(strings.ToLower(replay), sig) || bodyLooksLikeWAFBlock(replay) {
			continue
		}
		s.store(targetID, "critical", ip, ip.Param+"="+payload, fmt.Sprintf("NoSQL driver error triggered by operator corpus payload %q; response leaked %q twice and the signature was absent from baseline", payload, sig), 95)
		s.report(targetID, ip, logFn, "custom-error", 95)
		return true
	}
	return false
}

// booleanOpDiff runs a TRUE-vs-FALSE MongoDB-operator pair through the same
// low-false-positive gate the $ne/$eq path uses: the two responses must differ by
// more than the endpoint's adaptive noise floor AND by ≥15%, neither may be an
// auth/error page, and the gap must REPRODUCE in the SAME direction across two
// independent request pairs (killing dynamic-content jitter). Returns the TRUE and
// FALSE body lengths (for evidence) and whether the operator was interpreted.
func (s *NoSQLiScanner) booleanOpDiff(ctx context.Context, ip insertionPoint, auth map[string]string, isJSON bool, vol volProfile, trueVal, trueOp, falseVal, falseOp string) (tLen, fLen int, ok bool) {
	loc := insertionLocation(ip)
	if loc != "query" && loc != "body" && loc != "json" {
		return 0, 0, false // structured $operators cannot be represented here
	}
	trueStatus, trueBody := s.send(ctx, ip, trueVal, trueOp, auth, isJSON)
	falseStatus, falseBody := s.send(ctx, ip, falseVal, falseOp, auth, isJSON)
	if trueStatus == 0 || falseStatus == 0 {
		return 0, 0, false
	}
	if bodyLooksLikeWAFBlock(trueBody) || bodyLooksLikeWAFBlock(falseBody) {
		return 0, 0, false
	}
	threshold := vol.sigDiff(200)
	dTF := abs(len(trueBody) - len(falseBody))
	gap := dTF * 100 / max1(len(trueBody), len(falseBody)) // percent difference
	if dTF > threshold && gap >= 15 &&
		matchAny(strings.ToLower(trueBody), idorErrorSignatures) == "" &&
		(trueStatus != falseStatus || !bodiesSameObject(trueBody, falseBody)) {
		trueStatus2, trueBody2 := s.send(ctx, ip, trueVal, trueOp, auth, isJSON)
		falseStatus2, falseBody2 := s.send(ctx, ip, falseVal, falseOp, auth, isJSON)
		dTF2 := abs(len(trueBody2) - len(falseBody2))
		sameDirection := (len(trueBody) >= len(falseBody)) == (len(trueBody2) >= len(falseBody2))
		if dTF2 > threshold && sameDirection && trueStatus2 == trueStatus && falseStatus2 == falseStatus &&
			bodiesSameObject(trueBody, trueBody2) && bodiesSameObject(falseBody, falseBody2) &&
			!bodyLooksLikeWAFBlock(trueBody2) && !bodyLooksLikeWAFBlock(falseBody2) &&
			matchAny(strings.ToLower(trueBody2), idorErrorSignatures) == "" {
			return len(trueBody), len(falseBody), true
		}
	}
	return 0, 0, false
}

// whereTimeBasedPass runs whereTimeBasedProbe over candidates the
// deterministic/boolean pass above did not already flag, at low concurrency
// — each confirmation holds a connection open for several seconds, mirroring
// SQLi's own timeBasedPass (sqli_timing.go).
func (s *NoSQLiScanner) whereTimeBasedPass(ctx context.Context, targetID string, points []insertionPoint, flagged map[string]bool, auth map[string]string, found *atomic.Int64, logFn LogFunc) {
	var todo []insertionPoint
	for _, ip := range points {
		if !flagged[insertionIdentity(ip)] {
			todo = append(todo, ip)
		}
	}
	if len(todo) == 0 {
		return
	}
	logFn("info", "nosqli", fmt.Sprintf("Time-based NoSQL injection ($where, statistical linear-scaling proof) over %d insertion point(s)...", len(todo)))

	sem := make(chan struct{}, 4) // low: each confirmation holds a connection for seconds
	var wg sync.WaitGroup
	for _, ip := range todo {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip insertionPoint) {
			defer wg.Done()
			defer func() { <-sem }()
			// Hard per-candidate deadline: a genuine hit completes its 0/2/5s
			// scaling proof in well under a minute, bounding the pathological
			// case of a jittery-but-not-yet-severely-throttled host.
			timingCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
			ev, ok := s.whereTimeBasedProbe(timingCtx, ip, auth)
			cancel()
			if ok {
				s.store(targetID, "critical", ip, ip.Param+"&$where=sleep(5000)", ev, 95)
				found.Add(1)
				s.report(targetID, ip, logFn, "where-time-based", 95)
			}
		}(ip)
	}
	wg.Wait()
}

// whereTimeBasedProbe tests MongoDB's $where operator — arbitrary JavaScript
// executed server-side per matched document — via a statistical, linear-
// scaling timing proof. $where is the one NoSQLi technique booleanOpDiff
// structurally cannot see: it has no visible differential at all when the
// handler ignores the query result (a logging/audit write, a fire-and-forget
// filter), exactly why SQLi keeps a dedicated time-based pass instead of
// trusting boolean/error detection alone. This reuses that SAME proven
// engine (serverTTFB/sampleTTFB/timingScalingConfirmed in sqli_timing.go) —
// median-of-N TTFB samples, a 0/2/5-second linear-scaling requirement, and
// non-overlap with the baseline distribution — rather than trusting a single
// timer, which is a classic false-positive source under network jitter or a
// slow WAF.
func (s *NoSQLiScanner) whereTimeBasedProbe(ctx context.Context, ip insertionPoint, auth map[string]string) (string, bool) {
	loc := insertionLocation(ip)
	if loc != "query" && loc != "body" && loc != "json" {
		return "", false // $where cannot be represented outside these shapes
	}
	if hostThrottleSevere(hostOfURL(ip.URL)) {
		return "", false
	}
	sleep := func(ms int) string { return fmt.Sprintf("sleep(%d)", ms) }
	reqFor := func(whereExpr string) func(context.Context) (*http.Request, error) {
		return func(c context.Context) (*http.Request, error) { return nosqliWhereRequest(c, ip, whereExpr, auth) }
	}

	// True zero-injection baseline (no $where key at all). Noise gate: an
	// endpoint that is already slow or wildly jittery cannot support a
	// trustworthy timing verdict.
	base, _, baseMax, ok := sampleTTFB(ctx, ip, 3, 8*time.Second, reqFor(""))
	if !ok || base > 3*time.Second || baseMax > base+2*time.Second {
		return "", false
	}

	dl := 12 * time.Second
	// Cheap screen: one sleep(5000) request eliminates a non-vulnerable point
	// before paying for the full three-sample proof.
	fast5, ok := serverTTFB(ctx, ip, dl, reqFor(sleep(5000)))
	if !ok || fast5-base < 3500*time.Millisecond {
		return "", false
	}
	// Confirm: sleep(5000) must add a clear, non-overlapping median delay.
	i5, i5min, _, ok := sampleTTFBSeeded(ctx, ip, 3, dl, []time.Duration{fast5}, reqFor(sleep(5000)))
	if !ok || i5-base < 3500*time.Millisecond || i5min < baseMax+2*time.Second {
		return "", false
	}
	// Control: adding the $where KEY ITSELF with sleep(0) must stay ≈
	// baseline — proves the extra operator/JSON structure isn't itself what's
	// slow (a bigger structural change than SQLi's own "append a suffix").
	i0, _, _, ok := sampleTTFB(ctx, ip, 2, dl, reqFor(sleep(0)))
	if !ok || i0 > base+1500*time.Millisecond {
		return "", false
	}
	// Linear scaling: sleep(2000) must add ≈2s and sleep(5000)−sleep(2000) ≈3s.
	i2, _, _, ok := sampleTTFB(ctx, ip, 3, dl, reqFor(sleep(2000)))
	if !ok || !timingScalingConfirmed(base, baseMax, i0, i2, i5, i5min) {
		return "", false
	}

	add2, add5, step := i2-base, i5-base, i5-i2
	ev := fmt.Sprintf(
		"NoSQL $where time-based injection PROVEN by linear delay scaling (server think-time via TTFB, network noise cancelled). "+
			"Baseline≈%dms; injected $where sleep(0)≈%dms (≈baseline → the extra operator isn't inherently slow), sleep(2000)≈%dms (+%dms), sleep(5000)≈%dms (+%dms). "+
			"The induced delay tracks the injected sleep 1:1 (Δ(5000-2000)≈%dms) and the injected responses do not overlap the baseline — this is server-side JavaScript executing via $where, not latency/WAF.",
		base.Milliseconds(), i0.Milliseconds(), i2.Milliseconds(), add2.Milliseconds(), i5.Milliseconds(), add5.Milliseconds(), step.Milliseconds())
	return ev, true
}

// nosqliWhereRequest builds a request with MongoDB's $where operator added as
// a TOP-LEVEL sibling key alongside the insertion point's own field(s) — the
// shape a handler built on Model.find(req.query)/Model.find(req.body)
// actually evaluates ($where is a filter-level operator; unlike $ne/$eq/
// $regex above it is never nested under one field name). whereExpr == ""
// builds the request with no $where key at all — the zero-injection baseline
// the timing engine compares against.
func nosqliWhereRequest(ctx context.Context, ip insertionPoint, whereExpr string, auth map[string]string) (*http.Request, error) {
	finish := func(req *http.Request, err error, contentType string) (*http.Request, error) {
		if err != nil {
			return nil, err
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
		for k, v := range auth {
			req.Header.Set(k, v)
		}
		return req, nil
	}
	switch insertionLocation(ip) {
	case "json":
		fields := make(map[string]string, len(ip.Siblings)+1)
		for k, v := range ip.Siblings {
			fields[k] = v
		}
		fields[ip.Param] = ip.Value
		var root map[string]any
		_ = json.Unmarshal([]byte(buildJSONFieldsTyped(fields, ip.SiblingTypes, "")), &root)
		if root == nil {
			root = map[string]any{}
		}
		if whereExpr != "" {
			root["$where"] = whereExpr
		}
		body, _ := json.Marshal(root)
		req, err := http.NewRequestWithContext(ctx, strings.ToUpper(ip.Method), ip.URL, strings.NewReader(string(body)))
		return finish(req, err, "application/json")
	case "body":
		values := url.Values{}
		for k, v := range ip.Siblings {
			values.Set(k, v)
		}
		values.Set(ip.Param, ip.Value)
		if whereExpr != "" {
			values.Set("$where", whereExpr)
		}
		req, err := http.NewRequestWithContext(ctx, strings.ToUpper(ip.Method), ip.URL, strings.NewReader(values.Encode()))
		return finish(req, err, "application/x-www-form-urlencoded")
	default: // query
		u := ip.URL
		if whereExpr != "" {
			u = setRawQueryParam(ip.URL, "$where", whereExpr)
		}
		req, err := http.NewRequestWithContext(ctx, strings.ToUpper(ip.Method), u, nil)
		return finish(req, err, "")
	}
}

const (
	valuePlain = "1"
	valueErr   = `'"` + "`" + `{;$`
)

// send injects value into the point. When op != "" it wraps the value in a
// MongoDB operator: query -> param[$op]=value ; JSON -> {"param":{"$op":value}}.
func (s *NoSQLiScanner) send(ctx context.Context, ip insertionPoint, value, op string, auth map[string]string, isJSON bool) (int, string) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var req *http.Request
	var err error
	if g := guidedFrom(reqCtx); g != nil {
		req, err = g.injected(reqCtx, ip, value, op)
	} else if op == "" {
		// Error/plain probes work in every insertion location and must retain the
		// target's auth, query contract, JSON/form siblings and real method.
		req, err = buildInjectedRequest(reqCtx, ip, value, auth)
	} else if isJSON {
		payload := buildNoSQLJSONBody(ip, value, op)
		req, err = http.NewRequestWithContext(reqCtx, strings.ToUpper(ip.Method), ip.URL, strings.NewReader(payload))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	} else if insertionLocation(ip) == "body" {
		values := url.Values{}
		for k, v := range ip.Siblings {
			if k != ip.Param {
				values.Set(k, v)
			}
		}
		body := values.Encode()
		if body != "" {
			body += "&"
		}
		body += url.QueryEscape(ip.Param) + "[" + op + "]=" + url.QueryEscape(value)
		req, err = http.NewRequestWithContext(reqCtx, strings.ToUpper(ip.Method), ip.URL, strings.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	} else {
		// Query string. Operator form uses the raw key param[$op].
		key := ip.Param
		if op != "" {
			key = ip.Param + "[" + op + "]"
		}
		u := setRawQueryParam(ip.URL, key, value)
		req, err = http.NewRequestWithContext(reqCtx, strings.ToUpper(ip.Method), u, nil)
	}
	if err != nil {
		return 0, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
	for k, v := range auth {
		req.Header.Set(k, v)
	}
	resp, err := nosqliClient.Do(req)
	if err != nil {
		return 0, ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	resp.Body.Close()
	return resp.StatusCode, string(body)
}

func buildNoSQLJSONBody(ip insertionPoint, value, op string) string {
	fields := make(map[string]string, len(ip.Siblings))
	for k, v := range ip.Siblings {
		if k != ip.Param {
			fields[k] = v
		}
	}
	var root map[string]any
	_ = json.Unmarshal([]byte(buildJSONFieldsTyped(fields, ip.SiblingTypes, "")), &root)
	if root == nil {
		root = map[string]any{}
	}
	parts := strings.Split(ip.Param, ".")
	cur := root
	for i, raw := range parts {
		part := strings.TrimSpace(raw)
		if part == "" {
			continue
		}
		if i == len(parts)-1 {
			cur[part] = map[string]any{op: value}
			break
		}
		next, ok := cur[part].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[part] = next
		}
		cur = next
	}
	body, _ := json.Marshal(root)
	return string(body)
}

// setRawQueryParam replaces/sets key=value in the URL's raw query WITHOUT
// url-encoding the key (so param[$ne] stays intact, which url.Values would mangle).
func setRawQueryParam(rawURL, key, value string) string {
	base := stripQuery(rawURL)
	parsed, err := url.Parse(rawURL)
	var pairs []string
	if err == nil {
		for k, vs := range parsed.Query() {
			if k == strings.SplitN(key, "[", 2)[0] {
				continue // drop the original param we're overriding
			}
			for _, v := range vs {
				pairs = append(pairs, url.QueryEscape(k)+"="+url.QueryEscape(v))
			}
		}
	}
	pairs = append(pairs, key+"="+url.QueryEscape(value))
	return base + "?" + strings.Join(pairs, "&")
}

func (s *NoSQLiScanner) store(targetID, sev string, ip insertionPoint, payload, evidence string, confidence int) {
	priority := confidence * severityWeightIDOR(sev)
	verdict := CandDetected
	if confidence >= ConfEvidence {
		verdict = VerifyVerified
	}
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: "nosql_injection", Severity: sev, URL: ip.URL,
		Method: ip.Method, Parameter: ip.Param, Location: locOf(ip), Payload: payload,
		Evidence: evidence, Source: "nosqli-native", DetectionMethod: "operator-differential",
		Confidence: confidence, Priority: priority, Verdict: verdict,
	})
}

func (s *NoSQLiScanner) report(targetID string, ip insertionPoint, logFn LogFunc, kind string, confidence int) {
	level, label := "info", "candidate"
	if confidence >= ConfEvidence {
		level, label = "warn", "confirmed"
	}
	logFn(level, "nosqli", fmt.Sprintf("NoSQL injection %s (%s): %s param=%s [%s]", label, kind, ip.URL, ip.Param, ip.Method))
	if s.broadcast != nil && confidence >= ConfEvidence {
		s.broadcast("new_vuln_finding", map[string]any{
			"target_id": targetID, "type": "nosql_injection", "url": ip.URL, "parameter": ip.Param,
		})
	}
}

// firstNewSignature returns the first signature present in body but NOT baseline.
func firstNewSignature(body, baseline string, sigs []string) string {
	for _, s := range sigs {
		if strings.Contains(body, s) && !strings.Contains(baseline, s) {
			return s
		}
	}
	return ""
}

func max1(a, b int) int {
	if a > b {
		if a == 0 {
			return 1
		}
		return a
	}
	if b == 0 {
		return 1
	}
	return b
}
