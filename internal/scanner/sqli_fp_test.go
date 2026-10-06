package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
)

// The data-flow bug: headerChecks tested X-Forwarded-For and Referer, but
// fetchWithHeader only ever set Cookie/User-Agent, so those headers were never
// actually injected. This asserts the injection now reaches each header.
func TestSQLiFetchWithHeaderSetsAllHeaders(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo the header under test so the caller can confirm the injection landed.
		w.Write([]byte("XFF=" + r.Header.Get("X-Forwarded-For") +
			"|REF=" + r.Header.Get("Referer") +
			"|UA=" + r.Header.Get("User-Agent") +
			"|CK=" + r.Header.Get("Cookie") +
			"|XC=" + r.Header.Get("X-Custom")))
	}))
	defer srv.Close()
	s := &SQLiScanner{}
	ctx := context.Background()

	if b := s.fetchWithHeader(ctx, srv.URL, "X-Forwarded-For", "INJ123"); !strings.Contains(b, "XFF=127.0.0.1,INJ123") {
		t.Fatalf("X-Forwarded-For injection not sent: %q", b)
	}
	if b := s.fetchWithHeader(ctx, srv.URL, "Referer", "INJ123"); !strings.Contains(b, "REF=https://INJ123/") {
		t.Fatalf("Referer injection not sent: %q", b)
	}
	if b := s.fetchWithHeader(ctx, srv.URL, "X-Custom", "INJ123"); !strings.Contains(b, "XC=INJ123") {
		t.Fatalf("custom header injection not sent: %q", b)
	}
	if b := s.fetchWithHeader(ctx, srv.URL, "Cookie", "INJ123"); !strings.Contains(b, "CK=id=INJ123") {
		t.Fatalf("Cookie injection not sent: %q", b)
	}
}

// hasQuote reports whether the injected id value carries a quote (the error probe).
func hasQuote(v string) bool { return strings.ContainsAny(v, "'\"`") }

// TestHeaderProbeDetectsParenOnlyBoundary proves the fix for a real false
// negative: headerProbe used to send one combined payload ("recon'\"`") and
// never tried a parenthesis-closing boundary at all. A header value injected
// inside a parenthesised predicate (a logging/audit query built as
// WHERE ip=($v)) throws no error on a bare quote/backtick — only on a value
// that actually closes the paren — so the old single-payload probe could
// never detect this class of header SQLi.
func TestHeaderProbeDetectsParenOnlyBoundary(t *testing.T) {
	withLoopbackAllowed(t)
	dbErr := "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom") == "recon)" {
			w.Write([]byte(dbErr))
			return
		}
		w.Write([]byte("stable normal response"))
	}))
	defer srv.Close()
	s := &SQLiScanner{}

	kind, payload, _ := s.headerProbe(context.Background(), srv.URL, "X-Custom", "X-Custom", nil)
	if kind != "error_based" {
		t.Fatalf("expected the paren-only boundary to be detected, got kind=%q", kind)
	}
	if payload != "recon)" {
		t.Fatalf("expected the reproduction payload to be the paren-closing boundary, got %q", payload)
	}
}

// TestHeaderProbeRejects429AsBlockPageNotFinding proves the fix for a real
// false positive: fetchWithHeaderAuth used to discard the HTTP status code
// entirely, so headerProbe's WAF guard (bodyLooksLikeWAFBlock, body-only)
// could never apply the "429 is always a block" rule that every other call
// site in this file uses via looksLikeBlockPage(status, body). A server that
// rate-limits repeated header-fuzzing with a 429 whose body happens to
// contain SQL-error-shaped text (no vendor block-page signature, so the old
// body-only check missed it) must not be reported as confirmed SQLi.
func TestHeaderProbeRejects429AsBlockPageNotFinding(t *testing.T) {
	withLoopbackAllowed(t)
	dbErr := "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hasQuote(r.Header.Get("X-Custom")) || strings.Contains(r.Header.Get("X-Custom"), ")") {
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(dbErr))
			return
		}
		w.Write([]byte("stable normal response"))
	}))
	defer srv.Close()
	s := &SQLiScanner{}

	kind, _, _ := s.headerProbe(context.Background(), srv.URL, "X-Custom", "X-Custom", nil)
	if kind != "" {
		t.Fatalf("a 429 rate-limit response must never be reported as confirmed SQLi, got kind=%q", kind)
	}
}

// TestHeaderChecksDeepLadderReachesXForwardedHostBooleanBlind proves the fix
// for a real false negative: headerChecks used to run the full boolean/time-
// based blind ladder (quickProbe) on the host's representative route for ONLY
// User-Agent and X-Forwarded-For — every other header, including
// X-Forwarded-Host, got only the error-based headerProbe. A boolean-blind
// SQLi that never throws a raw DB error (a classic logging-table vector,
// e.g. WHERE host = '$v' with no error reporting) was therefore a guaranteed
// miss via X-Forwarded-Host on every target. This drives the REAL
// headerChecks end-to-end against a mock app that evaluates the injected
// boolean condition and returns a same-length differential body — detectable
// only by the deep ladder, never by headerProbe's error-signature-only check.
func TestHeaderChecksDeepLadderReachesXForwardedHostBooleanBlind(t *testing.T) {
	withLoopbackAllowed(t)
	full := strings.Repeat("PROFILE-alice-admin;", 30)
	none := strings.Repeat("NOTFOUND-no-record-;", 30)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if sqliOracleTrue(r.Header.Get("X-Forwarded-Host"), "sqli") {
			_, _ = w.Write([]byte(full))
		} else {
			_, _ = w.Write([]byte(none))
		}
	}))
	defer srv.Close()

	db, tid := testDB(t)
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code) VALUES (?,?,?,200)`,
		uuid.New().String(), tid, srv.URL+"/account"); err != nil {
		t.Fatal(err)
	}

	s := &SQLiScanner{db: db, cfg: &config.Config{}}
	var found atomic.Int64
	s.headerChecks(context.Background(), tid, nil, func(_, _, _ string) {}, &found)
	if found.Load() == 0 {
		t.Fatal("expected a boolean-blind X-Forwarded-Host SQLi (never throws a DB error) to be detected via the widened deep ladder")
	}
}

// Error-based must REPRODUCE: a DB error that flashes only once (transient 500)
// must NOT be reported. A consistent DB error MUST be reported.
func TestSQLiErrorBasedRequiresReproduction(t *testing.T) {
	withLoopbackAllowed(t)
	ctx := context.Background()
	dbErr := "<html>You have an error in your SQL syntax; check the manual near '1' at line 1</html>"
	normal := "<html>ok ok ok normal page stable content here</html>"

	// Transient: emit the DB error on the FIRST quote request only.
	var firstQuote int32
	transient := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hasQuote(r.URL.Query().Get("id")) && atomic.AddInt32(&firstQuote, 1) == 1 {
			w.Write([]byte(dbErr))
			return
		}
		w.Write([]byte(normal))
	}))
	defer transient.Close()
	ip := insertionPoint{URL: transient.URL + "/?id=1", Param: "id", Method: "GET"}
	if kind, _, _ := (&SQLiScanner{}).quickProbe(ctx, ip, nil); kind == "error_based" {
		t.Fatal("a one-shot (transient) DB error must NOT be reported as error-based SQLi")
	}

	// Consistent: emit the DB error on EVERY quote request.
	consistent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hasQuote(r.URL.Query().Get("id")) {
			w.Write([]byte(dbErr))
			return
		}
		w.Write([]byte(normal))
	}))
	defer consistent.Close()
	ip2 := insertionPoint{URL: consistent.URL + "/?id=1", Param: "id", Method: "GET"}
	if kind, _, _ := (&SQLiScanner{}).quickProbe(ctx, ip2, nil); kind != "error_based" {
		t.Fatalf("a reproducible DB error must be reported as error-based SQLi, got %q", kind)
	}
}

// A host whose adaptive throttle is already severely ramped (repeated
// 429/503/timeout, observed by ANY module) must have quickProbe's expensive
// ladders (error-forced extraction, boolean pairs, OR-based extraction —
// together dozens of requests per candidate) skipped entirely: continuing to
// grind through them is what turns one struggling host into many extra
// minutes on a large scan, per the sqlSpeed fix. This counts real requests to
// prove it, rather than trusting the code path by inspection.
func TestSQLiSkipsExpensiveLaddersOnSeverelyThrottledHost(t *testing.T) {
	withLoopbackAllowed(t)
	var reqCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqCount, 1)
		w.Write([]byte("<html>ok normal stable page content here</html>"))
	}))
	defer srv.Close()

	ip := insertionPoint{URL: srv.URL + "/?id=1", Param: "id", Method: "GET"}
	host := hostOfURL(ip.URL)
	hostThrottles.Delete(host)

	// Baseline: healthy host runs the full ladder (error-suffix probe +
	// error-forced extraction + boolean pairs + OR-based extraction).
	atomic.StoreInt32(&reqCount, 0)
	(&SQLiScanner{}).quickProbe(context.Background(), ip, nil)
	healthyRequests := atomic.LoadInt32(&reqCount)
	if healthyRequests < 20 {
		t.Fatalf("expected the full ladder to make a substantial number of requests on a healthy host, got %d", healthyRequests)
	}

	// Ramp the host's throttle to its ceiling, as repeated 429/503 would.
	for i := 0; i < 10; i++ {
		hostThrottleObserve(host, 503, false)
	}
	if !hostThrottleSevere(host) {
		t.Fatal("expected the host to be reported severely throttled after ramping")
	}

	atomic.StoreInt32(&reqCount, 0)
	(&SQLiScanner{}).quickProbe(context.Background(), ip, nil)
	severeRequests := atomic.LoadInt32(&reqCount)
	// The cheap stage alone (base + 6 error suffixes) is 7 requests; allow a
	// little headroom without allowing the expensive ladders back in.
	if severeRequests > 10 {
		t.Fatalf("expected a severely throttled host to skip the expensive ladders (few requests), got %d (healthy case was %d)", severeRequests, healthyRequests)
	}
	hostThrottles.Delete(host)
}

func TestSQLiFullEngineInjectsHeaderAndAuthenticatedCookie(t *testing.T) {
	withLoopbackAllowed(t)
	dbErr := "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hasQuote(r.Header.Get("X-Forwarded-For")) || hasQuote(cookieValue(r.Header.Get("Cookie"), "cart")) {
			w.Write([]byte(dbErr))
			return
		}
		w.Write([]byte("stable normal response"))
	}))
	defer srv.Close()
	s := &SQLiScanner{}
	auth := map[string]string{"Cookie": "session=secret; cart=7"}

	headerIP := insertionPoint{URL: srv.URL, Param: "X-Forwarded-For", Value: "127.0.0.1", Method: "GET", Location: "header"}
	if kind, payload, _ := s.quickProbe(context.Background(), headerIP, auth); kind != "error_based" {
		t.Fatalf("full SQLi engine did not reach header sink: %q", kind)
	} else if payload == "" {
		t.Fatal("header SQLi must carry the reproduction payload")
	}
	cookieIP := insertionPoint{URL: srv.URL, Param: "cart", Value: "7", Method: "GET", Location: "cookie"}
	if kind, payload, _ := s.quickProbe(context.Background(), cookieIP, auth); kind != "error_based" {
		t.Fatalf("full SQLi engine did not reach authenticated cookie sink: %q", kind)
	} else if payload == "" {
		t.Fatal("cookie SQLi must carry the reproduction payload")
	}
	req, err := buildInjectedRequest(context.Background(), cookieIP, "7'", auth)
	if err != nil {
		t.Fatal(err)
	}
	if cookieValue(req.Header.Get("Cookie"), "session") != "secret" {
		t.Fatalf("injecting cart cookie dropped auth session: %q", req.Header.Get("Cookie"))
	}
}
