package scanner

// ─────────────────────────────────────────────────────────────────────────────
// In-process vulnerability benchmark lab.
//
// This is a permanent, deterministic regression suite that drives the REAL
// detector cores against a set of LABELLED mock endpoints (httptest, in-process,
// never exposed) and computes a per-detector confusion matrix (TP/FP/FN/TN) plus
// precision/recall. Every case carries a machine-readable ground-truth label
// (`positive`), and the test FAILS on any false positive or false negative — so a
// regression that either invents a finding on a safe endpoint or misses a planted
// vulnerability breaks the build.
//
// Design rules honoured here:
//   - No sleeping mocks: time-based paths are exercised structurally but the
//     servers never sleep, so the suite stays fast and deterministic.
//   - No target-specific logic: cases test detector BEHAVIOUR (error reflected vs
//     WAF block vs transient flash), never a hostname or a canned string that only
//     the benchmark would produce.
//   - The manifest is the ground truth. Detectors are judged against it; the
//     detectors are never tuned to the manifest.
// ─────────────────────────────────────────────────────────────────────────────

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// benchCase is one labelled endpoint/input for one detector.
type benchCase struct {
	detector string // detector family (grouping key for the matrix)
	name     string // human-readable case name
	positive bool   // ground truth: true = a real vulnerability is present
	// run executes the real detector core and reports its verdict:
	// true  = the detector flagged a vulnerability
	// false = the detector reported clean
	run func(t *testing.T) bool
}

// ── Mock apps (deterministic, non-sleeping) ─────────────────────────────────

// sqliErrorApp: a classic error-based injectable param. Any quote in the value
// surfaces a raw MySQL error; a benign value returns a stable page.
func sqliErrorApp() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "text/html")
		if strings.ContainsAny(v, "'\"`") {
			w.Write([]byte("<html>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax near '''</html>"))
			return
		}
		w.Write([]byte("<html>product row 1</html>"))
	}))
}

// sqliPostgresApp: error-based on a Postgres backend (different engine signature)
// to confirm the error catalogue is not MySQL-only.
func sqliPostgresApp() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "text/html")
		if strings.ContainsAny(v, "'\"`") {
			w.Write([]byte("<html>PostgreSQL query failed: ERROR: unterminated quoted string at or near \"'\"</html>"))
			return
		}
		w.Write([]byte("<html>product row 1</html>"))
	}))
}

// sqliReflectOnlyApp: echoes the value but never errors — a reflection sink, not
// a SQL sink. Must NOT be reported as SQLi.
func sqliReflectOnlyApp() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>you searched for: " + html.EscapeString(v) + "</html>"))
	}))
}

// sqliWAFApp: a quote trips a WAF block page that also happens to contain SQL-ish
// text (the classic error-based false positive). base passes the WAF. Must be a TN.
func sqliWAFApp() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "text/html")
		if strings.ContainsAny(v, "'\"`") {
			// Cloudflare block page that mentions "SQL syntax" — a WAF, not a DB error.
			w.Write([]byte("<html>Attention Required! | Cloudflare — cf-ray 1234. Your request was blocked (it looked like SQL syntax check the manual that corresponds to your MySQL server version).</html>"))
			return
		}
		w.Write([]byte("<html>product row 1</html>"))
	}))
}

// sqliTransientApp: the FIRST quote-bearing request flashes a DB error (a flaky
// upstream 500), every later one is clean. The reproduce guard must reject it.
func sqliTransientApp() *httptest.Server {
	var quoteHits int32
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "text/html")
		if strings.ContainsAny(v, "'\"`") {
			if atomic.AddInt32(&quoteHits, 1) == 1 {
				w.Write([]byte("<html>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near '''</html>"))
				return
			}
		}
		w.Write([]byte("<html>product row 1</html>"))
	}))
}

// sqliBooleanApp: a blind boolean-injectable numeric param backed by a GENUINE
// boolean oracle over database()="labdb". A TRUE injected condition returns the
// full record; a FALSE one returns an empty result. No SQL error is ever emitted,
// so only the boolean differential can detect it — and because the oracle really
// evaluates the injected condition, the engine's binary-search extraction reads the
// database name back, which is what promotes it from a bare differential to a proven
// finding (the require-a-name-or-time evidence bar).
func sqliBooleanApp() *httptest.Server {
	full := "<html>" + strings.Repeat("record-data ", 200) + "</html>"
	empty := "<html>no results</html>"
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if sqliOracleTrue(r.URL.Query().Get("id"), "labdb") {
			w.Write([]byte(full))
			return
		}
		w.Write([]byte(empty))
	}))
}

// sqliDynamicApp: a highly volatile page (rotating recommendations) that also
// never errors. Its per-request size swings dwarf any boolean signal, so blind
// length differentials must be suppressed → TN.
func sqliDynamicApp() *httptest.Server {
	var n int32
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		i := atomic.AddInt32(&n, 1)
		pad := 1000 + int((i*7919)%9000)
		w.Write([]byte("<html>" + strings.Repeat("x", pad) + "</html>"))
	}))
}

// runSQLi drives the real quickProbe against one mock and reports detection.
func runSQLi(app func() *httptest.Server, param string) func(*testing.T) bool {
	return func(t *testing.T) bool {
		srv := app()
		defer srv.Close()
		s := &SQLiScanner{}
		ip := insertionPoint{URL: srv.URL + "/?" + param + "=1", Param: param, Method: "GET"}
		kind, _ := s.quickProbe(context.Background(), ip, nil)
		return kind != ""
	}
}

// redirectApp classes: follow behaviour is what checkOpenRedirectURL validates.
func redirectReflectApp() *httptest.Server { // 302 Location = the raw param → open redirect
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.URL.Query().Get("next"); v != "" {
			w.Header().Set("Location", v)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
}

func redirectEncodedApp() *httptest.Server { // filters raw off-site markers, decodes param first
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.ToLower(r.URL.RawQuery)
		if strings.Contains(raw, "//") || strings.Contains(raw, "http") || strings.Contains(raw, `\`) {
			w.WriteHeader(http.StatusOK) // raw off-site markers rejected
			return
		}
		if v := r.URL.Query().Get("next"); v != "" { // decoded once by Go
			w.Header().Set("Location", v)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
}

func redirectMetaApp() *httptest.Server { // client-side redirect via meta refresh (no Location)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("next")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><head><meta http-equiv="refresh" content="0; url=` + v + `"></head></html>`))
	}))
}

func redirectReflectBodyApp() *httptest.Server { // reflects the payload but never redirects
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("next")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>You entered: " + html.EscapeString(v) + " — this is not a link.</body></html>"))
	}))
}

func redirectSameOriginApp() *httptest.Server { // ignores the param, always same-origin
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/dashboard")
		w.WriteHeader(http.StatusFound)
	}))
}

func redirectNoneApp() *httptest.Server { // never redirects
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>ok</html>"))
	}))
}

func runOpenRedirect(app func() *httptest.Server) func(*testing.T) bool {
	return func(t *testing.T) bool {
		srv := app()
		defer srv.Close()
		res, ok := checkOpenRedirectURL(srv.URL+"/go", "next")
		return ok && res.class == redirectExternal
	}
}

// CORS apps.
func corsReflectCredApp() *httptest.Server { // reflects any Origin + credentials → critical
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
	}))
}

func corsStrictApp() *httptest.Server { // fixed allow-list, never reflects
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://trusted.example")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
	}))
}

func runCORS(app func() *httptest.Server) func(*testing.T) bool {
	return func(t *testing.T) bool {
		srv := app()
		defer srv.Close()
		s := &CORSScanner{}
		_, _, _, ok := s.check(context.Background(), srv.URL+"/api/data")
		return ok
	}
}

// sqliAlwaysErrorApp: a page that ALWAYS contains SQL-ish text (a tutorial page,
// an error logged into the template) — the differential must not fire because the
// benign baseline carries the same signature.
func sqliAlwaysErrorApp() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>FAQ: a 'You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version' message means…</html>"))
	}))
}

// XSS apps (reuse reflectApp/jsonReflectApp from xss_context_test.go).
func runXSS(app *httptest.Server, want string) func(*testing.T) bool {
	return func(t *testing.T) bool {
		defer app.Close()
		v := NewXSSContextVerifier(nil)
		r := v.Verify(context.Background(), VulnerabilityCandidate{Type: "xss", URL: app.URL + "/?q=x", Parameter: "q"})
		// The deterministic benchmark measures detection recall. A strong
		// executable-markup observation is a true positive candidate; only the
		// separate Chromium E2E suite is allowed to call it CONFIRMED.
		return r.Verdict == VerifyVerified || (r.Verdict == VerifyInconclusive && r.Confidence >= 85)
	}
}

// corsNullCredApp: Origin: null echoed back with credentials → high (exploitable
// from a sandboxed iframe).
func corsNullCredApp() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == "null" {
			w.Header().Set("Access-Control-Allow-Origin", "null")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
	}))
}

// jwtCritical reports whether analyzeJWT surfaced a forgeable (critical) issue.
func jwtCritical(token string) bool {
	for _, is := range analyzeJWT(token) {
		if is.kind == "alg_none" || is.kind == "weak_secret" {
			return true
		}
	}
	return false
}

// ── The manifest ────────────────────────────────────────────────────────────

func benchmarkCases(t *testing.T) []benchCase {
	// A strong HS256 token: random 32-byte secret, expires within a year, benign
	// claims — nothing forgeable, nothing sensitive.
	strongSecret := "9f3c1a7e5b2d4086af61c0e9d7b83a25f4e6c8091b2d3a4c5e6f70819a2b3c4d"
	strongJWT := mkJWT(t, map[string]any{
		"sub": "user-123",
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	}, strongSecret)
	weakJWT := mkJWT(t, map[string]any{
		"sub": "user-123",
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	}, "secret") // "secret" is in jwtWeakSecrets → forgeable
	// alg=none forged from the strong token (strip signature, set alg none).
	noneJWT := forgeAlgNone(strongJWT)

	// LFI bodies.
	passwdBody := "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
	benignBody := "<html><body>Welcome to the file viewer</body></html>"

	// IDOR object bodies. Same object served to two identities = broken access.
	objectA := `{"id":42,"owner":"alice","balance":1000,"card":"4111111111111111"}`
	// Two DIFFERENT users' objects rendered through the SAME template — different
	// data, so NOT the same object (must not be an IDOR).
	tmplUserA := `{"id":42,"owner":"alice","email":"alice@example.com","role":"user","joined":"2021-01-01"}`
	tmplUserB := `{"id":43,"owner":"bob","email":"bob@example.com","role":"user","joined":"2021-06-15"}`

	// soft404 baselines for content discovery.
	catchAll := soft404{active: true, statusCode: 200, bodyLen: 512, noise: 8, contentType: "text/html", title: "Not Found"}
	realZip := []byte(strings.Repeat("PK\x03\x04binarychunk", 60)) // ~780B application/zip

	cases := []benchCase{
		// ── SQL injection ────────────────────────────────────────────────────
		{"sqli", "error-based injectable (reproduced)", true, runSQLi(sqliErrorApp, "id")},
		{"sqli", "error-based Postgres engine", true, runSQLi(sqliPostgresApp, "id")},
		{"sqli", "blind boolean injectable", true, runSQLi(sqliBooleanApp, "id")},
		{"sqli", "reflection sink, no SQL error", false, runSQLi(sqliReflectOnlyApp, "id")},
		{"sqli", "WAF block page carrying SQL text", false, runSQLi(sqliWAFApp, "id")},
		{"sqli", "transient one-shot DB error", false, runSQLi(sqliTransientApp, "id")},
		{"sqli", "highly dynamic page (size noise)", false, runSQLi(sqliDynamicApp, "id")},
		{"sqli", "SQL text present in baseline too", false, runSQLi(sqliAlwaysErrorApp, "id")},

		// ── Reflected XSS (context-aware verification) ───────────────────────
		{"xss", "raw reflection in HTML text", true,
			runXSS(reflectApp(false, func(s string) string { return "<div>" + s + "</div>" }), "html_text")},
		{"xss", "raw reflection in JS string", true,
			runXSS(reflectApp(false, func(s string) string { return "<script>var x='" + s + "';</script>" }), "js_string")},
		{"xss", "HTML-encoded reflection", false,
			runXSS(reflectApp(true, func(s string) string { return "<div>" + s + "</div>" }), "")},
		{"xss", "JSON body + nosniff (ably.com FP)", false,
			runXSS(jsonReflectApp("application/json; charset=utf-8", true), "")},

		// ── Open redirect ────────────────────────────────────────────────────
		{"open_redirect", "direct Location reflection", true, runOpenRedirect(redirectReflectApp)},
		{"open_redirect", "encoded-separator bypass delivered", true, runOpenRedirect(redirectEncodedApp)},
		{"open_redirect", "client-side meta-refresh redirect", true, runOpenRedirect(redirectMetaApp)},
		{"open_redirect", "fixed same-origin redirect", false, runOpenRedirect(redirectSameOriginApp)},
		{"open_redirect", "payload reflected in body, no redirect", false, runOpenRedirect(redirectReflectBodyApp)},
		{"open_redirect", "no redirect at all", false, runOpenRedirect(redirectNoneApp)},

		// ── CORS ─────────────────────────────────────────────────────────────
		{"cors", "reflected origin + credentials", true, runCORS(corsReflectCredApp)},
		{"cors", "null origin + credentials", true, runCORS(corsNullCredApp)},
		{"cors", "strict fixed allow-list", false, runCORS(corsStrictApp)},

		// ── JWT (offline) ────────────────────────────────────────────────────
		{"jwt", "weak/known HMAC secret", true, func(t *testing.T) bool { return jwtCritical(weakJWT) }},
		{"jwt", "alg=none unsigned token", true, func(t *testing.T) bool { return jwtCritical(noneJWT) }},
		{"jwt", "strong secret, benign claims", false, func(t *testing.T) bool { return jwtCritical(strongJWT) }},

		// ── LFI (confirmation) ───────────────────────────────────────────────
		{"lfi", "/etc/passwd disclosed", true, func(t *testing.T) bool {
			return confirmLFI("../../../../etc/passwd", passwdBody) != ""
		}},
		{"lfi", "php://filter base64 source disclosure", true, func(t *testing.T) bool {
			// The wrapper returns the target file's PHP source as base64; confirmLFI
			// must decode it and recognise the <?php marker.
			b64 := "PD9waHAgJGRiID0gInNlY3JldCI7IGluY2x1ZGUoJF9HRVRbImZpbGUiXSk7ID8+"
			return confirmLFI("php://filter/convert.base64-encode/resource=index.php", "<html>"+b64+"</html>") != ""
		}},
		{"lfi", "benign page, no file read", false, func(t *testing.T) bool {
			return confirmLFI("../../../../etc/passwd", benignBody) != ""
		}},

		// ── IDOR / BOLA (object comparison) ──────────────────────────────────
		{"idor", "same object served to both identities", true, func(t *testing.T) bool {
			return bodiesSameObject(objectA, objectA)
		}},
		{"idor", "same object, volatile fields differ", true, func(t *testing.T) bool {
			// Identical object, but each response carries a fresh CSRF token and a
			// server timestamp. blurVolatile must normalise these so the two are still
			// recognised as the SAME object (a missed-IDOR guard).
			a := `{"id":42,"owner":"alice","balance":1000,"csrf":"a1b2c3d4e5f6a1b2","ts":1712000000}`
			b := `{"id":42,"owner":"alice","balance":1000,"csrf":"f6e5d4c3b2a1f6e5","ts":1712003600}`
			return bodiesSameObject(a, b)
		}},
		{"idor", "same template, different user data", false, func(t *testing.T) bool {
			return bodiesSameObject(tmplUserA, tmplUserB)
		}},

		// ── Content discovery (soft-404 gate) ────────────────────────────────
		{"dir_discovery", "real file kept (different CT)", true, func(t *testing.T) bool {
			return !catchAll.matches(200, realZip, "application/zip")
		}},
		{"dir_discovery", "catch-all shell discarded (same title)", false, func(t *testing.T) bool {
			body := []byte("<html><head><title>Not Found</title></head><body>whatever length here</body></html>")
			return !catchAll.matches(200, body, "text/html")
		}},

		// ── Subdomain takeover (confidence gate) ─────────────────────────────
		{"takeover", "fingerprint + dangling DNS", true, func(t *testing.T) bool {
			return takeoverConfidence(true, true, false) > 0
		}},
		{"takeover", "live ALB, no fingerprint", false, func(t *testing.T) bool {
			// Live load balancer: no takeover fingerprint, DNS resolves.
			return takeoverConfidence(false, false, false) > 0 || !awsNonTakeoverableInfra("app-1234.us-east-1.elb.amazonaws.com")
		}},
	}
	return cases
}

// ── The benchmark runner ────────────────────────────────────────────────────

type detStat struct{ tp, fp, fn, tn int }

func TestBenchmarkLab(t *testing.T) {
	withLoopbackAllowed(t)

	cases := benchmarkCases(t)
	stats := map[string]*detStat{}
	order := []string{}
	var failures []string

	for _, c := range cases {
		if _, ok := stats[c.detector]; !ok {
			stats[c.detector] = &detStat{}
			order = append(order, c.detector)
		}
		got := c.run(t)
		st := stats[c.detector]
		switch {
		case c.positive && got:
			st.tp++
		case c.positive && !got:
			st.fn++
			failures = append(failures, fmt.Sprintf("FALSE NEGATIVE  [%s] %s — planted vulnerability was MISSED", c.detector, c.name))
		case !c.positive && got:
			st.fp++
			failures = append(failures, fmt.Sprintf("FALSE POSITIVE  [%s] %s — safe endpoint was FLAGGED", c.detector, c.name))
		default:
			st.tn++
		}
	}

	// Machine-readable matrix.
	sort.Strings(order)
	var totTP, totFP, totFN, totTN int
	t.Logf("\n=== VULNERABILITY BENCHMARK LAB — %d cases across %d detectors ===", len(cases), len(order))
	t.Logf("%-15s %4s %4s %4s %4s  %-9s %-9s", "detector", "TP", "FP", "FN", "TN", "precision", "recall")
	t.Logf("%s", strings.Repeat("-", 62))
	for _, d := range order {
		s := stats[d]
		totTP, totFP, totFN, totTN = totTP+s.tp, totFP+s.fp, totFN+s.fn, totTN+s.tn
		t.Logf("%-15s %4d %4d %4d %4d  %-9s %-9s", d, s.tp, s.fp, s.fn, s.tn, ratio(s.tp, s.tp+s.fp), ratio(s.tp, s.tp+s.fn))
	}
	t.Logf("%s", strings.Repeat("-", 62))
	t.Logf("%-15s %4d %4d %4d %4d  %-9s %-9s", "TOTAL", totTP, totFP, totFN, totTN, ratio(totTP, totTP+totFP), ratio(totTP, totTP+totFN))

	if len(failures) > 0 {
		t.Errorf("benchmark found %d misclassification(s):\n  %s", len(failures), strings.Join(failures, "\n  "))
	}
}

// ratio formats a precision/recall value, guarding the zero-denominator case.
func ratio(num, den int) string {
	if den == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.3f", float64(num)/float64(den))
}
