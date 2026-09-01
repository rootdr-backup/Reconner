package scanner

// ─────────────────────────────────────────────────────────────────────────────
// LEVEL B — END-TO-END SCANNER BENCHMARK (authoritative detection metric)
//
// Unlike benchmark_lab_test.go (LEVEL A, which calls detector cores directly),
// this harness drives Reconner's REAL per-module pipeline:
//
//     seed parameters/services (post-discovery state)
//        → real New*Scanner(...) construction (exactly as the scheduler builds them)
//        → scanner.Run(ctx, targetID, logFn)
//        → real request construction + HTTP engine + detector + confirmation/reproduction
//        → real finding storage (vuln_findings / open_redirect_findings) + dedup (UNIQUE)
//        → read findings back and score against a machine-readable manifest.
//
// The lab services are realistic (routing, multiple content types, dynamic
// bodies, WAF-like blocks, template rendering, redirects) and every case carries
// explicit ground truth. The harness measures, per detector:
//   TP / FP / FN / TN · precision · recall
//   + incorrect severity · missing/invalid evidence · wrong parameter attribution
//   + duplicate findings · request-construction failures (byte-exact payload delivery)
//
// It fails the build on any FP, FN, wrong severity, wrong param, missing
// evidence, duplicate, or request-construction failure — so a detector regression
// in any of those dimensions breaks CI, not just a raw miss.
//
// Detectors whose confirmation is inherently out-of-band or time-based (SSRF/OAST,
// blind XXE, blind-XSS callback, time-based CMDi/SQLi) are intentionally NOT driven
// here — they need real external infrastructure or wall-clock sleeps and cannot be
// made deterministic in-process. Their pure cores are covered at LEVEL A. This is
// stated honestly rather than faked with a sleeping mock.
// ─────────────────────────────────────────────────────────────────────────────

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

// e2eCase is one labelled endpoint driven through a real detector Run().
type e2eCase struct {
	id       string
	detector string // sqli | lfi | ssti | xss | nosqli | open_redirect
	level    int    // difficulty 0..6
	variant  string
	param    string
	value    string
	method   string // "" → GET
	ctype    string // POST content-type

	handler http.HandlerFunc

	// ground truth
	vulnerable bool
	wantType   string // expected vuln_findings.type (empty for open_redirect table)
	wantSev    string // expected severity (checked only for TPs)

	// request-construction assertion: after the run, the server must have received
	// at least one request whose RAW query contained this literal (byte-exact
	// delivery). Used for encoded-payload variants (e.g. "%2f%2f").
	rawMustContain string
}

// e2eRecorder captures the raw query bytes each case's endpoint actually received,
// so we can prove payloads reached the server byte-for-byte (no double-encoding).
type e2eRecorder struct {
	mu   sync.Mutex
	seen map[string][]string
}

func newE2ERecorder() *e2eRecorder { return &e2eRecorder{seen: map[string][]string{}} }
func (r *e2eRecorder) record(id, raw string) {
	r.mu.Lock()
	r.seen[id] = append(r.seen[id], raw)
	r.mu.Unlock()
}
func (r *e2eRecorder) sawContains(id, sub string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, q := range r.seen[id] {
		if strings.Contains(q, sub) {
			return true
		}
	}
	return false
}
func (r *e2eRecorder) sawAny(id, sub string) bool { // any raw query with substring
	return r.sawContains(id, sub)
}

// ── Lab handler factories (realistic, deterministic, non-sleeping) ──────────

// SQLi handlers ---------------------------------------------------------------
func sqliMySQLErr(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get(param)
		w.Header().Set("Content-Type", "text/html")
		if strings.ContainsAny(v, "'\"`") {
			_, _ = w.Write([]byte("<html>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax near '''</html>"))
			return
		}
		_, _ = w.Write([]byte("<html>product row 1</html>"))
	}
}
func sqliPgErr(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get(param)
		w.Header().Set("Content-Type", "text/html")
		if strings.ContainsAny(v, "'\"`") {
			_, _ = w.Write([]byte("<html>PostgreSQL query failed: ERROR: unterminated quoted string at or near \"'\"</html>"))
			return
		}
		_, _ = w.Write([]byte("<html>product row 1</html>"))
	}
}
func sqliBoolean(param string) http.HandlerFunc {
	full := "<html>" + strings.Repeat("record-data ", 200) + "</html>"
	empty := "<html>no results</html>"
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// A genuine boolean oracle over database()="labdb" so the engine can both
		// detect the differential AND extract the DB name (the require-proof bar).
		if sqliOracleTrue(r.URL.Query().Get(param), "labdb") {
			_, _ = w.Write([]byte(full))
			return
		}
		_, _ = w.Write([]byte(empty))
	}
}
func sqliReflect(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>you searched for: " + html.EscapeString(r.URL.Query().Get(param)) + "</html>"))
	}
}
func sqliWAF(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get(param)
		w.Header().Set("Content-Type", "text/html")
		if strings.ContainsAny(v, "'\"`") {
			_, _ = w.Write([]byte("<html>Attention Required! | Cloudflare — cf-ray 42. Your request was blocked (it looked like SQL syntax check the manual that corresponds to your MySQL server version).</html>"))
			return
		}
		_, _ = w.Write([]byte("<html>product row 1</html>"))
	}
}
func sqliTransient(param string) http.HandlerFunc {
	var quoteHits int32
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get(param)
		w.Header().Set("Content-Type", "text/html")
		if strings.ContainsAny(v, "'\"`") && atomic.AddInt32(&quoteHits, 1) == 1 {
			_, _ = w.Write([]byte("<html>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near '''</html>"))
			return
		}
		_, _ = w.Write([]byte("<html>product row 1</html>"))
	}
}
func sqliGeneric500(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get(param)
		if strings.ContainsAny(v, "'\"`") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("<html>500 Internal Server Error — request id 8842</html>"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>product row 1</html>"))
	}
}
func sqliDynamic(param string) http.HandlerFunc {
	var n int32
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		i := atomic.AddInt32(&n, 1)
		pad := 1000 + int((i*7919)%9000)
		_, _ = w.Write([]byte("<html>" + strings.Repeat("x", pad) + "</html>"))
	}
}

// mysqlErrOnQuote is the shared MySQL-error body used across SQLi variants.
const mysqlErrBody = "<html>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax near '''</html>"
const okRowBody = "<html>product row 1</html>"

// sqliFormBody: error-based SQLi where the parameter arrives in an
// x-www-form-urlencoded POST body (exercises the POST-form request-construction path).
func sqliFormBody(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		v := r.PostFormValue(param)
		w.Header().Set("Content-Type", "text/html")
		if strings.ContainsAny(v, "'\"`") {
			_, _ = w.Write([]byte(mysqlErrBody))
			return
		}
		_, _ = w.Write([]byte(okRowBody))
	}
}

// sqliJSONBody: error-based SQLi where the parameter arrives inside a JSON POST
// body (exercises the JSON request-construction path — json.Marshal encoding).
func sqliJSONBody(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		v := fmt.Sprintf("%v", m[param])
		w.Header().Set("Content-Type", "text/html")
		if strings.ContainsAny(v, "'\"`") {
			_, _ = w.Write([]byte(mysqlErrBody))
			return
		}
		_, _ = w.Write([]byte(okRowBody))
	}
}

// LFI handlers ----------------------------------------------------------------
func lfiPasswd(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get(param)
		w.Header().Set("Content-Type", "text/plain")
		if strings.Contains(v, "etc/passwd") {
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"))
			return
		}
		_, _ = w.Write([]byte("Welcome, choose a document."))
	}
}
func lfiPHPFilter(param string) http.HandlerFunc {
	// base64 of "<?php $db='secret'; include($_GET['f']); ?>"
	const src = "PD9waHAgJGRiPSdzZWNyZXQnOyBpbmNsdWRlKCRfR0VUWydmJ10pOyA/Pg=="
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get(param)
		w.Header().Set("Content-Type", "text/plain")
		if strings.Contains(v, "convert.base64-encode") {
			_, _ = w.Write([]byte(src))
			return
		}
		if strings.Contains(v, "etc/passwd") {
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
			return
		}
		_, _ = w.Write([]byte("document body"))
	}
}

// lfiEncoded models a filter that blocks a LITERAL "../" traversal but is bypassed
// by percent-encoded separators (..%2f..). Only fires when the encoded payload
// reaches the server byte-exact (%2f intact, not double-encoded to %252f).
func lfiEncoded(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.RawQuery
		w.Header().Set("Content-Type", "text/plain")
		if strings.Contains(raw, "../") { // literal traversal blocked by the "WAF"
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("blocked: path traversal"))
			return
		}
		v := r.URL.Query().Get(param) // %2f decoded to "/" by Go
		if strings.Contains(v, "etc/passwd") {
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
			return
		}
		_, _ = w.Write([]byte("document body"))
	}
}

func lfiSafe(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>viewing: " + html.EscapeString(r.URL.Query().Get(param)) + "</html>"))
	}
}
func lfiNotFound(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("file not found"))
	}
}

// SSTI handlers ---------------------------------------------------------------
var sstiEval = strings.NewReplacer(
	"{{7*7}}", "49", "${7*7}", "49", "#{7*7}", "49", "<%=7*7%>", "49",
	"{7*7}", "49", "${{7*7}}", "49", "@(7*7)", "49", "{{7*'7'}}", "7777777",
	"{{8*8}}", "64", "${8*8}", "64", "#{8*8}", "64", "<%=8*8%>", "64",
	"{8*8}", "64", "${{8*8}}", "64", "@(8*8)", "64", "{{8*'8'}}", "88888888",
)

func sstiVulnerable(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<h1>Hello " + sstiEval.Replace(r.URL.Query().Get(param)) + "</h1>"))
	}
}
func sstiLiteral(param string) http.HandlerFunc { // reflects the template unevaluated
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<h1>Hello " + html.EscapeString(r.URL.Query().Get(param)) + "</h1>"))
	}
}
func sstiStatic49(param string) http.HandlerFunc { // "49" present but NOT the evaluated marker
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<h1>Score: 49 for " + html.EscapeString(r.URL.Query().Get(param)) + "</h1>"))
	}
}

// XSS (DAST) handlers ---------------------------------------------------------
func xssRawHTML(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<div>results for " + r.URL.Query().Get(param) + "</div>"))
	}
}

// xssQuotedAttr reflects into a double-quoted HTML attribute value — an
// executable context only when the quote survives raw (breakout to a new element).
func xssQuotedAttr(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<input type="text" value="` + r.URL.Query().Get(param) + `"><button>go</button>`))
	}
}

// xssSingleQuotedAttr reflects raw into a SINGLE-quoted attribute — breakout needs
// the single quote (the old fixed-'"' check missed this whole class).
func xssSingleQuotedAttr(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<input type='text' value='` + r.URL.Query().Get(param) + `'><button>go</button>`))
	}
}

// xssCSSBlock reflects raw inside a <style> block — breakout via </style>.
func xssCSSBlock(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><style>.theme{color:` + r.URL.Query().Get(param) + `;}</style></head><body>x</body></html>`))
	}
}

func xssEncoded(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<div>results for " + html.EscapeString(r.URL.Query().Get(param)) + "</div>"))
	}
}
func xssJSON(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"q":"` + r.URL.Query().Get(param) + `"}`))
	}
}
func xssTextPlain(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("echo: " + r.URL.Query().Get(param)))
	}
}

// NoSQLi handlers -------------------------------------------------------------
func nosqlErr(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get(param)
		w.Header().Set("Content-Type", "application/json")
		if strings.ContainsAny(v, "{$;\"'`") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"MongoError: unterminated object near '{'"}`))
			return
		}
		_, _ = w.Write([]byte(`{"user":"alice"}`))
	}
}
func nosqlSafe(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"q":"` + html.EscapeString(r.URL.Query().Get(param)) + `","user":"alice"}`))
	}
}

// Open-redirect handlers ------------------------------------------------------
func orDirect(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if v := r.URL.Query().Get(param); v != "" {
			w.Header().Set("Location", v)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}
func orEncoded(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := strings.ToLower(r.URL.RawQuery)
		if strings.Contains(raw, "//") || strings.Contains(raw, "http") || strings.Contains(raw, `\`) {
			w.WriteHeader(http.StatusOK) // raw off-site markers rejected
			return
		}
		if v := r.URL.Query().Get(param); v != "" {
			w.Header().Set("Location", v)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}
func orMeta(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><meta http-equiv="refresh" content="0; url=` + r.URL.Query().Get(param) + `"></head></html>`))
	}
}
func orSameOrigin(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/dashboard")
		w.WriteHeader(http.StatusFound)
	}
}
func orReflectBody(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>You entered: " + html.EscapeString(r.URL.Query().Get(param)) + "</html>"))
	}
}

// ── Manifest ────────────────────────────────────────────────────────────────

func e2eManifest() []e2eCase {
	return []e2eCase{
		// SQLi (type=sqli, sev=high) ------------------------------------------
		{id: "sqli-mysql", detector: "sqli", level: 0, variant: "mysql-error", param: "id", value: "1", handler: sqliMySQLErr("id"), vulnerable: true, wantType: "sqli", wantSev: "high"},
		{id: "sqli-pg", detector: "sqli", level: 1, variant: "postgres-error", param: "id", value: "1", handler: sqliPgErr("id"), vulnerable: true, wantType: "sqli", wantSev: "high"},
		{id: "sqli-bool", detector: "sqli", level: 2, variant: "blind-boolean", param: "id", value: "1", handler: sqliBoolean("id"), vulnerable: true, wantType: "sqli", wantSev: "high"},
		{id: "sqli-reflect", detector: "sqli", level: 5, variant: "reflection-only", param: "id", value: "1", handler: sqliReflect("id"), vulnerable: false},
		{id: "sqli-waf", detector: "sqli", level: 4, variant: "waf-block-sqltext", param: "id", value: "1", handler: sqliWAF("id"), vulnerable: false},
		{id: "sqli-transient", detector: "sqli", level: 3, variant: "transient-500", param: "id", value: "1", handler: sqliTransient("id"), vulnerable: false},
		{id: "sqli-generic500", detector: "sqli", level: 5, variant: "generic-500-no-sql", param: "id", value: "1", handler: sqliGeneric500("id"), vulnerable: false},
		{id: "sqli-dynamic", detector: "sqli", level: 3, variant: "dynamic-noise", param: "id", value: "1", handler: sqliDynamic("id"), vulnerable: false},
		{id: "sqli-formbody", detector: "sqli", level: 6, variant: "post-form-body", param: "id", value: "1", method: "POST", ctype: "application/x-www-form-urlencoded", handler: sqliFormBody("id"), vulnerable: true, wantType: "sqli", wantSev: "high"},
		{id: "sqli-jsonbody", detector: "sqli", level: 6, variant: "post-json-body", param: "id", value: "1", method: "POST", ctype: "application/json", handler: sqliJSONBody("id"), vulnerable: true, wantType: "sqli", wantSev: "high"},

		// LFI (type=lfi, sev=critical) ----------------------------------------
		{id: "lfi-passwd", detector: "lfi", level: 0, variant: "etc-passwd", param: "file", value: "readme", handler: lfiPasswd("file"), vulnerable: true, wantType: "lfi", wantSev: "critical"},
		{id: "lfi-phpfilter", detector: "lfi", level: 2, variant: "php-filter-b64", param: "file", value: "readme", handler: lfiPHPFilter("file"), vulnerable: true, wantType: "lfi", wantSev: "critical"},
		{id: "lfi-encoded", detector: "lfi", level: 4, variant: "encoded-traversal-bypass", param: "file", value: "readme", handler: lfiEncoded("file"), vulnerable: true, wantType: "lfi", wantSev: "critical", rawMustContain: "%2f"},
		{id: "lfi-reflect", detector: "lfi", level: 5, variant: "reflection-only", param: "file", value: "readme", handler: lfiSafe("file"), vulnerable: false},
		{id: "lfi-notfound", detector: "lfi", level: 5, variant: "not-found", param: "file", value: "readme", handler: lfiNotFound("file"), vulnerable: false},

		// SSTI (type=ssti, sev=critical) --------------------------------------
		{id: "ssti-eval", detector: "ssti", level: 0, variant: "jinja-eval", param: "q", value: "x", handler: sstiVulnerable("q"), vulnerable: true, wantType: "ssti", wantSev: "critical"},
		{id: "ssti-literal", detector: "ssti", level: 5, variant: "reflect-literal", param: "q", value: "x", handler: sstiLiteral("q"), vulnerable: false},
		{id: "ssti-static49", detector: "ssti", level: 5, variant: "static-49-fp-trap", param: "q", value: "x", handler: sstiStatic49("q"), vulnerable: false},

		// XSS via DAST (type=xss, sev=high) -----------------------------------
		{id: "xss-html", detector: "xss", level: 0, variant: "raw-html", param: "q", value: "x", handler: xssRawHTML("q"), vulnerable: true, wantType: "xss", wantSev: "high"},
		{id: "xss-dqattr", detector: "xss", level: 2, variant: "quoted-attribute-breakout", param: "q", value: "x", handler: xssQuotedAttr("q"), vulnerable: true, wantType: "xss", wantSev: "high"},
		{id: "xss-sqattr", detector: "xss", level: 2, variant: "single-quoted-attribute-breakout", param: "q", value: "x", handler: xssSingleQuotedAttr("q"), vulnerable: true, wantType: "xss", wantSev: "high"},
		{id: "xss-css", detector: "xss", level: 3, variant: "style-block-breakout", param: "q", value: "x", handler: xssCSSBlock("q"), vulnerable: true, wantType: "xss", wantSev: "high"},
		{id: "xss-encoded", detector: "xss", level: 1, variant: "html-encoded", param: "q", value: "x", handler: xssEncoded("q"), vulnerable: false},
		{id: "xss-json", detector: "xss", level: 4, variant: "json-reflection", param: "q", value: "x", handler: xssJSON("q"), vulnerable: false},
		{id: "xss-text", detector: "xss", level: 4, variant: "text-plain", param: "q", value: "x", handler: xssTextPlain("q"), vulnerable: false},

		// NoSQLi (type=nosql_injection, sev=critical) -------------------------
		{id: "nosql-err", detector: "nosqli", level: 0, variant: "mongo-error", param: "user", value: "1", handler: nosqlErr("user"), vulnerable: true, wantType: "nosql_injection", wantSev: "critical"},
		{id: "nosql-safe", detector: "nosqli", level: 5, variant: "reflection-only", param: "user", value: "1", handler: nosqlSafe("user"), vulnerable: false},

		// Open redirect (open_redirect_findings.verified) ---------------------
		{id: "or-direct", detector: "open_redirect", level: 0, variant: "location-reflect", param: "next", value: "/home", handler: orDirect("next"), vulnerable: true},
		{id: "or-encoded", detector: "open_redirect", level: 1, variant: "encoded-bypass", param: "next", value: "/home", handler: orEncoded("next"), vulnerable: true, rawMustContain: "%2f"},
		{id: "or-meta", detector: "open_redirect", level: 4, variant: "meta-refresh", param: "next", value: "/home", handler: orMeta("next"), vulnerable: true},
		{id: "or-sameorigin", detector: "open_redirect", level: 5, variant: "fixed-same-origin", param: "next", value: "/home", handler: orSameOrigin("next"), vulnerable: false},
		{id: "or-reflectbody", detector: "open_redirect", level: 5, variant: "reflect-no-redirect", param: "next", value: "/home", handler: orReflectBody("next"), vulnerable: false},
	}
}

// ── Harness ─────────────────────────────────────────────────────────────────

type e2eStat struct{ tp, fp, fn, tn, wrongSev, noEvidence, wrongParam, dup, rcFail int }

func TestBenchmarkE2E(t *testing.T) {
	withLoopbackAllowed(t)
	// Mirror production defaults that gate detector behaviour. defaultConfig()
	// ships EnableDAST=true; an empty Config would silently disable the whole DAST
	// module (its Run() early-returns when EnableDAST is false), so the harness
	// must set it to represent the real running configuration.
	cfg := &config.Config{}
	cfg.EnableDAST = true
	log := logger.New("error")
	exec := tools.NewExecutor(cfg, log)
	nolog := func(_, _, _ string) {}

	all := e2eManifest()
	byDet := map[string][]e2eCase{}
	order := []string{}
	for _, c := range all {
		if _, ok := byDet[c.detector]; !ok {
			order = append(order, c.detector)
		}
		byDet[c.detector] = append(byDet[c.detector], c)
	}
	sort.Strings(order)

	stats := map[string]*e2eStat{}
	var failures []string

	for _, det := range order {
		cases := byDet[det]
		rec := newE2ERecorder()

		// One lab server per detector; each case mounted at /c/<id>.
		mux := http.NewServeMux()
		for _, c := range cases {
			id, h := c.id, c.handler
			mux.HandleFunc("/c/"+c.id, func(w http.ResponseWriter, r *http.Request) {
				rec.record(id, r.URL.RawQuery)
				h(w, r)
			})
		}
		srv := httptest.NewServer(mux)

		// Fresh DB seeded with this detector's cases as discovered parameters.
		db, _ := database.New(t.TempDir() + "/e2e.db")
		_ = database.RunMigrations(db)
		tid := uuid.New().String()
		_, _ = db.Exec(`INSERT INTO targets (id, domain, priority) VALUES (?,?, 'medium')`, tid, "lab.local")
		for _, c := range cases {
			method := c.method
			if method == "" {
				method = "GET"
			}
			// GET: the parameter lives in the query string. POST: the parameter is
			// carried in the body, so the seeded URL is just the path (the injection
			// helpers build the body themselves from parameters.value).
			u := srv.URL + "/c/" + c.id
			if method == "GET" {
				u += "?" + c.param + "=" + c.value
			}
			_, _ = db.Exec(`INSERT INTO parameters (id, target_id, url, parameter, value, method, content_type, source) VALUES (?,?,?,?,?,?,?, 'seed')`,
				uuid.New().String(), tid, u, c.param, c.value, method, c.ctype)
		}

		// Drive the REAL detector pipeline.
		runDetector(t, det, db, exec, cfg, log, tid, nolog)

		// Score against ground truth.
		st := &e2eStat{}
		stats[det] = st
		for _, c := range cases {
			ftype, fsev, fparam, fevid, fcount := lookupFinding(db, tid, det, c.id)
			detected := fcount > 0
			if fcount > 1 {
				st.dup++
				failures = append(failures, fmt.Sprintf("DUPLICATE [%s] %s — %d findings for one case", det, c.id, fcount))
			}
			switch {
			case c.vulnerable && detected:
				st.tp++
				// Evidence integrity.
				if strings.TrimSpace(fevid) == "" {
					st.noEvidence++
					failures = append(failures, fmt.Sprintf("NO-EVIDENCE [%s] %s — finding stored without evidence", det, c.id))
				}
				// Severity correctness (skip open_redirect: separate table).
				if c.wantSev != "" && !strings.EqualFold(fsev, c.wantSev) {
					st.wrongSev++
					failures = append(failures, fmt.Sprintf("WRONG-SEVERITY [%s] %s — got %q want %q", det, c.id, fsev, c.wantSev))
				}
				if c.wantType != "" && ftype != "" && !strings.EqualFold(ftype, c.wantType) {
					failures = append(failures, fmt.Sprintf("WRONG-TYPE [%s] %s — got %q want %q", det, c.id, ftype, c.wantType))
				}
				// Parameter attribution.
				if fparam != "" && fparam != c.param {
					st.wrongParam++
					failures = append(failures, fmt.Sprintf("WRONG-PARAM [%s] %s — got %q want %q", det, c.id, fparam, c.param))
				}
				// Request-construction: the byte-exact payload must have reached the server.
				if c.rawMustContain != "" && !rec.sawAny(c.id, c.rawMustContain) {
					st.rcFail++
					failures = append(failures, fmt.Sprintf("REQUEST-CONSTRUCTION-FAILURE [%s] %s — server never received literal %q (double-encoded?)", det, c.id, c.rawMustContain))
				}
			case c.vulnerable && !detected:
				st.fn++
				failures = append(failures, fmt.Sprintf("FALSE NEGATIVE [%s] %s (L%d/%s) — planted vuln MISSED", det, c.id, c.level, c.variant))
			case !c.vulnerable && detected:
				st.fp++
				failures = append(failures, fmt.Sprintf("FALSE POSITIVE [%s] %s (L%d/%s) — safe endpoint FLAGGED (evidence: %.80q)", det, c.id, c.level, c.variant, fevid))
			default:
				st.tn++
			}
		}

		db.Close()
		srv.Close()
	}

	// Report.
	var tTP, tFP, tFN, tTN int
	t.Logf("\n=== LEVEL B — END-TO-END SCANNER BENCHMARK (%d cases, %d detectors) ===", len(all), len(order))
	t.Logf("%-15s %3s %3s %3s %3s  %-9s %-9s  %s", "detector", "TP", "FP", "FN", "TN", "precision", "recall", "quality-issues")
	t.Logf("%s", strings.Repeat("-", 88))
	for _, det := range order {
		s := stats[det]
		tTP, tFP, tFN, tTN = tTP+s.tp, tFP+s.fp, tFN+s.fn, tTN+s.tn
		issues := fmt.Sprintf("sev:%d evid:%d param:%d dup:%d reqc:%d", s.wrongSev, s.noEvidence, s.wrongParam, s.dup, s.rcFail)
		t.Logf("%-15s %3d %3d %3d %3d  %-9s %-9s  %s", det, s.tp, s.fp, s.fn, s.tn, ratioE2E(s.tp, s.tp+s.fp), ratioE2E(s.tp, s.tp+s.fn), issues)
	}
	t.Logf("%s", strings.Repeat("-", 88))
	t.Logf("%-15s %3d %3d %3d %3d  %-9s %-9s", "TOTAL", tTP, tFP, tFN, tTN, ratioE2E(tTP, tTP+tFP), ratioE2E(tTP, tTP+tFN))

	if len(failures) > 0 {
		t.Errorf("end-to-end benchmark found %d issue(s):\n  %s", len(failures), strings.Join(failures, "\n  "))
	}
}

// runDetector constructs the REAL scanner (as the scheduler does) and runs it.
func runDetector(t *testing.T, det string, db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, tid string, logFn LogFunc) {
	ctx := context.Background()
	switch det {
	case "sqli":
		_ = NewSQLiScanner(db, exec, cfg, log, nil).Run(ctx, tid, logFn)
	case "lfi":
		_ = NewLFIScanner(db, exec, cfg, log, nil).Run(ctx, tid, logFn)
	case "ssti":
		_ = NewSSTIScanner(db, exec, cfg, log, nil).Run(ctx, tid, logFn)
	case "xss":
		_ = NewDASTScanner(db, cfg, log, nil).Run(ctx, tid, logFn)
	case "nosqli":
		_ = NewNoSQLiScanner(db, exec, cfg, log, nil).Run(ctx, tid, logFn)
	case "open_redirect":
		_ = NewDirScanner(db, exec, cfg, log).RunOpenRedirectDiscovery(ctx, tid, logFn)
	default:
		t.Fatalf("unknown detector %q", det)
	}
}

// lookupFinding returns (type, severity, parameter, evidence, count) for a case.
func lookupFinding(db *database.DB, tid, det, caseID string) (ftype, fsev, fparam, fevid string, count int) {
	like := "%/c/" + caseID + "%"
	if det == "open_redirect" {
		// open_redirect_findings: a VERIFIED external redirect is the finding.
		rows, err := db.Query(`SELECT parameter, provenance, verified FROM open_redirect_findings WHERE target_id=? AND url LIKE ?`, tid, like)
		if err != nil {
			return
		}
		defer rows.Close()
		for rows.Next() {
			var p, prov string
			var verified int
			_ = rows.Scan(&p, &prov, &verified)
			if verified == 1 {
				count++
				fparam, fevid, fsev, ftype = p, prov, "high", "open_redirect"
			}
		}
		return
	}
	rows, err := db.Query(`SELECT type, severity, parameter, evidence FROM vuln_findings WHERE target_id=? AND url LIKE ?`, tid, like)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		count++
		_ = rows.Scan(&ftype, &fsev, &fparam, &fevid)
	}
	return
}

func ratioE2E(num, den int) string {
	if den == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.3f", float64(num)/float64(den))
}

// ── Cross-detector attribution (Phase 10) ───────────────────────────────────
//
// Runs EVERY param-injection detector against ONE shared lab and asserts each
// endpoint yields only its own vulnerability class — no detector claims a finding
// that belongs to another (an XSS sink must not be reported as SQLi, a SQL sink
// must not be reported as XSS), and a static endpoint that merely REFLECTS SQL
// error text (without executing anything) yields nothing at all.
func TestBenchmarkCrossDetector(t *testing.T) {
	withLoopbackAllowed(t)
	cfg := &config.Config{}
	cfg.EnableDAST = true
	log := logger.New("error")
	exec := tools.NewExecutor(cfg, log)
	nolog := func(_, _, _ string) {}

	mux := http.NewServeMux()
	// XSS-only: raw reflection into HTML text.
	mux.HandleFunc("/x/xss", xssRawHTML("q"))
	// SQLi-only: MySQL error on a broken quote.
	mux.HandleFunc("/x/sqli", sqliMySQLErr("id"))
	// FP trap: static SQL-error text present on EVERY response (reflected, not
	// executed) — the differential must see it in the baseline and stay silent.
	mux.HandleFunc("/x/sqltext", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>Docs: a \"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version\" message is shown when… value=" + html.EscapeString(r.URL.Query().Get("id")) + "</html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db, _ := database.New(t.TempDir() + "/x.db")
	defer db.Close()
	_ = database.RunMigrations(db)
	tid := uuid.New().String()
	_, _ = db.Exec(`INSERT INTO targets (id, domain, priority) VALUES (?,?, 'medium')`, tid, "lab.local")

	seed := func(path, param, value string) {
		_, _ = db.Exec(`INSERT INTO parameters (id, target_id, url, parameter, value, method, content_type, source) VALUES (?,?,?,?,?, 'GET','', 'seed')`,
			uuid.New().String(), tid, srv.URL+path+"?"+param+"="+value, param, value)
	}
	seed("/x/xss", "q", "x")
	seed("/x/sqli", "id", "1")
	seed("/x/sqltext", "id", "1")

	ctx := context.Background()
	_ = NewSQLiScanner(db, exec, cfg, log, nil).Run(ctx, tid, nolog)
	_ = NewLFIScanner(db, exec, cfg, log, nil).Run(ctx, tid, nolog)
	_ = NewSSTIScanner(db, exec, cfg, log, nil).Run(ctx, tid, nolog)
	_ = NewNoSQLiScanner(db, exec, cfg, log, nil).Run(ctx, tid, nolog)
	_ = NewDASTScanner(db, cfg, log, nil).Run(ctx, tid, nolog)

	// endpoint substring → the ONLY vuln type allowed there ("" = none allowed).
	allowed := map[string]string{"/x/xss": "xss", "/x/sqli": "sqli", "/x/sqltext": ""}
	rows, _ := db.Query(`SELECT type, url FROM vuln_findings WHERE target_id=?`, tid)
	defer rows.Close()
	seen := map[string]string{}
	for rows.Next() {
		var typ, u string
		_ = rows.Scan(&typ, &u)
		for frag, want := range allowed {
			if strings.Contains(u, frag) {
				seen[frag] = typ
				if want == "" {
					t.Errorf("MISATTRIBUTION: endpoint %s must yield NO finding, got %q", frag, typ)
				} else if typ != want {
					t.Errorf("MISATTRIBUTION: endpoint %s yielded %q, expected only %q", frag, typ, want)
				}
			}
		}
	}
	if seen["/x/xss"] != "xss" {
		t.Errorf("expected the XSS endpoint to be attributed as xss, got %q", seen["/x/xss"])
	}
	if seen["/x/sqli"] != "sqli" {
		t.Errorf("expected the SQLi endpoint to be attributed as sqli, got %q", seen["/x/sqli"])
	}
	t.Logf("cross-detector attribution OK: xss→%q sqli→%q sqltext→%q(none)", seen["/x/xss"], seen["/x/sqli"], seen["/x/sqltext"])
}
