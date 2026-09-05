package scanner

import (
	"context"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

// SQLmap verification adapter (Phase 5). PROVES a strong internal SQLi candidate
// with sqlmap. Conservative: structured args (no shell concat — via the executor's
// exec.CommandContext), scope-checked, low level/risk, bounded time. A POSITIVE
// sqlmap injection is the only thing that promotes a candidate to CONFIRMED; a
// non-positive run is INCONCLUSIVE (WAF/rate-limit/session/etc.), never a false
// negative asserted as "not vulnerable".

type SQLmapVerifier struct {
	exec         *tools.Executor
	cfg          *config.Config
	logger       *logger.Logger
	targetDomain string
	origins      []string
	authHeaders  map[string]string // selected identity (already decrypted)
	db           *database.DB
}

var sqlmapFallbackOutputMu sync.Mutex

func NewSQLmapVerifier(exec *tools.Executor, cfg *config.Config, log *logger.Logger, targetDomain string, origins []string, authHeaders map[string]string) *SQLmapVerifier {
	return &SQLmapVerifier{exec: exec, cfg: cfg, logger: log, targetDomain: targetDomain, origins: origins, authHeaders: authHeaders}
}

func (v *SQLmapVerifier) Name() string { return "sqlmap" }

// CanVerify: SQLi candidates only, and only when enabled + tool present.
func (v *SQLmapVerifier) CanVerify(c VulnerabilityCandidate) bool {
	return c.Type == "sqli" && v.cfg != nil && v.cfg.EnableSQLmap && v.exec != nil && v.exec.IsToolAvailable("sqlmap")
}

func (v *SQLmapVerifier) Verify(ctx context.Context, c VulnerabilityCandidate) VerifyResult {
	// Scope guard: never point sqlmap at an out-of-scope / internal host.
	if !URLInScope(v.targetDomain, v.origins, c.URL) {
		return VerifyResult{Verdict: VerifyRejected, Reason: "candidate URL out of scope", Method: "sqlmap"}
	}
	args := buildSQLmapArgsWithShape(c, RequestIdentityHeaders(ctx, v.authHeaders), v.requestSiblings(ctx, c), v.requestSiblingTypes(ctx, c))
	// Concurrent proof workers must not share sqlmap's default per-host session
	// files. Isolate each candidate in a temporary output directory; otherwise two
	// candidates on one host can lock/corrupt each other's session and become
	// spurious inconclusive results.
	if outputDir, err := os.MkdirTemp("", "reconner-sqlmap-"); err == nil {
		defer os.RemoveAll(outputDir)
		args = append(args, "--output-dir", outputDir)
	} else {
		// A broken/full temp filesystem must not make concurrent candidates share
		// sqlmap's session state. Serialize only this rare fallback and still run
		// the verifier so coverage is not silently lost.
		sqlmapFallbackOutputMu.Lock()
		defer sqlmapFallbackOutputMu.Unlock()
	}
	res, err := v.exec.Run(ctx, "sqlmap", args...)
	if err != nil && res == nil {
		return VerifyResult{Verdict: VerifyInconclusive, Reason: "sqlmap failed to run: " + err.Error(), Method: "sqlmap"}
	}
	out := res.Stdout + "\n" + res.Stderr
	positive, dbms, injType := parseSQLmapOutput(out)
	if positive {
		ev := "sqlmap CONFIRMED injection on parameter " + c.Parameter
		if injType != "" {
			ev += " (" + injType + ")"
		}
		if dbms != "" {
			ev += ", DBMS: " + dbms
		}
		return VerifyResult{Verdict: VerifyVerified, Confidence: 98, Evidence: ev, Method: "sqlmap"}
	}
	// Ran but did not positively confirm → INCONCLUSIVE with a reason (do not
	// claim "not vulnerable" — WAF/rate-limit/session/dynamic params can hide it).
	return VerifyResult{Verdict: VerifyInconclusive, Reason: sqlmapInconclusiveReason(out), Method: "sqlmap"}
}

// buildSQLmapArgs constructs a conservative, structured sqlmap argument array.
// NEVER build a shell string — the executor runs argv directly.
func buildSQLmapArgs(c VulnerabilityCandidate, cookie string) []string {
	auth := map[string]string{}
	if cookie != "" {
		auth["Cookie"] = cookie
	}
	return buildSQLmapArgsWithHeaders(c, auth)
}

// buildSQLmapArgsWithHeaders reconstructs the request placement the native
// detector used. Payload is deliberately ignored: it is detector evidence, not
// a serialised POST body. A custom '*' marker is used for path/header/cookie
// insertion points, while regular query/form/JSON fields are selected with -p.
func buildSQLmapArgsWithHeaders(c VulnerabilityCandidate, auth map[string]string) []string {
	return buildSQLmapArgsWithRequest(c, auth, nil)
}

func buildSQLmapArgsWithRequest(c VulnerabilityCandidate, auth, siblings map[string]string) []string {
	return buildSQLmapArgsWithShape(c, auth, siblings, nil)
}

func buildSQLmapArgsWithShape(c VulnerabilityCandidate, auth, siblings, siblingTypes map[string]string) []string {
	method := strings.ToUpper(strings.TrimSpace(c.Method))
	if method == "" {
		method = "GET"
	}
	loc := strings.ToLower(strings.TrimSpace(c.Location))
	if loc == "" {
		if method == "POST" {
			loc = "body"
		} else {
			loc = "query"
		}
	}
	targetURL := c.URL
	customMarker := false
	var data string
	var extraHeaders []string
	var markedCookie string

	switch {
	case strings.HasPrefix(loc, "path:"):
		if idx, ok := isPathLocation(loc); ok {
			targetURL = sqlmapPathMarker(c.URL, idx)
			customMarker = targetURL != c.URL
		}
	case strings.HasPrefix(loc, "graphql:"):
		method = "POST"
		ip := insertionPoint{URL: c.URL, Param: c.Parameter, Method: "POST", ContentType: "application/json", Location: c.Location, Siblings: siblings}
		if body, ok := buildGraphQLInjectionBody(ip, candidateBaselineValue(c)+"*"); ok {
			data = body
			customMarker = true
			extraHeaders = append(extraHeaders, "Content-Type: application/json")
		}
	case loc == "json":
		if method == "GET" {
			method = "POST"
		}
		payload := make(map[string]string, len(siblings)+1)
		for k, v := range siblings {
			payload[k] = v
		}
		payload[c.Parameter] = candidateBaselineValue(c) + "*"
		data = buildJSONFieldsTyped(payload, siblingTypes, c.Parameter)
		customMarker = true
		extraHeaders = append(extraHeaders, "Content-Type: application/json")
	case loc == "multipart":
		if method == "GET" {
			method = "POST"
		}
		const boundary = "----ReconnerSQLmapBoundary7MA4YWxk"
		fields := make(map[string]string, len(siblings)+1)
		for k, v := range siblings {
			fields[k] = v
		}
		fields[c.Parameter] = candidateBaselineValue(c) + "*"
		data = sqlmapMultipartBody(boundary, fields)
		customMarker = true
		extraHeaders = append(extraHeaders, "Content-Type: multipart/form-data; boundary="+boundary)
	case loc == "xml":
		if method == "GET" {
			method = "POST"
		}
		fields := make(map[string]string, len(siblings)+1)
		for k, v := range siblings {
			fields[k] = v
		}
		fields[c.Parameter] = candidateBaselineValue(c) + "*"
		data = buildXMLFields(fields)
		customMarker = true
		extraHeaders = append(extraHeaders, "Content-Type: application/xml")
	case loc == "body":
		if method == "GET" {
			method = "POST"
		}
		vals := url.Values{}
		for k, v := range siblings {
			vals.Set(k, v)
		}
		vals.Set(c.Parameter, candidateBaselineValue(c))
		data = vals.Encode()
		extraHeaders = append(extraHeaders, "Content-Type: application/x-www-form-urlencoded")
	case loc == "cookie":
		cookie := headerValue(auth, "Cookie")
		name := c.Parameter
		if strings.EqualFold(name, "cookie") || strings.TrimSpace(name) == "" {
			name = "recon_sqli"
		}
		markedCookie = sqlmapCookieMarker(cookie, name)
		if markedCookie != "" {
			customMarker = true
		}
	case loc == "header":
		name := strings.TrimSpace(c.Parameter)
		value := "recon-sqli*"
		switch strings.ToLower(name) {
		case "user-agent":
			value = "Mozilla/5.0 (compatible; ReconnerSQLi*)"
		case "referer", "referrer":
			name = "Referer"
			value = "https://recon-sqli.invalid/*"
		case "x-forwarded-for":
			value = "127.0.0.1, 127.0.0.1*"
		}
		if name != "" {
			extraHeaders = append(extraHeaders, name+": "+value)
			customMarker = true
		}
	}

	args := []string{
		"-u", targetURL,
		"--batch",               // non-interactive
		"--disable-coloring",    // clean, parseable output
		"--level=3", "--risk=1", // deeper boundaries/headers, without destructive risk-3 vectors
		"--technique=BEUSTQ", // Boolean/Error/Union/Stacked/Time + inline queries
		"--timeout=15", "--retries=2", "--threads=2", "--time-sec=3",
		"--answers=quit=N,crack=N,dict=N,continue=Y",
	}
	// Do not let --random-agent overwrite a User-Agent injection marker or an
	// authenticated identity's required UA.
	if !(loc == "header" && strings.EqualFold(c.Parameter, "User-Agent")) && headerValue(auth, "User-Agent") == "" {
		args = append(args, "--random-agent")
	}
	if method != "GET" {
		args = append(args, "--method="+method)
	}
	if data != "" {
		args = append(args, "--data", data)
	}
	if !customMarker && c.Parameter != "" {
		args = append(args, "-p", c.Parameter)
	}

	// Preserve authenticated reachability. Cookie is emitted through sqlmap's
	// dedicated option for ordinary parameters; other headers are passed as one
	// newline-delimited argv value. The header currently being injected is not
	// overwritten by its baseline identity value.
	if loc == "cookie" && markedCookie != "" {
		args = append(args, "--cookie", markedCookie)
	} else if loc != "cookie" {
		if cookie := headerValue(auth, "Cookie"); cookie != "" {
			args = append(args, "--cookie", cookie)
		}
	}
	keys := make([]string, 0, len(auth))
	for k := range auth {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := auth[k]
		if strings.EqualFold(k, "Cookie") || strings.EqualFold(k, "Content-Length") ||
			(loc == "header" && strings.EqualFold(k, c.Parameter)) {
			continue
		}
		extraHeaders = append(extraHeaders, k+": "+v)
	}
	if len(extraHeaders) > 0 {
		args = append(args, "--headers", strings.Join(extraHeaders, "\n"))
	}
	return args
}

func (v *SQLmapVerifier) requestSiblings(ctx context.Context, c VulnerabilityCandidate) map[string]string {
	method := strings.ToUpper(strings.TrimSpace(c.Method))
	loc := strings.ToLower(strings.TrimSpace(c.Location))
	if v.db == nil || method == "" || method == "GET" ||
		!(loc == "body" || loc == "json" || loc == "multipart" || loc == "xml" || strings.HasPrefix(loc, "graphql:")) {
		return nil
	}
	rows, err := v.db.QueryContext(ctx, `
		SELECT parameter,COALESCE(value,'') FROM parameters
		WHERE target_id=? AND url=? AND UPPER(COALESCE(method,'GET'))=?`, c.TargetID, c.URL, method)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var name, value string
		if rows.Scan(&name, &value) == nil && name != "" {
			out[name] = value
		}
	}
	return out
}

func (v *SQLmapVerifier) requestSiblingTypes(ctx context.Context, c VulnerabilityCandidate) map[string]string {
	if v.db == nil || !strings.EqualFold(c.Location, "json") {
		return nil
	}
	method := strings.ToUpper(strings.TrimSpace(c.Method))
	rows, err := v.db.QueryContext(ctx, `
		SELECT parameter,COALESCE(location,'') FROM parameters
		WHERE target_id=? AND url=? AND UPPER(COALESCE(method,'GET'))=?`, c.TargetID, c.URL, method)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var name, location string
		if rows.Scan(&name, &location) == nil {
			if typ := insertionJSONType(location); typ != "" {
				out[name] = typ
			}
		}
	}
	return out
}

func sqlmapMultipartBody(boundary string, fields map[string]string) string {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		name := strings.ReplaceAll(k, `"`, "")
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString(`Content-Disposition: form-data; name="` + name + `"` + "\r\n\r\n")
		b.WriteString(fields[k] + "\r\n")
	}
	b.WriteString("--" + boundary + "--\r\n")
	return b.String()
}

func candidateBaselineValue(c VulnerabilityCandidate) string {
	if u, err := url.Parse(c.URL); err == nil && c.Parameter != "" {
		if v := u.Query().Get(c.Parameter); v != "" {
			return v
		}
	}
	return "1"
}

func headerValue(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func sqlmapPathMarker(rawURL string, idx int) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	segs := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if idx < 0 || idx >= len(segs) || segs[idx] == "" {
		return rawURL
	}
	segs[idx] += "*"
	u.Path = "/" + strings.Join(segs, "/")
	u.RawPath = ""
	// net/url encodes '*' as %2A in paths, but sqlmap's custom injection marker
	// must remain a literal asterisk in argv/on the request template.
	return strings.Replace(u.String(), "%2A", "*", 1)
}

func sqlmapCookieMarker(cookie, name string) string {
	var parts []string
	found := false
	for _, part := range strings.Split(cookie, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 && strings.EqualFold(strings.TrimSpace(kv[0]), name) {
			parts = append(parts, strings.TrimSpace(kv[0])+"="+kv[1]+"*")
			found = true
		} else {
			parts = append(parts, part)
		}
	}
	if !found {
		parts = append(parts, name+"=1*")
	}
	return strings.Join(parts, "; ")
}

var (
	reSQLmapVuln    = regexp.MustCompile(`(?i)parameter '?[^']*'? (?:is|appears to be) [^\n]*vulnerable|the following injection point`)
	reSQLmapType    = regexp.MustCompile(`(?i)Type:\s*([^\n]+)`)
	reSQLmapDBMS    = regexp.MustCompile(`(?i)back-end DBMS:\s*([^\n]+)`)
	reSQLmapNotVuln = regexp.MustCompile(`(?i)all tested parameters do not appear to be injectable`)
)

// parseSQLmapOutput extracts a positive-injection verdict + DBMS + type.
func parseSQLmapOutput(out string) (positive bool, dbms, injType string) {
	if reSQLmapVuln.MatchString(out) && !reSQLmapNotVuln.MatchString(out) {
		positive = true
	}
	if m := reSQLmapDBMS.FindStringSubmatch(out); len(m) == 2 {
		dbms = strings.TrimSpace(m[1])
	}
	if m := reSQLmapType.FindStringSubmatch(out); len(m) == 2 {
		injType = strings.TrimSpace(m[1])
	}
	return
}

// sqlmapInconclusiveReason gives a human reason a run didn't confirm.
func sqlmapInconclusiveReason(out string) string {
	low := strings.ToLower(out)
	switch {
	case reSQLmapNotVuln.MatchString(out):
		return "sqlmap tested the parameter and did not find it injectable (could be WAF/dynamic response — kept INCONCLUSIVE, not rejected)"
	case strings.Contains(low, "connection timed out") || strings.Contains(low, "unable to connect"):
		return "sqlmap could not reach the target (timeout/connection) — retry when stable"
	case strings.Contains(low, "403") || strings.Contains(low, "waf") || strings.Contains(low, "blocked"):
		return "sqlmap appears blocked (WAF/403) — verification inconclusive"
	default:
		return "sqlmap ran but did not positively confirm injection"
	}
}
