package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// ── a tiny boolean-SQL oracle, just rich enough to answer the exact conditions
// blindExtractDBName emits for the MySQL recipe. This models a genuinely-injectable
// endpoint: injected boolean SQL is actually evaluated against database()='shopdb'.

var (
	reEq    = regexp.MustCompile(`^database\(\) = '([^']*)'$`)
	reLen   = regexp.MustCompile(`^LENGTH\(database\(\)\) (>=|<=|=|>|<) (\d+)$`)
	reAscii = regexp.MustCompile(`^ASCII\(SUBSTRING\(\(database\(\)\),(\d+),1\)\) (>=|<=|=|>|<) (\d+)$`)
)

func cmpOp(a int, op string, b int) bool {
	switch op {
	case ">=":
		return a >= b
	case "<=":
		return a <= b
	case "=":
		return a == b
	case ">":
		return a > b
	case "<":
		return a < b
	}
	return false
}

func evalCond(e, dbname string) bool {
	e = strings.TrimSpace(e)
	if strings.HasPrefix(e, "NOT (") && strings.HasSuffix(e, ")") {
		return !evalCond(e[len("NOT ("):len(e)-1], dbname)
	}
	switch e {
	case "1=1":
		return true
	case "1=2":
		return false
	}
	if m := reEq.FindStringSubmatch(e); m != nil {
		return dbname == m[1]
	}
	if m := reLen.FindStringSubmatch(e); m != nil {
		n, _ := strconv.Atoi(m[2])
		return cmpOp(len(dbname), m[1], n)
	}
	if m := reAscii.FindStringSubmatch(e); m != nil {
		p, _ := strconv.Atoi(m[1])
		n, _ := strconv.Atoi(m[3])
		if p < 1 || p > len(dbname) {
			return false
		}
		return cmpOp(int(dbname[p-1]), m[2], n)
	}
	return false
}

// evalPayload interprets the injected `id` value as "1 AND <condition>" (with or
// without wrapping parens / a trailing comment) and returns whether the row is
// still selected (condition TRUE). Anything it doesn't recognise (baseline "1",
// earlier non-boolean probes) is treated as the benign baseline row.
func evalPayload(k, dbname string) bool {
	k = strings.TrimSpace(k)
	k = strings.TrimSpace(strings.TrimSuffix(k, "-- -"))
	if k == "1" || k == "" {
		return true
	}
	if strings.HasPrefix(k, "1 AND (") && strings.HasSuffix(k, ")") {
		return evalCond(k[len("1 AND ("):len(k)-1], dbname)
	}
	if strings.HasPrefix(k, "1 AND ") {
		return evalCond(strings.TrimPrefix(k, "1 AND "), dbname)
	}
	return true // earlier probes (quote/UNION/extractvalue) → benign baseline object
}

// TestBlindBooleanProvenByExtraction: a real boolean-SQLi endpoint must be detected
// AND the finding must carry the extracted database name — never a bare
// differential.
func TestBlindBooleanProvenByExtraction(t *testing.T) {
	const dbname = "shopdb"
	objA := "<html><body>" + strings.Repeat("A", 1000) + "</body></html>" // TRUE / baseline
	objB := "<html><body>" + strings.Repeat("B", 1400) + "-different</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if evalPayload(r.URL.Query().Get("id"), dbname) {
			w.Write([]byte(objA))
		} else {
			w.Write([]byte(objB))
		}
	}))
	defer srv.Close()

	s := &SQLiScanner{}
	ip := insertionPoint{URL: srv.URL + "/item?id=1", Param: "id", Method: "GET"}
	kind, ev := s.quickProbe(context.Background(), ip, nil)
	if kind != "boolean_based" {
		t.Fatalf("expected boolean_based detection, got kind=%q ev=%q", kind, ev)
	}
	if !strings.Contains(ev, "shopdb") {
		t.Fatalf("finding evidence must contain the EXTRACTED database name; got: %q", ev)
	}
	if !strings.Contains(ev, "PROVEN by extraction") {
		t.Fatalf("evidence should state it was proven by extraction; got: %q", ev)
	}
	t.Logf("proven: %s", ev)
}

// TestBlindBooleanCoincidenceNoFinding is the aparat.com false-positive: a TRUE/
// FALSE differential is present (an id→object / cache endpoint returns a different
// object for the "false" value) but NO injected SQL is actually evaluated. The
// oracle cannot separate a condition from its negation, so extraction fails and NO
// finding may be emitted.
func TestBlindBooleanCoincidenceNoFinding(t *testing.T) {
	objA := "<html><body>" + strings.Repeat("A", 1000) + "</body></html>"
	objB := "<html><body>" + strings.Repeat("B", 1400) + "-different</body></html>"
	// Only the literal FALSE detection strings return the "different" object; every
	// other value — the baseline, the TRUE strings, and ALL extraction probes and
	// their negations — returns the baseline object. So the differential is real but
	// the endpoint evaluates no SQL: a probe and its negation look identical.
	falseStrings := map[string]bool{
		"1 AND 1=2": true, "1' AND '1'='2": true, "1 AND 1=2-- -": true,
		`1" AND "1"="2`: true, "1) AND (1=2)-- -": true, "1)) AND ((1=2))-- -": true,
		"1') AND ('1'='2": true, "1/**/aNd/**/1=2": true, "1'/**/aNd/**/'1'='2": true,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if falseStrings[r.URL.Query().Get("id")] {
			w.Write([]byte(objB))
		} else {
			w.Write([]byte(objA))
		}
	}))
	defer srv.Close()

	s := &SQLiScanner{}
	ip := insertionPoint{URL: srv.URL + "/item?id=1", Param: "id", Method: "GET"}
	kind, ev := s.quickProbe(context.Background(), ip, nil)
	if kind != "" {
		t.Fatalf("coincidental differential (no SQL) must NOT be reported; got kind=%q ev=%q", kind, ev)
	}
}

// TestBlindBooleanStatusOracle covers APIs that encode row/no-row solely in the
// HTTP status (for example 204 vs 404) with identical empty bodies. The old
// body-length-only classifier discarded this real extraction channel.
func TestBlindBooleanStatusOracle(t *testing.T) {
	const dbname = "statusdb"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if evalPayload(r.URL.Query().Get("id"), dbname) {
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	s := &SQLiScanner{}
	ip := insertionPoint{URL: srv.URL + "/item?id=1", Param: "id", Value: "1", Method: "GET"}
	kind, ev := s.quickProbe(context.Background(), ip, nil)
	if kind != "boolean_based" || !strings.Contains(ev, dbname) {
		t.Fatalf("status-only boolean oracle must be extracted; kind=%q evidence=%q", kind, ev)
	}
}

func TestOrderByBooleanOracleExtraction(t *testing.T) {
	const dbname = "ordersdb"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("sort")
		truth := true
		if i := strings.Index(v, "CASE WHEN ("); i >= 0 {
			rest := v[i+len("CASE WHEN ("):]
			if end := strings.Index(rest, ") THEN 1 ELSE 2 END"); end >= 0 {
				truth = evalCond(rest[:end], dbname)
			}
		}
		if truth {
			w.Write([]byte("row-alice,row-bob,row-carol"))
		} else {
			w.Write([]byte("row-carol,row-bob,row-alice"))
		}
	}))
	defer srv.Close()

	s := &SQLiScanner{}
	ip := insertionPoint{URL: srv.URL + "/users?sort=name", Param: "sort", Value: "name", Method: "GET"}
	kind, ev := s.quickProbe(context.Background(), ip, nil)
	if kind != "boolean_based" || !strings.Contains(ev, dbname) || !strings.Contains(ev, "ORDER BY") {
		t.Fatalf("ORDER BY SQLi must be proven by extraction; kind=%q evidence=%q", kind, ev)
	}
}

func TestORBooleanOracleWhenBaselineSelectsNoRow(t *testing.T) {
	const dbname = "missingrowdb"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("id")
		truth := false // id=999 does not exist
		if i := strings.Index(v, " OR ("); i >= 0 {
			rest := strings.TrimSuffix(v[i+len(" OR ("):], "-- -")
			rest = strings.TrimSpace(strings.TrimSuffix(rest, ")"))
			truth = evalCond(rest, dbname)
		}
		if truth {
			w.Write([]byte("selected-row-from-database"))
		} else {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("no-row"))
		}
	}))
	defer srv.Close()

	s := &SQLiScanner{}
	ip := insertionPoint{URL: srv.URL + "/item?id=999", Param: "id", Value: "999", Method: "GET"}
	kind, ev := s.quickProbe(context.Background(), ip, nil)
	if kind != "boolean_based" || !strings.Contains(ev, dbname) || !strings.Contains(ev, "OR-based") {
		t.Fatalf("OR oracle must recover SQLi when baseline has no row; kind=%q evidence=%q", kind, ev)
	}
}

// TestBlindExtractDirectRejectsNonOracle unit-tests the extractor: against the
// coincidence endpoint it must return ok=false (nothing extracted).
func TestBlindExtractDirectRejectsNonOracle(t *testing.T) {
	objA := strings.Repeat("A", 1000)
	objB := strings.Repeat("B", 1400)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") == "1 AND 1=2" {
			w.Write([]byte(objB))
		} else {
			w.Write([]byte(objA))
		}
	}))
	defer srv.Close()

	s := &SQLiScanner{}
	ip := insertionPoint{URL: srv.URL + "/item?id=1", Param: "id", Method: "GET"}
	vol := measureVolatility(context.Background(), sqliHTTPClient, ip, nil, "1")
	isTrueLike := func(r []byte) bool { return vol.matchesBaseline(len(r)) }
	if name, dbms, ok := s.blindExtractDBName(context.Background(), ip, nil, "1 AND (%s)", isTrueLike); ok {
		t.Fatalf("extractor must reject a non-oracle endpoint, got name=%q dbms=%q", name, dbms)
	}
}
