package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
)

// TestSQLiContentDifferentialBoolean proves the FULL boolean-blind path end to end:
// (1) a same-length TRUE vs FALSE content differential the size check misses, AND
// (2) the require-proof gate — the finding is emitted only because the engine then
// drives that TRUE/FALSE oracle to EXTRACT the current database name. The mock is a
// genuine boolean oracle over database()="sqli": it returns the record for a TRUE
// injected condition and a same-length "not found" page for a FALSE one, so the
// engine's binary-search extraction actually reads the name back.
func TestSQLiContentDifferentialBoolean(t *testing.T) {
	withLoopbackAllowed(t)
	full := strings.Repeat("PROFILE-alice-admin;", 30) // 600 bytes (the record)
	none := strings.Repeat("NOTFOUND-no-record-;", 30) // 600 bytes — SAME length
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if sqliOracleTrue(r.URL.Query().Get("id"), "sqli") {
			_, _ = w.Write([]byte(full))
		} else {
			_, _ = w.Write([]byte(none))
		}
	}))
	defer srv.Close()

	s := &SQLiScanner{}
	ip := insertionPoint{URL: srv.URL + "/?id=1", Param: "id", Method: "GET"}
	kind, ev := s.quickProbe(context.Background(), ip, nil)
	if kind != "boolean_based" {
		t.Fatalf("same-length blind boolean SQLi must be detected + proven; got kind=%q ev=%q", kind, ev)
	}
	if !strings.Contains(ev, `"sqli"`) {
		t.Errorf("evidence must carry the extracted database name: %q", ev)
	}
}

// sqliOracleTrue is a compact boolean-SQL evaluator that models a vulnerable app
// whose query is `... WHERE id = <value>` with row id=1 present and database()=db.
// It evaluates the injected condition so the engine's real detection AND extraction
// payloads read back correctly — a genuine oracle, not a keyword match.
func sqliOracleTrue(value, db string) bool {
	s := strings.ToLower(value)
	s = strings.ReplaceAll(s, "/**/", " ")
	if i := strings.Index(s, "-- "); i >= 0 {
		s = s[:i]
	}
	// isolate the injected boolean condition after the id match.
	var cond string
	if a := strings.Index(s, "and ("); a >= 0 {
		rest := s[a+len("and ("):]
		if b := strings.LastIndex(rest, ")"); b >= 0 {
			cond = rest[:b]
		} else {
			cond = rest
		}
	} else if a := strings.LastIndex(s, "and "); a >= 0 {
		cond = s[a+len("and "):]
	} else {
		return true // bare id=1 → the row exists (baseline)
	}
	return sqliEvalCond(strings.TrimSpace(cond), strings.ToLower(db))
}

func sqliEvalCond(c, db string) bool {
	c = strings.TrimSpace(c)
	c = strings.TrimSuffix(strings.TrimSpace(strings.TrimSuffix(c, "'1'='1")), "and")
	c = strings.TrimSpace(c)
	if strings.HasPrefix(c, "not") {
		inner := strings.TrimSpace(strings.TrimPrefix(c, "not"))
		inner = strings.TrimPrefix(inner, "(")
		inner = strings.TrimSuffix(inner, ")")
		return !sqliEvalCond(inner, db)
	}
	c = strings.TrimPrefix(c, "(")
	c = strings.TrimSuffix(c, ")")
	c = strings.TrimSpace(c)
	for _, op := range []string{">=", "<=", "=", ">", "<"} {
		if i := strings.Index(c, op); i >= 0 {
			l := sqliEvalExpr(strings.TrimSpace(c[:i]), db)
			r := sqliEvalExpr(strings.TrimSpace(c[i+len(op):]), db)
			return sqliCmp(l, op, r)
		}
	}
	return false
}

// sqliVal is either a number or a string (for database()=... comparisons).
type sqliVal struct {
	num   int
	str   string
	isStr bool
}

func sqliEvalExpr(e, db string) sqliVal {
	e = strings.TrimSpace(e)
	if strings.HasPrefix(e, "'") { // quoted string literal
		return sqliVal{str: strings.Trim(e, "'"), isStr: true}
	}
	if strings.Contains(e, "database()") || strings.Contains(e, "current_database()") || strings.Contains(e, "db_name()") {
		switch {
		case strings.HasPrefix(e, "length(") || strings.HasPrefix(e, "char_length(") || strings.HasPrefix(e, "len("):
			return sqliVal{num: len(db)}
		case strings.HasPrefix(e, "ascii("):
			// ascii(substring(database(),P,1)) — pull P.
			p := 1
			if k := strings.Index(e, "),"); k >= 0 {
				rest := e[k+2:]
				fmt.Sscanf(rest, "%d", &p)
			}
			if p >= 1 && p <= len(db) {
				return sqliVal{num: int(db[p-1])}
			}
			return sqliVal{num: 0}
		default:
			return sqliVal{str: db, isStr: true} // bare database()
		}
	}
	n := 0
	fmt.Sscanf(e, "%d", &n)
	return sqliVal{num: n}
}

func sqliCmp(l sqliVal, op string, r sqliVal) bool {
	if l.isStr || r.isStr {
		return op == "=" && l.str == r.str
	}
	switch op {
	case ">=":
		return l.num >= r.num
	case "<=":
		return l.num <= r.num
	case ">":
		return l.num > r.num
	case "<":
		return l.num < r.num
	default:
		return l.num == r.num
	}
}

// TestSQLiContentDifferentialNoFP: a parameter that has NO effect on the response
// (same body for every value) must NOT be flagged — FALSE == baseline, so the
// content differential's "FALSE differs" requirement fails.
func TestSQLiContentDifferentialNoFP(t *testing.T) {
	withLoopbackAllowed(t)
	body := strings.Repeat("STATIC-CONTENT-HERE;", 30)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(body)) // identical for every value
	}))
	defer srv.Close()

	s := &SQLiScanner{}
	ip := insertionPoint{URL: srv.URL + "/?id=1", Param: "id", Method: "GET"}
	if kind, ev := s.quickProbe(context.Background(), ip, nil); kind != "" {
		t.Fatalf("an inert parameter must NOT be flagged as SQLi; got kind=%q ev=%q", kind, ev)
	}
}

// TestSQLiPlantBlindRegistersProbes proves the SQLi detector OWNS its blind
// out-of-band confirmation: with a callback configured, plantBlindSQLi registers
// probes under kind='sqli' (so a later callback is attributed to blind_sqli),
// without needing the multi-class OAST module.
func TestSQLiPlantBlindRegistersProbes(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	db, err := database.New(t.TempDir() + "/sqli.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	tid := uuid.New().String()
	_, _ = db.Exec(`INSERT INTO targets (id, domain) VALUES (?,?)`, tid, "lab.local")
	_, _ = db.Exec(`INSERT INTO parameters (id, target_id, url, parameter, value, method, content_type, source) VALUES (?,?,?, 'id','1','GET','', 'seed')`,
		uuid.New().String(), tid, srv.URL+"/item?id=1")

	s := &SQLiScanner{db: db, cfg: &config.Config{BlindXSSCallbackURL: "http://oob.example"}}
	s.plantBlindSQLi(context.Background(), tid, func(_, _, _ string) {})

	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM oob_probes WHERE target_id=? AND kind='sqli'`, tid).Scan(&n)
	if n == 0 {
		t.Error("plantBlindSQLi must register at least one kind='sqli' OOB probe when a callback is configured")
	}
	// No callback configured → no probes planted (graceful no-op).
	s2 := &SQLiScanner{db: db, cfg: &config.Config{}}
	tid2 := uuid.New().String()
	_, _ = db.Exec(`INSERT INTO targets (id, domain) VALUES (?,?)`, tid2, "lab2.local")
	_, _ = db.Exec(`INSERT INTO parameters (id, target_id, url, parameter, value, method, content_type, source) VALUES (?,?,?, 'id','1','GET','', 'seed')`,
		uuid.New().String(), tid2, srv.URL+"/item?id=1")
	s2.plantBlindSQLi(context.Background(), tid2, func(_, _, _ string) {})
	var n2 int
	_ = db.QueryRow(`SELECT COUNT(*) FROM oob_probes WHERE target_id=?`, tid2).Scan(&n2)
	if n2 != 0 {
		t.Errorf("no callback configured → plantBlindSQLi must plant nothing; got %d", n2)
	}
}
