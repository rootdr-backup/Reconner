package scanner

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/recon-platform/internal/database"
)

func TestDastConfirmContexts(t *testing.T) {
	if p, n, ok := dastConfirm(ReflectionAnalysis{Context: CtxHTMLText}); !ok || p != "<rcnq2z>" || n != "<rcnq2z>" {
		t.Fatalf("html-text confirm wrong: %q %q %v", p, n, ok)
	}
	if p, _, ok := dastConfirm(ReflectionAnalysis{Context: CtxQuotedAttr, Quote: '"'}); !ok || p != `"><rcnq2z>` {
		t.Fatalf("double-quoted-attr confirm wrong: %q %v", p, ok)
	}
	// Single-quoted attribute must break the SINGLE quote, not a hardcoded double.
	if p, _, ok := dastConfirm(ReflectionAnalysis{Context: CtxQuotedAttr, Quote: '\''}); !ok || p != `'><rcnq2z>` {
		t.Fatalf("single-quoted-attr confirm wrong: %q %v", p, ok)
	}
	// CSS context breaks out of <style>.
	if p, _, ok := dastConfirm(ReflectionAnalysis{Context: CtxCSS}); !ok || p != `</style><rcnq2z>` {
		t.Fatalf("css confirm wrong: %q %v", p, ok)
	}
	if _, _, ok := dastConfirm(ReflectionAnalysis{Context: CtxJSString}); ok {
		t.Fatal("JS-string context must NOT be markup-confirmable via dastConfirm")
	}
}

func TestSQLErrorAppearedDifferential(t *testing.T) {
	base := "<html>welcome</html>"
	injected := "<html>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version</html>"
	if !sqlErrorAppeared(base, injected) {
		t.Fatal("error present only after injection must be detected")
	}
	// static error already in baseline → NOT differential (no new signal)
	if sqlErrorAppeared(injected, injected) {
		t.Fatal("error present in baseline too must NOT count (static, not injected)")
	}
}

func addParam(db *database.DB, targetID, url, param string) {
	_, _ = db.Exec(`INSERT INTO parameters (id, target_id, url, parameter, method, content_type)
		VALUES (?,?,?,?, 'GET','')`, url+"|"+param, targetID, url, param)
}

func TestDASTDetectsRawHTMLInjectionWithoutBrowserOverclaim(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()

	// vulnerable app: reflects `q` RAW into HTML text.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>hi " + r.URL.Query().Get("q") + " bye</body></html>"))
	}))
	defer srv.Close()
	addParam(db, tid, srv.URL+"/?q=1", "q")

	s := NewDASTScanner(db, nil, nil, func(string, any) {})
	if err := s.Run(context.Background(), tid, func(string, string, string) {}); err != nil {
		t.Fatalf("run: %v", err)
	}

	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='xss' AND status IN ('candidate','finding')`, tid).Scan(&n)
	if n == 0 {
		t.Fatal("raw HTML reflection must be retained as an XSS candidate or browser-confirmed finding")
	}
	var status string
	_ = db.QueryRow(`SELECT status FROM candidates WHERE target_id=? AND type='xss'`, tid).Scan(&status)
	if status != CandInconclusive && status != CandConfirmed {
		t.Fatalf("candidate must await runtime proof or be browser-confirmed, got %q", status)
	}
}

func TestDASTRejectsEncodedReflection(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()

	// safe app: HTML-encodes the reflection → not executable.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>hi " + html.EscapeString(r.URL.Query().Get("q")) + " bye</body></html>"))
	}))
	defer srv.Close()
	addParam(db, tid, srv.URL+"/?q=1", "q")

	s := NewDASTScanner(db, nil, nil, func(string, any) {})
	_ = s.Run(context.Background(), tid, func(string, string, string) {})

	var findings int
	_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='xss'`, tid).Scan(&findings)
	if findings != 0 {
		t.Fatal("encoded reflection must NOT produce a finding (false positive)")
	}
	var status string
	_ = db.QueryRow(`SELECT status FROM candidates WHERE target_id=? AND type='xss'`, tid).Scan(&status)
	if status != CandRejected {
		t.Fatalf("encoded reflection candidate must be REJECTED, got %q", status)
	}
}

func TestDASTErrorBasedSQLiCandidate(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()

	// app that emits a MySQL error whenever a single quote reaches it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("id")
		if strings.Contains(q, "'") {
			_, _ = w.Write([]byte("You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	addParam(db, tid, srv.URL+"/?id=1", "id")

	s := NewDASTScanner(db, nil, nil, func(string, any) {})
	_ = s.Run(context.Background(), tid, func(string, string, string) {})

	var typ, status string
	err := db.QueryRow(`SELECT type, status FROM candidates WHERE target_id=? AND type='sqli'`, tid).Scan(&typ, &status)
	if err != nil {
		t.Fatalf("expected a sqli candidate: %v", err)
	}
	if status != CandDetected {
		t.Fatalf("error-based SQLi must remain DETECTED until SQL-specific verification proves it, got %q", status)
	}
}
