package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/pkg/logger"
)

// TestRunXSSIsolatesFromSQLi proves the standalone XSS objective is XSS-only: on
// an endpoint that is BOTH reflected-XSS-vulnerable AND emits a SQL error on a
// broken quote, RunXSS confirms the XSS finding but registers NO SQLi candidate
// (the error-based SQLi side-channel is skipped in XSS-only mode).
func TestRunXSSIsolatesFromSQLi(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		// A broken quote also surfaces a MySQL error — a SQLi signal DAST would
		// normally register as a candidate. XSS-only must ignore it.
		body := "<div>results for " + v + "</div>"
		if containsQuote(v) {
			body += "<!-- You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version -->"
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	db, err := database.New(t.TempDir() + "/xss.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	tid := uuid.New().String()
	_, _ = db.Exec(`INSERT INTO targets (id, domain, priority) VALUES (?,?, 'medium')`, tid, "lab.local")
	_, _ = db.Exec(`INSERT INTO parameters (id, target_id, url, parameter, value, method, content_type, source) VALUES (?,?,?, 'q','x','GET','', 'seed')`,
		uuid.New().String(), tid, srv.URL+"/echo?q=x")

	cfg := &config.Config{}
	if err := NewDASTScanner(db, cfg, logger.New("error"), nil).RunXSS(context.Background(), tid, func(_, _, _ string) {}); err != nil {
		t.Fatalf("RunXSS: %v", err)
	}

	var xss int
	_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='xss'`, tid).Scan(&xss)
	if xss == 0 {
		t.Error("RunXSS must confirm the reflected XSS")
	}
	// Isolation: no SQLi candidate and no SQLi finding.
	var sqliCand, sqliFind int
	_ = db.QueryRow(`SELECT COUNT(*) FROM candidates WHERE target_id=? AND type='sqli'`, tid).Scan(&sqliCand)
	_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='sqli'`, tid).Scan(&sqliFind)
	if sqliCand != 0 {
		t.Errorf("ISOLATION VIOLATION: XSS-only scan registered %d SQLi candidate(s)", sqliCand)
	}
	if sqliFind != 0 {
		t.Errorf("ISOLATION VIOLATION: XSS-only scan produced %d SQLi finding(s)", sqliFind)
	}
}

func containsQuote(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' || s[i] == '"' || s[i] == '`' {
			return true
		}
	}
	return false
}
