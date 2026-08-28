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

// TestATOSelfRedirectAnalysisNoOpenRedirectFinding proves the ATO decoupling at
// EXECUTION level: given a discovered redirect-prone parameter on an auth flow,
// the ATO engine runs its OWN redirect analysis (checkOpenRedirectURL), raises an
// account_takeover chain, and writes NOTHING to open_redirect_findings — so an
// ATO-only scan never produces an independent open-redirect finding as a side
// effect. The Open Redirect DETECTOR module is never invoked here.
func TestATOSelfRedirectAnalysisNoOpenRedirectFinding(t *testing.T) {
	withLoopbackAllowed(t)

	// An auth flow with an open redirect: /login?next= reflects into Location.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.URL.Query().Get("next"); v != "" {
			w.Header().Set("Location", v)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	db, err := database.New(t.TempDir() + "/ato.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	tid := uuid.New().String()
	_, _ = db.Exec(`INSERT INTO targets (id, domain, priority) VALUES (?,?, 'medium')`, tid, "lab.local")
	// Discovered redirect-prone param on a sensitive auth path (as recon would leave it).
	loginURL := srv.URL + "/login?next=/dashboard"
	_, _ = db.Exec(`INSERT INTO parameters (id, target_id, url, parameter, value, method, content_type, source) VALUES (?,?,?, 'next','/dashboard','GET','', 'seed')`,
		uuid.New().String(), tid, loginURL)

	cfg := &config.Config{}
	eng := NewAccountTakeoverEngine(db, nil, cfg, logger.New("error"), nil)
	if err := eng.Run(context.Background(), tid, func(_, _, _ string) {}); err != nil {
		t.Fatalf("ato run: %v", err)
	}

	// It must raise the account-takeover chain (redirect-on-auth-flow).
	var ato int
	_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='account_takeover'`, tid).Scan(&ato)
	if ato == 0 {
		t.Errorf("ATO must raise an account_takeover chain for an open redirect on an auth flow")
	}

	// ISOLATION: ATO must NOT have written an independent open_redirect finding —
	// neither to open_redirect_findings nor as a vuln_findings row of that type.
	var orFindings, orVuln int
	_ = db.QueryRow(`SELECT COUNT(*) FROM open_redirect_findings WHERE target_id=?`, tid).Scan(&orFindings)
	_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type LIKE '%redirect%'`, tid).Scan(&orVuln)
	if orFindings != 0 {
		t.Errorf("ISOLATION VIOLATION: ATO-only wrote %d open_redirect_findings row(s)", orFindings)
	}
	if orVuln != 0 {
		t.Errorf("ISOLATION VIOLATION: ATO-only emitted %d redirect-typed vuln_finding(s)", orVuln)
	}

	// And every finding it did produce is an account_takeover finding.
	rows, _ := db.Query(`SELECT DISTINCT type FROM vuln_findings WHERE target_id=?`, tid)
	defer rows.Close()
	for rows.Next() {
		var typ string
		_ = rows.Scan(&typ)
		if typ != "account_takeover" {
			t.Errorf("ISOLATION VIOLATION: ATO-only produced non-ATO finding type %q", typ)
		}
	}
}
