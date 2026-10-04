package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/pkg/logger"
)

// TestXSSConcurrentBrowserConfirmation is a minimal, REAL end-to-end proof
// for the reported "xss finds nothing" complaint: it stands up an
// httptest.Server with many genuinely-vulnerable reflected-XSS parameters
// (unescaped reflection straight into HTML text) and drives the ACTUAL
// production entry point (DASTScanner.RunXSS) against all of them at once,
// so dastWorkers' concurrent goroutines really do call into the shared
// browserXSSConfirmer simultaneously -- the exact path
// (testPoint -> proveExecutingXSS -> ConfirmInsertionWithAnalysesAndTemplates
// -> fireWithHeaders -> ensureTab -> chromedp.Run -> ExecAllocator.Allocate)
// the CI race detector caught.
//
// Requires a real Chromium: RECONNER_CHROME=/path/to/chrome go test -race
// -run TestXSSConcurrentBrowserConfirmation ./internal/scanner/
func TestXSSConcurrentBrowserConfirmation(t *testing.T) {
	if findChromePath() == "" {
		t.Skip("no Chrome/Chromium available (set RECONNER_CHROME); skipping real-browser concurrency proof")
	}

	const points = 20 // > dastWorkers (12), so every worker slot is in flight on a browser confirmation at once
	mux := http.NewServeMux()
	for i := 0; i < points; i++ {
		path := fmt.Sprintf("/vuln%d", i)
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			// The simplest possible real reflected XSS: the query param lands
			// unescaped directly in HTML text content, no encoding at all.
			fmt.Fprintf(w, "<html><body>Hello %s</body></html>", r.URL.Query().Get("q"))
		})
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db, err := database.New(t.TempDir() + "/xssconc.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	tid := uuid.New().String()
	if _, err := db.Exec(`INSERT INTO targets (id, domain, priority) VALUES (?,?, 'medium')`, tid, "lab.local"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < points; i++ {
		if _, err := db.Exec(`INSERT INTO parameters (id, target_id, url, parameter, value, method, content_type, source) VALUES (?,?,?, 'q','x','GET','', 'seed')`,
			uuid.New().String(), tid, fmt.Sprintf("%s/vuln%d?q=x", srv.URL, i)); err != nil {
			t.Fatal(err)
		}
	}

	cfg := &config.Config{}
	logs := make([]string, 0)
	logFn := func(level, _, msg string) { logs = append(logs, level+": "+msg) }
	if err := NewDASTScanner(db, cfg, logger.New("error"), nil).RunXSS(context.Background(), tid, logFn); err != nil {
		t.Fatalf("RunXSS: %v", err)
	}

	var confirmed int
	if err := db.QueryRow(`SELECT COUNT(*) FROM candidates WHERE target_id=? AND type='xss' AND status='CONFIRMED'`, tid).Scan(&confirmed); err != nil {
		t.Fatal(err)
	}
	t.Logf("confirmed=%d / %d candidates (chrome=%s)", confirmed, points, os.Getenv("RECONNER_CHROME"))
	for _, l := range logs {
		t.Log(l)
	}
	if confirmed < points {
		t.Errorf("expected all %d trivially-vulnerable reflected-XSS params to be CONFIRMED via real browser proof under concurrency, got %d", points, confirmed)
	}
}
