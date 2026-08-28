package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestBrowserXSSConfirmLive is a REAL end-to-end proof: it stands up a tiny
// server with one genuinely-vulnerable endpoint (reflects the param into HTML
// unescaped) and one safe endpoint (HTML-escapes it), then drives a headless
// Chromium to confirm the payload actually executes on the vulnerable one and
// does NOT on the safe one.
//
// Guarded: normal `go test ./...` skips it so the suite never needs a browser.
// Run with:  RECONNER_BROWSER_TEST=1 RECONNER_CHROME=/path/to/chrome go test -run BrowserXSSConfirmLive ./internal/scanner/
func TestBrowserXSSConfirmLive(t *testing.T) {
	if os.Getenv("RECONNER_BROWSER_TEST") == "" {
		t.Skip("browser E2E disabled; set RECONNER_BROWSER_TEST=1 (and RECONNER_CHROME) to run")
	}
	if findChromePath() == "" {
		t.Skip("no chrome binary resolvable; set RECONNER_CHROME")
	}

	mux := http.NewServeMux()
	// VULNERABLE: raw reflection into HTML text.
	mux.HandleFunc("/vuln", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body><h1>Results</h1><div>%s</div></body></html>", r.URL.Query().Get("q"))
	})
	// SAFE: HTML-escaped reflection.
	mux.HandleFunc("/safe", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		esc := strings.NewReplacer("<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;").Replace(r.URL.Query().Get("q"))
		fmt.Fprintf(w, "<html><body><div>%s</div></body></html>", esc)
	})
	// SPA-STYLE: raw HTML has NO reflection; JS injects the param into the DOM
	// after load. The browserless parser sees nothing; the browser must catch it.
	mux.HandleFunc("/spa", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><div id=app></div><script>
			var p = new URLSearchParams(location.search).get('q');
			document.getElementById('app').innerHTML = p;
		</script></body></html>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	b := getXSSBrowser()
	if b == nil {
		t.Fatal("confirmer nil despite chrome present")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	if pl, ok := b.Confirm(ctx, srv.URL+"/vuln?q=hi", "q"); !ok {
		t.Errorf("VULN endpoint: expected browser to confirm execution, got none")
	} else {
		t.Logf("VULN confirmed with payload: %s", pl)
	}

	if _, ok := b.Confirm(ctx, srv.URL+"/safe?q=hi", "q"); ok {
		t.Errorf("SAFE endpoint: browser reported execution on an HTML-escaped reflection (false positive)")
	}

	if pl, ok := b.Confirm(ctx, srv.URL+"/spa?q=hi", "q"); !ok {
		t.Errorf("SPA endpoint: expected browser to confirm client-rendered XSS, got none")
	} else {
		t.Logf("SPA confirmed with payload: %s", pl)
	}
}
