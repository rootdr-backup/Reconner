package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
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

	childMux := http.NewServeMux()
	childMux.HandleFunc("/reflect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><title>child</title><body>%s</body></html>", r.URL.Query().Get("q"))
	})
	child := httptest.NewServer(childMux)
	defer child.Close()

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
	// TRANSIENT DOM FLOW: the canary reaches innerHTML and is immediately removed.
	// A post-render outerHTML grep cannot see it; runtime sink instrumentation must
	// retain the flow and route it to the execution ladder.
	mux.HandleFunc("/transient", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><div id=app></div><script>
			var p = new URLSearchParams(location.search).get('q');
			app.innerHTML = p; app.textContent = '';
		</script></body></html>`)
	})
	// CROSS-ORIGIN FRAME: the vulnerable reflection executes on another origin.
	// Reading top.document is forbidden here, so this fixture prevents regression
	// of the nonce-scoped postMessage proof channel.
	mux.HandleFunc("/cross-frame", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		src := child.URL + "/reflect?q=" + url.QueryEscape(r.URL.Query().Get("q"))
		fmt.Fprintf(w, `<html><title>parent</title><body><iframe src=%q></iframe></body></html>`, src)
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

	if pl, ok := b.Confirm(ctx, srv.URL+"/cross-frame?q=hi", "q"); !ok {
		t.Errorf("CROSS-FRAME endpoint: expected nonce postMessage proof, got none")
	} else {
		t.Logf("Cross-origin frame confirmed with payload: %s", pl)
	}

	transient := insertionPoint{URL: srv.URL + "/transient?q=hi", Param: "q", Method: "GET", Location: "query"}
	if !b.DOMReflectsInsertion(ctx, transient, nil) {
		t.Fatal("runtime instrumentation missed a transient innerHTML flow")
	}
	if trace := b.RuntimeTrace(transient, nil); !strings.Contains(trace, "Element.innerHTML") {
		t.Fatalf("runtime trace did not identify the sink: %q", trace)
	}
	if pl, ok := b.ConfirmInsertion(ctx, transient, nil); !ok {
		t.Error("transient runtime-routed DOM XSS did not execute")
	} else {
		t.Logf("Transient DOM XSS confirmed with payload: %s", pl)
	}
}
