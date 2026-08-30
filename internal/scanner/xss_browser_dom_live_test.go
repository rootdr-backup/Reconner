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

// This guarded integration test exercises every attacker-controlled DOM source
// using a real Chromium. It catches CDP/browser-policy failures that static/unit
// tests cannot see (window.name persistence, real postMessage origin, hash-router
// shapes, path escaping, iframe/srcdoc title proof and external JS resources).
func TestBrowserDOMSourceModesLive(t *testing.T) {
	if os.Getenv("RECONNER_BROWSER_TEST") == "" {
		t.Skip("browser E2E disabled; set RECONNER_BROWSER_TEST=1 and RECONNER_CHROME")
	}
	if findChromePath() == "" {
		t.Skip("no Chrome/Chromium binary available")
	}

	mux := http.NewServeMux()
	page := func(script string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><title>clean</title><body><div id=app></div><script>%s</script></body></html>`, script)
		}
	}
	mux.HandleFunc("/hash", page(`app.innerHTML=decodeURIComponent(location.hash.slice(1))`))
	mux.HandleFunc("/hash-param", page(`app.innerHTML=new URLSearchParams(location.hash.slice(1)).get('html')`))
	mux.HandleFunc("/name", page(`app.innerHTML=window.name`))
	mux.HandleFunc("/message", page(`addEventListener('message',e=>app.innerHTML=e.data)`))
	mux.HandleFunc("/frame", page(`app.innerHTML='<iframe srcdoc="'+new URLSearchParams(location.search).get('html')+'"></iframe>'`))
	mux.HandleFunc("/path/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		segment := strings.TrimPrefix(r.URL.Path, "/path/")
		fmt.Fprintf(w, `<html><title>clean</title><body><div id=app></div><script>app.innerHTML=%q</script></body></html>`, segment)
	})
	mux.HandleFunc("/asset.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprintf(w, `void('%s')`, r.URL.Query().Get("q"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	b := getXSSBrowser()
	if b == nil {
		t.Fatal("browser confirmer unexpectedly unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	for _, tc := range []struct {
		name, path, mode, param string
	}{
		{"raw hash", "/hash", "hash", ""},
		{"hash parameter", "/hash-param", "hash", "html"},
		{"window.name", "/name", "window.name", ""},
		{"postMessage", "/message", "postMessage", ""},
		{"path segment", "/path/seed", "path", "path:1"},
		{"iframe srcdoc", "/frame", "query", "html"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if pl, ok := b.ConfirmDOMSource(ctx, srv.URL+tc.path, tc.mode, tc.param, nil); !ok {
				t.Fatalf("real browser did not prove %s DOM source", tc.name)
			} else if !strings.Contains(pl, "alert(document.domain)") {
				t.Fatalf("reported PoC is not popup-capable: %q", pl)
			}
		})
	}

	if pl, ok := b.ConfirmScriptResource(ctx, insertionPoint{
		URL: srv.URL + "/asset.js?q=seed", Param: "q", Method: "GET", Location: "query",
	}, nil); !ok || !strings.Contains(pl, "alert(document.domain)") {
		t.Fatalf("external JavaScript reflection was not runtime-proven: ok=%v payload=%q", ok, pl)
	}
}
