package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"
)

// TestBrowserXSSContextCoverageLive is the release coverage gate for reflected
// XSS. It measures execution—not string reflection—across the major browser
// contexts documented by PortSwigger/OWASP. The percentage is deliberately tied
// to this named, reviewable matrix; it is not presented as a universal web-wide
// detection percentage.
func TestBrowserXSSContextCoverageLive(t *testing.T) {
	if os.Getenv("RECONNER_BROWSER_TEST") == "" {
		t.Skip("browser E2E disabled; set RECONNER_BROWSER_TEST=1 and RECONNER_CHROME")
	}
	if findChromePath() == "" {
		t.Fatal("browser coverage was explicitly required but no Chrome/Chromium binary is available")
	}

	contexts := []struct{ name, page string }{
		{"html-text", `<html><title>clean</title><body><div>%s</div></body></html>`},
		{"double-attr", `<html><title>clean</title><body><input value="%s"></body></html>`},
		{"single-attr", `<html><title>clean</title><body><input value='%s'></body></html>`},
		{"unquoted-attr", `<html><title>clean</title><body><input value=%s></body></html>`},
		{"event-handler-single", `<html><title>clean</title><body><button onclick="window.seed('%s')">go</button></body></html>`},
		{"event-handler-double", `<html><title>clean</title><body><button onclick='window.seed("%s")'>go</button></body></html>`},
		{"textarea-rcdata", `<html><title>clean</title><body><textarea>%s</textarea></body></html>`},
		{"title-rcdata", `<html><title>%s</title><body></body></html>`},
		{"xmp-rawtext", `<html><title>clean</title><body><xmp>%s</xmp></body></html>`},
		{"noembed-rawtext", `<html><title>clean</title><body><noembed>%s</noembed></body></html>`},
		{"iframe-rawtext", `<html><title>clean</title><body><iframe>%s</iframe></body></html>`},
		{"iframe-srcdoc", `<html><title>clean</title><body><iframe srcdoc="%s"></iframe></body></html>`},
		{"style-rawtext", `<html><title>clean</title><style>body{color:%s}</style><body></body></html>`},
		{"html-comment", `<html><title>clean</title><body><!--%s--></body></html>`},
		{"js-single", `<html><title>clean</title><script>window.seed='%s'</script></html>`},
		{"js-double", `<html><title>clean</title><script>window.seed="%s"</script></html>`},
		{"js-template", "<html><title>clean</title><script>window.seed=`%s`</script></html>"},
		{"js-expression", `<html><title>clean</title><script>window.seed=0%s</script></html>`},
		{"url-href", `<html><title>clean</title><body><a href="%s">go</a></body></html>`},
	}

	mux := http.NewServeMux()
	for _, fixture := range contexts {
		page := fixture.page
		mux.HandleFunc("/"+fixture.name, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, page, r.URL.Query().Get("q"))
		})
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	b := getXSSBrowser()
	if b == nil {
		t.Fatal("browser confirmer unexpectedly unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	passed := 0
	for _, fixture := range contexts {
		name := fixture.name
		t.Run(name, func(t *testing.T) {
			probeURL := srv.URL + "/" + name + "?q=" + url.QueryEscape(xssProbe)
			resp, err := http.Get(probeURL) // #nosec G107 -- loopback test server only
			if err != nil {
				t.Fatalf("fetch probe: %v", err)
			}
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr != nil {
				t.Fatalf("read probe: %v", readErr)
			}
			analysis := AnalyzeReflection(string(body))
			if !analysis.Reflected || analysis.Context == CtxNone {
				t.Fatalf("context analyzer missed fixture: %+v", analysis)
			}
			ip := insertionPoint{URL: srv.URL + "/" + name + "?q=seed", Param: "q", Method: "GET", Location: "query"}
			if payload, ok := b.ConfirmInsertionWithAnalysis(ctx, ip, nil, &analysis); !ok {
				t.Errorf("browser did not prove execution in %s (%+v)", name, analysis)
			} else {
				passed++
				t.Logf("proved with %s", payload)
			}
		})
	}

	coverage := float64(passed) / float64(len(contexts)) * 100
	t.Logf("XSS context matrix coverage: %.1f%% (%d/%d)", coverage, passed, len(contexts))
	if coverage < 100 {
		t.Fatalf("XSS context coverage %.1f%% is below the 100%% named-matrix release gate", coverage)
	}
}

// TestBrowserXSSNegativeCoverageLive is the matching precision gate. These are
// local controls that look attractive to a reflection scanner but must never be
// promoted without nonce execution.
func TestBrowserXSSNegativeCoverageLive(t *testing.T) {
	if os.Getenv("RECONNER_BROWSER_TEST") == "" {
		t.Skip("browser E2E disabled; set RECONNER_BROWSER_TEST=1 and RECONNER_CHROME")
	}
	if findChromePath() == "" {
		t.Fatal("browser precision gate requires Chrome/Chromium")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/encoded-html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><title>clean</title><div>%s</div></html>`, html.EscapeString(r.URL.Query().Get("q")))
	})
	mux.HandleFunc("/encoded-attr", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><title>clean</title><input value="%s"></html>`, html.EscapeString(r.URL.Query().Get("q")))
	})
	mux.HandleFunc("/csp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'none'")
		fmt.Fprintf(w, `<html><title>clean</title><div>%s</div></html>`, r.URL.Query().Get("q"))
	})
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": r.URL.Query().Get("q")})
	})
	mux.HandleFunc("/text-content", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html><title>clean</title><div id=x></div><script>x.textContent=new URLSearchParams(location.search).get('q')</script></html>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	b := getXSSBrowser()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	for _, route := range []string{"encoded-html", "encoded-attr", "csp", "json", "text-content"} {
		t.Run(route, func(t *testing.T) {
			probeURL := srv.URL + "/" + route + "?q=" + url.QueryEscape(xssProbe)
			resp, err := http.Get(probeURL) // #nosec G107 -- loopback fixture only
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			var analysis *ReflectionAnalysis
			if a := AnalyzeReflection(string(body)); a.Reflected {
				analysis = &a
			}
			ip := insertionPoint{URL: srv.URL + "/" + route + "?q=seed", Param: "q", Method: "GET", Location: "query"}
			if route == "text-content" {
				if !b.DOMReflectsInsertion(ctx, ip, nil) {
					t.Fatal("textContent control should remain visible to reflection inventory")
				}
				if trace := b.RuntimeTrace(ip, nil); trace != "" {
					t.Fatalf("safe textContent must not be classified as an injection sink: %q", trace)
				}
				return
			}
			if payload, ok := b.ConfirmInsertionWithAnalysis(ctx, ip, nil, analysis); ok {
				t.Fatalf("safe control executed payload %q", payload)
			}
		})
	}
}
