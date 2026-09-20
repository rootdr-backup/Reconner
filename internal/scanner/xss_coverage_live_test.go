package scanner

import (
	"context"
	"fmt"
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
		t.Skip("no Chrome/Chromium binary available")
	}

	contexts := map[string]string{
		"html-text":       `<html><title>clean</title><body><div>%s</div></body></html>`,
		"double-attr":     `<html><title>clean</title><body><input value="%s"></body></html>`,
		"single-attr":     `<html><title>clean</title><body><input value='%s'></body></html>`,
		"unquoted-attr":   `<html><title>clean</title><body><input value=%s></body></html>`,
		"textarea-rcdata": `<html><title>clean</title><body><textarea>%s</textarea></body></html>`,
		"title-rcdata":    `<html><title>%s</title><body></body></html>`,
		"style-rawtext":   `<html><title>clean</title><style>body{color:%s}</style><body></body></html>`,
		"html-comment":    `<html><title>clean</title><body><!--%s--></body></html>`,
		"js-single":       `<html><title>clean</title><script>window.seed='%s'</script></html>`,
		"js-double":       `<html><title>clean</title><script>window.seed="%s"</script></html>`,
		"js-template":     "<html><title>clean</title><script>window.seed=`%s`</script></html>",
		"js-expression":   `<html><title>clean</title><script>window.seed=0%s</script></html>`,
		"url-href":        `<html><title>clean</title><body><a href="%s">go</a></body></html>`,
	}

	mux := http.NewServeMux()
	for name, page := range contexts {
		page := page
		mux.HandleFunc("/"+name, func(w http.ResponseWriter, r *http.Request) {
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
	for name := range contexts {
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
	if coverage < 80 {
		t.Fatalf("XSS context coverage %.1f%% is below the 80%% release gate", coverage)
	}
}
