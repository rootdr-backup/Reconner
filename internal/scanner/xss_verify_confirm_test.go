package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

var reStripTag = regexp.MustCompile(`(?i)<\s*/?\s*[a-z][a-z0-9]*[^>]*>`)

// TestXSSVerifierRequiresRealExecution proves the FP fix: a partial sanitizer
// that strips complete <tag> sequences but leaves STRAY '<'/'>' characters makes
// the probe's breakout chars "survive" (so the old char-only check verified it) —
// yet no real element ever forms. The confirm stage injects a marker element,
// sees it stripped, and REJECTS. This is the dominant nuclei/dalfox reflected-XSS
// false positive.
func TestXSSVerifierRequiresRealExecution(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("q")
		v = reStripTag.ReplaceAllString(v, "") // strip real tags, keep stray < >
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<div>results for " + v + "</div>"))
	}))
	defer srv.Close()

	v := NewXSSContextVerifier(nil)
	res := v.Verify(context.Background(), VulnerabilityCandidate{Type: "xss", URL: srv.URL + "/?q=x", Parameter: "q"})
	if res.Verdict == VerifyVerified {
		t.Fatalf("a reflection where NO real tag forms must NOT verify (nuclei FP class): %+v", res)
	}

	// Control: a genuinely raw reflection (no stripping) must still VERIFY, so the
	// stricter confirm did not break real detection.
	raw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<div>results for " + r.URL.Query().Get("q") + "</div>"))
	}))
	defer raw.Close()
	res2 := v.Verify(context.Background(), VulnerabilityCandidate{Type: "xss", URL: raw.URL + "/?q=x", Parameter: "q"})
	if res2.Verdict != VerifyVerified {
		t.Fatalf("a genuinely executable raw reflection must still VERIFY: %+v", res2)
	}
}
