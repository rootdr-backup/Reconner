package scanner

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAnalyzeReflectionContexts(t *testing.T) {
	// HTML text, raw breakout → executable
	a := AnalyzeReflection(`<div>hello rcnx9k7'"<> world</div>`)
	if !a.Reflected || a.Context != CtxHTMLText || !a.Executable {
		t.Fatalf("html-text raw must be executable: %+v", a)
	}
	// HTML text, encoded → NOT executable
	b := AnalyzeReflection(`<div>hello rcnx9k7` + html.EscapeString(`'"<>`) + `</div>`)
	if !b.Reflected || !b.Encoded || b.Executable {
		t.Fatalf("encoded reflection must NOT be executable: %+v", b)
	}
	// quoted attribute, quote survives → executable
	c := AnalyzeReflection(`<input value="rcnx9k7'"<>">`)
	if c.Context != CtxQuotedAttr || !c.Executable {
		t.Fatalf("quoted-attr with surviving quote must be executable: %+v", c)
	}
	// JS string context
	d := AnalyzeReflection(`<script>var x='rcnx9k7'"<>';</script>`)
	if d.Context != CtxJSString || !d.Executable {
		t.Fatalf("js-string must be executable: %+v", d)
	}
	// not reflected
	e := AnalyzeReflection(`<div>nothing here</div>`)
	if e.Reflected {
		t.Fatal("must not report reflection when marker absent")
	}
}

// mock reflector: echoes the `q` param either RAW (vulnerable) or HTML-escaped.
func reflectApp(encode bool, wrap func(string) string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("q")
		if encode {
			v = html.EscapeString(v)
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(wrap(v)))
	}))
}

func TestXSSVerifierExecutableVsEncoded(t *testing.T) {
	withLoopbackAllowed(t)
	ctx := context.Background()
	v := NewXSSContextVerifier(nil)

	// vulnerable: raw reflection is retained, but only Chromium may VERIFY it.
	vuln := reflectApp(false, func(s string) string { return "<div>" + s + "</div>" })
	defer vuln.Close()
	r := v.Verify(ctx, VulnerabilityCandidate{Type: "xss", URL: vuln.URL + "/?q=x", Parameter: "q"})
	if r.Verdict != VerifyInconclusive && r.Verdict != VerifyVerified {
		t.Fatalf("raw HTML reflection must remain a candidate or browser-verify: %+v", r)
	}
	if r.Verdict == VerifyVerified && r.Method != "xss-browser" {
		t.Fatalf("only runtime browser proof may verify reflected XSS: %+v", r)
	}
	if !strings.Contains(r.Evidence+r.Reason, "html_text") {
		t.Fatalf("evidence must name the context: %q", r.Evidence)
	}

	// safe: HTML-encoded reflection → REJECTED (the key FP defense)
	safe := reflectApp(true, func(s string) string { return "<div>" + s + "</div>" })
	defer safe.Close()
	r2 := v.Verify(ctx, VulnerabilityCandidate{Type: "xss", URL: safe.URL + "/?q=x", Parameter: "q"})
	if r2.Verdict != VerifyRejected {
		t.Fatalf("encoded reflection must be REJECTED (no false positive): %+v", r2)
	}

	// not reflected at all → INCONCLUSIVE
	none := reflectApp(false, func(_ string) string { return "<div>static</div>" })
	defer none.Close()
	r3 := v.Verify(ctx, VulnerabilityCandidate{Type: "xss", URL: none.URL + "/?q=x", Parameter: "q"})
	if r3.Verdict != VerifyInconclusive {
		t.Fatalf("non-reflected must be INCONCLUSIVE: %+v", r3)
	}
}

// jsonReflectApp echoes the `q` param RAW into a JSON body with the given
// Content-Type, optionally adding X-Content-Type-Options: nosniff. This
// reproduces the ably.com report: GET …?clientId="};alert(document.domain);//
// reflected into {"clientId":"…"} with Content-Type: application/json + nosniff.
// The breakout characters survive raw in the body (JSON does not encode < or >),
// so body-only analysis would call it executable — but a browser never renders a
// JSON response as HTML, so it is inert.
func jsonReflectApp(contentType string, nosniff bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", contentType)
		if nosniff {
			w.Header().Set("X-Content-Type-Options", "nosniff")
		}
		_, _ = w.Write([]byte(`{"clientId":"` + v + `"}`))
	}))
}

func TestXSSVerifierRejectsJSONReflection(t *testing.T) {
	withLoopbackAllowed(t)
	ctx := context.Background()
	v := NewXSSContextVerifier(nil)

	// The exact ably.com shape: JSON body + nosniff. Must be REJECTED, not verified.
	jsonNoSniff := jsonReflectApp("application/json; charset=utf-8", true)
	defer jsonNoSniff.Close()
	r := v.Verify(ctx, VulnerabilityCandidate{Type: "xss", URL: jsonNoSniff.URL + "/?q=x", Parameter: "q"})
	if r.Verdict != VerifyRejected {
		t.Fatalf("JSON+nosniff reflection must be REJECTED (ably.com FP): %+v", r)
	}
	if !strings.Contains(r.Reason, "application/json") {
		t.Fatalf("rejection reason must name the non-HTML content type: %q", r.Reason)
	}

	// JSON without nosniff is still a declared non-HTML type → still inert.
	jsonOnly := jsonReflectApp("application/json", false)
	defer jsonOnly.Close()
	r2 := v.Verify(ctx, VulnerabilityCandidate{Type: "xss", URL: jsonOnly.URL + "/?q=x", Parameter: "q"})
	if r2.Verdict != VerifyRejected {
		t.Fatalf("application/json reflection must be REJECTED even without nosniff: %+v", r2)
	}

	// Control: the SAME raw reflection served as text/html remains a strong
	// candidate, or is verified when Chromium is available.
	// Guards against the gate over-rejecting and masking genuine findings.
	htmlSink := jsonReflectApp("text/html", true)
	defer htmlSink.Close()
	r3 := v.Verify(ctx, VulnerabilityCandidate{Type: "xss", URL: htmlSink.URL + "/?q=x", Parameter: "q"})
	if r3.Verdict != VerifyInconclusive && r3.Verdict != VerifyVerified {
		t.Fatalf("raw HTML reflection must remain a candidate or browser-verify: %+v", r3)
	}
	if r3.Verdict == VerifyVerified && r3.Method != "xss-browser" {
		t.Fatalf("only browser proof may verify HTML reflection: %+v", r3)
	}
}

func TestXSSVerifierRejectsPercentEncodedOGURLReflection(t *testing.T) {
	withLoopbackAllowed(t)
	// Reproduces tirana-airport.com: the application publishes the requested URL
	// in og:url, but keeps every query metacharacter percent-encoded. The marker
	// text is visible in source; it never leaves the meta content attribute.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, `<!doctype html><html><head><meta name="url" property="og:url" content="https://example.test/?`+
			r.URL.Query().Encode()+`"></head><body><script src="/assets/app.js"></script></body></html>`)
	}))
	defer srv.Close()

	v := NewXSSContextVerifier(nil)
	res := v.Verify(context.Background(), VulnerabilityCandidate{
		Type: "xss", Subtype: "reflected", URL: srv.URL + "/?userid=x", Parameter: "userid",
	})
	if res.Verdict != VerifyRejected {
		t.Fatalf("percent-encoded og:url reflection must be rejected, not confirmed: %+v", res)
	}
}

func TestCheckParamReflectionContentTypeGate(t *testing.T) {
	withLoopbackAllowed(t)

	// A canary echoed into a JSON response is NOT an HTML-context reflected param.
	jsonApp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write([]byte(`{"echo":"` + r.URL.Query().Get("q") + `"}`))
	}))
	defer jsonApp.Close()
	if r, _ := checkParamReflection(jsonApp.URL+"/?q=seed", "q"); r {
		t.Fatal("reflection into a JSON response must NOT count as a reflected parameter")
	}

	// The same echo in an HTML document IS a reflected parameter.
	htmlApp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<p>" + r.URL.Query().Get("q") + "</p>"))
	}))
	defer htmlApp.Close()
	if r, _ := checkParamReflection(htmlApp.URL+"/?q=seed", "q"); !r {
		t.Fatal("verbatim reflection into an HTML body must count as a reflected parameter")
	}
}

func TestBrowserRenderMIMEGates(t *testing.T) {
	if !browserRendersAsHTML("image/svg+xml", `<svg xmlns="http://www.w3.org/2000/svg"></svg>`, true) {
		t.Fatal("an SVG document remains an active browser document under nosniff")
	}
	if !browserRendersAsHTML("application/xml", `<svg xmlns="http://www.w3.org/2000/svg"></svg>`, true) {
		t.Fatal("XML carrying an SVG root must be treated as an active SVG document")
	}
	if browserRendersAsHTML("application/json", `<svg onload=alert(1)>`, false) {
		t.Fatal("JSON must never become an HTML/SVG sink from body bytes alone")
	}
	for _, ct := range []string{"application/javascript", "text/javascript; charset=utf-8", "application/example+javascript"} {
		if !scriptLikeContentType(ct) {
			t.Fatalf("script MIME not recognized: %q", ct)
		}
	}
	if scriptLikeContentType("application/json") {
		t.Fatal("JSON must not be classified as an executable script resource")
	}
}

func TestXSSVerifierKeepsReflectedJavaScriptForRuntimeProof(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write([]byte(`callback("` + r.URL.Query().Get("q") + `")`))
	}))
	defer srv.Close()

	// Exercise the deterministic phase directly: a JS resource is not safe merely
	// because top-level navigation does not render it as HTML. It must be retained
	// for ConfirmScriptResource instead of being falsely rejected.
	v := NewXSSContextVerifier(nil)
	res := v.verifyBrowserless(context.Background(), VulnerabilityCandidate{
		Type: "xss", Subtype: "reflected", URL: srv.URL + "/asset.js?q=x", Parameter: "q",
	})
	if res.Verdict != VerifyInconclusive || res.Method != "xss-script-resource" {
		t.Fatalf("reflected JS endpoint must be queued for script-resource proof: %+v", res)
	}
}

func TestXSSVerifierReplaysPOSTFormInsertionPoint(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<main>"+r.Form.Get("q")+"</main>")
	}))
	defer srv.Close()

	v := NewXSSContextVerifier(nil)
	res := v.verifyBrowserless(context.Background(), VulnerabilityCandidate{
		Type: "xss", Subtype: "reflected", URL: srv.URL, Method: "POST",
		Parameter: "q", Location: "body",
	})
	if res.Verdict != VerifyInconclusive || res.Confidence < 85 {
		t.Fatalf("POST form reflection must use its real insertion point and remain a strong runtime candidate: %+v", res)
	}
}

func TestXSSVerifierDoesNotClaimCSPBlockedInlineExecution(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'nonce-server-only'")
		_, _ = io.WriteString(w, "<main>"+r.URL.Query().Get("q")+"</main>")
	}))
	defer srv.Close()

	v := NewXSSContextVerifier(nil)
	res := v.verifyBrowserless(context.Background(), VulnerabilityCandidate{
		Type: "xss", Subtype: "reflected", URL: srv.URL + "/?q=x", Parameter: "q",
	})
	if res.Verdict != VerifyInconclusive {
		t.Fatalf("raw HTML injection blocked by nonce-only CSP needs runtime proof: %+v", res)
	}
}
