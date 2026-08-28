package scanner

import (
	"context"
	"html"
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

	// vulnerable: raw reflection in HTML text → VERIFIED
	vuln := reflectApp(false, func(s string) string { return "<div>" + s + "</div>" })
	defer vuln.Close()
	r := v.Verify(ctx, VulnerabilityCandidate{Type: "xss", URL: vuln.URL + "/?q=x", Parameter: "q"})
	if r.Verdict != VerifyVerified {
		t.Fatalf("raw HTML reflection must VERIFY: %+v", r)
	}
	if !strings.Contains(r.Evidence, "html_text") {
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

	// Control: the SAME raw reflection served as text/html IS a real XSS → VERIFIED.
	// Guards against the gate over-rejecting and masking genuine findings.
	htmlSink := jsonReflectApp("text/html", true)
	defer htmlSink.Close()
	r3 := v.Verify(ctx, VulnerabilityCandidate{Type: "xss", URL: htmlSink.URL + "/?q=x", Parameter: "q"})
	if r3.Verdict != VerifyVerified {
		t.Fatalf("raw reflection in a text/html response must still VERIFY: %+v", r3)
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
