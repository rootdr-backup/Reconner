package scanner

import "strings"

import "testing"

// TestContextClassifyExtended proves the new HTML-comment and RCDATA (textarea/
// title) contexts are detected, so a reflection there gets the RIGHT breakout
// instead of being mis-handled (a real-world XSS sink that was previously missed).
func TestContextClassifyExtended(t *testing.T) {
	cases := []struct {
		before   string
		wantCtx  string
		wantClos string
	}{
		{`<!-- user note: `, CtxComment, ""},
		{`<title>search results for `, CtxRCDATA, "</title>"},
		{`<textarea>draft: `, CtxRCDATA, "</textarea>"},
		{`<div>hello `, CtxHTMLText, ""},
		{`<input value="`, CtxQuotedAttr, ""},
	}
	for _, c := range cases {
		ctx, _, closeTag := classifyContext(c.before)
		if ctx != c.wantCtx {
			t.Errorf("before=%q ctx=%q want %q", c.before, ctx, c.wantCtx)
		}
		if c.wantClos != "" && closeTag != c.wantClos {
			t.Errorf("before=%q closeTag=%q want %q", c.before, closeTag, c.wantClos)
		}
	}
}

// TestBuildExecPayloadsBreakout proves each context yields executing payloads with
// the correct breakout prefix, so the confirm stage sends vectors that actually
// escape the context (the "finds XSS but no popup" fix depends on this).
func TestBuildExecPayloadsBreakout(t *testing.T) {
	q := AnalyzeReflection(`<input value="` + xssMarker + `">`) // quoted-attr, double quote
	// The probe reflects into a quoted attribute; buildExecPayloads should prefix a
	// quote+close so the vectors break out of the attribute.
	q.Context = CtxQuotedAttr
	q.Quote = '"'
	pls := buildExecPayloads(q)
	if len(pls) == 0 {
		t.Fatal("no exec payloads for quoted-attr")
	}
	if !strings.HasPrefix(pls[0].Payload, `">`) {
		t.Errorf("quoted-attr vector must break the quote+tag, got %q", pls[0].Payload)
	}
	// URL sink offers a javascript: vector first.
	u := ReflectionAnalysis{Context: CtxURL, Quote: '"'}
	up := buildExecPayloads(u)
	if len(up) == 0 || !strings.HasPrefix(up[0].Payload, "javascript:") {
		t.Errorf("URL sink must offer a javascript: vector first, got %+v", up[:1])
	}
	// Every vector must carry a JS execution body — a report PoC must pop. Accept
	// direct calls (alert/confirm/print/eval) and obfuscated forms that still
	// reference document.domain (e.g. (alert)(document.domain), top[`al`+`ert`](…)).
	for _, p := range htmlTextExecLadder() {
		low := strings.ToLower(p.Payload)
		if !strings.Contains(low, "alert(") && !strings.Contains(low, "confirm(") &&
			!strings.Contains(low, "print()") && !strings.Contains(low, "eval(") &&
			!strings.Contains(low, "document.domain") {
			t.Errorf("payload has no JS execution body: %q", p.Payload)
		}
	}
}

// TestExecPayloadSurvived proves the raw-survival check: a tag vector counts only
// when its element forms as a live start tag AND its handler token is present raw.
func TestExecPayloadSurvived(t *testing.T) {
	p := xssExecPayload{Payload: `<svg onload=alert(document.domain)>`, Elem: "svg", Token: "onload"}
	if !execPayloadSurvived(`...<svg onload=alert(document.domain)>...`, p) {
		t.Error("live <svg onload=> must count as survived")
	}
	// handler stripped → not survived (element formed but no executing token).
	if execPayloadSurvived(`...<svg >...`, p) {
		t.Error("a <svg> with the handler stripped must NOT count as executable")
	}
	// reflected only inside a quoted attribute value → not a live tag.
	if execPayloadSurvived(`<meta content="<svg onload=alert(document.domain)>">`, p) {
		t.Error("payload trapped in a quoted attribute must NOT count as a live tag")
	}
	// Real regression: og:url reflects only the percent-encoded request URL while
	// the page independently contains many legitimate SVG icons. A global
	// strings.Contains("onload") + any-<svg> check joined those unrelated facts and
	// reported a working XSS even though no injected element existed.
	ogURL := `<meta name="url" property="og:url" content="https://example.test/?user=%22%3E%3Csvg+onload%3Dalert%28document.domain%29%3E">` +
		`<svg class="logo"><path d="M0 0"></path></svg><svg class="icon"></svg>`
	if execPayloadSurvived(ogURL, p) {
		t.Error("percent-encoded og:url reflection plus unrelated live SVGs must NOT count as XSS")
	}
	// Even a legitimate SVG event elsewhere must not match unless its exact
	// executable value is the injected one on the same subtree.
	if execPayloadSurvived(ogURL+`<svg onload="initLogo()"></svg>`, p) {
		t.Error("handler name on an unrelated SVG must not satisfy payload proof")
	}
}

func TestEveryTagPayloadUsesCorrelatedExecutionSignal(t *testing.T) {
	for _, p := range htmlTextExecLadder() {
		if p.Elem == "" {
			continue
		}
		if !execPayloadSurvived("<!doctype html><html><body>"+p.Payload+"</body></html>", p) {
			t.Errorf("live payload was not recognized: elem=%s payload=%q", p.Elem, p.Payload)
		}
	}
}
