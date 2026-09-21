package scanner

import (
	"strings"
	"testing"
)

// TestAnalyzeReflectionMultiOccurrence: input echoed in TWO places — safely
// HTML-encoded first, raw-executable second — must be judged by the strongest
// (executable) reflection, not the first one seen.
func TestAnalyzeReflectionMultiOccurrence(t *testing.T) {
	body := `<title>` + xssMarker + `&lt;&gt;</title><div>` + xssMarker + `'"<> x</div>`
	a := AnalyzeReflection(body)
	if !a.Reflected || a.Context != CtxHTMLText || !a.Executable {
		t.Fatalf("must pick the executable HTML-text reflection over the encoded one: %+v", a)
	}
}

func TestAnalyzeReflectionsRetainsDistinctContexts(t *testing.T) {
	body := `<title>` + xssMarker + `&lt;&gt;</title>` +
		`<input value="` + xssMarker + `'"<>">` +
		`<script>window.seed='` + xssMarker + `'"<>'</script>`
	all := AnalyzeReflectionsWithMarker(body, xssMarker)
	if len(all) != 3 {
		t.Fatalf("wanted three distinct reflection contexts, got %d: %+v", len(all), all)
	}
	seen := map[string]bool{}
	for _, a := range all {
		seen[a.Context] = true
	}
	for _, want := range []string{CtxRCDATA, CtxQuotedAttr, CtxJSString} {
		if !seen[want] {
			t.Errorf("missing %s reflection: %+v", want, all)
		}
	}
	if all[0].Context == CtxRCDATA {
		t.Fatalf("encoded RCDATA copy must not outrank executable reflections: %+v", all)
	}
}

func TestAnalyzeReflectionsDeduplicatesEquivalentCopies(t *testing.T) {
	body := `<div>` + xssMarker + `'"<>` + `</div><p>` + xssMarker + `'"<>` + `</p>`
	all := AnalyzeReflectionsWithMarker(body, xssMarker)
	if len(all) != 1 || all[0].Context != CtxHTMLText {
		t.Fatalf("equivalent HTML-text copies should share one payload ladder: %+v", all)
	}
}

func TestRawTextAndSrcdocContexts(t *testing.T) {
	for _, tc := range []struct {
		body, close string
	}{
		{`<xmp>` + xssMarker + `'"<>` + `</xmp>`, `</xmp>`},
		{`<iframe>` + xssMarker + `'"<>` + `</iframe>`, `</iframe>`},
		{`<noframes>` + xssMarker + `'"<>` + `</noframes>`, `</noframes>`},
	} {
		a := AnalyzeReflection(tc.body)
		if a.Context != CtxRAWTEXT || a.CloseTag != tc.close || !a.Executable {
			t.Errorf("RAWTEXT state misclassified: %+v", a)
		}
	}

	a := AnalyzeReflection(`<iframe srcdoc="` + xssMarker + `'"<>"></iframe>`)
	if a.Context != CtxSrcDoc || a.TagName != "iframe" || a.AttrName != "srcdoc" || !a.Executable {
		t.Fatalf("iframe srcdoc nested-HTML context missed: %+v", a)
	}
}

// TestAnalyzeReflectionSingleQuotedAttr: a single-quoted attribute is executable
// only when the SINGLE quote survives — the old fixed-'"' check missed this.
func TestAnalyzeReflectionSingleQuotedAttr(t *testing.T) {
	// single quote survives → executable, quote recorded as '\''
	a := AnalyzeReflection(`<input value='` + xssMarker + `'"<>'>`)
	if a.Context != CtxQuotedAttr || a.Quote != '\'' || !a.Executable {
		t.Fatalf("single-quoted attr with surviving ' must be executable: %+v", a)
	}
	// A double-quoted attr where ONLY the single quote survives (double is encoded)
	// must NOT be executable — you cannot break a "-delimited value with a '.
	b := AnalyzeReflection(`<input value="` + xssMarker + `'&quot;&lt;&gt;">`)
	if b.Executable {
		t.Fatalf("double-quoted attr without a surviving double quote must NOT be executable: %+v", b)
	}
}

// TestAnalyzeReflectionCSSBreakout: reflection inside <style> is executable when
// the angle brackets survive (</style> breakout), inert when they are encoded.
func TestAnalyzeReflectionCSSBreakout(t *testing.T) {
	a := AnalyzeReflection(`<style>.a{x:` + xssMarker + `'"<>}</style>`)
	if a.Context != CtxCSS || !a.Executable {
		t.Fatalf("css with surviving <> must be executable via </style> breakout: %+v", a)
	}
	b := AnalyzeReflection(`<style>.a{x:` + xssMarker + `&lt;&gt;}</style>`)
	if b.Context != CtxCSS || b.Executable {
		t.Fatalf("css with encoded <> must NOT be executable: %+v", b)
	}
}

// TestAnalyzeReflectionURLAttr: a URL-bearing attribute (href/src/…) is
// classified as a URL sink with its quote recorded, and breaking the quote is
// executable.
func TestAnalyzeReflectionURLAttr(t *testing.T) {
	for _, attr := range []string{"href", "src", "formaction", "xlink:href"} {
		a := AnalyzeReflection(`<a ` + attr + `="` + xssMarker + `'"<>">`)
		if a.Context != CtxURL || a.Quote != '"' || !a.Executable {
			t.Fatalf("%s value must classify as executable URL sink: %+v", attr, a)
		}
	}
	// A non-URL attribute stays a quoted attribute, not a URL sink.
	a := AnalyzeReflection(`<div title="` + xssMarker + `'"<>">`)
	if a.Context != CtxQuotedAttr {
		t.Fatalf("non-URL attr must not be a URL sink: %+v", a)
	}
}

func TestJavascriptURLCapabilityUsesTagAndAttributeSemantics(t *testing.T) {
	for _, tc := range []struct {
		tag, attr string
		want      bool
	}{
		{"a", "href", true},
		{"area", "href", true},
		{"link", "href", false},
		{"form", "action", true},
		{"div", "action", false},
		{"button", "formaction", true},
		{"iframe", "src", true},
		{"script", "src", false},
		{"img", "src", false},
		{"object", "data", true},
	} {
		if got := javascriptURLCapable(tc.tag, tc.attr); got != tc.want {
			t.Errorf("%s[%s] javascript capability=%t want %t", tc.tag, tc.attr, got, tc.want)
		}
	}
	link := AnalyzeReflection(`<link href="` + xssMarker + `&#39;&quot;&lt;&gt;">`)
	if link.URLScheme || link.Executable {
		t.Fatalf("link[href] must not inherit anchor javascript-URL semantics: %+v", link)
	}
}

// TestAnalyzeReflectionEncodedStillRejected: entity encoding neutralises HTML
// syntax, except at browser-decoded subcontexts such as an event-handler JS string
// or a URL value controlled from its first byte.
func TestAnalyzeReflectionEncodedStillRejected(t *testing.T) {
	for _, body := range []string{
		`<div>` + xssMarker + `&lt;&gt;&quot;&#39;</div>`,
		`<input value="` + xssMarker + `&quot;&lt;&gt;">`,
		`<a href="/search?q=` + xssMarker + `&quot;&lt;&gt;">`,
	} {
		if a := AnalyzeReflection(body); a.Executable {
			t.Fatalf("encoded reflection must never be executable: %q → %+v", body, a)
		}
	}
}

func TestAnalyzeReflectionBrowserDecodedSubcontexts(t *testing.T) {
	// HTML entities are decoded before an event-handler is compiled as JS. The
	// encoded apostrophe therefore still breaks the inner JS string.
	a := AnalyzeReflection(`<button onclick="run('` + xssMarker + `&#39;&quot;&lt;&gt;')">`)
	if a.Context != CtxEventHandler || a.JSQuote != '\'' || !a.Executable || !strings.Contains(a.Decoded, "'") {
		t.Fatalf("entity-decoded event-handler breakout missed: %+v", a)
	}
	// No punctuation is required when the attacker owns the beginning of href:
	// javascript: is a runtime execution primitive even if angle brackets/quotes
	// are encoded.
	b := AnalyzeReflection(`<a href="` + xssMarker + `&#39;&quot;&lt;&gt;">`)
	if b.Context != CtxURL || !b.URLScheme || !b.Executable {
		t.Fatalf("scheme-controllable URL sink missed: %+v", b)
	}
}

func TestEventHandlerDistinguishesHTMLEntitiesFromOtherEscapes(t *testing.T) {
	for _, encodedQuote := range []string{"%27", "%2527", `\x27`, `\u0027`} {
		body := `<button onclick="run('` + xssMarker + encodedQuote + `&quot;&lt;&gt;')">`
		a := AnalyzeReflection(body)
		if a.Context != CtxEventHandler || a.Executable {
			t.Errorf("%s is not decoded by the outer HTML tokenizer into a JS delimiter: %+v", encodedQuote, a)
		}
	}
	entity := AnalyzeReflection(`<button onclick="run('` + xssMarker + `&#39;&quot;&lt;&gt;')">`)
	if !entity.Executable || !strings.Contains(entity.Decoded, "'") {
		t.Fatalf("HTML entity must still be decoded before event-handler compilation: %+v", entity)
	}
}

func TestJSQuoteEscapingIsBreakableWhenBackslashSurvives(t *testing.T) {
	marker := "rcnslash"
	reflected := strings.Replace(xssProbeFor(marker), "'", `\'`, 1)
	a := analyzeReflectionProbe(`<script>const value='`+reflected+`';</script>`, marker, xssProbeSuffix)
	if a.Context != CtxJSString || a.JSQuote != '\'' || !a.Executable ||
		!strings.Contains(a.Escaped, "'") || !strings.Contains(a.Surviving, `\`) {
		t.Fatalf("quote-only escaping with a raw backslash must enable double-escape verification: %+v", a)
	}
	ladder := xssBrowserPayloadsForAnalysis(&a)
	if len(ladder) == 0 || !strings.HasPrefix(ladder[0], `\'`) {
		t.Fatalf("unsafe JS escaping needs the backslash-prefixed proof first: %v", ladder)
	}
}

func TestSrcdocRecognizesNestedHTMLAfterEntityDecoding(t *testing.T) {
	a := AnalyzeReflection(`<iframe srcdoc="` + xssMarker + `&#39;&quot;&lt;&gt;"></iframe>`)
	if a.Context != CtxSrcDoc || !a.Executable || !strings.Contains(a.Decoded, "<>") {
		t.Fatalf("srcdoc must model its second HTML parse: %+v", a)
	}
	doubleEncoded := AnalyzeReflection(`<iframe srcdoc="` + xssMarker + `%2527%2522%253c%253e"></iframe>`)
	if doubleEncoded.Executable {
		t.Fatalf("double percent encoding does not create nested HTML by itself: %+v", doubleEncoded)
	}
}

func TestContextTokenizerHandlesEqualsAndScriptComments(t *testing.T) {
	a := AnalyzeReflection(`<div data-x="a=b" title='` + xssMarker + `\'"<>` + `'>`)
	if a.Context != CtxQuotedAttr || a.AttrName != "title" || a.Quote != '\'' {
		t.Fatalf("attribute tokenizer was confused by '=' in a previous value: %+v", a)
	}
	b := AnalyzeReflection("<script nonce=\"x\">// ' ignored\nconst value=\"" + xssMarker + `'"<>";</script>`)
	if b.Context != CtxJSString || b.JSQuote != '"' || !b.Executable {
		t.Fatalf("JS comment/opening-tag quotes confused JS string state: %+v", b)
	}
}
