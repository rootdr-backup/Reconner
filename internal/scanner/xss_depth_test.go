package scanner

import "testing"

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

// TestAnalyzeReflectionEncodedStillRejected: the core FP defense is preserved —
// a fully HTML-encoded reflection is never executable, in any context.
func TestAnalyzeReflectionEncodedStillRejected(t *testing.T) {
	for _, body := range []string{
		`<div>` + xssMarker + `&lt;&gt;&quot;&#39;</div>`,
		`<input value="` + xssMarker + `&quot;&lt;&gt;">`,
		`<a href="` + xssMarker + `&lt;&gt;">`,
	} {
		if a := AnalyzeReflection(body); a.Executable {
			t.Fatalf("encoded reflection must never be executable: %q → %+v", body, a)
		}
	}
}
