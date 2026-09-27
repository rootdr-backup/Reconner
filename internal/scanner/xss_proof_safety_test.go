package scanner

import (
	"strings"
	"testing"
)

// Browser-confirmation payloads may show the requested Reconner proof popup, but
// must not turn that proof into data access or exfiltration.
func TestXSSBrowserPayloadsAreNonExfiltratingProofs(t *testing.T) {
	for _, payload := range xssBrowserPayloads() {
		lower := strings.ToLower(payload)
		if !strings.Contains(payload, "document.title") {
			t.Errorf("payload lacks the nonce proof sink: %q", payload)
		}
		if !strings.Contains(payload, "alert('reconner')") {
			t.Errorf("payload lacks the requested Reconner proof popup: %q", payload)
		}
		if !strings.Contains(payload, "postMessage") {
			t.Errorf("payload lacks the cross-frame nonce proof channel: %q", payload)
		}
		for _, forbidden := range []string{
			"confirm(", "prompt(", "document.cookie", "localstorage",
			"sessionstorage", "fetch(", "xmlhttprequest", "sendbeacon(",
		} {
			if strings.Contains(lower, forbidden) {
				t.Errorf("payload contains non-proof behavior %q: %q", forbidden, payload)
			}
		}
	}
}

// TestXSSBrowserPayloadsForAnalysisAreNonExfiltratingProofs extends the same
// invariant to xssBrowserPayloadsForAnalysis — the context-aware ladder
// actually used for the primary (browser-available) confirmation path, which
// the test above does not reach at all (it only iterates the flat
// context-less fallback list).
func TestXSSBrowserPayloadsForAnalysisAreNonExfiltratingProofs(t *testing.T) {
	contexts := []ReflectionAnalysis{
		{Context: CtxHTMLText},
		{Context: CtxQuotedAttr, Quote: '"'},
		{Context: CtxQuotedAttr, Quote: '\''},
		{Context: CtxURL, Quote: '"', URLScheme: true},
		{Context: CtxUnquotedAttr},
		{Context: CtxUnquotedAttr, AttrName: "value"},
		{Context: CtxEventHandler, Quote: '"', JSQuote: '"'},
		{Context: CtxJSString, JSQuote: '\''},
		{Context: CtxJSString, JSQuote: '`'},
		{Context: CtxJSExpr},
		{Context: CtxCSS},
		{Context: CtxComment},
		{Context: CtxRCDATA, CloseTag: "</textarea>"},
		{Context: CtxRAWTEXT, CloseTag: "</xmp>"},
		{Context: CtxSrcDoc, Quote: '"'},
	}
	for _, a := range contexts {
		for _, payload := range xssBrowserPayloadsForAnalysis(&a) {
			lower := strings.ToLower(payload)
			if !strings.Contains(payload, "document.title") {
				t.Errorf("[%s] payload lacks the nonce proof sink: %q", a.Context, payload)
			}
			if !strings.Contains(payload, "alert('reconner')") {
				t.Errorf("[%s] payload lacks the requested Reconner proof popup: %q", a.Context, payload)
			}
			if !strings.Contains(payload, "postMessage") {
				t.Errorf("[%s] payload lacks the cross-frame nonce proof channel: %q", a.Context, payload)
			}
			for _, forbidden := range []string{
				"confirm(", "prompt(", "document.cookie", "localstorage",
				"sessionstorage", "fetch(", "xmlhttprequest", "sendbeacon(",
			} {
				if strings.Contains(lower, forbidden) {
					t.Errorf("[%s] payload contains non-proof behavior %q: %q", a.Context, forbidden, payload)
				}
			}
		}
	}
}
