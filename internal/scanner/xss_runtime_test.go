package scanner

import (
	"strings"
	"testing"
)

func TestRuntimeDOMInstrumentationCoversCoreSinks(t *testing.T) {
	script := runtimeDOMInstrumentationScript(`rcn"</script>marker`)
	for _, sink := range []string{
		"Element.innerHTML",
		"Element.outerHTML",
		"Element.insertAdjacentHTML",
		"Element.setAttribute",
		"Element.setHTMLUnsafe",
		"ShadowRoot.setHTMLUnsafe",
		"Document.write",
		"Document.parseHTMLUnsafe",
		"Range.createContextualFragment",
		"DOMParser.parseFromString",
		"HTMLIFrameElement.srcdoc",
		"HTMLScriptElement.src",
		"window.setTimeout",
	} {
		if !strings.Contains(script, sink) {
			t.Errorf("runtime instrumentation is missing %s", sink)
		}
	}
	// json.Marshal must keep an attacker-controlled marker from terminating the
	// generated JavaScript string literal.
	if strings.Contains(script, `const marker="rcn"</script>`) {
		t.Fatal("marker was embedded without JSON escaping")
	}
}

func TestRuntimeDOMHitSummaryDeduplicates(t *testing.T) {
	hits := []runtimeDOMHit{
		{Sink: "Element.innerHTML"},
		{Sink: "Element.innerHTML"},
		{Sink: "Document.write"},
	}
	if got := runtimeDOMHitSummary(hits); got != "Element.innerHTML -> Document.write" {
		t.Fatalf("unexpected runtime trace: %q", got)
	}
}

func TestXSSProofObserverIsNonceScoped(t *testing.T) {
	script := xssProofObserverScript(`RCNX"</script>`)
	for _, want := range []string{xssProofResultKey, "addEventListener", "__reconnerXSSProof"} {
		if !strings.Contains(script, want) {
			t.Fatalf("proof observer missing %q: %s", want, script)
		}
	}
	if strings.Contains(script, `const nonce=RCNX"</script>`) {
		t.Fatal("nonce was embedded without JSON escaping")
	}
}
