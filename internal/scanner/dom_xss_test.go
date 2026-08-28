package scanner

import "testing"

// TestAnalyzeDOMXSSPrecise proves the static analyzer flags ONLY a direct
// URL-source → HTML-injection-sink flow, and stays silent on the noise classes
// that flooded before (one-hop minified vars, function-arg setTimeout, jQuery $()
// selectors, postMessage e.data, benign constant sinks).
func TestAnalyzeDOMXSSPrecise(t *testing.T) {
	// TRUE positives — source sits directly in an HTML-injection sink.
	for _, tp := range []string{
		`el.innerHTML = location.hash.slice(1);`,
		`document.write(location.search);`,
		`node.outerHTML = decodeURIComponent(location.href);`,
		`$(sel).html(window.name);`,
		// modern framework HTML sinks (compiled bundles):
		`return {dangerouslySetInnerHTML:{__html: location.hash}};`,
		`$sce.trustAsHtml(location.search)`,
		`frame.srcdoc = location.href;`,
	} {
		if hits := analyzeDOMXSS(tp, true); len(hits) == 0 {
			t.Errorf("expected a DOM-XSS hit for: %s", tp)
		}
	}

	// FALSE-positive classes that MUST stay silent now.
	for _, fp := range []string{
		`setTimeout(t, 300);`,                              // function-ref timer, not a string sink
		`$(e);`,                                            // jQuery selector, e is an element
		`window.addEventListener('message', e => box.innerHTML = e.data);`, // postMessage (origin-gated), not a URL source
		`var q = location.hash; render(q);`,               // one-hop into render() — not a sink
		`el.innerHTML = "<b>welcome</b>";`,                // constant
		`el.innerHTML = data.title;`,                       // server value, no URL source
		`location.href = e.data;`,                          // navigation, not an HTML sink
	} {
		if hits := analyzeDOMXSS(fp, true); len(hits) != 0 {
			t.Errorf("expected NO DOM-XSS hit for: %s (got %+v)", fp, hits)
		}
	}
}

// TestAnalyzeDOMXSSOneHop proves the bounded one-hop taint fires on real
// (un-minified) code but stays silent on minified single-letter vars and on flows
// that pass through a sanitizer.
func TestAnalyzeDOMXSSOneHop(t *testing.T) {
	pos := []string{
		`const userInput = location.hash; el.innerHTML = userInput;`,
		`let payloadValue = location.search; node.outerHTML = payloadValue;`,
	}
	for _, s := range pos {
		hits := analyzeDOMXSS(s, true)
		if len(hits) == 0 {
			t.Errorf("expected a one-hop DOM-XSS hit for: %s", s)
			continue
		}
		if !hits[0].OneHop {
			t.Errorf("expected OneHop=true for: %s", s)
		}
	}

	// deep=false (minified bundle) → one-hop MUST be off even for a good name.
	if hits := analyzeDOMXSS(`const userInput = location.hash; el.innerHTML = userInput;`, false); len(hits) != 0 {
		t.Errorf("one-hop must be disabled when deep=false, got %+v", hits)
	}

	// FALSE one-hop classes that MUST stay silent even with deep=true.
	for _, fp := range []string{
		`var a = location.hash; el.innerHTML = a;`,                                       // minified single-letter var
		`const userInput = location.hash; el.innerHTML = encodeURIComponent(userInput);`, // sanitizer between
		`const userInput = location.hash; el.textContent = userInput;`,                   // textContent is not an HTML sink
	} {
		if hits := analyzeDOMXSS(fp, true); len(hits) != 0 {
			t.Errorf("expected NO one-hop hit for: %s (got %+v)", fp, hits)
		}
	}
}
