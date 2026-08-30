package scanner

import (
	"context"
	"testing"
)

// TestAnalyzeDOMXSSPrecise proves direct URL and unguarded postMessage flows reach
// real markup/code sinks while unrelated values and non-sinks stay silent.
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
		`setTimeout(location.hash, 0);`,
		`window.addEventListener('message', e => box.innerHTML = e.data);`,
	} {
		if hits := analyzeDOMXSS(tp, true); len(hits) == 0 {
			t.Errorf("expected a DOM-XSS hit for: %s", tp)
		}
	}

	// FALSE-positive classes that MUST stay silent now.
	for _, fp := range []string{
		`setTimeout(t, 300);`,               // function-ref timer, not a string sink
		`$(e);`,                             // jQuery selector, e is an element
		`var q = location.hash; render(q);`, // one-hop into render() — not a sink
		`el.innerHTML = "<b>welcome</b>";`,  // constant
		`el.innerHTML = data.title;`,        // server value, no attacker source
		`location.href = e.data;`,           // no message-listener context
	} {
		if hits := analyzeDOMXSS(fp, true); len(hits) != 0 {
			t.Errorf("expected NO DOM-XSS hit for: %s (got %+v)", fp, hits)
		}
	}
}

// TestAnalyzeDOMXSSOneHop proves ordered taint follows both readable and minified
// multi-hop aliases, even in the shallow/raw-bundle mode, while sanitizer and
// safe-sink flows remain silent.
func TestAnalyzeDOMXSSOneHop(t *testing.T) {
	pos := []string{
		`const userInput = location.hash; el.innerHTML = userInput;`,
		`let payloadValue = location.search; node.outerHTML = payloadValue;`,
		`var a=location.hash;var b=decodeURIComponent(a);var c=b;el.innerHTML=c;`,
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

	// Raw/minified mode still follows a bounded number of exact dependencies.
	if hits := analyzeDOMXSS(`const a=location.hash;el.innerHTML=a;`, false); len(hits) == 0 {
		t.Errorf("minified one-hop was missed")
	}

	// FALSE one-hop classes that MUST stay silent even with deep=true.
	for _, fp := range []string{
		`const userInput = location.hash; el.innerHTML = encodeURIComponent(userInput);`, // sanitizer between
		`const userInput = location.hash; el.textContent = userInput;`,                   // textContent is not an HTML sink
		`let x=location.hash;x="safe";el.innerHTML=x;`,                                   // safe reassignment kills taint
	} {
		if hits := analyzeDOMXSS(fp, true); len(hits) != 0 {
			t.Errorf("expected NO one-hop hit for: %s (got %+v)", fp, hits)
		}
	}
}

func TestAnalyzeDOMXSSPropertiesAndFunctionSummaries(t *testing.T) {
	positives := []string{
		`state.value=location.hash;box.innerHTML=state.value;`,
		`function render(value){box.innerHTML=value} render(location.search);`,
		`const render=(label,value)=>{box.outerHTML=value};render("safe",location.hash);`,
		`function readHash(){return location.hash}const value=readHash();box.innerHTML=value;`,
		`const readSearch=()=>location.search;box.innerHTML=readSearch();`,
		`const encoded=encodeURIComponent(location.hash);const decoded=decodeURIComponent(encoded);box.innerHTML=decoded;`,
	}
	for _, js := range positives {
		if hits := analyzeDOMXSS(js, true); len(hits) == 0 {
			t.Errorf("missed property/wrapper DOM flow: %s", js)
		}
	}

	for _, safe := range []string{
		`box.setHTML(location.hash);`,                                 // native Sanitizer-backed API
		`new DOMParser().parseFromString(location.hash,"text/html");`, // parsed document is inert until inserted
		`box.innerHTML=location.origin;`,                              // target origin is not attacker payload
		`const encoded=encodeURIComponent(location.hash);box.innerHTML=encoded;`,
	} {
		if hits := analyzeDOMXSS(safe, true); len(hits) != 0 {
			t.Errorf("safe/non-executing flow became a candidate: %s: %+v", safe, hits)
		}
	}
	if hits := analyzeDOMXSS(`box.setHTMLUnsafe(location.hash);`, true); len(hits) == 0 {
		t.Fatal("setHTMLUnsafe must remain a DOM injection sink")
	}
}

func TestAnalyzeDOMXSSPostMessageVariants(t *testing.T) {
	cases := []string{
		`window.onmessage=e=>{box.innerHTML=e["data"]}`,
		`self.onmessage=({data})=>{box.innerHTML=data}`,
		`addEventListener("message",function({data:payload}){box.innerHTML=payload})`,
	}
	for _, js := range cases {
		hits := analyzePostMessageDOMXSS(js, true)
		if len(hits) == 0 {
			t.Errorf("missed postMessage handler form: %s", js)
		}
	}

	logged := analyzePostMessageDOMXSS(`onmessage=e=>{console.log(e.origin);box.innerHTML=e.data}`, true)
	if len(logged) == 0 || logged[0].Confidence != 78 {
		t.Fatalf("merely logging event.origin is not an origin guard: %+v", logged)
	}
	guarded := analyzePostMessageDOMXSS(`onmessage=e=>{if(e.origin!=="https://trusted.example")return;box.innerHTML=e.data}`, true)
	if len(guarded) == 0 || guarded[0].Confidence != 65 {
		t.Fatalf("a real origin conditional should lower the static lead pending runtime proof: %+v", guarded)
	}
}

func TestExtractDOMParamHints(t *testing.T) {
	js := `const p=new URLSearchParams(location.search).get('returnTo');
	        route.queryParamMap.get("html"); searchParams.has('preview')`
	got := extractDOMParamHints(js)
	for _, want := range []string{"returnTo", "html", "preview"} {
		if !containsString(got, want) {
			t.Fatalf("DOM query parameter %q missed in %+v", want, got)
		}
	}
}

func TestDOMPageInventoryUsesRealAndJSHintedParams(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	_, _ = db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,content_type)
		VALUES ('svc',?,'https://app.test/search',200,'text/html')`, tid)
	_, _ = db.Exec(`INSERT INTO parameters (id,target_id,url,parameter,method,location)
		VALUES ('p',?,'https://app.test/search?q=one','q','GET','query')`, tid)
	_, _ = db.Exec(`INSERT INTO parameters (id,target_id,url,parameter,method,location)
		VALUES ('pathp',?,'https://app.test/users/123','id','GET','path:1')`, tid)
	_, _ = db.Exec(`INSERT INTO js_files (id,target_id,url) VALUES ('js',?,'https://app.test/app.js')`, tid)
	_, _ = db.Exec(`INSERT INTO js_findings (id,target_id,js_file_id,type,value)
		VALUES ('jf',?,'js','dom_param','preview')`, tid)
	pages := loadDOMPageTargets(context.Background(), db, tid, 20)
	if len(pages) != 2 {
		t.Fatalf("expected query and path routes in DOM inventory: %+v", pages)
	}
	var queryOK, pathOK bool
	for _, page := range pages {
		queryOK = queryOK || (containsString(page.Params, "q") && containsString(page.Params, "preview"))
		pathOK = pathOK || containsString(page.PathLocations, "path:1")
	}
	if !queryOK || !pathOK {
		t.Fatalf("incomplete DOM page inventory: %+v", pages)
	}
}
