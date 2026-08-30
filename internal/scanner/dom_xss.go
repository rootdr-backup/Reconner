package scanner

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/recon-platform/internal/database"
)

// DOM-XSS analysis — PRECISE + VERIFIED.
//
// The static pass is an ordered, bounded taint analysis. It follows exact local
// assignments (including short minified names and object properties), short
// source-returning helpers, and functions that wrap a dangerous sink. It never
// promotes a grep hit: static flows remain candidates until Chromium proves that
// an attacker-controlled source actually executes.
//
// A static hit is a CANDIDATE (a lead to verify), never a confirmed finding. The
// CONFIRMED findings — with a real popup PoC — come from VerifyDOMXSSOnPages, which
// drives a real headless browser: it puts an executing payload in the page's
// location.hash / a query param and observes it actually run.

// DOM-XSS sources are tiered by how directly an attacker controls them, which maps
// to the confidence a STATIC lead earns. High-tier sources (the URL and its parts)
// are fully attacker-controlled on a crafted link; low-tier sources (referrer,
// window.name) need a second step (a referring page / an opener) so a raw static
// hit on them is a weaker lead. event.data / postMessage is intentionally excluded
// here — it is exploitable only when the origin check is missing, a separate class
// that belongs to the postMessage analyzer, not the DOM-URL sink flow.
var domSourcesHigh = []string{
	"location.hash", "location.search", "location.href", "location.pathname",
	"document.location", "window.location",
	"document.URL", "document.documentURI", "document.baseURI",
}
var domSourcesLow = []string{
	"document.referrer", "window.name", "history.state",
	"navigation.currentEntry.getState",
}

var bareLocationSource = regexp.MustCompile(`(?:^|[^A-Za-z0-9_$\.])location(?:[^A-Za-z0-9_$\.]|$)`)

// domSourceTier returns the highest-tier URL source that appears in arg, and a
// confidence weight for it (high tier = stronger lead). "" tier means no source.
func domSourceTier(arg string) (src string, high bool) {
	for _, s := range domSourcesHigh {
		if strings.Contains(arg, s) {
			return s, true
		}
	}
	for _, s := range domSourcesLow {
		if strings.Contains(arg, s) {
			return s, false
		}
	}
	if m := bareLocationSource.FindString(arg); m != "" {
		return "location", true
	}
	return "", false
}

// htmlInjectionSink pairs a name with a regex capturing the sink's argument. Only
// sinks that inject HTML/markup (⇒ script execution) are here.
type htmlInjectionSink struct {
	name string
	re   *regexp.Regexp
}

// htmlInjectionSinks covers the classic DOM sinks PLUS the modern
// framework-specific HTML sinks that ship in compiled bundles — the ones a
// reflection-only or classic-sink-only analyzer misses on a React/Vue/Angular app.
// Every entry injects HTML/markup (or evaluates code), so a URL-controlled value
// reaching it is script execution.
var htmlInjectionSinks = []htmlInjectionSink{
	{"innerHTML", regexp.MustCompile(`\.innerHTML\s*=\s*([^;\n]{1,160})`)},
	{"outerHTML", regexp.MustCompile(`\.outerHTML\s*=\s*([^;\n]{1,160})`)},
	{"insertAdjacentHTML", regexp.MustCompile(`\.insertAdjacentHTML\s*\([^,]{0,30},\s*([^;\n)]{1,160})`)},
	{"document.write", regexp.MustCompile(`document\.write(?:ln)?\s*\(([^;\n]{1,160})`)},
	{"jQuery.html", regexp.MustCompile(`\.html\s*\(\s*([^;\n)]{1,160})`)},
	{"jQuery.append", regexp.MustCompile(`\.(?:append|prepend|before|after|replaceWith)\s*\(\s*([^;\n)]{1,220})`)},
	{"createContextualFragment", regexp.MustCompile(`createContextualFragment\s*\(([^;\n)]{1,160})`)},
	{"eval", regexp.MustCompile(`(?:^|[^.\w])eval\s*\(([^;\n)]{1,160})`)},
	{"setTimeout(string)", regexp.MustCompile(`(?:setTimeout|setInterval)\s*\(\s*([^,;\n)]{1,220})`)},
	// Modern framework HTML sinks (compiled into bundles):
	{"React.dangerouslySetInnerHTML", regexp.MustCompile(`dangerouslySetInnerHTML\s*[:=]\s*\{\s*(?:\{\s*)?__html\s*:\s*([^}\n]{1,160})`)},
	{"Angular.$sce.trustAsHtml", regexp.MustCompile(`trustAsHtml\s*\(([^;\n)]{1,160})`)},
	{"Element.srcdoc", regexp.MustCompile(`\.srcdoc\s*=\s*([^;\n]{1,160})`)},
	// setHTML() intentionally sanitizes. setHTMLUnsafe() is the actual injection
	// primitive and must not be confused with the safe API.
	{"Element.setHTMLUnsafe", regexp.MustCompile(`\.setHTMLUnsafe\s*\(([^;\n)]{1,160})`)},
	{"setAttribute(srcdoc/event)", regexp.MustCompile(`\.setAttribute\s*\(\s*['"](?:srcdoc|on[a-z]+)['"]\s*,\s*([^;\n)]{1,220})`)},
	{"script.src", regexp.MustCompile(`(?:script|scriptEl|scriptTag|newScript)\.src\s*=\s*([^;\n]{1,220})`)},
	{"location navigation", regexp.MustCompile(`(?:window\.)?location(?:\.href)?\s*=\s*([^;\n]{1,220})`)},
	{"Function", regexp.MustCompile(`(?:^|[^.\w])new\s+Function\s*\(([^;\n)]{1,160})`)},
}

type domXSSHit struct {
	Sink       string
	Source     string
	Snippet    string
	Confidence int  // static-lead confidence (candidate band)
	OneHop     bool // true when proven via a single intermediate assignment
	Hops       int
}

// domSanitizers are calls that neutralise a value before it reaches a sink, so a
// one-hop flow passing through one of them is NOT a lead. Kept small and specific
// to avoid masking real flows.
var domSanitizers = []string{
	"DOMPurify.sanitize", "Sanitizer.sanitize", "sanitizeFor(",
	"encodeHTML", "escapeHTML", "htmlEncode", "he.encode(",
}

func hasSanitizerBetween(seg string) bool {
	for _, s := range domSanitizers {
		if strings.Contains(seg, s) {
			return true
		}
	}
	return false
}

var (
	domLHS     = `[A-Za-z_$][A-Za-z0-9_$]*(?:(?:\.[A-Za-z_$][A-Za-z0-9_$]*)|(?:\[['"][A-Za-z_$][A-Za-z0-9_$]*['"]\])){0,4}`
	declAssign = regexp.MustCompile(`(?:var|let|const)\s+(` + domLHS + `)\s*=\s*([^;\n]{1,500})`)
	bareAssign = regexp.MustCompile(`(?:^|[;{}\n])\s*(` + domLHS + `)\s*=\s*([^;\n]{1,500})`)
)

type domTaint struct {
	source  string
	hops    int
	encoded bool
}

func domURLReencoded(expr string) bool {
	encoded := strings.Contains(expr, "encodeURIComponent(") || strings.Contains(expr, "encodeURI(") || strings.Contains(expr, "escape(")
	decoded := strings.Contains(expr, "decodeURIComponent(") || strings.Contains(expr, "decodeURI(") || strings.Contains(expr, "unescape(")
	return encoded && !decoded
}

func domURLDecoded(expr string) bool {
	return strings.Contains(expr, "decodeURIComponent(") || strings.Contains(expr, "decodeURI(") || strings.Contains(expr, "unescape(")
}

type domFlowEvent struct {
	pos, order int
	assign     bool
	name, rhs  string
	sink       htmlInjectionSink
	arg, code  string
}

type domJSFunction struct {
	name   string
	params []string
	body   string
}

func splitJSParams(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(strings.TrimPrefix(part, "..."))
		if i := strings.IndexByte(part, '='); i >= 0 {
			part = strings.TrimSpace(part[:i])
		}
		if regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`).MatchString(part) {
			out = append(out, part)
		}
	}
	return out
}

// matchingJSBrace returns the closing brace while ignoring braces inside quoted
// strings, templates and comments. This keeps wrapper summaries inside the real
// function body instead of accidentally consuming the following bundle code.
func matchingJSBrace(content string, open int) int {
	depth := 0
	var quote byte
	lineComment, blockComment, escaped := false, false, false
	for i := open; i < len(content); i++ {
		c := content[i]
		if lineComment {
			if c == '\n' {
				lineComment = false
			}
			continue
		}
		if blockComment {
			if c == '*' && i+1 < len(content) && content[i+1] == '/' {
				blockComment = false
				i++
			}
			continue
		}
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '/' && i+1 < len(content) {
			if content[i+1] == '/' {
				lineComment = true
				i++
				continue
			}
			if content[i+1] == '*' {
				blockComment = true
				i++
				continue
			}
		}
		if c == '\'' || c == '"' || c == '`' {
			quote = c
			continue
		}
		switch c {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func collectDOMFunctions(content string) []domJSFunction {
	type fnPattern struct {
		re                *regexp.Regexp
		nameGroup, pGroup int
	}
	patterns := []fnPattern{
		{regexp.MustCompile(`function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]{0,240})\)\s*\{`), 1, 2},
		{regexp.MustCompile(`(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*function\s*\(([^)]{0,240})\)\s*\{`), 1, 2},
		{regexp.MustCompile(`(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*\(([^)]{0,240})\)\s*=>\s*\{`), 1, 2},
		{regexp.MustCompile(`(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*=>\s*\{`), 1, 2},
	}
	seen := map[string]bool{}
	var out []domJSFunction
	for _, p := range patterns {
		for _, m := range p.re.FindAllStringSubmatchIndex(content, -1) {
			ng, pg := p.nameGroup*2, p.pGroup*2
			if len(m) <= pg+1 || m[ng] < 0 || m[pg] < 0 {
				continue
			}
			open := strings.LastIndex(content[m[0]:m[1]], "{") + m[0]
			close := matchingJSBrace(content, open)
			if close <= open {
				continue
			}
			name := content[m[ng]:m[ng+1]]
			key := fmt.Sprintf("%d|%s", m[0], name)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, domJSFunction{name: name, params: splitJSParams(content[m[pg]:m[pg+1]]), body: content[open+1 : close]})
		}
	}
	// Expression-bodied arrows are common in bundled React code.
	arrowExpr := regexp.MustCompile(`(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:\(([^)]{1,160})\)|([A-Za-z_$][A-Za-z0-9_$]*))\s*=>\s*([^;\n]{1,500})`)
	for _, m := range arrowExpr.FindAllStringSubmatch(content, -1) {
		params := m[2]
		if params == "" {
			params = m[3]
		}
		out = append(out, domJSFunction{name: m[1], params: splitJSParams(params), body: m[4]})
	}
	return out
}

type domSinkWrapper struct {
	name, param, sink string
	paramIndex        int
}

func splitJSArguments(raw string) []string {
	var out []string
	start, depth := 0, 0
	var quote byte
	escaped := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
			} else if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' || c == '`' {
			quote = c
			continue
		}
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(raw[start:i]))
				start = i + 1
			}
		}
	}
	out = append(out, strings.TrimSpace(raw[start:]))
	return out
}

func summarizeDOMFunctions(content string) (sources []extraDOMSource, sinks []domSinkWrapper) {
	for _, fn := range collectDOMFunctions(content) {
		// A helper that returns a URL source is itself a source at its call sites.
		for _, ret := range regexp.MustCompile(`\breturn\s+([^;\n]{1,500})`).FindAllStringSubmatch(fn.body, -1) {
			if hasSanitizerBetween(ret[1]) {
				continue
			}
			if src, high := domSourceTier(ret[1]); src != "" {
				sources = append(sources, extraDOMSource{expr: fn.name + "(", label: fn.name + "() ← " + src, high: high})
				break
			}
		}
		// A function whose parameter reaches a sink becomes a virtual sink at each
		// call site, covering render(location.hash) and minified equivalents.
		for _, sk := range htmlInjectionSinks {
			for _, m := range sk.re.FindAllStringSubmatch(fn.body, -1) {
				if len(m) < 2 || hasSanitizerBetween(m[1]) {
					continue
				}
				for paramIndex, param := range fn.params {
					if identIn(m[1], param) {
						sinks = append(sinks, domSinkWrapper{name: fn.name, param: param, paramIndex: paramIndex, sink: sk.name})
					}
				}
			}
		}
	}
	// Concise source helpers (`const read = () => location.hash`) have no return
	// keyword but are semantically identical to the block-bodied form above.
	conciseSource := regexp.MustCompile(`(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:\([^)]{0,160}\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*=>\s*([^;\n]{1,500})`)
	for _, m := range conciseSource.FindAllStringSubmatch(content, -1) {
		if hasSanitizerBetween(m[2]) {
			continue
		}
		if src, high := domSourceTier(m[2]); src != "" {
			sources = append(sources, extraDOMSource{expr: m[1] + "(", label: m[1] + "() ← " + src, high: high})
		}
	}
	return sources, sinks
}

func identIn(expr, ident string) bool {
	re := regexp.MustCompile(`(?:^|[^A-Za-z0-9_$])` + regexp.QuoteMeta(ident) + `(?:[^A-Za-z0-9_$]|$)`)
	return re.MatchString(expr)
}

func clearDOMTaint(tainted map[string]domTaint, name string) {
	delete(tainted, name)
	for existing := range tainted {
		if strings.HasPrefix(existing, name+".") || strings.HasPrefix(existing, name+"[") {
			delete(tainted, existing)
		}
	}
}

func bestDOMTaint(expr string, tainted map[string]domTaint) (domTaint, bool) {
	var best domTaint
	found := false
	for name, tv := range tainted {
		if identIn(expr, name) && (!found || tv.hops < best.hops || (tv.hops == best.hops && tv.source < best.source)) {
			best, found = tv, true
		}
	}
	return best, found
}

// analyzeDOMXSS performs ordered, bounded source→assignment→sink propagation.
// Unlike the historical one-hop/name-length heuristic, it follows short minified
// identifiers too, but only along real assignment dependencies that occur before
// the sink. Runtime browser proof remains the promotion gate, so static results
// are candidates rather than findings.
func analyzeDOMXSS(content string, deep bool) []domXSSHit {
	hits := analyzeDOMFlows(content, deep, nil)
	hits = append(hits, analyzePostMessageDOMXSS(content, deep)...)
	if len(hits) > 12 {
		hits = hits[:12]
	}
	return hits
}

type extraDOMSource struct {
	expr, label string
	high        bool
}

func sourceInDOMExpr(expr string, extra []extraDOMSource) (string, bool) {
	if src, high := domSourceTier(expr); src != "" {
		return src, high
	}
	for _, s := range extra {
		if identIn(expr, s.expr) {
			return s.label, s.high
		}
	}
	return "", false
}

func analyzeDOMFlows(content string, deep bool, extra []extraDOMSource) []domXSSHit {
	if content == "" {
		return nil
	}
	functionSources, wrappers := summarizeDOMFunctions(content)
	extra = append(append([]extraDOMSource{}, extra...), functionSources...)
	var events []domFlowEvent
	seenAssignments := map[string]bool{}
	collectAssign := func(re *regexp.Regexp) {
		for _, m := range re.FindAllStringSubmatchIndex(content, -1) {
			if len(m) < 6 || m[2] < 0 || m[4] < 0 {
				continue
			}
			name, rhs := content[m[2]:m[3]], content[m[4]:m[5]]
			key := fmt.Sprintf("%d|%s", m[0], name)
			if seenAssignments[key] {
				continue
			}
			seenAssignments[key] = true
			events = append(events, domFlowEvent{pos: m[0], assign: true, name: name, rhs: rhs})
		}
	}
	collectAssign(declAssign)
	collectAssign(bareAssign)
	for _, sk := range htmlInjectionSinks {
		for _, m := range sk.re.FindAllStringSubmatchIndex(content, -1) {
			if len(m) < 4 || m[2] < 0 {
				continue
			}
			events = append(events, domFlowEvent{pos: m[0], order: 1, sink: sk,
				arg: content[m[2]:m[3]], code: content[m[0]:m[1]]})
		}
	}
	for _, wrapper := range wrappers {
		call := regexp.MustCompile(`\b` + regexp.QuoteMeta(wrapper.name) + `\s*\(\s*([^;\n)]{1,600})`)
		for _, m := range call.FindAllStringSubmatchIndex(content, -1) {
			if len(m) < 4 || m[2] < 0 {
				continue
			}
			prefixStart := m[0] - 24
			if prefixStart < 0 {
				prefixStart = 0
			}
			prefix := content[prefixStart:m[0]]
			if strings.Contains(prefix, "function ") {
				continue
			}
			args := splitJSArguments(content[m[2]:m[3]])
			if wrapper.paramIndex >= len(args) || args[wrapper.paramIndex] == "" {
				continue
			}
			events = append(events, domFlowEvent{pos: m[0], order: 1,
				sink: htmlInjectionSink{name: "function " + wrapper.name + " → " + wrapper.sink},
				arg:  args[wrapper.paramIndex], code: content[m[0]:m[1]]})
		}
	}
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].pos == events[j].pos {
			return events[i].order < events[j].order
		}
		return events[i].pos < events[j].pos
	})

	maxHops := 4
	if deep {
		maxHops = 8
	}
	tainted := map[string]domTaint{}
	seenHits := map[string]bool{}
	var hits []domXSSHit
	for _, ev := range events {
		if ev.assign {
			if hasSanitizerBetween(ev.rhs) {
				clearDOMTaint(tainted, ev.name)
				continue
			}
			if src, _ := sourceInDOMExpr(ev.rhs, extra); src != "" {
				tainted[ev.name] = domTaint{source: src + " → " + ev.name, hops: 1, encoded: domURLReencoded(ev.rhs)}
				continue
			}
			tv, found := bestDOMTaint(ev.rhs, tainted)
			clearDOMTaint(tainted, ev.name) // an untainted reassignment kills old state
			if found && tv.hops < maxHops {
				encoded := tv.encoded
				if domURLDecoded(ev.rhs) {
					encoded = false
				} else if domURLReencoded(ev.rhs) {
					encoded = true
				}
				tainted[ev.name] = domTaint{source: tv.source + " → " + ev.name, hops: tv.hops + 1, encoded: encoded}
			}
			continue
		}
		if hasSanitizerBetween(ev.arg) {
			continue
		}
		if domURLReencoded(ev.arg) {
			continue
		}
		src, high := sourceInDOMExpr(ev.arg, extra)
		hops := 0
		if src == "" {
			if tv, found := bestDOMTaint(ev.arg, tainted); found {
				if tv.encoded && !domURLDecoded(ev.arg) {
					continue
				}
				src, hops = tv.source, tv.hops
				_, high = sourceInDOMExpr(tv.source, extra)
			}
		}
		if src == "" {
			continue
		}
		key := ev.sink.name + "|" + src
		if seenHits[key] {
			continue
		}
		seenHits[key] = true
		conf := 70
		if high && hops == 0 {
			conf = 75
		} else if !high && hops > 0 {
			conf = 65
		}
		snippet := strings.TrimSpace(ev.code)
		if len(snippet) > 220 {
			snippet = snippet[:220] + "…"
		}
		hits = append(hits, domXSSHit{Sink: ev.sink.name, Source: src, Snippet: snippet,
			Confidence: conf, OneHop: hops > 0, Hops: hops})
		if len(hits) >= 12 {
			break
		}
	}
	return hits
}

var (
	messageListener     = regexp.MustCompile(`(?i)(?:addEventListener\s*\(\s*['"]message['"]|(?:window\.|self\.)?onmessage\s*=)`)
	callbackParam       = regexp.MustCompile(`(?:function\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)|\(?\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\)?\s*=>)`)
	destructuredMessage = regexp.MustCompile(`\{\s*data(?:\s*:\s*([A-Za-z_$][A-Za-z0-9_$]*))?[^}]*\}\s*\)?\s*(?:=>|\{)`)
	jsSimpleIdentifier  = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)
)

func messageHandlerWindow(content string, start int) string {
	end := start + 4000
	if end > len(content) {
		end = len(content)
	}
	window := content[start:end]
	// Prefer the callback's balanced block. This prevents an e.origin mention in
	// the next listener/function from being mistaken for a guard in this handler.
	if arrow := strings.Index(window, "=>"); arrow >= 0 && arrow < 500 {
		if rel := strings.IndexByte(window[arrow+2:], '{'); rel >= 0 && rel < 120 {
			open := start + arrow + 2 + rel
			if close := matchingJSBrace(content, open); close > open {
				return content[start : close+1]
			}
		}
	}
	if fn := strings.Index(window, "function"); fn >= 0 && fn < 500 {
		// Locate the function BODY brace, not a destructured parameter's `{data}`.
		if header := regexp.MustCompile(`function\s*\([^)]*\)\s*\{`).FindStringIndex(window[fn:]); header != nil {
			open := start + fn + header[1] - 1
			if close := matchingJSBrace(content, open); close > open {
				return content[start : close+1]
			}
		}
	}
	// Expression-bodied arrows end at the line/statement boundary.
	cut := len(window)
	for _, sep := range []string{"\n", ");"} {
		if i := strings.Index(window, sep); i >= 0 && i+len(sep) < cut {
			cut = i + len(sep)
		}
	}
	return window[:cut]
}

func postMessageOriginGuard(window, param, destructuredOrigin string) bool {
	accesses := []string{}
	if param != "" {
		accesses = append(accesses, param+".origin", param+`["origin"]`, param+`['origin']`, param+".source")
	}
	if destructuredOrigin != "" {
		accesses = append(accesses, destructuredOrigin)
	}
	for _, access := range accesses {
		if !strings.Contains(window, access) {
			continue
		}
		quoted := regexp.QuoteMeta(access)
		guardPatterns := []string{
			`(?s)\bif\s*\([^)]{0,400}` + quoted,
			`(?s)\bswitch\s*\([^)]{0,200}` + quoted,
			`(?s)\.(?:includes|has)\s*\(\s*` + quoted,
			`(?s)` + quoted + `\s*(?:===|==|!==|!=)`,
		}
		for _, p := range guardPatterns {
			if regexp.MustCompile(p).MatchString(window) {
				return true
			}
		}
	}
	return false
}

func analyzePostMessageDOMXSS(content string, deep bool) []domXSSHit {
	var out []domXSSHit
	for _, loc := range messageListener.FindAllStringIndex(content, -1) {
		window := messageHandlerWindow(content, loc[0])
		pm := callbackParam.FindStringSubmatch(window)
		param := ""
		if len(pm) >= 3 {
			param = pm[1]
			if param == "" {
				param = pm[2]
			}
		}
		var sources []extraDOMSource
		originVar := ""
		if param != "" {
			for _, dataExpr := range []string{param + ".data", param + `["data"]`, param + `['data']`} {
				if strings.Contains(window, dataExpr) {
					sources = append(sources, extraDOMSource{expr: dataExpr, label: "postMessage " + dataExpr})
				}
			}
		}
		if dm := destructuredMessage.FindStringSubmatch(window); len(dm) > 0 {
			dataVar := "data"
			if dm[1] != "" {
				dataVar = dm[1]
			}
			sources = append(sources, extraDOMSource{expr: dataVar, label: "postMessage destructured data"})
			originField := regexp.MustCompile(`\borigin(?:\s*:\s*([A-Za-z_$][A-Za-z0-9_$]*))?`).FindStringSubmatch(dm[0])
			if len(originField) > 0 {
				originVar = "origin"
				if len(originField) > 1 && originField[1] != "" {
					originVar = originField[1]
				}
			}
		}
		if len(sources) == 0 {
			continue
		}
		originGuard := postMessageOriginGuard(window, param, originVar)
		for i := range sources {
			sources[i].high = !originGuard
		}
		flows := analyzeDOMFlows(window, deep, sources)
		for _, h := range flows {
			if !strings.Contains(h.Source, "postMessage") {
				continue
			}
			if originGuard {
				h.Confidence = 65
				h.Source += " (origin/source guard present; runtime verifies whether it is bypassable)"
			} else {
				h.Confidence = 78
				h.Source += " (no origin check in listener window)"
			}
			out = append(out, h)
		}
	}
	return out
}

// looksMinified reports whether JS content is minified (very long average line
// length / almost no newlines). One-hop taint is unsafe on minified code, so we
// gate it on this.
func looksMinified(content string) bool {
	n := len(content)
	if n < 2000 {
		return false // small file — treat as readable
	}
	newlines := strings.Count(content, "\n")
	if newlines == 0 {
		return true
	}
	return n/(newlines+1) > 200 // avg line > 200 chars ⇒ minified
}

// storeDOMXSSFindings records DIRECT static DOM-XSS leads as CANDIDATES (never
// confirmed). Honest, low-confidence, with the real attack vector spelled out — the
// browser verifier is what promotes any of these to a confirmed finding with a popup.
func (s *JSScanner) storeDOMXSSFindings(ctx context.Context, targetID, jsURL, content string, fromSourceMap bool) int {
	// Third-party / CDN guard: a DOM lead in a bundle served from a host outside the
	// target's registrable domain (jQuery on a CDN, a vendor widget) is almost never
	// exploitable against the target — the flow would have to reach the target's own
	// DOM, which a static hit inside a third-party file cannot show. Suppress those
	// to keep the lead list first-party and actionable. Source-map-recovered content
	// is keyed by the ORIGINAL bundle URL, so this check still applies correctly.
	if host := hostOfJSURL(jsURL); host != "" {
		if scope := s.targetScope(ctx, targetID); scope != "" && !sameRegistrable(host, scope) {
			return 0
		}
	}

	// One-hop taint is enabled only where names are trustworthy: source-map-recovered
	// originals, or raw bundles that are not minified. Minified bundles stay
	// direct-only (the single-letter FP flood otherwise).
	deep := fromSourceMap || !looksMinified(content)
	hits := analyzeDOMXSS(content, deep)
	stored := 0
	for _, h := range hits {
		flow := "written directly to"
		if h.OneHop {
			flow = "assigned to a local variable and then passed to"
		}
		ev := fmt.Sprintf(
			"Potential DOM XSS (STATIC, UNVERIFIED): a URL-controllable source `%s` is %s the HTML-injection sink `%s`.\n  code: %s\n  found in: %s\n"+
				"  Attack vector: if the app renders this bundle on a page and the value reaches the sink unsanitised, a payload in the page's %s executes. Verify in a browser by loading an app page that uses this code with the payload placed in the %s.\n"+
				"  This is a static lead — the scanner promotes it to a CONFIRMED finding only when a headless browser observes it actually execute.",
			h.Source, flow, h.Sink, h.Snippet, jsURL, h.Source, h.Source)
		conf := h.Confidence
		if conf == 0 {
			conf = 45
		}
		if _, err := RecordDetectorObservation(ctx, s.db, DetectorObservation{
			TargetID: targetID, Type: "dom_xss", Subtype: "static-flow", Severity: "medium",
			URL: jsURL, Method: "STATIC", Parameter: h.Sink + " ← " + h.Source, Location: "javascript",
			Evidence: ev, Source: "js-analysis", DetectionMethod: "source-to-sink",
			Confidence: conf, Verdict: CandDetected,
		}); err == nil {
			stored++
		}
	}
	return stored
}

// hostOfJSURL extracts the hostname from a JS file URL (which may carry a
// " (source-map)" suffix appended by the caller). Returns "" if unparseable.
func hostOfJSURL(jsURL string) string {
	raw := strings.TrimSpace(strings.SplitN(jsURL, " ", 2)[0])
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// targetScope returns the target's registrable domain (its scope), cached per
// scanner call is unnecessary — this is called once per JS file, not per hit.
func (s *JSScanner) targetScope(ctx context.Context, targetID string) string {
	var domain string
	if err := s.db.QueryRowContext(ctx, `SELECT domain FROM targets WHERE id = ?`, targetID).Scan(&domain); err != nil {
		return ""
	}
	return strings.TrimSpace(domain)
}

var domParamHintPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:searchParams|queryParams|queryParamMap|routeParams|params)\s*\.\s*(?:get|has)\s*\(\s*['"]([A-Za-z0-9_.:-]{1,80})['"]`),
	regexp.MustCompile(`(?i)URLSearchParams\s*\([^)]{0,160}\)\s*\.\s*(?:get|has)\s*\(\s*['"]([A-Za-z0-9_.:-]{1,80})['"]`),
	regexp.MustCompile(`(?i)(?:location\.search|document\.location\.search)[^;\n]{0,240}['"]([A-Za-z][A-Za-z0-9_.:-]{0,79})['"]`),
}

func extractDOMParamHints(content string) []string {
	seen := map[string]bool{}
	var out []string
	for _, re := range domParamHintPatterns {
		for _, m := range re.FindAllStringSubmatch(content, -1) {
			if len(m) < 2 {
				continue
			}
			p := strings.TrimSpace(m[1])
			if p == "" || seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
			if len(out) >= 40 {
				return out
			}
		}
	}
	return out
}

func (s *JSScanner) storeDOMParamHints(ctx context.Context, targetID, jsFileID, content string) {
	for _, p := range extractDOMParamHints(content) {
		var exists int
		_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM js_findings
			WHERE target_id=? AND js_file_id=? AND type='dom_param' AND value=?`, targetID, jsFileID, p).Scan(&exists)
		if exists != 0 {
			continue
		}
		_, _ = s.db.ExecContext(ctx, `INSERT INTO js_findings
			(id,target_id,js_file_id,type,value,context,severity) VALUES (?,?,?,'dom_param',?,'URLSearchParams','info')`,
			newXSSToken("domparam"), targetID, jsFileID, p)
	}
}

type domPageTarget struct {
	URL           string
	Params        []string
	PathLocations []string
	score         int
}

func domPageKey(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return strings.SplitN(raw, "#", 2)[0]
	}
	u.Fragment = ""
	u.RawQuery = ""
	return strings.ToLower(u.Scheme+"://"+u.Host) + u.EscapedPath()
}

func loadDOMPageTargets(ctx context.Context, db *database.DB, targetID string, limit int) []domPageTarget {
	targets := map[string]*domPageTarget{}
	add := func(raw, param, location string, score int) {
		raw = strings.TrimSpace(strings.SplitN(raw, "#", 2)[0])
		if raw == "" || !strings.HasPrefix(raw, "http") || isStaticAssetURL(raw) || !urlHostInScope(ctx, raw) {
			return
		}
		key := domPageKey(raw)
		t := targets[key]
		if t == nil {
			t = &domPageTarget{URL: raw, score: score}
			targets[key] = t
		} else if score > t.score {
			t.score = score
			t.URL = raw
		}
		if _, path := isPathLocation(location); path {
			if !containsString(t.PathLocations, location) {
				t.PathLocations = append(t.PathLocations, location)
			}
		} else if param != "" && !containsString(t.Params, param) {
			t.Params = append(t.Params, param)
		}
	}
	rows, err := db.QueryContext(ctx, `SELECT url,parameter,COALESCE(location,'query'),COALESCE(is_reflected,0)
		FROM parameters WHERE target_id=? AND UPPER(COALESCE(method,'GET'))='GET'
		ORDER BY COALESCE(is_reflected,0) DESC LIMIT 6000`, targetID)
	if err == nil {
		for rows.Next() {
			var raw, param, location string
			var reflected int
			if rows.Scan(&raw, &param, &location, &reflected) == nil {
				add(raw, param, location, 100+reflected*20)
			}
		}
		rows.Close()
	}
	rows, err = db.QueryContext(ctx, `SELECT url,COALESCE(content_type,''),COALESCE(status_code,0)
		FROM http_services WHERE target_id=? AND COALESCE(status_code,0) BETWEEN 200 AND 399
		ORDER BY CASE WHEN LOWER(COALESCE(content_type,'')) LIKE '%html%' THEN 0 ELSE 1 END,LENGTH(url) LIMIT 2500`, targetID)
	if err == nil {
		for rows.Next() {
			var raw, ct string
			var status int
			if rows.Scan(&raw, &ct, &status) == nil && (ct == "" || strings.Contains(strings.ToLower(ct), "html")) {
				add(raw, "", "", 30)
			}
		}
		rows.Close()
	}

	var hints []string
	rows, err = db.QueryContext(ctx, `SELECT DISTINCT value FROM js_findings
		WHERE target_id=? AND type='dom_param' AND value<>'' LIMIT 80`, targetID)
	if err == nil {
		for rows.Next() {
			var p string
			if rows.Scan(&p) == nil && !containsString(hints, p) {
				hints = append(hints, p)
			}
		}
		rows.Close()
	}
	if len(hints) == 0 {
		hints = []string{"q", "search", "query", "input"}
	}
	for _, t := range targets {
		for _, p := range hints {
			if len(t.Params) >= 12 {
				break
			}
			if !containsString(t.Params, p) {
				t.Params = append(t.Params, p)
			}
		}
	}
	var out []domPageTarget
	for _, t := range targets {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].score == out[j].score {
			return len(out[i].URL) < len(out[j].URL)
		}
		return out[i].score > out[j].score
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

// VerifyDOMXSSOnPages drives a REAL headless browser to CONFIRM DOM XSS: for each
// HTML page it places an executing payload in location.hash and in a query param
// and observes whether it actually runs (the value flows attacker-URL → app JS →
// sink → execution). Every hit is a CONFIRMED finding with a working popup PoC —
// the opposite of the static candidate flood. Bounded by a page budget because each
// page is a full browser navigation.
func VerifyDOMXSSOnPages(ctx context.Context, db *database.DB, targetID string, logFn LogFunc) {
	b := getXSSBrowser()
	if b == nil {
		return
	}
	pages := loadDOMPageTargets(ctx, db, targetID, 250)
	if len(pages) == 0 {
		return
	}
	auth := loadAuthHeaders(ctx, db, targetID)
	var nameLead, messageLead int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM candidates WHERE target_id=? AND type='dom_xss' AND evidence LIKE '%window.name%'`, targetID).Scan(&nameLead)
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM candidates WHERE target_id=? AND type='dom_xss' AND evidence LIKE '%postMessage%'`, targetID).Scan(&messageLead)
	logFn("info", "dom_xss", fmt.Sprintf("Verifying DOM XSS in Chromium across %d real page route(s), discovered query names, hash, window.name and postMessage sources...", len(pages)))

	confirmed := 0
	budget := 600 // source attempts; each result still requires runtime execution
	for _, page := range pages {
		if ctx.Err() != nil || budget <= 0 {
			break
		}
		hashParam := ""
		if len(page.Params) > 0 {
			hashParam = page.Params[0]
		}
		tests := []struct{ mode, param string }{{"hash", hashParam}}
		for _, p := range page.Params {
			tests = append(tests, struct{ mode, param string }{"query", p})
		}
		for _, location := range page.PathLocations {
			tests = append(tests, struct{ mode, param string }{"path", location})
		}
		if nameLead > 0 {
			tests = append(tests, struct{ mode, param string }{"window.name", ""})
		}
		if messageLead > 0 {
			tests = append(tests, struct{ mode, param string }{"postMessage", ""})
		}
		for _, test := range tests {
			if budget <= 0 {
				break
			}
			budget--
			pl, ok := b.ConfirmDOMSource(ctx, page.URL, test.mode, test.param, auth)
			if !ok {
				continue
			}
			confirmed++
			src := test.mode
			param := "dom:" + test.mode
			poc := strings.SplitN(page.URL, "#", 2)[0] + "#" + pl
			switch test.mode {
			case "query":
				src = "query parameter " + test.param
				param = test.param
				poc = injectParam(strings.SplitN(page.URL, "#", 2)[0], test.param, pl)
			case "window.name":
				poc = "Set window.name to the payload from an attacker page, then navigate to " + page.URL
			case "postMessage":
				poc = "From an attacker-controlled frame: targetWindow.postMessage(" + strconv.Quote(pl) + ", '*')"
			case "path":
				src = "URL path segment " + test.param
				param = test.param
				if idx, valid := isPathLocation(test.param); valid {
					poc = injectPathSegment(strings.SplitN(page.URL, "#", 2)[0], idx, pl)
				}
			}
			ev := fmt.Sprintf(
				"DOM XSS EXECUTION CONFIRMED in a real headless browser: a payload placed in the page's %s executed and changed the document title to a random nonce after the page rendered. Reflection alone cannot produce this proof.\n  Working PoC (open in a browser — it pops alert(document.domain)): %s\n  Payload: %s",
				src, poc, pl)
			_, _ = RecordDetectorObservation(ctx, db, DetectorObservation{
				TargetID: targetID, Type: "dom_xss", Subtype: test.mode, Severity: "high",
				URL: page.URL, Method: "GET", Parameter: param, Location: test.mode,
				Payload: pl, Evidence: ev, Source: "xss-browser", DetectionMethod: "runtime-execution",
				Confidence: 99, Verdict: VerifyVerified,
			})
		}
	}
	logFn("warn", "dom_xss", fmt.Sprintf("DOM XSS browser verification done. %d CONFIRMED (executing) DOM XSS finding(s).", confirmed))
}
