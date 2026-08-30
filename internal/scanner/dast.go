package scanner

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/pkg/logger"
)

// DASTScanner is Reconner's native, context-aware DAST engine — the layer that
// finds the class of bugs template matchers (nuclei) structurally miss:
// context-dependent injection where the RIGHT payload depends on WHERE the input
// lands. Instead of firing a fixed payload and grepping, it works per insertion
// point in three disciplined steps:
//
//  1. BASELINE — a benign nonce, to know the parameter's normal reflection/errors.
//  2. PROBE + CLASSIFY — one reflection probe (marker + breakout chars) reused
//     from the XSS context engine tells us the exact context (HTML text / quoted
//     attr / unquoted attr / JS string / JS expr) and which breakout chars
//     survived UNENCODED there.
//  3. CONTEXT-AWARE CONFIRM (differential) — for a markup context it injects a
//     brand-new benign ELEMENT built for that exact context and confirms the raw
//     element survived in the response (deterministic HTML-injection proof, near
//     zero FP). A safely-encoded reflection is explicitly REJECTED. In the same
//     pass a broken-quote differential (error appears only AFTER the quote, not in
//     baseline) raises an error-based SQLi candidate for sqlmap to PROVE.
//
// Everything flows into the unified candidate pipeline — the engine never
// self-confirms SQLi (sqlmap does) and reuses the shared HTTP/insertion/context
// primitives (no parallel engines).
type DASTScanner struct {
	db        *database.DB
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc

	// browserBudget bounds how many insertion points may be escalated to the
	// (slow, serialized) headless browser per scan — the DOM/SPA XSS path. Reset at
	// the start of each run so a reflection-heavy target can't spend the whole scan
	// in the browser.
	browserBudget atomic.Int64
}

func NewDASTScanner(db *database.DB, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *DASTScanner {
	return &DASTScanner{db: db, cfg: cfg, logger: log, broadcast: broadcast}
}

var dastClient = &http.Client{
	Transport: sharedHTTPTransport,
	Timeout:   15 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// unique, collision-resistant markers.
const (
	dastNonce     = "rcnb3axz9" // benign baseline value
	dastElement   = "rcnq2z"    // the injected new-element name we confirm raw
	dastMaxPoints = 600         // hard cap on insertion points per run
	dastWorkers   = 12          // concurrent insertion points

	// dastBrowserBudget caps how many non-raw-reflected params get escalated to the
	// headless browser (the DOM/SPA XSS path) per scan. The single browser tab
	// serializes navigations, so this bounds the worst case while still covering a
	// meaningful sample of a client-rendered app's parameters.
	dastBrowserBudget = 150
)

// Run drives the DAST engine across the target's insertion points.
// Run is the combined DAST engine: context-aware reflected XSS + error-based
// SQLi candidate registration over every insertion point.
func (s *DASTScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	return s.run(ctx, targetID, logFn, false)
}

// RunXSS is the standalone XSS objective: the SAME deep context-aware reflected-
// XSS engine (HTML-text / quoted+unquoted attribute / single- & double-quote /
// JS-string / CSS / URL-sink contexts, multi-reflection, breakout-confirmed) but
// WITHOUT the error-based SQLi candidate side-channel — so selecting XSS alone
// produces XSS findings only and nothing else.
func (s *DASTScanner) RunXSS(ctx context.Context, targetID string, logFn LogFunc) error {
	return s.run(ctx, targetID, logFn, true)
}

func (s *DASTScanner) run(ctx context.Context, targetID string, logFn LogFunc, xssOnly bool) error {
	if !xssOnly && s.cfg != nil && !s.cfg.EnableDAST {
		return nil
	}
	label := "dast"
	if xssOnly {
		label = "xss"
	}
	pointLimit := dastMaxPoints
	if xssOnly && s.cfg != nil {
		pointLimit = s.cfg.URLLimit()
	}
	points := loadInsertionPoints(ctx, s.db, targetID, pointLimit)
	if xssOnly {
		points = loadXSSInsertionPoints(ctx, s.db, targetID, pointLimit)
	}
	if len(points) == 0 {
		logFn("info", label, "No insertion points to test.")
		return nil
	}
	auth := loadAuthHeaders(ctx, s.db, targetID)
	// Reset the per-scan headless-browser budget. Params whose reflection is NOT
	// visible in raw HTML (client-rendered / SPA / DOM sinks) are escalated to a real
	// browser — but only up to this many, so a huge target can't stall in the browser.
	s.browserBudget.Store(dastBrowserBudget)
	logFn("info", label, fmt.Sprintf("Context-aware reflected-XSS analysis over %d insertion point(s)...", len(points)))

	var xssConfirmed, xssRejected, sqliCand int64
	sem := make(chan struct{}, dastWorkers)
	var wg sync.WaitGroup

	for _, ip := range points {
		if ctx.Err() != nil {
			break
		}
		if ip.Param == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip insertionPoint) {
			defer wg.Done()
			defer func() { <-sem }()
			res := s.testPoint(ctx, targetID, ip, auth, xssOnly)
			atomic.AddInt64(&xssConfirmed, int64(res.xssConfirmed))
			atomic.AddInt64(&xssRejected, int64(res.xssRejected))
			atomic.AddInt64(&sqliCand, int64(res.sqliCand))
		}(ip)
	}
	wg.Wait()

	// Promote static DOM-XSS leads to PROVEN findings: drive a real browser to place
	// an executing payload in each page's location.hash / a query param and confirm
	// it actually runs. This is the real evidence (a popup PoC), not a static grep.
	VerifyDOMXSSOnPages(ctx, s.db, targetID, logFn)

	if xssOnly {
		logFn("warn", label, fmt.Sprintf("XSS analysis done. XSS confirmed=%d, encoded-reflections rejected=%d.", xssConfirmed, xssRejected))
	} else {
		logFn("warn", label, fmt.Sprintf(
			"DAST done. XSS confirmed=%d, encoded-reflections rejected=%d, error-based SQLi candidates=%d.",
			xssConfirmed, xssRejected, sqliCand))
	}
	return nil
}

type dastOutcome struct {
	xssConfirmed int
	xssRejected  int
	sqliCand     int
}

func (s *DASTScanner) testPoint(ctx context.Context, targetID string, ip insertionPoint, auth map[string]string, xssOnly bool) dastOutcome {
	var out dastOutcome
	if ctx.Err() != nil {
		return out
	}

	// 1) baseline — normal behaviour of this parameter. A per-request value avoids
	// cache/collision artifacts from the historical fixed nonce.
	baselineNonce := newXSSToken("rcnbase")
	baseline, _ := sendInjected(ctx, dastClient, ip, baselineNonce, auth)

	// 2) reflection probe + context classification (reused XSS context engine).
	probeMarker := newXSSToken("rcnctx")
	probe := sendInjectedResponse(ctx, dastClient, ip, xssProbeFor(probeMarker), auth)
	a := analyzeReflectionProbe(probe.Body, probeMarker, xssProbeSuffix)
	// A reflected payload only executes when the browser renders the response as
	// HTML. Input echoed into application/json (or any declared non-HTML type) is
	// inert even when '"<> survive raw — the classic reflected-XSS false positive
	// (e.g. an API endpoint reflecting a `clientId` into its JSON body). Decide the
	// HTML-sink question ONCE, here, from the probe's own Content-Type.
	probeHTMLSink := browserRendersResponse(probe.Status, probe.ContentType, probe.Body, probe.NoSniff)
	if looksLikeBlockPage(probe.Status, probe.Body) {
		c := s.xssCandidate(targetID, ip, a.Context, "XSS probe reached a WAF/edge block page; application behavior is unknown")
		_, _ = RecordCandidateResult(ctx, s.db, c, VerifyResult{
			Verdict: VerifyInconclusive, Confidence: ConfCandidateLo, Method: "dast-waf",
			Reason: fmt.Sprintf("WAF/edge block or challenge during XSS probe (HTTP %d)", probe.Status),
		}, FindingMeta{Actor: "dast"})
		return out
	}
	if a.Reflected {
		switch {
		case !probeHTMLSink && scriptLikeContentType(probe.ContentType):
			// JavaScript/ECMAScript responses are inert on a top-level navigation,
			// but become executable when the endpoint is embedded as <script src>.
			// JSONP and reflected JS endpoints were therefore a real false-negative:
			// the old MIME gate rejected them before testing the browser's script
			// resource execution path. Only Chromium can prove this class faithfully
			// because it applies MIME/nosniff/CORS/resource-loading semantics itself.
			if b := getXSSBrowser(); b != nil {
				if pl, ok := b.ConfirmScriptResource(ctx, ip, auth); ok {
					s.confirmXSS(ctx, targetID, ip, "script_resource", pl, "browser", 99)
					out.xssConfirmed++
					break
				}
			}
			c := s.xssCandidate(targetID, ip, "script_resource", "input is reflected in a JavaScript resource; external-script execution requires runtime proof")
			_, _ = RecordCandidateResult(ctx, s.db, c, VerifyResult{
				Verdict: VerifyInconclusive, Confidence: ConfCandidateLo, Method: "dast-script-resource",
				Reason: "reflected JavaScript/JSONP resource found, but executable script-resource loading was not proven",
			}, FindingMeta{Actor: "dast"})
		case a.Executable && !probeHTMLSink:
			// Reflected with breakout chars surviving, but the response is not an HTML
			// document → a browser will not execute it. Record as provably-not-a-bug.
			c := s.xssCandidate(targetID, ip, a.Context, "reflected into non-HTML ("+ctLabel(probe.ContentType)+") response — a browser will not render/execute it")
			_, _ = RecordCandidateResult(ctx, s.db, c, VerifyResult{Verdict: VerifyRejected,
				Method: "dast-context", Reason: "non-rendered response: " + ctLabel(probe.ContentType)}, FindingMeta{Actor: "dast"})
			out.xssRejected++
		case a.Encoded && !a.Executable:
			// Reflected but safely output-encoded → NOT executable. Record the
			// REJECTED candidate so it's provably-not-a-bug, never a finding.
			c := s.xssCandidate(targetID, ip, a.Context, "reflected but HTML-encoded — not executable")
			_, _ = RecordCandidateResult(ctx, s.db, c, VerifyResult{Verdict: VerifyRejected,
				Method: "dast-context", Reason: "required breakout characters encoded in " + a.Context}, FindingMeta{Actor: "dast"})
			out.xssRejected++
		case a.Executable:
			confirmed := false
			// A URL attribute controlled from its first byte does not need a quote
			// breakout: javascript: is itself the execution primitive. The benign
			// marker-tag confirm below cannot prove this class, so send it directly
			// to Chromium (which activates javascript: links) instead of silently
			// leaving every scheme-only sink inconclusive.
			if a.Context == CtxURL && a.URLScheme {
				execPayload, proof, conf, executed := s.proveExecutingXSS(ctx, ip, a, auth)
				if executed {
					s.confirmXSS(ctx, targetID, ip, a.Context, execPayload, proof, conf)
					out.xssConfirmed++
					confirmed = true
				}
			}
			// 3) context-aware differential confirm. First the markup contexts
			// (HTML text / quoted / unquoted attr) whose new-element injection is
			// deterministically provable. If that isn't applicable, try the
			// <script>-breakout: a reflection sitting inside a <script> block whose
			// angle brackets survive RAW can close </script> and inject a new HTML
			// element — a deterministic, browserless proof of an executable XSS that
			// a JS-context reflection would otherwise leave merely "inconclusive".
			payload, needle, confirmable := dastConfirm(a)
			if !confirmable {
				payload, needle, confirmable = jsScriptBreakout(a)
			}
			if confirmable && !confirmed {
				confResp := sendInjectedResponse(ctx, dastClient, ip, payload, auth)
				// Two hard FP gates before an XSS is CONFIRMED:
				//  (1) the response must actually be rendered as HTML — a payload
				//      reflected into a CSS/JS/JSON/plain response never executes;
				//  (2) the injected element must appear as a GENUINE start tag in HTML
				//      text (htmlTagInjected), not merely as raw characters sitting
				//      inside a quoted attribute value or a <script>/<style> body — that
				//      is reflection, not markup injection. Together these kill the two
				//      dominant reflected-XSS false-positive classes (static-asset
				//      version params and tracking params echoed into a quoted attr/URL).
				if browserRendersResponse(confResp.Status, confResp.ContentType, confResp.Body, confResp.NoSniff) &&
					htmlTagInjected(confResp.Body, dastElement) &&
					!strings.Contains(baseline, needle) {
					// HTML injection is proven. Now find a payload the app does NOT
					// filter, so the REPORTED PoC actually pops (the dominant "finds
					// XSS but no popup" gap): browser real-execution proof first, then
					// a browserless bypass-ladder rotation.
					execPayload, proof, conf, executed := s.proveExecutingXSS(ctx, ip, a, auth)
					if executed {
						s.confirmXSS(ctx, targetID, ip, a.Context, execPayload, proof, conf)
						out.xssConfirmed++
						confirmed = true
					}
				}
			}
			// executable context but not deterministically confirmable here (e.g. a
			// JS string whose quote survives but whose angle brackets are encoded, so
			// only an in-JS breakout works) — strong candidate, left for browser/
			// manual proof (never auto-reported as a finding).
			if !confirmed {
				c := s.xssCandidate(targetID, ip, a.Context, "breakout/injection signal survived, but executable JavaScript was not proven")
				_, _ = RecordCandidateResult(ctx, s.db, c, VerifyResult{Verdict: VerifyInconclusive,
					Confidence: ConfCandidateLo, Method: "dast-context", Reason: "no runtime or CSP-valid executable payload proof"}, FindingMeta{Actor: "dast"})
			}
		}
	} else if probeHTMLSink && xssOnly {
		// SPA / DOM XSS: the probe is NOT reflected in the raw HTML, but the response
		// IS an HTML document — the classic client-rendered app where the reflection is
		// written into the DOM by JavaScript after load (invisible to the raw-HTML
		// parser, which is why mature JS sites looked "0 reflected / 0 XSS"). Escalate
		// to a real headless browser, bounded by the per-scan budget, and confirm
		// actual execution. Only for the standalone XSS objective so a full combined
		// scan isn't slowed by browser navigations on every non-reflected param.
		if s.browserBudget.Add(-1) >= 0 {
			if b := getXSSBrowser(); b != nil {
				if pl, ok := b.ConfirmInsertion(ctx, ip, auth); ok {
					s.confirmXSS(ctx, targetID, ip, "dom", pl, "browser", 99)
					out.xssConfirmed++
				}
			}
		}
	}

	// SQLi error-based differential: a DB error that appears only AFTER a broken
	// quote (and NOT in the baseline) is a strong error-based SQLi signal. We do
	// NOT self-confirm — we register a candidate for the sqlmap verifier to PROVE.
	// Skipped when running as the standalone XSS objective, so an XSS-only scan
	// never registers a SQLi candidate.
	if !xssOnly && ctx.Err() == nil {
		quoteBody, _ := sendInjected(ctx, dastClient, ip, dastNonce+"'", auth)
		if sqlErrorAppeared(baseline, quoteBody) {
			c := VulnerabilityCandidate{
				TargetID: targetID, Type: "sqli", Subtype: "error-based",
				URL: ip.URL, Method: ip.Method, Parameter: ip.Param, Location: locOf(ip),
				Payload: "'", DetectionSource: "dast", DetectionMethod: "error-diff",
				Severity: "high", Confidence: 80, Status: CandDetected,
				Evidence: "SQL error signature appeared only after a broken-quote injection (absent in baseline) at parameter " + ip.Param,
			}
			_, _ = RecordCandidateDetection(ctx, s.db, c, FindingMeta{Actor: "dast"})
			out.sqliCand++
		}
	}
	return out
}

// dastConfirm returns the context-specific payload that injects a NEW benign
// element plus the raw needle to confirm, for the markup contexts we can prove
// deterministically without a browser. JS contexts return confirmable=false.
func dastConfirm(a ReflectionAnalysis) (payload, needle string, confirmable bool) {
	el := "<" + dastElement + ">"
	switch a.Context {
	case CtxHTMLText:
		return el, el, true
	case CtxQuotedAttr, CtxURL:
		if a.Context == CtxURL && a.URLScheme && a.Quote == 0 {
			return "", "", false
		}
		// Break out of the ACTUAL opening quote (single- vs double-quoted attrs and
		// href/src URL sinks alike), close the tag, inject a fresh element. The
		// re-inject + htmlTagInjected gate below still proves it materialised.
		q := `"`
		if a.Quote == '\'' {
			q = "'"
		}
		return q + `>` + el, el, true
	case CtxUnquotedAttr:
		return `>` + el, el, true
	case CtxCSS:
		// Close the <style> element, then inject a new element into HTML text.
		return `</style>` + el, el, true
	case CtxComment:
		// Close the HTML comment, then inject a new element into HTML text.
		return `-->` + el, el, true
	case CtxRCDATA:
		// Close the raw-text element (</textarea> etc.), then a fresh element.
		return a.CloseTag + el, el, true
	default:
		return "", "", false
	}
}

// jsScriptBreakout returns a deterministic <script>-breakout confirm for a
// reflection that landed inside a <script> block. If BOTH angle brackets survived
// UNENCODED, closing the script element (`</script>`) and injecting a brand-new
// raw element proves full HTML injection — a real, executable reflected XSS even
// though the input sits in JavaScript. When the angle brackets are encoded the
// breakout cannot form, so it stays non-confirmable (a browser-level in-JS proof
// would be required) and returns confirmable=false.
func jsScriptBreakout(a ReflectionAnalysis) (payload, needle string, confirmable bool) {
	if a.Context != CtxJSString && a.Context != CtxJSExpr {
		return "", "", false
	}
	if strings.Contains(a.Surviving, "<") && strings.Contains(a.Surviving, ">") {
		el := "<" + dastElement + ">"
		return "</script>" + el, el, true
	}
	return "", "", false
}

// htmlishResponse reports whether a response body would be parsed as HTML by a
// browser. Injected markup is only executable in an HTML (or XHTML) document;
// reflected into text/css, application/javascript, application/json, text/plain,
// an image, a font, etc. it is inert. When the Content-Type is absent we only
// trust it as HTML if the body actually carries an HTML signature, so a
// header-less static asset can't masquerade as a page.
func htmlishResponse(contentType, body string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if strings.HasPrefix(ct, "text/html") || strings.Contains(ct, "application/xhtml") {
		return true
	}
	if ct != "" {
		// A declared, non-HTML content type is never an HTML sink.
		return false
	}
	low := strings.ToLower(body)
	return strings.Contains(low, "<!doctype html") || strings.Contains(low, "<html")
}

// ctLabel returns a short, human-readable label for a Content-Type used in
// evidence/reasons — the media type without parameters, or "no Content-Type".
func ctLabel(contentType string) string {
	ct := strings.TrimSpace(contentType)
	if ct == "" {
		return "no Content-Type"
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return strings.ToLower(ct)
}

// browserRendersAsHTML reports whether a top-level navigation to this response
// would be parsed as an HTML document by the browser — the precondition for any
// reflected payload to execute at all. It is stricter than htmlishResponse in
// exactly one way: when the server sends X-Content-Type-Options: nosniff, MIME
// sniffing is forbidden, so a response that is only "HTML-ish" by body signature
// (blank/absent Content-Type) is NOT rendered as HTML and cannot execute markup.
//
// A response that DECLARES a non-HTML type — application/json above all: user
// input echoed into a JSON API body is the single most common reflected-XSS
// false positive — is never an HTML sink, with or without nosniff. Even when the
// breakout characters ('"<>) survive raw in the JSON, a browser navigating to
// `Content-Type: application/json` renders/downloads text, never a document, so
// the alert() cannot fire. (This is exactly the ably.com clientId reflection:
// JSON body + nosniff → reflected, but inert.)
func browserRendersAsHTML(contentType, body string, nosniff bool) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	activeSVG := strings.Contains(ct, "image/svg+xml") ||
		((strings.Contains(ct, "application/xml") || strings.HasPrefix(ct, "text/xml")) &&
			strings.Contains(strings.ToLower(body), "<svg"))
	if nosniff {
		return strings.HasPrefix(ct, "text/html") || strings.Contains(ct, "application/xhtml") || activeSVG
	}
	if activeSVG {
		return true
	}
	return htmlishResponse(contentType, body)
}

// scriptLikeContentType identifies responses a browser may execute when loaded
// as a classic external script. These are deliberately NOT classified as HTML:
// top-level navigation renders their source, while a <script src> consumer runs
// it. Keeping this separate avoids both the old false-negative and JSON-as-XSS
// false positives.
func scriptLikeContentType(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch ct {
	case "application/javascript", "application/ecmascript", "text/javascript",
		"text/ecmascript", "application/x-javascript", "text/jscript":
		return true
	default:
		return strings.HasSuffix(ct, "+javascript")
	}
}

// browserRendersResponse adds HTTP navigation semantics to the MIME decision.
// Browsers do not render redirect bodies, 204/205 responses, or 304 responses as
// a document, even when those bodies contain HTML-looking attacker input.
func browserRendersResponse(status int, contentType, body string, nosniff bool) bool {
	if status >= 300 && status < 400 {
		return false
	}
	if status == http.StatusNoContent || status == http.StatusResetContent || status == http.StatusNotModified || status < 200 {
		return false
	}
	return browserRendersAsHTML(contentType, body, nosniff)
}

// wafBlockSignatures are phrases characteristic of a WAF / edge block or challenge
// page. A payload "reflected" on such a page is not an app reflection — the WAF
// echoes the offending value into its own block template — and it never executes,
// so treating it as an XSS hit is a false positive. Lower-cased comparison.
var wafBlockSignatures = []string{
	"access denied", "request blocked", "you have been blocked",
	"attention required", "cloudflare", "akamai", "incapsula", "imperva",
	"mod_security", "modsecurity", "web application firewall", "waf",
	"forbidden", "403 forbidden", "not acceptable", "captcha",
	"ray id", "blocked by", "security policy", "request rejected",
	"unusual traffic", "bot detection", "perimeterx", "datadome",
}

// looksLikeBlockPage reports whether an HTTP response is a WAF/edge block or
// challenge page rather than the real application response. It combines the status
// code (403/406/429/503 are the classic block codes) with body signatures so a
// legitimate 403 app page that merely contains one phrase is not over-matched: a
// short body carrying a signature, or a block status WITH a signature, qualifies.
func looksLikeBlockPage(status int, body string) bool {
	low := strings.ToLower(body)
	sig := false
	for _, s := range wafBlockSignatures {
		if strings.Contains(low, s) {
			sig = true
			break
		}
	}
	if !sig {
		return false
	}
	switch status {
	case 403, 406, 429, 503, 401:
		return true
	}
	// 200-with-signature is a block only when the body is small (a block template),
	// not a large real page that happens to mention one of these words.
	return len(body) < 4096
}

// htmlTagInjected reports whether an element named `name` occurs in `body` as a
// GENUINE start tag in HTML text — NOT inside a quoted attribute value, NOT inside
// another tag's attribute area, and NOT inside <script>/<style> raw-text. It is
// the deterministic, browserless proof that a reflected payload actually CREATED a
// new element (real markup injection / XSS), as opposed to its characters merely
// appearing raw somewhere in the response. This distinguishes a true breakout
// (`...>`<name>`) from a reflection that stayed trapped inside `content="...<name>"`.
// exploitExample renders the real executable payload that matches HOW the XSS was
// proven, so the report shows a working exploit rather than a generic template. A
// <script>-breakout proof reports the breakout exploit; everything else uses the
// canonical per-context payload.
func exploitExample(ctxName, injected string) string {
	if strings.HasPrefix(injected, "</script>") {
		return "</script><svg onload=alert(document.domain)>"
	}
	return contextPayload(ctxName)
}

// proveExecutingXSS returns a payload the application does NOT neutralise — one
// that genuinely executes — so the reported PoC pops instead of being a real bug
// with a filtered payload. Order of proof strength:
//  1. Headless browser: navigates the injected GET URL and confirms alert() truly
//     ran (document.title nonce), returning the EXACT payload that executed (99).
//  2. Browserless bypass ladder: rotates the context's executing payloads (case/
//     slash/rare-tag/rare-handler WAF variants) and returns the first whose element
//     + handler survive RAW as live markup (95).
//  3. Fallback: injection was proven but every tested vector was filtered — report
//     the canonical payload at lower confidence so a human can craft a bypass (90).
func (s *DASTScanner) proveExecutingXSS(ctx context.Context, ip insertionPoint, a ReflectionAnalysis, auth map[string]string) (payload, proof string, confidence int, executed bool) {
	// 1) browserless rotation over the executing/bypass ladder: the first alert
	//    payload whose element + handler survive RAW as live markup in an HTML
	//    response. Raw survival in an HTML sink means a browser navigating it WILL
	//    execute — this is the clean, copy-paste alert PoC we prefer to report.
	ladder := ""
	for _, p := range buildExecPayloads(a) {
		if ctx.Err() != nil {
			break
		}
		r := sendInjectedResponse(ctx, dastClient, ip, p.Payload, auth)
		if browserRendersResponse(r.Status, r.ContentType, r.Body, r.NoSniff) &&
			cspAllowsInlineScript(r.CSP) && execPayloadSurvived(r.Body, p) {
			ladder = p.Payload
			break
		}
	}
	// 2) independent real-execution proof in a headless browser (GET sinks). This
	//    also catches client-rendered / SPA reflections the raw-HTML pass can't see.
	browserPayload := ""
	if b := getXSSBrowser(); b != nil {
		if pl, ok := b.ConfirmInsertion(ctx, ip, auth); ok {
			browserPayload = pl
		}
	}
	switch {
	case ladder != "" && browserPayload != "":
		return ladder, "browser+differential", 99, true
	case browserPayload != "":
		// app executes, but no ladder vector survived the raw pass (client-rendered
		// or a filter the raw check couldn't beat) — report the browser-proven vector.
		return browserPayload, "browser", 99, true
	case ladder != "":
		return ladder, "differential", 95, true
	default:
		// HTML injection alone is not JavaScript execution. Keep it as a candidate
		// when every executable vector is filtered or blocked by CSP.
		return "", "inconclusive", ConfCandidateLo, false
	}
}

// cspAllowsInlineScript reports whether response CSP permits the inline event/
// script vectors used by the browserless ladder. A formed <svg onload> is HTML
// injection, but under a nonce/hash-only CSP it is not executable XSS. Runtime
// browser proof can still confirm a CSP bypass independently.
func cspAllowsInlineScript(csp string) bool {
	csp = strings.ToLower(strings.TrimSpace(csp))
	if csp == "" {
		return true
	}
	var sourceList string
	for _, directive := range strings.Split(csp, ";") {
		fields := strings.Fields(strings.TrimSpace(directive))
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		if name == "script-src-elem" {
			sourceList = strings.Join(fields[1:], " ")
			break
		}
		if name == "script-src" || (name == "default-src" && sourceList == "") {
			sourceList = strings.Join(fields[1:], " ")
		}
	}
	if sourceList == "" {
		return true
	}
	return strings.Contains(sourceList, "'unsafe-inline'")
}

// xssCandidate builds a reflected-XSS candidate for the insertion point.
func (s *DASTScanner) xssCandidate(targetID string, ip insertionPoint, ctxName, note string) VulnerabilityCandidate {
	return VulnerabilityCandidate{
		TargetID: targetID,
		Type:     "xss", Subtype: "reflected", URL: ip.URL, Method: ip.Method,
		Parameter: ip.Param, Location: locOf(ip), DetectionSource: "dast",
		DetectionMethod: "context:" + ctxName, Severity: "high",
		Confidence: 70, Status: CandDetected, Evidence: note,
	}
}

// confirmXSS records a CONFIRMED reflected-XSS candidate + a finding. The payload
// stored is one PROVEN to survive/execute (browser real-exec, or a bypass-ladder
// vector that landed raw as live markup) — so the report's PoC actually pops. The
// proof label and confidence come from proveExecutingXSS.
func (s *DASTScanner) confirmXSS(ctx context.Context, targetID string, ip insertionPoint, ctxName, execPayload, proof string, confidence int) {
	var how string
	switch proof {
	case "browser", "browser+differential":
		how = "EXECUTION CONFIRMED in a real headless browser (JavaScript changed document.title to our random nonce; the reported PoC uses alert(document.domain))"
	case "differential":
		how = "HTML injection proven and this exact payload survived RAW as live markup (bypass-ladder differential vs baseline)"
	default:
		how = "HTML injection proven via a benign marker element (differential vs baseline); this canonical payload is a starting point — the app filtered the tested executing vectors, craft a bypass"
	}
	ev := fmt.Sprintf("Reflected XSS in %s context at parameter %q. %s. Working payload: %s",
		ctxName, ip.Param, how, execPayload)
	c := VulnerabilityCandidate{
		TargetID: targetID, Type: "xss", Subtype: "reflected", URL: ip.URL,
		Method: ip.Method, Parameter: ip.Param, Location: locOf(ip),
		Payload: execPayload, DetectionSource: "dast",
		DetectionMethod: "context:" + ctxName + "/" + proof, Severity: "high",
		Confidence: confidence, Evidence: ev,
	}
	_, _ = RecordCandidateResult(ctx, s.db, c, VerifyResult{
		Verdict: VerifyVerified, Confidence: confidence, Evidence: ev, Method: "dast-" + proof,
	}, FindingMeta{Actor: "dast"})
}

// sqlErrorAppeared reports whether a SQL error signature is present in the
// post-injection body but NOT in the baseline (differential → not a static error).
func sqlErrorAppeared(baseline, injected string) bool {
	for _, re := range sqlErrorSignatures {
		if re.MatchString(injected) && !re.MatchString(baseline) {
			return true
		}
	}
	return false
}

// locOf maps an insertion point to a candidate location string.
func locOf(ip insertionPoint) string {
	switch {
	case strings.ToUpper(ip.Method) == "POST" && strings.Contains(ip.ContentType, "json"):
		return "json"
	case strings.ToUpper(ip.Method) == "POST":
		return "body"
	default:
		return "query"
	}
}
