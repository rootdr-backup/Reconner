package scanner

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
)

// DOM-XSS analysis — PRECISE + VERIFIED.
//
// The static pass is deliberately conservative: it flags ONLY a DIRECT flow where a
// URL-controllable source appears INSIDE an HTML-injection sink's argument
// (e.g. `el.innerHTML = location.hash`, `document.write(location.search)`). It does
// NOT do one-variable-hop taint — in minified bundles that matched single-letter
// vars (`t`,`e`,`v`) against every sink and produced a flood of un-exploitable
// noise in third-party libraries. It also excludes the noisy "sinks" that are not
// HTML injection (setTimeout/setInterval with a function arg, jQuery `$()` selector,
// `location=` navigation, `setAttribute`) and the postMessage `event.data` source
// (exploitable only when origin is unchecked — a separate class, not a URL sink).
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
	"document.URL", "document.documentURI", "document.baseURI",
}
var domSourcesLow = []string{
	"document.referrer", "window.name",
}

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
	{"createContextualFragment", regexp.MustCompile(`createContextualFragment\s*\(([^;\n)]{1,160})`)},
	{"eval", regexp.MustCompile(`(?:^|[^.\w])eval\s*\(([^;\n)]{1,160})`)},
	// Modern framework HTML sinks (compiled into bundles):
	{"React.dangerouslySetInnerHTML", regexp.MustCompile(`dangerouslySetInnerHTML\s*[:=]\s*\{\s*(?:\{\s*)?__html\s*:\s*([^}\n]{1,160})`)},
	{"Angular.$sce.trustAsHtml", regexp.MustCompile(`trustAsHtml\s*\(([^;\n)]{1,160})`)},
	{"Element.srcdoc", regexp.MustCompile(`\.srcdoc\s*=\s*([^;\n]{1,160})`)},
	{"DOMParser.parseFromString", regexp.MustCompile(`parseFromString\s*\(([^,\n]{1,160}?),`)},
	{"Element.setHTML", regexp.MustCompile(`\.setHTML\s*\(([^;\n)]{1,160})`)},
	{"Function", regexp.MustCompile(`(?:^|[^.\w])new\s+Function\s*\(([^;\n)]{1,160})`)},
}

type domXSSHit struct {
	Sink       string
	Source     string
	Snippet    string
	Confidence int  // static-lead confidence (candidate band)
	OneHop     bool // true when proven via a single intermediate assignment
}

// domSanitizers are calls that neutralise a value before it reaches a sink, so a
// one-hop flow passing through one of them is NOT a lead. Kept small and specific
// to avoid masking real flows.
var domSanitizers = []string{
	"encodeURIComponent", "encodeURI", "escape(", "DOMPurify", "sanitize",
	".textContent", "encodeHTML", "escapeHTML", "htmlEncode", "JSON.stringify",
}

func hasSanitizerBetween(seg string) bool {
	for _, s := range domSanitizers {
		if strings.Contains(seg, s) {
			return true
		}
	}
	return false
}

// meaningfulIdent reports whether name is a real (non-minified) identifier worth
// one-hop taint. Minifiers rename locals to 1–3 char lowercase tokens (a, e, t,
// n, r, i, o, aa, ab, …); tracking those against every sink is exactly the
// single-letter FP flood the direct-only pass was created to avoid. A name earns
// one-hop only if it is long OR camelCase OR snake_case — the shape of code that
// still has its original (or source-map-recovered) names.
func meaningfulIdent(name string) bool {
	if len(name) < 4 {
		return false
	}
	if strings.Contains(name, "_") {
		return true
	}
	for _, c := range name {
		if c >= 'A' && c <= 'Z' {
			return true
		}
	}
	return len(name) >= 6 // a long all-lowercase word (e.g. "payload", "userinput")
}

var oneHopAssign = regexp.MustCompile(`(?:var|let|const)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*([^;\n]{1,120})`)

// analyzeDOMXSS finds source→sink DOM-XSS flows in one JS/HTML document.
//   - DIRECT: the URL source sits inside the sink's own argument (precise, always on).
//   - ONE-HOP (deep only): `const x = <source>; … sink(x)` within a bounded window,
//     x a meaningful identifier, no sanitizer between. Enabled only for
//     source-map-recovered / un-minified code, where names are real — never on raw
//     minified bundles (the historical FP source).
func analyzeDOMXSS(content string, deep bool) []domXSSHit {
	if content == "" {
		return nil
	}
	var hits []domXSSHit
	seen := map[string]bool{}
	add := func(h domXSSHit) bool {
		key := h.Sink + "|" + h.Source
		if seen[key] {
			return true
		}
		seen[key] = true
		if len(h.Snippet) > 160 {
			h.Snippet = h.Snippet[:160] + "…"
		}
		hits = append(hits, h)
		return len(hits) < 3 // cap per document — a lead, not an inventory
	}

	// Direct source-in-sink.
	for _, sk := range htmlInjectionSinks {
		for _, m := range sk.re.FindAllStringSubmatch(content, -1) {
			src, high := domSourceTier(m[1])
			if src == "" {
				continue
			}
			conf := 50
			if high {
				conf = 58
			}
			if !add(domXSSHit{Sink: sk.name, Source: src, Snippet: strings.TrimSpace(m[0]), Confidence: conf}) {
				return hits
			}
		}
	}

	// One-hop taint (deep only): a URL source assigned to a meaningful variable that
	// then flows into a sink, with no sanitizer in between and within a bounded span.
	if deep {
		for _, am := range oneHopAssign.FindAllStringSubmatchIndex(content, -1) {
			name := content[am[2]:am[3]]
			rhs := content[am[4]:am[5]]
			src, high := domSourceTier(rhs)
			if src == "" || !meaningfulIdent(name) {
				continue
			}
			// bounded search window AFTER the assignment for a sink using `name`.
			start := am[1]
			end := start + 600
			if end > len(content) {
				end = len(content)
			}
			window := content[start:end]
			varUse := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `\b`)
			for _, sk := range htmlInjectionSinks {
				sm := sk.re.FindStringSubmatchIndex(window)
				if sm == nil {
					continue
				}
				arg := window[sm[2]:sm[3]]
				if !varUse.MatchString(arg) {
					continue
				}
				if hasSanitizerBetween(window[:sm[1]]) {
					continue
				}
				conf := 44
				if high {
					conf = 50
				}
				snip := "let " + name + " = …" + src + "…; " + strings.TrimSpace(window[sm[0]:sm[1]])
				if !add(domXSSHit{Sink: sk.name, Source: src + " → " + name, Snippet: snip, Confidence: conf, OneHop: true}) {
					return hits
				}
				break
			}
		}
	}
	return hits
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
		if _, err := s.db.ExecContext(ctx, `
			INSERT INTO vuln_findings (id, target_id, type, severity, url, parameter, payload, evidence, confidence, status)
			VALUES (?,?, 'dom_xss','medium',?,?,?,?,?, 'candidate')
			ON CONFLICT(target_id, type, url, parameter) DO UPDATE SET
				evidence=excluded.evidence, confidence=excluded.confidence, status='candidate'`,
			uuid.New().String(), targetID, jsURL, h.Sink+" ← "+h.Source,
			"", ev, conf); err == nil {
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
	rows, err := db.QueryContext(ctx, `
		SELECT url FROM http_services
		WHERE target_id = ? AND COALESCE(source,'probe') IN ('probe','seed')
		ORDER BY LENGTH(url) ASC LIMIT 40`, targetID)
	if err != nil {
		return
	}
	var pages []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) == nil && strings.HasPrefix(u, "http") {
			pages = append(pages, u)
		}
	}
	rows.Close()
	if len(pages) == 0 {
		return
	}
	logFn("info", "dom_xss", fmt.Sprintf("Verifying DOM XSS in a headless browser across %d page(s) (hash + query sources)...", len(pages)))

	confirmed := 0
	budget := 60 // total browser confirmations, bounded
	for _, page := range pages {
		if ctx.Err() != nil || budget <= 0 {
			break
		}
		for _, mode := range []string{"hash", "query"} {
			if budget <= 0 {
				break
			}
			budget--
			pl, ok := b.ConfirmDOMSource(ctx, page, mode)
			if !ok {
				continue
			}
			confirmed++
			src := "location.hash"
			poc := strings.SplitN(page, "#", 2)[0] + "#" + pl
			if mode == "query" {
				src = "query parameter"
				poc = injectParam(strings.SplitN(page, "#", 2)[0], "rcx", pl)
			}
			ev := fmt.Sprintf(
				"DOM XSS EXECUTION CONFIRMED in a real headless browser: a payload placed in the page's %s executed (a JS dialog carrying our nonce fired after the page rendered). This is a proven, exploitable DOM XSS.\n  Working PoC (open in a browser — it pops alert(document.domain)): %s\n  Payload: %s",
				src, poc, pl)
			_, _ = db.ExecContext(ctx, `
				INSERT INTO vuln_findings (id, target_id, type, severity, url, parameter, payload, evidence, confidence, status)
				VALUES (?,?, 'dom_xss','high',?,?,?,?,?, 'finding')
				ON CONFLICT(target_id, type, url, parameter) DO UPDATE SET
					evidence=excluded.evidence, confidence=excluded.confidence, payload=excluded.payload, status='finding'`,
				uuid.New().String(), targetID, page, "dom:"+mode, pl, ev, 99)
			break // one confirmed source per page is enough
		}
	}
	logFn("warn", "dom_xss", fmt.Sprintf("DOM XSS browser verification done. %d CONFIRMED (executing) DOM XSS finding(s).", confirmed))
}
