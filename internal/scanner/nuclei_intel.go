package scanner

import (
	"net/url"
	"strings"

	"github.com/recon-platform/internal/config"
)

// Nuclei intelligence layer: turn raw nuclei output into the SAME normalized
// VulnerabilityCandidate the rest of the engine speaks, classify it into a
// canonical vuln class, and know which templates are detection-only noise that
// must never stand as a finding on their own. This is what lets nuclei "miss
// nothing" (every actionable class is captured as a candidate regardless of the
// template's self-reported severity) while staying HIGH-SIGNAL (noisy
// informational templates are demoted to candidate-only, and verifiable classes
// are re-proven before they count).

// realVulnTags are tags that mark a template as a genuine vulnerability class
// (not a passive detection). Their presence overrides the noisy-template guard.
var realVulnTags = map[string]bool{
	"sqli": true, "xss": true, "rce": true, "ssrf": true, "lfi": true,
	"ssti": true, "xxe": true, "redirect": true, "injection": true,
	"traversal": true, "lfr": true, "cve": true, "exposure": true,
	"disclosure": true, "takeover": true, "default-login": true,
	"auth-bypass": true, "idor": true, "deserialization": true,
	"crlf": true, "oast": true, "intrusive": true, "fuzz": true, "dast": true,
}

// noisyIDMarkers are template-id / tag substrings for detection-only templates
// that are pure noise as standalone findings: technology fingerprinting, TLS/DNS
// posture, missing headers, favicon hashes, etc. Matched only when the template
// carries NO realVulnTag.
var noisyIDMarkers = []string{
	"tech-detect", "waf-detect", "wappalyzer", "-detection", "detect-",
	"version-detect", "-version", "missing-security-header", "http-missing",
	"ssl-", "tls-", "-tls", "weak-cipher", "self-signed", "dns-", "-dns",
	"favicon", "metatag", "form-detection", "options-method", "screenshot",
	"robots-txt", "robotstxt", "sitemap", "email-extract", "cname", "cdn-",
	"http-trace", "x-powered", "server-header", "cookie-without", "unsafe-",
	"security-txt", "cache-control", "content-type-header", "cors-misconfig-detect",
}

// noisyTagMarkers: detection-only tags. Same override rule as above.
var noisyTagMarkers = map[string]bool{
	"tech": true, "detect": true, "fingerprint": true, "waf": true,
	"ssl": true, "tls": true, "dns": true, "network": true, "misc": true,
	"favicon": true, "iot": true, "wappalyzer": true, "headers": true,
}

// blockedTemplateIDs are template IDs (exact match, case-insensitive) that
// produce ZERO trace — no finding, no candidate — because they are KNOWN to
// be broken/false-positive-generating or operator-rejected, not merely
// noisy. Unlike nucleiNoisyTemplate (which demotes detection-only templates
// to candidate-only), a blocked template is dropped outright: it never even
// becomes a candidate.
//
//   - "sql": a malformed community template (display name "SQL Injecion" —
//     note the typo) whose matcher fires on ANY URL-encoded special
//     character appended to the path (%27, %22, %5C, %2C, %2A, ...)
//     regardless of the actual response — every one of its "hits" was the
//     exact same 302→/login redirect, i.e. no real differential signal at
//     all. Its id "sql" also doesn't contain "sqli"/"sql-injection" so
//     classifyNucleiTemplate never recognized it as sqli, meaning it also
//     never reached sqlmap verification — a structural gap independent of
//     the template itself (see nucleiRun/Run() wiring below).
//   - "header-reflection": low-value noise (reflects request headers back,
//     which is extremely common and rarely exploitable on its own).
//   - "graphite-browser-default-credential": fires without confirming the
//     target actually runs Graphite — a template/host mismatch false
//     positive on non-Graphite hosts.
//   - "smb-anonymous-access-detection": operator-rejected as unreliable on
//     this fleet's targets.
//   - "smb-signing-not-required": replaced by a native check (see
//     smbSigningRequired in smb.go, wired into network.go's analyzeProtocol)
//     that reads the SecurityMode field straight out of the SMB2 NEGOTIATE
//     response instead of trusting an external template's heuristics —
//     never guesses "not required" from an inconclusive probe.
var blockedTemplateIDs = map[string]bool{
	"sql":                                 true,
	"header-reflection":                   true,
	"graphite-browser-default-credential": true,
	"smb-anonymous-access-detection":      true,
	"smb-signing-not-required":            true,

	// ── Community templates removed outright: chronic false-positive generators
	// or zero-signal noise (operator policy: anything with a meaningful FP rate
	// is dropped, not just demoted). These fire on the wrong host, on soft-404
	// pages, or report a "finding" that is really just posture/reflection.
	"options-method":                   true, // reports OPTIONS allowed — informational, not a vuln
	"http-trace":                       true, // TRACE enabled — near-zero real impact, high volume
	"xss-deprecated-header":            true, // X-XSS-Protection header — deprecated, non-issue
	"x-xss-protection":                 true,
	"cookies-without-httponly":         true, // cookie-flag posture — noise as a standalone finding
	"cookies-without-secure-flag":      true,
	"cookies-samesite-none":            true,
	"tomcat-manager-pathnormalization": true, // FPs on any 401/redirecting /manager path
	"fingerprinthub-web-fingerprints":  true, // pure tech fingerprinting, enormous and noisy
	"wappalyzer-recognition":           true,
	"waf-detect":                       true, // WAF fingerprint — detection only
	"tech-detect":                      true,
	"addeventlistener-detected":        true,
	"google-floc-disabled":             true, // privacy-header posture, not a vuln
	"cache-poisoning-xss":              true, // very FP-prone standalone; real cache issues are re-proven natively
	"basic-cors":                       true, // generic CORS reflection — high FP without credentialed follow-up

	// Timing/heuristic "oracle" and cache templates that fire on nearly every
	// CDN-fronted host (Cloudflare/Fastly vary+cache headers, brotli negotiation)
	// with almost no true positives. Real cache poisoning is re-proven natively by
	// cachepoison.go with an unkeyed-input reflection + second-request confirm.
	"brotli-compression-oracle-attack": true, // ~99% FP: infers a "side channel" from brotli/vary on any CDN
	"web-cache-poisoning-real":         true, // HIGH-sev community template; fires on Age/Vary/Cache-Control alone
	"web-cache-poisoning":              true,
	"cache-poisoning":                  true, // generic; native engine handles the real ones

	// "LFR in Express" — a community LFI/path-read template for Express.js apps
	// that fires on almost any 200 to /..%2f… regardless of whether a real file
	// was read: a chronic false-positive generator (operator-flagged). Blocked by
	// id here (so -eid stops nuclei running it at all) AND by display name below.
	"lfr-in-express-via-get": true,
	"lfr-in-express":         true,
	"express-lfr":            true,
	"lfr-express":            true,
	"node-express-lfr":       true,
}

// blockedNamePatterns are lowercase substrings of a template's DISPLAY NAME
// (out.Info.Name) that mark it as blocked. Used when the exact template ID
// isn't known/stable but the reported name is — e.g. a custom/community
// template whose id varies by sync but whose name doesn't, or as a backstop
// when our guessed id above doesn't exactly match the real one.
var blockedNamePatterns = []string{
	"lfr in express via get",
	"smb anonymous access detection",
	"smb signing not required",
	// High-FP / zero-signal community templates (name-based backstop for the IDs
	// above, since community-synced ids drift but display names are stable).
	"lfr in express",
	"x-xss-protection",
	"cookies without",
	"options method",
	"http trace",
	"trace method",
	"waf detection",
	"wappalyzer",
	"web technologies",
	"tomcat manager path",
	"basic cors",
	"floc",
	// Junk community/AI-generated "…Detection" templates seen firing CRITICAL/HIGH
	// on live targets from presence-only matches (removed from the default extra
	// repos; this is the on-disk backstop for installs that already cloned them).
	"nph-publish",
	"wa-abbvie",
	"listserv vulnerable endpoint",
	"partitioned cookies",
	"chips ",
	"passkey authentication bypass",
	"webauthn/passkey",
	"algorithm confusion attack",
	"brotli compression oracle",
	"compression oracle",
	"web cache poisoning",
	"cache poisoning",
}

// injectionEchoMarkers identify templates whose "proof" is a token echoed back in
// the response body (command-injection / RCE / shellshock / expression-injection).
// For these, a match is a FALSE POSITIVE when the server merely reflected the
// request URL into the page — e.g. a canonical/og:url meta tag echoing the whole
// requested path, payload and all — because no command actually ran; the "proof"
// token is just the echoed request.
var injectionEchoMarkers = []string{
	"command-injection", "cmd-injection", "cmdi", "os-command", "command injection",
	"shellshock", "cve-2014-6271", "code-injection", "expression-injection",
	"expression language", "template-injection-echo", "rce", "remote-code",
}

func nucleiInjectionEchoClass(templateID, name string, tags []string) bool {
	hay := strings.ToLower(templateID + " " + name + " " + strings.Join(tags, " "))
	for _, m := range injectionEchoMarkers {
		if strings.Contains(hay, m) {
			return true
		}
	}
	return false
}

// requestPathQuery extracts the "/path?query" request-target from a raw HTTP
// request's start line ("METHOD target HTTP/x").
func requestPathQuery(request string) string {
	line := request
	if nl := strings.IndexAny(request, "\r\n"); nl >= 0 {
		line = request[:nl]
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// httpBodyOf returns the body of a raw HTTP response (everything after the blank
// line that ends the header block); falls back to the whole text if none is found.
func httpBodyOf(response string) string {
	if i := strings.Index(response, "\r\n\r\n"); i >= 0 {
		return response[i+4:]
	}
	if i := strings.Index(response, "\n\n"); i >= 0 {
		return response[i+2:]
	}
	return response
}

// nucleiURLReflectionFP reports whether an injection-echo template's match is
// really just the request URL being reflected verbatim into the response body —
// the dominant false positive for command-injection/RCE templates on sites that
// echo the requested path (canonical/og:url meta, search boxes, error pages: the
// tirana-airport.com "echo www-data" case). It fires ONLY for injection-echo
// templates and ONLY when the request's own path+query is found reflected in the
// body, so version/CVE detections and OAST-proven RCE are never affected.
func nucleiURLReflectionFP(templateID, name string, tags []string, request, response string) bool {
	if !nucleiInjectionEchoClass(templateID, name, tags) {
		return false
	}
	rp := requestPathQuery(request)
	if len(rp) < 10 {
		return false
	}
	body := httpBodyOf(response)
	if body == "" {
		return false
	}
	// Compare after lenient percent-decoding on BOTH sides. This is the robust
	// check: it does not matter whether nuclei captured the request-target encoded
	// (/player%28%29...) while the app reflected it into og:url in a different
	// encoding — decoding both to their canonical bytes makes the reflected path
	// match regardless of encode/decode direction.
	rpDec := lenientURLDecode(rp)
	bodyDec := lenientURLDecode(body)
	if len(rpDec) < 10 {
		return false
	}
	return strings.Contains(body, rp) ||
		strings.Contains(bodyDec, rpDec) ||
		strings.Contains(body, rpDec)
}

// lenientURLDecode decodes %XX and '+' greedily, leaving malformed escapes
// untouched (unlike url.QueryUnescape, which errors out on a stray '%' — common in
// HTML/JS bodies — and returns nothing). Used to normalize both the request path
// and the response body for reflection comparison.
func lenientURLDecode(s string) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' && i+2 < len(s) {
			if v, ok := hexByte(s[i+1], s[i+2]); ok {
				b.WriteByte(v)
				i += 2
				continue
			}
		}
		if c == '+' {
			b.WriteByte(' ')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func hexByte(a, b byte) (byte, bool) {
	hv := func(x byte) (byte, bool) {
		switch {
		case x >= '0' && x <= '9':
			return x - '0', true
		case x >= 'a' && x <= 'f':
			return x - 'a' + 10, true
		case x >= 'A' && x <= 'F':
			return x - 'A' + 10, true
		}
		return 0, false
	}
	h, ok1 := hv(a)
	l, ok2 := hv(b)
	return h<<4 | l, ok1 && ok2
}

// nucleiBlockedTemplate reports whether a template is on the hard blocklist
// (see blockedTemplateIDs/blockedNamePatterns) — operator-curated exclusions
// for specific templates PROVEN to be false-positive generators or otherwise
// rejected, independent of the generic noisy/detection-only heuristics below.
func nucleiBlockedTemplate(templateID, name string) bool {
	if blockedTemplateIDs[strings.ToLower(strings.TrimSpace(templateID))] {
		return true
	}
	lname := strings.ToLower(name)
	for _, p := range blockedNamePatterns {
		if strings.Contains(lname, p) {
			return true
		}
	}
	return false
}

// blockedTemplateIDList returns the built-in blocked IDs as a flat slice, for
// passing to nuclei's -eid/-exclude-id flag (name-only exclusions can't be
// expressed that way — those are still caught by the Go-side check above).
func blockedTemplateIDList() []string {
	ids := make([]string, 0, len(blockedTemplateIDs))
	for id := range blockedTemplateIDs {
		ids = append(ids, id)
	}
	return ids
}

// nucleiExcludeIDFlag builds nuclei's "-eid id1,id2,..." argument pair from
// the built-in blocklist plus any operator-added exclusions
// (cfg.NucleiExcludeTemplateIDs) — passed to EVERY nuclei invocation (web
// AND network) so blocked templates never even run, on top of the Go-side
// nucleiBlockedTemplate check that catches anything -eid can't express (name-
// only exclusions, or an id guess that's slightly off). Always returns a
// non-empty flag pair since the built-in list is never empty.
func nucleiExcludeIDFlag(cfg *config.Config) []string {
	ids := blockedTemplateIDList()
	if cfg != nil {
		for _, id := range cfg.NucleiExcludeTemplateIDs {
			id = strings.ToLower(strings.TrimSpace(id))
			if id != "" {
				ids = append(ids, id)
			}
		}
	}
	return []string{"-eid", strings.Join(ids, ",")}
}

// nucleiNoisyTemplate reports whether a template is detection-only noise that
// should NOT stand alone as an actionable finding. A template carrying any real
// vulnerability tag is never considered noisy, regardless of its id.
func nucleiNoisyTemplate(templateID string, tags []string) bool {
	for _, t := range tags {
		if realVulnTags[strings.ToLower(strings.TrimSpace(t))] {
			return false
		}
	}
	id := strings.ToLower(templateID)
	for _, m := range noisyIDMarkers {
		if strings.Contains(id, m) {
			return true
		}
	}
	noisyTags := 0
	for _, t := range tags {
		if noisyTagMarkers[strings.ToLower(strings.TrimSpace(t))] {
			noisyTags++
		}
	}
	// A template whose ONLY tags are detection-oriented is noise.
	return noisyTags > 0 && noisyTags == len(tags)
}

// classifyNucleiTemplate maps a template to a canonical vuln class Reconner's
// verifiers understand (sqli/xss/ssrf/lfi/command_injection/ssti/open_redirect/
// xxe/exposure/…). The second return is a coarse subtype used for provenance.
// Tags win over id keywords; id keywords are the fallback.
func classifyNucleiTemplate(templateID string, tags []string) (typ, subtype string) {
	has := func(want string) bool {
		for _, t := range tags {
			if strings.EqualFold(strings.TrimSpace(t), want) {
				return true
			}
		}
		return false
	}
	id := strings.ToLower(templateID)
	contains := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(id, s) {
				return true
			}
		}
		return false
	}

	switch {
	case has("sqli") || contains("sqli", "sql-injection", "sql_injection"):
		return "sqli", "nuclei-sqli"
	case has("xss") || contains("xss", "cross-site-scripting"):
		return "xss", "reflected"
	case has("ssrf") || contains("ssrf", "server-side-request"):
		return "ssrf", "nuclei-ssrf"
	case has("lfi") || has("lfr") || has("traversal") || contains("lfi", "path-traversal", "directory-traversal", "file-inclusion", "file-read"):
		return "lfi", "nuclei-lfi"
	case has("rce") || contains("rce", "remote-code", "command-injection", "cmd-injection", "code-injection", "oscommand"):
		return "command_injection", "nuclei-rce"
	case has("ssti") || contains("ssti", "template-injection"):
		return "ssti", "nuclei-ssti"
	case has("redirect") || contains("open-redirect", "openredirect", "-redirect"):
		return "open_redirect", "nuclei-redirect"
	case has("xxe") || contains("xxe", "xml-external"):
		return "xxe", "nuclei-xxe"
	case has("takeover") || contains("takeover", "subdomain-takeover"):
		return "subdomain_takeover", "nuclei-takeover"
	case has("exposure") || has("disclosure") || contains("exposure", "exposed", "disclosure", "config", "backup", ".env", "git-config", "listing", "phpinfo", "debug"):
		return "exposure", "nuclei-exposure"
	case has("default-login") || contains("default-login", "default-credential", "weak-credential"):
		return "default_login", "nuclei-default-login"
	case has("crlf") || contains("crlf"):
		return "crlf", "nuclei-crlf"
	case has("idor") || contains("idor", "bola"):
		return "idor", "nuclei-idor"
	default:
		// Still a real (medium+) finding — keep it, just not in a verifiable class.
		return "nuclei", "nuclei-generic"
	}
}

// nucleiVerifiableType reports whether a canonical class has a deterministic
// verifier/replay in Reconner (so a nuclei hit of this class can be re-proven).
func nucleiVerifiableType(typ string) bool {
	switch typ {
	case "sqli", "xss", "open_redirect", "lfi", "ssrf", "command_injection", "ssti":
		return true
	}
	return false
}

// paramFromURL pulls the single most-likely-injected query parameter out of a
// nuclei matched-at URL (the last query key), so a verifiable candidate carries
// the parameter its verifier needs. Empty when the URL has no query.
func paramFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	q := u.Query()
	if len(q) == 0 {
		return ""
	}
	// Prefer a parameter that looks injectable; else the last one seen.
	best := ""
	for k := range q {
		lk := strings.ToLower(k)
		for _, hint := range []string{"id", "q", "search", "url", "path", "file", "page", "redirect", "next", "return", "dest", "name", "cat"} {
			if strings.Contains(lk, hint) {
				return k
			}
		}
		best = k
	}
	return best
}

// nucleiToCandidate normalizes a nuclei hit into a VulnerabilityCandidate.
func nucleiToCandidate(targetID, templateID, name, severity, matchedAt string, tags []string) VulnerabilityCandidate {
	typ, subtype := classifyNucleiTemplate(templateID, tags)
	param := ""
	loc := "path"
	if nucleiVerifiableType(typ) {
		if param = paramFromURL(matchedAt); param != "" {
			loc = "query"
		}
	}
	return VulnerabilityCandidate{
		TargetID:        targetID,
		Type:            typ,
		Subtype:         subtype,
		URL:             matchedAt,
		Method:          "GET",
		Parameter:       param,
		Location:        loc,
		DetectionSource: "nuclei",
		DetectionMethod: "template:" + templateID,
		Severity:        strings.ToLower(severity),
		Confidence:      nucleiSeed(severity),
		Status:          CandDetected,
		Evidence:        "nuclei template " + templateID + " (" + name + ") matched at " + matchedAt,
	}
}

// nucleiSeed gives a starting confidence from the template severity. Nuclei's
// matchers are precise, so a critical/high template starts high; the verifier
// (when one exists) then confirms or rejects.
func nucleiSeed(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 85
	case "high":
		return 80
	case "medium":
		return 65
	case "low":
		return 45
	default:
		return 30
	}
}
