package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// This file ports two ideas from WatchMySix's monitoring engine:
//
//  1. DYNAMIC-VALUE NORMALIZATION (calibration, applied deterministically):
//     before hashing a page for change-detection we replace volatile values
//     (UUIDs, timestamps, CSRF/nonce tokens, high-entropy strings) with stable
//     placeholders. Two identical requests to a dynamic site then produce the
//     SAME normalized hash — killing the false-positive "it changed!" alerts that
//     plague naive hash-diff monitoring.
//
//  2. SECURITY-ATTRIBUTE DETECTION: snapshot the security-sensitive HTML on a
//     page (external <script src>, <iframe src>, <form action>, hidden inputs,
//     external links, <link href>). A change here — a NEW external script, a
//     changed form action — is a real supply-chain / phishing / form-hijack
//     signal, reported as a finding, not just "content changed".

// ── 1. Dynamic-value normalization ──────────────────────────────────────────

var (
	reUUID       = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	reISO8601    = regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?`)
	reUnixMs     = regexp.MustCompile(`\b1[0-9]{12}\b`)
	reUnixSec    = regexp.MustCompile(`\b1[0-9]{9}\b`)
	reLongHex    = regexp.MustCompile(`\b[0-9a-fA-F]{32,}\b`)
	reB64Token   = regexp.MustCompile(`\b[A-Za-z0-9+/_-]{40,}={0,2}\b`)
	reCSRFAttr   = regexp.MustCompile(`(?i)(csrf|xsrf|nonce|authenticity[_-]?token|_token|viewstate|request[_-]?verification)["'\s]*[:=]\s*["']?[A-Za-z0-9+/=_\-]{8,}["']?`)
	reCSRFMeta   = regexp.MustCompile(`(?i)(<meta[^>]+(?:csrf|xsrf|token)[^>]+content=)["'][^"']+["']`)
	reHiddenCSRF = regexp.MustCompile(`(?i)(<input[^>]+type=["']?hidden["']?[^>]*value=)["'][A-Za-z0-9+/=_\-]{8,}["']`)
	reWhitespace = regexp.MustCompile(`\s+`)
)

// normalizeContent replaces volatile values with placeholders so a dynamic page
// yields a stable representation across identical requests.
func normalizeContent(body string) string {
	b := body
	b = reCSRFMeta.ReplaceAllString(b, `${1}"<CSRF>"`)
	b = reHiddenCSRF.ReplaceAllString(b, `${1}"<CSRF>"`)
	b = reCSRFAttr.ReplaceAllString(b, `${1}=<CSRF>`)
	b = reUUID.ReplaceAllString(b, "<UUID>")
	b = reISO8601.ReplaceAllString(b, "<TS>")
	b = reUnixMs.ReplaceAllString(b, "<TS>")
	b = reUnixSec.ReplaceAllString(b, "<TS>")
	b = reLongHex.ReplaceAllString(b, "<HEX>")
	b = reB64Token.ReplaceAllString(b, "<TOKEN>")
	b = reWhitespace.ReplaceAllString(b, " ")
	return strings.TrimSpace(b)
}

// normalizedHash returns a stable SHA-256 of the normalized content.
func normalizedHash(body string) string {
	sum := sha256.Sum256([]byte(normalizeContent(body)))
	return hex.EncodeToString(sum[:])
}

// ── 2. Security-attribute detection ─────────────────────────────────────────

type securityAttr struct {
	Kind  string `json:"kind"`  // script|iframe|form|hidden|link|stylesheet
	Value string `json:"value"` // the src/action/href/name
}

type securitySnapshot struct {
	Attrs []securityAttr `json:"attrs"`
	// Headers holds the security-relevant response headers present on the page.
	// A header that DISAPPEARS between snapshots (e.g. Strict-Transport-Security,
	// Content-Security-Policy) is a high-severity regression.
	Headers map[string]string `json:"headers,omitempty"`
}

// securityHeaders are the response headers whose removal weakens the site's
// security posture — tracked so monitoring can flag a regression.
var securityHeaders = []string{
	"strict-transport-security",
	"content-security-policy",
	"x-frame-options",
	"x-content-type-options",
	"referrer-policy",
	"permissions-policy",
	"cross-origin-opener-policy",
	"cross-origin-resource-policy",
	"cross-origin-embedder-policy",
}

// extractSecurityHeaders pulls the tracked security headers (lower-cased) that
// are present in the response.
func extractSecurityHeaders(get func(string) string) map[string]string {
	out := map[string]string{}
	for _, h := range securityHeaders {
		if v := strings.TrimSpace(get(h)); v != "" {
			out[h] = v
		}
	}
	return out
}

// diffSecurityHeaders returns the tracked headers that were REMOVED (present in
// old, gone in cur). Added/tightened headers aren't a security regression.
func diffSecurityHeaders(old, cur map[string]string) []string {
	var removed []string
	for h := range old {
		if _, ok := cur[h]; !ok {
			removed = append(removed, h)
		}
	}
	sort.Strings(removed)
	return removed
}

// classifyChangeSeverity rates a monitoring change type for alert triage, so a
// removed security header or new redirect outranks a body-text tweak.
func classifyChangeSeverity(changeType string) string {
	switch {
	case strings.HasPrefix(changeType, "security_header_removed"),
		strings.HasPrefix(changeType, "security:"):
		return "high"
	case strings.Contains(changeType, "status"),
		strings.Contains(changeType, "redirect"):
		return "medium"
	case strings.Contains(changeType, "js_change"):
		return "medium"
	case strings.Contains(changeType, "http_change"):
		return "low"
	default:
		return "info"
	}
}

var (
	reScriptSrc = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)
	reIframeSrc = regexp.MustCompile(`(?i)<iframe[^>]+src\s*=\s*["']([^"']+)["']`)
	reFormAct   = regexp.MustCompile(`(?i)<form[^>]+action\s*=\s*["']([^"']+)["']`)
	reHiddenIn  = regexp.MustCompile(`(?i)<input[^>]+type\s*=\s*["']?hidden["']?[^>]*\bname\s*=\s*["']([^"']+)["']`)
	reLinkHref  = regexp.MustCompile(`(?i)<link[^>]+href\s*=\s*["']([^"']+)["']`)
	reAHref     = regexp.MustCompile(`(?i)<a[^>]+href\s*=\s*["'](https?://[^"']+)["']`)
)

// extractSecuritySnapshot pulls security-sensitive attributes from HTML. Only
// EXTERNAL (cross-origin) script/iframe/link/a values are kept — those are the
// supply-chain / phishing surface; same-origin resources are noise here.
func extractSecuritySnapshot(body, pageHost string) securitySnapshot {
	seen := map[string]bool{}
	var out []securityAttr
	add := func(kind, val string) {
		val = strings.TrimSpace(val)
		if val == "" {
			return
		}
		key := kind + "|" + val
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, securityAttr{Kind: kind, Value: val})
	}
	ext := func(u string) bool { return isExternalResource(u, pageHost) }

	for _, m := range reScriptSrc.FindAllStringSubmatch(body, -1) {
		if ext(m[1]) {
			add("script", m[1])
		}
	}
	for _, m := range reIframeSrc.FindAllStringSubmatch(body, -1) {
		if ext(m[1]) {
			add("iframe", m[1])
		}
	}
	for _, m := range reFormAct.FindAllStringSubmatch(body, -1) {
		add("form", m[1]) // ALL form actions matter (login form hijack)
	}
	for _, m := range reHiddenIn.FindAllStringSubmatch(body, -1) {
		add("hidden", m[1]) // hidden field names (added/removed = token handling change)
	}
	for _, m := range reLinkHref.FindAllStringSubmatch(body, -1) {
		if ext(m[1]) {
			add("stylesheet", m[1])
		}
	}
	for _, m := range reAHref.FindAllStringSubmatch(body, -1) {
		if ext(m[1]) {
			add("link", m[1])
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Value < out[j].Value
	})
	return securitySnapshot{Attrs: out}
}

// isExternalResource reports whether a resource URL points off the page's host.
func isExternalResource(u, pageHost string) bool {
	u = strings.TrimSpace(u)
	if strings.HasPrefix(u, "//") {
		u = "http:" + u
	}
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return false // relative / same-origin / data: / inline
	}
	h := hostOf(u)
	if h == "" || pageHost == "" {
		return h != ""
	}
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	pageHost = strings.ToLower(strings.TrimSuffix(pageHost, "."))
	return h != pageHost
}

func hostOf(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
}

func (s securitySnapshot) toJSON() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func parseSecuritySnapshot(js string) securitySnapshot {
	var s securitySnapshot
	if js != "" {
		_ = json.Unmarshal([]byte(js), &s)
	}
	return s
}

type securityChange struct {
	action string // added | removed
	attr   securityAttr
}

// diffSecuritySnapshots returns what security attributes were added/removed.
func diffSecuritySnapshots(old, cur securitySnapshot) []securityChange {
	oldSet := map[string]securityAttr{}
	for _, a := range old.Attrs {
		oldSet[a.Kind+"|"+a.Value] = a
	}
	curSet := map[string]securityAttr{}
	for _, a := range cur.Attrs {
		curSet[a.Kind+"|"+a.Value] = a
	}
	var out []securityChange
	for k, a := range curSet {
		if _, ok := oldSet[k]; !ok {
			out = append(out, securityChange{"added", a})
		}
	}
	for k, a := range oldSet {
		if _, ok := curSet[k]; !ok {
			out = append(out, securityChange{"removed", a})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].action != out[j].action {
			return out[i].action < out[j].action
		}
		if out[i].attr.Kind != out[j].attr.Kind {
			return out[i].attr.Kind < out[j].attr.Kind
		}
		return out[i].attr.Value < out[j].attr.Value
	})
	return out
}

// securityChangeSeverity rates a security-attribute change for bug-bounty
// relevance: a NEW external script/iframe or a changed form action is the
// dangerous case (supply-chain injection, form hijacking, clickjacking).
func securityChangeSeverity(c securityChange) string {
	if c.action == "added" {
		switch c.attr.Kind {
		case "script", "iframe", "form":
			return "high"
		case "stylesheet", "hidden":
			return "medium"
		default:
			return "low"
		}
	}
	// removals are lower signal (still worth noting for forms/scripts)
	switch c.attr.Kind {
	case "form", "hidden":
		return "medium"
	default:
		return "low"
	}
}
