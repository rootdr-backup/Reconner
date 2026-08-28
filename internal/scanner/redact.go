package scanner

import (
	"regexp"
	"strings"
)

// Redaction (Phase 11): credentials must never leak into evidence, logs,
// reports, or the frontend. These helpers scrub sensitive material from any
// text before it is stored or displayed. This is defence-in-depth — evidence is
// also built from already-safe fields where possible.

var (
	reAuthHeader   = regexp.MustCompile(`(?i)(authorization|proxy-authorization)\s*:\s*[^\r\n]+`)
	reCookieHeader = regexp.MustCompile(`(?i)(cookie|set-cookie)\s*:\s*[^\r\n]+`)
	reCSRFHeader   = regexp.MustCompile(`(?i)(x-csrf-token|x-xsrf-token|csrf-token)\s*:\s*[^\r\n]+`)
	reBearer       = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._\-]+`)
	reJWT          = regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}`)
	reAPIKeyKV     = regexp.MustCompile(`(?i)(api[_-]?key|access[_-]?token|secret|password|session|token)\s*[=:]\s*["']?[A-Za-z0-9._\-]{6,}["']?`)
)

// RedactText removes credentials from a free-text blob (request dumps, logs).
func RedactText(s string) string {
	s = reAuthHeader.ReplaceAllString(s, "$1: [REDACTED]")
	s = reCookieHeader.ReplaceAllString(s, "$1: [REDACTED]")
	s = reCSRFHeader.ReplaceAllString(s, "$1: [REDACTED]")
	s = reBearer.ReplaceAllString(s, "Bearer [REDACTED]")
	s = reJWT.ReplaceAllString(s, "[REDACTED-JWT]")
	s = reAPIKeyKV.ReplaceAllString(s, "$1=[REDACTED]")
	return s
}

// RedactHeaders returns a copy of a header map with sensitive values masked,
// keeping the KEY visible (so a report can say "Cookie was present") but never
// the value.
func RedactHeaders(h map[string]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		lk := strings.ToLower(k)
		switch {
		case lk == "cookie" || lk == "authorization" || lk == "proxy-authorization" ||
			strings.Contains(lk, "csrf") || strings.Contains(lk, "token") || strings.Contains(lk, "secret"):
			out[k] = "[REDACTED]"
		default:
			out[k] = v
		}
	}
	return out
}
