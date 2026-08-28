package scanner

import "strings"

// OAST/blind-detection helpers shared across web detectors (formerly co-located
// with the now-removed network module).

// oobHostOnly returns the bare host (no scheme, path, or port) of a callback base.
func oobHostOnly(base string) string {
	h := stripScheme(base)
	if i := strings.IndexByte(h, '/'); i >= 0 {
		h = h[:i]
	}
	if !strings.HasPrefix(h, "[") {
		if i := strings.LastIndexByte(h, ':'); i >= 0 {
			h = h[:i]
		}
	}
	return h
}

// log4ShellHeaders are the request headers a Log4Shell (CVE-2021-44228) JNDI probe
// is injected into during web OAST testing.
var log4ShellHeaders = []string{
	"User-Agent", "Referer", "X-Api-Version", "X-Forwarded-For", "X-Forwarded-Host",
	"X-Client-IP", "True-Client-IP", "X-Real-IP", "Originating-IP", "X-Requested-With",
	"Accept-Language", "X-Druid-Comment", "Contact", "X-Api-Key", "Authorization",
}
