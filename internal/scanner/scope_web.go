package scanner

import (
	"net/url"
	"strings"
)

// SplitScope parses a target scope string into web host(s). Reconner is a web
// application scanner: the whole scope is treated as web hosts, and the network
// scope is always empty (the network module has been removed). Kept as a stable
// helper so target/asset creation and the scheduler share one parser.
//
// Accepts comma-, whitespace-, or newline-separated hosts/URLs.
func SplitScope(value string) (webHosts []string, netScope string) {
	value = strings.TrimSpace(value)
	// An individual endpoint URL may legitimately contain commas or semicolons
	// in its path/query. Treat a complete URL as one seed before considering the
	// legacy multi-scope delimiters. Literal whitespace or delimiters in the
	// authority indicate a multi-value string, not one endpoint URL.
	if isSingleHTTPURLSeed(value) {
		return []string{value}, ""
	}
	seen := map[string]bool{}
	for _, tok := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	}) {
		tok = strings.TrimSpace(tok)
		if tok == "" || seen[tok] {
			continue
		}
		seen[tok] = true
		webHosts = append(webHosts, tok)
	}
	return webHosts, ""
}

func isSingleHTTPURLSeed(value string) bool {
	if value == "" || strings.ContainsAny(value, " \t\r\n") {
		return false
	}
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return false
	}
	return !strings.ContainsAny(u.Hostname(), ",;")
}
