package scanner

import "strings"

// SplitScope parses a target scope string into web host(s). Reconner is a web
// application scanner: the whole scope is treated as web hosts, and the network
// scope is always empty (the network module has been removed). Kept as a stable
// helper so target/asset creation and the scheduler share one parser.
//
// Accepts comma-, whitespace-, or newline-separated hosts/URLs.
func SplitScope(value string) (webHosts []string, netScope string) {
	seen := map[string]bool{}
	for _, tok := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
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
