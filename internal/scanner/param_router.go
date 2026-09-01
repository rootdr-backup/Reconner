package scanner

import (
	"regexp"
	"strings"
	"unicode"
)

// Endpoint → vulnerability routing (Phase 2).
//
// Every discovered parameter is classified — by its NAME tokens and its example
// VALUE — into the vulnerability classes whose detectors are worth running on it.
// This replaces the scattered, exact-match per-module keyword maps (which missed
// returnUrl / image_url / file_path because they weren't literally in the list)
// and the SQL `LIKE '%to%'` prefilter (which matched "token"/"photo"). Modules ask
// paramProneTo(class, name, value) so a param-heavy target is tested where it
// actually matters instead of shotgunning every parameter with every payload.
//
// Matching is TOKEN-based, not substring: "redirect_url" and "returnUrl" split to
// {redirect,url} / {return,url} and match, while "token" (→ {token}) does NOT
// match the redirect token "to". Value heuristics add signal a name can't: a
// value that IS a URL routes to SSRF + open-redirect regardless of the param name.

// VulnClass is a routing target (matches the vuln_findings `type` vocabulary).
type VulnClass string

const (
	ClassSSRF     VulnClass = "ssrf"
	ClassRedirect VulnClass = "open_redirect"
	ClassLFI      VulnClass = "lfi"
	ClassSQLi     VulnClass = "sqli"
	ClassIDOR     VulnClass = "idor"
	ClassSSTI     VulnClass = "ssti"
	ClassCMDi     VulnClass = "cmdi"
	ClassNoSQLi   VulnClass = "nosqli"
	ClassCRLF     VulnClass = "crlf"
	ClassXSS      VulnClass = "xss"
)

// classTokens: a parameter matches a class when ANY of its name tokens is in the
// class set. Curated from gf-patterns / Assetnote parameter research + the legacy
// per-module lists (so this is a strict superset of the old exact-match maps).
var classTokens = map[VulnClass]map[string]bool{
	ClassSSRF: set("url", "uri", "link", "redirect", "return", "dest", "destination",
		"callback", "webhook", "proxy", "image", "imageurl", "img", "fileurl", "feed",
		"fetch", "resource", "remote", "domain", "host", "site", "target", "source",
		"forward", "load", "port", "continue", "next", "data", "reference", "ref"),
	ClassRedirect: set("url", "redirect", "redir", "next", "return", "returnurl", "goto",
		"dest", "destination", "target", "link", "location", "back", "forward",
		"continue", "to", "out", "checkout", "callback", "success", "cancel", "go"),
	ClassLFI: set("file", "page", "path", "doc", "document", "folder", "root", "pg",
		"include", "inc", "template", "tpl", "style", "view", "content", "layout",
		"lang", "language", "download", "read", "cat", "dir", "board", "detail",
		"show", "conf", "config", "load", "filename", "filepath", "src", "item",
		"module", "mod", "class", "pdf", "attachment", "download_file"),
	ClassSQLi: set("id", "user", "userid", "order", "sort", "orderby", "filter", "query",
		"search", "column", "field", "category", "cat", "select", "where", "group",
		"status", "type", "key", "table", "row", "num", "count", "limit", "offset"),
	ClassIDOR: set("id", "uid", "userid", "account", "acct", "order", "orderid", "invoice",
		"doc", "docid", "file", "fileid", "object", "objectid", "key", "ref", "number",
		"profile", "customer", "member", "record", "item", "itemid", "group", "no",
		"pid", "gid", "cid", "aid"),
	ClassSSTI: set("template", "tpl", "preview", "name", "message", "content", "subject",
		"body", "title", "greeting", "render", "email", "text"),
	ClassCMDi: set("cmd", "command", "exec", "execute", "ping", "host", "ip", "query",
		"jump", "code", "func", "option", "process", "daemon", "run", "shell", "system",
		"do", "cli", "download", "log"),
	ClassNoSQLi: set("user", "username", "email", "login", "password", "pass", "account",
		"id", "uid", "query", "search", "filter", "where", "selector", "match", "lookup",
		"name", "token", "key", "value", "criteria", "condition", "sort", "role"),
	ClassCRLF: set("url", "redirect", "next", "return", "location", "header", "host", "domain",
		"file", "filename", "download", "disposition", "name", "value", "lang", "path", "callback"),
	ClassXSS: set("q", "query", "search", "keyword", "name", "message", "comment", "text",
		"content", "title", "description", "input", "term", "redirect", "url", "return",
		"callback", "lang", "view", "tab", "id", "page"),
}

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, i := range items {
		m[i] = true
	}
	return m
}

var (
	tokenSplitRE  = regexp.MustCompile(`[^a-z0-9]+`)
	fileValueRE   = regexp.MustCompile(`(?i)\.(php|asp|aspx|jsp|json|xml|txt|log|conf|cfg|ini|pdf|html?|bak|env|yml|yaml|properties)$`)
	numericValRE  = regexp.MustCompile(`^\d{1,19}$`)
	uuidValRE     = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	urlishValueRE = regexp.MustCompile(`(?i)^(https?:)?//`)
)

// paramTokens splits a parameter name into lowercase tokens, breaking on
// delimiters (_-.[]/ etc.) AND camelCase / letter↔digit boundaries, so
// "returnUrl", "redirect_uri", and "imageURL2" all yield clean tokens.
func paramTokens(name string) []string {
	var sb strings.Builder
	var prev rune
	for _, r := range name {
		if prev != 0 {
			if (unicode.IsLower(prev) && unicode.IsUpper(r)) ||
				(unicode.IsLetter(prev) && unicode.IsDigit(r)) ||
				(unicode.IsDigit(prev) && unicode.IsLetter(r)) {
				sb.WriteByte('_')
			}
		}
		sb.WriteRune(r)
		prev = r
	}
	raw := tokenSplitRE.Split(strings.ToLower(sb.String()), -1)
	out := raw[:0]
	for _, t := range raw {
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

// valueClasses derives routing signal from an example parameter VALUE.
func valueClasses(value string) map[VulnClass]bool {
	out := map[VulnClass]bool{}
	v := strings.TrimSpace(value)
	if v == "" {
		return out
	}
	switch {
	case urlishValueRE.MatchString(v):
		out[ClassSSRF] = true
		out[ClassRedirect] = true
	}
	if strings.ContainsAny(v, "/\\") || fileValueRE.MatchString(v) {
		out[ClassLFI] = true
	}
	if numericValRE.MatchString(v) || uuidValRE.MatchString(v) {
		out[ClassIDOR] = true
	}
	return out
}

// classifyParam returns every vulnerability class a parameter routes to, from its
// name tokens plus its example value.
func classifyParam(name, value string) map[VulnClass]bool {
	out := map[VulnClass]bool{}
	tokens := paramTokens(name)
	for class, toks := range classTokens {
		for _, t := range tokens {
			if toks[t] {
				out[class] = true
				break
			}
		}
	}
	for c := range valueClasses(value) {
		out[c] = true
	}
	return out
}

// paramProneTo reports whether a parameter is worth testing for a given class.
func paramProneTo(class VulnClass, name, value string) bool {
	return classifyParam(name, value)[class]
}
