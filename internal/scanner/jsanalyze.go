package scanner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// jsanalyze.go ports two high-value, low-false-positive ideas from the jsrecon
// tool into Reconner:
//
//  1. SOURCE-MAP RECOVERY: a minified bundle often ships (or references) a
//     .map that carries the ORIGINAL, un-minified source in `sourcesContent`.
//     Reconner previously only flagged "a source map exists"; now we actually
//     fetch it and recover the original source, then run the normal secret /
//     endpoint extraction over it — where hard-coded keys and internal routes
//     are readable instead of mangled.
//
//  2. LIBRARY FINGERPRINT → KNOWN-CVE MATCH: identify front-end libraries and
//     versions in the JS and flag those with public CVEs (outdated jQuery,
//     Bootstrap, lodash, Moment, DataTables, AngularJS…). Version-based, so it
//     is surfaced as a CANDIDATE (heuristic), never a confirmed finding.

// ── 1. Source-map recovery ───────────────────────────────────────────────────

var reSourceMapRef = regexp.MustCompile(`(?://|/\*)[#@]\s*sourceMappingURL=([^\s*'"]+)`)

type sourceMap struct {
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

// recoverSourceMapSources finds a sourceMappingURL in the JS, fetches the map
// (inline data: URI or a sibling URL), and returns the recovered original
// sources concatenated. Empty when there's no map or it carries no content.
func recoverSourceMapSources(ctx context.Context, client *http.Client, jsURL, content string) string {
	m := reSourceMapRef.FindStringSubmatch(content)
	if m == nil {
		return ""
	}
	ref := strings.TrimSpace(m[1])

	var raw string
	if strings.HasPrefix(ref, "data:") {
		// data:application/json;base64,<...> or url-encoded.
		_, payload, ok := strings.Cut(ref, ",")
		if !ok {
			return ""
		}
		if strings.Contains(ref[:strings.Index(ref, ",")], ";base64") {
			b, err := base64.StdEncoding.DecodeString(payload)
			if err != nil {
				return ""
			}
			raw = string(b)
		} else if dec, err := url.QueryUnescape(payload); err == nil {
			raw = dec
		}
	} else {
		mapURL := resolveRef(jsURL, ref)
		if mapURL == "" {
			return ""
		}
		reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, "GET", mapURL, nil)
		if err != nil {
			return ""
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
		resp, err := client.Do(req)
		if err != nil {
			return ""
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return ""
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 20*1024*1024))
		raw = string(b)
	}

	if raw == "" {
		return ""
	}
	var sm sourceMap
	if json.Unmarshal([]byte(raw), &sm) != nil {
		return ""
	}
	if len(sm.SourcesContent) == 0 {
		return ""
	}
	var b strings.Builder
	for _, c := range sm.SourcesContent {
		if c != "" {
			b.WriteString(c)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// resolveRef resolves a (possibly relative) reference against a base URL.
func resolveRef(base, ref string) string {
	bu, err := url.Parse(base)
	if err != nil {
		return ""
	}
	ru, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return bu.ResolveReference(ru).String()
}

// ── 2. Library fingerprint + known-CVE matching ──────────────────────────────

type jsLibSig struct {
	name string
	re   *regexp.Regexp
}

var jsLibSignatures = []jsLibSig{
	{"jQuery", regexp.MustCompile(`(?i)jquery\s*[:=]\s*["']([\d.]+)["']`)},
	{"jQuery", regexp.MustCompile(`jQuery JavaScript Library v([\d.]+)`)},
	{"jQuery UI", regexp.MustCompile(`jQuery UI[ \-]v?([\d.]+)`)},
	{"Bootstrap", regexp.MustCompile(`Bootstrap v([\d.]+)`)},
	{"DataTables", regexp.MustCompile(`DataTables ([\d.]+)`)},
	{"Moment.js", regexp.MustCompile(`moment\.version\s*=\s*["']([\d.]+)["']`)},
	{"Lodash", regexp.MustCompile(`(?i)lodash[@ ]([\d.]+)`)},
	{"Vue.js", regexp.MustCompile(`Vue.{0,30}version\s*[:=]\s*["']([\d.]+)["']`)},
	{"AngularJS", regexp.MustCompile(`(?i)angular.{0,20}?full["']?\s*[:=]?\s*["']([\d.]+)["']`)},
	{"Handlebars", regexp.MustCompile(`Handlebars.{0,20}VERSION\s*=\s*["']([\d.]+)["']`)},
	{"Axios", regexp.MustCompile(`axios[@/ ]([\d]+\.[\d]+\.[\d]+)`)},
	{"Select2", regexp.MustCompile(`Select2:.{0,40}?([\d]+\.[\d]+\.[\d]+)`)},
}

type jsCVE struct {
	constraint string // "<X.Y.Z" | "N.x" | "*"
	note       string
	severity   string
}

var jsKnownIssues = map[string][]jsCVE{
	"jQuery": {{"<3.5.0", "CVE-2020-11022/11023: XSS via htmlPrefilter/DOM manipulation", "medium"}},
	"Bootstrap": {
		{"<4.0.0", "XSS in data-target / tooltip (3.x branch)", "medium"},
		{"4.x", "Bootstrap 4 branch EOL; CVE-2024-6484/6485 XSS", "medium"},
	},
	"DataTables": {
		{"<1.10.23", "CVE-2020-28458: Prototype Pollution", "medium"},
		{"<1.11.3", "CVE-2021-23445: XSS", "medium"},
	},
	"Moment.js": {
		{"<2.29.2", "CVE-2022-24785: path traversal in locale", "medium"},
		{"<2.29.4", "CVE-2022-31129: ReDoS", "low"},
	},
	"Lodash":    {{"<4.17.21", "CVE-2021-23337 / CVE-2020-8203: Prototype Pollution / Cmd Injection", "high"}},
	"AngularJS": {{"*", "AngularJS EOL since Jan 2022; multiple XSS/sandbox-bypass CVEs", "medium"}},
}

type jsLibHit struct {
	Name, Version, Note, Severity string
}

// fingerprintVulnerableLibraries returns libraries whose detected version
// matches a known-CVE constraint.
func fingerprintVulnerableLibraries(content string) []jsLibHit {
	libs := map[string]string{}
	for _, sig := range jsLibSignatures {
		if m := sig.re.FindStringSubmatch(content); m != nil {
			ver := ""
			for _, g := range m[1:] {
				if g != "" {
					ver = g
					break
				}
			}
			if _, ok := libs[sig.name]; !ok || (libs[sig.name] == "" && ver != "") {
				libs[sig.name] = ver
			}
		}
	}
	var hits []jsLibHit
	for name, ver := range libs {
		for _, cve := range jsKnownIssues[name] {
			if versionMatchesConstraint(ver, cve.constraint) {
				hits = append(hits, jsLibHit{name, ver, cve.note, cve.severity})
			}
		}
	}
	return hits
}

func parseVerNums(v string) []int {
	parts := regexp.MustCompile(`\d+`).FindAllString(v, 4)
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, _ := strconv.Atoi(p)
		out = append(out, n)
	}
	if len(out) == 0 {
		out = []int{0}
	}
	return out
}

func verLess(a, b []int) bool {
	for i := 0; i < len(a) || i < len(b); i++ {
		av, bv := 0, 0
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av != bv {
			return av < bv
		}
	}
	return false
}

// versionMatchesConstraint mirrors jsrecon's constraint matcher: "*", "N.x",
// "<X.Y.Z".
func versionMatchesConstraint(ver, constraint string) bool {
	if constraint == "*" {
		return true
	}
	if ver == "" {
		return false
	}
	if strings.HasSuffix(constraint, ".x") {
		major := strings.SplitN(constraint, ".", 2)[0]
		return strconv.Itoa(parseVerNums(ver)[0]) == major
	}
	if strings.HasPrefix(constraint, "<") {
		return verLess(parseVerNums(ver), parseVerNums(constraint[1:]))
	}
	if strings.HasPrefix(constraint, ">") {
		return verLess(parseVerNums(constraint[1:]), parseVerNums(ver))
	}
	return false
}
