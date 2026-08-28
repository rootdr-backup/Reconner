package scanner

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/html"
)

// Deep Authenticated Authorization Crawl. Given origin + one identity it crawls
// AS THAT IDENTITY capturing real HTTP requests, from HTML links/forms, JSON
// leaves, pagination, first-party JS, OpenAPI docs, and response-guided feedback.

type RequestNode struct {
	RequestID       string
	IdentityLabel   string
	Method          string
	URL             string
	NormURL         string
	ContentType     string
	Body            string
	Status          int
	RespCT          string
	RespBody        string
	Fingerprint     string
	Depth           int
	Parent          string
	Source          string
	DiscoveryMethod string
	External        bool
	ObjectRefs      []AuthzRef
}

type IdentityGraph struct {
	IdentityLabel string
	Nodes         []*RequestNode
	byKey         map[string]*RequestNode
	Partial       bool
	StopReason    string
}

func newIdentityGraph(label string) *IdentityGraph {
	return &IdentityGraph{IdentityLabel: label, byKey: map[string]*RequestNode{}}
}
func (g *IdentityGraph) key(method, normURL string) string { return strings.ToUpper(method) + "|" + normURL }
func (g *IdentityGraph) seen(method, normURL string) bool {
	_, ok := g.byKey[g.key(method, normURL)]
	return ok
}
func (g *IdentityGraph) add(n *RequestNode) {
	g.byKey[g.key(n.Method, n.NormURL)] = n
	g.Nodes = append(g.Nodes, n)
}

type CrawlPolicy struct {
	MaxDepth        int
	MaxRequests     int
	MaxPerHost      int
	MaxRespBytes    int64
	RequestTimeout  time.Duration
	OverallTimeout  time.Duration
	MaxPagesPerList int
}

func crawlDepthPolicy(prof AuthzProfile) CrawlPolicy {
	switch prof {
	case AuthzSafe:
		return CrawlPolicy{MaxDepth: 4, MaxRequests: 300, MaxPerHost: 300, MaxRespBytes: 512 * 1024,
			RequestTimeout: 12 * time.Second, OverallTimeout: 4 * time.Minute, MaxPagesPerList: 5}
	case AuthzDeep:
		return CrawlPolicy{MaxDepth: 8, MaxRequests: 1500, MaxPerHost: 1200, MaxRespBytes: 1024 * 1024,
			RequestTimeout: 15 * time.Second, OverallTimeout: 15 * time.Minute, MaxPagesPerList: 25}
	default:
		return CrawlPolicy{MaxDepth: 6, MaxRequests: 700, MaxPerHost: 600, MaxRespBytes: 768 * 1024,
			RequestTimeout: 12 * time.Second, OverallTimeout: 8 * time.Minute, MaxPagesPerList: 12}
	}
}

type AuthenticatedCrawler struct {
	Identity     *Identity
	TargetDomain string
	Origins      []string
	Policy       CrawlPolicy
	Log          func(stage, msg string)
	graph        *IdentityGraph
	perHost      map[string]int
	deadline     time.Time
	requests     int
}

func NewAuthenticatedCrawler(id *Identity, targetDomain string, origins []string, pol CrawlPolicy, log func(stage, msg string)) *AuthenticatedCrawler {
	if log == nil {
		log = func(string, string) {}
	}
	label := "unauthenticated"
	if id != nil {
		label = id.Label
	}
	return &AuthenticatedCrawler{Identity: id, TargetDomain: targetDomain, Origins: origins, Policy: pol, Log: log,
		graph: newIdentityGraph(label), perHost: map[string]int{}}
}

type crawlItem struct {
	method, url, body, ct, source, parent string
	depth                                 int
}

func (c *AuthenticatedCrawler) Crawl(ctx context.Context, seeds []string) *IdentityGraph {
	c.deadline = time.Now().Add(c.Policy.OverallTimeout)
	if c.Identity != nil && c.Identity.ValidationURL != "" {
		if st := ValidateSession(ctx, *c.Identity); st != "authenticated" {
			c.graph.Partial = true
			c.graph.StopReason = "identity session not authenticated at start (" + st + ")"
			c.Log("crawl", c.graph.IdentityLabel+": session "+st+" — refusing to crawl with a dead session")
			return c.graph
		}
	}
	q := make([]crawlItem, 0, len(seeds))
	for _, s := range seeds {
		q = append(q, crawlItem{method: "GET", url: s, source: "manual-seed", depth: 0})
	}
	for _, wk := range c.wellKnownSeeds(seeds) {
		q = append(q, crawlItem{method: "GET", url: wk.url, source: wk.source, depth: 0})
	}
	for len(q) > 0 {
		if ctx.Err() != nil || time.Now().After(c.deadline) {
			c.graph.Partial = true
			c.graph.StopReason = "overall timeout / context cancelled"
			break
		}
		if c.requests >= c.Policy.MaxRequests {
			c.graph.Partial = true
			c.graph.StopReason = "request budget reached"
			break
		}
		item := q[0]
		q = q[1:]
		if item.depth > c.Policy.MaxDepth {
			continue
		}
		nu := NormalizeURL(item.url)
		if c.graph.seen(item.method, nu) {
			continue
		}
		host := hostOfURL(item.url)
		if host != "" && c.perHost[host] >= c.Policy.MaxPerHost {
			continue
		}
		inScope := URLInScope(c.TargetDomain, c.Origins, item.url)
		node := &RequestNode{RequestID: newReqID(), IdentityLabel: c.graph.IdentityLabel, Method: item.method,
			URL: item.url, NormURL: nu, ContentType: item.ct, Body: item.body, Depth: item.depth,
			Parent: item.parent, Source: item.source, DiscoveryMethod: item.source, External: !inScope}
		if !inScope {
			c.graph.add(node)
			continue
		}
		if item.method != "GET" && item.method != "HEAD" {
			c.graph.add(node)
			continue
		}
		resp := c.fetch(ctx, item.method, item.url)
		c.requests++
		c.perHost[host]++
		node.Status = resp.status
		node.RespCT = resp.ct
		node.RespBody = resp.body
		node.Fingerprint = BodyHash(resp.body)
		node.ObjectRefs = extractObjectRefs(item.url, resp.ct, resp.body, nil)
		c.graph.add(node)
		if resp.err != nil {
			continue
		}
		if c.Identity != nil && c.Identity.ValidationURL != "" && c.requests%40 == 0 {
			if st := ValidateSession(ctx, *c.Identity); st != "authenticated" {
				c.graph.Partial = true
				c.graph.StopReason = "identity session drifted to " + st + " mid-crawl"
				c.Log("crawl", c.graph.IdentityLabel+": session drifted ("+st+") — stopping")
				break
			}
		}
		for _, d := range c.discover(item.url, resp, item.depth) {
			if !c.graph.seen(d.method, NormalizeURL(d.url)) {
				q = append(q, d)
			}
		}
	}
	return c.graph
}

type crawlResp struct {
	status int
	ct     string
	body   string
	link   string
	err    error
}

func (c *AuthenticatedCrawler) fetch(ctx context.Context, method, rawURL string) crawlResp {
	rctx, cancel := context.WithTimeout(ctx, c.Policy.RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, strings.ToUpper(method), rawURL, nil)
	if err != nil {
		return crawlResp{err: err}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Reconner/1.0)")
	if c.Identity != nil {
		if c.Identity.UserAgent != "" {
			req.Header.Set("User-Agent", c.Identity.UserAgent)
		}
		for k, v := range c.Identity.Headers {
			req.Header.Set(k, v)
		}
	}
	resp, err := identityHTTPClient.Do(req)
	if err != nil {
		return crawlResp{err: err}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, c.Policy.MaxRespBytes))
	return crawlResp{status: resp.StatusCode, ct: resp.Header.Get("Content-Type"), body: string(b), link: resp.Header.Get("Link")}
}

func (c *AuthenticatedCrawler) discover(fromURL string, resp crawlResp, depth int) []crawlItem {
	var out []crawlItem
	ct := strings.ToLower(resp.ct)
	nd := depth + 1
	switch {
	case strings.Contains(ct, "html"):
		out = append(out, c.discoverHTML(fromURL, resp.body, nd)...)
	case strings.Contains(ct, "json"), strings.Contains(ct, "yaml"), strings.Contains(ct, "yml"):
		if looksLikeOpenAPI(resp.body) {
			out = append(out, discoverOpenAPI(fromURL, resp.body, nd)...)
		}
		out = append(out, c.discoverJSON(fromURL, resp.body, nd)...)
	case strings.Contains(ct, "javascript"):
		out = append(out, c.discoverJS(fromURL, resp.body, nd)...)
	}
	for _, nextURL := range parseLinkHeaderNext(resp.link) {
		abs := resolveRef(fromURL, nextURL)
		if abs != "" {
			out = append(out, crawlItem{method: "GET", url: abs, source: "pagination", parent: fromURL, depth: nd})
		}
	}
	return out
}

func (c *AuthenticatedCrawler) discoverHTML(fromURL, body string, depth int) []crawlItem {
	var out []crawlItem
	z := html.NewTokenizer(strings.NewReader(body))
	var curForm *formSpec
	flushForm := func() {
		if curForm == nil {
			return
		}
		if it, ok := curForm.toCrawlItem(fromURL, depth); ok {
			out = append(out, it)
		}
		curForm = nil
	}
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		tok := z.Token()
		switch tok.Data {
		case "a", "link":
			if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
				if href := attr(tok, "href"); href != "" {
					if abs := resolveRef(fromURL, href); abs != "" && isHTTPish(abs) {
						out = append(out, crawlItem{method: "GET", url: abs, source: "html", parent: fromURL, depth: depth})
					}
				}
			}
		case "script":
			if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
				if src := attr(tok, "src"); src != "" {
					if abs := resolveRef(fromURL, src); abs != "" && isHTTPish(abs) {
						out = append(out, crawlItem{method: "GET", url: abs, source: "javascript", parent: fromURL, depth: depth})
					}
				}
			}
		case "form":
			if tt == html.StartTagToken {
				flushForm()
				curForm = &formSpec{action: attr(tok, "action"), method: strings.ToUpper(attr(tok, "method")), fields: map[string]string{}}
			} else if tt == html.EndTagToken {
				flushForm()
			}
		case "input", "textarea", "select":
			if curForm != nil && (tt == html.StartTagToken || tt == html.SelfClosingTagToken) {
				if n := attr(tok, "name"); n != "" {
					curForm.fields[n] = attr(tok, "value")
				}
			}
		}
	}
	flushForm()
	return out
}

func (c *AuthenticatedCrawler) discoverJSON(fromURL, body string, depth int) []crawlItem {
	var out []crawlItem
	for _, s := range jsonPathStrings(body) {
		abs := resolveRef(fromURL, s)
		if abs != "" && isHTTPish(abs) {
			out = append(out, crawlItem{method: "GET", url: abs, source: "json", parent: fromURL, depth: depth})
		}
	}
	for _, s := range jsonNextLinks(body) {
		abs := resolveRef(fromURL, s)
		if abs != "" && isHTTPish(abs) {
			out = append(out, crawlItem{method: "GET", url: abs, source: "pagination", parent: fromURL, depth: depth})
		}
	}
	return out
}

func (c *AuthenticatedCrawler) discoverJS(fromURL, body string, depth int) []crawlItem {
	var out []crawlItem
	for _, cand := range extractJSRequestCandidates(body) {
		if strings.ContainsAny(cand, "${}+`") {
			continue
		}
		abs := resolveRef(fromURL, cand)
		if abs != "" && isHTTPish(abs) {
			out = append(out, crawlItem{method: "GET", url: abs, source: "javascript", parent: fromURL, depth: depth})
		}
	}
	return out
}

func (c *AuthenticatedCrawler) wellKnownSeeds(seeds []string) []struct{ url, source string } {
	var out []struct{ url, source string }
	origins := map[string]bool{}
	for _, s := range seeds {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			origins[u.Scheme+"://"+u.Host] = true
		}
	}
	for o := range origins {
		out = append(out, struct{ url, source string }{o + "/robots.txt", "robots"})
		out = append(out, struct{ url, source string }{o + "/sitemap.xml", "sitemap"})
		for _, doc := range []string{"/openapi.json", "/openapi.yaml", "/swagger.json",
			"/swagger.yaml", "/api-docs", "/v2/api-docs", "/v3/api-docs", "/.well-known/openapi.json"} {
			out = append(out, struct{ url, source string }{o + doc, "openapi"})
		}
	}
	return out
}

type formSpec struct {
	action string
	method string
	fields map[string]string
}

func (f *formSpec) toCrawlItem(fromURL string, depth int) (crawlItem, bool) {
	action := resolveRef(fromURL, f.action)
	if action == "" {
		action = fromURL
	}
	if !isHTTPish(action) {
		return crawlItem{}, false
	}
	m := f.method
	if m == "" {
		m = "GET"
	}
	vals := url.Values{}
	names := make([]string, 0, len(f.fields))
	for k := range f.fields {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		vals.Set(k, f.fields[k])
	}
	if m == "GET" {
		u := action
		if enc := vals.Encode(); enc != "" {
			if strings.Contains(u, "?") {
				u += "&" + enc
			} else {
				u += "?" + enc
			}
		}
		return crawlItem{method: "GET", url: u, source: "form", parent: fromURL, depth: depth}, true
	}
	return crawlItem{method: m, url: action, body: vals.Encode(),
		ct: "application/x-www-form-urlencoded", source: "form", parent: fromURL, depth: depth}, true
}

var (
	reJSFetch  = regexp.MustCompile(`(?:fetch|axios(?:\.\w+)?|\.(?:get|post|put|patch|delete)|ajax|open)\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`)
	reJSPath   = regexp.MustCompile(`["'` + "`" + `](/(?:api|rest|graphql|gql|v\d)/[a-zA-Z0-9_\-/${}.:?=&%]+)["'` + "`" + `]`)
	reJSONNxt  = regexp.MustCompile(`"(?:next|next_page|next_cursor|nextUrl|next_url|nextPage)"\s*:\s*"([^"]+)"`)
	reJSONPath = regexp.MustCompile(`"((?:https?://[^"\s]{4,300})|(?:/[a-zA-Z0-9_][a-zA-Z0-9_\-/.]{1,250}))"`)
	reReqID    = 0
)

func extractJSRequestCandidates(js string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, m := range reJSFetch.FindAllStringSubmatch(js, -1) {
		add(m[1])
	}
	for _, m := range reJSPath.FindAllStringSubmatch(js, -1) {
		add(m[1])
	}
	return out
}

func jsonPathStrings(body string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range reJSONPath.FindAllStringSubmatch(body, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

func jsonNextLinks(body string) []string {
	var out []string
	for _, m := range reJSONNxt.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

func parseLinkHeaderNext(link string) []string {
	if link == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(link, ",") {
		lp := strings.ToLower(part)
		if !strings.Contains(lp, `rel="next"`) && !strings.Contains(lp, "rel=next") {
			continue
		}
		if i := strings.Index(part, "<"); i >= 0 {
			if j := strings.Index(part[i+1:], ">"); j >= 0 {
				out = append(out, part[i+1:i+1+j])
			}
		}
	}
	return out
}

func attr(tok html.Token, name string) string {
	for _, a := range tok.Attr {
		if strings.EqualFold(a.Key, name) {
			return a.Val
		}
	}
	return ""
}

func isHTTPish(u string) bool {
	return strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")
}

func newReqID() string {
	reReqID++
	return "req-" + itoa(reReqID)
}
