package scanner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// reflectProbe is a fixed marker kept only for the fallback path. The primary
// reflection check now uses a UNIQUE random canary per request (ex-param style),
// so a value that merely happens to sit on the page can't be mistaken for a
// reflection of our injected input.
const reflectProbe = "r3fl3ct9xPROBE"

// reflectMarker is the branded, human-recognizable canary base injected into the
// parameter's value. It carries a unique random suffix per request so a value
// that merely happens to sit on the page can't be mistaken for a reflection of
// OUR injected input — but the constant "rootdrreflect" prefix means you can spot
// exactly which value Reconner injected when you view the page source.
const reflectMarker = "rootdrreflect"

// randomCanary returns an unmistakable, unique token (letters+hex only, so it is
// never URL-encoded and survives verbatim into HTML). It always contains the
// reflectMarker prefix so the injected value is identifiable in the page source.
func randomCanary() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return reflectMarker + hex.EncodeToString(b)
}

var reflectClient = &http.Client{
	Timeout:   8 * time.Second,
	Transport: sharedHTTPTransport,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// checkParamReflection injects a unique canary into `param` and reports whether it
// is reflected VERBATIM into the HTML body (outside <script>/<style>), plus whether
// the response is an HTML document at all (htmlSink) so the caller can decide to
// escalate a non-reflected-but-HTML param to a real browser (SPA/DOM reflection).
// It retries once on a transient/WAF failure. A random per-request canary rules out
// coincidental matches; script/style stripping rules out JS-only echoes.
func checkParamReflection(rawURL, param string) (reflected, htmlSink bool) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false, false
	}

	canary := randomCanary()
	q := parsed.Query()
	q.Set(param, canary)
	parsed.RawQuery = q.Encode()

	var body []byte
	var ctype string
	var nosniff bool
	ok := false
	for attempt := 0; attempt < 2; attempt++ { // one retry: WAF/edge can drop the first probe
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		req, err := http.NewRequestWithContext(ctx, "GET", parsed.String(), nil)
		if err != nil {
			cancel()
			return false, false
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		resp, err := reflectClient.Do(req)
		if err != nil {
			cancel()
			continue
		}
		body, _ = io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		ctype = resp.Header.Get("Content-Type")
		nosniff = strings.EqualFold(strings.TrimSpace(resp.Header.Get("X-Content-Type-Options")), "nosniff")
		resp.Body.Close()
		cancel()
		ok = true
		break
	}
	if !ok {
		return false, false
	}

	// The reflection only matters if a browser would render this response as an HTML
	// document — a canary echoed into application/json (or other non-HTML) is not an
	// HTML-context reflected parameter. nosniff makes a body-signature guess
	// non-authoritative. Mirrors the DAST/verifier Content-Type gate and stops
	// JSON-API reflections (the ably.com clientId case) inflating the count.
	htmlSink = browserRendersAsHTML(ctype, string(body), nosniff)
	if !htmlSink {
		return false, false
	}

	// Count a reflection that appears VERBATIM in the returned HTML body (outside
	// <script>/<style>).
	html := stripScriptStyle(string(body))
	return strings.Contains(html, canary), true
}

var reScriptStyleBlock = regexp.MustCompile(`(?is)<(script|style)\b[^>]*>.*?</(script|style)>`)

// stripScriptStyle removes <script> and <style> blocks so reflections that live
// only inside JS/CSS don't count as HTML-context reflected parameters.
func stripScriptStyle(html string) string {
	return reScriptStyleBlock.ReplaceAllString(html, "")
}

// redirectClass is the verdict of an open-redirect probe.
type redirectClass int

const (
	redirectNone     redirectClass = iota // param never triggers a redirect
	redirectInternal                      // redirects, but final host is same-origin → CANDIDATE
	redirectExternal                      // final host is attacker-controlled → VERIFIED FINDING
)

// openRedirectResult carries the verdict plus the provenance (the full redirect
// chain) so the finding can show exactly how it was proven.
type openRedirectResult struct {
	class    redirectClass
	testURL  string
	finalLoc string
	chain    string // human-readable hop-by-hop chain (provenance)
}

const evilRedirectHost = "evil.com"

// checkOpenRedirectURL injects redirect payloads and FOLLOWS the redirect chain
// manually (up to 8 hops), returning whether the final destination leaves the
// origin (external = verified) or stays same-origin/relative (internal =
// candidate). Per spec, only an external final Location is a real finding.
func checkOpenRedirectURL(rawURL, param string) (openRedirectResult, bool) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return openRedirectResult{}, false
	}
	originHost := strings.ToLower(strings.TrimPrefix(parsed.Hostname(), "www."))

	payloads := []string{
		"https://evil.com",
		"//evil.com",
		"https://evil.com/",
		"//evil.com/%2F..",
		"/\\evil.com",
		"\\/\\/evil.com",
		"https:/evil.com",
		"https://target.example@evil.com",
		"//evil.com/%2e%2e",
		"https://evil.com%2f",
		// Encoded-separator bypasses: an app that URL-DECODES the parameter before
		// building its redirect turns these into //evil.com — a common real-world
		// filter bypass. These only ever produce a finding because the final
		// destination is validated to be the injected attacker host, so adding them
		// widens coverage without any false-positive risk. (They previously could
		// not even be delivered: the old q.Encode() construction double-encoded the
		// '%' to %25, so %2f arrived as %252f and was inert.)
		"%2f%2fevil.com",
		"/%2f/evil.com",
		"/%5cevil.com",
		"%2f%5cevil.com",
		"///evil.com",
		"https:%2f%2fevil.com",
	}

	var candidate *openRedirectResult // remember an internal redirect as fallback

	for _, payload := range payloads {
		// Build the test URL with MINIMAL escaping so a pre-encoded bypass payload
		// (%2f, %2e%2e, %5c) reaches the server byte-for-byte instead of being
		// double-encoded by url.Values.Encode() into an inert literal.
		testURLStr := injectParam(rawURL, param, payload)
		parsedTest, perr := url.Parse(testURLStr)
		if perr != nil {
			continue
		}

		finalLoc, chain, redirected := followRedirectChain(testURLStr)
		if !redirected {
			// No 3xx Location — but the app may redirect via a meta-refresh tag or
			// a JS location assignment (a real open-redirect vector the header walk
			// misses). Low-FP: we only flag when the redirect construct points at
			// our injected attacker host.
			if mh := metaOrJSRedirectHost(testURLStr, parsedTest); mh != "" && isInjectedRedirectHost(mh) && isExternalRedirectHost(mh, originHost) {
				return openRedirectResult{
					class:    redirectExternal,
					testURL:  testURLStr,
					finalLoc: "client-side redirect (meta refresh / JS) → " + mh,
					chain:    fmt.Sprintf("param=%s payload=%s\n  client-side redirect to %s", param, payload, mh),
				}, true
			}
			continue
		}
		provenance := fmt.Sprintf("param=%s payload=%s\n%s", param, payload, chain)

		finalHost := hostFromLocation(finalLoc, parsedTest)
		if finalHost != "" && isInjectedRedirectHost(finalHost) && isExternalRedirectHost(finalHost, originHost) {
			// Confirmed: our injected host is where the browser ends up.
			return openRedirectResult{
				class:    redirectExternal,
				testURL:  testURLStr,
				finalLoc: finalLoc,
				chain:    provenance,
			}, true
		}
		// Redirect happened but stayed same-origin/relative → candidate only.
		if candidate == nil {
			candidate = &openRedirectResult{
				class:    redirectInternal,
				testURL:  testURLStr,
				finalLoc: finalLoc,
				chain:    provenance,
			}
		}
	}

	if candidate != nil {
		return *candidate, true
	}
	return openRedirectResult{}, false
}

// followRedirectChain manually walks Location headers up to 8 hops, returning
// the final Location value seen, a printable chain, and whether any redirect
// occurred at all.
func followRedirectChain(startURL string) (finalLoc, chain string, redirected bool) {
	client := &http.Client{
		Timeout:   6 * time.Second,
		Transport: sharedHTTPTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	cur := startURL
	var b strings.Builder
	for hop := 0; hop < 8; hop++ {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		req, err := http.NewRequestWithContext(ctx, "GET", cur, nil)
		if err != nil {
			cancel()
			break
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
		resp, err := client.Do(req)
		cancel()
		if err != nil {
			break
		}
		resp.Body.Close()
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			break
		}
		loc := resp.Header.Get("Location")
		if loc == "" {
			break
		}
		redirected = true
		finalLoc = loc
		fmt.Fprintf(&b, "  %d %s -> %s\n", resp.StatusCode, cur, loc)
		// Resolve relative Location against current URL to continue the walk.
		base, err := url.Parse(cur)
		if err != nil {
			break
		}
		next, err := url.Parse(loc)
		if err != nil {
			break
		}
		cur = base.ResolveReference(next).String()
	}
	return finalLoc, b.String(), redirected
}

// metaRefreshRe matches <meta http-equiv="refresh" content="0;url=DEST">.
var metaRefreshRe = regexp.MustCompile(`(?is)<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]+content\s*=\s*["'][^"']*?url\s*=\s*([^"'>\s]+)`)

// jsRedirectRe matches the common client-side redirect assignments:
// location = "...", location.href = "...", location.replace("..."),
// location.assign("..."), window.location(.href) = "...".
var jsRedirectRe = regexp.MustCompile(`(?is)(?:window\s*\.\s*)?location\s*(?:\.\s*href\s*)?(?:=|\.\s*replace\s*\(|\.\s*assign\s*\()\s*["']([^"']+)["']`)

// metaOrJSRedirectHost fetches the (200) page and returns the host a meta-refresh
// or JS redirect points to — used to catch open redirects that don't use a 3xx
// Location header. Returns "" if the page performs no client-side redirect. Only
// the FIRST redirect construct found is considered (that's what the browser acts
// on), keeping this low-FP: a mere reflected URL elsewhere in the body is ignored.
func metaOrJSRedirectHost(pageURL string, base *url.URL) string {
	client := &http.Client{
		Timeout:   6 * time.Second,
		Transport: sharedHTTPTransport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", pageURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if ct != "" && !strings.Contains(ct, "html") {
		return "" // only HTML documents run meta/JS redirects
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	dest := ""
	if m := metaRefreshRe.FindSubmatch(body); m != nil {
		dest = string(m[1])
	} else if m := jsRedirectRe.FindSubmatch(body); m != nil {
		dest = string(m[1])
	}
	if dest == "" {
		return ""
	}
	return hostFromLocation(dest, base)
}

// hostFromLocation resolves a (possibly relative) Location against the request
// URL and returns its lower-cased host.
func hostFromLocation(loc string, base *url.URL) string {
	loc = strings.TrimSpace(loc)
	if loc == "" {
		return ""
	}
	// Normalise the backslash trick browsers treat as '/'.
	norm := strings.ReplaceAll(loc, "\\", "/")
	u, err := url.Parse(norm)
	if err != nil {
		return ""
	}
	if !u.IsAbs() && u.Host == "" {
		u = base.ResolveReference(u)
	}
	return strings.ToLower(strings.TrimPrefix(u.Hostname(), "www."))
}

// isInjectedRedirectHost reports whether the final redirect destination is the
// attacker host WE injected (evil.com or a subdomain of it). This is the guard
// that separates a REAL open redirect — the app sent the browser to OUR payload
// host — from an app that always bounces to its OWN fixed external destination
// (an SSO/login provider, a CDN, an analytics/marketing redirect) regardless of
// the parameter value. The latter is not a vulnerability, yet the previous code
// flagged it for every parameter it tested because it only asked "is the final
// host off-origin?" and never "is it the host I injected?". That mismatch — the
// code contradicting its own "we only flag when it points at our injected host"
// comment — was the single biggest open-redirect false-positive source.
func isInjectedRedirectHost(finalHost string) bool {
	h := strings.ToLower(strings.TrimPrefix(finalHost, "www."))
	evil := strings.TrimPrefix(strings.ToLower(evilRedirectHost), "www.")
	return h == evil || strings.HasSuffix(h, "."+evil)
}

// isExternalRedirectHost reports whether the final host is off the origin — the
// definition of a *verified* open redirect.
func isExternalRedirectHost(finalHost, originHost string) bool {
	if finalHost == "" {
		return false
	}
	if finalHost == originHost || strings.HasSuffix(finalHost, "."+originHost) {
		return false // same-origin or a subdomain of it
	}
	return true
}
