package scanner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/recon-platform/internal/database"
)

// insertionPoint is a single testable location: a parameter on a request, with
// the method and content-type that tell the active modules HOW to inject —
// query string (GET), form body (POST), or JSON body. This is what lets the
// scanner cover POST forms and JSON APIs, not just GET params.
type insertionPoint struct {
	URL         string
	Param       string
	Method      string // GET | POST
	ContentType string // "", application/x-www-form-urlencoded, application/json
	// Location tells the injector WHERE the value lives: "" / "query" (a
	// ?name=value pair, the default) or "path:<index>" for a REST-style path
	// segment (e.g. /appointment/<id>). Body/JSON placement is still derived from
	// Method+ContentType; Location only distinguishes query- vs path-based GETs.
	Location string
}

// isPathLocation reports whether the insertion point injects into a path segment,
// and returns the 0-based segment index.
func isPathLocation(loc string) (int, bool) {
	if !strings.HasPrefix(loc, "path") {
		return 0, false
	}
	if i := strings.IndexByte(loc, ':'); i >= 0 {
		n := 0
		for _, c := range loc[i+1:] {
			if c < '0' || c > '9' {
				return 0, false
			}
			n = n*10 + int(c-'0')
		}
		return n, true
	}
	return 0, false
}

// injectPathSegment returns rawURL with the path segment at index idx replaced by
// value (minimally escaped so payload metacharacters survive but path boundaries
// stay intact). The query string, host and scheme are preserved. Out-of-range idx
// returns rawURL unchanged.
func injectPathSegment(rawURL string, idx int, value string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	segs := strings.Split(u.EscapedPath(), "/")
	// segs[0] is "" for an absolute path; real segments start at index 1.
	target := idx + 1
	if target <= 0 || target >= len(segs) {
		return rawURL
	}
	segs[target] = pathEscapeMinimal(value)
	u.RawPath = strings.Join(segs, "/")
	u.Path = u.RawPath // keep RawPath authoritative so our escaping is preserved
	return u.String()
}

// pathEscapeMinimal escapes only the characters that would break the path
// structure or the URL parse (space, ?, #, %); it deliberately leaves injection
// metacharacters ('"<>) raw so a reflected/SQLi payload reaches the app intact —
// the same philosophy as queryEscapeMinimal for the query string.
func pathEscapeMinimal(v string) string {
	repl := strings.NewReplacer(
		" ", "%20", "?", "%3f", "#", "%23", "%", "%25", "/", "%2f",
	)
	return repl.Replace(v)
}

// trackingParams are analytics/click-attribution/cache-buster query parameters
// that are never an application attack surface. They flood the parameters table on
// real sites and, under an unordered cap, crowd out the genuinely injectable params
// so they never get tested — the "junk floods the scan, real bugs missed" defect.
// Dropping them spends the insertion-point budget on real surface.
var trackingParams = map[string]bool{
	"utm_source": true, "utm_medium": true, "utm_campaign": true, "utm_term": true,
	"utm_content": true, "utm_id": true, "utm_name": true, "utm_reader": true,
	"fbclid": true, "gclid": true, "gclsrc": true, "dclid": true, "msclkid": true,
	"yclid": true, "igshid": true, "mc_eid": true, "mc_cid": true, "_ga": true,
	"_gl": true, "twclid": true, "wickedid": true, "s_kwcid": true, "vero_id": true,
	"oly_enc_id": true, "oly_anon_id": true, "spm": true, "scm": true,
}

func isTrackingParam(name string) bool { return trackingParams[strings.ToLower(strings.TrimSpace(name))] }

// insertionKey is the LOGICAL identity of an insertion point: method + path + param
// name, IGNORING the specific parameter VALUES. It collapses ?id=1, ?id=2 … ?id=9999
// (and every ?utm=…-carrying variant of the same endpoint) into ONE testable point,
// so the budget covers distinct endpoints instead of thousands of value-variants.
func insertionKey(rawURL, param, method string) string {
	path := rawURL
	if u, err := url.Parse(rawURL); err == nil {
		path = strings.ToLower(u.Host) + u.Path
	}
	return strings.ToUpper(method) + " " + path + " |" + strings.ToLower(param)
}

// loadInsertionPoints returns the highest-value, DISTINCT insertion points for the
// active injection modules, capped by limit. It pulls a generous ordered pool
// (reflected params first — reflection is the precondition for XSS and most
// injection proofs), then dedupes by logical identity and drops tracking junk so
// the `limit` budget is spent on real, distinct attack surface rather than value
// variants or analytics params.
func loadInsertionPoints(ctx context.Context, db *database.DB, targetID string, limit int) []insertionPoint {
	pool := limit * 20
	if pool < 5000 {
		pool = 5000
	}
	rows, err := db.QueryContext(ctx, `
		SELECT url, parameter, COALESCE(method,'GET'), COALESCE(content_type,''), COALESCE(location,'query'), COALESCE(is_reflected,0)
		FROM parameters WHERE target_id = ?
		ORDER BY COALESCE(is_reflected,0) DESC
		LIMIT ?
	`, targetID, pool)
	if err != nil {
		return nil
	}
	defer rows.Close()
	// Skip insertion points on stock WordPress/Joomla/Drupal hosts. This one gate
	// covers every active injection module that draws its targets from here (DAST/
	// XSS, command-injection, NoSQLi, SSTI, race, stored-XSS, OAST): blindly
	// fuzzing a patched CMS core is wasted effort and a false-positive magnet;
	// nuclei's CMS templates still cover the real known-CVE surface.
	cmsSkip := loadCMSSkipHosts(db, targetID)
	seen := make(map[string]bool)
	var out []insertionPoint
	for rows.Next() {
		var ip insertionPoint
		var reflected int
		if err := rows.Scan(&ip.URL, &ip.Param, &ip.Method, &ip.ContentType, &ip.Location, &reflected); err != nil {
			continue
		}
		if !urlHostInScope(ctx, ip.URL) {
			continue
		}
		if ip.Param == "" || isTrackingParam(ip.Param) {
			continue
		}
		if hostSkippedByCMS(ip.URL, cmsSkip) {
			continue
		}
		key := insertionKey(ip.URL, ip.Param, ip.Method) + "|" + ip.Location
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ip)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// loadAuthHeaders returns the per-target authentication headers (Authorization,
// Cookie, custom) that should be attached to every scan request so the scanner
// can reach pages behind a login.
func loadAuthHeaders(ctx context.Context, db *database.DB, targetID string) map[string]string {
	var raw string
	_ = db.QueryRowContext(ctx, `SELECT COALESCE(auth_headers,'') FROM targets WHERE id = ?`, targetID).Scan(&raw)
	out := map[string]string{}
	if strings.TrimSpace(raw) == "" {
		return out
	}
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

// buildInjectedRequest constructs an *http.Request with `param` set to `value`
// in the correct location for the insertion point's method/content-type.
func buildInjectedRequest(ctx context.Context, ip insertionPoint, value string, auth map[string]string) (*http.Request, error) {
	method := strings.ToUpper(ip.Method)
	if method == "" {
		method = "GET"
	}

	var req *http.Request
	var err error

	// Path-segment injection (REST-style value in the URL path). Independent of
	// method, though in practice these are GETs; the value replaces the target
	// segment and the query string is preserved.
	if idx, ok := isPathLocation(ip.Location); ok {
		req, err = http.NewRequestWithContext(ctx, method, injectPathSegment(ip.URL, idx, value), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
		for k, v := range auth {
			req.Header.Set(k, v)
		}
		return req, nil
	}

	switch {
	case method == "POST" && strings.Contains(ip.ContentType, "json"):
		// JSON body: { "param": "value" }
		payload := map[string]string{ip.Param: value}
		b, _ := json.Marshal(payload)
		req, err = http.NewRequestWithContext(ctx, "POST", stripQuery(ip.URL), strings.NewReader(string(b)))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	case method == "POST":
		// form body: param=value (plus siblings from the original query, if any).
		// The injected value is encoded with the SAME minimal escaping as the GET
		// path (queryEscapeMinimal), NOT url.Values.Encode(): the latter re-encodes a
		// stray '%', so a pre-encoded bypass payload (%0a, ..%2f, %00) becomes %250a /
		// ..%252f and reaches the server as an inert literal instead of a newline /
		// slash — a silent false negative for POST-body injection that the GET path
		// already avoids. Only structural characters (space, &, #, +, control bytes,
		// a stray %) are escaped, so field boundaries stay intact.
		sibs := siblingValues(ip.URL)
		delete(sibs, ip.Param)
		var body strings.Builder
		if enc := sibs.Encode(); enc != "" {
			body.WriteString(enc)
			body.WriteByte('&')
		}
		body.WriteString(url.QueryEscape(ip.Param))
		body.WriteByte('=')
		body.WriteString(queryEscapeMinimal(value))
		req, err = http.NewRequestWithContext(ctx, "POST", stripQuery(ip.URL), strings.NewReader(body.String()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	default:
		// GET query string
		req, err = http.NewRequestWithContext(ctx, "GET", injectParam(ip.URL, ip.Param, value), nil)
	}
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
	for k, v := range auth {
		req.Header.Set(k, v)
	}
	return req, nil
}

// sendInjected performs the injected request and returns body + elapsed time.
func sendInjected(ctx context.Context, client *http.Client, ip insertionPoint, value string, auth map[string]string) (string, time.Duration) {
	body, _, d := sendInjectedFull(ctx, client, ip, value, auth)
	return body, d
}

// sendInjectedFull is sendInjected plus the HTTP status code, for callers that
// need to tell a WAF/challenge block (403/406/429 + block-page body) apart from a
// real application response, or to gate a differential check on status. A failed
// request returns ("", 0, elapsed).
func sendInjectedFull(ctx context.Context, client *http.Client, ip insertionPoint, value string, auth map[string]string) (string, int, time.Duration) {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := buildInjectedRequest(reqCtx, ip, value, auth)
	if err != nil {
		return "", 0, 0
	}
	// Adaptive per-host pacing: zero delay for a healthy host, ramping up only when
	// this host has been timing out / rate-limiting. Done BEFORE the timing window
	// so a time-based detector's measurement is never inflated by the backoff.
	host := hostOfURL(ip.URL)
	hostThrottleWait(reqCtx, host)
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		hostThrottleObserve(host, 0, true)
		return "", 0, time.Since(start)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	resp.Body.Close()
	hostThrottleObserve(host, resp.StatusCode, false)
	return string(body), resp.StatusCode, time.Since(start)
}

// sendInjectedCT is sendInjectedFull plus the response Content-Type, for callers
// (reflected-XSS confirmation) that must know whether the response is actually
// rendered as HTML. A payload reflected into a text/css, application/javascript,
// JSON or plain-text response is inert in a browser and must never be reported as
// XSS — the single biggest reflected-XSS false-positive source. A failed request
// returns ("", 0, "", elapsed).
func sendInjectedCT(ctx context.Context, client *http.Client, ip insertionPoint, value string, auth map[string]string) (string, int, string, time.Duration) {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := buildInjectedRequest(reqCtx, ip, value, auth)
	if err != nil {
		return "", 0, "", 0
	}
	host := hostOfURL(ip.URL)
	hostThrottleWait(reqCtx, host)
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		hostThrottleObserve(host, 0, true)
		return "", 0, "", time.Since(start)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	resp.Body.Close()
	hostThrottleObserve(host, resp.StatusCode, false)
	return string(body), resp.StatusCode, resp.Header.Get("Content-Type"), time.Since(start)
}

func stripQuery(rawURL string) string {
	if i := strings.Index(rawURL, "?"); i >= 0 {
		return rawURL[:i]
	}
	return rawURL
}

// siblingValues returns the original query params (so a POST keeps its other
// fields realistic while we mutate one).
func siblingValues(rawURL string) url.Values {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return url.Values{}
	}
	return parsed.Query()
}
