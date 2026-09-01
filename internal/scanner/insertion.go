package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/recon-platform/internal/database"
)

// insertionPoint is a single testable location: a parameter on a request, with
// the method and content-type that tell the active modules HOW to inject —
// query string (GET), form body (POST), or JSON body. This is what lets the
// scanner cover POST forms and JSON APIs, not just GET params.
type insertionPoint struct {
	URL   string
	Param string
	// Value is the value discovered for this exact insertion point. Active
	// detectors must mutate the real value instead of silently replacing every
	// parameter with "1": doing the latter changes UUID/string/date lookups to a
	// different route/object before the SQL probe even reaches the application.
	Value string
	// Siblings preserves the other discovered fields of the same form/JSON
	// request. Omitting required siblings makes the application reject the request
	// during validation, before the mutated field can ever reach its SQL sink.
	Siblings     map[string]string
	SiblingTypes map[string]string // JSON sibling path -> string|number|integer|boolean|object|array
	Method       string            // GET | POST
	ContentType  string            // "", application/x-www-form-urlencoded, application/json
	// Location tells the injector WHERE the value lives: "" / "query" (a
	// ?name=value pair, the default) or "path:<index>" for a REST-style path
	// segment (e.g. /appointment/<id>). Body/JSON placement is still derived from
	// Method+ContentType; Location only distinguishes query- vs path-based GETs.
	Location string
}

// insertionLocation returns the normalized candidate/request location while
// preserving explicit path/header/cookie locations. A database row commonly
// carries the historical default "query" even for a POST form, so method and
// content type are authoritative for body placement.
func insertionLocation(ip insertionPoint) string {
	loc := strings.ToLower(strings.TrimSpace(ip.Location))
	if strings.HasPrefix(loc, "path:") || strings.HasPrefix(loc, "graphql:") || loc == "path" || loc == "header" || loc == "cookie" {
		return loc
	}
	if !strings.EqualFold(ip.Method, "GET") && strings.TrimSpace(ip.Method) != "" {
		// Explicit query placement with no request-body content type is used by
		// OpenAPI operations such as POST /search?page=2. Historical form rows also
		// defaulted location to "query", but their content type identifies the body.
		if loc == "query" && strings.TrimSpace(ip.ContentType) == "" {
			return "query"
		}
		ct := strings.ToLower(ip.ContentType)
		if strings.Contains(ct, "multipart/form-data") {
			return "multipart"
		}
		if strings.Contains(ct, "xml") {
			return "xml"
		}
		if strings.Contains(ct, "json") {
			return "json"
		}
		return "body"
	}
	if loc == "json" || loc == "body" {
		return loc
	}
	return "query"
}

// insertionIdentity distinguishes placements that happen to share a URL and
// parameter name. Without method/location/content-type in this key, a GET hit
// can suppress the POST/JSON/path version of the same logical field.
func insertionIdentity(ip insertionPoint) string {
	return insertionKey(ip.URL, ip.Param, ip.Method) + "|" +
		insertionLocation(ip) + "|" + strings.ToLower(strings.TrimSpace(ip.ContentType))
}

// insertionSiblingGroupKey identifies fields that belong to the same logical
// request. Active detectors must replay those fields together: dropping a CSRF
// token, tenant, action or required JSON property makes validation reject the
// mutation before it reaches the sink and is a deterministic false negative.
func insertionSiblingGroupKey(ip insertionPoint) string {
	loc := insertionLocation(ip)
	if strings.HasPrefix(loc, "graphql:") {
		parts := strings.Split(loc, ":")
		if len(parts) >= 3 {
			loc = strings.Join(parts[:3], ":") // same endpoint + operation
		}
	}
	return strings.ToUpper(strings.TrimSpace(ip.Method)) + "\x00" + ip.URL + "\x00" +
		strings.ToLower(strings.TrimSpace(ip.ContentType)) + "\x00" + loc
}

func insertionJSONType(location string) string {
	loc := strings.ToLower(strings.TrimSpace(location))
	if strings.HasPrefix(loc, "json:") {
		return strings.TrimPrefix(loc, "json:")
	}
	return ""
}

func insertionHasBodySiblings(ip insertionPoint) bool {
	loc := insertionLocation(ip)
	return loc == "body" || loc == "json" || loc == "multipart" || loc == "xml" ||
		strings.HasPrefix(loc, "graphql:")
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
	// Keep RawPath encoded and Path decoded. Assigning an encoded string to both
	// fields makes url.URL escape '%' again (`%20` -> `%2520`), so path payloads
	// containing spaces/slashes reached the app still encoded and could not form
	// executable markup.
	segs[target] = url.PathEscape(value)
	rawPath := strings.Join(segs, "/")
	decodedPath, err := url.PathUnescape(rawPath)
	if err != nil {
		return rawURL
	}
	u.RawPath = rawPath
	u.Path = decodedPath
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

func isTrackingParam(name string) bool {
	return trackingParams[strings.ToLower(strings.TrimSpace(name))]
}

// insertionKey is the LOGICAL identity of an insertion point: method + path + param
// name, IGNORING the specific parameter VALUES. It collapses ?id=1, ?id=2 … ?id=9999
// (and every ?utm=…-carrying variant of the same endpoint) into ONE testable point,
// so the budget covers distinct endpoints instead of thousands of value-variants.
func insertionKey(rawURL, param, method string) string {
	path := rawURL
	if u, err := url.Parse(rawURL); err == nil {
		// Values vary constantly across crawl/history sources, but the set of query
		// field names is part of the request contract. /search?id=1&mode=admin must
		// not collapse into /search?id=1&mode=public, while id=1/id=2 should.
		var names []string
		for name := range u.Query() {
			names = append(names, strings.ToLower(name))
		}
		sort.Strings(names)
		path = strings.ToLower(u.Host) + u.Path + "?" + strings.Join(names, ",")
	}
	return strings.ToUpper(method) + " " + path + " |" + strings.ToLower(param)
}

var (
	semanticNumericSegment = regexp.MustCompile(`^[0-9]{1,20}$`)
	semanticUUIDSegment    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	semanticHexSegment     = regexp.MustCompile(`(?i)^[0-9a-f]{16,64}$`)
)

// semanticRouteIdentity collapses concrete object values that clearly map to the
// same route handler (/orders/1001 and /orders/1002), while preserving method,
// parameter, placement, content type and query-field shape. Callers retain two
// representatives per normalized route, so a valid/invalid or public/private
// object variant still gets exercised without testing thousands of IDs through
// identical code.
func semanticRouteIdentity(ip insertionPoint) (string, bool) {
	u, err := url.Parse(ip.URL)
	if err != nil {
		return insertionIdentity(ip), false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	changed := false
	for i, raw := range parts {
		part, err := url.PathUnescape(raw)
		if err != nil {
			part = raw
		}
		switch {
		case semanticNumericSegment.MatchString(part):
			parts[i], changed = "{n}", true
		case semanticUUIDSegment.MatchString(part):
			parts[i], changed = "{uuid}", true
		case semanticHexSegment.MatchString(part):
			parts[i], changed = "{hex}", true
		}
	}
	if !changed {
		return insertionIdentity(ip), false
	}
	var queryNames []string
	for name := range u.Query() {
		queryNames = append(queryNames, strings.ToLower(name))
	}
	sort.Strings(queryNames)
	key := strings.ToUpper(ip.Method) + " " + strings.ToLower(u.Host) + "/" + strings.Join(parts, "/") +
		"?" + strings.Join(queryNames, ",") + " |" + strings.ToLower(ip.Param) + "|" +
		insertionLocation(ip) + "|" + strings.ToLower(strings.TrimSpace(ip.ContentType))
	return key, true
}

// loadInsertionPoints returns the highest-value, DISTINCT insertion points for the
// active injection modules, capped by limit. It pulls a generous ordered pool
// (reflected params first — reflection is the precondition for XSS and most
// injection proofs), then dedupes by logical identity and drops tracking junk so
// the `limit` budget is spent on real, distinct attack surface rather than value
// variants or analytics params.
func loadInsertionPoints(ctx context.Context, db *database.DB, targetID string, limit int) []insertionPoint {
	if limit <= 0 {
		limit = 1000000
	}
	pool := limit * 20
	if pool < 5000 {
		pool = 5000
	}
	rows, err := db.QueryContext(ctx, `
		SELECT url, parameter, COALESCE(value,''), COALESCE(method,'GET'), COALESCE(content_type,''), COALESCE(location,'query'), COALESCE(is_reflected,0)
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
	var all []insertionPoint
	siblingGroups := make(map[string]map[string]string)
	siblingTypeGroups := make(map[string]map[string]string)
	for rows.Next() {
		var ip insertionPoint
		var reflected int
		if err := rows.Scan(&ip.URL, &ip.Param, &ip.Value, &ip.Method, &ip.ContentType, &ip.Location, &reflected); err != nil {
			continue
		}
		ip.Method = strings.ToUpper(strings.TrimSpace(ip.Method))
		if ip.Method == "" {
			ip.Method = "GET"
		}
		if ip.Param == "" || !urlHostInScope(ctx, ip.URL) {
			continue
		}
		all = append(all, ip)
		if insertionHasBodySiblings(ip) {
			key := insertionSiblingGroupKey(ip)
			if siblingGroups[key] == nil {
				siblingGroups[key] = map[string]string{}
			}
			siblingGroups[key][ip.Param] = ip.Value
			if typ := insertionJSONType(ip.Location); typ != "" {
				if siblingTypeGroups[key] == nil {
					siblingTypeGroups[key] = map[string]string{}
				}
				siblingTypeGroups[key][ip.Param] = typ
			}
		}
	}
	seen := make(map[string]bool)
	semanticCounts := make(map[string]int)
	var out []insertionPoint
	for _, ip := range all {
		if ip.Param == "" || isTrackingParam(ip.Param) {
			continue
		}
		if hostSkippedByCMS(ip.URL, cmsSkip) {
			continue
		}
		key := insertionIdentity(ip)
		if seen[key] {
			continue
		}
		seen[key] = true
		if routeKey, normalized := semanticRouteIdentity(ip); normalized {
			if semanticCounts[routeKey] >= 2 {
				continue
			}
			semanticCounts[routeKey]++
		}
		out = append(out, ip)
		if len(out) >= limit {
			break
		}
	}
	for i := range out {
		key := insertionSiblingGroupKey(out[i])
		if group := siblingGroups[key]; len(group) > 0 {
			out[i].Siblings = make(map[string]string, len(group))
			for name, value := range group {
				out[i].Siblings[name] = value
			}
		}
		if types := siblingTypeGroups[key]; len(types) > 0 {
			out[i].SiblingTypes = make(map[string]string, len(types))
			for name, typ := range types {
				out[i].SiblingTypes[name] = typ
			}
		}
	}
	return out
}

// loadRoutedInsertionPoints is the proof-oriented surface loader used by
// detectors whose positive result is independently replayed (LFI/SSRF/SSTI and
// similar classes). Unlike the older generic loader it does not discard CMS or
// analytics-looking parameters: a deterministic file signature, evaluated
// template marker, or OAST callback remains valid on those surfaces. Likely
// class matches are ordered first; fallback controls how many unfamiliar names
// are retained so new framework conventions do not become silent blind spots.
func loadRoutedInsertionPoints(ctx context.Context, db *database.DB, targetID string, class VulnClass, limit, fallback int) []insertionPoint {
	if limit <= 0 {
		limit = 1000000
	}
	rows, err := db.QueryContext(ctx, `
		SELECT url,parameter,COALESCE(value,''),COALESCE(method,'GET'),
		       COALESCE(content_type,''),COALESCE(location,'query'),COALESCE(is_reflected,0)
		FROM parameters WHERE target_id=?
		ORDER BY COALESCE(is_reflected,0) DESC, LENGTH(url), url, parameter`, targetID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	type routedPoint struct {
		ip        insertionPoint
		reflected bool
	}
	var prone, other []routedPoint
	seen := map[string]bool{}
	siblingGroups := map[string]map[string]string{}
	siblingTypeGroups := map[string]map[string]string{}
	for rows.Next() {
		var ip insertionPoint
		var reflected int
		if rows.Scan(&ip.URL, &ip.Param, &ip.Value, &ip.Method, &ip.ContentType, &ip.Location, &reflected) != nil {
			continue
		}
		ip.Method = strings.ToUpper(strings.TrimSpace(ip.Method))
		if ip.Method == "" {
			ip.Method = "GET"
		}
		if ip.Param == "" || !urlHostInScope(ctx, ip.URL) {
			continue
		}
		if insertionHasBodySiblings(ip) {
			key := insertionSiblingGroupKey(ip)
			if siblingGroups[key] == nil {
				siblingGroups[key] = map[string]string{}
			}
			siblingGroups[key][ip.Param] = ip.Value
			if typ := insertionJSONType(ip.Location); typ != "" {
				if siblingTypeGroups[key] == nil {
					siblingTypeGroups[key] = map[string]string{}
				}
				siblingTypeGroups[key][ip.Param] = typ
			}
		}
		key := insertionIdentity(ip)
		if seen[key] {
			continue
		}
		seen[key] = true
		r := routedPoint{ip: ip, reflected: reflected != 0}
		if paramProneTo(class, ip.Param, ip.Value) {
			prone = append(prone, r)
		} else {
			other = append(other, r)
		}
	}

	// Reflected inputs are more likely to reach a renderer, but stable ordering
	// within each tier keeps scans reproducible and makes regression comparisons
	// meaningful.
	sort.SliceStable(prone, func(i, j int) bool {
		if prone[i].reflected != prone[j].reflected {
			return prone[i].reflected
		}
		return insertionIdentity(prone[i].ip) < insertionIdentity(prone[j].ip)
	})
	sort.SliceStable(other, func(i, j int) bool {
		if other[i].reflected != other[j].reflected {
			return other[i].reflected
		}
		return insertionIdentity(other[i].ip) < insertionIdentity(other[j].ip)
	})

	combined := make([]routedPoint, 0, len(prone)+fallback)
	combined = append(combined, prone...)
	if fallback < 0 || fallback > len(other) {
		fallback = len(other)
	}
	combined = append(combined, other[:fallback]...)

	semanticCounts := map[string]int{}
	out := make([]insertionPoint, 0, minInt(limit, len(combined)))
	for _, r := range combined {
		ip := r.ip
		if routeKey, normalized := semanticRouteIdentity(ip); normalized {
			if semanticCounts[routeKey] >= 2 {
				continue
			}
			semanticCounts[routeKey]++
		}
		key := insertionSiblingGroupKey(ip)
		if group := siblingGroups[key]; len(group) > 0 {
			ip.Siblings = make(map[string]string, len(group))
			for name, value := range group {
				ip.Siblings[name] = value
			}
		}
		if types := siblingTypeGroups[key]; len(types) > 0 {
			ip.SiblingTypes = make(map[string]string, len(types))
			for name, typ := range types {
				ip.SiblingTypes[name] = typ
			}
		}
		out = append(out, ip)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// loadXSSInsertionPoints is intentionally broader than the shared injection
// loader. Analytics parameters and CMS routes are not safe to discard for XSS:
// both are frequently rendered by templates/plugins, and dropping them is a
// deterministic false negative. The XSS engine performs its own MIME/context/
// runtime proof, so this surface expansion does not weaken finding quality.
func loadXSSInsertionPoints(ctx context.Context, db *database.DB, targetID string, limit int) []insertionPoint {
	if limit <= 0 {
		limit = 1000000
	}
	pool := limit
	if pool < 10000 {
		pool = 10000
	}
	rows, err := db.QueryContext(ctx, `
		SELECT url,parameter,COALESCE(value,''),COALESCE(method,'GET'),COALESCE(content_type,''),COALESCE(location,'query'),COALESCE(is_reflected,0)
		FROM parameters WHERE target_id=?
		ORDER BY COALESCE(is_reflected,0) DESC,
			CASE WHEN UPPER(COALESCE(method,'GET'))='GET' THEN 0 ELSE 1 END,
			LENGTH(url),url,parameter LIMIT ?`, targetID, pool)
	if err != nil {
		return nil
	}
	defer rows.Close()
	seen := map[string]bool{}
	semanticCounts := map[string]int{}
	var out []insertionPoint
	for rows.Next() {
		var ip insertionPoint
		var reflected int
		if rows.Scan(&ip.URL, &ip.Param, &ip.Value, &ip.Method, &ip.ContentType, &ip.Location, &reflected) != nil ||
			ip.Param == "" || !urlHostInScope(ctx, ip.URL) {
			continue
		}
		key := insertionIdentity(ip)
		if seen[key] {
			continue
		}
		seen[key] = true
		if routeKey, normalized := semanticRouteIdentity(ip); normalized {
			if semanticCounts[routeKey] >= 2 {
				continue
			}
			semanticCounts[routeKey]++
		}
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
	loc := insertionLocation(ip)
	if loc == "header" || loc == "cookie" {
		req, err = http.NewRequestWithContext(ctx, method, ip.URL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
		for k, v := range auth {
			req.Header.Set(k, v)
		}
		if loc == "cookie" {
			req.Header.Set("Cookie", replaceCookieValue(req.Header.Get("Cookie"), ip.Param, value))
		} else {
			req.Header.Set(ip.Param, value)
		}
		return req, nil
	}
	if strings.HasPrefix(strings.ToLower(ip.Location), "graphql:") {
		body, ok := buildGraphQLInjectionBody(ip, value)
		if !ok {
			return nil, errors.New("invalid GraphQL insertion location")
		}
		req, err = http.NewRequestWithContext(ctx, "POST", ip.URL, strings.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
		for k, v := range auth {
			req.Header.Set(k, v)
		}
		return req, nil
	}

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
	case loc == "json":
		payload := make(map[string]string, len(ip.Siblings)+1)
		for k, v := range ip.Siblings {
			payload[k] = v
		}
		payload[ip.Param] = value
		body := buildJSONFieldsTyped(payload, ip.SiblingTypes, ip.Param)
		req, err = http.NewRequestWithContext(ctx, method, ip.URL, strings.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	case loc == "multipart":
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		for k, v := range ip.Siblings {
			if k != ip.Param {
				_ = mw.WriteField(k, v)
			}
		}
		_ = mw.WriteField(ip.Param, value)
		_ = mw.Close()
		req, err = http.NewRequestWithContext(ctx, method, ip.URL, &body)
		if err == nil {
			req.Header.Set("Content-Type", mw.FormDataContentType())
		}
	case loc == "xml":
		fields := make(map[string]string, len(ip.Siblings)+1)
		for k, v := range ip.Siblings {
			fields[k] = v
		}
		fields[ip.Param] = value
		body := buildXMLFields(fields)
		req, err = http.NewRequestWithContext(ctx, method, ip.URL, strings.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/xml")
		}
	case loc == "body":
		// form body: param=value plus fields discovered in the same form. Query
		// parameters on the form action remain in the URL; moving them into the body
		// changes routing/validation semantics and can hide the SQL sink.
		// The injected value is encoded with the SAME minimal escaping as the GET
		// path (queryEscapeMinimal), NOT url.Values.Encode(): the latter re-encodes a
		// stray '%', so a pre-encoded bypass payload (%0a, ..%2f, %00) becomes %250a /
		// ..%252f and reaches the server as an inert literal instead of a newline /
		// slash — a silent false negative for POST-body injection that the GET path
		// already avoids. Only structural characters (space, &, #, +, control bytes,
		// a stray %) are escaped, so field boundaries stay intact.
		sibs := url.Values{}
		for k, v := range ip.Siblings {
			if k != ip.Param {
				sibs.Set(k, v)
			}
		}
		delete(sibs, ip.Param)
		var body strings.Builder
		if enc := sibs.Encode(); enc != "" {
			body.WriteString(enc)
			body.WriteByte('&')
		}
		body.WriteString(url.QueryEscape(ip.Param))
		body.WriteByte('=')
		body.WriteString(queryEscapeMinimal(value))
		req, err = http.NewRequestWithContext(ctx, method, ip.URL, strings.NewReader(body.String()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	default:
		// GET query string
		req, err = http.NewRequestWithContext(ctx, method, injectParam(ip.URL, ip.Param, value), nil)
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

func buildJSONFields(fields map[string]string) string {
	return buildJSONFieldsTyped(fields, nil, "")
}

func buildJSONFieldsTyped(fields, types map[string]string, forceStringPath string) string {
	root := map[string]interface{}{}
	for path, value := range fields {
		parts := strings.Split(path, ".")
		cur := root
		for i, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if i == len(parts)-1 {
				cur[part] = jsonFieldValue(value, types[path], path == forceStringPath)
				continue
			}
			next, ok := cur[part].(map[string]interface{})
			if !ok {
				next = map[string]interface{}{}
				cur[part] = next
			}
			cur = next
		}
	}
	b, _ := json.Marshal(root)
	return string(b)
}

func jsonFieldValue(value, typ string, forceString bool) interface{} {
	if forceString {
		return value
	}
	switch strings.ToLower(typ) {
	case "integer":
		if n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil {
			return n
		}
		return int64(1)
	case "number":
		if n, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil {
			return n
		}
		return float64(1)
	case "boolean", "bool":
		if v, err := strconv.ParseBool(strings.TrimSpace(value)); err == nil {
			return v
		}
		return true
	case "object":
		var v map[string]interface{}
		if json.Unmarshal([]byte(value), &v) == nil {
			return v
		}
		return map[string]interface{}{}
	case "array":
		var v []interface{}
		if json.Unmarshal([]byte(value), &v) == nil {
			return v
		}
		return []interface{}{}
	default:
		return value
	}
}

func buildXMLFields(fields map[string]string) string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	var b bytes.Buffer
	b.WriteString("<request>")
	for _, rawName := range names {
		name := safeXMLName(rawName)
		b.WriteByte('<')
		b.WriteString(name)
		b.WriteByte('>')
		_ = xml.EscapeText(&b, []byte(fields[rawName]))
		b.WriteString("</")
		b.WriteString(name)
		b.WriteByte('>')
	}
	b.WriteString("</request>")
	return b.String()
}

func safeXMLName(name string) string {
	var b strings.Builder
	for i, r := range name {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' ||
			(i > 0 && ((r >= '0' && r <= '9') || r == '-' || r == '.'))
		if ok {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "field"
	}
	return b.String()
}

// buildGraphQLInjectionBody turns a harvested GraphQL argument insertion point
// into a syntactically valid operation. Other arguments from the same operation
// are replayed as siblings so required-argument validation does not stop the
// request before resolver/SQL execution.
func buildGraphQLInjectionBody(ip insertionPoint, value string) (string, bool) {
	parts := strings.Split(ip.Location, ":")
	if len(parts) < 4 || !strings.EqualFold(parts[0], "graphql") {
		return "", false
	}
	kind, operation, targetArg := strings.ToLower(parts[1]), parts[2], parts[3]
	if kind != "query" && kind != "mutation" {
		kind = "query"
	}
	args := map[string]string{}
	prefix := operation + "."
	for name, v := range ip.Siblings {
		if strings.HasPrefix(name, prefix) {
			args[strings.TrimPrefix(name, prefix)] = v
		}
	}
	args[targetArg] = value
	names := make([]string, 0, len(args))
	for name := range args {
		names = append(names, name)
	}
	sort.Strings(names)
	var encoded []string
	for _, name := range names {
		v := args[name]
		if v == "" {
			v = "1"
		}
		b, _ := json.Marshal(v)
		encoded = append(encoded, name+":"+string(b))
	}
	selection := "{__typename}"
	if len(parts) >= 5 && strings.EqualFold(parts[4], "scalar") {
		selection = ""
	}
	query := kind + "{" + operation + "(" + strings.Join(encoded, ",") + ")" + selection + "}"
	b, _ := json.Marshal(map[string]string{"query": query})
	return string(b), true
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
	release, acquired := hostRequestAcquire(reqCtx, host)
	if !acquired {
		return "", 0, 0
	}
	defer release()
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
	r := sendInjectedResponse(ctx, client, ip, value, auth)
	return r.Body, r.Status, r.ContentType, r.Duration
}

type injectedResponse struct {
	Body        string
	Status      int
	ContentType string
	NoSniff     bool
	CSP         string
	Duration    time.Duration
}

// sendInjectedResponse is the XSS-grade response primitive. In addition to the
// body/status/MIME type it preserves browser-relevant headers that decide whether
// reflected markup can actually execute.
func sendInjectedResponse(ctx context.Context, client *http.Client, ip insertionPoint, value string, auth map[string]string) injectedResponse {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := buildInjectedRequest(reqCtx, ip, value, auth)
	if err != nil {
		return injectedResponse{}
	}
	host := hostOfURL(ip.URL)
	release, acquired := hostRequestAcquire(reqCtx, host)
	if !acquired {
		return injectedResponse{}
	}
	defer release()
	hostThrottleWait(reqCtx, host)
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		hostThrottleObserve(host, 0, true)
		return injectedResponse{Duration: time.Since(start)}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	resp.Body.Close()
	hostThrottleObserve(host, resp.StatusCode, false)
	return injectedResponse{
		Body:        string(body),
		Status:      resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		NoSniff:     strings.EqualFold(strings.TrimSpace(resp.Header.Get("X-Content-Type-Options")), "nosniff"),
		CSP:         resp.Header.Get("Content-Security-Policy"),
		Duration:    time.Since(start),
	}
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
