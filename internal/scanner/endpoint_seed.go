package scanner

import (
	"context"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
)

// Single-endpoint / URL-target seeding.
//
// A web scope token is normally a bare host (example.com) that the pipeline
// resolves → probes → crawls. But an operator often wants to point Reconner at ONE
// exact endpoint — e.g. https://example.com/appointment?h=<payload> — and have the
// full pipeline (param discovery, crawl, JS analysis, DAST/XSS/SQLi/…) run against
// THAT url and everything reachable under it. For that to work the endpoint's own
// insertion points must exist in the DB before the injection modules read them:
//
//   • the URL itself is registered as an http_service (source='seed') so the
//     crawler/JS/nuclei/dir modules seed from the EXACT endpoint (not just the host
//     root), and
//   • every QUERY parameter and every PATH SEGMENT of the URL is registered as a
//     `parameters` row (query vs path:<index> location) so XSS/SQLi/DAST test them
//     immediately, on the first pass, without waiting to re-discover them.
//
// This is what makes "give a URL → find the bug in ?h=" work end-to-end.

// looksLikeEndpointURL reports whether a scope token is a full URL that carries a
// meaningful path and/or query (i.e. an ENDPOINT, not just a host). A bare host or
// a scheme+host with only "/" is handled by the normal host pipeline.
func looksLikeEndpointURL(token string) bool {
	token = strings.TrimSpace(token)
	if !strings.Contains(token, "://") {
		// allow "host/path?x=1" without a scheme too.
		if !strings.ContainsAny(token, "/?") {
			return false
		}
		token = "https://" + token
	}
	u, err := url.Parse(token)
	if err != nil || u.Host == "" {
		return false
	}
	hasPath := u.Path != "" && u.Path != "/"
	hasQuery := u.RawQuery != ""
	return hasPath || hasQuery
}

// normalizeEndpointURL returns the token as a fully-qualified URL (adding https://
// when the scheme is missing), or "" if it cannot be parsed.
func normalizeEndpointURL(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	if !strings.Contains(token, "://") {
		token = "https://" + token
	}
	u, err := url.Parse(token)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.String()
}

// NormalizeEndpointURL is the exported wrapper the scheduler uses.
func NormalizeEndpointURL(token string) string { return normalizeEndpointURL(token) }

// hostOfEndpoint returns the bare host of a URL/endpoint token (no scheme, no
// path), for seeding into the subdomains table so http_probe covers the host.
func hostOfEndpoint(token string) string {
	if !strings.Contains(token, "://") {
		token = "https://" + token
	}
	u, err := url.Parse(token)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// injectablePathSegments returns the (index, value) of each non-empty path segment
// worth registering as a path insertion point. Static-asset-looking last segments
// (foo.js, style.css) are skipped; everything else is fair game because the
// operator explicitly named this endpoint.
func injectablePathSegments(u *url.URL) (indexes []int, values []string) {
	segs := strings.Split(u.EscapedPath(), "/")
	// segs[0] is "" for an absolute path; real segments start at 1 → index 0.
	for i := 1; i < len(segs); i++ {
		seg := segs[i]
		if seg == "" {
			continue
		}
		dec, err := url.PathUnescape(seg)
		if err != nil {
			dec = seg
		}
		if strings.Contains(dec, ".") && isStaticAssetSegment(dec) {
			continue
		}
		indexes = append(indexes, i-1)
		values = append(values, dec)
	}
	return indexes, values
}

// isStaticAssetSegment reports whether a path segment is a static asset filename
// (so we don't waste a path insertion point fuzzing /app.min.js).
func isStaticAssetSegment(seg string) bool {
	dot := strings.LastIndexByte(seg, '.')
	if dot < 0 {
		return false
	}
	return nucleiStaticExts["."+strings.ToLower(seg[dot+1:])]
}

// SeedEndpointURL registers a single endpoint URL and its insertion points so the
// whole pipeline can operate on it. Returns the bare host (to seed the host into
// subdomains) and whether anything endpoint-specific was seeded.
func SeedEndpointURL(ctx context.Context, db *database.DB, targetID, rawURL string) (host string, seeded bool) {
	norm := normalizeEndpointURL(rawURL)
	if norm == "" {
		return "", false
	}
	u, err := url.Parse(norm)
	if err != nil {
		return "", false
	}
	host = u.Hostname()

	if !looksLikeEndpointURL(rawURL) {
		return host, false // a bare host — nothing endpoint-specific to seed
	}

	// 1) Register the endpoint URL as an http_service so crawl/JS/nuclei/dir seed
	//    from it. source='seed' marks it as operator-provided (not probe-confirmed);
	//    the consuming queries include 'seed'. A later real probe upgrades the row.
	_, _ = db.ExecContext(ctx, `
		INSERT INTO http_services (id, target_id, url, source, status_code)
		VALUES (?, ?, ?, 'seed', 0)
		ON CONFLICT(target_id, url) DO NOTHING`,
		uuid.New().String(), targetID, norm)

	// 2) Register QUERY parameters (location='query'). The value is kept as a hint;
	//    the reflection/injection engines replace it with their own probes.
	for name, vals := range u.Query() {
		if strings.TrimSpace(name) == "" {
			continue
		}
		val := ""
		if len(vals) > 0 {
			val = vals[0]
		}
		if _, err := db.ExecContext(ctx, `
			INSERT INTO parameters (id, target_id, url, parameter, value, source, method, content_type, location, is_reflected)
			VALUES (?, ?, ?, ?, ?, 'endpoint-seed', 'GET', '', 'query', 0)
			ON CONFLICT(target_id,url,parameter,method,location,content_type) DO UPDATE SET source='endpoint-seed'`,
			uuid.New().String(), targetID, norm, name, val); err == nil {
			seeded = true
		}
	}

	// 3) Register PATH segments (location='path:<index>'). The `parameters` unique
	//    key is (target_id, url, parameter); a path segment's synthetic name encodes
	//    its index so two segments never collide.
	idxs, valsSeg := injectablePathSegments(u)
	for k, idx := range idxs {
		pname := "path" + itoa(idx)
		if _, err := db.ExecContext(ctx, `
			INSERT INTO parameters (id, target_id, url, parameter, value, source, method, content_type, location, is_reflected)
			VALUES (?, ?, ?, ?, ?, 'endpoint-seed', 'GET', '', ?, 0)
			ON CONFLICT(target_id,url,parameter,method,location,content_type) DO UPDATE SET source='endpoint-seed', location=excluded.location`,
			uuid.New().String(), targetID, norm, pname, valsSeg[k], "path:"+itoa(idx)); err == nil {
			seeded = true
		}
	}
	return host, seeded
}
