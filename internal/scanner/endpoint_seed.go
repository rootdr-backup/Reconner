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
// worth registering as a path insertion point.
//
// A static-asset-LOOKING last segment (photo.jpg, report.pdf, style.css) is
// deliberately NOT skipped, even though it was until this comment was written:
// an image/file-serving endpoint that resolves a path segment against the
// filesystem (/images/<name>, /download/<name>, /avatars/<name>) is precisely
// the classic real-world LFI/path-traversal vector — "looks like a static
// file" is exactly what makes it indistinguishable from a genuinely static
// asset by inspection alone, which is the whole reason to actually TEST it
// rather than assume. The old skip (meant to stop XSS/SQLi/SSTI from wasting a
// candidate on a truly immutable webpack bundle path) accidentally starved
// LFI of its single most common target class, since this is the ONLY function
// that ever produces a path-based insertion point. It still costs those other
// classes nothing: the synthetic parameter name ("path<N>") routes almost
// exclusively to LFI/CRLF via paramProneTo's name-token classification (see
// param_router.go), not to XSS/SQLi/SSTI, so nothing downstream gets spammed.
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
		indexes = append(indexes, i-1)
		values = append(values, dec)
	}
	return indexes, values
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

// seedPathSegmentsFromURLs registers a path-segment insertion point (see
// injectablePathSegments) for EVERY url given, not just a single explicitly-
// seeded endpoint. Before this, path-based candidates (location="path:<N>")
// only ever existed for the one operator-provided single-endpoint scope
// (SeedEndpointURL above) or an OpenAPI-documented path parameter — the
// overwhelming bulk of a normal scan's crawled surface (katana/gau/
// waybackurls/hakrawler output) only ever contributed QUERY parameters.
// LFI/SQLi/CRLF's most common real-world target class is often the URL PATH
// itself (/images/<name>, /download/<id>, /files/<name>), so this closes a
// structural blind spot affecting every path-shaped vector those detectors
// look for, not just the rare single-endpoint-scope case.
//
// Bounded to the first maxURLs (by iteration order) so a target with an
// enormous crawled corpus can't turn this into an unbounded insert storm;
// one prepared statement inside a single transaction keeps the bulk insert
// itself cheap regardless of how many rows that allows.
func seedPathSegmentsFromURLs(ctx context.Context, db *database.DB, targetID string, urls []string, maxURLs int) int {
	if maxURLs > 0 && len(urls) > maxURLs {
		urls = urls[:maxURLs]
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO parameters (id, target_id, url, parameter, value, source, method, content_type, location, is_reflected)
		VALUES (?, ?, ?, ?, ?, 'crawl-path', 'GET', '', ?, 0)
		ON CONFLICT(target_id,url,parameter,method,location,content_type) DO NOTHING`)
	if err != nil {
		_ = tx.Rollback()
		return 0
	}
	seeded := 0
	for _, raw := range urls {
		if ctx.Err() != nil {
			break
		}
		u, err := url.Parse(raw)
		if err != nil || u.Path == "" || u.Path == "/" {
			continue
		}
		idxs, vals := injectablePathSegments(u)
		for k, idx := range idxs {
			res, err := stmt.ExecContext(ctx, uuid.New().String(), targetID, raw, "path"+itoa(idx), vals[k], "path:"+itoa(idx))
			if err != nil {
				continue
			}
			if n, _ := res.RowsAffected(); n > 0 {
				seeded++
			}
		}
	}
	_ = stmt.Close()
	_ = tx.Commit()
	return seeded
}
