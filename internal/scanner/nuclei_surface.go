package scanner

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Nuclei surface canonicalization (P0 — target normalization + deduplication).
//
// A param-heavy site produces tens of thousands of URLs that are the SAME logical
// endpoint (…/user?id=1, …/user?id=2, …/order/1699…, …?utm_source=x). Feeding
// every one to nuclei as an independent target is the root cause of the "18,192
// URLs → 18,228 targets" explosion. This layer folds equivalent URLs to ONE
// representative target + a stable surface_fingerprint, WITHOUT losing real
// coverage: distinct paths, hosts, and meaningful parameter SETS stay distinct.
//
// What it folds (safe):
//   - query VALUES               (?id=1 == ?id=2)                — like NormalizeURL
//   - numeric path segments      (/user/123 == /user/456)        — like NormalizeURL
//   - UUID path segments         (/u/9a3f… == /u/7b2c…)          — NEW
//   - hex/hash path segments     (/f/ab12cd34… )                 — NEW
//   - long-digit / timestamp seg (/order-1699000000 )            — NEW
//   - tracking / cache-bust keys (utm_*, gclid, fbclid, _, cb…)  — NEW (dropped from the set)
//
// What it deliberately KEEPS distinct (no false-positive dedup):
//   - different paths            (/user vs /admin/user)
//   - different hosts
//   - different MEANINGFUL parameter sets (?a vs ?a&b where b isn't tracking)

var (
	reSurfUUID     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reSurfHex      = regexp.MustCompile(`^[0-9a-fA-F]{8,}$`) // md5/sha/hex identifiers
	reSurfNum      = regexp.MustCompile(`^\d+$`)
	reSurfLongDig  = regexp.MustCompile(`\d{6,}`) // a 6+ digit run inside a segment (id/timestamp)
	reSurfHostPort = regexp.MustCompile(`:(80|443)$`)
)

// nucleiTrackingParams are query keys that never change the security surface, so
// they're dropped from the fingerprint. Conservative on purpose — only keys that
// are unambiguously analytics / cache-busting, never app parameters like id/q.
var nucleiTrackingParams = map[string]bool{
	"utm_source": true, "utm_medium": true, "utm_campaign": true, "utm_term": true,
	"utm_content": true, "utm_id": true, "utm_name": true, "utm_reader": true,
	"gclid": true, "fbclid": true, "dclid": true, "msclkid": true, "yclid": true,
	"mc_cid": true, "mc_eid": true, "_ga": true, "_gl": true, "igshid": true,
	"cb": true, "cachebuster": true, "cache_buster": true, "nocache": true,
	"_": true, "__": true, "rand": true, "random": true,
}

// isDynamicIDSegment reports whether a path segment is a dynamic identifier that
// should fold to {id} (so equivalent resources collapse to one surface).
func isDynamicIDSegment(s string) bool {
	if s == "" {
		return false
	}
	switch {
	case reSurfNum.MatchString(s):
		return true
	case reSurfUUID.MatchString(s):
		return true
	case len(s) >= 8 && reSurfHex.MatchString(s):
		return true
	case reSurfLongDig.MatchString(s):
		// segment carries a long digit run (order-1699000000, id_1234567) → dynamic
		return true
	}
	return false
}

// nucleiSurfaceFingerprint returns a stable key identifying the LOGICAL endpoint
// of a URL for nuclei scheduling. Two URLs with the same fingerprint are the same
// surface and only one needs to be scanned.
func nucleiSurfaceFingerprint(raw string) string {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return strings.ToLower(raw)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	host := strings.ToLower(u.Host)
	host = reSurfHostPort.ReplaceAllString(host, "") // strip default ports

	// Fold dynamic id path segments.
	segs := strings.Split(u.Path, "/")
	for i, s := range segs {
		if isDynamicIDSegment(s) {
			segs[i] = "{id}"
		}
	}
	path := strings.Join(segs, "/")
	if path == "" {
		path = "/"
	}

	// Meaningful query keys only (values dropped, tracking/cache-bust dropped).
	var keys []string
	for k := range u.Query() {
		lk := strings.ToLower(k)
		if nucleiTrackingParams[lk] {
			continue
		}
		keys = append(keys, lk)
	}
	sort.Strings(keys)

	fp := scheme + "://" + host + path
	if len(keys) > 0 {
		fp += "?" + strings.Join(keys, "&")
	}
	return fp
}

// nucleiDynamicSegThreshold: when a single path position under the same parent
// takes at least this many DISTINCT values across the raw URL set, that position
// is a dynamic resource slug/id (usernames, video slugs, article titles) and is
// folded to {dyn}. This is what the numeric/UUID rules can't catch — a video
// portal's /v/<slug> and /profile/<user> are the same logical endpoint but every
// slug is alphabetic, so without this an 18k-URL Wayback history explodes into
// thousands of "distinct" nuclei surfaces. Kept high so normal sites (a handful
// of real sibling paths like /login, /admin, /api) are never folded.
const nucleiDynamicSegThreshold = 40

// buildDynamicPrefixes scans the raw URL set and returns the set of path prefixes
// whose immediate child segment is high-cardinality (≥ threshold distinct values)
// — i.e. a dynamic slug/id position. Prior numeric/UUID segments are folded to
// {id} when forming the parent key so, e.g., /user/1/x and /user/2/x share the
// same parent /user/{id} and their children aggregate.
func buildDynamicPrefixes(raw []string, threshold int) map[string]bool {
	children := make(map[string]map[string]bool)
	for _, r := range raw {
		u, err := url.Parse(strings.TrimSpace(r))
		if err != nil || u.Host == "" {
			continue
		}
		base := strings.ToLower(u.Scheme) + "://" + reSurfHostPort.ReplaceAllString(strings.ToLower(u.Host), "")
		trimmed := strings.Trim(u.Path, "/")
		if trimmed == "" {
			continue
		}
		prefix := base
		for _, s := range strings.Split(trimmed, "/") {
			if children[prefix] == nil {
				children[prefix] = make(map[string]bool)
			}
			children[prefix][s] = true
			advance := s
			if isDynamicIDSegment(s) {
				advance = "{id}"
			}
			prefix = prefix + "/" + advance
		}
	}
	dyn := make(map[string]bool)
	for k, set := range children {
		if len(set) >= threshold {
			dyn[k] = true
		}
	}
	return dyn
}

// nucleiSurfaceFingerprintFolded is nucleiSurfaceFingerprint plus adaptive
// high-cardinality path folding (dynamic slug/id positions → {dyn}). It advances
// the prefix key identically to buildDynamicPrefixes so the dynamic-prefix lookup
// lines up. Query-key semantics are unchanged (distinct meaningful param sets stay
// distinct), so no real coverage is lost.
func nucleiSurfaceFingerprintFolded(raw string, dyn map[string]bool) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return nucleiSurfaceFingerprint(raw)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	host := reSurfHostPort.ReplaceAllString(strings.ToLower(u.Host), "")
	base := scheme + "://" + host

	path := "/"
	if trimmed := strings.Trim(u.Path, "/"); trimmed != "" {
		segs := strings.Split(trimmed, "/")
		prefix := base
		for i, s := range segs {
			advance, out := s, s
			switch {
			case isDynamicIDSegment(s):
				advance, out = "{id}", "{id}"
			case dyn[prefix]:
				out = "{dyn}" // advance stays raw s to match buildDynamicPrefixes keys
			}
			segs[i] = out
			prefix = prefix + "/" + advance
		}
		path = "/" + strings.Join(segs, "/")
	}

	var keys []string
	for k := range u.Query() {
		lk := strings.ToLower(k)
		if nucleiTrackingParams[lk] {
			continue
		}
		keys = append(keys, lk)
	}
	sort.Strings(keys)

	fp := base + path
	if len(keys) > 0 {
		fp += "?" + strings.Join(keys, "&")
	}
	return fp
}

// dedupeNucleiSurfaces reduces a raw URL list to one representative real URL per
// logical surface, preserving input order (so the first-seen concrete URL — which
// actually exists — is the one scanned). It folds query values, numeric/UUID/hex
// path ids, tracking params, AND adaptive high-cardinality slug/id path segments,
// then enforces a per-host cap so one giant host can't consume the whole budget.
// Returns the representatives and the number of raw inputs collapsed/dropped (for
// the dedup-ratio log). capN (>0) bounds the total result; maxPerHost (>0) bounds
// each host's contribution.
func dedupeNucleiSurfaces(raw []string, capN, maxPerHost int) (surfaces []string, collapsed int) {
	dyn := buildDynamicPrefixes(raw, nucleiDynamicSegThreshold)
	seen := make(map[string]bool, len(raw))
	perHost := make(map[string]int)
	for _, u := range raw {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		fp := nucleiSurfaceFingerprintFolded(u, dyn)
		if seen[fp] {
			collapsed++
			continue
		}
		if maxPerHost > 0 {
			h := surfaceHost(u)
			if perHost[h] >= maxPerHost {
				collapsed++ // host budget spent — treat as folded away
				continue
			}
			perHost[h]++
		}
		seen[fp] = true
		surfaces = append(surfaces, u)
		if capN > 0 && len(surfaces) >= capN {
			break
		}
	}
	return surfaces, collapsed
}

// surfaceHost returns the lower-cased host (default ports stripped) for per-host
// capping; "" when unparseable so such URLs share one bucket.
func surfaceHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return reSurfHostPort.ReplaceAllString(strings.ToLower(u.Host), "")
}
