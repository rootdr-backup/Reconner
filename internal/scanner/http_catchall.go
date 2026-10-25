package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// The HTTP catch-all pass closes the hole the DNS wildcard gate cannot see:
// a zone with NO DNS wildcard can still serve one shared homepage or one
// redirect for EVERY hostname under it (parking-style hosting, SaaS
// platforms). Those names arrive as fully "verified" subdomains — the DNS gate
// happily passes them — and flood the Hosts tab, reports and every web module
// downstream.
//
// The pass runs at the END of the HTTP-probe module (only when the operator
// enabled it in config; default is OFF) and groups the http_services rows that
// the probing ALREADY collected:
//
//   - Redirect groups: 3+ hosts that share one fingerprint AND redirect to the
//     apex (or www-apex). This is the classic wildcard redirect the operator
//     reported ("asdf-garbage.git." style junk pointing at the homepage).
//   - Homepage clones: 5+ hosts byte-identical (status), title-, server-,
//     content-type/length-, tech-, WAF/CMS-fingerprint-identical to the apex
//     homepage that was probed in the same run.
//
// Grouping is 2xx-only by design: 401/403 auth walls legitimately serve the
// same shell for every host and must never be marked; per-host SSO redirects
// carry state that makes their fingerprints differ. The residual risk is a
// legit byte-identical 200-fleet that is NOT apex-related — rare, and
// reversible since rows are marked, never deleted, and the whole pass is a
// config toggle.
//
// Zero network cost: no DNS, no extra HTTP requests — the pass reads the
// fingerprints stored seconds earlier.

const (
	catchallMinRedirectGroup = 3 // redirect-to-apex fleets need less agreement: pointing at the apex is the wildcard's signature
	catchallMinContentGroup  = 5 // homepage cloning is only "catch-all-shaped" with more members; protects legitimate twins (staging/prod mirrors)
)

// hostFromServiceURL extracts and normalizes the hostname of an http_services
// URL. Probing stores scheme://host[:port][/path]; the subdomain matching only
// cares about the registered hostname part.
func hostFromServiceURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
		return strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	}
	// Fallback for scheme-less or malformed rows: cut the authority.
	rest := raw
	rest = strings.TrimPrefix(rest, "https://")
	rest = strings.TrimPrefix(rest, "http://")
	if idx := strings.IndexAny(rest, "/?#"); idx >= 0 {
		rest = rest[:idx]
	}
	if idx := strings.LastIndex(rest, "@"); idx >= 0 { // strip userinfo
		rest = rest[idx+1:]
	}
	if idx := strings.Index(rest, ":"); idx >= 0 { // strip port
		rest = rest[:idx]
	}
	return strings.ToLower(strings.TrimSuffix(rest, "."))
}

// sortedTechnologies normalizes the stored technologies JSON so two hosts with
// the same tech stack in different order share one fingerprint.
func sortedTechnologies(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "[]" {
		return ""
	}
	var techs []string
	if err := json.Unmarshal([]byte(raw), &techs); err != nil {
		return strings.ToLower(raw) // tolerate non-JSON rows; still comparable
	}
	sort.Strings(techs)
	return strings.ToLower(strings.Join(techs, ","))
}

type catchallRow struct {
	host         string
	contentFP    string // status|title|server|content-type|length|techs|waf|cms
	redirectHost string // lowercase target hostname, "" when no redirect
}

// buildCatchallRow computes the grouping fields of one http_services row.
func buildCatchallRow(rawURL string, statusCode int, title, server, contentType string, contentLength int, redirectURL, technologies, waf, cms string) catchallRow {
	var fp strings.Builder
	fmt.Fprintf(&fp, "%d|%s|%s|%s|%d|%s|%s|%s",
		statusCode, strings.ToLower(strings.TrimSpace(title)), strings.ToLower(strings.TrimSpace(server)),
		strings.ToLower(strings.TrimSpace(contentType)), contentLength,
		sortedTechnologies(technologies), strings.ToLower(strings.TrimSpace(waf)), strings.ToLower(strings.TrimSpace(cms)))
	return catchallRow{
		host:         hostFromServiceURL(rawURL),
		contentFP:    fp.String(),
		redirectHost: normalizeSubdomainName(hostFromServiceURL(redirectURL)),
	}
}

// catchallApexTargets reports the hostnames a wildcard redirect aims at: the
// apex itself or the canonical www host.
func catchallApexTargets(apex string) map[string]bool {
	targets := map[string]bool{apex: true, "www." + apex: true}
	return targets
}

// groupCatchallFingerprints groups rows by content fingerprint.
func groupCatchallFingerprints(rows []catchallRow) map[string][]catchallRow {
	groups := map[string][]catchallRow{}
	for _, row := range rows {
		groups[row.contentFP] = append(groups[row.contentFP], row)
	}
	return groups
}

// qualifiesCatchallGroup decides whether a fingerprint group is a wildcard
// fleet and returns the members to mark. rows must exclude non-2xx entries.
// The apex and www hosts are never in the returned set: they ARE the origin
// the wildcard copies, so marking them would hide the real site.
func qualifiesCatchallGroup(rows []catchallRow, apexTargets map[string]bool) (marked []catchallRow, kind string) {
	if len(rows) == 0 {
		return nil, ""
	}
	redirecting := 0
	hasApexMember := false
	hasForeignRedirect := false
	for _, row := range rows {
		if row.redirectHost != "" {
			if apexTargets[row.redirectHost] {
				redirecting++
			} else {
				// One member redirects somewhere else entirely — a mixed
				// group of distinct apps, not a wildcard funnel.
				hasForeignRedirect = true
			}
		}
		if apexTargets[row.host] {
			hasApexMember = true
		}
	}
	if redirecting >= catchallMinRedirectGroup && !hasForeignRedirect {
		// At least three identical pages funnel into the apex and NOTHING in
		// the group redirects elsewhere: a wildcard redirect. The apex/www
		// rows stay unmarked (they ARE the origin).
		for _, row := range rows {
			if !apexTargets[row.host] {
				marked = append(marked, row)
			}
		}
		return marked, "redirect"
	}
	if hasApexMember && len(rows) >= catchallMinContentGroup {
		// The apex homepage itself sits inside a large identical-content
		// group: every member serves the apex's homepage — a content
		// catch-all. The apex/www rows stay unmarked (they ARE the origin);
		// strictly-deeper members get marked.
		for _, row := range rows {
			if !apexTargets[row.host] {
				marked = append(marked, row)
			}
		}
		return marked, "homepage"
	}
	return nil, ""
}

// runCatchallPass implements the opt-in step-2 pass. It resolves the target's
// apex from the targets row, fingerprints all stored 2xx services, marks the
// wildcard fleet members (DNS-source rows only) and drops their
// http_services rows so web modules never fetch them again.
func (s *HTTPScanner) runCatchallPass(ctx context.Context, targetID string, logFn LogFunc) error {
	var apex string
	if err := s.db.QueryRowContext(ctx, `SELECT domain FROM targets WHERE id=?`, targetID).Scan(&apex); err != nil || strings.TrimSpace(apex) == "" {
		// Unknown target — the pass is best-effort; probing already logged context.
		return nil
	}
	apex = normalizeSubdomainName(apex)

	rows, err := s.db.QueryContext(ctx, `
		SELECT url, status_code, title, COALESCE(server,''), COALESCE(content_type,''),
		       COALESCE(content_length,0), COALESCE(redirect_url,''), COALESCE(technologies,'[]'),
		       COALESCE(waf,''), COALESCE(cms,'')
		FROM http_services
		WHERE target_id=? AND status_code BETWEEN 200 AND 299`, targetID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var candidateRows []catchallRow
	var total2xx int
	for rows.Next() {
		var rawURL, title, server, contentType, redirectURL, technologies, waf, cms string
		var statusCode, contentLength int
		if rows.Scan(&rawURL, &statusCode, &title, &server, &contentType, &contentLength, &redirectURL, &technologies, &waf, &cms) != nil {
			continue
		}
		total2xx++
		row := buildCatchallRow(rawURL, statusCode, title, server, contentType, contentLength, redirectURL, technologies, waf, cms)
		if row.host == "" {
			continue
		}
		// Apex/www rows stay in the candidate pool (they anchor the homepage
		// group) but can only ever be marked by group logic, never as strays.
		candidateRows = append(candidateRows, row)
	}
	rows.Close()

	if len(candidateRows) == 0 {
		logFn("info", "http_probe", fmt.Sprintf("HTTP catch-all pass: %d stored 2xx service(s) — nothing to group", total2xx))
		return nil
	}

	apexTargets := catchallApexTargets(apex)
	groups := groupCatchallFingerprints(candidateRows)

	markedSet := map[string]string{} // host -> pattern kind (deduped across schemes/groups)
	redirectGroups, homepageGroups := 0, 0
	for _, members := range groups {
		marked, kind := qualifiesCatchallGroup(members, apexTargets)
		if kind == "" {
			continue
		}
		if kind == "redirect" {
			redirectGroups++
		} else {
			homepageGroups++
		}
		for _, row := range marked {
			// Defense in depth: only hosts strictly under the target apex are
			// ever marked (qualifies already excludes apex/www; this also
			// rejects any foreign host a stray service row might carry).
			if row.host == apex || !strings.HasSuffix(row.host, "."+apex) {
				continue
			}
			if _, seen := markedSet[row.host]; !seen {
				markedSet[row.host] = kind
			}
		}
	}

	if len(markedSet) == 0 {
		logFn("info", "http_probe", fmt.Sprintf("HTTP catch-all pass: %d live 2xx host(s) analysed — no catch-all groups", total2xx))
		return nil
	}

	markedHosts := make([]string, 0, len(markedSet))
	for host := range markedSet {
		markedHosts = append(markedHosts, host)
	}
	sort.Strings(markedHosts)
	for _, host := range markedHosts {
		logFn("info", "http_probe", fmt.Sprintf("HTTP catch-all: %s serves the wildcard group (%s pattern)", host, markedSet[host]))
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `UPDATE subdomains SET catchall=1
		WHERE target_id=? AND subdomain=? AND COALESCE(source,'dns')='dns' AND COALESCE(catchall,0)=0`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	urlStmt, err := tx.PrepareContext(ctx, `DELETE FROM http_services
		WHERE target_id=? AND (url LIKE 'https://'||?||'/%' OR url LIKE 'https://'||?||':%'
			OR url LIKE 'http://'||?||'/%' OR url LIKE 'http://'||?||':%' OR url='https://'||? OR url='http://'||?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	marked := 0
	for _, host := range markedHosts {
		res, _ := stmt.ExecContext(ctx, targetID, host)
		if affRows, aerr := res.RowsAffected(); aerr == nil && affRows > 0 {
			marked++
			// Drop the junk services so JS/params/DAST/nuclei never target
			// them again. The subdomain row keeps the evidence of WHY.
			_, _ = urlStmt.ExecContext(ctx, targetID, host, host, host, host, host, host)
		}
	}
	_ = stmt.Close()
	_ = urlStmt.Close()
	if err := tx.Commit(); err != nil {
		return err
	}

	logFn("info", "http_probe", fmt.Sprintf(
		"HTTP catch-all pass: %d live 2xx host(s) analysed — %d wildcard group(s) (%d redirect, %d homepage), %d host(s) marked and hidden",
		total2xx, redirectGroups+homepageGroups, redirectGroups, homepageGroups, marked))
	return nil
}
