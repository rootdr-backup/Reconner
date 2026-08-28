package scanner

import (
	"context"

	"github.com/recon-platform/internal/database"
)

// Correlation / deduplication (P3). The same authorization root cause often
// manifests on many resources (BOLA on /api/projects/1, /2, /3…). We group
// findings by (vuln type + endpoint TEMPLATE) so the researcher sees ONE root
// issue with N affected resources — without destroying the individual evidence.

// CorrelationKey groups findings sharing a root cause: same vuln type + same
// normalized endpoint (object ids collapsed to {id}).
func CorrelationKey(vulnType, rawURL string) string {
	return vulnType + "|" + NormalizeURL(rawURL)
}

// CorrelateFindings (re)computes correlation for a target: assigns each finding a
// correlation_key and points every member of a group at a single ROOT finding
// (the strongest by confidence, then severity). Returns the number of distinct
// root groups. Idempotent.
func CorrelateFindings(ctx context.Context, db *database.DB, targetID string) int {
	rows, err := db.QueryContext(ctx,
		`SELECT id, type, url, COALESCE(confidence,0), COALESCE(severity,'') FROM vuln_findings WHERE target_id=?`, targetID)
	if err != nil {
		return 0
	}
	type f struct {
		id, typ, url, sev string
		conf              int
	}
	var all []f
	for rows.Next() {
		var x f
		if rows.Scan(&x.id, &x.typ, &x.url, &x.conf, &x.sev) == nil {
			all = append(all, x)
		}
	}
	rows.Close()

	sevRank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
	// best finding per key
	best := map[string]f{}
	keyOf := map[string]string{} // findingID → key
	for _, x := range all {
		k := CorrelationKey(x.typ, x.url)
		keyOf[x.id] = k
		b, ok := best[k]
		if !ok || x.conf > b.conf || (x.conf == b.conf && sevRank[x.sev] > sevRank[b.sev]) {
			best[k] = x
		}
	}
	for _, x := range all {
		k := keyOf[x.id]
		root := best[k].id
		_, _ = db.ExecContext(ctx,
			`UPDATE vuln_findings SET correlation_key=?, root_finding_id=? WHERE id=?`, k, root, x.id)
	}
	return len(best)
}
