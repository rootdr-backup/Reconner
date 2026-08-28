package api

import (
	"net/http"
	"strings"
)

// Global findings view. The per-target tabs are the detail view; a community
// operator running many targets also wants ONE place that answers "what has
// Reconner actually found, everywhere, right now". handleListAllFindings
// aggregates confirmed vuln findings across every target the caller owns (all
// targets for an admin), newest/most-severe first, with the target each belongs
// to — the backing data for the top-level Findings page.

type allFinding struct {
	ID         string `json:"id"`
	TargetID   string `json:"target_id"`
	Domain     string `json:"domain"`
	Type       string `json:"type"`
	Severity   string `json:"severity"`
	URL        string `json:"url"`
	Parameter  string `json:"parameter"`
	Confidence int    `json:"confidence"`
	Priority   int    `json:"priority"`
	Status     string `json:"status"`
	Evidence   string `json:"evidence"`
	CreatedAt  string `json:"created_at"`
}

// handleListAllFindings (GET /findings) returns confirmed findings across all of
// the caller's targets. Optional query params: status (finding|candidate|all,
// default finding), severity (critical|high|medium|low|info), type.
func (h *Handler) handleListAllFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	status := q.Get("status")
	if status == "" {
		status = "finding"
	}

	query := `SELECT f.id, f.target_id, COALESCE(t.domain,''), f.type, f.severity,
			f.url, COALESCE(f.parameter,''),
			COALESCE(f.confidence,0), COALESCE(f.priority,0), COALESCE(f.status,'finding'),
			SUBSTR(COALESCE(f.evidence,''),1,2000), f.created_at
		FROM vuln_findings f JOIN targets t ON t.id = f.target_id
		WHERE COALESCE(f.triage,'') != 'false_positive'`
	args := []any{}

	// Per-user isolation: a non-admin sees only findings on their own targets.
	if uid, isAdmin := h.callerScope(r); !isAdmin {
		query += " AND t.owner_id = ?"
		args = append(args, uid)
	}
	if status != "all" {
		query += " AND COALESCE(f.status,'finding') = ?"
		args = append(args, status)
	}
	if sev := q.Get("severity"); sev != "" {
		query += " AND LOWER(f.severity) = ?"
		args = append(args, strings.ToLower(sev))
	}
	if typ := q.Get("type"); typ != "" {
		query += " AND f.type = ?"
		args = append(args, typ)
	}
	query += ` ORDER BY f.priority DESC,
		CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
		f.created_at DESC LIMIT 1000`

	rows, err := h.db.Query(query, args...)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	out := []allFinding{}
	for rows.Next() {
		var f allFinding
		if err := rows.Scan(&f.ID, &f.TargetID, &f.Domain, &f.Type, &f.Severity,
			&f.URL, &f.Parameter, &f.Confidence, &f.Priority, &f.Status,
			&f.Evidence, &f.CreatedAt); err != nil {
			continue
		}
		out = append(out, f)
	}
	h.writeSuccess(w, out)
}
