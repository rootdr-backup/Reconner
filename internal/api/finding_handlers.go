package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/recon-platform/internal/models"
	"github.com/recon-platform/internal/scanner"
)

// handleSetFindingTriage records the operator's False-Positive triage decision on
// a vulnerability finding — confirmed (True Positive), false_positive, accepted_risk,
// fixed, or new — with an optional justification note. Triaged findings are filtered
// out of the working list and the exported report (FP management, section 3).
func (h *Handler) handleSetFindingTriage(w http.ResponseWriter, r *http.Request) {
	id, fid := mux.Vars(r)["id"], mux.Vars(r)["fid"]
	var req struct {
		Triage string `json:"triage"`
		Note   string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if !scanner.ValidTriageState(req.Triage) {
		h.writeError(w, http.StatusBadRequest, "invalid triage state (new|confirmed|false_positive|accepted_risk|fixed)")
		return
	}
	res, err := h.db.Exec(
		`UPDATE vuln_findings SET triage=?, triage_note=? WHERE id=? AND target_id=?`,
		req.Triage, req.Note, fid, id)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to update triage")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		h.writeError(w, http.StatusNotFound, "finding not found")
		return
	}
	h.hub.Broadcast("target_updated", map[string]string{"id": id})
	h.writeSuccess(w, map[string]string{"triage": req.Triage})
}

func (h *Handler) handleListSubdomains(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	offset := (page - 1) * limit
	alive := q.Get("alive")
	search := q.Get("search")

	query := `SELECT id, target_id, subdomain, ip, is_alive, status_code, page_title,
		has_https, has_http, response_time_ms, technologies, server, framework, cdn, waf,
		COALESCE(source,'dns'), last_seen, created_at
		FROM subdomains WHERE target_id = ?`
	args := []any{id}

	if alive == "true" {
		query += " AND is_alive = 1"
	} else if alive == "false" {
		query += " AND is_alive = 0"
	}

	if search != "" {
		query += " AND subdomain LIKE ?"
		args = append(args, "%"+search+"%")
	}

	var total int
	countQuery := "SELECT COUNT(*) FROM subdomains WHERE target_id = ?"
	countArgs := []any{id}
	if alive == "true" {
		countQuery += " AND is_alive = 1"
	} else if alive == "false" {
		countQuery += " AND is_alive = 0"
	}
	h.db.QueryRowContext(r.Context(), countQuery, countArgs...).Scan(&total)

	query += " ORDER BY subdomain LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := h.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to query subdomains")
		return
	}
	defer rows.Close()

	subs := make([]models.Subdomain, 0)
	for rows.Next() {
		var s models.Subdomain
		var techsJSON string
		var isAlive, hasHTTPS, hasHTTP int
		err := rows.Scan(&s.ID, &s.TargetID, &s.Subdomain, &s.IP, &isAlive,
			&s.StatusCode, &s.PageTitle, &hasHTTPS, &hasHTTP,
			&s.ResponseTimeMs, &techsJSON, &s.Server, &s.Framework,
			&s.CDN, &s.WAF, &s.Source, &s.LastSeen, &s.CreatedAt)
		if err != nil {
			continue
		}
		s.IsAlive = isAlive == 1
		s.HasHTTPS = hasHTTPS == 1
		s.HasHTTP = hasHTTP == 1
		s.Technologies = models.JSONToStringSlice(techsJSON)
		subs = append(subs, s)
	}

	h.writeJSON(w, http.StatusOK, map[string]any{
		"data":  subs,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

func (h *Handler) handleListHTTPServices(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	offset := (page - 1) * limit
	search := q.Get("search")
	statusFilter := q.Get("status")

	query := `SELECT id, target_id, url, status_code, title, server, content_type,
		content_length, redirect_url, technologies, response_time_ms, last_seen, created_at,
		COALESCE(waf,''), COALESCE(cms,'')
		FROM http_services WHERE target_id = ? AND COALESCE(source,'probe') = 'probe'`
	args := []any{id}

	if search != "" {
		query += " AND (url LIKE ? OR title LIKE ?)"
		like := "%" + search + "%"
		args = append(args, like, like)
	}

	if statusFilter != "" {
		var statusCode int
		fmt.Sscanf(statusFilter, "%d", &statusCode)
		if statusCode > 0 {
			query += " AND status_code = ?"
			args = append(args, statusCode)
		}
	}

	var total int
	h.db.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM http_services WHERE target_id = ? AND COALESCE(source,'probe') = 'probe'", id).Scan(&total)

	query += " ORDER BY url LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := h.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to query http services")
		return
	}
	defer rows.Close()

	services := make([]models.HTTPService, 0)
	for rows.Next() {
		var s models.HTTPService
		var techsJSON string
		err := rows.Scan(&s.ID, &s.TargetID, &s.URL, &s.StatusCode, &s.Title,
			&s.Server, &s.ContentType, &s.ContentLength, &s.RedirectURL,
			&techsJSON, &s.ResponseTimeMs, &s.LastSeen, &s.CreatedAt, &s.WAF, &s.CMS)
		if err != nil {
			continue
		}
		s.Technologies = models.JSONToStringSlice(techsJSON)
		services = append(services, s)
	}

	h.writeJSON(w, http.StatusOK, map[string]any{
		"data":  services,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

func (h *Handler) handleListJSFiles(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT id, target_id, url, size, hash, analyzed, last_seen, created_at
		FROM js_files WHERE target_id = ? ORDER BY url
	`, id)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	files := make([]models.JSFile, 0)
	for rows.Next() {
		var f models.JSFile
		var analyzed int
		err := rows.Scan(&f.ID, &f.TargetID, &f.URL, &f.Size, &f.Hash, &analyzed, &f.LastSeen, &f.CreatedAt)
		if err == nil {
			f.Analyzed = analyzed == 1
			files = append(files, f)
		}
	}
	h.writeSuccess(w, files)
}

func (h *Handler) handleListJSFindings(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	severity := r.URL.Query().Get("severity")
	findingType := r.URL.Query().Get("type")

	query := `SELECT jf.id, jf.target_id, jf.js_file_id, COALESCE(jsf.url, ''), jf.type, jf.value, jf.context, jf.severity, COALESCE(jf.verified, 0), jf.created_at
		FROM js_findings jf
		LEFT JOIN js_files jsf ON jsf.id = jf.js_file_id
		WHERE jf.target_id = ?`
	args := []any{id}

	if severity != "" {
		query += " AND jf.severity = ?"
		args = append(args, severity)
	}
	if findingType != "" {
		query += " AND jf.type = ?"
		args = append(args, findingType)
	}
	query += " ORDER BY CASE jf.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, jf.created_at DESC LIMIT 1000"

	rows, err := h.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	findings := make([]models.JSFinding, 0)
	for rows.Next() {
		var f models.JSFinding
		err := rows.Scan(&f.ID, &f.TargetID, &f.JSFileID, &f.JSFileURL, &f.Type, &f.Value, &f.Context, &f.Severity, &f.Verified, &f.CreatedAt)
		if err == nil {
			findings = append(findings, f)
		}
	}
	h.writeSuccess(w, findings)
}

func (h *Handler) handleListParameters(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	reflected := r.URL.Query().Get("reflected")
	search := r.URL.Query().Get("search")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	limit := 200
	offset := (page - 1) * limit

	query := `SELECT id, target_id, url, parameter, value, source, is_reflected, created_at
		FROM parameters WHERE target_id = ?`
	args := []any{id}

	if reflected == "true" {
		query += " AND is_reflected = 1"
	}
	if search != "" {
		query += " AND parameter LIKE ?"
		args = append(args, "%"+search+"%")
	}

	var total int
	h.db.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM parameters WHERE target_id = ?", id).Scan(&total)

	query += " ORDER BY parameter LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := h.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	params := make([]models.Parameter, 0)
	for rows.Next() {
		var p models.Parameter
		var isReflected int
		err := rows.Scan(&p.ID, &p.TargetID, &p.URL, &p.Parameter, &p.Value, &p.Source, &isReflected, &p.CreatedAt)
		if err == nil {
			p.IsReflected = isReflected == 1
			params = append(params, p)
		}
	}

	h.writeJSON(w, http.StatusOK, map[string]any{
		"data":  params,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

func (h *Handler) handleListDirectoryFindings(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT id, target_id, url, status_code, content_length, redirect_url, content_type, created_at
		FROM directory_findings WHERE target_id = ? ORDER BY content_length DESC, url
	`, id)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	findings := make([]models.DirectoryFinding, 0)
	for rows.Next() {
		var f models.DirectoryFinding
		err := rows.Scan(&f.ID, &f.TargetID, &f.URL, &f.StatusCode, &f.ContentLength, &f.RedirectURL, &f.ContentType, &f.CreatedAt)
		if err == nil {
			findings = append(findings, f)
		}
	}
	h.writeSuccess(w, findings)
}

func (h *Handler) handleListBackupFindings(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT id, target_id, url, status_code, content_length, COALESCE(file_type, ''), COALESCE(file_type, '') as backup_type, created_at
		FROM backup_findings WHERE target_id = ? ORDER BY content_length DESC, created_at DESC
	`, id)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	findings := make([]models.BackupFinding, 0)
	for rows.Next() {
		var f models.BackupFinding
		err := rows.Scan(&f.ID, &f.TargetID, &f.URL, &f.StatusCode, &f.ContentLength, &f.FileType, &f.BackupType, &f.CreatedAt)
		if err == nil {
			findings = append(findings, f)
		}
	}
	h.writeSuccess(w, findings)
}

func (h *Handler) handleListOpenRedirects(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT id, target_id, url, redirect_to, parameter, verified, created_at
		FROM open_redirect_findings WHERE target_id = ? ORDER BY created_at DESC
	`, id)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	findings := make([]models.OpenRedirectFinding, 0)
	for rows.Next() {
		var f models.OpenRedirectFinding
		var verified int
		err := rows.Scan(&f.ID, &f.TargetID, &f.URL, &f.RedirectTo, &f.Parameter, &verified, &f.CreatedAt)
		if err == nil {
			f.Verified = verified == 1
			findings = append(findings, f)
		}
	}
	h.writeSuccess(w, findings)
}

func (h *Handler) handleListNucleiFindings(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	severity := r.URL.Query().Get("severity")
	search := r.URL.Query().Get("search")

	// Hide hits the verifier proved to be false positives (a reflected-but-encoded
	// XSS template, a same-origin "open redirect", etc.). Rejected rows are kept in
	// the DB for audit but never shown as actionable findings.
	//
	// COLLAPSE DUPLICATES: a single nuclei template routinely fires on hundreds of
	// near-identical URLs (e.g. the same template appended to every static asset),
	// which flooded this list with one logical issue repeated N times. We now group
	// by template_id and return ONE representative row per template — the shortest
	// (cleanest, least path-fuzzed) matched URL — plus affected_count = how many
	// URLs it matched. Severity/search filters apply before grouping.
	inner := `SELECT id, target_id, template_id, template_name, severity, matched_url, description, tags, meta,
		COALESCE(curl_command,'') AS curl_command, COALESCE(request,'') AS request,
		COALESCE(response,'') AS response, created_at,
		COUNT(*) OVER (PARTITION BY template_id) AS affected_count,
		ROW_NUMBER() OVER (PARTITION BY template_id ORDER BY LENGTH(matched_url) ASC, created_at DESC) AS rn
		FROM nuclei_findings WHERE target_id = ? AND COALESCE(verification,'unverified') != 'rejected'`
	args := []any{id}

	if severity != "" {
		inner += " AND severity = ?"
		args = append(args, severity)
	}
	if search != "" {
		inner += " AND (template_name LIKE ? OR matched_url LIKE ? OR description LIKE ?)"
		like := "%" + search + "%"
		args = append(args, like, like, like)
	}

	// Truncate the heavy free-text columns and bound the row count for the same
	// reason as vuln_findings: full request/response bodies across many rows can
	// OOM the browser tab (black screen). The full PoC still opens on demand.
	query := `SELECT id, target_id, template_id, template_name, severity, matched_url,
		SUBSTR(COALESCE(description,''),1,2000), tags, meta,
		SUBSTR(COALESCE(curl_command,''),1,4000),
		SUBSTR(COALESCE(request,''),1,4000),
		SUBSTR(COALESCE(response,''),1,4000),
		created_at, affected_count
		FROM (` + inner + `) WHERE rn = 1
		ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
		         affected_count DESC, created_at DESC LIMIT 500`

	rows, err := h.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	findings := make([]models.NucleiFinding, 0)
	for rows.Next() {
		var f models.NucleiFinding
		var tagsJSON, metaJSON string
		err := rows.Scan(&f.ID, &f.TargetID, &f.TemplateID, &f.TemplateName,
			&f.Severity, &f.MatchedURL, &f.Description, &tagsJSON, &metaJSON,
			&f.CurlCommand, &f.Request, &f.Response, &f.CreatedAt, &f.AffectedCount)
		if err == nil {
			f.Tags = models.JSONToStringSlice(tagsJSON)
			f.Meta = models.JSONToMap(metaJSON)
			findings = append(findings, f)
		}
	}
	h.writeSuccess(w, findings)
}

// handleNucleiAffected returns EVERY matched URL for one template on a target —
// the full list behind a grouped finding's "affected_count", each with its own
// PoC (curl / request / response). This is what lets the UI/report expand a single
// collapsed row into "here are all N targets it fired on, with proof for each",
// instead of the other N-1 hits only ever appearing in the live log.
func (h *Handler) handleNucleiAffected(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	templateID := r.URL.Query().Get("template_id")
	if templateID == "" {
		h.writeError(w, http.StatusBadRequest, "template_id is required")
		return
	}
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT matched_url,
			SUBSTR(COALESCE(curl_command,''),1,4000),
			SUBSTR(COALESCE(request,''),1,6000),
			SUBSTR(COALESCE(response,''),1,6000),
			created_at
		FROM nuclei_findings
		WHERE target_id = ? AND template_id = ? AND COALESCE(verification,'unverified') != 'rejected'
		ORDER BY LENGTH(matched_url) ASC, created_at DESC LIMIT 1000
	`, id, templateID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	type Affected struct {
		MatchedURL  string `json:"matched_url"`
		CurlCommand string `json:"curl_command"`
		Request     string `json:"request"`
		Response    string `json:"response"`
		CreatedAt   string `json:"created_at"`
	}
	out := make([]Affected, 0)
	for rows.Next() {
		var a Affected
		if err := rows.Scan(&a.MatchedURL, &a.CurlCommand, &a.Request, &a.Response, &a.CreatedAt); err == nil {
			out = append(out, a)
		}
	}
	h.writeSuccess(w, out)
}

func (h *Handler) handleListMonitoringChanges(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT id, target_id, url, change_type, old_value, new_value, detected_at
		FROM monitoring_changes WHERE target_id = ?
		ORDER BY detected_at DESC LIMIT 500
	`, id)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	type Change struct {
		ID         string `json:"id"`
		TargetID   string `json:"target_id"`
		URL        string `json:"url"`
		ChangeType string `json:"change_type"`
		OldValue   string `json:"old_value"`
		NewValue   string `json:"new_value"`
		DetectedAt string `json:"detected_at"`
	}
	changes := make([]Change, 0)
	for rows.Next() {
		var c Change
		if err := rows.Scan(&c.ID, &c.TargetID, &c.URL, &c.ChangeType, &c.OldValue, &c.NewValue, &c.DetectedAt); err == nil {
			changes = append(changes, c)
		}
	}
	h.writeSuccess(w, changes)
}

func (h *Handler) handleListVulnFindings(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	vulnType := r.URL.Query().Get("type")
	// status filter: 'finding' (default) | 'candidate' | 'all'. Candidates are
	// unconfirmed and kept out of the default view / severity counts.
	statusFilter := r.URL.Query().Get("status")
	if statusFilter == "" {
		statusFilter = "finding"
	}

	// Cap the heavy free-text columns HERE, in SQL. A single finding's evidence or
	// provenance can be a full multi-megabyte HTTP exchange; the list view only
	// shows a truncated preview anyway (the full evidence loads on demand via the
	// Evidence button / EvidenceViewer). Sending 500 rows × megabytes was building
	// a DOM large enough to OOM the browser tab — the "click Vulns/Candidates and
	// the page goes black" crash, worst during an active scan that keeps re-fetching.
	query := `SELECT id, target_id, type, severity, url, parameter,
			SUBSTR(COALESCE(payload,''),1,2000),
			SUBSTR(COALESCE(evidence,''),1,4000),
			COALESCE(confidence,0), COALESCE(priority,0), COALESCE(status,'finding'),
			SUBSTR(COALESCE(provenance,''),1,4000),
			COALESCE(lifecycle,'LEGACY'), COALESCE(candidate_id,''),
			COALESCE(triage,''), SUBSTR(COALESCE(triage_note,''),1,1000), created_at
		FROM vuln_findings WHERE target_id = ?`
	args := []any{id}

	if vulnType != "" {
		query += " AND type = ?"
		args = append(args, vulnType)
	}
	if statusFilter != "all" {
		query += " AND COALESCE(status,'finding') = ?"
		args = append(args, statusFilter)
	}
	// False-Positive management: a specific triage view (e.g. ?triage=false_positive)
	// is shown on request; otherwise the working list HIDES findings marked as a
	// false positive so triaged noise stays out of the way.
	if tf := r.URL.Query().Get("triage"); tf != "" {
		query += " AND COALESCE(triage,'') = ?"
		args = append(args, tf)
	} else {
		query += " AND COALESCE(triage,'') != 'false_positive'"
	}

	// Rank by priority (severity × confidence) first — the genuinely
	// exploitable, high-confidence issues surface at the top.
	query += " ORDER BY priority DESC, CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, created_at DESC LIMIT 500"

	rows, err := h.db.Query(query, args...)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	type VulnFinding struct {
		ID          string `json:"id"`
		TargetID    string `json:"target_id"`
		Type        string `json:"type"`
		Severity    string `json:"severity"`
		URL         string `json:"url"`
		Parameter   string `json:"parameter"`
		Payload     string `json:"payload"`
		Evidence    string `json:"evidence"`
		Confidence  int    `json:"confidence"`
		Priority    int    `json:"priority"`
		Status      string `json:"status"`
		Provenance  string `json:"provenance"`
		Lifecycle   string `json:"lifecycle"`
		CandidateID string `json:"candidate_id"`
		Triage      string `json:"triage"`
		TriageNote  string `json:"triage_note"`
		CreatedAt   string `json:"created_at"`
	}
	findings := make([]VulnFinding, 0)
	for rows.Next() {
		var f VulnFinding
		if err := rows.Scan(&f.ID, &f.TargetID, &f.Type, &f.Severity, &f.URL, &f.Parameter, &f.Payload, &f.Evidence, &f.Confidence, &f.Priority, &f.Status, &f.Provenance, &f.Lifecycle, &f.CandidateID, &f.Triage, &f.TriageNote, &f.CreatedAt); err == nil {
			findings = append(findings, f)
		}
	}
	h.writeSuccess(w, findings)
}
