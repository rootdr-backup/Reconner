package api

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/recon-platform/internal/browser"
	"github.com/recon-platform/internal/models"
	"github.com/recon-platform/internal/scanner"
	"github.com/recon-platform/internal/scheduler"
	"github.com/recon-platform/internal/secret"
	"golang.org/x/net/http/httpguts"
)

func normalizeScanIdentity(userAgent string, headers map[string]string) (string, map[string]string, string, error) {
	userAgent = strings.TrimSpace(userAgent)
	if len(userAgent) > 512 || strings.ContainsAny(userAgent, "\r\n") {
		return "", nil, "", fmt.Errorf("scan User-Agent must be one line and at most 512 characters")
	}
	clean := make(map[string]string, len(headers))
	for rawName, rawValue := range headers {
		name, value := http.CanonicalHeaderKey(strings.TrimSpace(rawName)), strings.TrimSpace(rawValue)
		if name == "" || value == "" || len(name) > 128 || len(value) > 4096 ||
			!httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
			return "", nil, "", fmt.Errorf("scan headers must have valid single-line names and values")
		}
		switch strings.ToLower(name) {
		case "host", "content-length", "connection", "transfer-encoding", "proxy-authorization", "proxy-authenticate", "proxy-connection", "keep-alive", "te", "trailer", "upgrade", "user-agent":
			return "", nil, "", fmt.Errorf("header %q is reserved; use the dedicated User-Agent field when applicable", name)
		}
		if _, duplicate := clean[name]; duplicate {
			return "", nil, "", fmt.Errorf("scan header %q is duplicated with different casing", name)
		}
		clean[name] = value
	}
	if len(clean) > 64 {
		return "", nil, "", fmt.Errorf("at most 64 scan headers are allowed")
	}
	raw, err := json.Marshal(clean)
	if err != nil {
		return "", nil, "", fmt.Errorf("invalid scan headers")
	}
	return userAgent, clean, string(raw), nil
}

func normalizeScopeValues(scope string) ([]string, error) {
	seen := map[string]bool{}
	values := make([]string, 0)
	var tokens []string
	for _, line := range strings.FieldsFunc(scope, func(r rune) bool { return r == '\n' || r == '\r' }) {
		line = strings.TrimSpace(line)
		// A complete URL may legitimately contain commas/semicolons in its path or
		// query. The UI documents one asset per line, so preserve such a line whole.
		if strings.HasPrefix(strings.ToLower(line), "http://") || strings.HasPrefix(strings.ToLower(line), "https://") {
			tokens = append(tokens, line)
			continue
		}
		tokens = append(tokens, strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || r == ';' || r == '\t' || r == ' '
		})...)
	}
	for _, token := range tokens {
		value, err := normalizeAssetValue(token)
		if err != nil {
			return nil, fmt.Errorf("invalid asset %q: %w", strings.TrimSpace(token), err)
		}
		if !seen[value] {
			seen[value] = true
			values = append(values, value)
		}
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("at least one valid asset is required")
	}
	return values, nil
}

func reconcileManualAssetsTx(tx *sql.Tx, targetID string, values []string) error {
	desired := make(map[string]bool, len(values))
	for _, value := range values {
		desired[value] = true
		kind, _, _ := detectAssetKind(value)
		assetType := normalizeManualAssetType("", value, kind)
		if _, err := tx.Exec(`INSERT INTO assets (id,target_id,name,value,kind,asset_type,source,approval_status,monitor_enabled,updated_at)
			VALUES (?,?, '',?,?,?,'manual','approved',1,CURRENT_TIMESTAMP)
			ON CONFLICT(target_id,value) DO NOTHING`, uuid.New().String(), targetID, value, kind, assetType); err != nil {
			return err
		}
	}
	rows, err := tx.Query(`SELECT id,value FROM assets WHERE target_id=? AND COALESCE(source,'manual')='manual'`, targetID)
	if err != nil {
		return err
	}
	var remove []string
	for rows.Next() {
		var id, value string
		if err := rows.Scan(&id, &value); err != nil {
			rows.Close()
			return err
		}
		if !desired[value] {
			remove = append(remove, id)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, id := range remove {
		if _, err := tx.Exec(`DELETE FROM assets WHERE id=? AND target_id=?`, id, targetID); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) handleListTargets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	search := q.Get("search")
	priority := q.Get("priority")
	tag := q.Get("tag")
	status := q.Get("status")

	query := `SELECT id, domain, COALESCE(kind,'web'), COALESCE(description,''), COALESCE(tags,'[]'),
		COALESCE(priority,'medium'), COALESCE(notes,''), COALESCE(status,'idle'), COALESCE(scan_status,'idle'), COALESCE(enabled_modules,'[]'),
		last_scan_at, created_at, updated_at, COALESCE(subdomain_count,0), COALESCE(alive_host_count,0), COALESCE(finding_count,0),
		COALESCE(monitor_enabled,0), COALESCE(monitor_interval_hours,2), COALESCE(name,''), COALESCE(exclude_scope,'')
		FROM targets WHERE 1=1`
	args := []any{}

	// Per-user isolation: a member sees only their own targets; an admin sees all.
	if uid, isAdmin := h.callerScope(r); !isAdmin {
		query += " AND owner_id = ?"
		args = append(args, uid)
	}

	if kind := r.URL.Query().Get("kind"); kind != "" {
		query += " AND COALESCE(kind,'web') = ?"
		args = append(args, kind)
	}
	if search != "" {
		query += " AND (domain LIKE ? OR COALESCE(name,'') LIKE ? OR description LIKE ? OR notes LIKE ? OR tags LIKE ?)"
		like := "%" + search + "%"
		args = append(args, like, like, like, like, like)
	}
	if priority != "" {
		query += " AND priority = ?"
		args = append(args, priority)
	}
	if status != "" {
		query += " AND scan_status = ?"
		args = append(args, status)
	}
	if tag != "" {
		query += " AND EXISTS (SELECT 1 FROM json_each(CASE WHEN json_valid(tags) THEN tags ELSE '[]' END) WHERE value = ?)"
		args = append(args, tag)
	}

	query += " ORDER BY created_at DESC"

	rows, err := h.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to query targets")
		return
	}
	defer rows.Close()

	targets := make([]models.Target, 0)
	for rows.Next() {
		var t models.Target
		var lastScan *string
		var tagsJSON, modulesJSON string
		var monitorEnabled int

		err := rows.Scan(&t.ID, &t.Domain, &t.Kind, &t.Description, &tagsJSON, &t.Priority,
			&t.Notes, &t.Status, &t.ScanStatus, &modulesJSON,
			&lastScan, &t.CreatedAt, &t.UpdatedAt,
			&t.SubdomainCount, &t.AliveHostCount, &t.FindingCount,
			&monitorEnabled, &t.MonitorIntervalHours, &t.Name, &t.ExcludeScope)
		if err != nil {
			h.writeError(w, http.StatusInternalServerError, "failed to decode targets")
			return
		}

		t.Tags = models.JSONToStringSlice(tagsJSON)
		t.EnabledModules = models.JSONToStringSlice(modulesJSON)
		t.MonitorEnabled = monitorEnabled == 1
		if lastScan != nil && *lastScan != "" {
			parsed, err := time.Parse("2006-01-02T15:04:05Z", *lastScan)
			if err == nil {
				t.LastScanAt = &parsed
			}
		}

		targets = append(targets, t)
	}
	if err := rows.Err(); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to read targets")
		return
	}

	h.writeSuccess(w, targets)
}

func (h *Handler) handleCreateTarget(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain        string            `json:"domain"`
		Name          string            `json:"name"` // friendly label for the target
		Description   string            `json:"description"`
		Tags          []string          `json:"tags"`
		Priority      string            `json:"priority"`
		Notes         string            `json:"notes"`
		Kind          string            `json:"kind"`          // web | network (auto-detected if empty)
		ExcludeScope  string            `json:"exclude_scope"` // out-of-scope hosts/IPs/CIDRs/URLs
		ScanUserAgent string            `json:"scan_user_agent"`
		ScanHeaders   map[string]string `json:"scan_headers"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	raw := strings.TrimSpace(req.Domain)
	if raw == "" {
		h.writeError(w, http.StatusBadRequest, "domain/scope is required")
		return
	}
	scopeValues, err := normalizeScopeValues(raw)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	normalizedScope := strings.Join(scopeValues, ",")

	// Unified scope: a single target may mix web hosts and network IP/CIDR/ranges.
	// Auto-detect the kind from the scope composition (explicit req.Kind still wins,
	// for backward compatibility): web-only, network-only, or "mixed" (both).
	webHosts, netScope := scanner.SplitScope(normalizedScope)
	kind := strings.ToLower(strings.TrimSpace(req.Kind))
	if kind == "" {
		switch {
		case len(webHosts) > 0 && netScope != "":
			kind = "mixed"
		case netScope != "":
			kind = "network"
		default:
			kind = "web"
		}
	}

	// Preserve endpoint paths and query strings. Managed assets are authoritative,
	// and collapsing https://host/path into the invalid host/path form silently
	// lost the exact endpoint on subsequent edits and exports.
	domain := normalizedScope

	if req.Priority == "" {
		req.Priority = "medium"
	}

	id := uuid.New().String()
	tagsJSON := models.StringSliceToJSON(req.Tags)

	scanUserAgent, scanHeaders, scanHeadersJSON, err := normalizeScanIdentity(req.ScanUserAgent, req.ScanHeaders)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to create target")
		return
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(r.Context(), `
		INSERT INTO targets (id, domain, description, tags, priority, notes, kind, name, exclude_scope, owner_id, scan_user_agent, scan_headers)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, id, domain, req.Description, tagsJSON, req.Priority, req.Notes, kind, strings.TrimSpace(req.Name), strings.TrimSpace(req.ExcludeScope), h.currentUserID(r), scanUserAgent, scanHeadersJSON)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			h.writeError(w, http.StatusConflict, "target already exists")
			return
		}
		h.writeError(w, http.StatusInternalServerError, "failed to create target")
		return
	}
	if err := reconcileManualAssetsTx(tx, id, scopeValues); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to create managed assets")
		return
	}
	if err := tx.Commit(); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to create target")
		return
	}

	target := &models.Target{
		ID:            id,
		Domain:        domain,
		Name:          strings.TrimSpace(req.Name),
		Kind:          kind,
		Description:   req.Description,
		Tags:          req.Tags,
		Priority:      req.Priority,
		Notes:         req.Notes,
		Status:        "idle",
		ScanStatus:    "idle",
		ScanUserAgent: scanUserAgent,
		ScanHeaders:   scanHeaders,
	}

	h.hub.Broadcast("target_created", target)
	h.writeJSON(w, http.StatusCreated, map[string]any{"data": target, "success": true})
}

// handleNetworkServices returns the discovered open ip:port services for a
// network target (the inventory the Network panel renders).
func (h *Handler) handleNetworkServices(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT ip, port, protocol, service, product, version, banner,
		       is_web, web_url, web_title, web_status, tls
		FROM network_services WHERE target_id = ?
		ORDER BY ip, port`, id)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to query network services")
		return
	}
	defer rows.Close()
	type svc struct {
		IP       string `json:"ip"`
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		Service  string `json:"service"`
		Product  string `json:"product"`
		Version  string `json:"version"`
		Banner   string `json:"banner"`
		IsWeb    bool   `json:"is_web"`
		WebURL   string `json:"web_url"`
		WebTitle string `json:"web_title"`
		WebfStat int    `json:"web_status"`
		TLS      bool   `json:"tls"`
	}
	out := make([]svc, 0)
	for rows.Next() {
		var s svc
		var isWeb, tlsi int
		if rows.Scan(&s.IP, &s.Port, &s.Protocol, &s.Service, &s.Product, &s.Version,
			&s.Banner, &isWeb, &s.WebURL, &s.WebTitle, &s.WebfStat, &tlsi) == nil {
			s.IsWeb = isWeb == 1
			s.TLS = tlsi == 1
			out = append(out, s)
		}
	}
	h.writeSuccess(w, out)
}

func (h *Handler) handleGetTarget(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	var t models.Target
	var lastScan, monitorLastRun *string
	var tagsJSON, modulesJSON, scanHeadersJSON string
	var monitorEnabled int

	err := h.db.QueryRowContext(r.Context(), `
		SELECT id, domain, COALESCE(kind,'web'), COALESCE(description,''), COALESCE(tags,'[]'),
			COALESCE(priority,'medium'), COALESCE(notes,''), COALESCE(status,'idle'), COALESCE(scan_status,'idle'), COALESCE(enabled_modules,'[]'),
			last_scan_at, created_at, updated_at, COALESCE(subdomain_count,0), COALESCE(alive_host_count,0), COALESCE(finding_count,0),
			COALESCE(monitor_enabled,0), COALESCE(monitor_interval_hours,2), COALESCE(name,''), COALESCE(exclude_scope,''), monitor_last_run,
			COALESCE(scan_user_agent,''), COALESCE(scan_headers,'{}')
		FROM targets WHERE id = ?
	`, id).Scan(&t.ID, &t.Domain, &t.Kind, &t.Description, &tagsJSON, &t.Priority,
		&t.Notes, &t.Status, &t.ScanStatus, &modulesJSON,
		&lastScan, &t.CreatedAt, &t.UpdatedAt,
		&t.SubdomainCount, &t.AliveHostCount, &t.FindingCount,
		&monitorEnabled, &t.MonitorIntervalHours, &t.Name, &t.ExcludeScope, &monitorLastRun, &t.ScanUserAgent, &scanHeadersJSON)
	if err != nil {
		h.writeError(w, http.StatusNotFound, "target not found")
		return
	}

	t.Tags = models.JSONToStringSlice(tagsJSON)
	t.EnabledModules = models.JSONToStringSlice(modulesJSON)
	t.MonitorEnabled = monitorEnabled == 1
	t.ScanHeaders = map[string]string{}
	_ = json.Unmarshal([]byte(scanHeadersJSON), &t.ScanHeaders)
	if lastScan != nil {
		parsed, _ := time.Parse("2006-01-02T15:04:05Z", *lastScan)
		t.LastScanAt = &parsed
	}
	if monitorLastRun != nil {
		parsed, _ := time.Parse("2006-01-02T15:04:05Z", *monitorLastRun)
		t.MonitorLastRun = &parsed
	}

	h.writeSuccess(w, t)
}

func (h *Handler) handleUpdateTarget(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	var req struct {
		Domain         *string            `json:"domain"` // when present, re-scopes the target (kind re-detected)
		Name           *string            `json:"name"`
		Description    *string            `json:"description"`
		Tags           *[]string          `json:"tags"`
		Priority       *string            `json:"priority"`
		Notes          *string            `json:"notes"`
		ExcludeScope   *string            `json:"exclude_scope"`
		EnabledModules *[]string          `json:"enabled_modules"`
		ScanUserAgent  *string            `json:"scan_user_agent"`
		ScanHeaders    *map[string]string `json:"scan_headers"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// This endpoint is consumed as Partial<Target>. Load the current row first so
	// omitted fields stay untouched; the old zero-value decoding silently erased
	// enabled_modules (and, for API clients, metadata/identity) on unrelated edits.
	var name, description, tagsJSON, priority, notes, excludeScope, modulesJSON, scanUserAgent, scanHeadersJSON string
	err := h.db.QueryRowContext(r.Context(), `SELECT COALESCE(name,''),COALESCE(description,''),COALESCE(tags,'[]'),
		COALESCE(priority,'medium'),COALESCE(notes,''),COALESCE(exclude_scope,''),COALESCE(enabled_modules,'[]'),
		COALESCE(scan_user_agent,''),COALESCE(scan_headers,'{}') FROM targets WHERE id=?`, id).
		Scan(&name, &description, &tagsJSON, &priority, &notes, &excludeScope, &modulesJSON, &scanUserAgent, &scanHeadersJSON)
	if err == sql.ErrNoRows {
		h.writeError(w, http.StatusNotFound, "target not found")
		return
	}
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to load target")
		return
	}
	if req.Name != nil {
		name = strings.TrimSpace(*req.Name)
	}
	if req.Description != nil {
		description = *req.Description
	}
	if req.Tags != nil {
		tagsJSON = models.StringSliceToJSON(*req.Tags)
	}
	if req.Priority != nil {
		priority = *req.Priority
	}
	if req.Notes != nil {
		notes = *req.Notes
	}
	if req.ExcludeScope != nil {
		excludeScope = strings.TrimSpace(*req.ExcludeScope)
	}
	if req.EnabledModules != nil {
		modulesJSON = models.StringSliceToJSON(*req.EnabledModules)
	}
	var scanHeaders map[string]string
	if json.Unmarshal([]byte(scanHeadersJSON), &scanHeaders) != nil || scanHeaders == nil {
		scanHeaders = map[string]string{}
	}
	if req.ScanUserAgent != nil {
		scanUserAgent = *req.ScanUserAgent
	}
	if req.ScanHeaders != nil {
		scanHeaders = *req.ScanHeaders
	}
	scanUserAgent, _, scanHeadersJSON, err = normalizeScanIdentity(scanUserAgent, scanHeaders)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	rawScope := ""
	if req.Domain != nil {
		rawScope = strings.TrimSpace(*req.Domain)
		if rawScope == "" {
			h.writeError(w, http.StatusBadRequest, "domain/scope cannot be empty")
			return
		}
	}
	var scopeValues []string
	var kind, domain string
	if rawScope != "" {
		scopeValues, err = normalizeScopeValues(rawScope)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		webHosts, netScope := scanner.SplitScope(strings.Join(scopeValues, ","))
		switch {
		case len(webHosts) > 0 && netScope != "":
			kind = "mixed"
		case netScope != "":
			kind = "network"
		default:
			kind = "web"
		}
		if kind == "web" {
			domain = strings.Join(webHosts, ",")
		} else {
			domain = strings.Join(scopeValues, ",")
		}
	}

	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to update target")
		return
	}
	defer tx.Rollback()
	// Metadata, compliance identity and managed asset changes are one transaction;
	// a uniqueness conflict can no longer leave a half-updated project.
	res, err := tx.ExecContext(r.Context(), `
		UPDATE targets SET
			name = ?, description = ?, tags = ?, priority = ?, notes = ?,
			exclude_scope = ?, enabled_modules = ?, scan_user_agent = ?, scan_headers = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, name, description, tagsJSON, priority, notes, excludeScope, modulesJSON, scanUserAgent, scanHeadersJSON, id)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to update target")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		h.writeError(w, http.StatusNotFound, "target not found")
		return
	}
	if rawScope != "" {
		if _, err := tx.ExecContext(r.Context(), `UPDATE targets SET domain = ?, kind = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
			domain, kind, id); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				h.writeError(w, http.StatusConflict, "another target already uses that scope")
				return
			}
			h.writeError(w, http.StatusInternalServerError, "failed to update scope")
			return
		}
		if err := reconcileManualAssetsTx(tx, id, scopeValues); err != nil {
			h.writeError(w, http.StatusInternalServerError, "failed to reconcile managed assets")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to update target")
		return
	}

	h.hub.Broadcast("target_updated", map[string]string{"id": id})
	h.writeSuccess(w, map[string]string{"message": "updated"})
}

// deleteTargetByID cancels a target's in-flight scan and removes the target plus
// every row that belongs to it. Shared by the single- and bulk-delete handlers so
// both paths clean up identically (no orphaned evidence/objects on older DBs).
func (h *Handler) deleteTargetByID(id string) error {
	var exists int
	if err := h.db.QueryRow(`SELECT 1 FROM targets WHERE id=?`, id).Scan(&exists); err != nil {
		return err
	}
	// Cancel any running/pending scan for this target FIRST, so its goroutine
	// stops immediately instead of finishing in the background (and pinging
	// Telegram an hour later). Then delete — the FK cascade removes all related
	// rows (subdomains, http_services, findings, tasks, logs, screenshots…).
	if h.sched != nil {
		h.sched.CancelTasksForTarget(id)
	}
	tx, err := h.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// The v3/v4 tables (evidence, http_interactions, objects) were created without
	// a FK, so the cascade won't reach them — delete explicitly to avoid orphans.
	// (actions/object_relationships/workflow_variables DO cascade, but deleting
	// them here too is harmless and keeps behaviour uniform on older DBs.)
	for _, t := range []string{"evidence", "http_interactions", "objects", "actions", "object_relationships", "workflow_variables"} {
		if _, err := tx.Exec("DELETE FROM "+t+" WHERE target_id = ?", id); err != nil {
			return err
		}
	}

	res, err := tx.Exec("DELETE FROM targets WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if h.hub != nil {
		h.hub.Broadcast("target_deleted", map[string]string{"id": id})
	}
	return nil
}

func (h *Handler) handleDeleteTarget(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := h.deleteTargetByID(id); err != nil {
		if err == sql.ErrNoRows {
			h.writeError(w, http.StatusNotFound, "target not found")
			return
		}
		h.writeError(w, http.StatusInternalServerError, "failed to delete target")
		return
	}
	h.writeSuccess(w, map[string]string{"message": "deleted"})
}

// handleBulkDeleteTarget deletes many targets in one request — the backend for
// the multi-select "delete selected" action on the Web/Network target lists.
// Each id is removed with the same full cleanup as a single delete; ids that
// fail (already gone, etc.) are counted but never abort the batch, so one bad id
// can't strand the rest.
func (h *Handler) handleBulkDeleteTarget(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.IDs) == 0 {
		h.writeError(w, http.StatusBadRequest, "no target ids provided")
		return
	}
	// Per-user isolation: a member may bulk-delete only their own targets; an
	// admin may delete any. Non-owned ids are refused (counted as failed), never
	// silently touched.
	uid, isAdmin := h.callerScope(r)
	deleted, failed := 0, 0
	for _, id := range req.IDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if !isAdmin {
			if owner, ok := h.targetOwnerID(id); !ok || owner != uid {
				failed++
				continue
			}
		}
		if err := h.deleteTargetByID(id); err != nil {
			failed++
			continue
		}
		deleted++
	}
	h.writeSuccess(w, map[string]any{"deleted": deleted, "failed": failed, "requested": len(req.IDs)})
}

func (h *Handler) handleUpdateMonitor(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	var req struct {
		Enabled       bool `json:"monitor_enabled"`
		IntervalHours int  `json:"monitor_interval_hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.IntervalHours <= 0 {
		req.IntervalHours = 24
	}

	enabled := 0
	if req.Enabled {
		enabled = 1
	}

	res, err := h.db.Exec(
		`UPDATE targets SET monitor_last_run=CASE
			WHEN ?=1 AND COALESCE(monitor_enabled,0)=0 THEN NULL ELSE monitor_last_run END,
			monitor_enabled=?, monitor_interval_hours=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		enabled, enabled, req.IntervalHours, id,
	)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to update monitor settings")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		h.writeError(w, http.StatusNotFound, "target not found")
		return
	}
	if h.hub != nil {
		h.hub.Broadcast("target_updated", map[string]string{"id": id})
	}
	h.writeSuccess(w, map[string]any{"monitor_enabled": req.Enabled, "monitor_interval_hours": req.IntervalHours})
}

// handleSetAuth stores per-target authentication headers (Cookie, Authorization,
// custom) as a JSON map. These are attached to every active-scan request so the
// scanner can test pages behind a login.
func (h *Handler) handleSetAuth(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var req struct {
		AuthHeaders map[string]string `json:"auth_headers"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	raw := "{}"
	if len(req.AuthHeaders) > 0 {
		b, _ := json.Marshal(req.AuthHeaders)
		raw = string(b)
	}
	if _, err := h.db.Exec(`UPDATE targets SET auth_headers=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, raw, id); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to save auth headers")
		return
	}
	h.writeSuccess(w, map[string]any{"auth_headers": req.AuthHeaders})
}

// ── Identities (P0-1): multiple test users per target for cross-identity BOLA ──

func (h *Handler) handleListIdentities(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	rows, err := h.db.Query(`SELECT id, label, role, COALESCE(is_baseline,0), COALESCE(status,'unknown'),
	   COALESCE(auth_method,'headers'), COALESCE(last_verified_at,'') FROM identities WHERE target_id=? ORDER BY is_baseline DESC, created_at ASC`, id)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	type ident struct {
		ID           string `json:"id"`
		Label        string `json:"label"`
		Role         string `json:"role"`
		IsBaseline   bool   `json:"is_baseline"`
		Status       string `json:"status"`
		AuthMethod   string `json:"auth_method"`
		LastVerified string `json:"last_verified_at"`
	}
	out := []ident{}
	for rows.Next() {
		var it ident
		var base int
		if rows.Scan(&it.ID, &it.Label, &it.Role, &base, &it.Status, &it.AuthMethod, &it.LastVerified) == nil {
			it.IsBaseline = base != 0
			out = append(out, it)
		}
	}
	h.writeSuccess(w, out)
}

// handleListEvidence returns the structured, redacted evidence rows for a
// finding (Phase 7). Values are already redacted at write time.
func (h *Handler) handleListEvidence(w http.ResponseWriter, r *http.Request) {
	fid := mux.Vars(r)["fid"]
	rows, err := h.db.Query(`SELECT identity_label, request_text, response_text, comparison, note, COALESCE(image,''), created_at
	   FROM evidence WHERE finding_id=? ORDER BY created_at ASC`, fid)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	type ev struct {
		IdentityLabel string `json:"identity_label"`
		Request       string `json:"request"`
		Response      string `json:"response"`
		Comparison    string `json:"comparison"`
		Note          string `json:"note"`
		Image         string `json:"image"`
		CreatedAt     string `json:"created_at"`
	}
	out := []ev{}
	for rows.Next() {
		var e ev
		if rows.Scan(&e.IdentityLabel, &e.Request, &e.Response, &e.Comparison, &e.Note, &e.Image, &e.CreatedAt) == nil {
			out = append(out, e)
		}
	}
	h.writeSuccess(w, out)
}

func (h *Handler) handleCreateIdentity(w http.ResponseWriter, r *http.Request) {
	targetID := mux.Vars(r)["id"]
	var req struct {
		Label            string            `json:"label"`
		Role             string            `json:"role"`
		Headers          map[string]string `json:"headers"`
		Storage          map[string]string `json:"storage"`
		AuthMethod       string            `json:"auth_method"`
		Origin           string            `json:"origin"`
		UserAgent        string            `json:"user_agent"`
		ValidationURL    string            `json:"validation_url"`
		ValidationSignal string            `json:"validation_signal"`
		IsBaseline       bool              `json:"is_baseline"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Headers) == 0 {
		h.writeError(w, http.StatusBadRequest, "need headers (Cookie/Authorization/…)")
		return
	}
	if req.Label == "" {
		req.Label = "user"
	}
	if req.Role == "" {
		req.Role = "user"
	}
	if req.AuthMethod == "" {
		req.AuthMethod = "headers"
	}
	// Only one baseline per target.
	if req.IsBaseline {
		_, _ = h.db.Exec(`UPDATE identities SET is_baseline=0 WHERE target_id=?`, targetID)
	}
	// Encrypt credentials at rest (Phase 1 / Phase 11).
	box := secret.New(h.cfg.SessionSecret)
	hb, _ := json.Marshal(req.Headers)
	encHeaders := box.Encrypt(string(hb))
	encStorage := ""
	if len(req.Storage) > 0 {
		sb, _ := json.Marshal(req.Storage)
		encStorage = box.Encrypt(string(sb))
	}
	newID := uuid.New().String()
	base := 0
	if req.IsBaseline {
		base = 1
	}
	if _, err := h.db.Exec(
		`INSERT INTO identities (id, target_id, label, role, headers_json, is_baseline,
		   auth_method, origin, user_agent, storage_json, validation_url, validation_signal, status, captured_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?, 'unknown', CURRENT_TIMESTAMP)`,
		newID, targetID, req.Label, req.Role, encHeaders, base,
		req.AuthMethod, req.Origin, req.UserAgent, encStorage, req.ValidationURL, req.ValidationSignal); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to save identity")
		return
	}
	h.writeSuccess(w, map[string]any{"id": newID})
}

// handleImportSession ingests a browser-exported Playwright/Chrome storageState
// JSON, scopes it to the target origin, and saves it as an encrypted identity.
// This is the everywhere-works capture path (Phase 1/2, import mode).
func (h *Handler) handleImportSession(w http.ResponseWriter, r *http.Request) {
	targetID := mux.Vars(r)["id"]
	var req struct {
		Label            string `json:"label"`
		Role             string `json:"role"`
		Origin           string `json:"origin"`
		StorageState     string `json:"storage_state"`
		ValidationURL    string `json:"validation_url"`
		ValidationSignal string `json:"validation_signal"`
		IsBaseline       bool   `json:"is_baseline"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Origin == "" || req.StorageState == "" {
		h.writeError(w, http.StatusBadRequest, "need origin and storage_state JSON")
		return
	}
	cc, err := browser.ParseStorageState([]byte(req.StorageState), req.Origin)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Label == "" {
		req.Label = "user"
	}
	if req.Role == "" {
		req.Role = "user"
	}
	if req.IsBaseline {
		_, _ = h.db.Exec(`UPDATE identities SET is_baseline=0 WHERE target_id=?`, targetID)
	}
	box := secret.New(h.cfg.SessionSecret)
	hb, _ := json.Marshal(cc.Headers())
	encHeaders := box.Encrypt(string(hb))
	encStorage := ""
	if len(cc.LocalStorage) > 0 {
		sb, _ := json.Marshal(cc.LocalStorage)
		encStorage = box.Encrypt(string(sb))
	}
	base := 0
	if req.IsBaseline {
		base = 1
	}
	newID := uuid.New().String()
	if _, err := h.db.Exec(
		`INSERT INTO identities (id, target_id, label, role, headers_json, is_baseline,
		   auth_method, origin, user_agent, storage_json, validation_url, validation_signal, status, captured_at)
		 VALUES (?,?,?,?,?,?, 'browser-capture', ?,?,?,?,?, 'unknown', CURRENT_TIMESTAMP)`,
		newID, targetID, req.Label, req.Role, encHeaders, base,
		req.Origin, cc.UserAgent, encStorage, req.ValidationURL, req.ValidationSignal); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to save identity")
		return
	}
	h.writeSuccess(w, map[string]any{"id": newID, "cookies_captured": cc.CookieHeader != "", "localstorage_keys": len(cc.LocalStorage)})
}

// handleReplay replays a researcher-specified request under one or all identities
// (Phase 7). Bodies returned are redacted + truncated.
func (h *Handler) handleReplay(w http.ResponseWriter, r *http.Request) {
	targetID := mux.Vars(r)["id"]
	var req struct {
		Method      string `json:"method"`
		URL         string `json:"url"`
		Body        string `json:"body"`
		ContentType string `json:"content_type"`
		IdentityID  string `json:"identity_id"` // "" or "all" = every identity + unauth
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" {
		h.writeError(w, http.StatusBadRequest, "need url")
		return
	}
	if !h.inScope(targetID, req.URL) {
		h.writeError(w, http.StatusForbidden, "url is out of this target's scope — replay is restricted to the target domain / identity origins to prevent leaking captured sessions")
		return
	}
	spec := scanner.ReplaySpec{Method: req.Method, URL: req.URL, Body: req.Body, ContentType: req.ContentType}
	scanCtx := scanner.WithTargetRequestIdentity(r.Context(), h.db, h.cfg, targetID)
	ids := scanner.LoadIdentities(scanCtx, h.db, targetID, secret.New(h.cfg.SessionSecret))
	if req.IdentityID != "" && req.IdentityID != "all" {
		for i := range ids {
			if ids[i].ID == req.IdentityID {
				res := scanner.Replay(scanCtx, spec, &ids[i])
				h.writeSuccess(w, map[string]any{"results": []scanner.ReplayResult{res}})
				return
			}
		}
		h.writeError(w, http.StatusNotFound, "identity not found")
		return
	}
	results, comparison := scanner.ReplayAcrossIdentities(scanCtx, spec, ids)
	h.writeSuccess(w, map[string]any{"results": results, "comparison": comparison})
}

// handleListObjects returns discovered application resources (Phase 8).
func (h *Handler) handleListObjects(w http.ResponseWriter, r *http.Request) {
	targetID := mux.Vars(r)["id"]
	// Refresh from any newly-recorded traffic first.
	scanner.DiscoverObjectsFromTraffic(r.Context(), h.db, targetID)
	rows, err := h.db.Query(`SELECT obj_type, identifier, endpoint_template, param, owner_identity, source_url
	   FROM objects WHERE target_id=? ORDER BY endpoint_template, identifier LIMIT 1000`, targetID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	type obj struct {
		Type     string `json:"type"`
		ID       string `json:"identifier"`
		Endpoint string `json:"endpoint"`
		Param    string `json:"param"`
		Owner    string `json:"owner"`
		Source   string `json:"source_url"`
	}
	out := []obj{}
	for rows.Next() {
		var o obj
		if rows.Scan(&o.Type, &o.ID, &o.Endpoint, &o.Param, &o.Owner, &o.Source) == nil {
			out = append(out, o)
		}
	}
	h.writeSuccess(w, out)
}

// handleIngestTraffic ingests authenticated HTTP traffic observed in the
// researcher's browser (Phase 5) into the Request Intelligence layer.
func (h *Handler) handleIngestTraffic(w http.ResponseWriter, r *http.Request) {
	targetID := mux.Vars(r)["id"]
	var req struct {
		IdentityLabel string `json:"identity_label"`
		IdentityID    string `json:"identity_id"`
		Items         []struct {
			Method string `json:"method"`
			URL    string `json:"url"`
			Status int    `json:"status"`
			CT     string `json:"content_type"`
			Len    int    `json:"length"`
			Body   string `json:"body"` // OPTIONAL, used transiently for semantics — NOT persisted
		} `json:"items"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	ctx := r.Context()
	actions := 0
	for _, it := range req.Items {
		scanner.RecordInteraction(ctx, h.db, targetID,
			scanner.CanonRequest{Method: it.Method, URL: it.URL, IdentityLabel: req.IdentityLabel, Scanner: "browser-capture"},
			scanner.CanonResponse{Status: it.Status, CT: it.CT, Len: it.Len})

		// Semantic layer (Phase 2/4/6): classify the action, derive ownership,
		// extract reusable variables. The raw body is used ONLY here and never
		// stored — we persist only the derived, non-sensitive facts.
		a := scanner.ClassifyAction(it.Method, it.URL, it.Body, it.Status)
		scanner.StoreAction(ctx, h.db, targetID, req.IdentityID, req.IdentityLabel, "browser-capture", a)
		actions++
		for _, rel := range scanner.DeriveRelationships(a, it.Body, req.IdentityLabel) {
			scanner.StoreRelationship(ctx, h.db, targetID, rel)
		}
		if a.Verb == scanner.VerbCreate && it.Body != "" {
			for _, v := range scanner.ExtractVariables(it.Body, a.ObjectType, req.IdentityLabel, it.URL) {
				scanner.StoreVariable(ctx, h.db, targetID, "", v)
			}
		}
	}
	n := scanner.DiscoverObjectsFromTraffic(ctx, h.db, targetID)
	h.writeSuccess(w, map[string]any{"ingested": len(req.Items), "objects_found": n, "actions": actions})
}

// inScope loads the target domain + identity origins and checks every URL is a
// legitimate testing target — preventing a captured session from being replayed
// at an attacker-controlled or internal host (SSRF / credential exfiltration).
func (h *Handler) inScope(targetID string, urls ...string) bool {
	var domain string
	_ = h.db.QueryRow(`SELECT domain FROM targets WHERE id=?`, targetID).Scan(&domain)
	var origins []string
	if rows, err := h.db.Query(`SELECT COALESCE(origin,'') FROM identities WHERE target_id=?`, targetID); err == nil {
		for rows.Next() {
			var o string
			if rows.Scan(&o) == nil && o != "" {
				origins = append(origins, o)
			}
		}
		rows.Close()
	}
	for _, u := range urls {
		if u == "" {
			continue
		}
		if !scanner.URLInScope(domain, origins, u) {
			return false
		}
	}
	return true
}

// handleRunWorkflow executes a researcher-defined multi-step workflow with
// variable propagation across identities (deterministic). Flags a step that was
// expected denied but succeeded as a workflow authorization bypass finding.
func (h *Handler) handleRunWorkflow(w http.ResponseWriter, r *http.Request) {
	targetID := mux.Vars(r)["id"]
	var req struct {
		Steps []scanner.WorkflowStep `json:"steps"`
		Seed  map[string]string      `json:"seed"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Steps) == 0 {
		h.writeError(w, http.StatusBadRequest, "need steps")
		return
	}
	stepURLs := make([]string, 0, len(req.Steps))
	for _, st := range req.Steps {
		stepURLs = append(stepURLs, st.URL)
	}
	if !h.inScope(targetID, stepURLs...) {
		h.writeError(w, http.StatusForbidden, "a workflow step url is out of target scope")
		return
	}
	scanCtx := scanner.WithTargetRequestIdentity(r.Context(), h.db, h.cfg, targetID)
	ids := scanner.LoadIdentities(scanCtx, h.db, targetID, secret.New(h.cfg.SessionSecret))
	res := h.sched.AuthzEngine().RunWorkflow(scanCtx, targetID, ids, req.Steps, req.Seed)
	h.writeSuccess(w, res)
}

// handleVerifyWrite runs the researcher-triggered state-snapshot verification of
// a WRITE/DELETE/BFLA hypothesis (P2). Destructive — explicit researcher action
// on an authorized target. Produces a finding only on a confirmed side effect.
func (h *Handler) handleVerifyWrite(w http.ResponseWriter, r *http.Request) {
	targetID := mux.Vars(r)["id"]
	var req struct {
		OwnerLabel    string `json:"owner_label"`
		AttackerLabel string `json:"attacker_label"`
		ObjectType    string `json:"object_type"`
		ObjectID      string `json:"object_id"`
		ReadURL       string `json:"read_url"`
		WriteMethod   string `json:"write_method"`
		WriteURL      string `json:"write_url"`
		WriteBody     string `json:"write_body"`
		ContentType   string `json:"content_type"`
		HypothesisID  string `json:"hypothesis_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ReadURL == "" || req.WriteURL == "" {
		h.writeError(w, http.StatusBadRequest, "need read_url and write_url")
		return
	}
	if !h.inScope(targetID, req.ReadURL, req.WriteURL) {
		h.writeError(w, http.StatusForbidden, "url out of target scope")
		return
	}
	scanCtx := scanner.WithTargetRequestIdentity(r.Context(), h.db, h.cfg, targetID)
	ids := scanner.LoadIdentities(scanCtx, h.db, targetID, secret.New(h.cfg.SessionSecret))
	res := h.sched.AuthzEngine().VerifyWrite(scanCtx, targetID, ids, scanner.WriteVerifySpec{
		OwnerLabel: req.OwnerLabel, AttackerLabel: req.AttackerLabel,
		ObjectType: req.ObjectType, ObjectID: req.ObjectID, ReadURL: req.ReadURL,
		WriteMethod: req.WriteMethod, WriteURL: req.WriteURL, WriteBody: req.WriteBody,
		ContentType: req.ContentType, HypothesisID: req.HypothesisID,
	})
	h.writeSuccess(w, res)
}

// handleListHypotheses returns the ranked authorization hypotheses + lifecycle
// (Phase 7) — the analyst's "what's worth testing / what was verified" view.
func (h *Handler) handleListHypotheses(w http.ResponseWriter, r *http.Request) {
	targetID := mux.Vars(r)["id"]
	rows, err := h.db.Query(`SELECT kind, identity_label, object_type, object_id, action_verb, endpoint_template,
	   expected, observed, status, confidence, test_plan, reason, COALESCE(finding_id,'')
	   FROM hypotheses WHERE target_id=? ORDER BY
	   CASE status WHEN 'VERIFIED' THEN 0 WHEN 'HYPOTHESIS' THEN 1 WHEN 'TESTED' THEN 2 ELSE 3 END, confidence DESC LIMIT 1000`, targetID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	type row struct {
		Kind       string `json:"kind"`
		Identity   string `json:"identity"`
		ObjectType string `json:"object_type"`
		ObjectID   string `json:"object_id"`
		Action     string `json:"action"`
		Endpoint   string `json:"endpoint"`
		Expected   string `json:"expected"`
		Observed   string `json:"observed"`
		Status     string `json:"status"`
		Confidence int    `json:"confidence"`
		TestPlan   string `json:"test_plan"`
		Reason     string `json:"reason"`
		FindingID  string `json:"finding_id"`
	}
	out := []row{}
	for rows.Next() {
		var x row
		if rows.Scan(&x.Kind, &x.Identity, &x.ObjectType, &x.ObjectID, &x.Action, &x.Endpoint,
			&x.Expected, &x.Observed, &x.Status, &x.Confidence, &x.TestPlan, &x.Reason, &x.FindingID) == nil {
			out = append(out, x)
		}
	}
	h.writeSuccess(w, out)
}

// handleListFindingGroups returns findings collapsed by root cause (correlation):
// one root per (type + endpoint template) with its affected resource count.
func (h *Handler) handleListFindingGroups(w http.ResponseWriter, r *http.Request) {
	targetID := mux.Vars(r)["id"]
	scanner.CorrelateFindings(r.Context(), h.db, targetID)
	rows, err := h.db.Query(`
		SELECT correlation_key, COUNT(*) AS members,
		       MAX(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS sev,
		       (SELECT type FROM vuln_findings v2 WHERE v2.target_id=vf.target_id AND v2.correlation_key=vf.correlation_key LIMIT 1) AS type,
		       (SELECT evidence FROM vuln_findings v3 WHERE v3.id=vf.root_finding_id) AS root_evidence,
		       MAX(COALESCE(confidence,0))
		FROM vuln_findings vf
		WHERE target_id=? AND correlation_key<>'' AND COALESCE(status,'finding')='finding'
		GROUP BY correlation_key ORDER BY sev DESC, members DESC LIMIT 500`, targetID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	sevName := map[int]string{4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
	type grp struct {
		Key          string `json:"key"`
		Type         string `json:"type"`
		Severity     string `json:"severity"`
		Members      int    `json:"affected_count"`
		Confidence   int    `json:"confidence"`
		RootEvidence string `json:"root_evidence"`
	}
	out := []grp{}
	for rows.Next() {
		var g grp
		var sev int
		if rows.Scan(&g.Key, &g.Members, &sev, &g.Type, &g.RootEvidence, &g.Confidence) == nil {
			g.Severity = sevName[sev]
			out = append(out, g)
		}
	}
	h.writeSuccess(w, out)
}

// handleWorkflowGraph returns the analyst workflow graph (identities, objects,
// ownership + action edges).
func (h *Handler) handleWorkflowGraph(w http.ResponseWriter, r *http.Request) {
	targetID := mux.Vars(r)["id"]
	h.writeSuccess(w, scanner.BuildWorkflowGraph(r.Context(), h.db, targetID))
}

// handleListObservations returns the raw authorization observations (Phase 1/2).
func (h *Handler) handleListObservations(w http.ResponseWriter, r *http.Request) {
	targetID := mux.Vars(r)["id"]
	rows, err := h.db.Query(`SELECT identity_label, object_type, object_id, action_verb, expected, observed, confidence
	   FROM authorization_observations WHERE target_id=? ORDER BY created_at DESC LIMIT 2000`, targetID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	type ob struct {
		Identity   string `json:"identity"`
		ObjectType string `json:"object_type"`
		ObjectID   string `json:"object_id"`
		Action     string `json:"action"`
		Expected   string `json:"expected"`
		Observed   string `json:"observed"`
		Confidence int    `json:"confidence"`
	}
	out := []ob{}
	for rows.Next() {
		var x ob
		if rows.Scan(&x.Identity, &x.ObjectType, &x.ObjectID, &x.Action, &x.Expected, &x.Observed, &x.Confidence) == nil {
			out = append(out, x)
		}
	}
	h.writeSuccess(w, out)
}

// handleListRelationships returns Object Ownership 2.0 relationships (Phase 6).
func (h *Handler) handleListRelationships(w http.ResponseWriter, r *http.Request) {
	targetID := mux.Vars(r)["id"]
	rows, err := h.db.Query(`SELECT object_type, object_id, endpoint_template, identity_label, role, provenance
	   FROM object_relationships WHERE target_id=? ORDER BY object_type, object_id,
	   CASE role WHEN 'CREATOR' THEN 0 WHEN 'OWNER' THEN 1 WHEN 'ADMIN' THEN 2 ELSE 9 END LIMIT 2000`, targetID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	type rel struct {
		ObjectType string `json:"object_type"`
		ObjectID   string `json:"object_id"`
		Endpoint   string `json:"endpoint"`
		Identity   string `json:"identity"`
		Role       string `json:"role"`
		Provenance string `json:"provenance"`
	}
	out := []rel{}
	for rows.Next() {
		var x rel
		if rows.Scan(&x.ObjectType, &x.ObjectID, &x.Endpoint, &x.Identity, &x.Role, &x.Provenance) == nil {
			out = append(out, x)
		}
	}
	h.writeSuccess(w, out)
}

// handleListActions returns classified actions (Phase 2) for the analyst view.
func (h *Handler) handleListActions(w http.ResponseWriter, r *http.Request) {
	targetID := mux.Vars(r)["id"]
	rows, err := h.db.Query(`SELECT identity_label, verb, method, url, object_type, object_id, status, created_at
	   FROM actions WHERE target_id=? ORDER BY created_at DESC LIMIT 1000`, targetID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	type act struct {
		Identity   string `json:"identity"`
		Verb       string `json:"verb"`
		Method     string `json:"method"`
		URL        string `json:"url"`
		ObjectType string `json:"object_type"`
		ObjectID   string `json:"object_id"`
		Status     int    `json:"status"`
		CreatedAt  string `json:"created_at"`
	}
	out := []act{}
	for rows.Next() {
		var x act
		if rows.Scan(&x.Identity, &x.Verb, &x.Method, &x.URL, &x.ObjectType, &x.ObjectID, &x.Status, &x.CreatedAt) == nil {
			out = append(out, x)
		}
	}
	h.writeSuccess(w, out)
}

// handleValidateIdentity checks whether a stored identity's session is still
// authenticated (Phase 4) and persists the verdict + timestamp.
func (h *Handler) handleValidateIdentity(w http.ResponseWriter, r *http.Request) {
	targetID := mux.Vars(r)["id"]
	iid := mux.Vars(r)["iid"]
	scanCtx := scanner.WithTargetRequestIdentity(r.Context(), h.db, h.cfg, targetID)
	ids := scanner.LoadIdentities(scanCtx, h.db, targetID, secret.New(h.cfg.SessionSecret))
	var target *scanner.Identity
	for i := range ids {
		if ids[i].ID == iid {
			target = &ids[i]
			break
		}
	}
	if target == nil {
		h.writeError(w, http.StatusNotFound, "identity not found")
		return
	}
	status := scanner.ValidateSession(scanCtx, *target)
	_, _ = h.db.Exec(`UPDATE identities SET status=?, last_verified_at=CURRENT_TIMESTAMP WHERE id=?`, status, iid)
	h.writeSuccess(w, map[string]string{"status": status})
}

func (h *Handler) handleDeleteIdentity(w http.ResponseWriter, r *http.Request) {
	iid := mux.Vars(r)["iid"]
	if _, err := h.db.Exec(`DELETE FROM identities WHERE id=?`, iid); err != nil {
		h.writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	h.writeSuccess(w, map[string]string{"status": "deleted"})
}

func (h *Handler) handleStartScan(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	var req struct {
		Modules  []string `json:"modules"`
		Priority int      `json:"priority"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Modules = scheduler.AllModules
		req.Priority = 5
	}

	if req.Priority == 0 {
		req.Priority = 5
	}

	if err := h.requireIDORIdentities(id, req.Modules); err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	task, err := h.sched.CreateTask(id, req.Modules, req.Priority)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to create task")
		return
	}

	h.writeJSON(w, http.StatusCreated, map[string]any{"data": task, "success": true})
}

// requireIDORIdentities enforces the mandatory two-identity rule: cross-identity
// IDOR/BOLA testing is impossible to PROVE without a victim (User A) and an
// attacker (User B) session, so a scan that includes the idor module is rejected
// until two identities (session tokens or cookies) are configured on the target.
// This is what makes the IDOR result trustworthy instead of a single-account guess.
func (h *Handler) requireIDORIdentities(targetID string, modules []string) error {
	wants := false
	for _, m := range modules {
		if strings.EqualFold(strings.TrimSpace(m), "idor") {
			wants = true
			break
		}
	}
	if !wants {
		return nil
	}
	var n int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM identities WHERE target_id = ?`, targetID).Scan(&n)
	if n < 2 {
		return fmt.Errorf("IDOR/BOLA testing requires two identities (User A + User B). Add two sets of session tokens or cookies on the target before starting a scan with the IDOR module — currently configured: %d", n)
	}
	return nil
}

func (h *Handler) handlePauseScan(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := h.sched.PauseTarget(id); err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.writeSuccess(w, map[string]string{"status": "paused"})
}

func (h *Handler) handleResumeScan(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := h.sched.ResumeTarget(id); err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.writeSuccess(w, map[string]string{"status": "running"})
}

// handleSkipPhase aborts only the currently-running scan phase and lets the scan
// continue to the next one — the operator's "this phase is stuck / too slow / skip
// it" control, distinct from pause (waits) and cancel (stops the whole scan).
func (h *Handler) handleSkipPhase(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := h.sched.SkipCurrentPhase(id); err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.writeSuccess(w, map[string]string{"status": "phase_skipped"})
}

// handleCancelScan stops the target's ENTIRE running scan (all remaining phases),
// the hard-stop companion to skip-phase. Idempotent: cancelling when nothing runs
// is a no-op success.
func (h *Handler) handleCancelScan(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	h.sched.CancelTasksForTarget(id)
	h.writeSuccess(w, map[string]string{"status": "cancelled"})
}

func (h *Handler) handleTargetStats(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	stats := struct {
		Subdomains          int `json:"subdomains"`
		AliveHosts          int `json:"alive_hosts"`
		HTTPServices        int `json:"http_services"`
		JSFiles             int `json:"js_files"`
		JSFindings          int `json:"js_findings"`
		Parameters          int `json:"parameters"`
		ReflectedParameters int `json:"reflected_parameters"`
		DirectoryFindings   int `json:"directory_findings"`
		BackupFindings      int `json:"backup_findings"`
		OpenRedirects       int `json:"open_redirects"`
		NucleiFindings      int `json:"nuclei_findings"`
		CriticalFindings    int `json:"critical_findings"`
		HighFindings        int `json:"high_findings"`
		MediumFindings      int `json:"medium_findings"`
		LowFindings         int `json:"low_findings"`
	}{}

	queries := []struct {
		dest  *int
		query string
		args  []any
	}{
		{&stats.Subdomains, "SELECT COUNT(*) FROM subdomains WHERE target_id = ?", []any{id}},
		{&stats.AliveHosts, "SELECT COUNT(*) FROM subdomains WHERE target_id = ? AND is_alive = 1", []any{id}},
		{&stats.HTTPServices, "SELECT COUNT(*) FROM http_services WHERE target_id = ?", []any{id}},
		{&stats.JSFiles, "SELECT COUNT(*) FROM js_files WHERE target_id = ?", []any{id}},
		{&stats.JSFindings, "SELECT COUNT(*) FROM js_findings WHERE target_id = ?", []any{id}},
		{&stats.Parameters, "SELECT COUNT(*) FROM parameters WHERE target_id = ?", []any{id}},
		{&stats.ReflectedParameters, "SELECT COUNT(*) FROM parameters WHERE target_id = ? AND is_reflected = 1", []any{id}},
		{&stats.DirectoryFindings, "SELECT COUNT(*) FROM directory_findings WHERE target_id = ?", []any{id}},
		{&stats.BackupFindings, "SELECT COUNT(*) FROM backup_findings WHERE target_id = ?", []any{id}},
		{&stats.OpenRedirects, "SELECT COUNT(*) FROM open_redirect_findings WHERE target_id = ? AND COALESCE(status,'finding') = 'finding'", []any{id}},
		{&stats.NucleiFindings, "SELECT COUNT(*) FROM nuclei_findings WHERE target_id = ? AND COALESCE(verification,'unverified') != 'rejected'", []any{id}},
		{&stats.CriticalFindings, "SELECT COUNT(*) FROM nuclei_findings WHERE target_id = ? AND severity = 'critical' AND COALESCE(verification,'unverified') != 'rejected'", []any{id}},
		{&stats.HighFindings, "SELECT COUNT(*) FROM nuclei_findings WHERE target_id = ? AND severity = 'high' AND COALESCE(verification,'unverified') != 'rejected'", []any{id}},
		{&stats.MediumFindings, "SELECT COUNT(*) FROM nuclei_findings WHERE target_id = ? AND severity = 'medium' AND COALESCE(verification,'unverified') != 'rejected'", []any{id}},
		{&stats.LowFindings, "SELECT COUNT(*) FROM nuclei_findings WHERE target_id = ? AND severity = 'low' AND COALESCE(verification,'unverified') != 'rejected'", []any{id}},
	}

	for _, q := range queries {
		h.db.QueryRowContext(r.Context(), q.query, q.args...).Scan(q.dest)
	}

	h.writeSuccess(w, stats)
}

func (h *Handler) handleImportTargets(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(10 << 20)
	file, header, err := r.FormFile("file")
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "file required")
		return
	}
	defer file.Close()

	var domains []string

	if strings.HasSuffix(header.Filename, ".csv") {
		reader := csv.NewReader(file)
		records, err := reader.ReadAll()
		if err != nil {
			h.writeError(w, http.StatusBadRequest, "invalid CSV")
			return
		}
		for _, record := range records {
			if len(record) > 0 && record[0] != "domain" {
				domains = append(domains, record[0])
			}
		}
	} else {
		var content strings.Builder
		buf := make([]byte, 1024)
		for {
			n, err := file.Read(buf)
			if n > 0 {
				content.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		for _, line := range strings.Split(content.String(), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				domains = append(domains, line)
			}
		}
	}

	created, invalid, duplicates := 0, 0, 0
	for _, rawScope := range domains {
		values, normalizeErr := normalizeScopeValues(rawScope)
		if normalizeErr != nil {
			invalid++
			continue
		}
		domain := strings.Join(values, ",")
		id := uuid.New().String()
		tx, beginErr := h.db.BeginTx(r.Context(), nil)
		if beginErr != nil {
			invalid++
			continue
		}
		res, insertErr := tx.ExecContext(r.Context(), `INSERT OR IGNORE INTO targets (id, domain, priority, kind, owner_id) VALUES (?, ?, 'medium', 'web', ?)`, id, domain, h.currentUserID(r))
		if insertErr != nil {
			tx.Rollback()
			invalid++
			continue
		}
		if n, _ := res.RowsAffected(); n == 0 {
			tx.Rollback()
			duplicates++
			continue
		}
		if err := reconcileManualAssetsTx(tx, id, values); err != nil || tx.Commit() != nil {
			tx.Rollback()
			invalid++
			continue
		}
		created++
	}

	h.writeSuccess(w, map[string]any{
		"imported":   created,
		"total":      len(domains),
		"invalid":    invalid,
		"duplicates": duplicates,
	})
}

// handleGenerateReport builds a HackerOne-style Markdown report from the
// target's high-signal findings — ready to paste and fill in. No key needed.
// markdownNetworkSections writes the network-only report sections (Ingram
// camera/DVR findings and the discovered services table) into the Markdown
// report. Reads existing DB rows so it also covers already-finished scans.
func (h *Handler) markdownNetworkSections(ctx context.Context, b *strings.Builder, id string) {
	// ── Cameras / DVRs (Ingram) ──
	crows, _ := h.db.QueryContext(ctx, `
		SELECT v.url, v.type, v.severity, COALESCE(v.evidence,''), COALESCE(v.parameter,''), COALESCE(e.image,'')
		FROM vuln_findings v
		LEFT JOIN evidence e ON e.finding_id = v.id AND e.kind = 'camera_poc'
		WHERE v.target_id = ? AND v.type LIKE 'ingram_%' AND COALESCE(v.status,'finding') = 'finding'
		ORDER BY (COALESCE(e.image,'') = '') ASC, v.url`, id)
	if crows != nil {
		type cam struct{ addr, typ, sev, desc, poc, image string }
		var cams []cam
		for crows.Next() {
			var c cam
			if crows.Scan(&c.addr, &c.typ, &c.sev, &c.desc, &c.poc, &c.image) == nil {
				cams = append(cams, c)
			}
		}
		crows.Close()
		if len(cams) > 0 {
			fmt.Fprintf(b, "## 📷 Cameras / DVRs (%d)\n\n", len(cams))
			for _, c := range cams {
				product := strings.TrimSpace(strings.ReplaceAll(strings.TrimPrefix(c.typ, "ingram_"), "_", " "))
				fmt.Fprintf(b, "### %s — %s\n\n", c.addr, product)
				fmt.Fprintf(b, "- **Severity:** %s\n", strings.ToUpper(c.sev))
				if c.poc != "" {
					fmt.Fprintf(b, "- **PoC:** `%s`\n", c.poc)
				}
				if c.desc != "" {
					fmt.Fprintf(b, "- **Detail:** %s\n", c.desc)
				}
				fmt.Fprintf(b, "- **Panel:** http://%s/\n", c.addr)
				if c.image != "" {
					fmt.Fprintf(b, "- **Snapshot:** %s\n", c.image)
				}
				b.WriteString("\n")
			}
			b.WriteString("---\n\n")
		}
	}

	// ── Discovered services ──
	srows, _ := h.db.QueryContext(ctx, `
		SELECT ip, port, COALESCE(NULLIF(service,''),'?'), TRIM(COALESCE(product,'') || ' ' || COALESCE(version,''))
		FROM network_services WHERE target_id = ? ORDER BY ip, port LIMIT 5000`, id)
	if srows != nil {
		type sv struct {
			ip            string
			port          int
			service, prod string
		}
		var svcs []sv
		for srows.Next() {
			var s sv
			if srows.Scan(&s.ip, &s.port, &s.service, &s.prod) == nil {
				svcs = append(svcs, s)
			}
		}
		srows.Close()
		if len(svcs) > 0 {
			fmt.Fprintf(b, "## 🔌 Discovered Services (%d)\n\n", len(svcs))
			b.WriteString("| Host:Port | Service | Product |\n|---|---|---|\n")
			for _, s := range svcs {
				fmt.Fprintf(b, "| %s:%d | %s | %s |\n", s.ip, s.port, s.service, mdCell(strings.TrimSpace(s.prod)))
			}
			b.WriteString("\n---\n\n")
		}
	}

	// ── Recovered access / credentials (brute-force + camera default logins) ──
	krows, _ := h.db.QueryContext(ctx, `
		SELECT url,
		       CASE WHEN type LIKE 'ingram_%' THEN REPLACE(SUBSTR(type,8),'_',' ') ELSE REPLACE(type,'_',' ') END,
		       severity, COALESCE(evidence,'')
		FROM vuln_findings
		WHERE target_id = ? AND (type LIKE '%weak_credentials%' OR type LIKE 'ingram_%')
		  AND COALESCE(status,'finding') = 'finding'
		ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, url`, id)
	if krows != nil {
		type cred struct{ url, kind, sev, ev string }
		var creds []cred
		for krows.Next() {
			var c cred
			if krows.Scan(&c.url, &c.kind, &c.sev, &c.ev) == nil {
				creds = append(creds, c)
			}
		}
		krows.Close()
		if len(creds) > 0 {
			fmt.Fprintf(b, "## 🔑 Recovered Access / Credentials (%d)\n\n", len(creds))
			b.WriteString("| Host:Port | Kind | Severity | Detail |\n|---|---|---|---|\n")
			for _, c := range creds {
				fmt.Fprintf(b, "| %s | %s | %s | %s |\n", c.url, mdCell(c.kind), strings.ToUpper(c.sev), mdCell(c.ev))
			}
			b.WriteString("\n---\n\n")
		}
	}

	// ── Backups / config files exposed on discovered web services ──
	brows, _ := h.db.QueryContext(ctx, `
		SELECT url, status_code, COALESCE(file_type,'') FROM backup_findings
		WHERE target_id = ? ORDER BY url LIMIT 2000`, id)
	if brows != nil {
		type bak struct {
			url, ftype string
			status     int
		}
		var baks []bak
		for brows.Next() {
			var x bak
			if brows.Scan(&x.url, &x.status, &x.ftype) == nil {
				baks = append(baks, x)
			}
		}
		brows.Close()
		if len(baks) > 0 {
			fmt.Fprintf(b, "## 🗄 Backups / Config Files (%d)\n\n", len(baks))
			b.WriteString("| URL | Status | Type |\n|---|---|---|\n")
			for _, x := range baks {
				fmt.Fprintf(b, "| %s | %d | %s |\n", x.url, x.status, mdCell(x.ftype))
			}
			b.WriteString("\n---\n\n")
		}
	}
}

func (h *Handler) handleGenerateReport(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	var domain, kind string
	h.db.QueryRowContext(r.Context(), "SELECT domain, COALESCE(kind,'web') FROM targets WHERE id = ?", id).Scan(&domain, &kind)
	if domain == "" {
		h.writeError(w, http.StatusNotFound, "target not found")
		return
	}

	var b strings.Builder
	if kind == "network" {
		fmt.Fprintf(&b, "# Network Report — %s\n\n", domain)
		// Network-specific sections first (cameras + services); the shared
		// vuln/nuclei sections below already include the network findings.
		h.markdownNetworkSections(r.Context(), &b, id)
	} else {
		fmt.Fprintf(&b, "# Recon Report — %s\n\n", domain)
	}

	// Correlation / attack-path section (intelligence layer) first.
	_, _, paths := h.buildGraph(r, id)
	if len(paths) > 0 {
		b.WriteString("## Attack Paths (correlated, ranked)\n\n")
		for i, p := range paths {
			if i >= 15 {
				break
			}
			fmt.Fprintf(&b, "### %d. [%s] %s (%d%% confidence)\n\n", i+1, strings.ToUpper(p.Severity), p.Summary, p.Confidence)
			if len(p.Tech) > 0 {
				fmt.Fprintf(&b, "_Stack: %s_\n\n", strings.Join(p.Tech, ", "))
			}
			for _, step := range p.Steps {
				fmt.Fprintf(&b, "- %s\n", step)
			}
			b.WriteString("\n")
		}
		b.WriteString("---\n\n## All Findings\n\n")
	}

	// Vuln findings (high/critical first).
	vrows, _ := h.db.QueryContext(r.Context(), `
		SELECT type, severity, url, parameter, payload, evidence FROM vuln_findings
		WHERE target_id = ? AND COALESCE(status,'finding')='finding'
		ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END
	`, id)
	if vrows != nil {
		for vrows.Next() {
			var typ, sev, url, param, payload, evidence string
			if vrows.Scan(&typ, &sev, &url, &param, &payload, &evidence) != nil {
				continue
			}
			fmt.Fprintf(&b, "## [%s] %s\n\n", strings.ToUpper(sev), strings.ToUpper(typ))
			fmt.Fprintf(&b, "**Summary:** %s vulnerability found on `%s`.\n\n", typ, url)
			b.WriteString("**Steps to Reproduce:**\n")
			fmt.Fprintf(&b, "1. Navigate to `%s`\n", url)
			// For XSS, always show a browser-ready payload that pops alert().
			if typ == "xss" || typ == "stored_xss" || typ == "dom_xss" {
				xp := payload
				if !containsXSSMarker(xp) {
					xp = `"><svg onload=alert(document.domain)>`
				}
				pocURL := url
				if param != "" {
					sep := "?"
					if strings.Contains(url, "?") {
						sep = "&"
					}
					pocURL = url + sep + param + "=" + xp
				}
				fmt.Fprintf(&b, "2. Open this URL in a browser — it pops `alert(document.domain)`:\n   `%s`\n", pocURL)
				fmt.Fprintf(&b, "3. Payload: `%s`\n", xp)
			} else {
				if param != "" {
					fmt.Fprintf(&b, "2. Inject the payload into the `%s` parameter\n", param)
				}
				if payload != "" {
					fmt.Fprintf(&b, "3. Payload: `%s`\n", payload)
				}
			}
			fmt.Fprintf(&b, "\n**Evidence:**\n```\n%s\n```\n\n", evidence)
			b.WriteString("**Impact:** _<describe the concrete impact>_\n\n")
			b.WriteString("**Suggested Fix:** _<remediation>_\n\n---\n\n")
		}
		vrows.Close()
	}

	// Nuclei findings.
	nrows, _ := h.db.QueryContext(r.Context(), `
		SELECT template_name, severity, matched_url, description FROM nuclei_findings
		WHERE target_id = ? AND severity IN ('critical','high','medium')
		  AND COALESCE(verification,'unverified') != 'rejected'
		ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END
	`, id)
	if nrows != nil {
		for nrows.Next() {
			var name, sev, url, desc string
			if nrows.Scan(&name, &sev, &url, &desc) != nil {
				continue
			}
			fmt.Fprintf(&b, "## [%s] %s\n\n", strings.ToUpper(sev), name)
			fmt.Fprintf(&b, "**URL:** `%s`\n\n%s\n\n---\n\n", url, desc)
		}
		nrows.Close()
	}

	// ── Recon sections (parity with the HTML report) ─────────────────────────
	h.mdReconSections(r, &b, id)

	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s-report.md", domain))
	w.Write([]byte(b.String()))
}

// mdReconSections appends all recon data (subdomains, hosts, JS findings grouped,
// params, redirects, directories, backups) to the Markdown report so it matches
// the HTML report.
func (h *Handler) mdReconSections(r *http.Request, b *strings.Builder, id string) {
	ctx := r.Context()
	rowsList := func(title, query string, cols int) {
		rows, err := h.db.QueryContext(ctx, query, id)
		if err != nil {
			return
		}
		defer rows.Close()
		fmt.Fprintf(b, "\n## %s\n\n", title)
		n := 0
		for rows.Next() {
			vals := make([]any, cols)
			ptrs := make([]any, cols)
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if rows.Scan(ptrs...) != nil {
				continue
			}
			parts := make([]string, cols)
			for i := range vals {
				parts[i] = mdCell(vals[i])
			}
			fmt.Fprintf(b, "- %s\n", strings.Join(parts, " · "))
			n++
		}
		if n == 0 {
			b.WriteString("_none_\n")
		}
	}

	// JS findings grouped by (type,value) with ×N.
	jrows, err := h.db.QueryContext(ctx, `
		SELECT jf.type, jf.value, COUNT(*) FROM js_findings jf
		WHERE jf.target_id=? GROUP BY jf.type, jf.value
		ORDER BY COUNT(*) DESC LIMIT 2000`, id)
	if err == nil {
		b.WriteString("\n## JS Findings (grouped)\n\n")
		n := 0
		for jrows.Next() {
			var typ, val string
			var cnt int
			if jrows.Scan(&typ, &val, &cnt) != nil {
				continue
			}
			if cnt > 1 {
				fmt.Fprintf(b, "- [%s] `%s` ×%d\n", typ, val, cnt)
			} else {
				fmt.Fprintf(b, "- [%s] `%s`\n", typ, val)
			}
			n++
		}
		jrows.Close()
		if n == 0 {
			b.WriteString("_none_\n")
		}
	}

	rowsList("Subdomains", `SELECT subdomain, CASE is_alive WHEN 1 THEN 'alive' ELSE '' END, COALESCE(ip,'') FROM subdomains WHERE target_id=? ORDER BY subdomain LIMIT 5000`, 3)
	rowsList("Live HTTP Hosts", `SELECT url, status_code, COALESCE(title,'') FROM http_services WHERE target_id=? AND COALESCE(source,'probe')='probe' ORDER BY url LIMIT 3000`, 3)
	rowsList("Reflected Parameters", `SELECT url, parameter FROM parameters WHERE target_id=? AND is_reflected=1 ORDER BY url LIMIT 2000`, 2)
	rowsList("Open Redirects", `SELECT url, redirect_to FROM open_redirect_findings WHERE target_id=? ORDER BY url`, 2)
	rowsList("Directories", `SELECT url, status_code FROM directory_findings WHERE target_id=? ORDER BY url LIMIT 3000`, 2)
	rowsList("Backups / Config Files", `SELECT url, COALESCE(file_type,'') FROM backup_findings WHERE target_id=? ORDER BY url LIMIT 2000`, 2)
}

func mdCell(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case []byte:
		return string(t)
	case string:
		return t
	case int64:
		return fmt.Sprintf("%d", t)
	default:
		return fmt.Sprintf("%v", t)
	}
}

func (h *Handler) handleExportTarget(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	var domain string
	h.db.QueryRowContext(r.Context(), "SELECT domain FROM targets WHERE id = ?", id).Scan(&domain)

	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s-findings.csv", domain))
		writer := csv.NewWriter(w)
		writer.Write([]string{"type", "url", "details"})

		rows, _ := h.db.QueryContext(r.Context(), "SELECT url, status_code FROM subdomains WHERE target_id = ?", id)
		if rows != nil {
			for rows.Next() {
				var url string
				var status int
				rows.Scan(&url, &status)
				writer.Write([]string{"subdomain", url, fmt.Sprintf("status=%d", status)})
			}
			rows.Close()
		}
		writer.Flush()

	default:
		export := map[string]any{"target": domain}

		rows, _ := h.db.QueryContext(r.Context(), "SELECT subdomain, ip FROM subdomains WHERE target_id = ?", id)
		if rows != nil {
			var subs []map[string]string
			for rows.Next() {
				var sub, ip string
				rows.Scan(&sub, &ip)
				subs = append(subs, map[string]string{"subdomain": sub, "ip": ip})
			}
			rows.Close()
			export["subdomains"] = subs
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s-export.json", domain))
		json.NewEncoder(w).Encode(export)
	}
}
