package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/recon-platform/internal/models"
	"github.com/recon-platform/internal/scanner"
	"github.com/recon-platform/internal/scheduler"
)

func normalizeAssetValue(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", fmt.Errorf("asset value is required")
	}
	if strings.Contains(v, "://") {
		if strings.ContainsAny(v, "\r\n\t ") {
			return "", fmt.Errorf("asset URLs cannot contain unescaped whitespace")
		}
		u, err := url.Parse(v)
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return "", fmt.Errorf("asset URL must use http or https and include a host")
		}
		u.Scheme = strings.ToLower(u.Scheme)
		host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
		if port := u.Port(); port != "" {
			u.Host = net.JoinHostPort(host, port)
		} else if strings.Contains(host, ":") {
			u.Host = "[" + host + "]"
		} else {
			u.Host = host
		}
		u.Fragment = "" // fragments are browser-local and never reach the scanner.
		return u.String(), nil
	}
	if strings.ContainsAny(v, "\r\n\t ,;") {
		return "", fmt.Errorf("add one asset at a time")
	}
	v = strings.ToLower(strings.TrimSuffix(v, "/"))
	if ip := net.ParseIP(strings.Trim(v, "[]")); ip != nil {
		return ip.String(), nil
	}
	if _, network, err := net.ParseCIDR(v); err == nil {
		return network.String(), nil
	}
	if strings.ContainsAny(v, "/?#") && !strings.HasPrefix(v, "*.") {
		// A path/query without a scheme is ambiguous and was previously mangled
		// into a fake hostname. Require an explicit URL instead.
		return "", fmt.Errorf("paths and queries require an http:// or https:// URL")
	}
	return v, nil
}

// detectAssetKind classifies an asset value into web | network | mixed using the
// same Public-Suffix-aware splitter the scanner uses, so the scan menu can ask
// for the right module set (web, network, or BOTH for a mixed asset).
func detectAssetKind(value string) (kind, netScope string, webHosts []string) {
	webHosts, netScope = scanner.SplitScope(value)
	switch {
	case len(webHosts) > 0 && netScope != "":
		return "mixed", netScope, webHosts
	case netScope != "":
		return "network", netScope, webHosts
	default:
		return "web", netScope, webHosts
	}
}

func (h *Handler) handleListAssets(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	rows, err := h.db.QueryContext(r.Context(),
		`SELECT id, target_id, COALESCE(name,''), value, COALESCE(kind,'web'), COALESCE(asset_type,'domain'),
		 COALESCE(source,'manual'), COALESCE(source_id,''), COALESCE(approval_status,'approved'),
		 COALESCE(monitor_enabled,1), COALESCE(metadata,'{}'), created_at, COALESCE(updated_at,created_at)
		 FROM assets WHERE target_id = ? ORDER BY created_at ASC`, id)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()
	out := make([]models.Asset, 0)
	for rows.Next() {
		var a models.Asset
		var monitor int
		if rows.Scan(&a.ID, &a.TargetID, &a.Name, &a.Value, &a.Kind, &a.AssetType, &a.Source, &a.SourceID,
			&a.ApprovalStatus, &monitor, &a.Metadata, &a.CreatedAt, &a.UpdatedAt) == nil {
			a.MonitorEnabled = monitor == 1
			out = append(out, a)
		}
	}
	h.writeSuccess(w, out)
}

func (h *Handler) handleAddAsset(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var req struct {
		Name      string `json:"name"`
		Value     string `json:"value"`
		AssetType string `json:"asset_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Value) == "" {
		h.writeError(w, http.StatusBadRequest, "asset value is required")
		return
	}
	value, err := normalizeAssetValue(req.Value)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	kind, _, _ := detectAssetKind(value)
	assetType := normalizeManualAssetType(req.AssetType, value, kind)
	aid := uuid.New().String()
	if _, err := h.db.Exec(
		`INSERT INTO assets (id, target_id, name, value, kind, asset_type, source, approval_status, monitor_enabled, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, 'manual', 'approved', 1, CURRENT_TIMESTAMP)`,
		aid, id, strings.TrimSpace(req.Name), value, kind, assetType); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			h.writeError(w, http.StatusConflict, "that asset already exists on this target")
			return
		}
		h.writeError(w, http.StatusInternalServerError, "failed to add asset")
		return
	}
	h.hub.Broadcast("target_updated", map[string]string{"id": id})
	h.writeSuccess(w, models.Asset{ID: aid, TargetID: id, Name: strings.TrimSpace(req.Name), Value: value, Kind: kind, AssetType: assetType, Source: "manual", ApprovalStatus: "approved", MonitorEnabled: true})
}

func normalizeManualAssetType(explicit, value, kind string) string {
	t := strings.ToLower(strings.TrimSpace(explicit))
	allowed := map[string]bool{"domain": true, "url": true, "page": true, "js": true, "wildcard": true, "api": true, "cidr": true, "ip": true, "source_code": true, "android": true, "ios": true, "hardware": true, "other": true}
	if allowed[t] {
		return t
	}
	lower := strings.ToLower(strings.TrimSpace(value))
	if strings.HasPrefix(lower, "*.") {
		return "wildcard"
	}
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		if strings.HasSuffix(strings.Split(lower, "?")[0], ".js") {
			return "js"
		}
		return "url"
	}
	if kind == "network" {
		if strings.Contains(lower, "/") {
			return "cidr"
		}
		return "ip"
	}
	return "domain"
}

func (h *Handler) handleUpdateAsset(w http.ResponseWriter, r *http.Request) {
	id, aid := mux.Vars(r)["id"], mux.Vars(r)["aid"]
	var req struct {
		Name      *string `json:"name"`
		Value     *string `json:"value"`
		AssetType *string `json:"asset_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to update asset")
		return
	}
	defer tx.Rollback()
	var existing, name, assetType string
	if err := tx.QueryRowContext(r.Context(), `SELECT value,COALESCE(name,''),COALESCE(asset_type,'domain') FROM assets WHERE id=? AND target_id=?`, aid, id).
		Scan(&existing, &name, &assetType); err != nil {
		if err == sql.ErrNoRows {
			h.writeError(w, http.StatusNotFound, "asset not found")
		} else {
			h.writeError(w, http.StatusInternalServerError, "failed to update asset")
		}
		return
	}
	if req.Name != nil {
		name = strings.TrimSpace(*req.Name)
	}
	value, kind := existing, ""
	valueChanged := false
	if req.Value != nil {
		raw := strings.TrimSpace(*req.Value)
		if raw == "" {
			h.writeError(w, http.StatusBadRequest, "asset value cannot be empty")
			return
		}
		v, normalizeErr := normalizeAssetValue(raw)
		if normalizeErr != nil {
			h.writeError(w, http.StatusBadRequest, normalizeErr.Error())
			return
		}
		value, valueChanged = v, v != existing
	}
	kind, _, _ = detectAssetKind(value)
	if req.AssetType != nil {
		assetType = *req.AssetType
	}
	assetType = normalizeManualAssetType(assetType, value, kind)

	// All fields commit together. Previously a conflicting value returned 409
	// after the name had already changed, and omitted fields were erased.
	if valueChanged {
		if _, err := tx.ExecContext(r.Context(), `UPDATE assets SET value=?, kind=?, asset_type=?,
			metadata=json_remove(COALESCE(NULLIF(metadata,''),'{}'),'$.monitor_hash','$.monitor_size','$.monitor_status','$.monitor_title','$.monitor_url','$.monitor_security_snapshot','$.monitor_checked_at'),
			name=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND target_id=?`, value, kind, assetType, name, aid, id); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				h.writeError(w, http.StatusConflict, "another asset already uses that value")
				return
			}
			h.writeError(w, http.StatusInternalServerError, "failed to update asset value")
			return
		}
	} else if _, err := tx.ExecContext(r.Context(), `UPDATE assets SET name=?,kind=?,asset_type=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND target_id=?`,
		name, kind, assetType, aid, id); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to update asset")
		return
	}
	if err := tx.Commit(); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to update asset")
		return
	}
	h.hub.Broadcast("target_updated", map[string]string{"id": id})
	h.writeSuccess(w, map[string]string{"message": "updated"})
}

func (h *Handler) handleDeleteAsset(w http.ResponseWriter, r *http.Request) {
	id, aid := mux.Vars(r)["id"], mux.Vars(r)["aid"]
	var approval, assetType string
	if err := h.db.QueryRowContext(r.Context(), `SELECT COALESCE(approval_status,'approved'),COALESCE(asset_type,'domain') FROM assets WHERE id=? AND target_id=?`, aid, id).Scan(&approval, &assetType); err != nil {
		if err == sql.ErrNoRows {
			h.writeError(w, http.StatusNotFound, "asset not found")
		} else {
			h.writeError(w, http.StatusInternalServerError, "failed to load asset")
		}
		return
	}
	scannableType := map[string]bool{"domain": true, "wildcard": true, "url": true, "page": true, "js": true, "api": true, "ip": true, "cidr": true}
	if approval == "approved" && scannableType[assetType] {
		var remaining int
		if err := h.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM assets WHERE target_id=? AND id<>? AND COALESCE(approval_status,'approved')='approved'
			AND COALESCE(asset_type,'domain') IN ('domain','wildcard','url','page','js','api','ip','cidr')`, id, aid).Scan(&remaining); err != nil {
			h.writeError(w, http.StatusInternalServerError, "failed to validate project scope")
			return
		}
		if remaining == 0 {
			h.writeError(w, http.StatusConflict, "a project must keep at least one approved scannable asset; delete the project instead")
			return
		}
	}
	res, err := h.db.ExecContext(r.Context(), `DELETE FROM assets WHERE id=? AND target_id=?`, aid, id)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to delete asset")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		h.writeError(w, http.StatusNotFound, "asset not found")
		return
	}
	h.hub.Broadcast("target_updated", map[string]string{"id": id})
	h.writeSuccess(w, map[string]string{"message": "deleted"})
}

// handleScanAsset starts a scan pinned to ONE asset's scope — so a target's
// assets are scanned individually. Web modules come from the request; the network
// half runs automatically for a network/mixed asset.
func (h *Handler) handleScanAsset(w http.ResponseWriter, r *http.Request) {
	id, aid := mux.Vars(r)["id"], mux.Vars(r)["aid"]
	var req struct {
		Modules  []string `json:"modules"`
		Priority int      `json:"priority"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Modules = scheduler.AllModules
	}
	if req.Priority == 0 {
		req.Priority = 5
	}
	if err := h.requireIDORIdentities(id, req.Modules); err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var value, assetType string
	var approval string
	if err := h.db.QueryRowContext(r.Context(), `SELECT value,COALESCE(approval_status,'approved'),COALESCE(asset_type,'domain') FROM assets WHERE id=? AND target_id=?`, aid, id).Scan(&value, &approval, &assetType); err != nil {
		h.writeError(w, http.StatusNotFound, "asset not found")
		return
	}
	if approval != "approved" {
		h.writeError(w, http.StatusConflict, "asset is pending approval or suspended by an upstream scope change")
		return
	}
	scannable := map[string]bool{"domain": true, "wildcard": true, "url": true, "page": true, "js": true, "api": true, "ip": true, "cidr": true}
	if !scannable[assetType] {
		h.writeError(w, http.StatusBadRequest, "this asset type is catalog/reference metadata and has no compatible scan pipeline")
		return
	}
	task, err := h.sched.CreateScopedTask(id, req.Modules, req.Priority, value)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to start scan")
		return
	}
	h.writeJSON(w, http.StatusCreated, map[string]any{"data": task, "success": true})
}

// seedAssetsFromScope creates one asset per token of a freshly-created target's
// scope, so a multi-host target starts with a managed asset list.
func (h *Handler) seedAssetsFromScope(targetID, scope string) {
	seen := map[string]bool{}
	for _, tok := range strings.FieldsFunc(scope, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == '\r' || r == ';'
	}) {
		tok, err := normalizeAssetValue(tok)
		if err != nil || tok == "" || seen[tok] {
			continue
		}
		seen[tok] = true
		kind, _, _ := detectAssetKind(tok)
		assetType := normalizeManualAssetType("", tok, kind)
		_, _ = h.db.Exec(`INSERT INTO assets (id, target_id, name, value, kind, asset_type, source, approval_status, monitor_enabled, updated_at) VALUES (?, ?, '', ?, ?, ?, 'manual', 'approved', 1, CURRENT_TIMESTAMP)
			ON CONFLICT(target_id, value) DO NOTHING`, uuid.New().String(), targetID, tok, kind, assetType)
	}
}
