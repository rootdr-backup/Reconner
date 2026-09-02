package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/recon-platform/internal/models"
	"github.com/recon-platform/internal/scanner"
	"github.com/recon-platform/internal/scheduler"
)

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
	value := strings.TrimSpace(req.Value)
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
		Name      string `json:"name"`
		Value     string `json:"value"`
		AssetType string `json:"asset_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	// Always update the name; re-scope (and re-detect kind) when a new value is given.
	if _, err := h.db.Exec(`UPDATE assets SET name=? WHERE id=? AND target_id=?`,
		strings.TrimSpace(req.Name), aid, id); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to update asset")
		return
	}
	if v := strings.TrimSpace(req.Value); v != "" {
		kind, _, _ := detectAssetKind(v)
		assetType := normalizeManualAssetType(req.AssetType, v, kind)
		if _, err := h.db.Exec(`UPDATE assets SET value=?, kind=?, asset_type=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND target_id=?`, v, kind, assetType, aid, id); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				h.writeError(w, http.StatusConflict, "another asset already uses that value")
				return
			}
			h.writeError(w, http.StatusInternalServerError, "failed to update asset value")
			return
		}
	}
	h.hub.Broadcast("target_updated", map[string]string{"id": id})
	h.writeSuccess(w, map[string]string{"message": "updated"})
}

func (h *Handler) handleDeleteAsset(w http.ResponseWriter, r *http.Request) {
	id, aid := mux.Vars(r)["id"], mux.Vars(r)["aid"]
	if _, err := h.db.Exec(`DELETE FROM assets WHERE id=? AND target_id=?`, aid, id); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to delete asset")
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
		tok = strings.TrimSpace(tok)
		if tok == "" || seen[tok] {
			continue
		}
		seen[tok] = true
		kind, _, _ := detectAssetKind(tok)
		assetType := normalizeManualAssetType("", tok, kind)
		_, _ = h.db.Exec(`INSERT INTO assets (id, target_id, name, value, kind, asset_type, source, approval_status, monitor_enabled, updated_at) VALUES (?, ?, '', ?, ?, ?, 'manual', 'approved', 1, CURRENT_TIMESTAMP)
			ON CONFLICT(target_id, value) DO NOTHING`, uuid.New().String(), targetID, tok, kind, assetType)
	}
}
