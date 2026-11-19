package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// ── Breadth ("watch") coverage ───────────────────────────────────────────────
//
// A project is either DEEP (the full pipeline) or BREADTH (the cheap watch
// tier). The flip is enforced here, in the API, not in the UI: the UI only
// says what the operator wants.
//
// Flip TO breadth (watch_only 0 → 1):
//
//	watch_only = 1, watch_next_run = CURRENT_TIMESTAMP (the first round starts
//	now), watch_paused = 0, watch_fail_count = 0, monitor_enabled = 1 and
//	monitor_last_run = NULL, plus monitor_enabled = 0 on every asset row.
//	The project flag stays ON: watch rounds are the monitoring for this tier.
//	runDueMonitors excludes watch_only=1, so no deep monitor task starts.
//	Asset flags stay OFF because only the deep monitor reads them.
//
// Flip TO deep (watch_only 1 → 0):
//
//	watch_only = 0, watch_next_run = NULL, watch_paused = 0. monitor_enabled
//	is left as it is, and approved web assets get monitor_enabled = 1 so the
//	deep monitor can cover them.
//
// A project whose kind is `mixed` or `network` CANNOT run a watch round: the
// watch tier is web-only and the scheduler refuses a non-web project. The flip
// is refused with 400 and the list of network assets, so the operator can drop
// them first (the UI's "keep only web assets" action).

// watchFlipError carries the reason a flip was refused plus the identifiers
// the operator has to deal with.
type watchFlipError struct {
	Reason  string   `json:"reason"`
	Assets  []string `json:"assets"`
	Message string   `json:"message"`
}

func (e *watchFlipError) Error() string { return e.Message }

// networkAssetIdentifiers lists the project's network assets (CIDRs, IPs).
func networkAssetIdentifiers(ctx context.Context, q queryRower, targetID string) ([]string, error) {
	rows, err := q.QueryContext(ctx, `
		SELECT value FROM assets
		WHERE target_id = ?
		  AND (COALESCE(kind,'') = 'network' OR COALESCE(asset_type,'') IN ('cidr','ip','network','ip_address','range'))
		  AND COALESCE(approval_status,'approved') != 'suspended'
		ORDER BY value`, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// queryRower is the tiny slice of *sql.DB / *sql.Tx this file needs.
type queryRower interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// applyWatchCoverage flips one project between the deep and the breadth tier.
// It is the single enforcement point: the single-target PATCH and the bulk
// endpoint both call it, so both behave identically.
func applyWatchCoverage(ctx context.Context, tx *sql.Tx, targetID string, toWatch bool) error {
	var kind string
	var watchOnly int
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(kind,'web'), COALESCE(watch_only,0) FROM targets WHERE id=?`, targetID).
		Scan(&kind, &watchOnly)
	if err == sql.ErrNoRows {
		return &watchFlipError{Message: "target not found", Reason: "not_found"}
	}
	if err != nil {
		return err
	}
	if (watchOnly == 1) == toWatch {
		// Already in the requested mode: still normalise the schedule and the
		// monitor flag, so older breadth projects show the correct UI state.
		if toWatch {
			if _, err := tx.ExecContext(ctx, `UPDATE targets SET watch_paused=0, watch_fail_count=0, monitor_enabled=1, monitor_last_run=NULL WHERE id=?`, targetID); err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, `UPDATE assets SET monitor_enabled = 0 WHERE target_id = ?`, targetID)
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE targets SET watch_paused=0, watch_next_run=NULL WHERE id=?`, targetID)
		return err
	}

	if toWatch {
		if kind != "web" {
			assets, _ := networkAssetIdentifiers(ctx, tx, targetID)
			return &watchFlipError{
				Message: "a breadth project must be web-only: drop the network assets first",
				Reason:  "not_web_only",
				Assets:  assets,
			}
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE targets SET
				watch_only = 1,
				watch_next_run = CURRENT_TIMESTAMP,
				watch_last_run = NULL,
				watch_fail_count = 0,
				watch_root_index = 0,
				watch_paused = 0,
				monitor_enabled = 1,
				monitor_last_run = NULL,
				updated_at = CURRENT_TIMESTAMP
			WHERE id = ?`, targetID); err != nil {
			return err
		}
		// No deep monitor task runs for watch_only=1. Asset monitor flags are
		// for the deep monitor only, so keep them off during breadth.
		if _, err := tx.ExecContext(ctx, `UPDATE assets SET monitor_enabled = 0 WHERE target_id = ?`, targetID); err != nil {
			return err
		}
		return nil
	}

	// Back to the deep tier: the watch schedule stops. The project flag stays
	// on, so the operator can turn monitoring off. Approved web assets get
	// their monitor flag back; no deep monitor ran during breadth.
	if _, err := tx.ExecContext(ctx, `
		UPDATE targets SET
			watch_only = 0,
			watch_next_run = NULL,
			watch_paused = 0,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`, targetID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE assets SET monitor_enabled = 1
		WHERE target_id = ? AND COALESCE(approval_status,'approved') = 'approved'
		  AND COALESCE(kind,'web') = 'web'`, targetID); err != nil {
		return err
	}
	return nil
}

// handleBulkCoverage flips the coverage of many projects at once. Each project
// gets its own result, so one refused project never aborts the batch.
func (h *Handler) handleBulkCoverage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs       []string `json:"ids"`
		WatchOnly bool     `json:"watch_only"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.IDs) == 0 {
		h.writeError(w, http.StatusBadRequest, "ids is required")
		return
	}

	type bulkResult struct {
		ID     string   `json:"id"`
		OK     bool     `json:"ok"`
		Reason string   `json:"reason,omitempty"`
		Assets []string `json:"assets,omitempty"`
	}
	results := make([]bulkResult, 0, len(req.IDs))

	for _, id := range req.IDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		// Per-user isolation: a member may only flip their own projects.
		if uid, isAdmin := h.callerScope(r); !isAdmin {
			var owner int
			if err := h.db.QueryRowContext(r.Context(), `SELECT owner_id FROM targets WHERE id=?`, id).Scan(&owner); err != nil {
				results = append(results, bulkResult{ID: id, OK: false, Reason: "not found"})
				continue
			}
			if int64(owner) != uid {
				results = append(results, bulkResult{ID: id, OK: false, Reason: "not found"})
				continue
			}
		}

		tx, err := h.db.BeginTx(r.Context(), nil)
		if err != nil {
			results = append(results, bulkResult{ID: id, OK: false, Reason: "database error"})
			continue
		}
		err = applyWatchCoverage(r.Context(), tx, id, req.WatchOnly)
		if err != nil {
			tx.Rollback()
			var flipErr *watchFlipError
			if errorsAs(err, &flipErr) {
				results = append(results, bulkResult{ID: id, OK: false, Reason: flipErr.Reason, Assets: flipErr.Assets})
				continue
			}
			results = append(results, bulkResult{ID: id, OK: false, Reason: "update failed"})
			continue
		}
		if err := tx.Commit(); err != nil {
			results = append(results, bulkResult{ID: id, OK: false, Reason: "commit failed"})
			continue
		}
		results = append(results, bulkResult{ID: id, OK: true})
	}

	h.hub.Broadcast("target_updated", map[string]string{"id": "bulk"})
	h.writeSuccess(w, map[string]any{"results": results})
}

// errorsAs is a tiny wrapper so this file does not import errors just for the
// one type assertion it needs.
func errorsAs(err error, target **watchFlipError) bool {
	if e, ok := err.(*watchFlipError); ok {
		*target = e
		return true
	}
	return false
}

// handleWatchScopeEvents lists the landing audit trail of one project: every
// host the watch tier brought into its eligible scope, newest first.
func (h *Handler) handleWatchScopeEvents(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if uid, isAdmin := h.callerScope(r); !isAdmin {
		var owner int64
		if err := h.db.QueryRowContext(r.Context(), `SELECT owner_id FROM targets WHERE id=?`, id).Scan(&owner); err != nil || owner != uid {
			h.writeError(w, http.StatusNotFound, "target not found")
			return
		}
	}

	rows, err := h.db.QueryContext(r.Context(), `
		SELECT id, COALESCE(program_id,''), identifier, COALESCE(event_type,'landed'),
		       COALESCE(asset_id,''), detected_at, COALESCE(announced,0), COALESCE(metadata,'{}')
		FROM watch_scope_events WHERE target_id = ? ORDER BY detected_at DESC LIMIT 500`, id)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to query watch scope events")
		return
	}
	defer rows.Close()

	type watchScopeEvent struct {
		ID         string `json:"id"`
		ProgramID  string `json:"program_id"`
		Identifier string `json:"identifier"`
		EventType  string `json:"event_type"`
		AssetID    string `json:"asset_id"`
		DetectedAt string `json:"detected_at"`
		Announced  int    `json:"announced"`
		Metadata   string `json:"metadata"`
	}
	out := make([]watchScopeEvent, 0)
	for rows.Next() {
		var e watchScopeEvent
		if err := rows.Scan(&e.ID, &e.ProgramID, &e.Identifier, &e.EventType, &e.AssetID, &e.DetectedAt, &e.Announced, &e.Metadata); err != nil {
			h.writeError(w, http.StatusInternalServerError, "failed to decode watch scope events")
			return
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to read watch scope events")
		return
	}
	h.writeSuccess(w, out)
}

// handlePromoteWatchScope upgrades landed hosts to deep-tier seeds.
//
// A landed host is stored with asset_type='subdomain', so neither
// loadSubdomainRoots (domain/wildcard) nor loadProjectWebSeeds
// (domain/wildcard/url/page/js/api) picks it up: a deep scan ignores it. The
// operator can promote selected landed rows to asset_type='url', which makes
// the deep pipeline seed them.
func (h *Handler) handlePromoteWatchScope(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var req struct {
		Values []string `json:"values"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Values) == 0 {
		h.writeError(w, http.StatusBadRequest, "values is required")
		return
	}
	if uid, isAdmin := h.callerScope(r); !isAdmin {
		var owner int64
		if err := h.db.QueryRowContext(r.Context(), `SELECT owner_id FROM targets WHERE id=?`, id).Scan(&owner); err != nil || owner != uid {
			h.writeError(w, http.StatusNotFound, "target not found")
			return
		}
	}

	placeholders := make([]string, 0, len(req.Values))
	args := []any{id}
	for _, v := range req.Values {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			continue
		}
		placeholders = append(placeholders, "?")
		args = append(args, v)
	}
	if len(placeholders) == 0 {
		h.writeError(w, http.StatusBadRequest, "values is required")
		return
	}

	// Only rows the watch tier landed are promoted; a program-imported asset
	// keeps its own type.
	res, err := h.db.ExecContext(r.Context(), `
		UPDATE assets
		SET asset_type = 'url',
		    monitor_enabled = 0,
		    metadata = json_set(COALESCE(metadata,'{}'), '$.promoted_to_deep', 1),
		    updated_at = CURRENT_TIMESTAMP
		WHERE target_id = ? AND source = 'watch:scope' AND value IN (`+strings.Join(placeholders, ",")+`)`, args...)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to promote hosts")
		return
	}
	n, _ := res.RowsAffected()
	h.hub.Broadcast("target_updated", map[string]string{"id": id})
	h.writeSuccess(w, map[string]any{"promoted": n})
}
