package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/recon-platform/internal/bounty"
)

func optionalBool(v string) (*bool, error) {
	if strings.TrimSpace(v) == "" {
		return nil, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return nil, err
	}
	return &b, nil
}

func queryInt(v string) int { n, _ := strconv.Atoi(v); return n }

func (h *Handler) handleListBountyPrograms(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	bounties, err := optionalBool(q.Get("bounties"))
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid bounties filter")
		return
	}
	wildcard, err := optionalBool(q.Get("wildcard"))
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid wildcard filter")
		return
	}
	result, err := h.bounty.ListPrograms(r.Context(), bounty.ListOptions{
		Search: q.Get("search"), Provider: q.Get("provider"), Status: q.Get("status"), ProgramType: q.Get("type"), Industry: q.Get("industry"), SafeHarbor: q.Get("safe_harbor"), AssetType: q.Get("asset_type"),
		OffersBounties: bounties, HasWildcard: wildcard, MinAssets: queryInt(q.Get("min_assets")), MaxAssets: queryInt(q.Get("max_assets")),
		MinRewardCents: queryInt(q.Get("min_reward_cents")), Sort: q.Get("sort"), Page: queryInt(q.Get("page")), Limit: queryInt(q.Get("limit")),
	})
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to query bounty catalog")
		return
	}
	h.writeSuccess(w, result)
}

func (h *Handler) handleGetBountyProgram(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["programID"]
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	p, err := h.bounty.GetProgram(ctx, id)
	if err != nil {
		h.writeError(w, http.StatusNotFound, "program not found or its current scope is temporarily unavailable")
		return
	}
	h.writeSuccess(w, p)
}

func (h *Handler) handleBountySyncStatus(w http.ResponseWriter, r *http.Request) {
	states, err := h.bounty.Status(r.Context())
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to read catalog status")
		return
	}
	h.writeSuccess(w, states)
}

func (h *Handler) handleSyncBountyCatalog(w http.ResponseWriter, r *http.Request) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		err := h.bounty.SyncAll(ctx, true)
		if err != nil {
			if strings.Contains(err.Error(), "already running") {
				h.hub.Broadcast("bounty_catalog_sync", map[string]any{"status": "running"})
				return
			}
			h.logger.Warn("Manual bounty catalog sync incomplete", "error", err)
			h.hub.Broadcast("bounty_catalog_sync", map[string]any{"status": "error", "error": err.Error()})
			return
		}
		h.hub.Broadcast("bounty_catalog_sync", map[string]any{"status": "ok"})
	}()
	h.writeJSON(w, http.StatusAccepted, map[string]any{"success": true, "data": map[string]string{"status": "started"}})
}

func (h *Handler) handleCreateProjectFromProgram(w http.ResponseWriter, r *http.Request) {
	var req bounty.CreateProjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	id, err := h.bounty.CreateProject(r.Context(), h.currentUserID(r), mux.Vars(r)["programID"], req)
	if err != nil {
		status := http.StatusBadRequest
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			status = http.StatusConflict
		}
		h.writeError(w, status, err.Error())
		return
	}
	h.hub.Broadcast("target_created", map[string]string{"id": id})
	h.writeJSON(w, http.StatusCreated, map[string]any{"success": true, "data": map[string]string{"id": id, "url": "/targets/" + id}})
}

func (h *Handler) handleListBountyEvents(w http.ResponseWriter, r *http.Request) {
	events, err := h.bounty.ListScopeEvents(r.Context(), mux.Vars(r)["id"])
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to query scope changes")
		return
	}
	h.writeSuccess(w, events)
}

func (h *Handler) handleResolveBountyEvent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Decision string `json:"decision"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.bounty.ResolveScopeEvent(r.Context(), mux.Vars(r)["id"], mux.Vars(r)["eventID"], req.Decision); err != nil {
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.hub.Broadcast("target_updated", map[string]string{"id": mux.Vars(r)["id"]})
	h.writeSuccess(w, map[string]string{"status": req.Decision})
}
