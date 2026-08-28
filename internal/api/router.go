package api

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gorilla/mux"
	"github.com/recon-platform/internal/auth"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/scheduler"
	"github.com/recon-platform/internal/websocket"
	"github.com/recon-platform/pkg/logger"
)

type Handler struct {
	db     *database.DB
	hub    *websocket.Hub
	sched  *scheduler.Scheduler
	cfg    *config.Config
	logger *logger.Logger
	auth   *auth.Auth
}

func NewRouter(db *database.DB, hub *websocket.Hub, sched *scheduler.Scheduler, cfg *config.Config, log *logger.Logger) http.Handler {
	authService := auth.New(db, cfg)
	if err := authService.EnsureAdminUser(); err != nil {
		log.Error("Failed to ensure admin user", "error", err)
	}

	h := &Handler{
		db:     db,
		hub:    hub,
		sched:  sched,
		cfg:    cfg,
		logger: log,
		auth:   authService,
	}

	r := mux.NewRouter()

	// Static files
	frontendDir := filepath.Join(".", "frontend", "dist")
	r.HandleFunc("/ws", h.requireAuth(hub.ServeWS))
	r.PathPrefix("/assets/").Handler(http.StripPrefix("/assets/", http.FileServer(http.Dir(filepath.Join(frontendDir, "assets")))))
	r.HandleFunc("/screenshots/{id}", h.requireAuth(h.serveScreenshot))

	// Blind-XSS out-of-band callback (PUBLIC, no auth — victim browsers must
	// reach it). {token}.js serves the collector; {token} records the beacon.
	r.HandleFunc("/bx/{token}.js", h.handleBlindXSSJS).Methods("GET")
	r.HandleFunc("/bx/{token}", h.handleBlindXSSCallback).Methods("GET")

	// Out-of-band SSRF/RCE callback (PUBLIC, no auth, ANY method — the target
	// server calls back here when our injected payload fires).
	r.HandleFunc("/oob/{token}", h.handleOOBCallback)

	// API routes
	api := r.PathPrefix("/api").Subrouter()
	api.Use(h.jsonMiddleware)
	api.Use(h.corsMiddleware)
	api.Use(h.targetScopeMiddleware) // per-user isolation on every /targets/{id} route

	// Auth endpoints
	api.HandleFunc("/auth/login", h.handleLogin).Methods("POST")
	api.HandleFunc("/auth/logout", h.handleLogout).Methods("POST")
	api.HandleFunc("/auth/me", h.requireAuth(h.handleMe)).Methods("GET")
	api.HandleFunc("/auth/change-password", h.requireAuth(h.handleChangePassword)).Methods("POST")

	// User administration (admin-only): add / edit role / enable-disable / reset
	// password / delete. Guarded so the last active administrator can't be removed.
	api.HandleFunc("/users", h.requireAdmin(h.handleListUsers)).Methods("GET")
	api.HandleFunc("/users", h.requireAdmin(h.handleCreateUser)).Methods("POST")
	api.HandleFunc("/users/{uid}", h.requireAdmin(h.handleUpdateUser)).Methods("PATCH")
	api.HandleFunc("/users/{uid}", h.requireAdmin(h.handleDeleteUser)).Methods("DELETE")

	// Dashboard
	api.HandleFunc("/dashboard/stats", h.requireAuth(h.handleDashboardStats)).Methods("GET")
	api.HandleFunc("/dashboard/charts", h.requireAuth(h.handleDashboardCharts)).Methods("GET")

	// Targets
	api.HandleFunc("/targets", h.requireAuth(h.handleListTargets)).Methods("GET")
	api.HandleFunc("/targets", h.requireAuth(h.handleCreateTarget)).Methods("POST")
	api.HandleFunc("/targets/{id}", h.requireAuth(h.handleGetTarget)).Methods("GET")
	api.HandleFunc("/targets/{id}", h.requireAuth(h.handleUpdateTarget)).Methods("PUT")
	api.HandleFunc("/targets/{id}", h.requireAuth(h.handleDeleteTarget)).Methods("DELETE")
	api.HandleFunc("/targets/bulk-delete", h.requireAuth(h.handleBulkDeleteTarget)).Methods("POST")
	api.HandleFunc("/targets/import", h.requireAuth(h.handleImportTargets)).Methods("POST")
	api.HandleFunc("/targets/{id}/export", h.requireAuth(h.handleExportTarget)).Methods("GET")
	api.HandleFunc("/targets/{id}/scan", h.requireAuth(h.handleStartScan)).Methods("POST")
	api.HandleFunc("/targets/{id}/assets", h.requireAuth(h.handleListAssets)).Methods("GET")
	api.HandleFunc("/targets/{id}/assets", h.requireAuth(h.handleAddAsset)).Methods("POST")
	api.HandleFunc("/targets/{id}/assets/{aid}", h.requireAuth(h.handleUpdateAsset)).Methods("PATCH")
	api.HandleFunc("/targets/{id}/assets/{aid}", h.requireAuth(h.handleDeleteAsset)).Methods("DELETE")
	api.HandleFunc("/targets/{id}/assets/{aid}/scan", h.requireAuth(h.handleScanAsset)).Methods("POST")
	api.HandleFunc("/targets/{id}/pause", h.requireAuth(h.handlePauseScan)).Methods("POST")
	api.HandleFunc("/targets/{id}/resume", h.requireAuth(h.handleResumeScan)).Methods("POST")
	api.HandleFunc("/targets/{id}/skip-phase", h.requireAuth(h.handleSkipPhase)).Methods("POST")
	api.HandleFunc("/targets/{id}/cancel", h.requireAuth(h.handleCancelScan)).Methods("POST")
	api.HandleFunc("/targets/{id}/stats", h.requireAuth(h.handleTargetStats)).Methods("GET")
	api.HandleFunc("/targets/{id}/network-services", h.requireAuth(h.handleNetworkServices)).Methods("GET")
	api.HandleFunc("/targets/{id}/monitor", h.requireAuth(h.handleUpdateMonitor)).Methods("PATCH")
	api.HandleFunc("/targets/{id}/auth", h.requireAuth(h.handleSetAuth)).Methods("PATCH")
	api.HandleFunc("/targets/{id}/identities", h.requireAuth(h.handleListIdentities)).Methods("GET")
	api.HandleFunc("/targets/{id}/identities", h.requireAuth(h.handleCreateIdentity)).Methods("POST")
	api.HandleFunc("/targets/{id}/identities/{iid}", h.requireAuth(h.handleDeleteIdentity)).Methods("DELETE")
	api.HandleFunc("/targets/{id}/identities/{iid}/validate", h.requireAuth(h.handleValidateIdentity)).Methods("POST")
	api.HandleFunc("/targets/{id}/identities/import", h.requireAuth(h.handleImportSession)).Methods("POST")
	api.HandleFunc("/targets/{id}/findings/{fid}/evidence", h.requireAuth(h.handleListEvidence)).Methods("GET")
	api.HandleFunc("/targets/{id}/findings/{fid}/triage", h.requireAuth(h.handleSetFindingTriage)).Methods("POST", "PATCH")
	api.HandleFunc("/targets/{id}/replay", h.requireAuth(h.handleReplay)).Methods("POST")
	api.HandleFunc("/targets/{id}/objects", h.requireAuth(h.handleListObjects)).Methods("GET")
	api.HandleFunc("/targets/{id}/capture/traffic", h.requireAuth(h.handleIngestTraffic)).Methods("POST")
	api.HandleFunc("/targets/{id}/relationships", h.requireAuth(h.handleListRelationships)).Methods("GET")
	api.HandleFunc("/targets/{id}/actions", h.requireAuth(h.handleListActions)).Methods("GET")
	api.HandleFunc("/targets/{id}/hypotheses", h.requireAuth(h.handleListHypotheses)).Methods("GET")
	api.HandleFunc("/targets/{id}/observations", h.requireAuth(h.handleListObservations)).Methods("GET")
	api.HandleFunc("/targets/{id}/verify-write", h.requireAuth(h.handleVerifyWrite)).Methods("POST")
	api.HandleFunc("/targets/{id}/finding-groups", h.requireAuth(h.handleListFindingGroups)).Methods("GET")
	api.HandleFunc("/targets/{id}/workflow-graph", h.requireAuth(h.handleWorkflowGraph)).Methods("GET")
	api.HandleFunc("/targets/{id}/workflow/run", h.requireAuth(h.handleRunWorkflow)).Methods("POST")
	api.HandleFunc("/targets/{id}/report", h.requireAuth(h.handleGenerateReport)).Methods("GET")
	api.HandleFunc("/targets/{id}/report.pdf", h.requireAuth(h.handleGenerateReportPDF)).Methods("GET")
	api.HandleFunc("/targets/{id}/report.html", h.requireAuth(h.handleGenerateReportHTML)).Methods("GET")
	api.HandleFunc("/targets/{id}/graph", h.requireAuth(h.handleAssetGraph)).Methods("GET")

	// Findings
	api.HandleFunc("/targets/{id}/subdomains", h.requireAuth(h.handleListSubdomains)).Methods("GET")
	api.HandleFunc("/targets/{id}/http-services", h.requireAuth(h.handleListHTTPServices)).Methods("GET")
	api.HandleFunc("/targets/{id}/js-files", h.requireAuth(h.handleListJSFiles)).Methods("GET")
	api.HandleFunc("/targets/{id}/js-findings", h.requireAuth(h.handleListJSFindings)).Methods("GET")
	api.HandleFunc("/targets/{id}/parameters", h.requireAuth(h.handleListParameters)).Methods("GET")
	api.HandleFunc("/targets/{id}/directory-findings", h.requireAuth(h.handleListDirectoryFindings)).Methods("GET")
	api.HandleFunc("/targets/{id}/backup-findings", h.requireAuth(h.handleListBackupFindings)).Methods("GET")
	api.HandleFunc("/targets/{id}/open-redirects", h.requireAuth(h.handleListOpenRedirects)).Methods("GET")
	api.HandleFunc("/targets/{id}/nuclei-findings", h.requireAuth(h.handleListNucleiFindings)).Methods("GET")
	api.HandleFunc("/targets/{id}/nuclei-findings/affected", h.requireAuth(h.handleNucleiAffected)).Methods("GET")
	api.HandleFunc("/targets/{id}/vuln-findings", h.requireAuth(h.handleListVulnFindings)).Methods("GET")
	// Global findings aggregation (top-level Findings page) across all the caller's targets.
	api.HandleFunc("/findings", h.requireAuth(h.handleListAllFindings)).Methods("GET")
	api.HandleFunc("/targets/{id}/monitoring-changes", h.requireAuth(h.handleListMonitoringChanges)).Methods("GET")

	// Tasks
	api.HandleFunc("/tasks", h.requireAuth(h.handleListTasks)).Methods("GET")
	api.HandleFunc("/tasks/{id}", h.requireAuth(h.handleGetTask)).Methods("GET")
	api.HandleFunc("/tasks/{id}/cancel", h.requireAuth(h.handleCancelTask)).Methods("POST")
	api.HandleFunc("/tasks/{id}/resume", h.requireAuth(h.handleResumeTask)).Methods("POST")
	api.HandleFunc("/tasks/{id}/logs", h.requireAuth(h.handleGetTaskLogs)).Methods("GET")

	// Global search
	api.HandleFunc("/search", h.requireAuth(h.handleSearch)).Methods("GET")

	// Tool management
	api.HandleFunc("/tools/status", h.requireAuth(h.handleToolStatus)).Methods("GET")
	api.HandleFunc("/tools/catalog", h.requireAuth(h.handleToolCatalog)).Methods("GET")
	api.HandleFunc("/tools/install", h.requireAuth(h.handleToolInstall)).Methods("POST")

	// System
	api.HandleFunc("/system/settings", h.requireAuth(h.handleGetSettings)).Methods("GET")
	api.HandleFunc("/system/settings", h.requireAuth(h.handleUpdateSettings)).Methods("PATCH")
	api.HandleFunc("/system/stats", h.requireAuth(h.handleSystemStats)).Methods("GET")
	api.HandleFunc("/system/update-templates", h.requireAuth(h.handleUpdateNucleiTemplates)).Methods("POST")
	api.HandleFunc("/system/update-check", h.requireAuth(h.handleUpdateCheck)).Methods("GET")
	api.HandleFunc("/notifications", h.requireAuth(h.handleListNotifications)).Methods("GET")
	api.HandleFunc("/notifications/read", h.requireAuth(h.handleMarkNotificationsRead)).Methods("POST")

	// SPA fallback
	r.PathPrefix("/").HandlerFunc(h.serveSPA(frontendDir))

	return r
}

func (h *Handler) jsonMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

func (h *Handler) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization,X-CSRF-Token")
		}
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ctxUserIDKey carries the authenticated user's id through the request context so
// handlers (handleMe, user administration, per-user actions) know who is calling.
type ctxKey string

const ctxUserIDKey ctxKey = "recon_user_id"

func (h *Handler) currentUserID(r *http.Request) int64 {
	if v, ok := r.Context().Value(ctxUserIDKey).(int64); ok {
		return v
	}
	return 0
}

func (h *Handler) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID, err := h.auth.GetSessionFromRequest(r)
		if err != nil {
			h.writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		userID, err := h.auth.ValidateSession(sessionID)
		if err != nil {
			h.writeError(w, http.StatusUnauthorized, "session expired")
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), ctxUserIDKey, userID))
		next(w, r)
	}
}

// userFromSession resolves the caller's account straight from the session cookie
// (used by middleware that runs BEFORE the per-handler requireAuth closure). ok is
// false when there is no valid session.
func (h *Handler) userFromSession(r *http.Request) (*auth.User, bool) {
	sid, err := h.auth.GetSessionFromRequest(r)
	if err != nil {
		return nil, false
	}
	uid, err := h.auth.ValidateSession(sid)
	if err != nil {
		return nil, false
	}
	u, err := h.auth.GetUser(uid)
	if err != nil {
		return nil, false
	}
	return u, true
}

// callerScope returns the authenticated caller's user id and whether they are an
// admin — for scoping list/dashboard queries. Assumes requireAuth already ran
// (it sets the user id in context). A resolution failure is treated as a
// non-admin with id 0, which matches no owned rows (fail-closed).
func (h *Handler) callerScope(r *http.Request) (userID int64, isAdmin bool) {
	uid := h.currentUserID(r)
	u, err := h.auth.GetUser(uid)
	if err != nil {
		return uid, false
	}
	return uid, u.Role == auth.RoleAdmin
}

// targetOwnerID returns the owner user id of a target (0 for legacy/unknown).
func (h *Handler) targetOwnerID(targetID string) (int64, bool) {
	var owner int64
	err := h.db.QueryRow("SELECT owner_id FROM targets WHERE id = ?", targetID).Scan(&owner)
	if err != nil {
		return 0, false
	}
	return owner, true
}

// targetScopeMiddleware enforces per-user data isolation: every /api/targets/{id}
// route (all of which use {id} as the target id) is reachable only by the target's
// owner or an administrator. Non-owners get 403 — a member can neither see nor act
// on another member's scans. Routes without an {id} var pass straight through and
// are scoped in their own list queries instead.
func (h *Handler) targetScopeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tid := mux.Vars(r)["id"]
		if tid == "" {
			next.ServeHTTP(w, r)
			return
		}
		u, ok := h.userFromSession(r)
		if !ok {
			// Not authenticated — let the handler's requireAuth return 401 uniformly.
			next.ServeHTTP(w, r)
			return
		}
		if u.Role == auth.RoleAdmin {
			next.ServeHTTP(w, r)
			return
		}
		owner, found := h.targetOwnerID(tid)
		if !found || owner != u.ID {
			h.writeError(w, http.StatusForbidden, "you do not have access to this target")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireAdmin wraps requireAuth and additionally rejects non-admin accounts, so
// user administration is reachable only by administrators.
func (h *Handler) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return h.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		u, err := h.auth.GetUser(h.currentUserID(r))
		if err != nil || u.Role != auth.RoleAdmin {
			h.writeError(w, http.StatusForbidden, "administrator access required")
			return
		}
		next(w, r)
	})
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (h *Handler) writeError(w http.ResponseWriter, status int, msg string) {
	h.writeJSON(w, status, map[string]string{"error": msg})
}

func (h *Handler) writeSuccess(w http.ResponseWriter, data any) {
	h.writeJSON(w, http.StatusOK, map[string]any{"data": data, "success": true})
}

func (h *Handler) serveSPA(dir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		if strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/ws") {
			h.writeError(w, http.StatusNotFound, "not found")
			return
		}

		w.Header().Set("Content-Type", "text/html")
		http.ServeFile(w, r, filepath.Join(dir, "index.html"))
	}
}

func (h *Handler) serveScreenshot(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var filePath string
	err := h.db.QueryRow("SELECT file_path FROM screenshots WHERE id = ?", id).Scan(&filePath)
	if err != nil {
		h.writeError(w, http.StatusNotFound, "screenshot not found")
		return
	}

	w.Header().Del("Content-Type")
	http.ServeFile(w, r, filePath)
}
