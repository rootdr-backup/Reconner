package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/recon-platform/internal/models"
	"github.com/recon-platform/internal/scanner"
	"github.com/recon-platform/internal/scheduler"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

// apiKeySpec ties a settings field name + human label to its Config pointer, so
// the settings handlers stay a single source of truth (add a provider once).
func (h *Handler) apiKeyFields() []struct {
	Name, Label, Hint string
	Ptr               *string
} {
	c := h.cfg
	return []struct {
		Name, Label, Hint string
		Ptr               *string
	}{
		{"securitytrails", "SecurityTrails", "API key", &c.SecurityTrailsAPIKey},
		{"shodan", "Shodan", "API key", &c.ShodanAPIKey},
		{"censys", "Censys", "API_ID:API_SECRET", &c.CensysAPIKey},
		{"fofa", "FOFA", "email:key", &c.FOFAAPIKey},
		{"quake", "Quake (360)", "token", &c.QuakeAPIKey},
		{"zoomeye", "ZoomEye", "API key", &c.ZoomEyeAPIKey},
		{"virustotal", "VirusTotal", "v3 API key", &c.VirusTotalAPIKey},
	}
}

// maskKey turns a secret into a safe preview (never returns the raw value).
func maskKey(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 6 {
		return "••••"
	}
	return s[:2] + "••••" + s[len(s)-2:]
}

// handleGetSettings returns which passive-intel API keys are configured, as
// booleans + a masked preview only — the raw key is NEVER sent to the client.
func (h *Handler) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	type keyState struct {
		Name   string `json:"name"`
		Label  string `json:"label"`
		Hint   string `json:"hint"`
		Set    bool   `json:"set"`
		Masked string `json:"masked"`
	}
	out := make([]keyState, 0)
	for _, f := range h.apiKeyFields() {
		out = append(out, keyState{Name: f.Name, Label: f.Label, Hint: f.Hint, Set: *f.Ptr != "", Masked: maskKey(*f.Ptr)})
	}
	h.writeSuccess(w, map[string]any{"api_keys": out})
}

// handleUpdateSettings applies API-key edits and persists them to config.json.
// A provided empty string CLEARS that key; an omitted field is left unchanged.
// Values take effect for subsequent scans (the scanners read h.cfg at run time).
func (h *Handler) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var body map[string]*string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	changed := false
	for _, f := range h.apiKeyFields() {
		if v, ok := body[f.Name]; ok && v != nil {
			*f.Ptr = strings.TrimSpace(*v)
			changed = true
		}
	}
	if changed {
		if err := h.cfg.Save(); err != nil {
			h.writeError(w, http.StatusInternalServerError, "saved in memory but could not persist to config.json: "+err.Error())
			return
		}
	}
	h.handleGetSettings(w, r)
}

func (h *Handler) handleDashboardStats(w http.ResponseWriter, r *http.Request) {
	stats := models.DashboardStats{}

	// Per-user isolation: a member's dashboard reflects ONLY their own targets and
	// everything under them; an admin sees the whole platform. The `targets` table
	// scopes by owner_id; every child table scopes by target_id ∈ (owned targets).
	uid, isAdmin := h.callerScope(r)

	queries := []struct {
		dest  *int
		table string
		where string
	}{
		{&stats.Targets, "targets", ""},
		{&stats.Subdomains, "subdomains", ""},
		{&stats.AliveHosts, "subdomains", "is_alive = 1"},
		{&stats.HTTPServices, "http_services", ""},
		{&stats.JSFiles, "js_files", ""},
		{&stats.Parameters, "parameters", ""},
		{&stats.ReflectedParameters, "parameters", "is_reflected = 1"},
		{&stats.DirectoryFindings, "directory_findings", ""},
		{&stats.BackupFindings, "backup_findings", ""},
		// Surfaced/confirmed only — consistent with the per-target finding_count,
		// the report, and the Findings tabs.
		{&stats.OpenRedirectFindings, "open_redirect_findings", "COALESCE(status,'finding')='finding'"},
		{&stats.NucleiFindings, "nuclei_findings", "COALESCE(verification,'unverified') != 'rejected'"},
		{&stats.VulnFindings, "vuln_findings", "COALESCE(status,'finding')='finding'"},
		{&stats.RunningTasks, "tasks", "status = 'running'"},
		{&stats.FinishedTasks, "tasks", "status = 'finished'"},
		{&stats.FailedTasks, "tasks", "status = 'failed'"},
		{&stats.PendingTasks, "tasks", "status = 'pending'"},
	}

	for _, q := range queries {
		conds := []string{}
		args := []any{}
		if q.where != "" {
			conds = append(conds, q.where)
		}
		if !isAdmin {
			if q.table == "targets" {
				conds = append(conds, "owner_id = ?")
			} else {
				conds = append(conds, "target_id IN (SELECT id FROM targets WHERE owner_id = ?)")
			}
			args = append(args, uid)
		}
		sql := "SELECT COUNT(*) FROM " + q.table
		if len(conds) > 0 {
			sql += " WHERE " + strings.Join(conds, " AND ")
		}
		h.db.QueryRowContext(r.Context(), sql, args...).Scan(q.dest)
	}

	h.writeSuccess(w, stats)
}

func (h *Handler) handleDashboardCharts(w http.ResponseWriter, r *http.Request) {
	charts := map[string]any{}

	// Per-user isolation: a member's charts cover ONLY their own targets.
	uid, isAdmin := h.callerScope(r)
	ownerT, ownerC := "", "" // targets-table clause, child-table (target_id) clause
	var aT, aC []any
	if !isAdmin {
		ownerT = " WHERE owner_id = ?"
		aT = []any{uid}
		ownerC = " AND target_id IN (SELECT id FROM targets WHERE owner_id = ?)"
		aC = []any{uid}
	}

	// Top targets by FINDINGS (what a hunter cares about most), with id so the UI
	// can deep-link, plus kind for the web/network/mixed chip.
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT id, domain, COALESCE(name,''), COALESCE(kind,'web'), subdomain_count, alive_host_count, finding_count
		FROM targets `+ownerT+` ORDER BY finding_count DESC, subdomain_count DESC LIMIT 10
	`, aT...)
	if err == nil {
		defer rows.Close()
		var targetData []map[string]any
		for rows.Next() {
			var id, domain, name, kind string
			var subCount, aliveCount, findingCount int
			if err := rows.Scan(&id, &domain, &name, &kind, &subCount, &aliveCount, &findingCount); err == nil {
				targetData = append(targetData, map[string]any{
					"id": id, "domain": domain, "name": name, "kind": kind,
					"subdomains": subCount, "alive_hosts": aliveCount, "findings": findingCount,
				})
			}
		}
		charts["top_targets"] = targetData
	}

	// Findings by severity — COMBINED across nuclei + native vuln findings (only
	// promoted findings, not candidates), normalized to the standard tiers.
	sev := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	countSev := func(query string, args ...any) {
		sr, e := h.db.QueryContext(r.Context(), query, args...)
		if e != nil {
			return
		}
		defer sr.Close()
		for sr.Next() {
			var s string
			var c int
			if sr.Scan(&s, &c) == nil {
				s = strings.ToLower(strings.TrimSpace(s))
				if _, ok := sev[s]; !ok {
					s = "info"
				}
				sev[s] += c
			}
		}
	}
	countSev(`SELECT severity, COUNT(*) FROM nuclei_findings WHERE COALESCE(verification,'unverified') != 'rejected'`+ownerC+` GROUP BY severity`, aC...)
	countSev(`SELECT severity, COUNT(*) FROM vuln_findings WHERE COALESCE(status,'finding')='finding'`+ownerC+` GROUP BY severity`, aC...)
	sevData := make([]map[string]any, 0, 5)
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		sevData = append(sevData, map[string]any{"severity": s, "count": sev[s]})
	}
	charts["severity_breakdown"] = sevData

	// Vulnerabilities by TYPE (native vuln findings), top classes.
	typeRows, err := h.db.QueryContext(r.Context(), `
		SELECT type, COUNT(*) c FROM vuln_findings WHERE COALESCE(status,'finding')='finding'`+ownerC+`
		GROUP BY type ORDER BY c DESC LIMIT 8
	`, aC...)
	if err == nil {
		defer typeRows.Close()
		var typeData []map[string]any
		for typeRows.Next() {
			var typ string
			var c int
			if typeRows.Scan(&typ, &c) == nil {
				typeData = append(typeData, map[string]any{"type": typ, "count": c})
			}
		}
		charts["vuln_by_type"] = typeData
	}

	// Scans over time (last 30 days)
	timeRows, err := h.db.QueryContext(r.Context(), `
		SELECT date(created_at), COUNT(*) FROM tasks
		WHERE created_at >= datetime('now', '-30 days')`+ownerC+`
		GROUP BY date(created_at) ORDER BY date(created_at)
	`, aC...)
	if err == nil {
		defer timeRows.Close()
		var timeData []map[string]any
		for timeRows.Next() {
			var date string
			var count int
			if err := timeRows.Scan(&date, &count); err == nil {
				timeData = append(timeData, map[string]any{"date": date, "scans": count})
			}
		}
		charts["scans_over_time"] = timeData
	}

	h.writeSuccess(w, charts)
}

func (h *Handler) handleListTasks(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	status := q.Get("status")
	targetID := q.Get("target_id")
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	limit := 50
	offset := (page - 1) * limit

	query := `SELECT t.id, t.target_id, t.type, t.status, t.priority, t.progress, t.total,
		t.current_module, COALESCE(t.eta_seconds,0), COALESCE(t.module_eta_seconds,0), t.modules, COALESCE(t.completed_modules,'[]'), t.error, t.started_at, t.finished_at, t.created_at, t.updated_at,
		tgt.domain, COALESCE(tgt.name,'')
		FROM tasks t JOIN targets tgt ON tgt.id = t.target_id
		WHERE 1=1`
	args := []any{}

	// Per-user isolation: a member sees only tasks for their own targets.
	if uid, isAdmin := h.callerScope(r); !isAdmin {
		query += " AND tgt.owner_id = ?"
		args = append(args, uid)
	}

	if status != "" {
		query += " AND t.status = ?"
		args = append(args, status)
	}
	if targetID != "" {
		query += " AND t.target_id = ?"
		args = append(args, targetID)
	}

	query += " ORDER BY t.created_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := h.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	tasks := make([]models.Task, 0)
	for rows.Next() {
		var t models.Task
		var startedAt, finishedAt *string
		var modulesJSON, completedJSON string
		err := rows.Scan(&t.ID, &t.TargetID, &t.Type, &t.Status, &t.Priority,
			&t.Progress, &t.Total, &t.CurrentModule, &t.EtaSeconds, &t.ModuleEtaSeconds, &modulesJSON, &completedJSON, &t.Error,
			&startedAt, &finishedAt, &t.CreatedAt, &t.UpdatedAt, &t.TargetDomain, &t.Name)
		if err != nil {
			continue
		}
		t.Modules = models.JSONToStringSlice(modulesJSON)
		t.CompletedModules = models.JSONToStringSlice(completedJSON)

		if startedAt != nil && *startedAt != "" {
			parsed, _ := time.Parse("2006-01-02T15:04:05Z", *startedAt)
			t.StartedAt = &parsed
		}
		if finishedAt != nil && *finishedAt != "" {
			parsed, _ := time.Parse("2006-01-02T15:04:05Z", *finishedAt)
			t.FinishedAt = &parsed
		}

		tasks = append(tasks, t)
	}

	h.writeSuccess(w, tasks)
}

func (h *Handler) handleGetTask(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	var t models.Task
	var startedAt, finishedAt *string
	var modulesJSON, completedJSON string

	err := h.db.QueryRowContext(r.Context(), `
		SELECT t.id, t.target_id, t.type, t.status, t.priority, t.progress, t.total,
			t.current_module, COALESCE(t.eta_seconds,0), COALESCE(t.module_eta_seconds,0), t.modules, COALESCE(t.completed_modules,'[]'), t.error, t.started_at, t.finished_at, t.created_at, t.updated_at,
			tgt.domain, COALESCE(tgt.name,'')
		FROM tasks t JOIN targets tgt ON tgt.id = t.target_id WHERE t.id = ?
	`, id).Scan(&t.ID, &t.TargetID, &t.Type, &t.Status, &t.Priority,
		&t.Progress, &t.Total, &t.CurrentModule, &t.EtaSeconds, &t.ModuleEtaSeconds, &modulesJSON, &completedJSON, &t.Error,
		&startedAt, &finishedAt, &t.CreatedAt, &t.UpdatedAt, &t.TargetDomain, &t.Name)
	if err != nil {
		h.writeError(w, http.StatusNotFound, "task not found")
		return
	}

	t.Modules = models.JSONToStringSlice(modulesJSON)
	t.CompletedModules = models.JSONToStringSlice(completedJSON)
	if startedAt != nil {
		parsed, _ := time.Parse("2006-01-02T15:04:05Z", *startedAt)
		t.StartedAt = &parsed
	}
	if finishedAt != nil {
		parsed, _ := time.Parse("2006-01-02T15:04:05Z", *finishedAt)
		t.FinishedAt = &parsed
	}

	h.writeSuccess(w, t)
}

// handleUpdateNucleiTemplates triggers NucleiScanner.UpdateTemplates in the
// background: `nuclei -update-templates` for the standard store PLUS cloning
// the official nuclei-templates and fuzzing-templates repos into
// cfg.NucleiTemplates (see nuclei.go's syncExtraTemplates) — the "10x more
// injection-class template coverage" pass. This was previously unreachable
// dead code (no API route, no scheduled job, no UI button ever called it).
// Runs async since a full-repo clone can take a while; progress is broadcast
// over the websocket hub the same way task logs are, under module
// "nuclei_templates", so the frontend can show it without a dedicated poll.
func (h *Handler) handleUpdateNucleiTemplates(w http.ResponseWriter, r *http.Request) {
	if !h.sched.GetExecutor().IsToolAvailable("nuclei") {
		h.writeError(w, http.StatusConflict, "nuclei is not installed")
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		logFn := func(level, module, message string) {
			h.hub.Broadcast("system_log", map[string]any{
				"level": level, "module": module, "message": message, "time": time.Now().Format(time.RFC3339),
			})
		}
		ns := scanner.NewNucleiScanner(h.db, h.sched.GetExecutor(), h.cfg, h.logger)
		if err := ns.UpdateTemplates(ctx, logFn); err != nil {
			logFn("error", "nuclei_templates", "Update failed: "+err.Error())
		}
		// Explicit completion marker — without this, nothing ever told the
		// frontend "it's actually done" and its spinner just guessed with a
		// fixed timer (which could clear WHILE the sync was still running).
		logFn("info", "nuclei_templates", "Template sync complete.")
	}()
	h.writeSuccess(w, map[string]string{"message": "Template update started in the background — watch for nuclei_templates log lines."})
}

func (h *Handler) handleCancelTask(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := h.sched.CancelTask(id); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to cancel task")
		return
	}
	h.writeSuccess(w, map[string]string{"message": "task cancelled"})
}

// handleResumeTask creates a NEW task covering only the modules a failed/
// cancelled task never finished (see Scheduler.ResumeTask) — the fix for
// "an 8h watchdog killed a huge scan most of the way through, don't make me
// start over from zero."
func (h *Handler) handleResumeTask(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	newTask, err := h.sched.ResumeTask(id)
	if err != nil {
		if errors.Is(err, scheduler.ErrNothingToResume) {
			h.writeError(w, http.StatusConflict, err.Error())
			return
		}
		h.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.writeSuccess(w, newTask)
}

func (h *Handler) handleGetTaskLogs(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	since := r.URL.Query().Get("since")
	level := r.URL.Query().Get("level")

	query := `SELECT id, task_id, level, message, module, created_at
		FROM task_logs WHERE task_id = ?`
	args := []any{id}

	if since != "" {
		var sinceID int
		if n, err := strconv.Atoi(since); err == nil {
			sinceID = n
		}
		if sinceID > 0 {
			query += " AND id > ?"
			args = append(args, sinceID)
		}
	}

	if level != "" {
		query += " AND level = ?"
		args = append(args, level)
	}

	query += " ORDER BY id ASC LIMIT 1000"

	rows, err := h.db.QueryContext(r.Context(), query, args...)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	logs := make([]models.TaskLog, 0)
	for rows.Next() {
		var l models.TaskLog
		err := rows.Scan(&l.ID, &l.TaskID, &l.Level, &l.Message, &l.Module, &l.CreatedAt)
		if err == nil {
			logs = append(logs, l)
		}
	}

	h.writeSuccess(w, logs)
}

func (h *Handler) handleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		h.writeSuccess(w, map[string]any{})
		return
	}

	like := "%" + query + "%"
	results := map[string]any{}

	// Search targets
	targetRows, err := h.db.QueryContext(r.Context(), `
		SELECT id, domain, description FROM targets WHERE domain LIKE ? OR description LIKE ? LIMIT 10
	`, like, like)
	if err == nil {
		defer targetRows.Close()
		var targets []map[string]string
		for targetRows.Next() {
			var id, domain, desc string
			if err := targetRows.Scan(&id, &domain, &desc); err == nil {
				targets = append(targets, map[string]string{"id": id, "domain": domain, "description": desc})
			}
		}
		results["targets"] = targets
	}

	// Search subdomains
	subRows, err := h.db.QueryContext(r.Context(), `
		SELECT s.id, s.subdomain, s.ip, t.domain as target_domain
		FROM subdomains s JOIN targets t ON t.id = s.target_id
		WHERE s.subdomain LIKE ? LIMIT 20
	`, like)
	if err == nil {
		defer subRows.Close()
		var subs []map[string]string
		for subRows.Next() {
			var id, subdomain, ip, targetDomain string
			if err := subRows.Scan(&id, &subdomain, &ip, &targetDomain); err == nil {
				subs = append(subs, map[string]string{
					"id": id, "subdomain": subdomain, "ip": ip, "target_domain": targetDomain,
				})
			}
		}
		results["subdomains"] = subs
	}

	// Search nuclei findings
	nucleiRows, err := h.db.QueryContext(r.Context(), `
		SELECT n.id, n.template_name, n.severity, n.matched_url, t.domain
		FROM nuclei_findings n JOIN targets t ON t.id = n.target_id
		WHERE n.template_name LIKE ? OR n.matched_url LIKE ? OR n.description LIKE ? LIMIT 20
	`, like, like, like)
	if err == nil {
		defer nucleiRows.Close()
		var findings []map[string]string
		for nucleiRows.Next() {
			var id, name, sev, url, domain string
			if err := nucleiRows.Scan(&id, &name, &sev, &url, &domain); err == nil {
				findings = append(findings, map[string]string{
					"id": id, "name": name, "severity": sev, "url": url, "domain": domain,
				})
			}
		}
		results["nuclei_findings"] = findings
	}

	h.writeSuccess(w, results)
}

func (h *Handler) handleToolStatus(w http.ResponseWriter, r *http.Request) {
	tools := h.sched.ExpectedTools()

	status := make(map[string]bool)
	for _, tool := range tools {
		status[tool] = h.sched.GetExecutor().IsToolAvailable(tool)
	}

	h.writeSuccess(w, status)
}

func (h *Handler) handleSystemStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]any{}

	vm, err := mem.VirtualMemory()
	if err == nil {
		stats["memory_total_mb"] = vm.Total / 1024 / 1024
		stats["memory_used_mb"] = vm.Used / 1024 / 1024
		stats["memory_free_mb"] = vm.Free / 1024 / 1024
		stats["memory_percent"] = vm.UsedPercent
	}

	cpuPercent, err := cpu.Percent(0, false)
	if err == nil && len(cpuPercent) > 0 {
		stats["cpu_percent"] = cpuPercent[0]
	}

	stats["goroutines"] = runtime.NumGoroutine()
	stats["ws_clients"] = h.hub.ClientCount()
	stats["running_tasks"] = len(h.sched.GetRunningTasks())

	h.writeSuccess(w, stats)
}
