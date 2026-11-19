package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// ChangeEntry is one row in the unified Changes feed. The four sources are
// tagged so the UI can show a Watch / Deep / Scope / Bell badge.
type ChangeEntry struct {
	ID         string         `json:"id"`
	Source     string         `json:"source"` // monitor | watch | scope | notification
	TargetID   string         `json:"target_id"`
	TargetName string         `json:"target_name"`
	TaskID     string         `json:"task_id,omitempty"`
	URL        string         `json:"url"`
	ChangeType string         `json:"change_type"`
	Category   string         `json:"category"`
	Severity   string         `json:"severity"`
	OldValue   string         `json:"old_value"`
	NewValue   string         `json:"new_value"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	Seen       bool           `json:"seen"`
	DetectedAt string         `json:"detected_at"`
}

// WatchRound is one finished or running watch task for the round filter strip.
type WatchRound struct {
	ID          string `json:"id"`
	TargetID    string `json:"target_id"`
	TargetName  string `json:"target_name"`
	Status      string `json:"status"`
	Error       string `json:"error"`
	StartedAt   string `json:"started_at"`
	FinishedAt  string `json:"finished_at"`
	ChangeCount int    `json:"change_count"`
}

// changeCategoryExpr keeps the API taxonomy in one place. Header changes win
// over generic security changes, which matches the existing monitorRowKind
// order in the frontend.
func changeCategoryExpr(col string) string {
	return `CASE
		WHEN ` + col + ` IN ('status_change','http_change','http_service_removed','new_http_service','page_change') THEN 'http'
		WHEN ` + col + ` IN ('js_change','css_change')
		     OR ` + col + ` LIKE 'security:script_%'
		     OR ` + col + ` LIKE 'security:stylesheet_%' THEN 'scripts'
		WHEN ` + col + ` LIKE '%header%' THEN 'headers'
		WHEN ` + col + ` LIKE 'security:%' THEN 'security'
		WHEN ` + col + ` = 'tech_change' THEN 'tech'
		WHEN ` + col + ` IN ('new_subdomain','subdomain_removed','host_status_change','scope_landed','scope_re_eligible') THEN 'assets'
		WHEN ` + col + ` IN ('watch_failed','watch_kind_conflict','monitor_failed','monitor_escalation_started','scan_auto_paused') THEN 'alerts'
		ELSE 'http' END`
}

func changesPagination(r *http.Request) (page, limit, offset int) {
	q := r.URL.Query()
	page, _ = strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	limit, _ = strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	return page, limit, (page - 1) * limit
}

func parseChangesSince(raw string) string {
	if raw == "" {
		return ""
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC().Format("2006-01-02 15:04:05")
	}
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.Format("2006-01-02 15:04:05")
		}
	}
	return raw
}

// changesFeedQuery builds the four-source UNION and the shared WHERE clause.
// ownerArgs are the owner-scope placeholders inside the UNION; filterArgs are
// the placeholders in the WHERE clause. Read state is joined by the caller so
// count queries stay cheap.
func (h *Handler) changesFeedQuery(r *http.Request, forcedTargetID string) (inner, whereSQL string, ownerArgs, filterArgs []any) {
	q := r.URL.Query()
	uid, isAdmin := h.callerScope(r)

	args := make([]any, 0, 8)
	sourceMonitor := `SELECT mc.id, 'monitor' AS source, mc.target_id, COALESCE(t.domain,'') AS target_name, '' AS task_id,
		COALESCE(mc.url,'') AS url, mc.change_type, ` + changeCategoryExpr("mc.change_type") + ` AS category,
		COALESCE(mc.severity,'info') AS severity, COALESCE(mc.old_value,'') AS old_value,
		COALESCE(mc.new_value,'') AS new_value, '{}' AS metadata,
		COALESCE(mc.detected_at,'') AS detected_at
		FROM monitoring_changes mc JOIN targets t ON t.id=mc.target_id WHERE 1=1`
	if !isAdmin {
		sourceMonitor += ` AND t.owner_id=?`
		args = append(args, uid)
	}

	sourceWatch := `SELECT wc.id, 'watch' AS source, wc.target_id, COALESCE(t.domain,'') AS target_name,
		COALESCE(wc.task_id,'') AS task_id,
		COALESCE(wc.url,'') AS url, wc.change_type, ` + changeCategoryExpr("wc.change_type") + ` AS category,
		COALESCE(wc.severity,'info') AS severity, COALESCE(wc.old_value,'') AS old_value,
		COALESCE(wc.new_value,'') AS new_value, COALESCE(wc.metadata,'{}') AS metadata,
		COALESCE(wc.detected_at,'') AS detected_at
		FROM watch_round_changes wc JOIN targets t ON t.id=wc.target_id WHERE 1=1`
	if !isAdmin {
		sourceWatch += ` AND t.owner_id=?`
		args = append(args, uid)
	}

	scopeType := `CASE WHEN se.event_type='landed' THEN 'scope_landed'
		WHEN se.event_type='re_eligible' THEN 'scope_re_eligible'
		ELSE COALESCE(se.event_type,'') END`
	sourceScope := `SELECT se.id, 'scope' AS source, se.target_id, COALESCE(t.domain,'') AS target_name, '' AS task_id,
		COALESCE(se.identifier,'') AS url, ` + scopeType + ` AS change_type, ` + changeCategoryExpr(scopeType) + ` AS category,
		'info' AS severity, '' AS old_value, COALESCE(se.identifier,'') AS new_value,
		COALESCE(se.metadata,'{}') AS metadata, COALESCE(se.detected_at,'') AS detected_at
		FROM watch_scope_events se JOIN targets t ON t.id=se.target_id WHERE 1=1`
	if !isAdmin {
		sourceScope += ` AND t.owner_id=?`
		args = append(args, uid)
	}

	sourceNotification := `SELECT n.id, 'notification' AS source, COALESCE(n.target_id,'') AS target_id,
		COALESCE(t.domain,'') AS target_name, '' AS task_id,
		COALESCE(n.url,'') AS url, COALESCE(n.type,'') AS change_type,
		` + changeCategoryExpr("n.type") + ` AS category,
		COALESCE(n.severity,'info') AS severity, '' AS old_value, COALESCE(n.body,'') AS new_value,
		COALESCE(n.metadata,'{}') AS metadata, COALESCE(n.created_at,'') AS detected_at
		FROM notifications n LEFT JOIN targets t ON t.id=n.target_id
		WHERE COALESCE(n.type,'') <> 'scope_landed'`
	if !isAdmin {
		// Keep target-less notices visible, as the bell does.
		sourceNotification += ` AND (COALESCE(n.target_id,'')='' OR t.owner_id=?)`
		args = append(args, uid)
	}

	unionSQL := `( ` + sourceMonitor + ` UNION ALL ` + sourceWatch + ` UNION ALL ` +
		sourceScope + ` UNION ALL ` + sourceNotification + ` )`

	// Build derived status codes in a wrapper around the UNION. Source aliases
	// (mc/wc/se/n) differ and the sources are not uniform, so referencing x.*
	// inside a source would not compile. Only real change rows whose type
	// carries a status transition are parsed. Bell rows are excluded even when
	// their type matches: a notification mirrors a deep change with the same
	// type and a body that repeats the "status=NNN " text, so parsing it would
	// create a duplicate of the real change. The trailing-space check prevents
	// a value like "status=2000x" from parsing as 200.
	inner = `(
		SELECT u.*,
			` + changesStatusCodeExpr("u.change_type", "u.source", "u.old_value") + ` AS status_old,
			` + changesStatusCodeExpr("u.change_type", "u.source", "u.new_value") + ` AS status_new
		FROM ` + unionSQL + ` u
	) x`

	filters := make([]string, 0, 12)
	filterArgs = make([]any, 0, 12)
	targetID := forcedTargetID
	if targetID == "" {
		targetID = q.Get("target_id")
	}
	if targetID != "" {
		filters = append(filters, `x.target_id=?`)
		filterArgs = append(filterArgs, targetID)
	}

	// category accepts a comma list. "all" is dropped; all,http means http.
	// Unknown tokens are ignored. A non-empty value with no valid category
	// (for example ",,," or "garbage") matches nothing instead of silently
	// returning every category.
	if v := q.Get("category"); v != "" {
		validCategories := map[string]bool{
			"http": true, "scripts": true, "security": true, "tech": true,
			"headers": true, "assets": true, "alerts": true,
		}
		cats := make([]string, 0, 4)
		seenCat := map[string]bool{}
		hasAll := false
		for _, c := range strings.Split(v, ",") {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			if c == "all" {
				hasAll = true
				continue
			}
			if validCategories[c] && !seenCat[c] {
				seenCat[c] = true
				cats = append(cats, c)
			}
		}
		if len(cats) > 0 {
			ph := make([]string, len(cats))
			for i, c := range cats {
				ph[i] = "?"
				filterArgs = append(filterArgs, c)
			}
			filters = append(filters, `x.category IN (`+strings.Join(ph, ",")+`)`)
		} else if !hasAll {
			filters = append(filters, `1=0`)
		}
	}

	// Text search over the visible fields. LIKE wildcards in user input are
	// escaped so they stay literal.
	if v := strings.TrimSpace(q.Get("q")); v != "" {
		escaped := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(v)
		like := "%" + escaped + "%"
		filters = append(filters, `(x.url LIKE ? ESCAPE '\' OR x.target_name LIKE ? ESCAPE '\' OR x.change_type LIKE ? ESCAPE '\' OR x.old_value LIKE ? ESCAPE '\' OR x.new_value LIKE ? ESCAPE '\')`)
		for i := 0; i < 5; i++ {
			filterArgs = append(filterArgs, like)
		}
	}

	if v := q.Get("severity"); v != "" {
		filters = append(filters, `x.severity=?`)
		filterArgs = append(filterArgs, v)
	}
	if v := q.Get("source"); v != "" {
		filters = append(filters, `x.source=?`)
		filterArgs = append(filterArgs, v)
	}
	if v := q.Get("task_id"); v != "" {
		filters = append(filters, `x.task_id=?`)
		filterArgs = append(filterArgs, v)
	}
	if since := parseChangesSince(q.Get("since")); since != "" {
		filters = append(filters, `x.detected_at>=?`)
		filterArgs = append(filterArgs, since)
	}

	// A status-only row is a real transition: both codes valid and different.
	// The type and source guards live in changesStatusCodeExpr, which builds
	// the derived codes used here and in the class/code filters below.
	if q.Get("status_only") == "1" {
		filters = append(filters, `x.status_old BETWEEN 100 AND 599 AND x.status_new BETWEEN 100 AND 599
			AND x.status_old <> x.status_new AND x.change_type <> 'http_service_removed'`)
	}

	// status_class matches when either code falls in a requested class.
	if v := q.Get("status_class"); v != "" {
		seen := map[string]bool{}
		classes := make([]string, 0, 4)
		for _, c := range strings.Split(v, ",") {
			c = strings.TrimSpace(c)
			if (c == "2" || c == "3" || c == "4" || c == "5") && !seen[c] {
				seen[c] = true
				classes = append(classes, c)
			}
		}
		if len(classes) > 0 {
			parts := make([]string, 0, len(classes))
			for _, d := range classes {
				n, _ := strconv.Atoi(d)
				lo, hi := n*100, n*100+99
				parts = append(parts, `(x.status_old BETWEEN `+strconv.Itoa(lo)+` AND `+strconv.Itoa(hi)+
					` OR x.status_new BETWEEN `+strconv.Itoa(lo)+` AND `+strconv.Itoa(hi)+`)`)
			}
			filters = append(filters, `(x.status_old BETWEEN 100 AND 599 OR x.status_new BETWEEN 100 AND 599)
				AND (`+strings.Join(parts, " OR ")+`) AND x.change_type <> 'http_service_removed'`)
		}
	}

	// status_code matches an exact code on either side. Reject malformed or
	// out-of-range values instead of truncating or coercing them.
	if v := q.Get("status_code"); v != "" {
		codes := make([]any, 0, 8)
		seen := map[int]bool{}
		for _, c := range strings.Split(v, ",") {
			n, ok := statusCodeToken(strings.TrimSpace(c))
			if ok && !seen[n] {
				seen[n] = true
				codes = append(codes, n)
			}
		}
		if len(codes) > 0 {
			ph := make([]string, len(codes))
			for i := range codes {
				ph[i] = "?"
			}
			joined := strings.Join(ph, ",")
			filters = append(filters, `(x.status_old IN (`+joined+`) OR x.status_new IN (`+joined+`))
				AND x.change_type <> 'http_service_removed'`)
			filterArgs = append(filterArgs, codes...)
			filterArgs = append(filterArgs, codes...)
		}
	}

	if len(filters) > 0 {
		whereSQL = ` WHERE ` + strings.Join(filters, ` AND `)
	}
	return inner, whereSQL, args, filterArgs
}

// changesStatusCodeExpr parses the "status=NNN " prefix from a value column.
// Watch writes status_change and deep writes http_change/page_change; those
// are the only types that carry a status transition. Bell rows are excluded:
// a notification mirrors a deep change with the same type and repeats the
// token in its body, so parsing it would duplicate the real change. Other
// free-text rows (alerts, scope events) are already outside the type list.
// No metadata/JSON path is needed.
func changesStatusCodeExpr(typeCol, sourceCol, col string) string {
	return `CASE WHEN ` + typeCol + ` IN ('status_change','http_change','page_change')
		AND ` + sourceCol + ` <> 'notification'
		AND instr(` + col + `,'status=') > 0
		AND substr(` + col + `, instr(` + col + `,'status=')+10, 1) = ' '
		THEN CAST(substr(` + col + `, instr(` + col + `,'status=')+7, 3) AS INTEGER)
		ELSE 0 END`
}

// statusCodeToken accepts exactly three digits in the HTTP range. This matches
// the frontend's ^[1-5][0-9]{2}$ rule, so "+200" and "0200" are not silently
// accepted by the API but rejected by the UI.
func statusCodeToken(s string) (int, bool) {
	if len(s) != 3 || s[0] < '1' || s[0] > '5' {
		return 0, false
	}
	for i := 1; i < 3; i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, _ := strconv.Atoi(s)
	return n, true
}

func (h *Handler) handleListChanges(w http.ResponseWriter, r *http.Request) {
	h.listChanges(w, r, "")
}

func (h *Handler) handleListTargetChanges(w http.ResponseWriter, r *http.Request) {
	h.listChanges(w, r, mux.Vars(r)["id"])
}

func (h *Handler) listChanges(w http.ResponseWriter, r *http.Request, forcedTargetID string) {
	page, limit, offset := changesPagination(r)
	uid, _ := h.callerScope(r)
	inner, whereSQL, ownerArgs, filterArgs := h.changesFeedQuery(r, forcedTargetID)

	countArgs := append(append([]any{}, ownerArgs...), filterArgs...)
	var total int
	if err := h.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM `+inner+whereSQL, countArgs...).Scan(&total); err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}

	// Read state is per user. Join it after the UNION so one small table serves
	// all four sources and each caller sees only their own marks.
	dataArgs := append(append([]any{}, ownerArgs...), uid)
	dataArgs = append(dataArgs, filterArgs...)
	dataArgs = append(dataArgs, limit, offset)
	rows, err := h.db.QueryContext(r.Context(), `SELECT x.id, x.source, x.target_id, x.target_name, x.task_id,
		x.url, x.change_type, x.category, x.severity, x.old_value, x.new_value, x.metadata, x.detected_at,
		CASE WHEN cs.change_id IS NULL THEN 0 ELSE 1 END AS seen
		FROM `+inner+` LEFT JOIN change_seen cs ON cs.change_id=x.id AND cs.user_id=? `+
		whereSQL+` ORDER BY x.detected_at DESC, x.id DESC LIMIT ? OFFSET ?`, dataArgs...)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	entries := make([]ChangeEntry, 0)
	for rows.Next() {
		var e ChangeEntry
		var metadata string
		if err := rows.Scan(&e.ID, &e.Source, &e.TargetID, &e.TargetName, &e.TaskID,
			&e.URL, &e.ChangeType, &e.Category, &e.Severity, &e.OldValue, &e.NewValue,
			&metadata, &e.DetectedAt, &e.Seen); err != nil {
			h.writeError(w, http.StatusInternalServerError, "scan failed")
			return
		}
		e.Metadata = map[string]any{}
		if metadata != "" {
			_ = json.Unmarshal([]byte(metadata), &e.Metadata)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{
		"data": entries, "total": total, "page": page, "limit": limit,
	})
}

// handleSetChangesSeen marks a bounded set of change rows read or unread for
// the current user. Change ids are unique across all four feed sources.
func (h *Handler) handleSetChangesSeen(w http.ResponseWriter, r *http.Request) {
	uid, _ := h.callerScope(r)
	var body struct {
		IDs  []string `json:"ids"`
		Seen bool     `json:"seen"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if len(body.IDs) == 0 || len(body.IDs) > 500 {
		h.writeError(w, http.StatusBadRequest, "ids must contain 1 to 500 entries")
		return
	}

	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "transaction failed")
		return
	}
	defer tx.Rollback()

	query := `DELETE FROM change_seen WHERE change_id=? AND user_id=?`
	if body.Seen {
		query = `INSERT OR IGNORE INTO change_seen(change_id,user_id,seen_at) VALUES(?,?,CURRENT_TIMESTAMP)`
	}
	stmt, err := tx.PrepareContext(r.Context(), query)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "prepare failed")
		return
	}
	defer stmt.Close()

	for _, id := range body.IDs {
		if id == "" {
			continue
		}
		if _, err := stmt.ExecContext(r.Context(), id, uid); err != nil {
			h.writeError(w, http.StatusInternalServerError, "update failed")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		h.writeError(w, http.StatusInternalServerError, "commit failed")
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"updated": len(body.IDs)})
}

// handleMarkAllChangesSeen marks every row matching the current feed filters
// read for the current user. It uses the same UNION and filters as the list,
// so "Mark all read" honours the active target, time, and category filters.
func (h *Handler) handleMarkAllChangesSeen(w http.ResponseWriter, r *http.Request) {
	uid, _ := h.callerScope(r)
	inner, whereSQL, ownerArgs, filterArgs := h.changesFeedQuery(r, "")
	queryArgs := append([]any{uid}, ownerArgs...)
	queryArgs = append(queryArgs, filterArgs...)

	res, err := h.db.ExecContext(r.Context(), `INSERT OR IGNORE INTO change_seen(change_id,user_id,seen_at)
		SELECT x.id, ?, CURRENT_TIMESTAMP FROM `+inner+whereSQL, queryArgs...)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	updated, _ := res.RowsAffected()
	h.writeJSON(w, http.StatusOK, map[string]any{"updated": updated})
}

func (h *Handler) handleListWatchRounds(w http.ResponseWriter, r *http.Request) {
	page, limit, offset := changesPagination(r)
	q := r.URL.Query()
	uid, isAdmin := h.callerScope(r)

	// Watch tasks are pruned at 90 days, but their change rows live for 180.
	// Build rounds from two sources so old change rows still have a timeline:
	//  1. real watch_scan task rows;
	//  2. distinct task_ids that exist only in watch_round_changes.
	// NOT EXISTS keeps the two sources from emitting the same round twice.
	unionSQL := `SELECT t.id AS id, t.target_id AS target_id, COALESCE(tg.domain,'') AS target_name,
		COALESCE(t.status,'') AS status, COALESCE(t.error,'') AS error,
		COALESCE(t.started_at,'') AS started_at, COALESCE(t.finished_at,'') AS finished_at,
		tg.owner_id AS owner_id, COALESCE(t.started_at,t.created_at) AS sort_at,
		(SELECT COUNT(*) FROM watch_round_changes wc WHERE wc.task_id=t.id) AS change_count
		FROM tasks t JOIN targets tg ON tg.id=t.target_id WHERE t.type='watch_scan'
		UNION ALL
		SELECT wc.task_id AS id, wc.target_id AS target_id, COALESCE(tg.domain,'') AS target_name,
		'finished' AS status, '' AS error,
		MIN(COALESCE(wc.detected_at,'')) AS started_at,
		MAX(COALESCE(wc.detected_at,'')) AS finished_at,
		tg.owner_id AS owner_id, MAX(COALESCE(wc.detected_at,'')) AS sort_at,
		COUNT(*) AS change_count
		FROM watch_round_changes wc JOIN targets tg ON tg.id=wc.target_id
		WHERE COALESCE(wc.task_id,'') <> ''
		  AND NOT EXISTS (SELECT 1 FROM tasks t2 WHERE t2.id=wc.task_id)
		GROUP BY wc.task_id, wc.target_id`

	whereSQL := ` WHERE 1=1`
	args := make([]any, 0, 3)
	if !isAdmin {
		whereSQL += ` AND owner_id=?`
		args = append(args, uid)
	}
	if targetID := q.Get("target_id"); targetID != "" {
		whereSQL += ` AND target_id=?`
		args = append(args, targetID)
	}

	fromRounds := ` FROM (` + unionSQL + `) rounds` + whereSQL

	var total int
	if err := h.db.QueryRowContext(r.Context(), `SELECT COUNT(*)`+fromRounds, args...).Scan(&total); err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}

	queryArgs := append(append([]any{}, args...), limit, offset)
	rows, err := h.db.QueryContext(r.Context(), `SELECT id, target_id, target_name, status, error,
		started_at, finished_at, change_count`+fromRounds+`
		ORDER BY sort_at DESC, id DESC LIMIT ? OFFSET ?`, queryArgs...)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	rounds := make([]WatchRound, 0)
	for rows.Next() {
		var round WatchRound
		if err := rows.Scan(&round.ID, &round.TargetID, &round.TargetName, &round.Status,
			&round.Error, &round.StartedAt, &round.FinishedAt, &round.ChangeCount); err != nil {
			h.writeError(w, http.StatusInternalServerError, "scan failed")
			return
		}
		rounds = append(rounds, round)
	}
	if err := rows.Err(); err != nil {
		h.writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{
		"data": rounds, "total": total, "page": page, "limit": limit,
	})
}
