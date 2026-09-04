package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

type notification struct {
	ID        string `json:"id"`
	TargetID  string `json:"target_id"`
	Type      string `json:"type"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	URL       string `json:"url"`
	Severity  string `json:"severity"`
	IsRead    bool   `json:"is_read"`
	CreatedAt string `json:"created_at"`
}

// handleListNotifications returns the most recent notifications plus the current
// unread count for the bell badge.
func (h *Handler) handleListNotifications(w http.ResponseWriter, r *http.Request) {
	uid, isAdmin := h.callerScope(r)
	scope := ""
	// New rows use per-user receipts. When no receipts exist at all for an older
	// notification, retain its legacy is_read value to avoid resurfacing history.
	readExpr := `CASE
		WHEN EXISTS(SELECT 1 FROM notification_reads mine WHERE mine.notification_id=n.id AND mine.user_id=?) THEN 1
		WHEN NOT EXISTS(SELECT 1 FROM notification_reads any_read WHERE any_read.notification_id=n.id) THEN COALESCE(n.is_read,0)
		ELSE 0 END`
	args := []any{uid}
	if !isAdmin {
		// Global (target-less) notices are shared; target notices belong only to
		// the target owner. The old global query leaked every member's findings.
		scope = ` WHERE (COALESCE(n.target_id,'')='' OR EXISTS(
			SELECT 1 FROM targets t WHERE t.id=n.target_id AND t.owner_id=?))`
		args = append(args, uid)
	}
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT id, COALESCE(target_id,''), type, title, COALESCE(body,''), COALESCE(url,''),
		       COALESCE(severity,'info'), `+readExpr+`, created_at
		FROM notifications n`+scope+`
		ORDER BY created_at DESC
		LIMIT 100`, args...)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to query notifications")
		return
	}
	defer rows.Close()

	items := make([]notification, 0)
	for rows.Next() {
		var n notification
		var read int
		if rows.Scan(&n.ID, &n.TargetID, &n.Type, &n.Title, &n.Body, &n.URL, &n.Severity, &read, &n.CreatedAt) == nil {
			n.IsRead = read == 1
			items = append(items, n)
		}
	}
	if err := rows.Err(); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to read notifications")
		return
	}

	var unread int
	unreadQuery := `SELECT COUNT(*) FROM notifications n WHERE (` + readExpr + `)=0`
	unreadArgs := []any{uid}
	if !isAdmin {
		unreadQuery += ` AND (COALESCE(n.target_id,'')='' OR EXISTS(
			SELECT 1 FROM targets t WHERE t.id=n.target_id AND t.owner_id=?))`
		unreadArgs = append(unreadArgs, uid)
	}
	if err := h.db.QueryRowContext(r.Context(), unreadQuery, unreadArgs...).Scan(&unread); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to count notifications")
		return
	}

	h.writeSuccess(w, map[string]any{"notifications": items, "unread": unread})
}

// handleMarkNotificationsRead marks notifications read. With an "ids" list it
// marks those; with no body (or empty ids) it marks ALL as read.
func (h *Handler) handleMarkNotificationsRead(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		h.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	uid, isAdmin := h.callerScope(r)
	ownerClause := ""
	ownerArgs := []any{}
	if !isAdmin {
		ownerClause = ` AND (COALESCE(n.target_id,'')='' OR EXISTS(
			SELECT 1 FROM targets t WHERE t.id=n.target_id AND t.owner_id=?))`
		ownerArgs = append(ownerArgs, uid)
	}

	if len(req.IDs) == 0 {
		args := append([]any{uid}, ownerArgs...)
		if _, err := h.db.ExecContext(r.Context(), `INSERT OR IGNORE INTO notification_reads(notification_id,user_id,read_at)
			SELECT n.id,?,CURRENT_TIMESTAMP FROM notifications n WHERE 1=1`+ownerClause, args...); err != nil {
			h.writeError(w, http.StatusInternalServerError, "failed to mark notifications read")
			return
		}
		h.writeSuccess(w, map[string]string{"message": "all marked read"})
		return
	}
	seen := map[string]bool{}
	ids := make([]string, 0, len(req.IDs))
	for _, id := range req.IDs {
		id = strings.TrimSpace(id)
		if id != "" && !seen[id] && len(ids) < 100 {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		h.writeSuccess(w, map[string]string{"message": "marked read"})
		return
	}
	marks := strings.TrimRight(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, 0, 1+len(ids)+len(ownerArgs))
	args = append(args, uid)
	for _, id := range ids {
		args = append(args, id)
	}
	args = append(args, ownerArgs...)
	if _, err := h.db.ExecContext(r.Context(), `INSERT OR IGNORE INTO notification_reads(notification_id,user_id,read_at)
		SELECT n.id,?,CURRENT_TIMESTAMP FROM notifications n WHERE n.id IN (`+marks+`)`+ownerClause, args...); err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to mark notifications read")
		return
	}
	h.writeSuccess(w, map[string]string{"message": "marked read"})
}
