package api

import (
	"encoding/json"
	"net/http"
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
	rows, err := h.db.QueryContext(r.Context(), `
		SELECT id, COALESCE(target_id,''), type, title, COALESCE(body,''), COALESCE(url,''),
		       COALESCE(severity,'info'), COALESCE(is_read,0), created_at
		FROM notifications
		ORDER BY created_at DESC
		LIMIT 100`)
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

	var unread int
	_ = h.db.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM notifications WHERE COALESCE(is_read,0)=0").Scan(&unread)

	h.writeSuccess(w, map[string]any{"notifications": items, "unread": unread})
}

// handleMarkNotificationsRead marks notifications read. With an "ids" list it
// marks those; with no body (or empty ids) it marks ALL as read.
func (h *Handler) handleMarkNotificationsRead(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []string `json:"ids"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	if len(req.IDs) == 0 {
		_, _ = h.db.ExecContext(r.Context(), "UPDATE notifications SET is_read=1 WHERE COALESCE(is_read,0)=0")
		h.writeSuccess(w, map[string]string{"message": "all marked read"})
		return
	}
	for _, id := range req.IDs {
		_, _ = h.db.ExecContext(r.Context(), "UPDATE notifications SET is_read=1 WHERE id=?", id)
	}
	h.writeSuccess(w, map[string]string{"message": "marked read"})
}
