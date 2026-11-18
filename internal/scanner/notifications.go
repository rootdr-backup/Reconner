package scanner

import (
	"github.com/google/uuid"
	"github.com/recon-platform/internal/database"
)

// notify persists an operator-facing notification (rendered in the bell menu).
// Best-effort: a failed insert never breaks the scan that raised it. Callers are
// responsible for only raising HIGH-SIGNAL events (a real, deduped change) so the
// bell stays free of false positives.
func notify(db *database.DB, targetID, typ, title, body, url, severity string) {
	notifyWithMetadata(db, targetID, typ, title, body, url, severity, "{}")
}

// notifyWithMetadata persists an operator-facing notification together with a
// JSON metadata blob. Callers that need to keep structured details (for example
// the list of new subdomain host names) use this variant; the bell body stays a
// short human-readable summary. Best-effort: a failed insert never breaks the
// scan that raised it.
func notifyWithMetadata(db *database.DB, targetID, typ, title, body, url, severity, metadata string) {
	if severity == "" {
		severity = "info"
	}
	if metadata == "" {
		metadata = "{}"
	}
	_, _ = db.Exec(`
		INSERT INTO notifications (id, target_id, type, title, body, url, severity, is_read, metadata, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, CURRENT_TIMESTAMP)`,
		uuid.New().String(), targetID, typ, title, body, url, severity, metadata)
}
