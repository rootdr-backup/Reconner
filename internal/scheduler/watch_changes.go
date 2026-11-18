package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/recon-platform/internal/database"
)

// watchSnapshotCap bounds the snapshot cost on very large projects. The watch
// tier must stay cheap. A capped snapshot still diffs the common window, so a
// status flip inside the window is kept. Removal rows are suppressed because a
// new row inside the window can evict the last row and look like a deletion.
const watchSnapshotCap = 5000

type watchHTTPSnapshot struct {
	URL          string
	StatusCode   int
	Title        string
	Server       string
	Technologies string
	RedirectURL  string
}

type watchChange struct {
	URL        string
	ChangeType string
	OldValue   string
	NewValue   string
	Severity   string
	Metadata   string // JSON object
}

func snapshotWatchHTTP(ctx context.Context, db *database.DB, targetID string) (map[string]watchHTTPSnapshot, error) {
	rows, err := db.QueryContext(ctx, `SELECT COALESCE(url,''), COALESCE(status_code,0),
		COALESCE(title,''), COALESCE(server,''), COALESCE(technologies,'[]'), COALESCE(redirect_url,'')
		FROM http_services WHERE target_id=? ORDER BY url LIMIT ?`, targetID, watchSnapshotCap)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]watchHTTPSnapshot)
	for rows.Next() {
		var h watchHTTPSnapshot
		var technologies string
		if err := rows.Scan(&h.URL, &h.StatusCode, &h.Title, &h.Server, &technologies, &h.RedirectURL); err != nil {
			return nil, err
		}
		h.Technologies = joinWatchTechnologies(technologies)
		out[h.URL] = h
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func snapshotWatchHosts(ctx context.Context, db *database.DB, targetID string) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT COALESCE(subdomain,''), COALESCE(is_alive,0)
		FROM subdomains WHERE target_id=? ORDER BY subdomain LIMIT ?`, targetID, watchSnapshotCap)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]bool)
	for rows.Next() {
		var host string
		var alive int
		if err := rows.Scan(&host, &alive); err != nil {
			return nil, err
		}
		out[host] = alive != 0
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func joinWatchTechnologies(raw string) string {
	var list []string
	if err := json.Unmarshal([]byte(raw), &list); err == nil {
		return strings.Join(list, ", ")
	}
	return strings.Trim(raw, "[]\"")
}

func watchStatusSeverity(oldCode, newCode int) string {
	old2xx := oldCode >= 200 && oldCode < 300
	new2xx := newCode >= 200 && newCode < 300
	if old2xx != new2xx {
		return "medium"
	}
	if (oldCode >= 300 && oldCode < 400) && newCode >= 500 {
		return "medium"
	}
	return "low"
}

func watchURLHost(raw string) string {
	parsed, err := url.Parse(raw)
	if err == nil && parsed.Hostname() != "" {
		return strings.ToLower(parsed.Hostname())
	}
	// Fall back to stripping the scheme for malformed rows.
	trimmed := raw
	if i := strings.Index(trimmed, "://"); i >= 0 {
		trimmed = trimmed[i+3:]
	}
	if i := strings.IndexAny(trimmed, "/:@?"); i >= 0 {
		trimmed = trimmed[:i]
	}
	return strings.ToLower(trimmed)
}

// diffWatchHTTP compares two HTTP snapshots. hostDiffRan reports whether a host
// snapshot covered this round; when it did not, a new URL on an unknown host is
// still a real exposure and must be emitted. capped reports a truncated
// snapshot: removal rows are suppressed because a new URL inside the window
// evicts the last URL and would be misread as a deletion.
func diffWatchHTTP(before, after map[string]watchHTTPSnapshot, hostDiffRan, capped bool) []watchChange {
	changes := make([]watchChange, 0)

	// Hosts that already had at least one probed service before this round.
	// A new URL on a known host is a real exposure change. A new URL on a
	// brand-new host is normally covered by the host snapshot and scope landing.
	knownHosts := make(map[string]bool, len(before))
	for raw := range before {
		knownHosts[watchURLHost(raw)] = true
	}

	for url := range before {
		if _, ok := after[url]; !ok {
			if capped {
				continue
			}
			changes = append(changes, watchChange{
				URL: url, ChangeType: "http_service_removed", OldValue: url,
				NewValue: "", Severity: "medium", Metadata: "{}",
			})
		}
	}
	for url, cur := range after {
		old, existed := before[url]
		if !existed {
			if knownHosts[watchURLHost(url)] || !hostDiffRan {
				changes = append(changes, watchChange{
					URL: url, ChangeType: "new_http_service", OldValue: "",
					NewValue: url, Severity: "medium", Metadata: "{}",
				})
			}
			continue
		}
		if old.StatusCode != cur.StatusCode {
			changes = append(changes, watchChange{
				URL: url, ChangeType: "status_change",
				OldValue: fmt.Sprintf("status=%d title=%s", old.StatusCode, old.Title),
				NewValue: fmt.Sprintf("status=%d title=%s", cur.StatusCode, cur.Title),
				Severity: watchStatusSeverity(old.StatusCode, cur.StatusCode),
				Metadata: fmt.Sprintf(`{"old_code":%d,"new_code":%d}`, old.StatusCode, cur.StatusCode),
			})
		}
		if old.Title != cur.Title {
			changes = append(changes, watchChange{
				URL: url, ChangeType: "page_change", OldValue: old.Title,
				NewValue: cur.Title, Severity: "low", Metadata: "{}",
			})
		}
		if old.Server != cur.Server || old.Technologies != cur.Technologies {
			changes = append(changes, watchChange{
				URL: url, ChangeType: "tech_change",
				OldValue: fmt.Sprintf("Server: %s | Tech: %s", old.Server, old.Technologies),
				NewValue: fmt.Sprintf("Server: %s | Tech: %s", cur.Server, cur.Technologies),
				Severity: "low", Metadata: "{}",
			})
		}
		if old.RedirectURL != cur.RedirectURL {
			changes = append(changes, watchChange{
				URL: url, ChangeType: "http_change", OldValue: old.RedirectURL,
				NewValue: cur.RedirectURL, Severity: "low", Metadata: "{}",
			})
		}
	}
	return changes
}

func watchAliveValue(alive bool) string {
	if alive {
		return "alive"
	}
	return "dead"
}

// diffWatchHosts compares two host snapshots. A capped snapshot suppresses
// removals for the same reason as diffWatchHTTP: a new host in the window can
// evict the last host and look like a deletion.
func diffWatchHosts(before, after map[string]bool, capped bool) []watchChange {
	changes := make([]watchChange, 0)
	for host := range before {
		if _, ok := after[host]; !ok {
			if capped {
				continue
			}
			changes = append(changes, watchChange{
				URL: host, ChangeType: "subdomain_removed", OldValue: host,
				NewValue: "", Severity: "medium", Metadata: "{}",
			})
		}
	}
	for host, alive := range after {
		wasAlive, existed := before[host]
		if !existed {
			changes = append(changes, watchChange{
				URL: host, ChangeType: "new_subdomain", OldValue: "",
				NewValue: host, Severity: "medium", Metadata: "{}",
			})
			continue
		}
		if wasAlive != alive {
			changes = append(changes, watchChange{
				URL: host, ChangeType: "host_status_change",
				OldValue: watchAliveValue(wasAlive), NewValue: watchAliveValue(alive),
				Severity: "medium", Metadata: "{}",
			})
		}
	}
	return changes
}

func (s *Scheduler) insertWatchRoundChanges(ctx context.Context, taskID, targetID string, changes []watchChange) {
	if len(changes) == 0 {
		return
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		s.logger.Warn("watch changes: begin failed", "error", err)
		return
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO watch_round_changes
		(id,target_id,task_id,url,change_type,old_value,new_value,severity,metadata,detected_at)
		VALUES (?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)`)
	if err != nil {
		s.logger.Warn("watch changes: prepare failed", "error", err)
		return
	}
	defer func() { _ = stmt.Close() }()

	written := 0
	for _, c := range changes {
		metadata := c.Metadata
		if metadata == "" {
			metadata = "{}"
		}
		if _, err := stmt.ExecContext(ctx, uuid.New().String(), targetID, taskID, c.URL,
			c.ChangeType, c.OldValue, c.NewValue, c.Severity, metadata); err != nil {
			s.logger.Warn("watch changes: insert failed", "error", err, "type", c.ChangeType)
			continue
		}
		written++
	}
	if err := tx.Commit(); err != nil {
		s.logger.Warn("watch changes: commit failed", "error", err)
		return
	}
	if written != len(changes) {
		s.logger.Warn("watch changes: some rows were not written", "written", written, "total", len(changes))
	}
}
