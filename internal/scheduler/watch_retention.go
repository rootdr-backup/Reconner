package scheduler

import (
	"fmt"
	"strings"
	"time"
)

// watchTaskRetentionDays is how long a FINISHED watch task row survives. A
// watch project produces ~48 task rows a day, so without a prune the tasks
// table grows by hundreds of thousands of rows a month. Deep tasks are never
// pruned: they are the operator's history. This window is intentionally NOT one
// of the §1 operator knobs: it bounds database growth on the appliance, and
// the landed scope / notifications / deep-scan rows all survive it.
const watchTaskRetentionDays = 90

// watchLogKeepCount is how many of the most recent watch tasks PER PROJECT keep
// their logs and phases. The operator still reads the newest rounds in the UI;
// the older ones only need their summary row.
const watchLogKeepCount = 100

// retentionScheduler runs the retention prune once an hour. The prune is
// TIER-SCOPED: it only removes rows that the watch tier produced.
//
// A project that also ran a deep scan (or a manual deep scan) keeps every
// finding row, because the watch tier never writes them. The finding tables
// (js_files, parameters, directory_findings, nuclei_findings, vuln_findings,
// …) are therefore NEVER pruned by this job.
func (s *Scheduler) retentionScheduler() {
	defer s.wg.Done()
	s.pruneWatchChangeRows()
	s.pruneWatchRows()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.pruneWatchChangeRows()
			s.pruneWatchRows()
		}
	}
}

// pruneWatchChangeRows ages the watch audit trail globally. It must not use
// watchOnlyTargets(): mixed projects write changes too, and pruneWatchRows()
// returns early when there are no watch-only targets at all. Finished tasks are
// deleted after 90 days, but these rows have no task foreign key on purpose.
func (s *Scheduler) pruneWatchChangeRows() {
	days := 180
	if s.cfg != nil && s.cfg.WatchChangesRetentionDays > 0 {
		days = s.cfg.WatchChangesRetentionDays
	}
	for attempt := 0; attempt < 2; attempt++ {
		_, err := s.db.Exec(`DELETE FROM watch_round_changes
			WHERE COALESCE(detected_at,CURRENT_TIMESTAMP) < datetime('now','-' || ? || ' days')`, days)
		if err == nil {
			return
		}
		if attempt == 0 && strings.Contains(strings.ToLower(err.Error()), "busy") {
			time.Sleep(2 * time.Second)
			continue
		}
		s.logger.Warn("Watch change retention prune failed", "error", err)
		return
	}
}

// watchOnlyTargets returns the project ids whose WHOLE task history consists
// of watch rounds. Those projects produced every one of their rows through the
// watch tier, so their raw rows may be pruned. A project that ever ran a deep
// scan keeps its rows.
func (s *Scheduler) watchOnlyTargets() []string {
	rows, err := s.db.Query(`
		SELECT t.id FROM targets t
		WHERE t.watch_only = 1
		  AND NOT EXISTS (
			SELECT 1 FROM tasks x WHERE x.target_id = t.id AND COALESCE(x.type,'') <> ?
		  )
	`, watchScanType)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// pruneWatchRows removes the raw rows a watch round produced, once they are
// older than the configured window.
//
// Order matters: http_services has no foreign key to subdomains, but the
// subdomains row is the parent concept, so the services go first.
func (s *Scheduler) pruneWatchRows() {
	rows := s.watchOnlyTargets()
	if len(rows) == 0 {
		return
	}
	days := 30
	if s.cfg != nil && s.cfg.WatchRowsRetentionDays > 0 {
		days = s.cfg.WatchRowsRetentionDays
	}
	scopeDays := 180
	if s.cfg != nil && s.cfg.WatchScopeEventsRetentionDays > 0 {
		scopeDays = s.cfg.WatchScopeEventsRetentionDays
	}

	// One transaction for the whole prune: a half-pruned table is worse than a
	// failed prune. A busy database is retried once.
	for attempt := 0; attempt < 2; attempt++ {
		if err := s.pruneWatchRowsTx(rows, days, scopeDays); err != nil {
			if attempt == 0 && strings.Contains(strings.ToLower(err.Error()), "busy") {
				time.Sleep(2 * time.Second)
				continue
			}
			s.logger.Warn("Watch retention prune failed", "error", err)
			return
		}
		return
	}
}

func (s *Scheduler) pruneWatchRowsTx(targetIDs []string, days, scopeDays int) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	placeholders := make([]string, 0, len(targetIDs))
	args := make([]any, 0, len(targetIDs)*2)
	for _, id := range targetIDs {
		placeholders = append(placeholders, "?")
		args = append(args, id)
	}
	inList := strings.Join(placeholders, ",")
	ageArgs := append([]any{}, args...)
	ageArgs = append(ageArgs, days)

	steps := []struct {
		name string
		sql  string
	}{
		// http_services first: it references subdomains by id but has no
		// foreign key, so the parent row may go away independently.
		{"http_services", fmt.Sprintf(`DELETE FROM http_services WHERE target_id IN (%s)
			AND COALESCE(last_seen,CURRENT_TIMESTAMP) < datetime('now','-' || ? || ' days')`, inList)},
		{"subdomains", fmt.Sprintf(`DELETE FROM subdomains WHERE target_id IN (%s)
			AND COALESCE(last_seen,CURRENT_TIMESTAMP) < datetime('now','-' || ? || ' days')`, inList)},
		{"monitoring_changes", fmt.Sprintf(`DELETE FROM monitoring_changes WHERE target_id IN (%s)
			AND COALESCE(detected_at,CURRENT_TIMESTAMP) < datetime('now','-' || ? || ' days')`, inList)},
		{"screenshots", fmt.Sprintf(`DELETE FROM screenshots WHERE target_id IN (%s)
			AND COALESCE(created_at,CURRENT_TIMESTAMP) < datetime('now','-' || ? || ' days')`, inList)},
		{"browser_states", fmt.Sprintf(`DELETE FROM browser_states WHERE target_id IN (%s)
			AND COALESCE(created_at,CURRENT_TIMESTAMP) < datetime('now','-' || ? || ' days')`, inList)},
	}

	for _, step := range steps {
		res, err := tx.Exec(step.sql, ageArgs...)
		if err != nil {
			return fmt.Errorf("%s: %w", step.name, err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			s.logger.Info("Watch retention prune", "table", step.name, "rows", n)
		}
	}

	// Task logs and phases of watch tasks, except the most recent ones the
	// operator still reads in the UI. The keep list is PER PROJECT: a single
	// global top-N would let a busy project push another project's rounds out
	// of the keep set and delete their logs.
	keepSQL := `
		SELECT id FROM (
			SELECT id, ROW_NUMBER() OVER (
				PARTITION BY target_id
				ORDER BY COALESCE(finished_at,created_at) DESC
			) AS rn
			FROM tasks WHERE type = ? AND status IN ('finished','failed','cancelled')
		) WHERE rn <= ?`
	keepRows, err := tx.Query(keepSQL, watchScanType, watchLogKeepCount)
	if err != nil {
		return fmt.Errorf("keep list: %w", err)
	}
	keep := map[string]bool{}
	for keepRows.Next() {
		var id string
		if err := keepRows.Scan(&id); err == nil {
			keep[id] = true
		}
	}
	keepRows.Close()

	logRows, err := tx.Query(`SELECT id FROM tasks WHERE type = ?`, watchScanType)
	if err != nil {
		return fmt.Errorf("watch tasks: %w", err)
	}
	var pruneTaskIDs []string
	for logRows.Next() {
		var id string
		if err := logRows.Scan(&id); err == nil && !keep[id] {
			pruneTaskIDs = append(pruneTaskIDs, id)
		}
	}
	logRows.Close()
	for _, id := range pruneTaskIDs {
		// task_logs and task_phases cascade from the task row.
		if _, err := tx.Exec(`DELETE FROM task_logs WHERE task_id=?`, id); err != nil {
			return fmt.Errorf("task_logs: %w", err)
		}
		if _, err := tx.Exec(`DELETE FROM task_phases WHERE task_id=?`, id); err != nil {
			return fmt.Errorf("task_phases: %w", err)
		}
	}
	if len(pruneTaskIDs) > 0 {
		s.logger.Info("Watch retention prune", "table", "task_logs/task_phases", "tasks", len(pruneTaskIDs))
	}

	// The scope landing audit trail has its own, longer window.
	res, err := tx.Exec(`DELETE FROM watch_scope_events
		WHERE COALESCE(detected_at,CURRENT_TIMESTAMP) < datetime('now','-' || ? || ' days')`, scopeDays)
	if err != nil {
		return fmt.Errorf("watch_scope_events: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		s.logger.Info("Watch retention prune", "table", "watch_scope_events", "rows", n)
	}

	// Finished watch task rows older than the window. Their logs and phases
	// cascade with them.
	res, err = tx.Exec(`DELETE FROM tasks WHERE type = ?
		AND status IN ('finished','failed','cancelled')
		AND COALESCE(finished_at,created_at) < datetime('now','-' || ? || ' days')`,
		watchScanType, watchTaskRetentionDays)
	if err != nil {
		return fmt.Errorf("tasks: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		s.logger.Info("Watch retention prune", "table", "tasks", "rows", n)
	}

	return tx.Commit()
}
