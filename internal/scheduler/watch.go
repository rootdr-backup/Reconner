package scheduler

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/google/uuid"
)

// watchScanType tags the breadth tier: the cheap, chained "watch round" that
// keeps a fleet of projects under continuous observation. It is a DISTINCT task
// type from the deep "full_scan" so the two workloads can be counted, filtered,
// notified and drained separately.
const watchScanType = "watch_scan"

// watchScanModules is the fixed module set of a watch round: passive
// subdomain discovery plus one HTTP probe. Everything else in the deep
// pipeline is skipped and reported (the "report everything skipped" rule).
// "no_subdomain_brute" is a scan-option token, not a phase: it tells the
// subdomain scanner to skip the brute/permutation phase.
func watchScanModules() []string {
	return []string{ModuleSubdomainEnum, ModuleHTTPProbe, "no_subdomain_brute"}
}

// globalScanCeiling is the TOTAL number of scans (deep + watch) allowed to run
// at the same time.
//
// The deep lane alone used to be bounded by effectiveMaxConcurrent(), which on
// a 2-core/3GB box is 1. The watch tier adds a second, much lighter slot:
//   - effectiveMaxConcurrent()+1 because the memory/CPU guard is sized for one
//     HEAVY scan; a watch round is discovery + one HTTP pass and needs far less.
//   - NumCPU because two CPU-bound rounds on two cores is already saturation.
//   - MaxConcurrentScans is the operator knob (System → Scanning).
//
// When the pressure guard reports 0 (severe memory/CPU pressure while idle)
// nothing new starts — not even a watch round.
func (s *Scheduler) globalScanCeiling(running int) int {
	eff := s.effectiveMaxConcurrent(running)
	if eff <= 0 {
		return 0
	}
	ceiling := 1
	if s.cfg != nil && s.cfg.Limits.MaxConcurrentScans > 0 {
		ceiling = s.cfg.Limits.MaxConcurrentScans
	}
	if cpus := runtime.NumCPU(); ceiling > cpus {
		ceiling = cpus
	}
	if max := eff + 1; ceiling > max {
		ceiling = max
	}
	return ceiling
}

// deepLaneCap is how many DEEP scans may run at once. It is the memory-aware
// effectiveMaxConcurrent() bounded by the operator knob
// Limits.MaxConcurrentDeepScans (default 1).
func (s *Scheduler) deepLaneCap(running int) int {
	eff := s.effectiveMaxConcurrent(running)
	if eff < 0 {
		eff = 0
	}
	cap := eff
	if s.cfg != nil && s.cfg.Limits.MaxConcurrentDeepScans > 0 && s.cfg.Limits.MaxConcurrentDeepScans < cap {
		cap = s.cfg.Limits.MaxConcurrentDeepScans
	}
	return cap
}

// watchLaneCap is how many WATCH rounds may run at once. The deep lane keeps
// its reservation, so a deep scan never waits for a watch round: the watch
// lane only gets the slots the deep lane did not reserve.
func (s *Scheduler) watchLaneCap(running int) int {
	cap := 0
	if s.cfg != nil && s.cfg.Limits.MaxConcurrentWatchScans > 0 {
		cap = s.cfg.Limits.MaxConcurrentWatchScans
	}
	free := s.globalScanCeiling(running) - s.deepLaneCap(running)
	if free < 0 {
		free = 0
	}
	if cap > free {
		cap = free
	}
	return cap
}

// watchGapMinutes is the minimum wait before the next chained round of the
// same project. It is the ONLY rate control for watch traffic.
func (s *Scheduler) watchGapMinutes() int {
	if s.cfg != nil && s.cfg.WatchRoundsMinGap > 0 {
		return s.cfg.WatchRoundsMinGap
	}
	return 30
}

// watchFailLimit is how many consecutive failed watch rounds stop the chain.
func (s *Scheduler) watchFailLimit() int {
	if s.cfg != nil && s.cfg.WatchFailLimit > 0 {
		return s.cfg.WatchFailLimit
	}
	return 3
}

// runDueWatchRounds creates one watch task per due project.
//
// Selection rules:
//   - watch_only=1 (the project runs breadth rounds).
//   - watch_paused=0 (the operator did not pause watching).
//   - watch_next_run IS NOT NULL AND <= now. NULL means "not scheduled" — it
//     must NOT fall back to created_at, or a stopped chain restarts instantly.
//   - kind='web': a mixed or network project cannot run a watch round.
//   - no active task for the project.
//
// At most MaxConcurrentWatchScans*2 tasks are created per tick, in due order,
// so a bulk flip of 50 projects cannot flood the queue.
func (s *Scheduler) runDueWatchRounds() {
	if s.cfg == nil {
		return
	}
	limit := s.cfg.Limits.MaxConcurrentWatchScans * 2
	if limit < 1 {
		limit = 1
	}
	rows, err := s.db.Query(`
		SELECT id, domain FROM targets
		WHERE watch_only = 1
		  AND watch_paused = 0
		  AND watch_next_run IS NOT NULL
		  AND watch_next_run <= datetime('now')
		  AND COALESCE(kind,'web') = 'web'
		  AND NOT EXISTS (
			SELECT 1 FROM tasks t WHERE t.target_id = targets.id
			  AND t.status IN ('pending','running','paused','interrupted')
		  )
		ORDER BY watch_next_run ASC
		LIMIT ?
	`, limit)
	if err != nil {
		return
	}
	defer rows.Close()

	type dueProject struct{ id, domain string }
	var due []dueProject
	for rows.Next() {
		var id, domain string
		if err := rows.Scan(&id, &domain); err == nil {
			due = append(due, dueProject{id: id, domain: domain})
		}
	}
	rows.Close()

	for _, p := range due {
		// The project may have been flipped to deep between the query and here.
		var stillWatch, paused int
		var kind string
		_ = s.db.QueryRow(`SELECT COALESCE(watch_only,0), COALESCE(watch_paused,0), COALESCE(kind,'web') FROM targets WHERE id=?`, p.id).
			Scan(&stillWatch, &paused, &kind)
		if stillWatch != 1 || paused != 0 || kind != "web" {
			continue
		}
		s.logger.Info("Starting watch round", "target", p.domain)
		if _, err := s.CreateTaskTyped(p.id, watchScanModules(), 1, watchScanType); err != nil {
			s.logger.Error("Failed to create watch round", "target", p.domain, "error", err)
			continue
		}
	}
}

// drainPendingWatchTasks starts queued watch rounds. It is SEPARATE from
// drainPendingTasks (the deep drain) so the two lanes never compete for the
// same pending rows and the watch lane keeps its own admission cap.
func (s *Scheduler) drainPendingWatchTasks() {
	rows, err := s.db.Query(`
		SELECT t.id FROM tasks t
		WHERE t.status = 'pending' AND t.type = ?
		ORDER BY t.created_at ASC
		LIMIT 10
	`, watchScanType)
	if err != nil {
		return
	}
	var pending []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			pending = append(pending, id)
		}
	}
	rows.Close()

	for _, id := range pending {
		s.tryStartTask(id)
	}
}

// watchKindGuardScheduler raises one notification when a breadth project can
// no longer run a watch round because it turned mixed or network.
//
// A watch round needs a 'web' project: the scanner has no network executor and
// createTask rejects a mixed project without a scope override. The asset API
// already refuses a network asset on a watch project, so this is the safety
// net for rows that changed elsewhere. The operator hears about it ONCE per
// state change — the notice is recorded in the notifications table and the
// guard only fires again when the project changes back and forth.
func (s *Scheduler) watchKindGuardScheduler() {
	defer s.wg.Done()
	s.checkWatchKindGuard()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.checkWatchKindGuard()
		}
	}
}

func (s *Scheduler) checkWatchKindGuard() {
	rows, err := s.db.Query(`
		SELECT id, domain, COALESCE(kind,'web') FROM targets
		WHERE watch_only = 1 AND COALESCE(kind,'web') <> 'web'`)
	if err != nil {
		return
	}
	defer rows.Close()

	type offender struct{ id, domain, kind string }
	var bad []offender
	for rows.Next() {
		var o offender
		if err := rows.Scan(&o.id, &o.domain, &o.kind); err == nil {
			bad = append(bad, o)
		}
	}
	rows.Close()

	for _, o := range bad {
		// One notice per state change: a notice that already exists for this
		// project and this kind means the operator was told already.
		var seen int
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM notifications
			WHERE target_id=? AND type='watch_kind_conflict' AND body LIKE ?`,
			o.id, "%"+o.kind+"%").Scan(&seen)
		if seen > 0 {
			continue
		}
		s.logger.Warn("Watch round skipped: project is no longer a web project",
			"target", o.domain, "kind", o.kind)
		s.insertNotification(o.id, "watch_kind_conflict",
			"Watch rounds stopped",
			fmt.Sprintf("This project is a breadth (watch) project but its scope is %q. Watch rounds need a web-only project, so no round was started. Drop the network assets or flip the project back to a deep scan.", o.kind),
			"high")
	}
}

// watchScheduler runs the watch-round loop. It is a separate goroutine from
// the deep monitor scheduler: the two tiers have different triggers, different
// pipelines and different notifications.
func (s *Scheduler) watchScheduler() {
	defer s.wg.Done()
	s.runDueWatchRounds()
	s.drainPendingWatchTasks()
	s.flushScopeLandings()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.runDueWatchRounds()
			s.drainPendingWatchTasks()
			// The grouped scope-landed message is flushed once per tick window,
			// across ALL projects (D25).
			s.flushScopeLandings()
		}
	}
}

// applyWatchTerminalRules moves the chain of a watch project to its next
// round after a terminal task status.
//
//	finished    → next round in <gap> minutes, the failure counter resets
//	failed      → next round in <gap> minutes, the failure counter grows;
//	              at the limit the chain STOPS (paused, no next round) and the
//	              operator is told once
//	interrupted → next round in <gap> minutes (the service was stopped)
//	cancelled   → the chain STOPS (the operator cancelled the round)
//
// The timestamp is ALWAYS written, even when the watch lane is saturated:
// the lane decides whether a worker slot is free, the timestamp only decides
// WHEN the next round may start.
func (s *Scheduler) applyWatchTerminalRules(targetID, status string) {
	gap := s.watchGapMinutes()
	switch status {
	case "finished":
		_, _ = s.db.Exec(`UPDATE targets SET watch_last_run=CURRENT_TIMESTAMP,
			watch_next_run=datetime('now','+' || ? || ' minutes'), watch_fail_count=0
			WHERE id=? AND watch_only=1`, gap, targetID)
	case "failed":
		_, _ = s.db.Exec(`UPDATE targets SET watch_last_run=CURRENT_TIMESTAMP,
			watch_fail_count=COALESCE(watch_fail_count,0)+1
			WHERE id=? AND watch_only=1`, targetID)
		var fails int
		_ = s.db.QueryRow(`SELECT COALESCE(watch_fail_count,0) FROM targets WHERE id=?`, targetID).Scan(&fails)
		if fails >= s.watchFailLimit() {
			_, _ = s.db.Exec(`UPDATE targets SET watch_paused=1, watch_next_run=NULL
				WHERE id=? AND watch_only=1`, targetID)
			s.insertNotification(targetID, "watch_failed",
				"Watch rounds stopped",
				fmt.Sprintf("%d consecutive watch rounds failed. Watching is paused for this project.", fails),
				"high")
			return
		}
		_, _ = s.db.Exec(`UPDATE targets SET watch_next_run=datetime('now','+' || ? || ' minutes')
			WHERE id=? AND watch_only=1`, gap, targetID)
	case InterruptedStatus:
		_, _ = s.db.Exec(`UPDATE targets SET watch_next_run=datetime('now','+' || ? || ' minutes')
			WHERE id=? AND watch_only=1`, gap, targetID)
	case "cancelled":
		_, _ = s.db.Exec(`UPDATE targets SET watch_paused=1, watch_next_run=NULL
			WHERE id=? AND watch_only=1`, targetID)
	}
}

// recoverWatchTask applies the terminal rule to a watch task that startup
// recovery cancelled (a zombie from a crash). Without it the project stays due
// in the past and the round restarts immediately after every restart.
func (s *Scheduler) recoverWatchTask(targetID string) {
	_, _ = s.db.Exec(`UPDATE targets SET watch_fail_count=COALESCE(watch_fail_count,0)+1,
		watch_next_run=datetime('now','+' || ? || ' minutes')
		WHERE id=? AND watch_only=1 AND COALESCE(watch_paused,0)=0`, s.watchGapMinutes(), targetID)
}

// watchRoundRoot narrows the enumeration roots of a watch round to ONE root.
// A project with N domain assets costs N sequential enumeration rounds, so a
// watch round rotates the root instead of sweeping all of them.
func (s *Scheduler) watchRoundRoot(ctx context.Context, targetID, scope string, roots []string) []string {
	if len(roots) == 0 {
		return roots
	}
	var index int
	_ = s.db.QueryRow(`SELECT COALESCE(watch_root_index,0) FROM targets WHERE id=?`, targetID).Scan(&index)
	if index < 0 {
		index = 0
	}
	idx := index % len(roots)
	return []string{roots[idx]}
}

// advanceWatchRootIndex moves the rotation pointer after a round finished. It
// is called only on a FINISHED round: a failed round keeps the same root, so
// one network hiccup cannot skip a root for a full rotation. Two consecutive
// failures on the SAME root advance it anyway, so one broken root cannot stop
// the chain for every healthy root.
func (s *Scheduler) advanceWatchRootIndex(ctx context.Context, targetID, scope string) {
	// The task context is usually already cancelled at this point (the round
	// just finished), so the lookup runs on a fresh context.
	roots := s.loadSubdomainRoots(context.Background(), targetID, scope, "")
	if len(roots) == 0 {
		return
	}
	var index int
	_ = s.db.QueryRow(`SELECT COALESCE(watch_root_index,0) FROM targets WHERE id=?`, targetID).Scan(&index)
	next := (index + 1) % len(roots)
	_, _ = s.db.Exec(`UPDATE targets SET watch_root_index=? WHERE id=?`, next, targetID)
}

// watchRootFailLimit is how many consecutive FAILED rounds on the SAME root
// trigger the poison-root escape (plan §3).
const watchRootFailLimit = 2

// recordWatchRootFailure counts one failed round on the current root of a
// project and reports whether the rotation must advance now.
//
// The counter is per project and in memory: it exists only to stop a single
// permanently broken domain from blocking every other root, so it does not need
// to survive a restart. watch_fail_count keeps counting per project in the DB.
func (s *Scheduler) recordWatchRootFailure(targetID string) bool {
	s.mu.Lock()
	fails := s.watchRootFails[targetID] + 1
	if fails < watchRootFailLimit {
		s.watchRootFails[targetID] = fails
		s.mu.Unlock()
		return false
	}
	delete(s.watchRootFails, targetID)
	s.mu.Unlock()
	return true
}

// resetWatchRootFailures clears the per-root counter. A finished round (or any
// other terminal state that ends the chain) starts the next attempt fresh.
func (s *Scheduler) resetWatchRootFailures(targetID string) {
	s.mu.Lock()
	delete(s.watchRootFails, targetID)
	s.mu.Unlock()
}

// resumeTypeTag keeps the ORIGINAL task type when a task is resumed.
//
// A resumed watch round must stay a watch round: resuming it as a deep scan
// would run the whole heavy pipeline and put the task in the deep drain. A
// plain manual scan keeps the empty tag, which createTask resolves to
// "full_scan" (or the single module name) exactly as before.
func resumeTypeTag(originalType string) string {
	switch originalType {
	case watchScanType, monitorWatchType, monitorEscalationType:
		return originalType
	default:
		return ""
	}
}

// insertNotification writes an in-app notification row for a target.
func (s *Scheduler) insertNotification(targetID, typ, title, body, severity string) {
	if targetID == "" {
		return
	}
	_, _ = s.db.Exec(`INSERT INTO notifications(id,target_id,type,title,body,url,severity,is_read)
		VALUES(?,?,?,?,?,?,?,0)`,
		uuid.NewString(), targetID, typ, title, body, "/targets/"+targetID, severity)
}

// watchProjectPaused reports whether the operator paused watching.
func (s *Scheduler) watchProjectPaused(targetID string) bool {
	var paused int
	_ = s.db.QueryRow(`SELECT COALESCE(watch_paused,0) FROM targets WHERE id=?`, targetID).Scan(&paused)
	return paused == 1
}

// watchModulesSkippedLine builds the "what did this round NOT run" report.
// The deep pipeline has ~45 modules; listing every name in a Telegram message
// is noise, so the report groups them by category and truncates long groups.
func watchModulesSkippedLine() string {
	return watchModulesSkippedSummary()
}

// shortWatchDuration renders a duration for a one-line notification body.
func shortWatchDuration(d time.Duration) string {
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(time.Second).String()
}
