package scheduler

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// This file holds the two REPORTING surfaces of the watch tier:
//
//   - the "what did this round NOT run" summary (T9), grouped by category so
//     the message stays readable while every skipped module stays visible.
//   - the grouped scope-landed message (T8/D25): ONE Telegram message per
//     watch tick window across ALL projects, claimed in the database.
//
// Both are watch-tier only. The deep tier keeps its own message format.

// watchModuleGroup is one category of skipped modules.
type watchModuleGroup struct {
	Category string
	Modules  []string
}

// watchModuleCategory maps a module id to the category it belongs to. The
// categories mirror how the deep pipeline reads to an operator: what was
// discovered, what was crawled, what was attacked, what was checked, what was
// fingerprinted.
func watchModuleCategory(module string) string {
	switch module {
	case ModuleJSAnalysis, ModuleJSEndpoints, ModuleParamDiscovery, ModuleTimeMachine,
		ModuleParamReflection, ModuleParamFuzz, ModuleAPIDataExposure:
		return "analysis"
	case ModuleHeadlessCrawl, ModuleDirDiscovery, ModuleBackupDiscovery:
		return "crawling"
	case ModuleNuclei, ModuleDAST, ModuleXSS, ModuleDOMXSS, ModuleVulnScan, ModuleSQLi,
		ModuleSSRF, ModuleLFI, ModuleSSTI, ModuleCSTI, ModuleCmdi, ModuleCSRF, ModuleXXE,
		ModuleFileUpload, ModuleIDOR, ModuleJWT, ModuleAuthz, ModuleATO, ModuleNoSQLi,
		ModuleCachePoison:
		return "active testing"
	case ModuleOpenRedirect, ModuleTakeover, ModuleBLH, ModuleCORS, ModuleExposure,
		ModuleRace, ModuleSmuggling:
		return "exposure checks"
	case ModuleOAST:
		return "out-of-band"
	case ModulePassive, ModuleIntel, ModuleShodan, ModuleOriginIP:
		return "external intelligence"
	case ModuleWPDetect, ModuleWPEnum, ModuleWPUsers, ModuleWPConfig, ModuleWPBackups,
		ModuleWPEndpoints, ModuleWPMisconfig, ModuleWPCredAudit, ModuleWPVulns:
		return "wordpress"
	case ModulePortScan, ModuleNetwork, ModuleNetworkBrute, ModuleNetworkBackup,
		ModuleNetworkNucleiOnly, ModuleNetworkIngram, ModuleNetDevices,
		ModuleNetworkInitialAccess, ModuleNetworkBruteSSH, ModuleNetworkBruteFTP,
		ModuleNetworkBruteMySQL, ModuleNetworkBrutePostgres, ModuleNetworkBruteRedis,
		ModuleNetworkBruteRDP, ModuleNetworkBruteVNC, ModuleNetworkBruteTelnet,
		ModuleNetworkBruteSMB:
		return "network"
	case ModuleVerify, ModuleMonitor:
		return "post-processing"
	default:
		return "other"
	}
}

// watchSkippedModuleGroups returns the deep-only modules of a watch round,
// grouped by category. The order of the groups is stable.
func watchSkippedModuleGroups() []watchModuleGroup {
	byCategory := map[string][]string{}
	for _, m := range AllModules {
		if m == ModuleSubdomainEnum || m == ModuleHTTPProbe {
			continue // the watch tier runs exactly these two
		}
		cat := watchModuleCategory(m)
		byCategory[cat] = append(byCategory[cat], m)
	}
	cats := make([]string, 0, len(byCategory))
	for c := range byCategory {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	out := make([]watchModuleGroup, 0, len(cats))
	for _, c := range cats {
		out = append(out, watchModuleGroup{Category: c, Modules: byCategory[c]})
	}
	return out
}

// watchModulesSkippedSummary is the short report: one line per category, with a
// long category truncated. It goes into the task log AND the watch Telegram
// message. Nothing is silently dropped — the category count is always visible.
func watchModulesSkippedSummary() string {
	groups := watchSkippedModuleGroups()
	if len(groups) == 0 {
		return ""
	}
	total := 0
	lines := make([]string, 0, len(groups))
	for _, g := range groups {
		total += len(g.Modules)
		names := g.Modules
		suffix := ""
		if len(names) > 8 {
			names = names[:8]
			suffix = fmt.Sprintf(" +%d more", len(g.Modules)-8)
		}
		lines = append(lines, fmt.Sprintf("%s (%d): %s%s", g.Category, len(g.Modules), strings.Join(names, ", "), suffix))
	}
	return fmt.Sprintf("Skipped %d deep-only module(s) — %s", total, strings.Join(lines, "; "))
}

// watchModulesSkippedFull is the complete module list. It goes into the task
// log only — a Telegram message with 45 module names is noise.
func watchModulesSkippedFull() string {
	groups := watchSkippedModuleGroups()
	if len(groups) == 0 {
		return ""
	}
	var b strings.Builder
	for _, g := range groups {
		fmt.Fprintf(&b, "%s (%d): %s\n", g.Category, len(g.Modules), strings.Join(g.Modules, ", "))
	}
	return strings.TrimRight(b.String(), "\n")
}

// scopeLanding is one claimed landing row.
type scopeLanding struct {
	EventID    string
	TargetID   string
	ProgramID  string
	Identifier string
}

// flushScopeLandings sends the grouped scope-landed message.
//
// ONE message per watch tick window across ALL projects (D25). The window is
// claimed IN THE DATABASE, not by a time key:
//
//	announced = 0  unannounced
//	announced = 2  claimed (in flight)
//	announced = 1  sent
//
// A row whose project still has a running watch round is NOT claimable: the
// round may still land more hosts. A failed send releases the claim back to 0
// so the next window retries, and a successful send marks the rows sent.
func (s *Scheduler) flushScopeLandings() {
	ctx := context.Background()
	rows, err := s.db.QueryContext(ctx, `
		SELECT e.id, e.target_id, COALESCE(e.program_id,''), e.identifier
		FROM watch_scope_events e
		WHERE e.announced = 0
		  AND NOT EXISTS (
			SELECT 1 FROM tasks t WHERE t.target_id = e.target_id
			  AND t.type = ? AND t.status IN ('pending','running','paused','interrupted')
		  )
		ORDER BY e.detected_at ASC
		LIMIT 500
	`, watchScanType)
	if err != nil {
		return
	}
	var landings []scopeLanding
	for rows.Next() {
		var l scopeLanding
		if err := rows.Scan(&l.EventID, &l.TargetID, &l.ProgramID, &l.Identifier); err == nil {
			landings = append(landings, l)
		}
	}
	rows.Close()
	if len(landings) == 0 {
		return
	}

	// Claim the rows in ONE update. The update is the claim: only the rows it
	// actually changed (announced 0 → 2) belong to this window.
	ids := make([]string, 0, len(landings))
	for _, l := range landings {
		ids = append(ids, l.EventID)
	}
	claimed := s.claimScopeLandings(ids)
	if len(claimed) == 0 {
		return
	}

	summary, hosts := s.summarizeScopeLandings(claimed)
	if len(hosts) == 0 && summary == "" {
		s.releaseScopeLandings(claimed)
		return
	}

	// The event key is owned by the scheduler and is unique per window, so the
	// Telegram outbox dedupes a retry of the same window.
	sent := false
	if s.notifier != nil {
		eventKey := "scope_landed:" + claimed[0].EventID
		s.notifier.NotifyScopeLanded(eventKey, summary, hosts)
		sent = true
	}
	// The claim is closed either way: the in-app bell already has a row for
	// every landing, and the hub event is what makes it appear live. Skipping
	// the close when no Telegram bot is configured would leave the rows at
	// announced=2 forever (and re-broadcast the same window every tick).
	s.markScopeLandingsSent(claimed)
	if s.hub != nil {
		s.hub.Broadcast("scope_landed", map[string]any{
			"target_id": claimed[0].TargetID,
			"count":     len(claimed),
		})
	}
	if sent {
		s.logger.Info("Sent grouped scope-landed message", "count", len(claimed), "hosts", len(hosts))
	} else {
		s.logger.Info("Broadcast scope-landed (no notifier configured)", "count", len(claimed), "hosts", len(hosts))
	}
}

// claimScopeLandings marks the given rows as in flight and returns the ones it
// actually claimed.
func (s *Scheduler) claimScopeLandings(ids []string) []scopeLanding {
	if len(ids) == 0 {
		return nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, 0, len(ids))
	for _, id := range ids {
		args = append(args, id)
	}
	res, err := s.db.Exec(`UPDATE watch_scope_events SET announced = 2
		WHERE announced = 0 AND id IN (`+placeholders+`)`, args...)
	if err != nil {
		return nil
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil
	}
	claimed := make([]scopeLanding, 0, len(ids))
	for _, id := range ids {
		var l scopeLanding
		var programID, identifier string
		if err := s.db.QueryRow(`SELECT id, target_id, COALESCE(program_id,''), identifier
			FROM watch_scope_events WHERE id=? AND announced=2`, id).
			Scan(&l.EventID, &l.TargetID, &programID, &identifier); err == nil {
			l.ProgramID = programID
			l.Identifier = identifier
			claimed = append(claimed, l)
		}
	}
	return claimed
}

// markScopeLandingsSent closes a window.
func (s *Scheduler) markScopeLandingsSent(landings []scopeLanding) {
	for _, l := range landings {
		_, _ = s.db.Exec(`UPDATE watch_scope_events SET announced = 1 WHERE id=?`, l.EventID)
	}
}

// releaseScopeLandings gives a failed window back to the queue.
func (s *Scheduler) releaseScopeLandings(landings []scopeLanding) {
	for _, l := range landings {
		_, _ = s.db.Exec(`UPDATE watch_scope_events SET announced = 0 WHERE id=? AND announced=2`, l.EventID)
	}
}

// summarizeScopeLandings builds the grouped message body: the total, the
// per-program counts, and up to WatchNotifyHostCap host names.
func (s *Scheduler) summarizeScopeLandings(landings []scopeLanding) (string, []string) {
	cap := 20
	if s.cfg != nil && s.cfg.WatchNotifyHostCap > 0 {
		cap = s.cfg.WatchNotifyHostCap
	}
	perProgram := map[string]int{}
	programNames := map[string]string{}
	var hosts []string
	projects := map[string]bool{}
	for _, l := range landings {
		projects[l.TargetID] = true
		name := "program " + shortProgramLabel(l.ProgramID)
		if l.ProgramID != "" {
			_ = s.db.QueryRow(`SELECT COALESCE(name,'') FROM bounty_programs WHERE id=?`, l.ProgramID).Scan(&name)
			if name == "" {
				name = "program " + shortProgramLabel(l.ProgramID)
			}
		}
		programNames[l.ProgramID] = name
		perProgram[l.ProgramID]++
		hosts = append(hosts, l.Identifier)
	}
	if len(hosts) == 0 {
		return "", nil
	}
	parts := make([]string, 0, len(perProgram))
	for pid, count := range perProgram {
		parts = append(parts, fmt.Sprintf("%s: %d", programNames[pid], count))
	}
	sort.Strings(parts)
	summary := fmt.Sprintf("%d new eligible host(s) across %d program(s) — %s",
		len(hosts), len(perProgram), strings.Join(parts, ", "))
	shown := hosts
	if len(shown) > cap {
		shown = shown[:cap]
	}
	return summary, shown
}

// shortProgramLabel is a short fallback name for a program without a name.
func shortProgramLabel(programID string) string {
	if len(programID) > 8 {
		return programID[:8]
	}
	return programID
}
