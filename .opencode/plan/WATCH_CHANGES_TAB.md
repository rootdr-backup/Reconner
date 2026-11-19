# Watch breadth "Changes" view — implementation plan

Status: plan only. No code changed.

## Goal

Make watch breadth rounds visible outside the bell.

Today a watch round (`watch_scan`) runs only subdomain enumeration and one HTTP probe. It does **not** run the monitor engine. It writes no `monitoring_changes` rows. The existing target tab `Changes` reads only `monitoring_changes`, so a watch-only project shows an empty tab. The only watch signals are bell rows: `scope_landed`, `watch_failed`, `watch_kind_conflict`.

This plan adds:

1. A durable per-round change log for watch rounds.
2. One reusable Changes explorer with subtabs and color-coded before/after diffs.
3. A global `/changes` page in the main sidebar, plus the same explorer inside each target's `Changes` tab.

## Design decisions (senior-call)

1. **Capture diffs in the scheduler, not in the scanners.**  
   Scanners get only `targetID`; they have no `taskID`. Adding task IDs through context would touch many call sites. A before/after snapshot around each watch module in `executeTask` is one hook. It also keeps the scanners cheap and unmodified.

2. **Do not add bell rows for normal changes.**  
   The bell stays quiet for ordinary watch rounds by design. The new Changes view is the place to read them. New bell rows would flood operators on every round.

3. **Keep JavaScript out of watch rounds by default.**  
   Watch rounds deliberately skip JS analysis, browser work, and extra fetches to stay inside the rate budget. The `Scripts` subtab shows deep-monitor JS/CSS diffs and says so when empty. Do not silently add JS fetching to watch rounds. If the operator later wants JS drift in watch rounds, add an opt-in module with its own rate cap.

4. **Reuse `watch_scope_events` for scope landings.**  
   It already has the audit trail, program ID, and retention window. The Changes API unions it into the feed. Do not duplicate landing rows into the new table.

5. **Keep watch change history long.**  
   `monitoring_changes` is pruned after 30 days for watch-only projects. The new table is the watch audit trail. Keep it 180 days by default, with a config knob.

6. **One component, two placements.**  
   Build `ChangesExplorer` once. Mount it on `/changes` without a target ID and in `TargetDetail` with a target ID. This prevents two drifting implementations.

---

## Phase 0 — branch and workspace

1. The repo currently has uncommitted user work on `main`:
   - `docs/SCANNING_GUIDE.md`
   - `docs/V5_1_0_RELEASE_NOTES.md`
   - `frontend/src/lib/api.ts`
   - `frontend/src/pages/BountyPrograms.tsx`
   - `internal/assets/assets.go`, `internal/assets/assets_test.go`
   - `internal/bounty/*`
   - `internal/scheduler/scheduler.go`, `internal/scheduler/scope_guard_test.go`

   Do not overwrite it. The implementer must commit or stash it first.

2. Create a branch from current `main`:

   ```sh
   git switch -c feature/watch-changes-tab
   ```

3. Do not merge upstream here. This work sits on top of the v5 merge already on `main`.

---

## Phase 1 — database and config

### 1.1 New table

File: `internal/database/migrations.go`

Add a migration constant near `createWatchScopeEventsTable` (around line 1902), before `createWatchTierIndexes`. Append it to the ordered migration slice in `RunMigrations` (around lines 168–177), after the watch-scope entry.

SQL:

```sql
CREATE TABLE IF NOT EXISTS watch_round_changes (
    id          TEXT PRIMARY KEY,
    target_id   TEXT NOT NULL,
    task_id     TEXT NOT NULL,
    url         TEXT NOT NULL DEFAULT '',
    change_type TEXT NOT NULL,
    old_value   TEXT NOT NULL DEFAULT '',
    new_value   TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT 'info',
    metadata    TEXT NOT NULL DEFAULT '{}',
    detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_watch_round_changes_target_time
    ON watch_round_changes(target_id, detected_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_watch_round_changes_task
    ON watch_round_changes(task_id, detected_at);
CREATE INDEX IF NOT EXISTS idx_watch_round_changes_type_time
    ON watch_round_changes(change_type, detected_at DESC);
```

Notes:

- `task_id` is deliberately a plain `TEXT` key. Do **not** add a foreign key to `tasks`. Retention deletes finished watch tasks after 90 days (`watch_retention.go:211-214`). A cascade would destroy the 180-day audit trail. Keep the index for round filtering.
- `change_type` values are the existing monitor vocabulary where possible:
  - `status_change` — HTTP status flip, e.g. `403 → 200`
  - `page_change` — page title changed
  - `tech_change` — server / technology changed
  - `new_subdomain` — host first seen
  - `subdomain_removed` — host disappeared
- `metadata` is JSON. Store structured extras there: `old_code`, `new_code`, `old_technologies`, `new_technologies`, `phase`.

### 1.2 Config knob

File: `internal/config/config.go`

Near the watch defaults (around lines 640–647), add:

```go
WatchChangesRetentionDays int // default 180
```

Default to 180. Do not reuse the 30-day `WatchRowsRetentionDays`; the Changes view is a long-lived audit trail. If operators must change it in the browser, also add the field to the System DTOs at `internal/api/system_handlers.go:120` and `:186`. Config-file support works without that step.

### 1.3 Retention

File: `internal/scheduler/watch_retention.go`

- `pruneWatchRows()` (around lines 75–102) reads the new config value. Do **not** pass it through `pruneWatchRowsTx`. That transaction only covers watch-only targets and returns early when none exist (`watch_retention.go:76-79`). Mixed deep/watch projects would never prune.
- Add a dedicated global prune outside that early return. Prefer a small separate function called from `retentionScheduler()`. Use its own argument list:

```go
changeDays := 180
if s.cfg != nil && s.cfg.WatchChangesRetentionDays > 0 {
    changeDays = s.cfg.WatchChangesRetentionDays
}
_, err := s.db.ExecContext(ctx, `DELETE FROM watch_round_changes
    WHERE COALESCE(detected_at,CURRENT_TIMESTAMP) < datetime('now','-' || ? || ' days')`, changeDays)
```

- No `inList` is needed. Keep `idx_watch_round_changes_target_time` and `idx_watch_round_changes_type_time` for reads.
- Do not change the `pruneWatchRowsTx` signature for this table. It gets no step in its `steps` slice.
- Update tests for the new global prune.

Do **not** add new watch changes to the notify path. No `notifications` rows, no `notification_created` broadcasts, no Telegram outbox rows.

---

## Phase 2 — backend producer (record watch round diffs)

New file: `internal/scheduler/watch_changes.go`

Define:

```go
type watchHTTPSnapshot struct {
    URL         string
    StatusCode  int
    Title       string
    Server      string
    Technologies string
    RedirectURL string
}

type watchChange struct {
    URL        string
    ChangeType string
    OldValue   string
    NewValue   string
    Severity   string
    Metadata   string // JSON
}
```

Functions:

```go
func snapshotWatchHTTP(ctx context.Context, db *database.DB, targetID string) (map[string]watchHTTPSnapshot, error)
func snapshotWatchHosts(ctx context.Context, db *database.DB, targetID string) (map[string]bool, error)
func diffWatchHTTP(before, after map[string]watchHTTPSnapshot) []watchChange
func diffWatchHosts(before, after map[string]bool) []watchChange
func (s *Scheduler) insertWatchRoundChanges(ctx context.Context, taskID, targetID string, changes []watchChange)
```

Rules for `diffWatchHTTP`:

- Match rows by `url`.
- New URL → skip. A newly live host is already covered by the host snapshot and scope landing.
- Removed URL → `subdomain_removed` with `old_value = host`, `new_value = ""`.
- `StatusCode` differs → `status_change`.
  - `old_value = fmt.Sprintf("status=%d title=%s", old.StatusCode, old.Title)`
  - `new_value = fmt.Sprintf("status=%d title=%s", new.StatusCode, new.Title)`
  - `metadata` holds `old_code` and `new_code` as integers.
- `Title` differs → `page_change` with plain old/new title strings.
- `Server` or `Technologies` differs → `tech_change` with readable old/new strings. Avoid dumping raw JSON unless needed; join technologies with `", "`.
- `RedirectURL` differs → `http_change` with old/new redirect URLs.
- Severity map:
  - `status_change`: `medium` when 2xx ↔ non-2xx or 3xx ↔ 5xx; otherwise `low`.
  - `page_change`: `low`.
  - `tech_change`, `http_change`: `low`.
  - `new_subdomain`, `subdomain_removed`: `medium`.

Use `idx_http_services_target` and `idx_subdomains_target`. Cap snapshots at 5,000 rows per target if a project is huge; log when capped.

If the implementer prefers to share severity logic, export `classifyChangeSeverity` in `internal/scanner/monitor_engine.go` (around lines 122–139) as `scanner.ChangeSeverity` and call it. Otherwise duplicate the small map and add a comment pointing at the source.

`insertWatchRoundChanges` must:

- Batch all rows in one transaction.
- Use `uuid.New().String()` and `CURRENT_TIMESTAMP`.
- Log and continue on error. Never fail a watch round because audit write failed.

### 2.1 Hook into the module loop

File: `internal/scheduler/scheduler.go`

Wrap `runPlannedModule` (closure at lines 2038–2064). Only run this when `taskType == watchScanType`. The closure captures snapshots only. It does **not** write rows.

Declare outer variables next to `runPlannedModule`:

```go
var beforeHTTP, afterHTTP map[string]watchHTTPSnapshot
var beforeHosts, afterHosts map[string]bool
var watchDiffModule string
```

Pseudo-code for the closure:

```go
runPlannedModule := func(moduleCtx context.Context, module string) error {
    moduleCtx = scanner.WithCoverageReporter(moduleCtx, ...existing...)

    if taskType == watchScanType {
        watchDiffModule = module
        switch module {
        case ModuleHTTPProbe:
            beforeHTTP, _ = snapshotWatchHTTP(moduleCtx, s.db, targetID)
        case ModuleSubdomainEnum:
            beforeHosts, _ = snapshotWatchHosts(moduleCtx, s.db, targetID)
        }
    }

    var err error
    switch module {
    case ModuleSubdomainEnum:
        err = runSubdomainRootFanout(...)
    case ModuleParamDiscovery, ModuleTimeMachine:
        err = runWebRootFanout(...)
    default:
        err = s.runModule(moduleCtx, module, targetID, domainFor(module), logFn)
    }

    if taskType == watchScanType && err == nil {
        switch module {
        case ModuleHTTPProbe:
            afterHTTP, _ = snapshotWatchHTTP(moduleCtx, s.db, targetID)
        case ModuleSubdomainEnum:
            afterHosts, _ = snapshotWatchHosts(moduleCtx, s.db, targetID)
        }
    }
    return err
}
```

Insert the diff rows in the single-module branch at `scheduler.go:2304-2353`, after `skipped, timedOut := finishPhase()` (line 2315) and after `phaseStatus, phaseReason := phaseOutcome(...)` (line 2316):

```go
if taskType == watchScanType && !skipped && !timedOut && err == nil && modCtx.Err() == nil {
    switch watchDiffModule {
    case ModuleHTTPProbe:
        s.insertWatchRoundChanges(ctx, taskID, targetID, diffWatchHTTP(beforeHTTP, afterHTTP))
    case ModuleSubdomainEnum:
        s.insertWatchRoundChanges(ctx, taskID, targetID, diffWatchHosts(beforeHosts, afterHosts))
    }
    beforeHTTP, afterHTTP, beforeHosts, afterHosts, watchDiffModule = nil, nil, nil, nil, ""
}
```

Important:

- Gate on `skipped` and `timedOut` from `finishPhase()`. `err == nil` alone is wrong. A cancelled or timed-out phase can return `nil` from the module. `scheduler.go:2194-2210`, `2266-2288`, and `2315-2339` show that the ledger uses `finishPhase()` as the authority.
- Watch modules never enter the prioritized or parallel branches today. `subdomain_enum` and `http_probe` are not in `injectionParallelGroup` or `perAssetModuleSet`. If that changes, add the same gate per module result in those branches.
- Keep the existing coverage reporter code unchanged.
- Do **not** run this for `monitor_watch` or deep tasks.
- Snapshot after the whole module, not inside `runSubdomainRootFanout`.
- If a module fails, is skipped, or times out, skip its diff write. The task row and bell already show the failure.

### 2.2 Round summary

Do not add a new summary table. The `tasks` row already has `status`, `error`, `started_at`, `finished_at`, and `duration`. The API joins it with `watch_round_changes` and `watch_scope_events` to produce counts. This avoids duplicate state.

---

## Phase 3 — backend API

New file: `internal/api/changes_handlers.go`

### 3.1 Unified change entry

Response row:

```go
type ChangeEntry struct {
    ID         string         `json:"id"`
    Source     string         `json:"source"`     // monitor | watch | scope | notification
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
    DetectedAt string         `json:"detected_at"`
}
```

Category map (share it with the frontend model docs, but keep one implementation in Go):

| Change type / notification type | Category |
|---|---|
| `status_change`, `http_change`, `page_change` | `http` |
| `js_change`, `css_change`, `security:script_*`, `security:stylesheet_*` | `scripts` |
| `security:*` | `security` |
| `tech_change` | `tech` |
| anything with `header`, including `security_header_removed` | `headers` |
| `new_subdomain`, `subdomain_removed`, `scope_landed`, `scope_re_eligible` | `assets` |
| `watch_failed`, `watch_kind_conflict`, `monitor_failed`, `monitor_escalation_started`, `scan_auto_paused` | `alerts` |

### 3.2 Query

Build a `UNION ALL` over four sources. Apply filters in an outer query so every source behaves the same.

Sources:

1. `monitoring_changes` → `source='monitor'`, `category` from `change_type`.
2. `watch_round_changes` → `source='watch'`, `category` from `change_type`.
3. `watch_scope_events` → `source='scope'`, `change_type = event_type` mapped to `scope_landed` / `scope_re_eligible`, `old_value=''`, `new_value=identifier`. Use the real `program_id` column (`migrations.go:1892`) for display. Join `project_programs` for a program name if needed.
4. `notifications` → `source='notification'`, but **exclude** `type='scope_landed'` to avoid a duplicate row with source 3. Map other types through the bucket logic in `internal/api/notification_handlers.go:27-47`.

Join `targets` for `target_name`. Use `COALESCE` on all nullable text columns. Select a literal `'{}'` for sources without a `metadata` column (`monitoring_changes`, `notifications`). Parse the resulting JSON into `map[string]any`; use an empty map when it is missing or invalid. Order by `detected_at DESC, id DESC`.

Query params:

- `target_id` — optional.
- `category` — optional, one of the table above plus `all`.
- `severity` — optional (`critical|high|medium|low|info`).
- `source` — optional (`monitor|watch|scope|notification`).
- `task_id` — optional. Used by the round timeline.
- `since` — optional RFC3339 or `YYYY-MM-DD HH:MM:SS`.
- `page`, `limit` — standard envelope; default `limit=100`, max `500`.

Response:

```json
{ "data": [ChangeEntry...], "total": 123, "page": 1, "limit": 100 }
```

Mirror `handleListMonitoringChanges` in `internal/api/finding_handlers.go:615-689` for pagination and error handling.

### 3.3 Round list

Add `handleListWatchRounds` in the same file, or in `internal/api/watch_coverage.go`.

`GET /api/watch/rounds`

Params: `target_id` optional, `page`, `limit`.

Query `tasks` where `type = 'watch_scan'`, newest first. For each row compute:

- `change_count` — count from `watch_round_changes` by `task_id`.
- `scope_landed` — count from `watch_scope_events` joined by target in the round window. Exact window is hard; if it is too costly, omit this count and show only `change_count`.
- `error` — from `tasks.error`.
- `status`, `started_at`, `finished_at`, `target_id`, `target_name`.

Do not read `task_logs` in this endpoint. The log is already available through the existing task log API.

### 3.4 Routes

File: `internal/api/router.go`

Register near the existing target changes route (line 209) and watch-scope routes (lines 137–138):

```go
api.HandleFunc("/changes", h.requireAuth(h.handleListChanges)).Methods("GET")
api.HandleFunc("/watch/rounds", h.requireAuth(h.handleListWatchRounds)).Methods("GET")
api.HandleFunc("/targets/{id}/changes", h.requireAuth(h.handleListTargetChanges)).Methods("GET")
```

Use the `api` subrouter. It carries `jsonMiddleware`, `corsMiddleware`, and `targetScopeMiddleware` (`router.go:101-104`). Do not call `r.HandleFunc("/api/...")`; that skips all of them and leaves the endpoint unauthenticated.

- `handleListTargetChanges` forces `target_id` from the route. `targetScopeMiddleware` already enforces ownership on `/api/targets/{id}/...`.
- `/api/changes` does **not** pass through `targetScopeMiddleware` (`router.go:398-400` skips paths outside `/api/targets/`). The handler must call `h.callerScope(r)` and add this clause to every source in the union for non-admins:

```sql
AND EXISTS (SELECT 1 FROM targets t WHERE t.id = <source_alias>.target_id AND t.owner_id = ?)
```

Exception: the `notifications` source must keep the bell's shared-row rule (`notification_handlers.go:84-86`). Use `COALESCE(n.target_id,'')='' OR EXISTS(...)`. A plain `EXISTS` would hide target-less notices such as catalog sync from non-admins.

Mirror `notification_handlers.go:71-101`. Add the user ID to the query args once per source. Never return target rows for a target the user cannot read.
- Apply the same owner clause to `handleListWatchRounds` for non-admins.

---

## Phase 4 — frontend model and shared explorer

### 4.1 API client and types

File: `frontend/src/types/index.ts`

Add:

```ts
export type ChangeCategory =
  | 'http' | 'scripts' | 'security' | 'tech' | 'headers' | 'assets' | 'alerts'

export interface ChangeEntry {
  id: string
  source: 'monitor' | 'watch' | 'scope' | 'notification'
  target_id: string
  target_name: string
  task_id?: string
  url: string
  change_type: string
  category: ChangeCategory
  severity: string
  old_value: string
  new_value: string
  metadata?: Record<string, unknown>
  detected_at: string
}

export interface WatchRound {
  id: string
  target_id: string
  target_name: string
  status: string
  error: string
  started_at: string
  finished_at: string
  change_count: number
}
```

Replace the old `ChangeFilter` union with the exported `ChangeCategory` above. Remove `css` from the top-level filters. Add `assets` and `alerts`. The Scripts subtab gets its own JavaScript / Stylesheets chips.

File: `frontend/src/lib/api.ts`

Add:

```ts
changes.list(params): Promise<{ data: ChangeEntry[]; total: number; ... }>
changes.forTarget(targetId, params)
watchApi.rounds(params): Promise<WatchRound[]>
```

Use the same `{data,total}` envelope handling as `fetchAllPaged()` (lines 42–74). For the global page, keep server-side pagination. For the per-target view, loading all pages is fine because the existing tab already does this through `findingsApi.monitoringChanges()` (lines 350–364).

### 4.2 Extract and extend the model helper

New file: `frontend/src/components/changes/changesModel.ts`

Move these from `TargetDetail.tsx` (lines 25–97):

- `ChangeFilter`
- `CHANGE_FILTERS`
- `monitorRowKind`
- `changeBadgeVariant`
- `MonitorChangeGroup`
- `groupMonitorChanges`
- `OCCURRENCE_PAGE_SIZE`

Add mapping for the new types:

```ts
CATEGORY_BY_TYPE = {
  status_change: 'http',
  http_change: 'http',
  page_change: 'http',
  js_change: 'scripts',
  css_change: 'scripts',
  tech_change: 'tech',
  new_subdomain: 'assets',
  subdomain_removed: 'assets',
  scope_landed: 'assets',
  scope_re_eligible: 'assets',
  security_header_removed: 'headers',
  watch_failed: 'alerts',
  ...
}
```

Keep named re-exports in `TargetDetail.tsx` so `TargetDetail.monitor.test.ts` and `TargetDetail.groups.test.ts` keep working.

Also change the grouping key. Give `groupMonitorChanges` an optional `identity` string. Key on `identity + '\0' + change_type + '\0' + old_value + '\0' + new_value`. Pass `target_id + ':' + task_id` from `ChangesExplorer`, and `''` from the per-target tab. Two projects with the same `403 → 200` must not merge on `/changes`. The empty identity keeps the existing tests green.

Add a `critical` case to `changeBadgeVariant`. It currently handles only high, medium, low, and info (`TargetDetail.tsx:54-64`).

Add pure helpers with tests:

```ts
parseStatusTransition(oldValue, newValue): { oldCode?: number; newCode?: number }
inlineDiffPieces(oldValue, newValue): { kind: 'same'|'added'|'removed'; text: string }[]
```

`inlineDiffPieces` uses `diffWordsWithSpace` from the already-installed `diff` package. `parseStatusTransition` uses `/(?:status=)?([1-5]\d{2})/` on both strings.

### 4.3 Inline color diff

New file: `frontend/src/components/changes/InlineChangeDiff.tsx`

Props: `oldValue`, `newValue`, `changeType`.

Render:

- `status_change`: two pills, old and new. Use `statusCodeColor()` from `frontend/src/lib/utils.ts:60-66`. Always show the digits. Render `403 → 200` with an arrow glyph.
- Everything else: word-level diff spans.
  - removed: `bg-severity-medium/10 text-severity-medium line-through`, prefix `−`
  - added: `bg-severity-low/10 text-severity-low`, prefix `+`
  - same: `text-text-muted`
  - full old and new strings in `title` attributes

Color is never the only signal. Keep the `+` / `−` glyphs and the badge text.

### 4.4 Round timeline

New file: `frontend/src/components/changes/RoundTimeline.tsx`

- Collapsible list of recent `WatchRound[]`.
- Each row: status dot from `TASK_STATUS_DOT` in `Dashboard.tsx:153-156`, target name, relative time via `timeAgo()`, duration, `change_count`, error text when present. `TASK_STATUS_DOT` is currently local. Export it from `Dashboard.tsx` or define the same map inside `RoundTimeline`. Do not write a failing import.
- Clicking a round sets `task_id` filter in the explorer and highlights the row.
- Empty state: "No watch rounds yet."
- Use `divide-y divide-white/[.05]` and uppercase section labels, as in `Tasks.tsx:183-196`.

### 4.5 Scope and notifications panels

New files:

- `frontend/src/components/changes/ScopeEventsPanel.tsx`
  - Calls `targetsApi.watchScopeEvents(id)` and `promoteWatchScope()` (already in `api.ts:149-152`).
  - Move the existing watch-scope card from `TargetDetail.tsx:1261-1287` here.
  - Keep the `Promote to Deep seed` action.
  - For the global page, render one panel per selected target; do not load scope events for all targets at once.

- `frontend/src/components/changes/ChangesNotificationsPanel.tsx`
  - Calls `notifications.list(bucket)` (already in `api.ts:539-547`).
  - Buckets: `all | deep | watch | findings`, same as `TopBar.tsx:128-161`.
  - `sevDot` at `TopBar.tsx:10-16` is local. Copy the small map into a shared `frontend/src/lib/notifications.ts` or duplicate it here. Do not import it from `TopBar`.
  - `openNotif()` at `TopBar.tsx:178-188` is local to the component. Extract it to `frontend/src/lib/notifications.ts` as `openNotification(n, navigate, markRead)` and call it from both TopBar and this panel.
  - Poll every 60 s and listen to `notification_created`, `scope_landed`, `task_finished`.

### 4.6 Main explorer

New file: `frontend/src/components/changes/ChangesExplorer.tsx`

Props:

```ts
{ targetId?: string; compact?: boolean }
```

State:

- `subtab`: `overview | http | scripts | assets | alerts`
- `category` chip filter: `all | security | scripts | http | tech | headers | assets | alerts` (no top-level `css`; Scripts has its own JavaScript / Stylesheets chips)
- `severity`, `source`, `since`, `targetId` (when global)
- `selectedTaskId`
- `visibleCount`, `expandedOccurrences`, `diffView`

Layout:

1. KPI strip: changes in range, status flips, new scope hosts, failed rounds, last detection. `SplitStat` at `Dashboard.tsx:122-147` is currently local. Export it first, or move it to a shared UI module. Then use it when a split is useful.
2. `RoundTimeline` (compact on per-target view).
3. Subtab bar using `.segmented-control` (`frontend/src/index.css:161-163`, used by `UpdateCenter.tsx:120-123`).
4. Filter row: chips from the updated `CHANGE_FILTERS` (the categories above), severity select, source select, time range select, target select (global only). Inside the Scripts subtab, add a second small chip row: All scripts / JavaScript / Stylesheets.
5. Grouped change list:
   - Columns: Target (global only), When, Source badge, Change, Before → After, Round.
   - Group with `groupMonitorChanges()` so repeated identical changes collapse into one row with occurrence expander. Keep the two-level windowing: `PAGE = 200` and `OCCURRENCE_PAGE_SIZE = 200`. Do not use `VirtualList`; rows wrap and have variable height.
   - Source badge: `Watch`, `Deep`, `Scope`, `Bell`. Use accent for Watch, muted for Deep, severity-medium for Scope.
   - `Diff` button only when `source === 'monitor'` and `change_type` is `css_change` or `js_change`. Opens existing `frontend/src/components/targets/ChangeDiffViewer.tsx`.
6. Footer with "distinct change group(s) · N change(s)" and "Load N more".

Live refresh:

- Keep the existing 3 s debounce on `task_progress` and immediate `task_finished` reload from `TargetDetail.tsx:658-730`.
- Add `scope_landed` and `notification_created` listeners.
- Global page polls every 30 s.

Empty states per subtab:

- Overview: "No changes recorded yet."
- HTTP & status: "No HTTP or status changes detected."
- Scripts: "No script diffs. Watch rounds do not fetch JavaScript; run a deep scan to track script drift."
- Assets & scope: "No new hosts or scope landings."
- Alerts: "No notifications in this bucket."

### 4.7 Global page and navigation

New file: `frontend/src/pages/Changes.tsx`

```tsx
export default function Changes() {
  return <div className="..."><h1>Changes</h1><p>One timeline for watch rounds and monitoring.</p><ChangesExplorer /></div>
}
```

Wire it in:

- `frontend/src/App.tsx:56-57`: add `<Route path="changes" element={<Changes/>}/>` near `findings`.
- `frontend/src/components/layout/Sidebar.tsx:68-80`: add `{ to: '/changes', label: 'Changes', Icon: Icons.changes }` to Operations, directly after the Projects/Targets item (line 72). Add a simple diff/pulse icon to the local `Icons` map. It is a main navigation item, not a tab inside Targets.
- `frontend/src/components/layout/TopBar.tsx:22`: add `changes: 'Changes'` to the breadcrumb label map.

### 4.8 Per-target tab

File: `frontend/src/pages/TargetDetail.tsx`

- Keep tab id `monitor`, label `Changes`, in `tabGroupsFor()` (lines 144–159).
- Replace the current monitor body (lines ~1458–1996) with:

  ```tsx
  <ChangesExplorer targetId={id} compact />
  ```

- Keep the existing imports/re-exports needed by tests.
- Remove the duplicate watch-scope card from lines 1261–1287; `ChangesExplorer` renders it in the Assets & scope subtab.
- Keep the existing help text that monitor is disabled for watch projects, but update it: watch changes now appear here automatically.

---

## Phase 5 — tests

### Backend (Go)

New `internal/scheduler/watch_changes_test.go`:

- `diffWatchHTTP` detects `403 → 200` with correct old/new and `medium` severity.
- Title-only change produces `page_change`.
- New and removed hosts produce `new_subdomain` / `subdomain_removed`.
- Unchanged snapshots produce zero rows.
- `insertWatchRoundChanges` writes rows with the right `task_id`.
- Deep task path writes nothing.

Update `internal/scheduler/watch_test.go` and `watch_retention_test.go`:

- Round execution produces rows in `watch_round_changes`.
- A skipped or timed-out phase produces no rows.
- Deleting a finished watch task does **not** delete `watch_round_changes` rows (no FK cascade).
- Retention prunes globally with `WatchChangesRetentionDays`. It also prunes mixed deep/watch projects and runs when there are no watch-only targets.

New `internal/api/changes_test.go`:

- `/api/changes` filters by target, category, severity, source, task, and `since`.
- Pagination is stable and `id` is the tiebreaker.
- `scope_landed` appears once from `watch_scope_events`, not twice from notifications.
- No row leaks across targets.
- `/api/targets/{id}/changes` honours the routed target id.

Migration test:

- Table and all three indexes exist after `RunMigrations`.

### Frontend

New `frontend/src/components/changes/changesModel.test.ts`:

- New change types map to the right category.
- `parseStatusTransition` handles `status=403 title=Forbidden` and bare codes.
- `inlineDiffPieces` marks changed words only.

New `frontend/src/pages/Changes.test.tsx`:

- Renders KPIs, timeline, subtabs, and grouped rows from mock data.
- Subtab click changes the list.
- Round click filters by `task_id`.
- Empty states render.

Keep `TargetDetail.monitor.test.ts` and `TargetDetail.groups.test.ts` green after the extraction.

### Full verification

```sh
go build ./...
go vet ./...
go test ./...
cd frontend && npm test -- --run
cd frontend && npm run build
```

Also grep for conflict markers:

```sh
git grep -nE '^(<<<<<<<|=======|>>>>>>>)'
```

---

## Phase 6 — docs

Update, after the user's uncommitted edits are committed:

- `docs/SCANNING_GUIDE.md`: describe the new Changes feed, the 180-day window, and the fact that watch rounds do not fetch JS.
- `docs/V5_1_0_RELEASE_NOTES.md`: add a short "Watch changes timeline" bullet.

Do not edit these files until the user confirms their current drafts.

---

## Acceptance criteria

1. A watch round that flips a host from `403` to `200` writes one `status_change` row with `old_code=403`, `new_code=200`, and `task_id` set.
2. The global `/changes` page shows that row with the target name, round ID, and colored `403 → 200` pill.
3. Clicking the round filters the feed to that round only.
4. Scope landings appear once in Assets & scope, with the `Promote to Deep seed` action still working.
5. Deep JS/CSS diffs still open the full `ChangeDiffViewer` drawer.
6. Watch-only projects show the Scripts empty-state message instead of a blank tab.
7. The bell receives no new rows for ordinary changes.
8. Filters, pagination, and per-target scoping work.
9. All tests and builds pass.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Snapshot cost on large targets | Query only the two indexed tables; cap at 5,000 rows; log when capped. |
| SQLite write contention during a round | Batch change rows in one transaction; ignore write errors with a warning. |
| Duplicate rows on repeated rounds | Diff is computed before/after inside one round, so unchanged values produce no rows. |
| Bell flood | No notification writes in the producer; exclude `scope_landed` notifications from the union. |
| Duplicate landing rows | Scope comes only from `watch_scope_events`. |
| Stale frontend rows during refresh | Keep `typeof` guards in `monitorRowKind` / `changeBadgeVariant`; keep stable group keys. |
| Existing tests break after extraction | Re-export moved helpers from `TargetDetail.tsx`. |
| User's uncommitted work gets overwritten | Commit or stash it before creating the feature branch. |
