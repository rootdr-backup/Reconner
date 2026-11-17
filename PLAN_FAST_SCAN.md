# Reconner — two-tier scanning (deep + breadth/watch)

Status: IMPLEMENTING (v13). The plan now lives in the repo as `PLAN_FAST_SCAN.md`.
Repo: /home/void/clones/Reconner, branch `feature/two-tier-watch-scanning` (forked from `main`).
Progress is tracked by the checkboxes in §10. Every finished task gets an `[x]`.
Untouched existing plans: `docs/HYBRID_GUIDED_CRAWL_PLAN.md`, `docs/RESEARCH_BACKLOG_2026Q3.md`.

This is one consolidated document. One numbers table, one design per topic, one task list.

---

## 1. The numbers (single source of truth: `internal/config/config.go`)

Every knob gets a doc comment stating the default and the reason. The same table goes into
`docs/SCANNING_GUIDE.md` and the release notes.

| Setting | Key | Default | Why |
|---|---|---|---|
| Global scan ceiling | `Limits.MaxConcurrentScans` | 2 | Total running scans (deep + watch). Ceiling = `min(this, runtime.NumCPU())`. |
| Deep lane cap | `Limits.MaxConcurrentDeepScans` | 1 | Deep scans are the expensive tier. Also bounded by today's `effectiveMaxConcurrent` (memory/CPU pressure aware). |
| Watch lane cap | `Limits.MaxConcurrentWatchScans` | 1 | One watch round at a time. Drops to 0 while a deep task is PENDING or running. |
| Watch round gap | `WatchRoundsMinGap` | 30 min | Minimum wait before the next chained round of the same project. |
| Watch HTTP threads | `Limits.WatchHTTPThreads` | 10 | httpx `-threads` per watch round. Deep keeps `Workers.HTTPProbing` (auto 40). |
| Watch HTTP rate | `Limits.WatchHTTPRateLimit` | 25 rps | httpx `-rate-limit` per watch round. Deep keeps `Limits.HTTPRateLimit` (150). |
| Watch source timeout | `WatchSourceTimeoutMinutes` | 5 | Per-source timeout for ONE discovery tool. There is NO shared round budget: DNS admission and the HTTP probe always run to the end. |
| Watch sources | `WatchEnumerationSources` | see §3.2 | Which discovery sources the watch tier may use. |
| Watch row retention | `WatchRowsRetentionDays` | 30 days | Prunes raw rows that a watch round produced. Landed scope, notifications, deep-scan rows and task rows survive. |
| Watch scope event retention | `WatchScopeEventsRetentionDays` | 180 days | Prunes `watch_scope_events` rows older than this. |
| Watch notification cap | `WatchNotifyHostCap` | 20 | Host names listed per grouped message. The count is always shown. |
| Watch failure limit | `WatchFailLimit` | 3 | Consecutive failed watch rounds before the chain stops for that project. |
| Task priority | (fixed) | deep 5, watch 1 | Deep starts first when a slot frees. |

Priority order in code: global ceiling → deep lane cap → watch lane cap.

## 2. Coverage model

New columns on `targets`:

```
watch_only       INTEGER NOT NULL DEFAULT 0   -- 0 = deep, 1 = breadth/watch
watch_last_run   DATETIME                     -- last finished watch round
watch_next_run   DATETIME                     -- when the next watch round may start
watch_fail_count INTEGER NOT NULL DEFAULT 0   -- consecutive failed watch rounds
watch_root_index INTEGER NOT NULL DEFAULT 0   -- which domain/wildcard asset the next round enumerates
watch_paused     INTEGER NOT NULL DEFAULT 0   -- 1 = the watch chain is stopped for this project
```

`watch_last_run`/`watch_next_run` are DATETIME, like `monitor_last_run`. The due query compares
them as strings against SQLite `datetime('now')`, so every write uses the SQLite layout
`YYYY-MM-DD HH:MM:SS`: `CURRENT_TIMESTAMP` for "now", `datetime('now', '+30 minutes')` for
"now + gap". The model fields are `*time.Time`. A Go-formatted timestamp would compare wrongly
and the round would never fire.

Rules enforced in the API, not only in the UI:

- 0 → 1 (flip to watch): `watch_only=1`, `watch_next_run=CURRENT_TIMESTAMP` (first round starts now),
  `monitor_enabled=0`, `monitor_last_run=NULL`, `watch_fail_count=0`, `watch_paused=0`.
- 1 → 0 (flip to deep): `watch_only=0`, `watch_next_run=NULL`, `watch_paused=0`. `monitor_enabled`
  stays as it is.
- `watch_paused` is the single "stop" switch for a project. It is set when the chain stops
  (cancelled, or the failure limit reached) and it is the operator's pause escape hatch. The due
  query never uses `COALESCE(watch_next_run, ...)`: a NULL `watch_next_run` means "not scheduled"
  and must NOT make the project due.
- `kind` is NOT silently rewritten. A project whose assets include network assets stays `mixed`,
  and a watch round only runs on a `kind='web'` project. The flip API refuses a `mixed` or
  `network` project outright (see below), so the operator must drop the network asset rows
  first. The UI's "keep only web assets" action does that and logs the dropped identifiers.
- If a network asset is added to a watch-only project later, the project turns `mixed` and the
  watch round stops. The asset API refuses a network asset on a watch-only project with a 400
  ("this project runs watch rounds; network assets are not supported"), so the project cannot
  fall into that state silently. If it happens anyway, the scheduler logs
  "watch round skipped: project <id> is mixed" once and raises one notification so the operator
  sees it.
- The flip API refuses a project whose `kind` is `mixed` or `network`. It returns 400 with the
  reason and the list of network asset identifiers. The operator must first drop the network
  assets (the UI's "keep only web assets" action). The bulk flip applies the same rule per
  project and reports which ones were refused.
- On flip to watch, the existing asset rows of the project also get `monitor_enabled=0`. The
  target flag alone is not enough: the asset rows carry their own flag, and `CreateProject`
  inserts them with `monitor_enabled=1`.
- `monitor_enabled` is forced to 0 for watch-only projects. `handleUpdateMonitor` rejects
  `monitor_enabled=1` on a watch-only project with a clear error.
- `monitor_enabled=0` only gates `monitor_watch` tasks. It never gates enumeration:
  `loadSubdomainRoots` reads every approved `domain`/`wildcard` asset regardless of it (see §2).

## 3. Watch discovery tier (what a watch round actually does)

Modules: `subdomain_enum` (passive only) + `http_probe`. Everything else is skipped and reported.

### 3.1 What "passive" means here

- Passive (dataset lookups, no traffic to the target): `subfinder -all`, `assetfinder`, `chaos`.
  The 7 HTTP sources in `subdomain.go` (crt.sh, certspotter, hackertarget, rapiddns, otx,
  anubis, urlscan) are passive as well, but they are OFF in the watch tier by default (D28):
  `subfinder -all` already queries its own provider list, which covers certificate logs and
  archives. The operator can switch any of them back on in the UI.
- NOT passive (active against the target): `findomain` (DNS wordlist brute + permutations),
  `activeEnum`/`deepDNSEnum` (brute + alterx), `vhostScan` (active Host-header probing),
  `asnmap` CIDR sweep, and the httpx probe itself (one request per host per scheme).
- The watch tier therefore ships four sources: `subfinder -all` + `assetfinder` + `chaos`
  (passive datasets) + `findomain` (active DNS brute; the operator reports it finds hosts in
  under 20 seconds). The scanner's own brute/permutation phase, recursion, ASN and vhost
  probing stay OFF.
- So a watch round is NOT fully passive. It sends DNS queries to the target's nameservers
  (findomain plus the DNS admission pass) and two HTTP requests per host (http and https,
  because httpx has no scheme flag).
- The httpx probe stays in the watch tier because liveness needs at least one request to the
  host. It is one request per host per scheme, root path only, and it is the only HTTP traffic
  a watch round sends to a target. This is the part that cannot be made passive without losing
  the alive/dead answer.

### 3.2 Per-source toggles (the UI knob the operator asked for)

New config `WatchEnumerationSources []string` (ids): `crtsh`, `certspotter`, `hackertarget`,
`rapiddns`, `otx`, `anubis`, `urlscan`, `subfinder`, `assetfinder`, `chaos`, `findomain`.
Default (operator decision D28): `subfinder,assetfinder,chaos,findomain`.

- `subdomain.go` reads the list from the scan context (set by the scheduler from the config)
  and skips a source that is not on the list, logging one line per skipped source with the
  reason ("disabled by operator" / "tool not installed" / "API key missing").
  The context value is new: `scanner.WithWatchSources(ctx, []string)` in
  `internal/scanner/scan_options.go`. The scheduler sets it from `WatchEnumerationSources` for
  every `watch_scan` task. Deep tasks leave it unset, so deep scans use every source.
- The list applies to the WATCH tier only. Deep scans keep every source, including gau,
  waybackurls, scilla and findomain (D10: deep tier unchanged).
- Removed from the watch tier per the operator: `gau`, `waybackurls`, `scilla`, and the 7 HTTP
  sources (`crtsh`, `certspotter`, `hackertarget`, `rapiddns`, `otx`, `anubis`, `urlscan`).
  They stay in the UI as switches, so one click puts them back.
  Added: `chaos` (projectdiscovery dataset tool). The API key is operator-editable in the UI:
  - Config field `ChaosAPIKey string \`json:"chaos_api_key"\`` (`internal/config/config.go`), with
    a `RECON_CHAOS_API_KEY` env fallback next to the other key fallbacks.
  - The key card lives in **System → Integrations → "Passive intelligence providers"**, next to
    securitytrails, shodan, censys, fofa, quake, zoomeye and virustotal. Adding it is one line in
    `apiKeyFields()` (`internal/api/system_handlers.go:24-41`); the card, the masked value and the
    "● connected / ○ not configured" states already exist for the other keys, so no new UI is
    needed. There is no page called "API Keys" in Reconner.
  - The CLI reads `PDCP_API_KEY`. The executor sets `cmd.Env = os.Environ() + HOME + PATH`
    (`internal/tools/executor.go:125,249,362,428`), so the plan adds a per-tool env injection:
    the chaos run gets `PDCP_API_KEY=<key>` in its environment.
  - With no key configured the tool is skipped and one log line says "chaos skipped: no API key
    configured". The source stays visible in the UI, so the operator sees why it returned nothing.
- The toggles apply to the WATCH tier only. Deep scans keep every source.
- The Dockerfile needs one new tool stage entry (`chaos`) plus the two tool-list lines that
  assert the binaries exist (Dockerfile:135-136 and :402-403). The in-app tool installer catalog
  (`internal/api/tool_install.go:39-57`, `toolCatalog`) also needs a `chaos` entry
  (`{methodGo, "github.com/projectdiscovery/chaos-client/cmd/chaos@v0.5.2", "https://github.com/projectdiscovery/chaos-client", "Needs a projectdiscovery API key (PDCP_API_KEY)."}`),
  otherwise the in-app installer cannot install chaos.

### 3.3 Speed (the reason the watch tier exists)

- **A round with no working discovery tool FAILS, it does not finish.** The scanner counts the
  enabled sources that ran and returned cleanly. If every enabled source failed (missing binary,
  missing API key, non-zero exit) the round ends as `failed`, so `watch_fail_count` grows and the
  chain stops at `WatchFailLimit` instead of spinning forever on a broken setup. "0 subdomains
  found cleanly" (the tools ran, the target has nothing) stays `finished`.
- The CLI sources currently run SEQUENTIALLY with per-tool budgets: subfinder 4 min +
  assetfinder 2 min + findomain 2 min + scilla 3 min + waybackurls 3 min + gau 3 min = 17 min
  worst case per root. The 7 HTTP sources already run concurrently with them.
- Fix: in watch mode the enabled CLI sources run CONCURRENTLY, each on its OWN timeout
  (`WatchSourceTimeoutMinutes`, default 5). There is NO shared round budget. Every source gets
  its own child context: `sourceCtx, cancel := context.WithTimeout(ctx, WatchSourceTimeoutMinutes*time.Minute)`.
  A source that exceeds its timeout returns its partial result and one log line
  "source <name> stopped after <n> min". The DNS admission and the httpx phase run on the PARENT
  task context, so they always finish. The round runs to the end; nothing is cut short.
- The sources run in parallel, so the discovery phase costs the SLOWEST source, not the sum.
  With the trimmed set a round is roughly: `subfinder -all` + `assetfinder` + `chaos` +
  `findomain` in parallel (each capped at `WatchSourceTimeoutMinutes`) → DNS admission
  (`resolveAll`, dnsx) → httpx probe. Target ≈ 5-10 min per root, not 20.
- Deep scans keep the current sequential path with the existing per-tool budgets.
- **The per-source timeout uses the streaming executor path.** `tools.Executor.RunWithCallback`
  (`internal/tools/executor.go:109`) already streams stdout line by line, so a source that is cut
  off still delivers the lines it produced. The plain `Run` path collects the output in a buffer
  (`cmd.Stdout = &stdout`), so nothing is lost there either, but a killed tool's output is only
  visible after the process dies. The watch path uses `RunWithCallback` so partial results arrive
  as they are printed.
- **A timed-out source is stopped politely.** `hardenProc` (`internal/tools/executor.go:37`) sets
  `Setpgid: true` and `cmd.Cancel` to SIGKILL on the process group. The watch path sends SIGTERM
  first, waits 2 seconds, then escalates to SIGKILL, so the tool can flush and exit cleanly. The
  exit code of a killed tool is a failure for that source, not for the whole round (unless it is
  the only source, see the rule above).
- **The HTTP phase is target-wide, not root-scoped.** `HTTPScanner.Run`
  (`internal/scanner/http.go:52-79`) loads every known host of the project
  (`subdomains WHERE ip != '' OR source IN ('seed','vhost') AND catchall=0`) and probes all of
  them. Root rotation limits the ENUMERATION, not the probe. At `WatchHTTPRateLimit` 25 rps and
  two requests per host (httpx tries http and https; there is no `-scheme` flag), 200 known hosts
  is about 16 minutes of probing. The round estimate above covers the discovery phase only; the
  probe cost scales with the project's accumulated host count. This is the intended behaviour
  (liveness of every known host), and it is why the round has no host cap but the rate is capped.
- `runSubdomainRootFanout` enumerates each `domain` asset of a project SEQUENTIALLY. A project
  with N domain assets costs N rounds. The watch tier therefore enumerates ONE root per round
  and rotates:
  - The scheduler reads the approved `domain`/`wildcard` asset list for the project (the same
    query as `loadSubdomainRoots`, which orders by `created_at ASC, id ASC`, so the order is
    stable) and picks the root at `watch_root_index`.
  - Guard: if the list is EMPTY the project has no root to enumerate. The round is skipped with
    one log line ("watch round skipped: project <id> has no domain asset") and
    `watch_next_run` is moved forward by the gap, so it does not retry every minute.
  - Guard: the index is reduced before use — `idx := watch_root_index % len(roots)` — so a shrunken
    root list can never index out of range.
  - The scheduler narrows the root list to ONE root before the fan-out: `subdomainRoots` becomes
    `[]string{selectedRoot}` and `runSubdomainRootFanout` runs the module once, for that root.
    The root reaches the scanner as a function argument (`runModule(ctx, module, targetID, root,
    logFn)` → `subdomainScanner.Run(ctx, targetID, domain, logFn)`), so there is NO context value
    for it. A `WithWatchRoot` context value would be ignored.
  - After the round, `watch_root_index = (watch_root_index + 1) % len(roots)`. The next round
    uses the next root.
  - The index advances ONLY when the round FINISHED. A failed round keeps the same root, so a
    network blip does not skip that root for a full rotation (15 h for 30 domains). The escape
    from the other side is the poison root: after 2 consecutive failures on the SAME root the
    index advances anyway (the round fails, `watch_fail_count` still counts, and the chain
    survives). `watch_fail_count` stays per project; the per-root counter is a separate,
    in-memory one (`failures on this root`). A project with one root always uses index 0.

## 4. Scope eligibility and auto-land

### 4.1 Source of truth

Eligible scope = the program's eligible assets, read live:

```
project_programs (target_id → program_id)
  → bounty_program_assets WHERE active=1 AND in_scope=1 AND eligible_submission=1
```

`project_programs` is a JOIN table: one project can be linked to SEVERAL programs. The eligible
set is therefore the UNION over every program linked to the target, never the single program id
stored on a landed row:

```sql
SELECT DISTINCT a.identifier
FROM project_programs pp
JOIN bounty_program_assets a ON a.program_id = pp.program_id
WHERE pp.target_id = ?
  AND a.active = 1 AND a.in_scope = 1 AND a.eligible_submission = 1
```

A host that is eligible under ANY linked program is landable, and the out-of-scope sweep must
use the same UNION. Using only the program id stored at landing time would mark hosts of the
second program out of scope.

The project's own `assets` rows and `targets.domain` are NOT the source of truth:
`reconcileProject` never updates `targets.domain`, so it goes stale.

`eligible_bounty=1` is not required. A host that is in scope and submission-eligible is
landable even when the bounty is capped, because the operator's rule was "bounty eligible
only" = "a valid submission target". `eligible_bounty` is used only to label the row.

If `project_programs.last_checked_at` is older than 30 minutes, `reconcileProject` runs first
so the comparison uses the current program scope.

A project with NO `project_programs` row (a manual project) has an empty eligible set. The round
logs one line "no bounty program linked: scope landing disabled for this project" and lands
nothing. The discovery and the HTTP probe still run, so the operator still sees the hosts.

### 4.2 Matcher

A discovered host is eligible when it equals an eligible identifier, or when it is covered by
an eligible wildcard identifier (`is_wildcard=1`, e.g. `*.example.com`):

- Normalize both sides: lowercase, trim trailing dot, strip scheme, path and port.
- Punycode: both sides are normalized with `idna.Lookup.ToASCII` so `bücher.example.com` and
  `xn--bcher-kva.example.com` are the same host. `golang.org/x/net` is already a dependency
  (`golang.org/x/net v0.61.0` in go.mod), so `golang.org/x/net/idna` needs no new module.
- Ports: the port is stripped for MATCHING (a program asset `example.com:8443` covers
  `example.com:8443`), but the stored `assets.value` keeps `host:port` when the port is not 80
  or 443, so the port is not lost.
- Wildcards are parsed strictly: only the `*.<domain>` form is supported. A malformed or
  unsupported glob (`*example.com` without the dot, `sub.*.example.com`) is skipped with one
  warning line and is never matched, so it can never land a wrong host.
- An identifier that carries a PATH is not a bare host. If the path is not empty and not "/"
  (e.g. `https://example.com/api/v1/`), the identifier is EXCLUDED from bare-host matching:
  that program asset only covers that subpath, so the bare domain must not be landed. Such an
  identifier is kept in the report as "path-scoped, not landable".
- Exact match wins.
- Wildcard `*.example.com` matches `a.example.com` and `a.b.example.com`. It does NOT match the
  apex `example.com`.
- An IP identifier matches only that exact IP.
- Unit tests cover: case, trailing dot, scheme in the identifier, wildcard depth, apex, IP,
  path-scoped identifier (excluded), punycode vs UTF-8, non-standard port, malformed wildcard
  (skipped).

### 4.3 Landing

For each eligible host that is new to the project:

- Insert into `assets`: `name`/`value` = host, `kind='web'`, `asset_type='subdomain'` (ALWAYS
  `subdomain`, including the apex — see §4.4), `source='watch:scope'`, `source_id` =
  `watch_scope_events.id`, `approval_status='approved'`, `monitor_enabled=0`, `metadata` JSON
  with the program id and the matched asset id.
- `ON CONFLICT(target_id, value) DO NOTHING` — `assets` has `UNIQUE(target_id, value)`.
  Rows with another `source` are never rewritten.
- The stored value is LOWERCASED, because SQLite compares text with BINARY collation, so
  `Example.com` and `example.com` would otherwise be two different rows in the same project.
  A unique index on `(target_id, LOWER(value))` is added so the guarantee holds even for rows
  written by other code paths.
- Write a `watch_scope_events` row: `(id, target_id, program_id, identifier, event_type,
  asset_id, detected_at, announced, metadata)`, plus an index on `(target_id, detected_at)`.
  `announced` is 0 until the grouped message has been sent, then 1. Without it the same hosts
  are re-announced every tick forever.
- The event table is the audit trail for the operator ("Watch scope" panel).
- The landing stage is AFTER the HTTP phase, never after DNS admission. The round first
  enumerates (passive sources), then resolves (dnsx), then probes (httpx), and only the hosts
  that came back from the HTTP phase are considered for landing. A host with no HTTP result is
  not landed.
- A round lands NOTHING when the HTTP phase was skipped (httpx missing) or produced no result.
  A DNS record that was never probed is not verified, and an unverified host must not become
  approved scope. The round logs "HTTP phase produced no result: nothing landed this round".
  The same rule applies when the project has no linked program (§4.1).

### 4.4 Landed hosts are scope, not scan roots

D15 stays: a landed host does not become an enumeration root and does not join the deep tier.
`loadSubdomainRoots` takes `asset_type IN ('domain','wildcard')`, `loadProjectWebSeeds` takes
`('domain','wildcard','url','page','js','api')`. Auto-land writes `asset_type='subdomain'`, so
landed hosts are intentionally excluded from both. This is deliberate and is documented in the
code so nobody "fixes" it later. The deep tier of the same program is unchanged.

- **Promoting a landed host to a Deep seed.** Because landed rows are `asset_type='subdomain'`,
  they are invisible to a deep scan: flipping a project from Breadth back to Deep does not
  automatically pull the landed hosts into the deep scan. That is the safe default (a deep scan
  should not grow by itself), but the operator needs a way to opt in. The Watch Scope panel gets
  a "Promote to Deep seed" action, and the Breadth → Deep confirmation dialog offers the same
  thing for the selected hosts. The promotion is an explicit UPDATE:
  `UPDATE assets SET asset_type='url', monitor_enabled=0 WHERE target_id=? AND source='watch:scope' AND value IN (...)`.
  `url` is a valid entry for `loadProjectWebSeeds`, so the host becomes a web seed of the next
  deep scan. The promotion is recorded in the asset metadata (`metadata.promoted_to_deep=1`).
- **`ResolveScopeEvent` must not rewrite a landed row.** The program scope approval path
  (`internal/bounty/catalog.go:460-512`) upserts with
  `ON CONFLICT(target_id, value) DO UPDATE SET ... source='bounty:catalog', asset_type=excluded.asset_type`.
  That would overwrite the `source` and the `asset_type` of a row that the watch tier landed,
  which would silently promote it into a scan root and lose the "watch:scope" marker. The upsert
  is guarded so it never rewrites a row with `source='watch:scope'`; the promotion stays an
  explicit UPDATE from the watch scope code.

### 4.5 Hosts that leave the eligible scope

A landed host whose program asset was later removed or made ineligible stays in `assets`
(approved) but is marked `metadata.out_of_scope=1` and is excluded from the next auto-land
diff, from the "in scope" report and from the grouped notification. It is not deleted,
because history matters.

- If the host becomes eligible again (the program asset returns, or the eligibility flag
  changes back), the matcher matches it again. The `assets` row ALREADY EXISTS, so
  `ON CONFLICT(target_id, value) DO NOTHING` would change nothing and "new to the project"
  would be false. The re-eligible path therefore does an explicit UPDATE of the existing row:
  `UPDATE assets SET metadata.out_of_scope = 0, updated_at = CURRENT_TIMESTAMP
   WHERE target_id = ? AND value = ? AND source = 'watch:scope'`.
  It then writes a NEW `watch_scope_events` row and announces the host again.
- A host that is out of scope is never re-landed as a new asset row: the `assets` row stays
  and its `metadata.out_of_scope` flag flips back to 0.
- The out-of-scope SWEEP is its own pass and does not run inside a watch round. It walks ALL
  `source='watch:scope'` assets of the project and compares them with the FULL program
  eligible set (not only the root that the last round enumerated), so a host that dropped out
  of scope is marked even when no round touched its root. It runs in the program scope
  reconciliation tick (`bountyCatalogScheduler`, every 30 min), next to `reconcileProject`, so
  a project that was flipped back to Deep still gets its markers updated.
- A watch round only ADDS hosts. It never marks anything out of scope. That is the sweep's job.

## 5. Scheduling

### 5.1 Ceilings

- `globalScanCeiling()` = `min(cfg.Limits.MaxConcurrentScans, runtime.NumCPU(),
  effectiveMaxConcurrent()+1)`.
  The `+1` is deliberate: `effectiveMaxConcurrent()` is the memory guard for ONE heavy scan
  (`resourceTargetCeiling` = min(configured, cpu/2, memBudgetMB/1024) = 1 on this box), so the
  guard allows one deep scan. The watch round is a light job (a few subprocesses), so it may take
  the second slot. Without the `+1` the global ceiling would be 1 and the watch tier would never
  run.
- If `effectiveMaxConcurrent()` reports 0 (severe memory/CPU pressure), the global ceiling is
  0 too: nothing new starts, watch included. This keeps the memory guard honest for the watch
  tier.
- Deep lane cap = `min(cfg.Limits.MaxConcurrentDeepScans, effectiveMaxConcurrent())`.
  On this box `effectiveMaxConcurrent()` is 1, so deep runs one scan at a time.
- Watch lane cap = `min(cfg.Limits.MaxConcurrentWatchScans, max(0, globalScanCeiling() -
  deepLaneCap))`. The deep lane's slots are RESERVED: the watch lane can only use what the deep
  lane does not need. On this box that is min(1, 2-1) = 1.
- The watch lane does NOT close because a deep task is pending. The deep lane's reserved slot
  guarantees the deep scan never waits, so closing the watch lane on a pending deep task would
  only starve the watch tier for hours when several deep scans are queued. The deep drain runs
  first every tick, so a pending deep scan takes a free slot before any watch round does.
- Effective ceiling on this box: 1 deep + 1 watch, always. Under severe pressure: 0 + 0.

### 5.2 Why a deep scan never waits for a watch round

Global ceiling 2, watch lane 1, deep lane 1. A running watch round occupies one of the two
slots, and the second slot is reserved for the deep lane, so the deep scan always has a slot.
The deep drain runs first in every tick, so a pending deep scan is picked before any watch round.
The watch chain gap (30 min) is per project, so it never blocks the deep lane.

### 5.3 Drain

- `drainPendingTasks()` (deep) skips `type='watch_scan'` rows.
- `drainPendingWatchTasks()` selects `status='pending' AND type='watch_scan' ORDER BY
  created_at ASC LIMIT 10`. It runs from the watch tick and right after a watch task finishes.
- `runDueWatchRounds()` selects projects with `watch_only=1`, `watch_paused=0`,
  `watch_next_run IS NOT NULL AND watch_next_run <= datetime('now')`, and no active task for the
  project. There is NO `COALESCE` fallback and NO `status != 'paused'` filter: `targets.status` is
  "idle" and has no paused state ("paused" is a TASK status), and a NULL `watch_next_run` means
  "not scheduled", not "due since forever".
  It creates one `watch_scan` task per project per tick with
  `CreateTaskTyped(projectID, [subdomain_enum, http_probe, no_subdomain_brute], 1, "watch_scan")`.
  - It also requires `kind='web'`. A `mixed` or `network` project is skipped with one log line
    "watch round skipped: project <id> is <kind>" (the flip API refuses those projects, so this
    is a belt-and-braces guard).
  - Before creating, it checks for an existing `pending` or `running` `watch_scan` task for the
    project. If one exists, it skips the project this tick. No duplicates.
  - The projects are processed in DUE ORDER (`ORDER BY watch_next_run ASC`), so the project that
    has waited longest goes first.
  - The tick creates at most `MaxConcurrentWatchScans * 2` watch tasks (2 by default). Without a
    cap, 60 due projects would create 60 pending rows in one tick and the last one would wait
    hours. The rest stay due and are picked up on the next tick. The cap also covers the bulk
    flip: 50 projects flipped at once all become due at the same moment, and the cap keeps that
    from becoming a queue flood.
- The deep drain runs first, then the watch drain. Both call `tryStartTask`, which checks the
  global ceiling, so a task never starts twice.
- `tryStartTask` re-checks the target before it starts a `watch_scan` task: `watch_only=1` and
  `kind='web'` must still hold. A queued watch task whose project was flipped back to Deep in
  the meantime is dropped (marked `cancelled`) instead of running, and one log line says so.
- `tryStartTask` also refuses to start a task for a project that already has a `running` task:
  `NOT EXISTS (SELECT 1 FROM tasks WHERE target_id = ? AND status = 'running')`. Without this, a
  manual deep scan that starts while a watch task is still `pending` leaves both lanes working
  on the same project at the same time, racing on the asset and subdomain tables. The deep scan
  wins: the pending watch task waits for the next tick.
- A watch project that turns `mixed` raises ONE notification (not one per tick). The alert is
  sent once per project, tracked in `watch_fail_count`-style fashion: the scheduler remembers the
  last alerted state and only alerts again when the state changes.

### 5.4 Chained rounds

- No timeout and no host cap: a watch round always finishes. Long rounds are logged, never
  cancelled.
- Terminal rules for `watch_next_run` (written with SQLite `datetime('now', '+<gap> minutes')`):
  - finished → `now + WatchRoundsMinGap` AND `watch_fail_count = 0` (the counter counts
    CONSECUTIVE failures, so a good round clears it; otherwise three isolated failures months
    apart would stop the chain)
  - failed → `now + WatchRoundsMinGap`, `watch_fail_count += 1`; at `WatchFailLimit` (3) the
    chain stops (`watch_paused=1`, `watch_next_run=NULL`) and one notification says so.
  - interrupted → `now + WatchRoundsMinGap`
  - cancelled → `watch_paused=1`, `watch_next_run=NULL` (the chain stops; cancelling is a
    deliberate operator act)
- `watch_next_run` is ALWAYS updated to `now + WatchRoundsMinGap` on a terminal status
  (finished, failed, interrupted), even when the watch lane is saturated. The lane only decides
  whether a WORKER SLOT is free; the timestamp is just a database write. If the timestamp were
  left in the past, the next tick would re-queue the project with a zero gap and the 30-minute
  spacing would be lost.
- The re-queue is skipped when the project is deleted or is no longer watch-only. It is retried
  on the next tick, so nothing is lost.
- Server restart: `recoverPendingTasks()` (`internal/scheduler/scheduler.go:464-492`) cancels
  zombie `running`/`paused` tasks with raw SQL and broadcasts `task_cancelled`. It does NOT go
  through the terminal handler, so a `watch_scan` task killed by a crash would leave
  `watch_next_run` in the past and re-queue instantly on the first tick after the restart.
  Startup recovery therefore applies the watch terminal rule to the `watch_scan` tasks it
  cancels: `watch_next_run = now + WatchRoundsMinGap`, `watch_fail_count += 1`.

### 5.5 Other task sources

- `runDueMonitors` filters `COALESCE(watch_only,0)=0`. A watch-only project never gets a
  `monitor_watch` task, so nothing is scanned twice.
- `notifyBountyScopeEvent` excludes `watch_only=1` projects from `bounty_favorite_scan`. For a
  watch-only project it does NOT emit a `scope_landed` event (a program scope change carries no
  newly discovered host to attach, and the brought-forward round will land the new hosts a
  minute later). It only brings the next watch round forward (`watch_next_run = now`).
- `ResumeTask` calls `CreateTaskTyped` with the original `task.Type`, so a resumed watch task
  stays `watch_scan` and stays in the watch drain.
  - `remaining` is computed as the stored module list minus `completed_modules`. The stored list
    contains the pseudo-module `no_subdomain_brute`, while `completed_modules` holds only real
    modules. So `remaining` keeps the pseudo-module, and when both real modules are done,
    `remaining` holds pseudo-modules only — `createTask` then fails with "select at least one
    executable module". `ResumeTask` therefore drops pseudo-modules from `remaining` before it
    creates the task, and when nothing real is left it reports "nothing left to resume" instead
    of creating a broken task.
- `refreshTargetScanStatus` gets a `touchLastScan` flag that is FALSE for watch tasks, so
  `last_scan_at` stays "last deep scan". `scan_status` for a watch-only project reflects the
  watch round, and the UI labels it "watch".

## 6. Notifications

### 6.1 Separate kinds

- In-app `notifications.type`: `scan_deep` (deep scan finished), `scan_watch` (watch round
  finished), `scope_landed` (new eligible hosts).
  - Today the scheduler writes NO in-app row for a finished scan: `notifyScanDone`
    (`internal/scheduler/scheduler.go:2970-2991`) only calls the Telegram notifier. The only
    in-app inserts are the scanner helper (`internal/scanner/notifications.go:17`), the scheduler's
    literal `monitor_failed` row (`scheduler.go:2136`) and the bounty's `bounty_scope_change` row
    (`internal/bounty/catalog.go:441`). So the scheduler must insert the `scan_deep` and
    `scan_watch` rows itself, at the end of a task. That is also what makes the bell filter work.
  - The `notifications` table has no tier column (id, target_id, type, title, body, url,
    severity, is_read, created_at). The bell filter maps types to tiers in the API: Deep =
    `scan_deep` plus the deep-only finding types; Watch = `scan_watch` + `scope_landed`;
    Findings = every vulnerability type. No new column is needed.
  - `notificationTitle` lives in `internal/scanner/monitor.go:669` and is used by scanner-side
    notifications only. The scheduler writes literal titles. The `scope_landed` title is a
    literal in the scheduler; the map entry is only added if a scanner-side path ever writes it.
- Telegram: three new methods on the `Notifier` interface — `NotifyWatchScanStarted`,
  `NotifyWatchScanFinished`, `NotifyScopeLanded`. The existing methods stay for the deep tier.
- Telegram preferences live on `telegram_chats` (one row per chat), not on `telegram_config`.
  Three new columns go on `telegram_chats`: `notify_watch_scan_started`,
  `notify_watch_scan_finished`, `notify_scope_landed`, plus the matching checkboxes in the chat
  editor UI. Defaults: watch start OFF, watch finish OFF, scope landed ON.
- `broadcastAndScore` forwards every `notification_created` event to the Telegram "Monitor
  change" template. The scope-landed notification must not travel that path: it is sent by the
  scheduler through the new `NotifyScopeLanded` method, and the notification row is written
  without a `notification_created` broadcast.
- The bell refreshes on `notification_created`, `task_finished` and `bounty_catalog_sync`
  (`frontend/src/components/layout/TopBar.tsx`). A `scope_landed` row written without a
  broadcast would never appear. The scheduler therefore broadcasts a new `scope_landed` event
  after writing the row, and the bell adds `scope_landed` to its listener list. The event goes
  out through `s.hub.Broadcast("scope_landed", ...)` directly, so `broadcastAndScore` never sees
  it and never forwards it to Telegram.

### 6.2 Noise control

- A watch round that finds nothing new sends no message at all.
- Scope landings are grouped: ONE Telegram message per watch tick window (the watch loop ticks
  every minute) that aggregates every landing of that window across ALL projects:
  "N new eligible hosts across M programs", with up to `WatchNotifyHostCap` host names grouped
  by program. A project that lands nothing adds no message. This is the locked decision
  (D25): one message per tick window, not one per project per round.
- The grouping window is claimed IN THE DATABASE, not by a time-based key. `announced` is a
  three-state flag: `0` = unannounced, `2` = claimed by the flush in flight, `1` = sent. The
  flush claims the rows in ONE update (`UPDATE watch_scope_events SET announced = 2
   WHERE announced = 0 AND target_id IN (...)`), sends the message, then sets `announced = 1`.
  If the send fails, the claim is released back to `0` so the next window retries the alert.
  A minute-based dedupe key (`scope_landed:tick:<unix-minute>`) is NOT used: it drops the alert
  when the commit lands before the send fails, and it collides when a retry lands in the same
  minute.
- The in-app bell keeps one row per watch round that landed something: count + up to
  `WatchNotifyHostCap` names. The bell gets a `type` filter so "Watch" and "Deep" can be
  filtered apart.
- Deep-scan notifications keep their current format and their current volume.
- The `new_subdomain` notification from `subdomain.go` is suppressed for watch rounds (the
  watch tier reports through `scope_landed` instead). The suppression is driven by the watch
  context flag, not by a target flag.

### 6.3 Skipped-module reporting

The watch round lists what it skipped. `AllModules` minus the two watch modules is ~45 names,
so the report is grouped, not raw:

```
Skipped for watch tier (45 modules):
  discovery   – js_analysis, js_endpoints, timemachine
  crawling    – headless_crawl
  active      – param_fuzz, dir_discovery, backup_discovery, nuclei, sqli, ssrf, lfi, …
  (full list in the task log)
```

The grouped summary goes into the task log and the Telegram watch message; the full name list
goes into the task log only. The grouping is by module category (discovery, crawling, active,
injection, WordPress, network, postprocess). Each group is one line with the module count and
the module names. A group with more than 8 names is truncated with "…".

## 7. Retention

A periodic job prunes raw rows older than `WatchRowsRetentionDays`. The prune is scoped by TIER,
not by `watch_only` alone, so a manual deep scan on a watch project is never destroyed:

- The finding tables are NEVER pruned: `js_files` (and the `js_findings` it cascades),
  `parameters`, `directory_findings`, `admin_panel_findings`, `backup_findings`,
  `open_redirect_findings`, `nuclei_findings`, `vuln_findings`, `screenshots`,
  `monitoring_changes`, `browser_states`. A watch round runs only `subdomain_enum` and
  `http_probe`, so it never writes these rows. They belong to deep scans, and a project that
  was flipped from Deep to Watch keeps them.
- `subdomains` and `http_services` are pruned by `last_seen` (NOT `created_at` — otherwise the
  alive count churns as rows age out while the host is still alive), but only for projects whose
  task history contains ONLY watch tasks (`type='watch_scan'`). A project that ever ran a deep
  or manual scan keeps its host rows too, because those rows may belong to the deep scan.
- `task_logs` and `task_phases` are pruned only for watch tasks older than the window. The
  `tasks` rows themselves survive.
- `watch_scope_events` rows are pruned after `WatchScopeEventsRetentionDays` (180 days).
- Survives: `assets` (landed scope is the durable value), `notifications`, `tasks` rows (the
  history of what ran), and every deep-tier row.
- The prune logs one line with the table name and the deleted row count.
- Pruning `subdomains` removes hosts from the httpx input list of the next round. A pruned host
  returns when the enumeration rediscovers it. The prune is safe, but it makes the first round
  after a prune slower.
- `http_services.subdomain_id` has no foreign key, so pruning a `subdomains` row leaves an
  orphan reference in `http_services` until that row is pruned too. The prune order handles it:
  `http_services` first, then `subdomains`.
- The prune runs every hour in a single transaction. It deletes in dependency order (child rows
  first), uses the DSN `busy_timeout` and `_txlock=immediate`, and retries once on
  `SQLITE_BUSY`.
- A task whose logs were pruned shows "logs pruned" in the task detail. The prune keeps the
  `task_logs` and `task_phases` of the most recent 100 watch tasks, so recent rounds stay
  inspectable.
- The `tasks` table itself grows: 100 watch projects × 48 rounds a day ≈ 144,000 rows a month.
  Finished `watch_scan` task rows older than 90 days are pruned as well (their logs and phases
  go with them, because `task_logs` and `task_phases` cascade on `task_id`). Deep task rows are
  never pruned.
- Because the task list and the dashboard counters read these tables, the migration adds the
  indexes the new queries need: `tasks(type, status, created_at DESC)` for the coverage filter
  and the drain, `tasks(target_id, created_at DESC)` for the per-project task list, and
  `targets(id, watch_only)` for the split counters.

## 8. API, UI and surfaces

### 8.1 API

- `GET/PATCH /targets/{id}`: `watch_only`, `watch_last_run`, `watch_next_run`, `watch_fail_count`,
  `watch_root_index`, `watch_paused`.
  The PATCH enforces the flip rules of §2 (including forcing `monitor_enabled=0`). It also accepts
  `watch_paused` for the pause switch.
- `POST /targets/bulk/coverage`: `{ids: [...], watch_only: bool}` — bulk flip with the same rules.
  It returns per-project results (`{id, ok, reason}`), so the UI can list which projects were
  refused and why.
- `GET /targets/{id}/watch-scope-events`: the landing audit trail.
- `GET/PATCH /system/scan-config` / `PATCH /system/scan-config`: the new knobs, clamped:
  watch concurrency 0..2, watch threads 1..40, watch rate 1..150, chain gap 5..1440 min,
  retention 1..365 days, scope-event retention 1..3650 days, notification cap 1..100,
  global scans 1..NumCPU, fail limit 1..10, source timeout 1..30 min.
  - `WatchEnumerationSources` is validated against the known source ids
    (`crtsh,certspotter,hackertarget,rapiddns,otx,anubis,urlscan,subfinder,assetfinder,chaos,findomain`).
    Unknown ids are dropped with one log line, and an empty list is rejected (an empty list would
    disable discovery completely).
  - The source timeout has a floor of 1 minute, so a 0 can never break discovery instantly.
- `GET /tasks?coverage=deep|breadth|all`: filter by the TASK type, not by the project's current
  coverage. `breadth` = `tasks.type = 'watch_scan'`, `deep` = every other task type.
  - Filtering on `targets.watch_only` would REWRITE HISTORY: a project that was deep last week
    and is breadth today would move its old deep scans into the Breadth tab. The filter uses the
    task type, which is a fact about the task, not about the project today.
  - The task row still carries no tier, so the response gains a `coverage` field. It is computed
    from the task type ("breadth" for `watch_scan`, "deep" otherwise) and a separate
    `project_breadth` boolean from `tgt.watch_only`. The "manual" badge means: the task is a deep
    task that runs on a project that is currently a breadth project. The handler already joins
    `tasks t JOIN targets tgt`, so the filter and the fields cost nothing extra.
- Every new endpoint keeps the per-user isolation that the existing target endpoints have
  (`owner_id`). `POST /targets/bulk/coverage`, `GET /targets/{id}/watch-scope-events`,
  `GET /tasks?coverage=` and `GET /notifications?type=` all filter by the owner's targets.
- `GET /tasks` gains a real `limit` (1..200, default 50) and keeps `page`/`offset`. Today the
  handler hardcodes `LIMIT 50` and ignores the `limit` the frontend sends
  (`internal/api/system_handlers.go:432-505`), so the list silently truncates. Watch rounds make
  this visible: 100 projects × one round every 30 min means thousands of task rows, and without
  pagination the Scan activity page shows only the newest 50.
- `GET /notifications?type=`: filter the bell by kind. The frontend `notifications.list()` takes
  no parameters today (`frontend/src/lib/api.ts:470-473`), so the client call changes too.
  The `type` parameter takes a BUCKET, not one raw type, because `notifications.type` is
  granular and a `WHERE type = ?` filter would return almost nothing:
  - `watch` → `type IN ('scan_watch','scope_landed')`
  - `deep` → `type IN ('scan_deep')` plus the deep-scan notification types
  - `findings` → the finding types (`vuln_findings` and friends as the scanner writes them)
  - `all` → no filter
  The mapping lives in one place in the API, so the UI buckets and the stored types cannot
  drift apart.

### 8.2 UI

- **Projects page** (`/targets`, the sidebar label is already "Projects"): coverage filter chips
  (All / Deep scans / Breadth watches), a coverage badge per card, and a bulk action
  "Set coverage" next to the existing bulk delete.
  - The page already has a kind filter (Web / Network / both) and a dynamic heading
    ("Projects" / "Web Projects" / "Network Projects"), and `mixed` projects count as both kinds
    (`frontend/src/pages/Targets.tsx:70-76,262-266`). The coverage chips are a SECOND axis. The
    count line under the heading states both axes in this exact format:
    "23 projects · 5 breadth · 12 web · 8 network". A mixed project appears in both the web and
    the network count, so the two counts can sum to more than the project count. The line says
    "counts overlap for mixed projects".
  - "Set coverage" applies to the rows selected in the CURRENT kind view only. The bulk action
    is SHOWN in the Web view, because every selected row there is eligible for breadth. It is
    HIDDEN in the Network view, because a network project is refused by the flip API. In the
    "All" view it is shown with a confirmation that lists the mixed and network projects that
    will be refused.
- **Project detail**: a coverage toggle next to the monitoring settings, with a confirmation
  dialog that states exactly what changes (passive discovery + HTTP probe only, network assets
  ignored, monitoring disabled, first watch round starts now / deep pipeline on the next scan,
  auto-landed hosts stay, monitoring stays off). It shows "Deep: <last deep scan> · Watch:
  <last watch round> · Next watch: <time>".
  - It also has a "Pause watching" switch for a breadth project. It sets `watch_paused=1`, which
    stops the chain. "Resume watching" clears it and sets `watch_next_run=CURRENT_TIMESTAMP`.
    A chain that stopped because of the failure limit or a cancel shows "watching stopped" with
    the reason, and the same resume button.
  - The monitoring card sits next to it (`frontend/src/pages/TargetDetail.tsx`, `saveMonitor`).
    When the project is breadth, the monitoring checkbox is disabled and shows "off — breadth
    projects run watch rounds instead", so the operator cannot switch monitoring back on by
    accident.
  - The `Modal` component already exists (`frontend/src/components/ui/index.tsx`), so the
    confirmation dialog is a new dialog, not a new component.
  - The flip dialog warns when the project has NO linked bounty program: a manual project has an
    empty eligible set, so a breadth round on it would discover hosts but never land any. The
    warning reads "this project has no bug bounty program, so discovered hosts are never added to
    scope". The operator can still flip it.
- **Scan activity** (`/tasks`): coverage chips, the task type on each card, and the watch rounds
  in their own group. The "manual" badge on a deep scan of a breadth project uses the new
  `coverage` field from the task response.
  - The list needs paging. The API hardcodes `LIMIT 50` and ignores the `limit` the frontend
    sends, and watch rounds add thousands of rows. The page gets "Older / Newer" buttons and a
    row count.
- **Dashboard**: the counters that the watch tier can actually move are split by coverage.
  - Split: Projects, Running tasks, Failed tasks, Alive hosts (Live services), Subdomains, HTTP
    services. These are the only counters the watch tier produces, because the watch tier runs
    only `subdomain_enum` + `http_probe`.
  - Not split: JS files, Parameters, Reflected params, Nuclei, Backup files, Open redirects,
    Verified findings, Urgent. The watch tier never runs those modules, so those counters are
    structurally 0 for a breadth project. Splitting them would double the query count
    (`handleDashboardStats` builds one aggregate query per counter) for a number that is always
    zero. They keep their single deep value.
- **Bell**: a type filter (All / Deep / Watch / Findings). The four buckets map to type LISTS on
  the server (`watch` → `scan_watch` + `scope_landed`, `deep` → `scan_deep` + the deep-scan
  types, `findings` → the finding types), so a bucket never shows an empty list because the
  stored type is more granular than the bucket.
  - The bell polls `notifApi.list()` every 60 s and renders one flat list
    (`frontend/src/components/layout/TopBar.tsx`). The filter is a `<select>` inside the bell
    panel, next to the "mark all read" action, and the client call passes the type.
  - The bell also listens for the new `scope_landed` event, so a new landing appears without
    waiting for the next poll.
- **System → Scanning**: a new "Watch scanning" subsection with the watch knobs and the source
  toggles (§3.2). The existing "monitor modules" list stays separate: the monitor tier and the
  watch tier are different module sets.
  - The watch MODULE set is shown as a READ-ONLY badge list ("subdomain_enum", "http_probe"), not
    as checkboxes. The set is fixed by D1 and by §5.3. Editable checkboxes would promise a
    choice that the scheduler does not honour, and a future agent would wire them up wrongly.
  - The Scanning card sits on the overview tab and is admin-gated (`isAdmin && scanDraft`), so
    the new subsection sits in the same card and inherits the gate. The chaos API key does NOT
    live here; it lives on the Integrations tab with the other provider keys.
- **Bounty programs**: the button reads "Create project", and the modal gains a coverage
  selector (Deep / Breadth). Breadth mode hides the monitoring checkbox and shows
  "passive discovery + HTTP probe, no brute force". A program whose selected assets contain no
  web asset is skipped with the reason "no web assets"; a single import of such a program
  returns 400. The bulk import reports per-program results and never aborts the batch.
  The project carries a coverage badge.
  - The create request grows a `watch_only` field, so the button label, the selector and the
    request body change together. The bulk import needs a result list surface (a modal listing
    each program with imported / skipped + reason), because a silent skip is not acceptable.
  - `CreateProject` (`internal/bounty/catalog.go:231-328`) has no `watch_only` field today. When
    it gains one it must also set the whole watch state on the new target: `watch_only=1`,
    `watch_next_run=CURRENT_TIMESTAMP` (the first round starts now), `watch_paused=0`,
    `monitor_enabled=0` on the target, and `monitor_enabled=0` on every asset row it inserts
    (it inserts them with `monitor_enabled=1` today).

## 9. Measurement (free, already recorded)

```sql
SELECT module, COUNT(*) AS runs, SUM(duration_ms) AS total_ms
FROM task_phases
WHERE task_id IN (SELECT id FROM tasks WHERE target_id = ?)
GROUP BY module
ORDER BY total_ms DESC;
```

Run it for the deep projects first. If one module dominates, it gets its own fix.

## 10. Task list

Progress is tracked with the checkboxes below. `[x]` means done, `[ ]` means open.

- [x] **T1** — DB: `targets.watch_only`, `watch_last_run` (DATETIME), `watch_next_run` (DATETIME), `watch_fail_count`, `watch_root_index`, `watch_paused`; new `watch_scope_events` table (`announced` column) + index.
- [x] **T2** — Config: every knob in §1 with a doc comment, plus `WatchEnumerationSources` and `ChaosAPIKey`; defaults in `defaultConfig` only. The watch knobs are NOT part of `autoTunedLimits` (`internal/config/config.go`): they are fixed operator knobs, not machine-tuned ones. `Load()` unmarshals the saved config over the defaults, so a saved value wins, but the loader must tell a NIL slice from an EMPTY one: a missing `watch_enumeration_sources` keeps the default list, an explicitly empty list stays empty (the operator turned every source off on purpose) and the scan then finds nothing. `RECON_NO_AUTOTUNE=1` keeps working because the watch knobs never came from the auto-tuner.
- [x] **T3** — Scanner: watch context flag; `WithWatchSources`; force `subBrute=false`, `subRecursion=false`, `asnDiscovery=false`; skip `vhostScan` in watch mode; suppress the `new_subdomain` notification; per-source enable/disable; concurrent CLI sources, EACH on its own timeout (`WatchSourceTimeoutMinutes`, child context per source, partial results kept, NO shared round budget — DNS admission and httpx run on the parent context and always finish); httpx-only HTTP phase (no `fingerprintHosts`, no `PreflightSessions`, no catch-all pass, no redirect following, no `basicHTTPProbe` fallback — log and skip when httpx is missing, and the round then lands NOTHING, so an unverified DNS record is never approved as scope). Dropping redirect following does not change any alive counter: `updateSubdomainAlive` sets `is_alive = 1` for ANY host with a probe result (`internal/scanner/http.go:308-349`) and every alive counter counts `is_alive = 1` without a status condition. Only the recorded status code changes (301 instead of the final 200), and `http_services` still gets a row.
- [x] **T4** — Scheduler: global ceiling, deep lane cap, watch lane cap, watch drain, `runDueWatchRounds` (kind='web' guard, duplicate check, `watch_paused=0` and `watch_next_run IS NOT NULL` filter), watch tick loop, deep drain before watch drain, root narrowing to one root before `runSubdomainRootFanout`.
- [x] **T5** — Chained rounds: terminal rules, `watch_fail_count`, failure limit, no timeout, no host cap.
- [x] **T6** — `runDueMonitors` filter `watch_only=0`; `notifyBountyScopeEvent` excludes watch-only projects from `bounty_favorite_scan`; `ResumeTask` calls `CreateTaskTyped` with the original type and drops pseudo-modules from `remaining` (nothing left to resume → clear message); `refreshTargetScanStatus` passes `touchLastScan=false` for watch tasks; terminal rules write `watch_next_run` with SQLite `datetime('now', '+<gap> minutes')` and set `watch_paused=1` when the chain stops.
- [x] **T7** — Scope: eligible-set loader (`internal/scanner/watch_scope.go`, empty set + log line "no bounty program linked: scope landing disabled for this project" when a project has no `project_programs` row), matcher with edge cases (path-scoped identifiers excluded), auto-land insert (a round with no HTTP result lands nothing), landing stage AFTER the HTTP phase, re-eligibility UPDATE of the existing `watch:scope` asset row (clear `metadata.out_of_scope`, new event row), the out-of-scope sweep in the program reconciliation tick (not inside a watch round), `watch_scope_events` with the 3-state `announced` flag (0 unannounced / 2 claimed / 1 sent).
- [x] **T27** — `CreateProject` gains `watch_only` and sets the whole watch state on the new target (`watch_next_run=CURRENT_TIMESTAMP`, `watch_paused=0`, `monitor_enabled=0` on the target and on every asset row it inserts).
- [x] **T8** — Notifications: the scheduler inserts the `scan_deep` and `scan_watch` in-app rows (today it writes none), `scope_landed` title, grouped per-tick message, `announced` flag, per-round bell row, `new_subdomain` suppression, new `scope_landed` hub event sent through `s.hub.Broadcast` (never through `broadcastAndScore`).
- [x] **T9** — Reporting: grouped skipped-module summary in the task log and the watch message.
- [x] **T10** — API: `watch_only` read/update, bulk coverage (per-project results), watch-scope-events, scan-config knobs, tasks coverage filter plus a `coverage` field on every task row, notifications type filter (type → tier mapping), mixed/network flip refusal, asset `monitor_enabled=0` on flip and on import, per-user (`owner_id`) scoping on every new endpoint.
- [x] **T11** — UI: Projects filter chips, coverage badge, bulk set-coverage.
- [x] **T12** — UI: Project detail coverage toggle + confirmation dialog + deep/watch timestamps.
- [x] **T13** — UI: Scan activity split, task type badge, coverage filter, paging (the API hardcodes LIMIT 50 and ignores the frontend `limit`).
- [x] **T14** — UI: Dashboard split counters — only the counters the watch tier can move (Projects, Running, Failed, Alive hosts, Subdomains, HTTP services), one tile per counter with two lines (Deep / Breadth). The JS/parameters/findings tiles stay single-valued.
- [x] **T15** — UI: System → Scanning "Watch scanning" subsection, source toggles, and the watch module set as a READ-ONLY badge list (the set is fixed: `subdomain_enum` + `http_probe`, not editable).
- [x] **T16** — UI: bell type filter — a `<select>` inside the bell panel next to "mark all read", the client call passes the type, and the bell listens for the `scope_landed` event.
- [x] **T17** — UI: Bounty programs coverage selector, web-only assets, per-program bulk results. The BACKEND import filters network/IP assets whenever `watch_only == true` (`internal/bounty/catalog.go:231-328`), so an import can never create a broken mixed project. The backend is the enforcement point; the UI selector only says what the operator wants.
- [x] **T18** — Telegram: three new `Notifier` methods, three new `telegram_chats` preference columns, chat editor checkboxes, distinct templates.
- [x] **T19** — Retention prune job with the per-table age columns, hourly cadence, single transaction, dependency order, retry on `SQLITE_BUSY`, keep the last 100 watch tasks' logs. The prune is TIER-scoped: the finding tables are never pruned, `subdomains`/`http_services` are pruned only for projects whose task history is all watch tasks, and `watch_scope_events` is pruned after `WatchScopeEventsRetentionDays`.
- [x] **T20** — Dockerfile: add `chaos` (`github.com/projectdiscovery/chaos-client/cmd/chaos@v0.5.2`); update the tool-list assertions. Also add `chaos` to the in-app tool install catalog (`internal/api/tool_install.go`), and add per-tool env injection to the executor so the chaos run gets `PDCP_API_KEY`.
- [x] **T21** — Docs: `docs/SCANNING_GUIDE.md` (numbers table + watch tier guide + operator FAQ) and release notes.
- [x] **T22** — Tests: watch drain ordering; the three terminal-status rules; the matcher edge cases; the retention age columns; deep-never-waits-for-watch; a watch task never runs brute, recursion, ASN or vhost; per-source toggles; bulk coverage rules; `ResumeTask` keeps the type; a stopped chain stays stopped (a NULL `watch_next_run` never makes a project due); `watch_next_run` written and compared in the SQLite datetime format; a resume with nothing left reports instead of failing; `scan_deep`/`scan_watch` rows land in the bell; the bell type filter maps types to tiers.
- [x] **T23** — Chaos key: `ChaosAPIKey` config + `RECON_CHAOS_API_KEY` env fallback; one line in `apiKeyFields()`; executor per-tool env injection (`PDCP_API_KEY`); in-app tool catalog entry; chaos skipped with a log line when no key is set. The executor reads `e.cfg.ChaosAPIKey` at RUN time when it builds `cmd.Env` (`internal/tools/executor.go:49-50,125,249,362,428`), so a key saved in the UI works without a restart. The same key is passed to subfinder as `PDCP_API_KEY` (same projectdiscovery account).
- [x] **T24** — Task list paging: the API honours `limit` (1..200, default 50) and keeps `page`/`offset`; the frontend sends both and shows "Older / Newer" plus a row count.
- [x] **T25** — Flip rules: refuse `mixed`/`network` projects (400 with the reason and the network asset list), set asset `monitor_enabled=0` on flip and on import, bulk per-project results, `watch_paused=0` and `watch_next_run=CURRENT_TIMESTAMP` on every flip to watch.
- [x] **T26** — Skipped-module log line: one line per module group, written when the WORKER STARTS the watch task (not at task creation), so a task that was created but never picked up leaves no orphaned report.
- [x] **T28** — UI: "Pause watching" / "Resume watching" switch on the project detail page, backed by `watch_paused`; a stopped chain shows "watching stopped" with the reason.
- [x] **T29** — SQLite: add `_txlock=immediate` to the DSN next to `_busy_timeout` (`internal/database/database.go:18`), so write transactions take the write lock up front. Two lanes plus the hourly prune would otherwise hit DEFERRED-transaction upgrade deadlocks (`SQLITE_BUSY` that `busy_timeout` cannot clear).
- [x] **T30** — Watch queue depth: `runDueWatchRounds` processes due projects in due order and creates at most `MaxConcurrentWatchScans` tasks per tick; `tryStartTask` re-checks `watch_only=1 AND kind='web'` and drops a queued watch task whose project was flipped back to Deep; a watch project that turns `mixed` raises one notification (not one per tick).
- [x] **T31** — Startup recovery: `recoverPendingTasks()` (`internal/scheduler/scheduler.go:464-492`) cancels zombie `running`/`paused` tasks with raw SQL and never reaches the watch terminal handler. It must apply the watch terminal rule to the `watch_scan` tasks it cancels: `watch_next_run = now + gap`, `watch_fail_count += 1`. Without it, a crash leaves the project due in the past and the round restarts instantly.
- [x] **T32** — Coverage filter by TASK type: `GET /tasks?coverage=` filters on `tasks.type` (`watch_scan` vs everything else), never on `targets.watch_only`, so flipping a project does not rewrite the history of its task list. The response gains `coverage` (from the task type) and `project_breadth` (from `tgt.watch_only`) for the "manual" badge.
- [x] **T33** — Grouped scope-landed message: DB claim instead of a time key. `announced` becomes 0 = unannounced, 2 = claimed in flight, 1 = sent. The flush claims the rows in one UPDATE, sends, then marks them sent; on a send failure the claim goes back to 0 so the next window retries. The minute-based dedupe key is dropped.

## 11. Open questions

None. The three decisions below are locked (operator: "do all your recommendations"):

- D25 — grouped scope-landed message: ONE message per watch tick window across all projects,
  with per-program counts and up to `WatchNotifyHostCap` names. Not one message per project.
- D26 — the per-source toggles apply to the WATCH tier only. Deep scans keep every source.
- D27 — `chaos` without an API key is skipped with one log line. The source stays visible in the
  UI.
- D29 — the `chaos` API key is edited in System → Integrations → "Passive intelligence
  providers", with the other provider keys. There is no separate "API Keys" page.
- D30 — split counters stay one tile each (two lines inside), so the dashboard grid does not
  double in size.
- D31 — the Scan activity list gets paging, because watch rounds make the task list grow without
  bound.

## 12. Risks

- A watch round is not free: it is passive discovery plus one HTTP request per host per scheme.
  The lane cap of 1 and the per-round rate of 25 rps keep it bounded.
- The probe cost grows with the project's host count, because the HTTP phase covers every known
  host. A project that accumulates 500 hosts spends about 40 minutes per round at 25 rps. The
  rate cap and the rotation keep it bounded, but the round gets slower as the project grows.
- The global ceiling of 2 is the sum of one deep scan and one watch round. Two cores, so the
  watch round's discovery phase and the deep scan compete for CPU. The deep lane reserves its
  slot first and the deep drain runs first every tick, so a deep scan never waits for a watch
  round. The watch lane takes only the slots the deep lane did not reserve, so queued deep
  scans cannot starve the watch tier either.
- The memory guard covers one heavy scan, so the global ceiling adds one slot for the light
  watch tier (`effectiveMaxConcurrent()+1`). On a box where the guard says 1, one deep scan and
  one watch round can run together. If that is too much, lower `MaxConcurrentScans` to 1.
- Auto-landing removes a human gate. The eligibility rule, the matcher, the audit table and the
  grouped notification are the controls. A wrong program scope lands wrong hosts, so the scope
  of a program is worth one look before the first sweep.
- The chained round never ends. The gap, the lane cap, the failure limit and the per-project
  pause switch are the escape hatches.
- Retention deletes raw rows. It is scoped by tier, so it never touches a deep scan's findings.
  It only prunes host rows of projects whose task history is all watch tasks, plus watch task
  logs and old scope events. Landed scope, notifications and task history survive.
- SQLite locking: two lanes plus the hourly prune can collide on the database. The DSN gets
  `_txlock=immediate` so a write transaction takes the write lock up front. Without it a DEFERRED
  transaction that upgrades to a write lock can hit a `SQLITE_BUSY` that `busy_timeout` cannot
  clear.
- The watch queue can grow: many projects become due at the same time. The tick creates only
  `MaxConcurrentWatchScans * 2` tasks per round and processes them in due order, so the backlog
  drains in order instead of all at once. The same cap covers the bulk flip, where 50 projects
  become due in the same second.
- Two lanes on one project at the same time would race on the asset and subdomain tables. The
  scheduler refuses to start a task for a project that already has a running task, so a manual
  deep scan always wins over a queued watch round.
- The `tasks` table grows by roughly 144,000 rows a month at 100 watch projects. Old finished
  watch task rows are pruned after 90 days and the migration adds the indexes the new list and
  counter queries need, so the dashboard stays fast.

## 13. Decision log (D1-D77)

The decisions behind this plan, so a future agent does not have to re-derive them.

| # | Decision |
|---|---|
| D1 | Breadth round = `subdomain_enum` (passive only) + `http_probe`. |
| D2 | Eligible new hosts land automatically as approved scope. No manual review step. |
| D3 | Only bounty-eligible scope counts: `in_scope=1 AND eligible_submission=1`. |
| D4 | Notifications are grouped, never one per host. |
| D5 | One source of truth for eligible scope: the live program assets. |
| D6 | Chained rounds re-queued after a minimum gap, not a fixed hourly schedule. |
| D7 | Watch lane is small (1). It takes the slots the deep lane does not reserve, so a deep scan never waits for a watch round and a watch round never starves behind queued deep scans. |
| D8 | Separate surfaces: task type `watch_scan`, split Scan activity, split counters, separate Telegram templates. |
| D9 | Every watch round reports the modules it skipped. |
| D10 | The deep tier is unchanged: every module, full coverage, all sources. |
| D11 | Bulk onboarding from bounty programs, one action, no hand-picking. |
| D12 | The Projects list filters deep vs breadth and shows a coverage badge. |
| D13 | The chain gap is configurable in the UI. Default 30 min. |
| D14 | Watch probes hit the root path only. |
| D15 | Auto-landed hosts do not become deep-tier assets and do not become enumeration roots. |
| D16 | Retention prunes raw watch rows older than 30 days. The numbers are documented and configurable. |
| D17 | A watch-only project is `kind=web` only when it has no network assets. Mixed projects keep their kind and the UI warns. |
| D18 | Watch-only projects have monitoring off, enforced by the API. |
| D19 | Auto-land writes a `watch_scope_events` row as the audit trail. |
| D20 | The global scan ceiling respects the memory and CPU pressure guard. |
| D21 | Deep scans never wait for a watch round. |
| D22 | A resumed task keeps its original type. |
| D23 | The Telegram preference columns live on `telegram_chats`. |
| D24 | The plan is one document with one numbers table. |
| D25 | One grouped scope-landed message per watch tick window, across all projects. |
| D26 | The per-source toggles apply to the watch tier only. |
| D27 | `chaos` without an API key is skipped with one log line. |
| D28 | The watch tier ships four sources: `subfinder`, `assetfinder`, `chaos`, `findomain`. The 7 HTTP sources, `gau`, `waybackurls` and `scilla` are off by default but stay in the UI. |
| D29 | The `chaos` API key is edited in System → Integrations → "Passive intelligence providers". There is no separate "API Keys" page. |
| D30 | A split counter stays one tile with two lines (Deep / Breadth), so the dashboard grid does not double in size. |
| D31 | The Scan activity list gets paging, because watch rounds make the task list grow without bound. |
| D32 | `watch_scope_events.announced` is required. Without it the same hosts are re-announced every tick. |
| D33 | Root rotation uses a `watch_root_index` column. The scheduler picks one root per round. |
| D34 | A `mixed` or `network` project cannot run a watch round. The flip API refuses it. |
| D35 | The bell needs a `scope_landed` broadcast event. A notification written without a broadcast never appears. |
| D36 | The per-tick window is fixed at 60 seconds. The grouped message claims its rows in the database (`announced` 2 = in flight) instead of using a time key. |
| D37 | Each discovery source has its own timeout (`WatchSourceTimeoutMinutes`). There is NO shared round budget: DNS admission and the HTTP probe always run to the end. |
| D38 | The dashboard splits only the counters the watch tier can move (projects, running, failed, alive hosts, subdomains, HTTP services). The finding counters stay single-valued. |
| D39 | The eligible-set loader lives in `internal/scanner/watch_scope.go`. A project with no program returns an empty set and one log line. |
| D40 | `watch_paused` is the one stop switch for a project. A NULL `watch_next_run` means "not scheduled" and never makes a project due. |
| D41 | `watch_last_run` and `watch_next_run` are DATETIME written with SQLite `datetime(...)`, so the string comparison against `datetime('now')` works. |
| D42 | Root rotation narrows the root list before the fan-out. The root is a function argument, not a context value. |
| D43 | The scheduler inserts the `scan_deep` and `scan_watch` in-app notification rows. The bell filters types through a type → tier mapping; no new column is added to `notifications`. |
| D44 | The HTTP phase of a watch round covers every known host of the project. Root rotation limits the enumeration, not the probe. |
| D45 | A resume drops pseudo-modules from the remaining module list, and reports "nothing left to resume" instead of creating a task with no executable module. |
| D46 | Every new endpoint keeps the per-user `owner_id` scoping. |
| D47 | No shared round budget. Each discovery source runs on its own timeout; DNS admission and httpx run on the parent context and always finish. |
| D48 | Retention is tier-scoped. The finding tables are never pruned, because a watch round never writes them. |
| D49 | A program asset with a path (`https://example.com/api/v1/`) is not a bare host and is never landable. |
| D50 | `watch_next_run` is updated on every terminal status, even when the watch lane is saturated. The lane only gates the worker slot. |
| D51 | The watch tick creates at most `MaxConcurrentWatchScans` tasks and processes due projects in due order. `tryStartTask` re-checks the coverage and drops stale queued watch tasks. |
| D52 | The SQLite DSN gets `_txlock=immediate` next to `_busy_timeout`, so write transactions take the write lock up front. |
| D53 | A round lands nothing when the HTTP phase is skipped or produced nothing, and a project with no linked program logs "no bounty program linked: scope landing disabled for this project". |
| D54 | A successful round resets `watch_fail_count` to 0, so the failure limit counts CONSECUTIVE failures. |
| D55 | A host that becomes eligible again is UPDATEd in place (the `assets` row exists, so `ON CONFLICT DO NOTHING` changes nothing): the `metadata.out_of_scope` flag is cleared and a new `watch_scope_events` row is written. |
| D56 | The out-of-scope sweep is its own pass over all `source='watch:scope'` assets of a project, compared with the FULL program eligible set. It runs in the program scope reconciliation tick, not in the watch round. A watch round only adds hosts. |
| D57 | Landing happens AFTER the HTTP phase. A host with no HTTP result is never landed. |
| D58 | The global scan ceiling is `min(MaxConcurrentScans, NumCPU, effectiveMaxConcurrent()+1)`. The deep lane keeps `min(MaxConcurrentDeepScans, effectiveMaxConcurrent())` slots and the watch lane gets the rest. The watch lane does NOT close because a deep task is pending, so the watch tier cannot starve. |
| D59 | Startup recovery applies the watch terminal rule to the `watch_scan` tasks it cancels, so a crash cannot leave a project permanently due. |
| D60 | The grouped scope-landed message claims its rows in the database (`announced` 0 = unannounced, 2 = in flight, 1 = sent). There is no minute-based dedupe key, and a send failure releases the claim for a retry. |
| D61 | The Scan activity coverage filter uses `tasks.type`, not `targets.watch_only`, so flipping a project never rewrites the history of its task list. `targets.watch_only` only feeds the "manual" badge. |
| D62 | The watch module set is fixed (`subdomain_enum` + `http_probe`) and is shown as a read-only badge list, not as checkboxes. |
| D63 | The backend bounty import filters network and IP assets whenever `watch_only` is true, so an import can never create a broken mixed project. |
| D64 | The executor reads `cfg.ChaosAPIKey` at run time, so a key saved in the UI works without a restart. |
| D65 | The root index advances only when a round FINISHED. A failed round keeps the same root, so one network blip does not skip a root for a full rotation. After 2 consecutive failures on the SAME root the index advances anyway, so one broken root cannot stop the chain. |
| D66 | A round where EVERY enabled discovery source failed is a FAILED round, not a finished one. "0 subdomains found cleanly" stays finished. |
| D67 | The per-source timeout uses the streaming executor path so partial results arrive as they are printed, and a timed-out source is stopped with SIGTERM, a 2-second grace, then SIGKILL. |
| D68 | The eligible set is the UNION over every program linked to the project, because `project_programs` is a join table and one project can link several programs. |
| D69 | The matcher normalizes punycode with `idna.Lookup.ToASCII`, strips ports for matching but keeps a non-standard port in the stored value, and only understands the wildcard form `*.<domain>`. |
| D70 | Landed asset values are stored lowercased, and a unique index on `(target_id, LOWER(value))` backs it, so `Example.com` and `example.com` cannot become two rows. |
| D71 | A landed host can be promoted to a deep seed from the Watch Scope panel or the Breadth → Deep dialog. The program scope upsert never rewrites a `watch:scope` row. |
| D72 | The watch tick creates at most `MaxConcurrentWatchScans * 2` tasks per tick, in due order, so a bulk flip cannot flood the queue. |
| D73 | The scheduler refuses to start a task for a project that already has a running task, so the deep and watch lanes never work on the same project at the same time. |
| D74 | The watch knobs are NOT part of the auto-tuner. A missing source list keeps the default, an explicitly empty list stays empty, and a saved config value always wins over the auto-tuned one. |
| D75 | Finished watch task rows older than 90 days are pruned, and the migration adds `tasks(type, status, created_at DESC)`, `tasks(target_id, created_at DESC)` and `targets(id, watch_only)`. |
| D76 | The bell filter takes a BUCKET that maps to a list of stored types, never one raw type, so a bucket is never empty because the stored type is more granular. |
| D77 | The plan file is reviewed against the codebase in rounds; every round ends with the plan file updated and the round's decisions appended to this log. |
