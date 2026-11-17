# Reconner v5.1.0 — two-tier scanning: deep scans + breadth watches

This release adds a second, cheap scanning tier. You can now watch many bounty
programs automatically without reviewing each one by hand, while your deep
targets keep the full pipeline. The two tiers run in separate lanes, have
separate dashboards and Telegram messages, and never block each other.


## Inherited from upstream v5.0.0

This release also merges upstream v5.0.0. Deep scans get those changes; watch
rounds stay cheap and do not inherit the browser-heavy ones.

- One slow phase no longer aborts the whole scan. The watchdog floor is now
  30 days, the ceiling 90 days, and backstop is 10 phase timeouts.
- Nuclei `-dast` parameter fuzzing is on for normal and slow deep scans.
- A deep scan auto-pauses when every known HTTP host is unreachable. Watch
  rounds keep their own fail limit and are excluded from auto-pause.
- CDN/bot-challenge pages get a headless-browser rescue pass in deep scans.
  Watch rounds never start Chromium.
- New ASN/CIDR CDN filtering, OTX origin-IP fallback, MongoDB `$where` NoSQLi
  detection, XSS false-positive fixes, and a 60-entry backup wordlist.
- HTTP Basic Auth brute force now needs network credential authorization and
  has attempt caps. Enable `EnableNetworkCredentialAudit` or
  `net_cred_authorized` if you rely on those findings.
- Target tabs are grouped and the group formerly called "Assets" is now
  "Surface". Dashboard stat tiles have real icons. Decorative emoji were
  removed from product text and Telegram messages.
- Two new nuclei templates: Grafana path traversal and unauthenticated Jolokia.

### Existing installations: watchdog migration

Upstream no longer bakes `scan_watchdog_hours: 24` into fresh configs. If your
`config.json` already has `"scan_watchdog_hours": 24`, delete the key or set it
to `0`. Otherwise the old 24-hour watchdog stays active and the new 30-day
adaptive default does not apply.

## What is new

- **Per-project coverage mode.** Each project is either a **Deep scan** (the
  unchanged full pipeline) or a **Breadth watch** (passive discovery + one HTTP
  probe, in a chained loop). Set it on the Projects page, on the project detail
  page, or when importing a bounty program. Existing projects stay deep.
- **Breadth watch.** A watch round enumerates one eligible root per round and
  rotates through the project's domain assets, then resolves the names and probes
  every known host at the root path over http and https. Brute force,
  permutations, recursion, ASN sweeps, virtual-host probing, crawling, injection
  and all post-processing modules are skipped; the task log names every skipped
  module group. There is no round timeout and no host cap.
- **Automatic, eligible-only scope landing.** A discovered host that matches the
  bounty-eligible scope of a linked program is added as approved scope after the
  HTTP probe confirms it. Nothing is added for manual (non-bounty) projects, and
  nothing unverified is landed. Landed hosts are scope, not scan roots; a
  "Promote to Deep seed" action is available in the Watch Scope panel.
- **Chained rounds.** When a round finishes, the project is re-queued after the
  minimum gap. Consecutive failures pause the chain with one alert. A per-project
  "Pause watching" switch stops it without losing state. A mixed or network
  project is refused and raises one alert.
- **Separate surfaces.** Scan activity splits into Deep scans and Breadth
  watches by task type, so flipping a project never rewrites its history. The
  dashboard splits the counters that the watch tier can change. The notification
  bell has Deep / Watch / Findings buckets. Telegram gets three new templates:
  Watch start, Watch result, and New scope (start and result off by default,
  New scope on). Scope landings are grouped into one message per watch tick
  across all projects.
- **Bulk onboarding.** Import a bounty program directly as a breadth project;
  network/IP assets are dropped, and the result panel shows what was imported or
  skipped. The Projects page has coverage chips, a coverage badge per card, and
  a bulk "Set coverage" action.
- **App-store scope is excluded.** Bounty import now excludes app-store listings
  from breadth and deep projects. Google Play, Apple App Store, Microsoft Store,
  Huawei AppGallery, and Steam URLs no longer become subdomain-enumeration roots
  or HTTP probe targets. Bulk results report the skipped count as
  `skipped_app_store`. Existing store rows stay visible as references. A
  project with only store assets finishes a watch round with zero hosts.
- **chaos discovery source.** The watch tier ships `subfinder`, `assetfinder`,
  `chaos`, and `findomain`. Set the projectdiscovery API key under System →
  Integrations → Passive intelligence providers. Per-source toggles and all watch
  timing knobs are under System → Scanning → Watch scanning.

## Watch tuning numbers

| Setting | Default |
|---|---|
| Global scan ceiling (`Limits.MaxConcurrentScans`) | 2 |
| Deep lane cap (`Limits.MaxConcurrentDeepScans`) | 1 |
| Watch lane cap (`Limits.MaxConcurrentWatchScans`) | 1 |
| Watch round interval (`WatchRoundIntervalHours`) | 12 h |
| Watch retry gap (`WatchRoundsMinGap`) | 30 min |
| Watch source timeout (`WatchSourceTimeoutMinutes`) | 5 min (per source; no shared budget) |
| Watch sources (`WatchEnumerationSources`) | `subfinder,assetfinder,chaos,findomain` |
| Watch HTTP threads (`Limits.WatchHTTPThreads`) | 10 |
| Watch HTTP rate (`Limits.WatchHTTPRateLimit`) | 25 rps per round |
| Watch row retention (`WatchRowsRetentionDays`) | 30 days |
| Watch scope event retention (`WatchScopeEventsRetentionDays`) | 180 days |
| Watch notify host cap (`WatchNotifyHostCap`) | 20 |
| Watch failure limit (`WatchFailLimit`) | 3 |

Existing installs keep their current next-round time. After the next finished
round, the new 12-hour interval applies. To get 24-hour rounds, set
`watch_round_interval_hours` to `24` in System → Scanning.

A normal watch round no longer writes a bell row. The bell shows only specific
breadth changes: new eligible scope and a stopped watch chain. Telegram still
sends the grouped round result when that chat option is on.

The global ceiling is `min(MaxConcurrentScans, NumCPU, effectiveMaxConcurrent+1)`.
The deep lane is capped by the memory guard; the watch lane takes only the slots
the deep lane did not reserve, so a deep scan never waits for a watch round.

## Data and retention

Watch data is pruned tier-by-tier: raw subdomains and HTTP services by
`last_seen`, watch task logs and phases (keeping the newest 100 tasks), scope
events older than 180 days, and finished watch task rows older than 90 days.
Landed scope, notifications, and all deep-tier data survive. Finding tables are
never pruned. The SQLite DSN now uses `_txlock=immediate` to avoid write-lock
upgrade deadlocks between the two lanes and the hourly prune.

See [the scanning guide](SCANNING_GUIDE.md#two-tier-scanning-deep-scans-and-breadth-watches)
for the full operator guide and FAQ.
