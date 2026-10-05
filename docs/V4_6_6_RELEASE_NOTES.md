# Reconner v4.6.6 — stop capping coverage by default, fix a real nuclei OOM kill

A live multi-asset scan (3 large `.ir` domains run together) surfaced two
real problems in the same run: content-discovery silently dropped most of
the admitted hosts behind a hardcoded `150`, and nuclei's vulnerability-scan
phase lost part of its coverage to an actual OS/cgroup OOM kill — with
nothing but a warning log line to show either one happened.

## The caps: raised to effectively "no limit" by default

Several hardcoded ceilings existed purely as defensive guesses, not real
resource limits, and silently dropped real coverage the moment a scan grew
past them:

- `dir_discovery_max_hosts` (content-discovery/backup-discovery host cap):
  **150 → 300000**. The pasted scan log showed this biting at "scanning 150
  of 14390 alive hosts" — 14240 hosts' backup/content discovery silently
  skipped.
- `nuclei_max_surfaces` / `nuclei_max_per_host` (nuclei's post-dedup surface
  ceiling and per-host fairness cap): **8000/2000 → 300000/300000**. The same
  log showed "Surface capped at 8000 (NucleiMaxSurfaces)".
- vhost Host-header discovery: the candidate-hostname cap (800 → 4000), the
  distinct-known-IP cap (40 → 100), and the wildcard-branch word cap
  (650 → 1500) were all raised too — the same log showed "vhost candidate
  cap hit: 40212 candidates ... first 800".

The philosophy change, not just the numbers: these all now follow the
already-documented "0 ⇒ built-in default" contract honestly — the built-in
default is simply wide enough that it never binds in practice, so the
operator decides whether a scan this wide is worth the time, not a silent
built-in ceiling. Set an explicit smaller value in `config.json` for any of
these if you want a real cap back.

**Existing installs:** `nuclei_max_surfaces`/`nuclei_max_per_host` were
previously baked into `config.json` as literal `8000`/`2000` on first run
(not `0`), so upgrading the binary alone won't raise them for a server
that's already been configured once — see "Upgrade" below for the one-time
`config.json` edit. `dir_discovery_max_hosts` does not need this: it was
always `0` unless you changed it yourself, so the new 300000 default applies
automatically.

## The real "signal: killed": raising caps safely required fixing this first

Raising `nuclei_max_surfaces` without addressing the actual memory cost
would have made things worse, not better: the same log showed two of four
parallel nuclei processes dying with `nuclei process error: signal: killed`
— confirmed NOT a context timeout (`ctx.Err()` was `nil` when the error
surfaced), so this was the OS/cgroup OOM killer. Each parallel nuclei
process independently loads and compiles the **full** template corpus
(10k+ templates once the official set, fuzzing-templates, and extra
community repos are synced) — running several at once, not the target
count, is nuclei's real memory cost, and a freshly-synced template store
made it worse on exactly the run that hit it.

Nuclei's parallel-process count is now clamped to what current cgroup
memory headroom can actually afford (~1.5 GB of budget per extra process),
logging a warning when it reduces the auto-computed default. An operator's
explicit `nuclei_parallel_processes` is never touched — only the
auto-computed default backs off under real memory pressure.

## Fixed the actual bottleneck behind "this stage takes a long time"

Raising host caps without fixing how those hosts get processed would have
just made scans run far longer without finishing. Content-discovery
(the built-in prober, the dirsearch/feroxbuster augmentation passes, and
backup/sensitive-file discovery) processed hosts in a single **sequential**
loop: each host's soft-404 baseline (up to two blocking HTTP requests) had
to finish before the *next* host's baseline even started — a serial
per-host startup cost that, at scale, dwarfed the actual bounded per-request
concurrency those stages already had. All three now process hosts
concurrently (bounded by the existing `directory_discovery` worker budget),
and backup discovery's own per-request throttle now scales with the
configured HTTP rate budget instead of a flat historical `40`.

## Upgrade

Rebuild/redeploy as usual. If your `config.json` already has explicit
`nuclei_max_surfaces`/`nuclei_max_per_host` values from a previous install
(check with `grep -E 'nuclei_max_surfaces|nuclei_max_per_host' ~/.recon-platform/config.json`),
raise them (or set them to `0` to take the new 300000 built-in default)
to actually get the wider coverage — a binary upgrade alone won't change a
value `config.json` already pins:

```json
{
  "nuclei_max_surfaces": 0,
  "nuclei_max_per_host": 0,
  "dir_discovery_max_hosts": 0
}
```

Merge those three keys into your existing `config.json` (keep everything
else as-is) and restart. `0` means "use the new built-in default"; set a
real number instead if you want an explicit ceiling.
