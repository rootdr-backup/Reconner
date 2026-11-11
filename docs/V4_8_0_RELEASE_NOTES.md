# Reconner v4.8.0 — restore findings (the v4.7.0 DNS regression), stop re-probe-after-cancel, UI fixes

v4.7.0 made subdomain *discovery* richer but quietly **starved the vulnerability
pipeline**: operators saw plenty of subdomains yet almost no findings, and nuclei
appeared to find nothing. This release fixes that regression at the root, makes the
recursive enumeration opt-in, and clears a batch of the UI papercuts reported
alongside it.

## The regression: empty findings / "nuclei finds nothing"

**Root cause.** v4.7.0 moved subdomain resolution onto fast public resolvers
(1.1.1.1 / 8.8.8.8 / Quad9 / OpenDNS) and turned recursion on by default. The
admission gate, however, treated *any* empty DNS answer as "does not resolve →
reject → prune". Public resolvers **rate-limit bulk enumeration**, and recursion
multiplied the query volume — so real, resolvable hosts intermittently returned
nothing, were deleted from the asset set, and never reached httpx. nuclei, XSS,
SQLi, LFI and every other detector then ran against an empty or tiny target list.
That is why subdomain *names* looked fine while findings cratered.

**Fixes:**

- **Authoritative vs. transient DNS.** Resolution now distinguishes a real
  `NXDOMAIN` (the host genuinely has no record) from a transient miss (timeout,
  SERVFAIL, or a throttled public resolver). **Only an authoritative negative can
  ever reject or prune a host.** A transient miss leaves the name — and any
  existing row — untouched, so a rate-limited lookup can no longer silently delete
  a live asset.
- **System-resolver fallback.** When a public resolver fails transiently, the
  lookup retries once through the system resolver (slower, but not rate-limited),
  recovering hosts the public resolver dropped.
- **Recursive enumeration is now opt-in.** It is off by default — an ordinary scan
  is apex-only again (fast, and never starved by a throttled recursive pass). A new
  **"Recursive enumeration"** checkbox in the scan dialog turns it on when you
  actually want depth. It is cancellable like any other phase.
- Guarded a latent `nuclei -eid ""` edge case (an empty exclude value is not a
  no-op to every nuclei build).

If you upgraded to v4.7.0 and saw findings collapse, this is the fix — no config
change needed, just redeploy.

## Scan cancellation no longer "just re-probes"

Cancelling a scan is correct at the backend (the context is cancelled, tool
processes are killed, the task is marked cancelled). The reported "it just
re-probes after I cancel" was the **continuous monitor**: its due-check only
skipped targets with a recent *monitor* task, so a target whose **manual** scan you
had just cancelled (or that had just finished) was immediately eligible for a
monitor re-probe — one would start within a minute. The due-check now skips any
target with an active task of **any** type, or any task activity in the last 30
minutes. A manual cancel genuinely stops the target's activity; monitoring resumes
on its normal interval, not instantly.

## UI fixes

- **Notifications no longer hide behind the page.** The notifications dropdown and
  the toast stack sat at `z-50`, below the app's `z-[100]` modal/overlay layer, so
  they could render behind other content. Both now sit above it.
- **The Changes view collapses near-duplicates.** Changes that are identical except
  for the URL (for example the same header added across dozens of hosts) now
  collapse into a single row with an affected-URL count, instead of dozens of
  near-identical rows burying the real drift.

## Note on per-module control

Turning individual modules on or off (CORS, a specific injection class, …) is done
through the **Custom** scan profile in the scan dialog, which already lets you pick
exactly which checks run.

## Upgrade

No migration, no config changes.

```
docker compose pull && docker compose up -d
```
