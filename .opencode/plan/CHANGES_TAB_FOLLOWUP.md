# Changes tab follow-up plan

Status: implemented. Item 1 and item 3 (option C) are committed. Item 2 is
verified in code and needs one live check from the user.

## 1. Per-target Changes tab — DONE (uncommitted)

Problem: my commits `4cdb5d2`..`50281a7` replaced the original per-target
tab with `ChangesExplorer`. I told the user it was unchanged, which was wrong.

Action taken:
- Restored `frontend/src/pages/TargetDetail.tsx` and
  `TargetDetail.monitor.test.ts` from `main` (`0e40189`).
- The original table, chips, grouping, occurrence expander, stylesheet/script
  `Diff` button and `ChangeDiffViewer` are back. Colors match the other tabs
  because the code is the original code.
- One deliberate change remains. The monitor tab now calls
  `changes.forTarget(id)` instead of `findingsApi.monitoringChanges(id)`, and
  maps `ChangeEntry` to `MonitoringChange`. This adds watch-round diffs, scope
  landings and bell rows to the same table without changing its design.

Validation: `go build ./...`, `go test -p 2 ./...`, `npx tsc --noEmit`,
`npm test -- --run` (63/63), `git diff --check`, `make frontend` all pass.

## 2. Watch breadth round visibility — DONE in code, needs one live check

The unified feed at `/api/targets/{id}/changes` already includes
`watch_round_changes`, `watch_scope_events` and `notifications`. The restored
per-target tab now reads that feed. `task_finished` calls `loadTab(tab)` for
every tab, including `monitor`. Backend tests already insert watch rows and
assert the forced-target endpoint returns them.

Known design rule: a round with no detected difference writes no change row.
It appears only in `/api/watch/rounds`. If the user still sees nothing, get the
target id and the round finish time, then check:
- `watch_round_changes` rows for that `task_id`;
- the round row in `tasks` (pruned at 90 days);
- the `task_finished` broadcast and the browser WS connection.

## 3. Merck & Co. — Hosts many, URLs only two

### Finding

This is a gap in the DNS resolver path. It is not a breadth-only rule and not
a deliberate exclusion of live aliases.

User data confirms it. `dig account.merck.com` returns:

```
account.merck.com. 300 IN CNAME d27qwt9heez1et.cloudfront.net.
d27qwt9heez1et.cloudfront.net. 60 IN A 108.157.60.59   (plus .86, .32, .79)
```

The A records live on the CloudFront name, not on the alias.

- `dnsxResolveIPs` runs `dnsx -a -aaaa -resp` (`recon_stack.go:239`). It does
  not report the final A records under the alias name. dnsx emits the CNAME
  token under `account.merck.com`; `net.ParseIP` drops it
  (`recon_stack.go:256`). The A records come back under the target name, which
  is not in the queried list. `ipmap["account.merck.com"]` stays empty.
- `classify` sees no IP, calls `cnameFor`, gets the target from the separate
  `-cname -resp` pass, and admits the row as source `dns-cname` with an empty
  IP (`subdomain.go:1176-1183`).
- The probe query requires a non-empty IP (`http.go:58`). The host is skipped.
  No `http_services` row, no URL, no scope landing, no change diff.
- This happens in deep and watch scans. Both use the same enumeration and the
  same probe query.
- The CNAME target is already captured in `cnameTargets[name]`
  (`dnsxCNAMECandidates`, `subdomain.go:1485-1521`). That is the missing input
  for the fix.
- `frontend/src/lib/api.ts:338-339`. Both Hosts and URLs use `fetchAllPaged`.
  The "only 2" is real data, not a client page cap.

The empty-IP admission for a CNAME is deliberate. It exists for takeover
checks (`subdomain.go:1176-1178`, `takeover.go:45-95`). The defect is that a
**live** CNAME target's IP is never copied onto the alias row.

### Options

A. Probe `dns-cname` hosts.
   Add `dns-cname` to the accepted sources in `internal/scanner/http.go:52-60`.
   The alias has no A/AAAA of its own, so httpx also fails to resolve it.
   Cost: failed requests and a larger watch rate budget.
   Gain: none. No service row, no status diff.

B. Add a UI note for truly dangling CNAMEs.
   Show "DNS alias — no HTTP probe" on those host rows. Correct only for
   aliases whose target does not resolve. Does not help live aliases.

C. Resolve and store the CNAME target IP (recommended).
   In `resolveAll`, collect the distinct values of `cnameTargets`, run one
   batched dnsx A/AAAA pass over them with `dnsxResolveIPs`, then in `classify`
   use those IPs when the alias itself has none. Admit with the IP and keep
   source `dns-cname`. The probe query accepts any non-empty IP, so the host
   enters `http_services`, scope landing and the change diff. A dangling
   CNAME keeps an empty IP and stays in takeover only.
   Cost: one extra dnsx pass over distinct CNAME targets per round.
   Tests: a CNAME alias with a resolvable target gets a non-empty IP and an
   `http_services` row; a dangling alias keeps an empty IP and no service.

D. Fix unrelated causes after C.
   If hosts have `source='dns'` and a non-empty IP but no service rows, look at
   httpx errors, rate limit or WAF. If hosts are `vhost`/`seed` rows, change
   the URL tab source filter at `finding_handlers.go:146` and show a source
   badge.

### Recommendation

Implement C. `diffWatchHTTP` writes a `status_change` only for URLs present in
both snapshots (`watch_changes.go:151`). A host needs an `http_services` row
first. C gives the alias an IP, so the probe stores that row and later rounds
can report a 403 → 200 flip. A is useless: the alias has no A/AAAA, so httpx
cannot resolve it either. B covers only dangling aliases. D covers separate
problems and can follow C.

### Optional data check

The root cause is confirmed for `account.merck.com`. To size the impact on the
whole target, run inside the container:

```
docker exec reconner sh -c 'sqlite3 /data/recon.db "
SELECT source, COUNT(*), SUM(CASE WHEN COALESCE(ip,\"\")=\"\" THEN 1 ELSE 0 END)
FROM subdomains WHERE target_id=(SELECT id FROM targets WHERE name LIKE \"%Merck%\")
GROUP BY source;"'
```

A large `dns-cname` count with empty IPs means C fixes many hosts.

## 4. Decisions

1. Option C implemented. `resolveAll` resolves distinct CNAME targets with one
   batched dnsx A/AAAA pass and copies the target IP onto live aliases.
   Source stays `dns-cname`; dangling aliases keep an empty IP.
2. Restored per-target tab committed with the fix.
3. Merck data check skipped. The user's `dig` output confirmed the root cause.

## 5. Validation checklist for any change

- `git diff --check`
- `go build ./...`
- `go test -p 2 ./...` (scanner tests take about 2 minutes)
- `npx tsc --noEmit`
- `npm test -- --run`
- `make frontend`
- Docker deploy, if the user asks:
  `docker cp ./reconner reconner:/usr/local/bin/reconner`
  `docker cp frontend/dist/. reconner:/opt/reconner/frontend/dist/`
  `docker restart reconner`
