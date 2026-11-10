# TODO — minor findings

Recorded: 2026-10-25
Source: validation audit of commit `0b6ebe1` (per-target HTTP catch-all override)
Verdict: no functional bugs. Items below are polish/consistency, none block use.

Status: items 1–3 fixed in the follow-up commit (see git log). Items 4–5 remain
open by design / pending a decision.

## 1. List endpoints emit empty override strings (API consistency)

`GET /targets` (handleListTargets) and the `POST /targets` create response
build `models.Target` without the new catchall fields, so JSON contains:

    "catchall_detection": "",
    "catchall_effective": false

The detail endpoint (`GET /targets/{id}`) always returns `inherit|on|off`.
The UI reads these fields only from the detail endpoint, so there is no UI
effect today. External API clients could misread the empty string.

Fix options:
- Fill the fields in the list/create handlers (compute like handleGetTarget), or
- add `omitempty` to both JSON tags in `internal/models/models.go`.

## 2. Doc comment misattached (cosmetic)

In `internal/scanner/http_catchall.go`, the `runCatchallPass` doc comment now
sits above `catchallEnabledForTarget` because the helper was inserted between
the comment and its function. `runCatchallPass` has no doc comment of its own.

Fix: move the comment down, or give each function its own short comment.

## 3. Silent UI failure on catch-all save (UX)

`saveCatchall` in `frontend/src/pages/TargetDetail.tsx` swallows errors
(`catch { /* ignore */ }`), same pattern as `saveMonitor`. On a failed PUT the
select snaps back to the previous value with no toast.

Fix: add an error toast (the page already has `addToast`).

## 4. DB error during override lookup falls back to global (edge)

`catchallEnabledForTarget` returns the global config when the targets query
errors. An explicitly-Off target could therefore run one catch-all pass during
a transient DB error. The pass is best-effort by design; noted so the behavior
is not a surprise.

Optional fix: fail closed for explicit overrides by caching the resolved value
per scan instead of re-querying.

## 5. Turning the override Off does not unmark existing rows (by design)

Marked rows keep `catchall = 1` and stay hidden from the Hosts tab, reports,
graph, stats and wordlist learning. This is the mark-never-delete design: the
override only controls FUTURE passes.

Optional follow-up (needs a decision): a small "unmark" action or a cleanup
query (`UPDATE subdomains SET catchall = 0 WHERE target_id = ?`) exposed in
the UI.
