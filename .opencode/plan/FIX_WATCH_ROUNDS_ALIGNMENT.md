# Fix: Rounds strip alignment on the Changes page

Status: plan only. No source files edited.

## Goal

Fix the visual alignment of the round chips strip on the global Changes page (`/changes`).
Change only the live component. Keep behavior identical.

## Scope — why this file

The repo changed since the first version of this plan.

- `frontend/src/pages/Changes.tsx:1,10` imports and renders `<ChangeLog />`. This is the live page.
- `frontend/src/components/changes/ChangeLog.tsx` owns the round chips strip at lines 382–410.
- `ChangesExplorer.tsx` and `RoundTimeline.tsx` have **no importer** in the app. They are dead code. Do not edit them.
- The per-target Changes tab is inline in `TargetDetail.tsx:857-871`. It renders a plain table and **no round strip**. Do not edit it. It also has uncommitted work from another agent.
- Do not edit `index.css`. `.panel-heading` is used by `Dashboard.tsx` and is unrelated to this strip.

## Root cause (verified against current markup)

The "Rounds" strip is a single horizontal row:

```
ChangeLog.tsx:383-410
<div className="flex items-center gap-1.5 overflow-x-auto pb-1">
  <span className="shrink-0 text-[10px] uppercase tracking-wide text-text-muted">Rounds</span>
  <button className="shrink-0 rounded-full border px-2.5 py-1 text-[10px] transition"> ... </button>
  ...
</div>
```

Three factual mismatches against the rows directly above it:

1. **Vertical padding is asymmetric.** The strip uses `pb-1` only (line 384). The select row above uses `py-2` (line 344). The strip sits closer to its bottom edge than its top edge.
2. **Chip text size differs from the filter chips.** Round chips are `text-[10px]` (line 392). The "Since" and category filter chips above are `text-[11px]` (lines 306, 333). The two chip rows look like they belong to different controls.
3. **The label has no spacing of its own.** "Rounds" (line 385) relies on the container `gap-1.5` only. The "Since" label above (line 299) also has `mr-1`. The two labels sit at different distances from their first chip.

`items-center` is already on the strip, so the label and chip text share a vertical center. Do not "fix" that part. The issue is padding, text size, and label spacing.

## Proposed fix

Edit `frontend/src/components/changes/ChangeLog.tsx` only. Three class changes:

1. Line 384 — strip container. Replace `overflow-x-auto pb-1` with `overflow-x-auto py-1.5`.
   - Gives symmetric top and bottom padding. Keeps `flex items-center gap-1.5` and horizontal scroll.

2. Line 385 — "Rounds" label. Add `mr-1` so it matches the "Since" label spacing.
   - Result: `shrink-0 mr-1 text-[10px] uppercase tracking-wide text-text-muted`.

3. Line 392 — round chips. Change `text-[10px]` to `text-[11px]`.
   - Matches the filter chips above. Keep `shrink-0 rounded-full border px-2.5 py-1 transition`.

Do not add a divider. The parent already uses `space-y-3` (line 296), and the select row above already has `border-y`. A second border would double the lines.

Do not change the `title` string, the dot span, the status word, the 20-round slice, or the click/Clear handlers.

## Constraints

- Class changes only. No new files, no new dependencies, no logic changes.
- Keep `overflow-x-auto`, `shrink-0` on the label and chips, and the `ROUND_DOT` dot.
- Preserve: chip click toggles `selectedTaskId`; "Clear" resets it; status word stays visible.
- No source edits until this plan is approved.
- Do not touch `TargetDetail.tsx`, `ChangesExplorer.tsx`, `RoundTimeline.tsx`, or `index.css`.

## Verification

Run from the repo root:

```sh
cd /home/void/clones/Reconner
npm --prefix frontend run build
npm --prefix frontend test -- --run
```

Visual check — global page only:

- Open `/changes` with at least two watch rounds present.
- The "Rounds" label sits on the same line and baseline as the chips.
- Chip text size matches the "Since" and category chips above.
- Top and bottom space around the strip is even.
- The strip still scrolls sideways when many rounds exist.
- Clicking a chip filters the feed; "Clear" removes the filter.

The per-target Changes tab does not render this strip. Do not test it for this fix.

If the running Docker container still shows the old layout, rebuild the frontend (`npm run build`) and copy `frontend/dist` into the container before checking. The global page code lives in the dashboard files, not the binary.

## Deferred — do not include in this fix

- **Timezone bug.** SQLite `CURRENT_TIMESTAMP` stores UTC as `YYYY-MM-DD HH:MM:SS`. JS `new Date()` parses that as local time. The host is UTC+03:30, so `timeAgo()` in `utils.ts:20-30` sees a future time and prints "Just now" for every round. Also affects the "Last detection" figure. Fix in a separate plan.
- **Pluralization.** The chip shows `r.change_count` with no noun in the visible text; the `title` uses "change(s)". Cosmetic.
- **Rounds strip ignores filters.** `watchApi.rounds()` is not filtered by the active category, severity, or time chip. The counts stay global while the feed below is filtered.
- **`compact` prop.** Declared at `ChangeLog.tsx:138` but never passed. No per-target placement exists today.

## Acceptance criteria

1. Only `frontend/src/components/changes/ChangeLog.tsx` changes.
2. Round chips use `text-[11px]`; the "Rounds" label has `mr-1`; the strip uses `py-1.5` with no `pb-1`.
3. `npm --prefix frontend run build` passes.
4. `npm --prefix frontend test -- --run` passes.
5. Visual check on `/changes` confirms even padding and matching chip size.
6. Chip click and Clear still filter the feed.
