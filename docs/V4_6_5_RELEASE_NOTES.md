# Reconner v4.6.5 — fixed the real cause of "XSS finds nothing": an upstream chromedp race

Investigating "ادونس ترش کن / xss چیزی پیدا نمیکنه" (make XSS more advanced /
XSS finds nothing) led to a genuine root cause, confirmed with both an
isolated reproduction and a real end-to-end run — not Reconner's own code,
but a data race inside the pinned chromedp library itself.

## The real bug: a race inside chromedp v0.13.6, not Reconner's serialization

Every XSS finding requires a real Chromium execution proof — no finding
without proof, by design — so a flaky browser-confirmation pipeline silently
suppresses real positives instead of erroring loudly. CI's race detector
previously caught a data race in exactly that path
(`browserXSSConfirmer.ensureTab` → `chromedp.Run` → `ExecAllocator.Allocate`),
once, then came back clean on an immediate re-run — the signature of a
timing-dependent bug, not a deterministic one.

Reconner's own serialization (`startMu` + `navGate` in `xss_browser.go`,
from two earlier "fix chromedp race" commits) turned out to be correct and
intact: it does guarantee only one goroutine is ever inside `chromedp.Run`
establishing a browser at a time. The race lives **inside chromedp itself**:
`ExecAllocator.Allocate` (chromedp v0.13.6) spawns a goroutine that writes
its own captured `wsURL`/`err` once Chromium prints its devtools URL — but
if that takes longer than the library's 20s read timeout, `Allocate`'s own
timeout branch *also* writes that same `err` and returns, leaving the first
goroutine to write the same memory later with no synchronization between
the two. A single slow browser launch (container contention, `-race`'s own
2-20x slowdown) is enough to trigger it — no concurrent Reconner candidate
required, though running many candidates concurrently (as Reconner does,
`dastWorkers`) makes a slow launch more likely to happen during a scan.

Fixed upstream in chromedp v0.13.7 (the timeout branch now returns its own
error directly instead of writing the shared variable). `go.mod`/`go.sum`
bump the pin accordingly — a pure bugfix patch, zero new dependencies, zero
API surface changes.

## Verified two ways

- An isolated synthetic test reproducing chromedp's exact allocation
  pattern: the v0.13.6 shape reliably trips `go test -race` within ~200
  iterations; the v0.13.7 shape never does, across repeated runs.
- A real end-to-end run of the actual production pipeline
  (`DASTScanner.RunXSS`) against 20 genuinely-vulnerable reflected-XSS
  parameters (unescaped reflection into HTML text — the simplest possible
  real case), exceeding the worker pool size so every worker is confirming a
  payload via a real Chromium simultaneously. All 20 confirmed, no race,
  under `-race`. Kept as `TestXSSConcurrentBrowserConfirmation`
  (`internal/scanner/xss_concurrency_repro_test.go`; skips cleanly with no
  Chrome available).

A broader audit of the context-detection ladder, confidence thresholds,
WAF-block heuristics, and payload coverage found no other regression —
XSS's detection logic itself is sound; the browser-proof pipeline's
reliability was the gap.

## Upgrade

No migration, no config changes, no new dependencies (a patch-level bump of
an existing dependency). Rebuild/redeploy.
