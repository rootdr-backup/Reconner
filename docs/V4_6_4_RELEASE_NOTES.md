# Reconner v4.6.4 — hakrawler was completely broken; deeper crawl by default

A real, silent bug found while investigating a "crawling isn't thorough
enough" report, plus the concrete fix that report asked for.

## hakrawler has been producing zero URLs, always, everywhere it's used

Reconner invoked hakrawler with `-url <target> -depth 2 -insecure`
(`param_discovery`) and `-url <target> -js -insecure` (`js_analysis`). The
pinned hakrawler build (hakluke/hakrawler, the exact commit the Dockerfile's
`HAKRAWLER_VERSION` pins) has **none of those flags**: it takes its crawl
target on **stdin**, not a `-url` flag, and its depth flag is `-d`, not
`-depth`. An unrecognized flag makes hakrawler print its usage to stderr and
**exit 0** — not a failure `RunWithCallback`/`Run` would ever see — so every
single hakrawler invocation in this codebase has been silently contributing
**zero** crawled URLs, in both call sites, for as long as that flag shape was
in use.

This was verified two ways: by installing the exact pinned hakrawler build
and reproducing the failure directly (`flag provided but not defined: -url`),
and by fixing the invocation and re-running it against a local test site,
where it correctly returned every linked page, query-param URL, and JS file.

Fixed by piping the target through stdin (`RunWithInputCallback`) with the
real flags (`-d 3 -insecure -timeout 25`), extracted into one shared,
tested `hakrawlerArgs()` helper used by both call sites so this exact
regression can't silently reappear in only one of them.

## Deeper crawl everywhere else

- **katana**: `-depth` was deliberately set to 2 — one level *shallower* than
  katana's own default of 3 — as part of an earlier speed fix. That fix's
  real mechanism was the per-host time ceiling (bounded `-ct` + bounded outer
  context + parallel hosts), not the shallower depth; now that the ceiling
  exists, depth is restored to katana's default in both `param_discovery` and
  `js_analysis`, with the ceiling raised slightly (45s→60s, `-ct` 30→40) to
  give the extra level room to run.
- **dirsearch**: never used recursion at all — a single flat pass that never
  looks inside a directory it already found (e.g. `/admin/` or `/api/v1/`).
  Added `-r -R 2 --recursion-status 200,301,302 --crawl`: recursion bounded to
  depth 2 and to alive/redirecting status codes only (recursing into a
  401/403 wastes requests for nothing reachable behind it), plus `--crawl` to
  mine additional path candidates out of responses already fetched (no extra
  requests of its own). Both are safe to enable now because `runDirsearch`'s
  existing 150s per-host outer ceiling (added after an earlier `--crawl`
  regression that let one host burn 5+ minutes) already bounds the worst
  case — recursion just spends that same budget more thoroughly, never a
  longer one.

## New regression tests

- `TestHakrawlerArgsNeverUsesURLOrDepthFlags` / `TestHakrawlerReceivesTargetViaStdinNotArgs`
  (`internal/scanner/hakrawler_test.go`) — pin the correct flag shape and prove
  the target flows through stdin, using a fake hakrawler binary that fails
  loudly if invoked with `-url`/`-depth`/`-js`.
- `TestRunDirsearchPassesBoundedRecursionFlags`
  (`internal/scanner/directory_external_test.go`) — pins the recursion flags
  on the real `runDirsearch` call path.

## Upgrade

No migration, no new dependencies. Rebuild/redeploy.
