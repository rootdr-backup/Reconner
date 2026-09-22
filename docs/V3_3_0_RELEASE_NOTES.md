# Reconner v3.3.0

This release focuses on the **Web behavior checks** module. It improves the
coverage and latency of its five detector families without weakening their
positive-proof or negative-control requirements.

## Parallel execution and request planning

- Runs 403 bypass, host-header injection, CRLF, prototype-pollution and
  cache-deception families concurrently. Each family retains a bounded worker
  pool and context cancellation.
- Deduplicates crawl/history URL value variants by origin, path and query-field
  shape before testing, preserving distinct routes while removing repeated
  policy checks.
- Converts 403 validation from two requests for every technique to one parallel
  preflight per technique. A possible bypass still requires a second stable 403
  control and an identical 200 replay before promotion.

## Coverage upgrades

- Adds forwarded URI, forwarded-chain, true-client-IP and additional path
  normalization/delimiter variants to 403 bypass checks.
- Expands host override inputs to `X-HTTP-Host-Override`, `X-Original-Host`,
  RFC-style `Forwarded: host=...` and absolute `X-Original-URL`. Controlled URLs
  are recognized in `Location`, `Content-Location`, `Link`, `Refresh`, parsed
  HTML URL attributes and structured response bodies; a bare debug echo remains
  non-actionable.
- Tests CRLF single-, double- and triple-decoding families in parallel and
  retains two independent random response-header proofs.
- Includes authenticated parameter routes in prototype-pollution discovery and
  adds JSON `POST`/`PUT`/`PATCH` proof with preserved sibling fields. A confirmed
  result requires two random properties to emerge at the top level; nested
  request echo remains only a candidate.
- Extends web-cache-deception proof beyond one `/file.css` suffix to delimiter,
  encoded delimiter, extension and static-prefix normalization discrepancies.
  Private JSON responses are covered alongside HTML, and modern `Cache-Status`
  families are recognized while `HIT-FOR-PASS`, `MISS`, dynamic and bypass
  responses are rejected.

## Local release evidence

- v3.3 positive behavior matrix: **13/13 passed**.
- v3.3 negative controls: **4/4 passed**.
- Three repeated matrix runs and targeted race-detector runs passed.
- The pre-existing focused detector suite fell from 2.639 seconds to 0.920
  seconds on the release workstation: **2.87x faster** for that named local
  workload despite the expanded technique set.
- The complete Go test suite passed after the changes.

These numbers describe deterministic local fixtures, not a universal claim that
every framework, intermediary or deployment on the internet is detectable. No
third-party host was tested. All validation traffic stayed on loopback servers
created by the test process.

Detailed cases and reproduction commands are in
[v3.3 Web behavior quality evidence](V3_3_WEB_BEHAVIOR_QUALITY_EVIDENCE.md).
