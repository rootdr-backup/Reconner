# Scanner quality evidence: backup, XSS and SQLi

Release candidate: v3.1.0.

This record describes bounded local evidence, not a universal internet-wide
detection percentage. No third-party system was scanned: every network request
in validation went to a local `httptest` fixture or local headless Chromium.

## Measurement contract

The suites keep positive and negative fixtures explicit. A required browser
cannot be skipped in CI. Counts apply only to the named fixture set; errors,
cancellation and timeouts are not silently classified as negatives. This follows
the test-set/scoring principles in [OWASP Benchmark](https://owasp.org/projects/benchmark)
and the precision/recall cautions in [NIST SATE V](https://www.nist.gov/publications/sate-v-report-ten-years-static-analysis-tool-expositions).

## Backup discovery

The former integration test supplied `/back/.env` as its only corpus input.
v3.1.0 proves that the default planner generates and schedules the path itself.
Two soft-404 calibration probes run first; `/back/.env` must then enter the first
40-candidate high-signal batch rather than sit behind the generic cross-product.

Observed-directory and adaptive-product paths now run before the full generic
corpus, while stable deduplication retains every former path. This changes
time-to-signal, not coverage. Soft-404 classification remains content-type,
title and size/noise aware, following the response-calibration principle in
[ffuf autocalibration](https://github.com/ffuf/ffuf/wiki/Autocalibration).

Backup probes request only bytes 0-262143. Both 200 servers that ignore Range and
206 servers that honor it are accepted. `Content-Range` supplies full size when
available; an unknown chunked body is no longer drained up to 200 MB merely to
count it. Local regression tests cover default `/back/.env` discovery, Range,
206 persistence, size extraction, magic bytes, short high-signal env files and
soft-404/HTML rejection.

## XSS

String reflection and static source-to-sink matches remain routing intelligence,
not verified findings. Verification requires a fresh nonce to execute in real
Chromium. Context ladders follow [PortSwigger's context model](https://portswigger.net/web-security/cross-site-scripting/contexts)
and its guidance to follow attacker-controlled sources into executable rendered
sinks ([DOM XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)).
Modern tracing includes direct HTML sinks catalogued by the
[Trusted Types API](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API),
including `setHTMLUnsafe()` and `Document.parseHTMLUnsafe()`.

v3.1.0 removes a fixed 250 ms delay from every Chromium attempt. A 100 ms poll
checks synchronous proof immediately and repeats only nonce-scoped interactions
while waiting for late SPA hydration. On the local release environment, the
warmed 13-positive context matrix completed 13/13 in 1.19 seconds; removed sleeps
alone formerly imposed a 3.25-second minimum. The separate safe encoded fixture
remained negative. This is a reproducible regression result, not universal recall.

When `RECONNER_BROWSER_TEST=1`, failure to locate Chromium is fatal rather than a
skip, preventing a green release gate that executed no browser coverage.

## SQL injection

Deterministic validation still requires reproduced DB errors or differential
boolean/arithmetic controls. Blind timing follows the conditional-response and
DBMS-specific delay model described by [PortSwigger](https://portswigger.net/web-security/sql-injection/blind),
with baseline, sleep(0), sleep(2) and sleep(5) distributions. This is consistent
with sqlmap's separation of boolean, error and time-based techniques in its
[official techniques](https://github.com/sqlmapproject/sqlmap/wiki/Techniques).

v3.1.0 prevents a missing request-write trace timestamp from becoming an
enormous apparent delay, and requires a two-thirds successful-sample quorum so
one surviving request cannot become its own median. The initial sleep(5) screen
is now reused in the three-sample confirmation, saving one roughly five-second
request per confirmed vector. The minimum injected sample must still clear the
slowest baseline and sleep(0)/sleep(2)/sleep(5) must still scale linearly.

Tests cover real scaling, modest jitter, fixed WAF delay, overlap, sub-linear
responses, quorum behavior and the exact two-request remainder after reuse.

## Reproduction

```bash
go test ./internal/scanner -run 'Test(Backup|ShortNestedEnv|SensitiveBackup|Timing|SQLi)' -count=1

RECONNER_BROWSER_TEST=1 RECONNER_CHROME=/path/to/chromium \
  go test ./internal/scanner \
  -run '^(TestBrowserXSSConfirmLive|TestBrowserXSSContextCoverageLive|TestBrowserDOMSourceModesLive)$' \
  -count=1 -v
```

The full release also requires formatting, unit/race tests, frontend
coverage/build, migrations, security checks, and native amd64/arm64 image builds
and scans on the same commit.
