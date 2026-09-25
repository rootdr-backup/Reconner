# v3.4 XSS state and coverage evidence

This change implements the F0 measurement foundation and the Package A
client-side/XSS work selected from the Q3 research backlog. Validation uses only
checked-in logic, SQLite test databases, Go `httptest` applications and local
Chromium fixtures. No third-party target is contacted.

## Contracts

- Every scheduled phase has durable discovered/eligible/attempted/candidate/
  confirmed/rejected/blocked/error counters.
- Candidate lifecycle transitions populate proof/rejection counters centrally;
  scanners cannot claim proof merely by increasing a metric.
- Browser state identity combines the current URL and semantic live-DOM shape.
  State nodes retain their transition parent and sequence.
- Safe automatic interactions are limited to hash links, ARIA tabs with an
  explicit target, and closed `details` summaries. Generic buttons and form
  submission are excluded.
- XSS runtime instrumentation observes classic sinks, static and streaming
  unsafe HTML insertion, source reads and Trusted Types policy flow. Runtime
  traces remain routing evidence; nonce execution remains the confirmation bar.

## Local verification

```bash
go test ./internal/scanner ./internal/database ./internal/api ./internal/scheduler
RECONNER_BROWSER_TEST=1 \
RECONNER_CHROME='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' \
go test ./internal/scanner \
  -run 'TestBrowserXSSConfirmLive|TestBrowserDOMSourceModesLive' -count=1 -v
cd frontend && npm test -- --run && npm run build
```

The browser matrix covers raw/hash-parameter, path, `window.name`, real
`postMessage`, nested `srcdoc`, reflected, SPA, cross-origin-frame and transient
DOM execution. Positive proof is a random per-attempt nonce; safe DOM rendering
and patched fixture controls remain negative.

This evidence does not assert a universal percentage against arbitrary web
applications. It makes release-to-release recall, false-positive and execution
cost changes measurable on deterministic local families.
