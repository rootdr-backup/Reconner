# Reconner v3 Stability Release Plan

## Release thesis

Reconner v3.0.0 is a stability, correctness, coverage, and performance release.
The feature set is frozen at v2.5.0. New scanners, integrations, protocols, and
major UI features are out of scope until v3.0.0 is released.

The release must not claim that an arbitrary black-box target can be scanned
with mathematically zero false positives or false negatives. That claim cannot
be proven for the open web. The enforceable v3 contract is:

- zero known correctness, data-loss, security, or release-blocking functional
  defects in the supported feature matrix;
- zero false positives and zero false negatives in Reconner's versioned,
  deterministic Tier A and Tier B benchmark corpus;
- no silent coverage gaps: every selected capability reports `tested`,
  `skipped`, `blocked`, `unsupported`, or `failed`, with a reason;
- only results satisfying a detector-specific proof contract may be presented
  as verified findings; weaker signals remain candidates or observations;
- no material performance regression from the frozen v2.5.0 baseline, and
  measured improvement for identified hot paths;
- clean install, upgrade from supported v2 releases, restart, backup, and
  restore must pass in the production Docker image.

## Non-negotiable working rules

1. Keep `VERSION` at `2.5.0` during hardening. Version 3 identifiers begin only
   after the release gates exist and pass.
2. Do not publish a v3 tag from a developer workstation. A signed/annotated tag
   may be created only from a reviewed release commit after all required CI jobs
   pass.
3. Fix from a reproducible failing test. Every bug fix adds a positive case, a
   confusing negative control, or both.
4. Prefer narrow fixes over broad rewrites. Refactors require characterization
   tests before behavior changes.
5. Never convert a timeout, WAF response, login redirect, soft-404, reflection,
   tool crash, or unavailable dependency into a clean bill of health.
6. Never convert an unverified signal into a finding to improve recall metrics.
7. Do not hide unsupported coverage. A partial capability is marked partial and
   is not advertised as stable until its required matrix is complete.
8. Preserve user data across every migration and failure path. Destructive
   target actions keep explicit confirmation and audit behavior.

## Ground-truth test levels

| Tier | Purpose | Required result |
|---|---|---|
| A | Unit proof contracts and parser/request reconstruction fixtures | Deterministic, zero FP/FN, no flaky tests |
| B | Local adversarial HTTP/browser/OAST labs with labeled vulnerable and safe controls | Deterministic, zero FP/FN, exact evidence assertions |
| C | Full Docker pipeline with real bundled external tools | Expected findings and phase states; graceful tool failure |
| D | Explicitly authorized staging/shadow targets | Manually labeled comparison and regression evidence; never used for an absolute open-web claim |

Every detector family needs at least one true positive, one true negative, one
deceptive negative, one unstable/WAF/rate-limit case, and request-contract
assertions for every supported insertion surface. Security fixes derived from a
real report must add a sanitized regression fixture to the permanent corpus.

## Phase 0 — Freeze, inventory, and baseline

Deliverables:

- freeze the v2.5.0 feature surface and create a complete inventory of API
  routes, UI workflows, scheduler modules, scanner families, data stores,
  migrations, external binaries, configuration keys, and notification events;
- assign one owner and one proof contract to every emitted result type;
- create a coverage matrix for query, path, form, JSON, multipart, XML,
  GraphQL, header, cookie, authenticated, unauthenticated, browser, and OAST
  contexts;
- record the current TP/FP/FN count per family, request count, wall time,
  allocations, peak RSS, database size, bundle size, and startup time;
- identify flaky tests by running deterministic suites repeatedly with fixed
  random seeds;
- create a risk register ordered by data loss, scope escape, false positive,
  false negative, deadlock, resource leak, and UX failure;
- preserve v2.5.0 outputs as the immutable performance comparison baseline.

Exit gate: every existing capability and result emitter appears in the
inventory. Unknown ownership or unknown coverage is itself a blocking defect.

## Phase 1 — Build the release gates before fixing behavior

Add required GitHub Actions jobs for:

- Go formatting/module consistency, `go test ./...`, and `go vet ./...`;
- race testing for scanner, API, scheduler, database, capture, browser, and
  secret-handling packages;
- Tier A/B benchmark scoring with machine-readable per-family TP/FP/FN output;
- repeated deterministic tests to detect order dependence and flakes;
- TypeScript build plus frontend unit and browser workflow tests;
- clean Docker build and health/login/target/scan/result smoke tests;
- migration tests using copies of supported historical databases;
- dependency, source, container, and secret scanning;
- version consistency between `VERSION`, frontend package metadata, image
  labels, tag name, and `/api/version`;
- build artifacts and diagnostic reports retained for failed jobs.

The release job must depend on every quality job. A tag/image/release cannot be
published after a skipped or failed gate.

Exit gate: deliberately breaking a detector assertion, frontend build,
migration, or smoke test prevents publication.

## Phase 2 — Core platform correctness

Audit and harden these flows end to end:

1. configuration defaults, validation, encryption, redaction, and restart;
2. authentication, session expiry, CSRF boundary, RBAC, user isolation, and
   admin-only operations;
3. target/project/program create, import, edit, scope change, monitor, and
   confirmed deletion;
4. SQLite migrations, transactions, foreign keys, contention, backup, restore,
   partial writes, full disk, and corrupt-input handling;
5. task creation and dependency planning, pause, resume, skip phase, cancel,
   timeout, watchdog, crash recovery, orphan reconciliation, and concurrent
   target isolation;
6. Telegram token replacement/disable, allowlist roles, commands, callbacks,
   duplicate updates, offline retry, rate limits, per-chat fan-out, exact-once
   phase/finding delivery, and secret-free errors/logs;
7. missing, outdated, crashed, hanging, or malformed external tool behavior.

Exit gate: no silent success, stuck task, duplicate mutation/notification,
cross-user/cross-target leak, or unrecoverable partial state in the fault matrix.

Browser-backed cancellation specifically requires phase-linked CDP contexts,
task-owned process-group termination, bounded allocator/profile cleanup and a
scheduler grace boundary. A browser worker that ignores cancellation must not
hold `current_module`, a navigation gate or a scheduler slot indefinitely.

## Phase 3 — Discovery and input-coverage truth

Validate the producers before judging detector recall:

- asset and subdomain admission, wildcard and multi-asset scope, DNS and vhost
  catch-all behavior;
- HTTP probing, redirect policy, TLS behavior, canonical URLs, virtual hosts,
  soft-404s, WAF/rate-limit baselines, and authenticated headers;
- crawl, headless crawl, JavaScript files/endpoints/dependencies, historical
  URLs, API specifications, directories, backups, parameters, and reflection;
- capture import, replay, redaction, identity binding, workflow variables, and
  exact request-template preservation;
- deduplication and provenance from discovery through verification.

For each target/scan, reconcile `discovered -> eligible -> attempted -> proved`
counts. Missing prerequisites, tool failures, policy blocks, and unsupported
request shapes must be visible rather than counted as negative results.

Exit gate: every labeled Tier A/B input reaches its intended detector once, and
every excluded input has a stable, testable reason.

## Phase 4 — Detector-by-detector proof audit

Audit every existing detector and every supported request surface. Work in this
order so high-confidence primitives stabilize before conditional protocols:

1. exposures, backups, passive intelligence, directories, origin discovery,
   takeover, broken-link hijacking, and Nuclei ingestion;
2. SQLi, XSS/DOM/stored XSS, NoSQLi, LFI, SSRF, SSTI, CSTI, XXE, command
   injection, CRLF, and open redirect;
3. CORS, CSRF, JWT, 403 bypass, host-header trust, prototype pollution, and
   account takeover;
4. IDOR/BOLA/BFLA and authorization replay across owner, attacker,
   unauthenticated, and role-separated identities;
5. cache poisoning/deception, request smuggling, race conditions, workflow
   checks, OAST attribution, and monitoring changes;
6. network/CIDR admission and legacy-data handling: the current source tree has
   no network executor, so API, scheduler, UI, and Telegram must reject new
   network execution explicitly while keeping historical rows readable and
   exportable.

For every family, define:

- supported prerequisites and insertion surfaces;
- exact positive proof and at least two independent negative controls where
  applicable;
- baseline/WAF/volatility/login/soft-error rejection behavior;
- retry, timeout, cancellation, and request-budget behavior;
- deterministic fingerprint, deduplication, severity, evidence, remediation,
  and reporting contract;
- candidate-to-verified lifecycle and independent re-verification behavior.

Exit gate: zero FP/FN in the declared Tier A/B matrix, no cross-class OAST
attribution, and no verified finding without reproducible proof.

## Phase 5 — End-to-end product and UI correctness

Automate the actual researcher workflows rather than only API functions:

- first boot, login, password change, update check, and tool status;
- create/edit/delete/import a target and enforce include/exclude scope;
- Quick, Standard, Deep, Custom, Guided, authenticated, and monitoring runs,
  plus explicit unsupported-state validation for network/CIDR requests;
- live scan state, logs, pause/resume/skip/cancel, reload, and restart recovery;
- findings list/detail/evidence/deduplication/export/report flows;
- custom corpus merge/deduplication/invalid-count/restore flows for every
  supported wordlist and payload category, plus bounded in-scope target bundle
  download with JavaScript chunk success/failure provenance;
- Telegram configuration, multi-chat role changes, test message, controls, and
  phase/finding alerts;
- empty/loading/error/offline/slow states, narrow screens, keyboard navigation,
  labels, focus, contrast, and destructive confirmations.

Exit gate: browser tests cover every release-critical workflow on the production
bundle, with no console error, uncaught request failure, clipped primary action,
or stale state after a successful mutation.

## Phase 6 — Performance, resource, and reliability hardening

Create small, medium, and large deterministic workloads and measure p50/p95 for
scan duration, request volume, verification latency, API latency, queue delay,
database contention, peak memory, goroutine count, browser processes, and output
growth.

Initial performance rules:

- no accepted change may regress its comparable v2.5.0 p95 wall time, request
  count, or peak RSS by more than 5% without a documented correctness reason;
- optimize the five largest measured hot paths and require a material measured
  improvement rather than an anecdotal speed claim;
- pause/skip/cancel must become observable promptly and never wait indefinitely
  for an external process;
- concurrency must remain bounded under target fan-out, Telegram fan-out,
  verification, browser work, and SQLite pressure;
- repeated scans must not leak goroutines, processes, file descriptors,
  temporary files, secrets, or unbounded database rows.

Lock absolute budgets only after Phase 0 measurements are recorded on the CI
reference runner; relative gates remain anchored to the immutable v2.5.0
baseline.

Exit gate: benchmark gates pass repeatedly and a 24-hour mixed-workload soak has
no deadlock, stuck scan, leak trend, data corruption, or notification loss.

## Phase 7 — Security, privacy, packaging, and upgrade audit

- verify outbound scope and redirect/rebinding protections for every HTTP and
  browser path;
- prove tokens, cookies, imported traffic, evidence, logs, errors, reports, and
  Telegram configuration are encrypted/redacted as designed;
- audit command execution, argument boundaries, archive/XML/JSON parsers,
  uploads, paths, permissions, and container user/capabilities;
- resolve actionable Go, npm, source, image, and secret-scan findings;
- generate an SBOM and preserve build provenance/checksums;
- test clean installation plus upgrades from each supported v2 database fixture,
  including interrupted migration and rollback-from-backup procedures;
- confirm documented environment variables, ports, volumes, health checks,
  architecture support, and offline/degraded behavior.

Exit gate: zero known exploitable high/critical dependency or product issue,
zero secret leak in the test corpus, and lossless upgrade/restore verification.

## Phase 8 — Release candidates and v3.0.0

Release sequence:

1. `v3.0.0-alpha.1` only after Phases 0-2 pass; internal/technical validation,
   not marked latest.
2. `v3.0.0-beta.1` after discovery and detector matrices pass; no new features
   after this point.
3. `v3.0.0-rc.1` after product, performance, security, and upgrade gates pass.
4. Repeat RC for every release-blocking fix; restart the relevant soak and
   regression window.
5. Publish `v3.0.0` only when an RC commit passes all gates unchanged.

Required release evidence:

- per-family Tier A/B TP/FP/FN report;
- coverage and unsupported/blocked matrix;
- functional/browser workflow report;
- race, flake, migration, Docker, security, and dependency reports;
- performance comparison against v2.5.0;
- 24-hour soak report;
- upgrade/backup/restore report;
- known-issues list, which must contain no supported correctness, security,
  data-loss, or release-blocking functional defect.

The v3 tag, GitHub release, `latest` image, and version metadata are updated only
after these artifacts exist and the final commit is unchanged from the tested
RC.

## Definition of done for one bug or detector gap

A work item is complete only when:

1. the failure is reproduced deterministically;
2. its root cause and affected paths are identified;
3. a regression test fails before the fix and passes after it;
4. adjacent positive and deceptive-negative controls still pass;
5. cancellation, timeout, scope, redaction, and concurrency behavior remain
   correct where relevant;
6. performance stays within budget;
7. user-visible errors, evidence, and documentation match actual behavior;
8. the full required CI slice passes with no flaky retry used to hide failure.

## Immediate execution order

1. Finish the Phase 0 inventory and publish the numeric v2.5.0 baseline.
2. Add the Phase 1 CI gates and prove that they can block a bad release.
3. Build the core fault matrix, beginning with scheduler/database/Telegram state.
4. Build the discovery coverage ledger and detector contract matrix.
5. Harden detectors one family at a time; never mix unrelated detector fixes in
   one change.
6. Add browser E2E, Docker fault tests, performance budgets, and soak tooling.
7. Begin prereleases only after the corresponding exit gates pass.

## Baseline snapshot — 2026-09-13

The first Phase 0 run was captured from the unchanged `v2.5.0` release commit
`b73d165`:

- `go test ./...` passed; the scanner package took `158.715s`;
- aggregate Go statement coverage is `47.0%`;
- package coverage currently includes API `24.2%`, scanner `53.1%`, scheduler
  `33.7%`, browser `32.7%`, tools `19.9%`, capture `78.3%`, database `66.1%`,
  auth `59.1%`, and secret handling `78.8%`;
- command, models, websocket, logger, and version packages currently report no
  statement coverage;
- the repository has 142 Go test files but currently has no frontend
  `*.test.*`/`*.spec.*` suite, so a successful TypeScript build is the only
  automated frontend gate;
- `go vet ./...` passed;
- the production frontend TypeScript/Vite build passed in `1.92s`; `dist` is
  approximately `496KB`, with approximately `125KB` total gzip-reported JS and
  `10KB` gzip-reported CSS;
- the scheduler exposes 42 canonical web/recon modules before its separate
  network-mode tokens, while the API router registers 114 routes;
- the current GitHub workflow builds and publishes the Docker image but does
  not run Go tests, vet, race tests, detector benchmarks, frontend tests/build,
  migrations, or production smoke tests as release prerequisites.

This is a starting measurement, not a quality claim. Coverage percentage alone
will not be optimized by testing trivial lines; the first additions target
release-critical error, state, concurrency, scope, and evidence paths.

## Current implementation checkpoint — 2026-09-14

Phases 1-5 are implemented on the hardening branch but are not considered a
v3.0.0 release until the complete local and required CI gate set passes on the
same commit:

- Phase 1: the quality workflow now gates formatting, modules, unit/coverage,
  vet, race slices, detector benchmarks, repeated migrations, npm audit,
  frontend unit/coverage/build/bundle checks, production Playwright workflows,
  release smoke, govulncheck, gosec, and Trivy. Docker publication depends on
  the quality gate and scans the locally built image before pushing it.
- Phase 2: regression coverage includes session/RBAC/isolation, same-origin and
  secure-cookie behavior, crash-safe secret rotation, migrations, target/task
  lifecycle, restart recovery, pause/resume/skip/cancel, Telegram multi-chat
  roles/audit/dedup/retry/alerts, and strict subprocess executable admission.
- Phase 3: module planning now records a durable per-phase outcome ledger and
  distinguishes `completed`, `blocked`, `failed`, `timed_out`, `skipped`, and
  `cancelled`. Missing prerequisites no longer become silent negative results.
- Phase 4: all 42 supported web modules have a checked-in prerequisite,
  completion, proof, and regression-file contract. Network/CIDR execution is
  explicitly unsupported rather than being represented by phantom tasks.
- Phase 5: repeatable production-bundle browser automation covers first boot,
  password rotation/login, multi-chat Telegram configuration, project CRUD,
  focused scanning, phase outcomes, destructive confirmation, and browser
  console/page errors. Scheduler tests cover live control state transitions.

The machine-readable authority for supported scanner coverage is
`internal/scheduler/module_contracts.go`; documentation must not advertise a
capability absent from that map. Phase 6-8 evidence, especially the 24-hour
soak, container build on both release architectures, upgrade/restore fixtures,
and unchanged-RC requirement, remains mandatory before final v3.0.0.
