# Reconner v3.0.0 Release Audit

Audit date: 2026-09-20

Release commit: populated by the protected GitHub merge and tag workflow.

## Product and UI

- The production bundle is exercised in Chromium from first login through
  target CRUD, scan creation, live phase history, Telegram multi-chat
  management, corpus merge/deduplication/restore and destructive confirmation.
- A release-specific browser audit visits every top-level page on 1440×900 and
  390×844 viewports. It rejects uncaught browser errors, page-level horizontal
  overflow, missing keyboard focus and a broken mobile navigation drawer.
- The shared v3 design system covers branding, typography, surfaces, controls,
  severity badges, responsive navigation, breadcrumbs and target operations.

## Correctness and security evidence

- Complete Go test suite and the scanner/API/scheduler race suite pass.
- Deterministic Tier A/B detector matrices enforce zero known FP and FN in the
  declared corpus; unsupported or blocked coverage remains explicit.
- Migration suites repeatedly exercise idempotence and populated legacy tables.
- Frontend unit tests, production build, bundle budget and production-browser
  tests pass without uncaught console errors.
- Dependency, source, secret and container scans reject actionable high or
  critical findings.
- The amd64 and arm64 production images are built and scanned independently on
  native runners before the verified multi-platform manifest is published.

## Operational evidence

- Skip/pause/cancel lifecycle tests cover stuck workers and task-owned Chromium
  process-group cleanup.
- Backup discovery includes nested high-signal paths such as `/back/.env` with
  deceptive-negative controls.
- Target research exports are bounded, scope-checked and include per-file
  JavaScript provenance and failure records.
- Custom wordlists and payloads are normalized, deduplicated, counted and can
  be restored per category.

## Fast-track disclosure

The repository owner requested that the final release audit and publication be
completed in one five-hour session. The automated regression, race, browser,
security, migration and native multi-architecture gates remain mandatory and
must all pass on the release commit. This fast-track audit does not claim that a
literal 24-hour pre-release soak was completed; longer-running production
monitoring continues after publication and any regression requires a patch
release.
