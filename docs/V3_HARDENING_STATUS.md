# Reconner v3 Hardening Status

This document records implementation progress without declaring a stable v3
release. `VERSION` remains `2.5.0`; no v3 tag is valid until Phases 6–8 of the
[release plan](V3_STABILITY_RELEASE_PLAN.md) pass on the final unchanged commit.

## Completed in the current hardening change set

- Skip Phase now links scheduler cancellation to every Chromium CDP operation,
  terminates only the active task's isolated browser process group, bounds
  allocator/profile cleanup and force-releases scheduler ownership after a short
  grace without removing parallel phase execution.
- DOM-XSS verification has a surface-scaled hard ceiling in addition to short
  per-operation deadlines. Regression tests cover owner isolation, process
  termination, phase cancellation and scheduler release for a stuck worker.
- Backup/config discovery covers nested high-signal locations including
  `/back/.env`. Short real environment files are admitted by content structure,
  while generic text, fake archives and HTML/soft-404 responses remain rejected.
- Administrators can manage custom wordlists and proof-safe payload templates
  for all applicable scanner families—including DNS/vhost/content/backup,
  exposure/GraphQL/API-spec paths, JWT secrets and injection engines. Imports
  are normalized and deduplicated, report added/duplicate/invalid totals,
  persist separately from defaults and support per-category restore.
- Target pages expose a ZIP research bundle containing structured scan records,
  task/phase history, storage-contained screenshots and bounded, scope-checked
  JavaScript/chunk snapshots with per-file provenance and errors.
- The v3 visual system now uses one reusable Reconner brand mark and a compact
  target control deck that consolidates status, automation, scan controls,
  exports and high-value metrics instead of scattering them across cards.

## Still required before any v3 tag

- full performance comparison against the immutable v2.5.0 baseline;
- repeated leak/resource measurements and the 24-hour mixed-workload soak;
- production-image upgrade, interrupted-migration, backup, restore and rollback
  evidence for every supported v2 database path;
- final dependency/container/security evidence on both amd64 and arm64;
- an unchanged release-candidate commit passing every required gate.

Until those artifacts exist, a green pull request means **hardening candidate**,
not `v3.0.0` stable.
