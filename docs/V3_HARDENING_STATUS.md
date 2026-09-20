# Reconner v3 Hardening Status

This document records the hardening scope promoted into the v3.0.0 release
candidate. `VERSION` is now `3.0.0`; publication remains blocked until every
required GitHub quality and native multi-architecture image gate passes on the
final unchanged commit. See the [release audit](V3_RELEASE_AUDIT.md).

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

## Release evidence and continuing validation

- deterministic correctness, race, migration, production-browser, dependency,
  secret and container gates are enforced in CI;
- amd64 and arm64 images must both pass before the manifest is published;
- the owner-requested five-hour fast track is disclosed in the release audit
  and does not misrepresent itself as a completed 24-hour pre-release soak;
- extended production monitoring continues after publication and any observed
  regression is handled as a patch release.
