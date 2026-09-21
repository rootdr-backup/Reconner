# Reconner v3.1.0

This release concentrates on three detector-quality paths: earlier backup
discovery, faster browser-proven XSS, and stricter/faster SQLi timing evidence.

## Backup finder

- Schedules nested and observed-directory candidates before the large generic
  cross-product, placing `/back/.env` in the first candidate batch.
- Preserves the complete prior candidate set through stable deduplication.
- Uses a bounded 256 KiB Range probe and accepts correct 206 responses.
- Reads full size from `Content-Range` without draining huge chunked backups.
- Proves default `/back/.env` generation, classification and persistence locally.

## XSS

- Replaces the fixed per-navigation sleep with adaptive proof polling.
- Returns synchronous proof immediately and exercises nonce-bearing controls
  repeatedly while waiting for SPA hydration.
- Keeps real-Chromium nonce execution as the finding boundary.
- Makes missing Chromium fail the required browser CI gate instead of skipping.
- Passes the named local matrix 13/13; the warmed matrix took 1.19 seconds versus
  a former 3.25-second fixed-sleep floor on the release environment.

## SQL injection

- Requires a two-thirds sample quorum for timing distributions.
- Rejects impossible TTFB values when request-write trace state is missing.
- Reuses the delayed screening sample, saving one five-second request per
  confirmed timing vector without weakening linear-scaling proof.

Detailed scope, limits, evidence and primary references are in
[Scanner quality evidence](QUALITY_EVIDENCE_REVIEW.md).
