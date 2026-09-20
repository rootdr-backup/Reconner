# Reconner v3.0.3

This patch upgrades XSS coverage and makes the payload import contract
understandable and recoverable.

- Browser proof now works inside cross-origin frames through a nonce-scoped
  `postMessage` channel; it no longer depends on forbidden `top.document` access.
- Context ladders now include additional raw-text breakouts (`noscript`, `xmp`,
  `noembed`, and `iframe`), `srcdoc`, and media error-event variants.
- Runtime DOM tracing covers modern `setHTMLUnsafe()` and
  `Document.parseHTMLUnsafe()` injection sinks alongside the classic sinks.
- A real-Chromium release gate proves execution across 13 HTML, attribute,
  RCDATA/raw-text, CSS, comment, JavaScript, template-literal, expression, and
  URL contexts. v3.0.3 passes 13/13 (100%) on this named fixture matrix; this is
  a reproducible regression metric, not a claim that every application is 100%
  detectable.
- The safe-reflection fixture remains a mandatory false-positive gate.

- The XSS corpus editor now explains why browser-proof templates require one
  `%s` nonce placeholder and `top.document.title`.
- Three valid templates are visible and can be loaded into the editor with one
  click.
- A live preflight count identifies incompatible lines before submission.
- When an import contains invalid XSS templates, rejected lines stay in the
  editor for correction and a detailed explanation replaces the ambiguous
  invalid counter.
- Plain alert/reflection payloads remain rejected intentionally so custom
  corpora cannot weaken Reconner's execution-proof false-positive controls.
