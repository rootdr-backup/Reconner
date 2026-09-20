# Reconner v3.0.3

This patch makes the XSS payload import contract understandable and recoverable.

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
