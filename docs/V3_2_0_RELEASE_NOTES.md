# Reconner v3.2.0

This release is a focused XSS engine upgrade. It changes neither the permission
model nor the verification boundary: a reflected string, parser heuristic or
static source-to-sink lead is still not a finding. Reconner promotes XSS only
after a fresh random nonce executes in headless Chromium.

## Multi-context reflected XSS

- Retains every distinct reflection context for a parameter and builds one
  bounded, deduplicated browser ladder across them. A safe title reflection can
  no longer hide a separate attribute or JavaScript sink.
- Separates HTML tokenizer states for RCDATA and RAWTEXT, including exact closing
  elements for `title`, `textarea`, `xmp`, `noembed`, `noframes` and `iframe`.
- Adds nested-document handling for `iframe[srcdoc]`, including HTML entities
  decoded during the outer parse before the inner document is parsed.
- Routes URL payloads by tag and attribute semantics. For example, `a[href]` and
  `iframe[src]` are not treated like `link[href]`, `img[src]` or `script[src]`.

## Transformation-aware JavaScript

- Distinguishes HTML entities, URL encoding, double percent encoding and
  JavaScript escapes rather than treating all encoded bytes as browser-decoded.
- Recognizes quote-only JavaScript escaping as unsafe only when an attacker
  backslash also survives, then verifies the appropriate double-escape vector in
  Chromium.
- Keeps mixed encoding decisions character-specific, so an irrelevant encoded
  byte cannot suppress a valid breakout or promote an inert reflection.

## Browser coverage and speed

- Expands context-aware ladders with independent, non-exfiltrating execution
  families while preserving early exit on the first nonce proof.
- Plain client-side `textContent` remains visible to parameter inventory but no
  longer triggers a complete XSS payload ladder. On the local release fixture,
  that safe route fell from 36.53 seconds to 0.87 seconds while real HTML sink
  routes remained covered.
- Runtime `setAttribute` tracing now records only event, nested-document and
  scriptable URL attributes instead of every harmless data attribute.
- Parsing APIs that are inert until their result is inserted no longer trigger
  browser escalation on their own; the later live insertion sink is traced.

## Local release evidence

- Positive real-Chromium matrix: **19/19** contexts executed the nonce proof.
- Negative real-Chromium matrix: **5/5** controls remained non-executing.
- DOM source matrix still passes query, hash, hash parameters, path,
  `window.name`, `postMessage`, cross-frame `srcdoc` and script resources.
- Attribute semantics, tokenizer states, encoding transformations and parser
  seeds have deterministic unit and fuzz-seed coverage.

No third-party host was tested while developing or validating this release. All
HTTP traffic was directed to Go `httptest` servers on loopback and the local
Chromium instance.

Detailed methodology and limitations are recorded in
[v3.2 XSS quality evidence](V3_2_XSS_QUALITY_EVIDENCE.md).
