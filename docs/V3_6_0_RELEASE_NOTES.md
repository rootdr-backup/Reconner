# Reconner v3.6.0

This release closes a set of root-cause false-negative/false-positive gaps
found during a full audit of the verification layer, substantially widens
reflected-XSS coverage across every stage of the pipeline, hardens the
backup/secret-file discovery module, upgrades the JWT and LFI detectors with
real-world bypass techniques, and removes an operator-facing wordlist ceiling
that was too small for large real wordlists.

## Verification-layer false-negative fix (cross-cutting)

- `looksLikeBlockPage` — the shared WAF/edge block-page gate used by nearly
  every detector (XSS, SQLi, SSRF, SSTI, XXE, NoSQLi, cache poisoning) —
  previously matched generic words ("forbidden", "captcha", "waf", "security
  policy") on their own. A genuine application 401/403/429/503 error page
  that happened to use one of those words was mistaken for a
  security-intermediary block and its signal was silently discarded. It now
  shares `waf.go`'s vendor-specific signature list (a Cloudflare Ray ID, a
  ModSecurity/Sucuri/Incapsula banner, a bot-challenge script), which is what
  actually distinguishes a WAF/edge block from the application's own
  response.
- A WAF block on the XSS-shaped probe no longer silently forecloses SQLi
  differential testing on the same insertion point — many WAFs pattern-match
  on `<script>`-shaped input but not on a lone quote, so the two checks are
  now independent.
- Consolidated a duplicated confidence-threshold reimplementation in the
  final verification pass onto the single shared `classify.go` helper, so
  the two can no longer silently drift apart.

## Multi-tenant isolation fix

- The WebSocket hub broadcast every live event — new findings with their
  URL/parameter/evidence, task/scan progress, logs, target updates — to every
  connected authenticated client with no per-user or per-target filtering,
  even though the REST API already enforces strict per-user target
  ownership. Any authenticated non-admin member could watch every other
  user's live scan activity and finding details over `/ws`. Broadcasts are
  now scoped to the target's owner (or an admin); a handful of scheduler
  broadcast call sites were missing `target_id` entirely and needed it added
  so the filter has something to key on.

## Reflected XSS: detection, reflection, payloads, and bypasses

- **Reflection detection**: `checkParamReflection` stripped `<script>`/
  `<style>` blocks before checking whether the canary was reflected, so a
  reflection landing only inside a script block — the JS-string/JS-expression
  context Reconner's own context analyzer is built to prove executable —
  never set `parameters.is_reflected`, making it invisible to the final
  catch-all reflected-XSS pass.
- **Primary (browser-available) proof ladder** roughly doubled per context
  with vectors provable through the existing (and newly extended) generic
  event dispatcher: mXSS (`<noscript><p title="</noscript>...">`, exploiting
  the browser's own re-parsing behavior rather than a string trick),
  `formaction=javascript:` (a real filter-bypass technique that needed the
  proof engine itself extended to click it), rare tags/handlers for
  allowlist bypass (`<style onload>`, `<marquee onstart>`,
  `<select>`/`<keygen>` autofocus, `onfocusin` on unknown tags,
  `<object data=javascript:>`), and a `javascript:` scheme variant with an
  embedded tab (the URL spec strips ASCII tab/newline before scheme-checking,
  defeating a literal-string filter).
- **Browserless fallback ladder** widened with the same mXSS vector plus
  filter-evasion obfuscation of the executing JavaScript body itself
  (`String.fromCharCode(...)`, bracket-string-concat without backticks,
  `Function()`/`setTimeout(string)`), for filters that block the literal
  substring `alert(`.
- **HTML breakout correctness fix**: when a reflection lands in a tag-NAME
  position rather than a real attribute value, an invented/unknown element is
  not reliably focusable, so the previous `autofocus`/`onfocus` vector could
  silently never fire there. The close-then-fresh-element vectors are now
  tried first in that case.
- Every new payload ships with a proof-safety test extending the existing
  non-exfiltration invariant (which previously covered only the flat,
  context-less fallback list) across every context this pipeline can
  produce.

## JWT: real-world bypass classes

Added the three most consequential JWT bug classes that were previously
uncovered, all proof-gated through the same live-replay-against-a-protected-
endpoint mechanism already used for `alg=none`:

- **RS256→HS256 algorithm confusion** — forges the real token as HS256,
  HMAC-signed with the server's own asymmetric public key bytes (recovered
  from the token's own `x5c` header or the target's discovered JWKS).
- **`kid` header injection** — a path-traversal `kid` redirects a
  filesystem-backed key lookup to a predictable empty file; a
  SQL-injection-shaped `kid` redirects a database-backed lookup to an
  attacker-chosen literal.
- **Embedded `jwk` header injection** — signs with a throwaway key generated
  for the one check and hands the server the matching public key in the
  token's own header.

## LFI: modernized bypass coverage

- **Log poisoning**: plants a harmless, uniquely-marked PHP echo in the
  target's own access log via one ordinary request's `User-Agent` header,
  then tries including common log paths — proof of LFI-to-RCE without
  writing, deleting, or altering anything the app doesn't already log.
- Alternate read-encoding wrappers (`php://filter/string.rot13`,
  `convert.quoted-printable-encode`) for WAFs that specifically block the
  literal string "base64".
- Double/percent-encoded traversal and semicolon path-segment normalization
  bypasses.

## SSRF: redirect-chain bypass

- `redirectChainPayloads` turns each of the target's own **confirmed**
  (`verified=1`) open redirects into an SSRF payload: the initial URL sits on
  the target's own trusted domain, so an allowlist that only validates the
  first hostname passes it, and the target's own redirect sends the
  server-side fetch on to the metadata IP — the classic redirect-chain SSRF
  bypass. Built only from redirects Reconner has already verified land
  off-origin; it never invents or probes an arbitrary internal address on
  its own.
- Adds a trailing-dot FQDN bypass, an alternate IPv6 hex-group encoding of
  the AWS/Azure/GCP metadata address, and Alibaba's metadata IP in decimal
  form.

## Mutation XSS and DOM Clobbering

- Adds the `<noscript>`-based mXSS vector to the payload ladder (see above).
- New static detector, `analyzeDOMClobbering`: flags JS that reads a
  lookup-by-name DOM property (`document.getElementById`/`forms`/`all` +
  `value`/`href`/`src`/`textContent`) directly into a dangerous HTML-injection
  sink with no validation that the result is the element the app expects.
  Each hit carries a concrete, technically-correct PoC gadget — the exact
  native string-returning element for the property actually read, not a
  generic guess. Static lead only, never auto-confirmed without browser
  proof, matching every other flow in the DOM-XSS analyzer.

## Backup / secret-file discovery

- **No WAF awareness**: unlike every injection detector, this module never
  checked for a WAF/edge block page. A non-HTML (JSON/plain-text) challenge
  answering a backup-shaped request (`.sql`/`.zip`/`.env`) could reach the
  loose per-type credibility bar and be misreported as a confirmed backup.
- **Structural false negative on an entire class of leaked secrets**:
  `/secrets.json`, `/credentials.json`, `/serviceaccount.json`,
  `/kubeconfig`, `/id_rsa`, `/secrets.yml` and more were already requested
  by the built-in wordlist, but their file-type classification
  (`json`/`yaml`/`unknown`) had no matching case in the credibility check —
  these responses could never become a finding regardless of what they
  actually contained. Fixed by validating body content against the shared
  vendor-specific secret corpus (high/critical severity only) before the
  extension switch: credible regardless of extension when the content is
  genuinely credential-shaped, while an ordinary JSON/YAML response at the
  same paths is still rejected.
- **Soft-404 baseline/candidate Range-header mismatch**: real backup
  candidate requests send `Range: bytes=0-262143`, but the soft-404 baseline
  probe sent no Range header at all. On any server that honors Range (nginx,
  Apache, most CDNs), the baseline was captured at status 200 while
  candidates come back 206 — and the soft-404 matcher short-circuits on any
  status mismatch, silently disabling the entire catch-all/soft-404
  rejection on exactly the servers content discovery runs against most
  often. The baseline now uses the same Range header as its candidates.
- Adds the Java KeyStore magic signature (`0xFEEDFEED`); `/keystore.jks` was
  already requested but could never be confirmed.

## Operator wordlists: 2 MiB → 500 MiB

An operator's own wordlist (subdomain permutations, directory lists, custom
payloads) can legitimately run into the hundreds of megabytes. Three
independent limits gated this end to end, and raising only the headline byte
cap would not have been enough on its own:

- The request-body ceiling in **System & updates → Wordlists & payloads**
  is raised from 2 MiB to 500 MiB.
- The server's global read/write timeouts (sized for ordinary API calls)
  would have aborted a genuinely large upload before it finished
  transferring; this endpoint now extends its own deadline instead of
  weakening the timeout for every other endpoint.
- A separate 20,000-entry cap on the merge itself — independent of byte
  size — is raised to 5,000,000; a real large-scale wordlist commonly runs
  into the millions of lines.

## Scope and local validation

Every fix in this release ships with a regression test, including negative
controls proving the existing false-positive guards still hold. All
validation traffic stayed on local `httptest` fixtures (Go) and local
`vitest`/`jsdom` fixtures (frontend); no third-party or production target
was contacted. `go build`, `go vet`, `gofmt`, the full `go test ./...`
suite, and `go test -race` on the scanner/api/websocket/scheduler packages
all pass, alongside the frontend's `tsc`, `vite build`, and `vitest` suites.

As with every release, passing the deterministic local fixture matrix is a
regression contract, not a claim of zero false positives or false negatives
against an arbitrary open-web target.
