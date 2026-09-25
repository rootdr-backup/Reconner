# Reconner research backlog — 2026 Q3

Status: research and planning only; no product code changed and no external
target was tested.

Research window: **2026-06-25 through 2026-09-25**. The review prioritizes
primary research, standards, official project releases, and reproducible
academic work. It is not a claim that every page published on the Internet was
read. It is a high-signal survey of the sources most likely to change Reconner's
architecture, coverage, precision, or performance.

## Executive conclusions

1. Reconner already has an unusually good proof boundary: its module contracts
   distinguish discovery, candidate evidence, independent verification, and
   blocked prerequisites. That should remain the foundation.
2. The largest XSS recall gap is no longer a shortage of generic payloads. It is
   incomplete discovery of deep client states and incomplete runtime modeling
   of sources, transformations, sanitizers, Trusted Types policies, web
   messages, and new HTML insertion APIs.
3. Modern crawling is a detection feature. A September 2026 paper reports at
   least 46% more average code coverage than individual comparison scanners by
   using client-centric, state-aware interaction. Reconner should make the
   rendered state graph a first-class artifact shared by XSS, IDOR, CSRF,
   upload, OAuth, and workflow modules.
4. Identity testing needs a multi-principal object/action model. Recent BOLA
   research shows state-changing action-level failures are at least as important
   as simple object reads; UUIDs and encoded IDs do not remove the risk.
5. HTTP/3, streaming HTML APIs, OAuth browser architecture, and CRLF/desync
   research changed the relevant platform surface during this review window.
   They should be represented explicitly instead of forced through HTTP/1-only
   or classic DOM assumptions.
6. Nuclei v3.11.1 is already pinned in Reconner. The next gain is governance:
   signed-template enforcement, capability admission, provenance, quarantine,
   and local positive/negative fixtures—not another blind template expansion.
7. No honest scanner can promise zero false negatives against the open web.
   Reconner can, however, publish measurable coverage: eligible surfaces,
   attempted surfaces, blocked surfaces, candidate-to-confirmed conversion,
   fixture-family recall, negative-corpus false-positive rate, and p95 cost.

## High-signal research reviewed

### Inside the exact three-month window

- 2026-09-23 — PortSwigger, [HTTP/3 in Burp Suite](https://portswigger.net/research/http3-in-burp-suite): QUIC/HTTP/3 discovery, protocol downgrade visibility, QPACK-blocked-stream and single-datagram race primitives, and the performance implications of HTTP/3.
- 2026-09-22 update — PortSwigger, [DOM XSS workflow](https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/input-validation/xss/dom-xss) and [web-message DOM XSS](https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/input-validation/xss/web-message-dom-xss): source-to-sink canaries, surrounding context, message interception, and origin-aware replay.
- 2026-09-02 — Olsson et al., [SpiderSapien](https://arxiv.org/abs/2609.02532): immersive client-side interaction, state discovery, form solving, and substantially improved code/XSS coverage.
- 2026-08-25 — PortSwigger, [What's in a tag name? JavaScript, apparently](https://portswigger.net/research/whats-in-a-tag-name-javascript-apparently): tag names and DOM-derived attributes can become JavaScript, URLs, or markup; tag-name transforms and newer DOM APIs create contexts classic reflection scanners miss.
- 2026-08-06 — PortSwigger, [CSS: the bomb inside your inbox](https://portswigger.net/research/css-the-bomb-inside-your-inbox): CSS, sanitization boundaries, CSSOM mutation, interaction selectors, UI redress, and external-resource side effects form a separate browser-injection class.
- 2026-08-05 — PortSwigger, [CRLF-Powered Desync Attacks](https://portswigger.net/research/crlf-powered-desync-attacks): response/header injection and parser disagreement can compose into desynchronization. This is a strong argument for isolated, opt-in, non-destructive protocol candidates rather than aggressive default probes.
- 2026-08-05 — PortSwigger, [Meet the HTTP Terminator](https://portswigger.net/research/can-ai-do-novel-security-research): useful scanner design lesson—generic anomaly discovery followed by deterministic, class-specific verification.
- 2026-08 — IETF, [RFC 10017: OAuth 2.0 for Browser-Based Applications](https://datatracker.ietf.org/doc/html/rfc10017): Authorization Code + PKCE, BFF/token-mediating patterns, browser token storage, service workers, origin isolation, and the real impact of malicious JavaScript in an OAuth client.
- 2026-07-22 — Barach, [AuthProbe](https://arxiv.org/abs/2607.20574): specification-driven, multi-identity BOLA detection with owner ground truth and a hardened negative counterpart.
- 2026-06-30 through 2026-08-08 — [Nuclei releases](https://github.com/projectdiscovery/nuclei/releases): signed JavaScript/code-template gates, safer execution boundaries, pooling/retry correctness, and headless/runtime fixes in the v3.10-v3.11 line.

### Adjacent background retained because it materially affects the plan

- Kaur, [BOLA in the Wild](https://arxiv.org/abs/2605.25865): 107 classified bug-bounty disclosures; action-level object BOLA is 41.7% of confirmed cases, vertical failures are material, and GraphQL global IDs recur.
- Chrome, [Declarative partial updates](https://developer.chrome.com/docs/web-platform/declarative-partial-updates): upcoming static and streaming HTML insertion APIs, unsafe variants, `runScripts`, sanitizer options, and Trusted Types integration.
- MDN, [Trusted Types](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API), [`setHTMLUnsafe`](https://developer.mozilla.org/en-US/docs/Web/API/Element/setHTMLUnsafe), and [HTML Sanitizer API](https://developer.mozilla.org/en-US/docs/Web/API/HTML_Sanitizer_API): the current browser sink and policy surface.
- ProjectDiscovery, [Nuclei Templates April 2026](https://projectdiscovery.io/blog/nuclei-templates-april-2026): concrete lessons from SPA catch-all, weak regex, stale takeover providers, default-login, and content-signature false positives.

## XSS: present capability and the next ceiling

### What Reconner already does well

- Reflection classification covers HTML text, quoted/unquoted attributes,
  URLs, event handlers, JavaScript strings/expressions/templates, JSON, CSS,
  comments, RCDATA/RAWTEXT, and nested `srcdoc`.
- Multiple reflection contexts are preserved rather than collapsed into a
  single label.
- Chromium confirmation requires a per-attempt nonce instead of accepting a
  reflected string as execution proof.
- Cross-frame proof, `window.name`, and real `postMessage` flows exist.
- Runtime observation includes `setHTMLUnsafe`, `parseHTMLUnsafe`,
  `createContextualFragment`, `srcdoc`, dangerous `setAttribute` uses, and
  other classic DOM sinks.
- Cancellation and task-owned browser cleanup are part of the execution model.

### Highest-value XSS gaps

| Priority | Gap | Planned capability | Confirmation boundary |
|---|---|---|---|
| P0 | Deep SPA state coverage | Build a deterministic rendered-state graph from interactable elements, forms, route transitions, dialogs, shadow DOM and same-origin frames; dedupe by semantic state, not URL alone | A state is admitted only with reproducible transition provenance |
| P0 | Runtime source-to-sink graph | Instrument source reads, transforms, sanitizer/Trusted Types policy calls and sink writes; connect them with per-probe lineage | Static matches remain candidates; execution or a deterministic dangerous-sink trace is required for promotion |
| P0 | Web-message modeling | Capture listener registration, sender/source/origin constraints, structured messages, destructuring and message-driven route transitions | Replay from the correct child/opener context; never treat a string match as proof |
| P0 | Modern HTML APIs | Track static/streaming `*HTML` and `*HTMLUnsafe` variants, ShadowRoot/Document forms, sanitizer options and `runScripts` behavior behind browser-feature detection | Versioned browser fixtures; safe APIs must stay negative |
| P0 | Tag-name-derived contexts | Model `localName`, attribute collections, `part`, class/token transforms and tag-name-to-code/URL/markup flows | Local fixtures for positive and patched twins; browser nonce proof |
| P1 | Parser/normalization differential | Record sent bytes, response bytes, browser-decoded DOM, reparsed DOM and transformation chain; include Unicode/replacement and mutation cases | Cross-layer mismatch is candidate evidence; actual execution is required for XSS |
| P1 | Stored/blind lifecycle | Plant an inert nonce only in explicitly operator-selected local/authorized workflows, revisit known render locations, expire and clean test state | Attributed later execution tied to exact insertion and render provenance |
| P1 | Service worker and persistent client state | Inventory registration, scope, cache/storage interactions and persistence-relevant flows | Report architecture/risk candidates separately from confirmed XSS |
| P1 | CSS injection separation | Add a distinct CSS/browser-side-effect candidate class instead of calling every style reflection XSS | Deterministic style/UI/resource effect in the local browser; no data-exfiltration probe by default |
| P1 | Performance without recall loss | Two-stage probe: one marker pass per shape, context-family minimization, shared browser pool, state/response cache, adaptive scheduling and per-origin budgets | Same fixture-family recall, lower request/browser count and lower p95 duration |
| P2 | Framework-aware hints | Detect common rendering primitives and template/runtime boundaries as scheduling hints, never as proof | Hints only prioritize; proof rules do not change |

### XSS benchmark proposed before implementation

- Vulnerable/patched twin fixtures for every supported context family.
- Separate suites for server reflection, DOM flow, stored render, web message,
  iframe/srcdoc, shadow DOM, sanitizer/Trusted Types, tag-name-derived data,
  mutation/reparse, and CSS injection.
- A held-out transformation set so payloads cannot simply overfit checked-in
  examples.
- Required reporting: eligible points, marker attempts, escalated contexts,
  browser attempts, confirmed executions, blocked attempts, median/p95 time,
  and requests per confirmation.
- Proposed exit gate: 100% on named deterministic regression fixtures, at least
  90% macro-family recall on a held-out local corpus, zero false positives on
  deterministic patched twins, and no p95 regression above an agreed budget.
  These are release gates, not claims about the entire Internet.

## Cross-cutting architecture required first

1. **Local evaluation lab:** versioned vulnerable/patched twins for every
   module, deterministic seeds, replayable captures, and no external assets.
2. **Coverage ledger:** every module reports discovered, eligible, attempted,
   skipped-by-budget, blocked-by-prerequisite, candidate, rejected, confirmed,
   and errored counts.
3. **Shared state graph:** URL/request nodes plus browser states, actions,
   identities, objects, data provenance, and transitions.
4. **Shape-aware scheduler:** cluster equivalent request/response/content/state
   shapes, test representatives first, expand only after meaningful signal.
5. **Evidence ladder:** observation -> candidate -> independent verification ->
   confirmed finding. Severity is assigned only after impact and proof.
6. **Capability policy:** explicit opt-in and budgets for write/state-changing,
   OAST, race, browser, protocol-desync, and high-cost operations.
7. **Reproducibility bundle:** sanitized request/response pairs, identity role,
   browser trace, proof token, tool/template version, and rejection controls.

## Plan for every current Reconner module

The table maps all 43 contracts in `V3ModuleContracts`; it proposes work but
does not change the existing parallel execution model.

| Module | Main gap to close | Planned upgrade and release gate | Priority |
|---|---|---|---|
| `subdomain_enum` | Provenance quality and wildcard/parked noise | Per-source confidence, DNS history correlation, wildcard/catch-all families, stable admission reasons; local DNS fixtures with zero sibling bleed | P2 |
| `http_probe` | Protocol and virtual-host surface | HTTP/1.1, HTTP/2 and HTTP/3/Alt-Svc inventory, redirect/TLS/vhost equivalence classes, body-preserving retries; protocol twin fixtures | P0 |
| `js_analysis` | Deep dependency/runtime coverage | Source maps, module/dynamic-import/worker/service-worker graph, chunk provenance, runtime-loaded assets, minified symbol hints; bounded cyclic-graph tests | P0 |
| `js_endpoints` | Endpoint shapes lose semantics | Preserve method, content type, parameter schema, auth hints, caller and route state; OpenAPI/GraphQL/WebSocket candidates without promoting strings to live endpoints | P0 |
| `param_discovery` | Hidden and state-dependent inputs | Merge HTML, runtime network, JS call sites, specs and interaction states; retain sibling values and body schemas; coverage ledger per request shape | P0 |
| `headless_crawl` | URL-centric crawling misses interactive states | SpiderSapien-inspired semantic action/state graph, shadow DOM, dialogs, forms and same-origin frames with loop/budget control | P0 |
| `timemachine` | Archive noise and stale scope | Snapshot clustering, live-vs-archive diff, historical parameter/asset provenance and strict host admission | P2 |
| `param_reflection` | Encoded/transformed reflection | Byte/decoder/DOM normalization chain, multi-context retention and response-family controls | P0 |
| `paramfuzz` | Cost and hidden-name confidence | Schema/content-type-specific dictionaries, shape sampling, two-control differential and adaptive expansion | P1 |
| `dir_discovery` | SPA/catch-all and duplicate content | Semantic response families, redirect chains, soft-404 calibration per prefix and representative-first expansion | P1 |
| `backup_discovery` | Name/location combinatorics and weak status signals | Asset-derived stems, nested path context, archive/config/database magic signatures, compressed member manifest, duplicate-content clustering | P1 |
| `open_redirect` | Client-side and parser differences | Server and rendered navigation traces, URL parser/encoding normalization, scheme/host controls and safe external sentinel | P1 |
| `nuclei` | Template trust/staleness/FP lifecycle | Enforce signed code/JS templates, capability allowlist, pinned engine/templates, provenance/hash, quarantine until positive/negative local fixtures pass | P0 |
| `xss` | Deep states and runtime lineage | Implement the XSS plan above; nonce execution or deterministic dangerous-sink trace, never reflection-only confirmation | P0 |
| `vuln_scan` | Family aggregation hides coverage | Split per-family eligibility/attempt/proof counters and route candidates into class-specific verifiers | P1 |
| `sqli` | DB/context diversity and timing noise | Syntax/context classification, boolean/error/time consensus, randomization against cache, repeated controls, dialect hints; no single timing hit confirmation | P1 |
| `ssrf` | URL parser chains and blind attribution | Context-aware URL forms, redirect/DNS/callback attribution, allowlisted OAST, internal-address tests only in isolated local lab | P1 |
| `lfi` | Encoding/wrapper and platform coverage | Path normalization matrix, platform-specific known-file signatures, sibling negatives and response-family controls | P1 |
| `ssti` | Engine identification and false evaluation | Harmless arithmetic pair, engine family inference, encoding/context transforms and independent confirmation | P1 |
| `csti` | Framework/runtime state | Render-state and framework-expression hints, two-expression browser confirmation, DOM mutation provenance | P1 |
| `cmdi` | Timing/noise and platform assumptions | Harmless computed-marker pairs, platform context classification, repeated controls and token-attributed local OAST | P1 |
| `passive` | Duplicate banners and weak informational findings | Evidence-specific extractors, content-family dedupe, secret/schema validators and finding-vs-inventory separation | P2 |
| `takeover` | Provider behavior becomes stale | Provider capability registry with last-verified date, DNS+HTTP claimability proof, quarantine stale providers | P2 |
| `blh` | Dead does not mean reclaimable | Provider/resource-specific reclaimability state, redirect/final-host evidence and temporal recheck | P2 |
| `csrf` | Candidate-only form analysis | Browser state-change proof on local/explicit workflows, SameSite/origin/referer behavior, token binding and safe rollback | P1 |
| `cors` | Endpoint/credential nuance | Origin reflection/null/subdomain controls, credentialed readable-content proof, preflight and cache variance | P1 |
| `exposure` | Generic paths and SPA false positives | Artifact-specific parsers/magic/content schema, secret validation without disclosure, catch-all controls and duplicate clustering | P1 |
| `intel` | Correlation can inflate confidence | Typed evidence graph, source freshness, contradiction handling and transparent confidence calculation | P2 |
| `oast` | Lifecycle and attribution | Per-attempt tokens, protocol/channel metadata, expiry, late-callback reconciliation and strict target/task binding | P1 |
| `xxe` | Parser/content-type coverage | XML/SVG/SOAP multipart shapes, harmless local file marker or attributed callback, parser error/control matrix | P1 |
| `file_upload` | Workflow discovery and post-processing proof | State-aware form/API discovery, filename/content/MIME matrix, retrieval/render/processing lifecycle, cleanup and content-family controls | P1 |
| `idor` | Reads dominate; object relationships incomplete | OpenAPI/runtime object graph, two+ controlled identities, owner ground truth, read/write/action matrices, UUID/global-ID support | P0 |
| `jwt` | Token-family and acceptance context | JWS/JWE/type/issuer/audience/key-route inventory, cryptographic acceptance differentials, endpoint-specific replay controls | P0 |
| `authz` | Writes remain hypotheses | Relationship-aware read/write/action replay in explicit local/authorized workflows, rollback, vertical and horizontal matrices | P0 |
| `ato` | Discovery caps and chain composition | OAuth/OIDC/recovery/MFA/passkey/session workflow graph, RFC 10017 architecture signals, chain proof and bounded browser replay | P0 |
| `nosqli` | Backend/operator diversity | JSON/form/GraphQL shape-aware operator/type differentials, sibling controls and response-semantic comparison | P1 |
| `cache_poison` | Cache-key inference and unsafe effects | Cache-key/normalization model, clean baselines, harmless markers, two-hit confirmation, browser/CDN variance; no shared-user impact | P1 |
| `origin_ip` | Baseline equivalence and provider dependency | Multi-signal TLS/header/body/favicon equivalence, historical-IP provenance, shared-host rejection | P2 |
| `shodan` | External dependency and stale observations | Freshness/coverage metadata, deduped IP queries, conflict handling and blocked-vs-empty distinction | P2 |
| `race` | Candidate-only and protocol-blind | Action preconditions, synchronized HTTP/1.1/2/3 strategies, conflicting-state proof, rollback and strict per-action budgets | P1 |
| `smuggling` | HTTP/1 focus and operational risk | Protocol parser matrix, non-destructive anomaly ranking, isolated local desync confirmation, explicit opt-in; never poison shared connections by default | P1 |
| `verify` | Queue cap and uneven verifiers | Risk/cost-aware priority queue, independent verifier contracts, retry reason taxonomy and late-evidence reconciliation | P0 |
| `monitor` | Changes lack semantic risk context | Stable semantic diffs over surface/state/evidence graphs, suppression windows, regression verification and ownership-aware alerts | P2 |

## Recommended implementation sequence

### F0 — Measurement and local laboratory

Coverage ledger, vulnerable/patched twins, state graph schema, evidence ladder,
budgets, reproducibility bundle, and benchmark runner. This prevents later
"improvements" from being judged by payload count or lines changed.

### F1 — XSS and client-state 2026

Headless state graph, JS graph, parameter/reflection lineage, runtime taint,
web-message model, modern/streaming HTML sinks, tag-name contexts,
normalization differential, stored lifecycle, and performance scheduling.

### F2 — Identity and API behavior

IDOR, authz, ATO, JWT, CSRF, OAuth/OIDC, GraphQL global IDs, multi-identity
object/action matrices, and safe rollback for state-changing local fixtures.

### F3 — Server-side injection and processing

SQLi, NoSQLi, SSTI/CSTI, command injection, LFI, SSRF, XXE, OAST, file upload,
backup/config exposure, and class-specific confirmation.

### F4 — Protocol, cache, and concurrency

HTTP/3 inventory, protocol-aware race testing, cache-key modeling, CRLF/header
injection candidates, and isolated smuggling verification with explicit opt-in.

### F5 — Recon signal and template governance

Subdomains, probing, archive/intel correlation, directory/exposure dedupe,
takeover/BLH provider freshness, Nuclei admission/quarantine, monitoring, and
report-quality output.

## Decision packages

The work can be approved as independent packages, but **F0 should precede any
claim about percentage improvement**:

- **Package A — XSS 2026:** F0 + F1.
- **Package B — Identity/API:** F0 + F2.
- **Package C — Injection/processing:** F0 + F3.
- **Package D — HTTP/3/protocol:** F0 + F4.
- **Package E — Recon/Nuclei quality:** F0 + F5.
- **Package Full:** F0, then F1 -> F2 -> F3 -> F4 -> F5, each behind its own
  benchmark and release gate.

Recommended first choice: **Package A**, because it improves the shared crawler,
JavaScript graph and parameter inventory that several later packages depend on.
The safest engineering choice is to land F0 as a separate release-gated change
before changing detector behavior.
