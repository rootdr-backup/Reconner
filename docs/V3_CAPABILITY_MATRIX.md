# Reconner v3 Supported Capability Matrix

This matrix freezes the v3 web-scanning surface. The executable authority is
`internal/scheduler/module_contracts.go`; its regression test requires exactly
one complete contract and an existing proof suite for every entry in
`scheduler.AllModules`.

A completed phase means its eligible inputs were attempted. It does not mean
the target is clean when prerequisites were missing. Those cases must be
reported as `blocked`, `unsupported`, `failed`, `timed_out`, `skipped`, or
`cancelled` in the durable phase ledger.

| Module | Class | Minimum prerequisite | Positive-proof contract |
|---|---|---|---|
| `subdomain_enum` | Discovery | Valid web domain | Admitted name with DNS/source provenance |
| `http_probe` | Discovery | Seeded web host | Status, TLS, response, and vhost metadata |
| `js_analysis` | Discovery | Live HTTP service | Content-derived observation tied to source asset |
| `js_endpoints` | Discovery | JavaScript asset | Normalized in-scope endpoint tied to source asset |
| `param_discovery` | Discovery | Live/crawled surface | Method, location, content type, and sibling values |
| `headless_crawl` | Discovery | Chromium and HTML seed | Rendered link/form provenance |
| `timemachine` | Discovery | Archive service and valid domain | Strict-hostname archived URL provenance |
| `param_reflection` | Discovery | Parameter inventory | MIME-aware reflected marker |
| `paramfuzz` | Discovery | Stable live endpoint | Repeatable controlled differential |
| `dir_discovery` | Detector | Live HTTP service | Soft-404/content-family differential |
| `backup_discovery` | Detector | Live HTTP service | File-type signature beyond status or length |
| `open_redirect` | Detector | Routable insertion point | External destination plus encoded/sibling controls |
| `nuclei` | Detector | Nuclei binary and live target | Parsed template evidence with noise guards |
| `xss` | Detector | HTML-capable insertion surface | Browser execution with independent marker |
| `vuln_scan` | Detector | Live/parameter surface | Family-specific proof or explicit candidate state |
| `sqli` | Detector | Routable insertion point | Multi-signal boolean/error/timing proof |
| `ssrf` | Detector | Insertion point; callback for blind proof | Controlled response or token-attributed callback |
| `lfi` | Detector | Routable insertion point | Known-file signature plus sibling replay |
| `ssti` | Detector | Routable insertion point | Two independent server-evaluated expressions |
| `csti` | Detector | Chromium and reflected HTML | Two independent client-rendered expressions |
| `cmdi` | Detector | Routable insertion point | Computed marker replay or token-attributed callback |
| `passive` | Detector | Fetchable live response | Response/header signature with host deduplication |
| `takeover` | Detector | Known subdomain DNS state | Provider-specific dangling-resource fingerprint |
| `blh` | Detector | Discovered HTML page | Dead external link plus reclaimability evidence |
| `csrf` | Detector | Authenticated state-changing form | Candidate until browser/side-effect proof exists |
| `cors` | Detector | Live HTTP service | Credentialed-origin differential and body replay |
| `exposure` | Detector | Live HTTP service | Artifact-specific content signature |
| `intel` | Detector | Persisted discovery observations | Stable multi-source correlation evidence |
| `oast` | Detector | Public callback URL and insertion point | Callback attributed to exact probe token |
| `xxe` | Detector | XML request or callback | Controlled marker or token-attributed callback |
| `idor` | Detector | Owner and attacker identities | Same-object owner/unauthenticated/attacker matrix |
| `jwt` | Detector | Captured JWT | Cryptographic acceptance differential |
| `authz` | Detector | Two identities and owned-object traffic | Relationship-aware cross-identity replay matrix |
| `ato` | Detector | Authentication/recovery surface | Chain-specific proof; weak signals stay candidates |
| `nosqli` | Detector | Structured insertion point | Operator/type differential with sibling controls |
| `cache_poison` | Detector | Cacheable live service | Clean baseline plus two stable poisoned hits |
| `origin_ip` | Detector | SecurityTrails key and fetchable baseline | Matching body fingerprint, or title plus size band |
| `shodan` | Discovery | Shodan key and resolved target IP | Provider response provenance per unique IP |
| `race` | Detector | Race-prone state-changing request | Multiple successes and conflicting outcomes; candidate |
| `smuggling` | Detector | Explicit opt-in live service | Reproducible framing delay over fast controls; candidate |
| `verify` | Postprocess | Pending verifiable candidate | Independent class-specific verifier result |
| `monitor` | Monitor | Live or previous snapshot | Stable repeated diff against persisted baseline |

## Supported target and request boundaries

- New execution supports web domains, web hosts, full HTTP(S) URLs, and
  JavaScript URL seeds admitted by the target scope rules.
- Query, path, form, JSON, XML, headers, cookies, browser, authenticated replay,
  and OAST are supported only by the modules whose prerequisite contract
  declares that surface. A selected module with no eligible shape must expose
  that fact rather than manufacture a negative result.
- Authorization detectors require correctly bound, distinct identities. With
  fewer than two identities, IDOR/authz phases are excluded or blocked.
- Provider-backed phases require their configured credential and distinguish an
  empty provider result from a provider/request failure.
- External-tool phases must report missing or failed tools. The runtime
  inventory is pinned and contains only tools called by supported web paths.

## Explicitly unsupported in v3.0.0 stability scope

Network/CIDR scanning, service/port discovery, network credential testing, and
camera/DVR discovery have no executor in this source tree. New network or mixed
targets and all legacy network module tokens are rejected before task creation
by the web API, scheduler, and Telegram management bot. Existing legacy rows
remain readable/exportable so upgrades do not destroy user data.

This boundary is intentional release truth, not a permanent product decision.
Those capabilities may return only after they have a real executor, phase
ledger semantics, proof contracts, negative controls, packaging, cancellation,
and end-to-end tests.
