# Reconner v3.4 Supported Capability Matrix

This matrix describes the shipped v3.4 web and explicit network execution
surfaces. The web-module authority is
`internal/scheduler/module_contracts.go`; its regression test requires exactly
one complete contract and an existing proof suite for every entry in
`scheduler.AllModules`. Network modules are admitted through a separate,
asset-gated plan so they cannot be mixed accidentally with web modules.

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
| `headless_crawl` | Discovery | Chromium and HTML seed | Persisted rendered-state graph with link/form, shadow-root, same-origin-frame and safe interaction provenance |
| `timemachine` | Discovery | Archive service and valid domain | Strict-hostname archived URL provenance |
| `param_reflection` | Discovery | Parameter inventory | MIME-aware reflected marker |
| `paramfuzz` | Discovery | Stable live endpoint | Repeatable controlled differential |
| `dir_discovery` | Detector | Live HTTP service | Soft-404/content-family differential; high-sensitive panels require product, credential-form, redirect, or authorization evidence and are content-grouped |
| `backup_discovery` | Detector | Live HTTP service | Archive/SQL signature or sensitive config-content schema beyond status/path |
| `open_redirect` | Detector | Routable insertion point | External destination plus encoded/sibling controls |
| `nuclei` | Detector | Nuclei binary and live target | Parsed template evidence with noise guards |
| `xss` | Detector | HTML-capable insertion surface | Source-to-sink runtime trace followed by browser execution with an independent marker |
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
| `file_upload` | Detector | Scoped multipart or file-like structured insertion point | Retrieved execution marker, Chromium proof, traversed-member retrieval, or token-attributed processing callback |
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

## Explicit network pipeline

Network profile names are planning tokens, not executable phases. Each profile
always includes `network`; Normal and Deep add only the compatible validation
modules described below.

| Module | Class | Minimum prerequisite | Positive-proof contract |
|---|---|---|---|
| `network` | Discovery | Admitted single IP, CIDR, or inclusive IP range | Verified TCP connectivity plus persisted host/port/service/banner evidence; bounded OS evidence when capabilities permit |
| `network_nuclei_only` | Detector | Verified open network services and Nuclei binary | Parsed network/TCP template evidence with the same severity, exclusion, and noise gates as web Nuclei intake |
| `network_initial_access` | Detector | Discovered HTTP service returning a stable 401/403 control | Two stable denied controls followed by two materially different, identical successful replays |
| `network_brute` | Detector | Real HTTP Basic challenge and explicit operator selection | Paced credential attempt with two identical success replays; lockout/rate-limit response aborts the audit |

## Supported target and request boundaries

- New execution supports web domains, web hosts, full HTTP(S) URLs, JavaScript
  URL seeds, single IPs, CIDRs, and bounded inclusive IP ranges admitted by the
  target scope rules.
- Query, path, form, JSON, XML, headers, cookies, browser, authenticated replay,
  and OAST are supported only by the modules whose prerequisite contract
  declares that surface. A selected module with no eligible shape must expose
  that fact rather than manufacture a negative result.
- Authorization detectors require correctly bound, distinct identities. With
  fewer than two identities, IDOR/authz phases are excluded or blocked.
- Provider-backed phases require their configured credential and distinguish an
  empty provider result from a provider/request failure.
- External-tool phases must report missing or failed tools. The runtime
  inventory is pinned and contains only tools called by supported web or
  explicit network paths.
- Operator corpora extend, but never replace, compiled defaults. Normalization,
  deduplication and category-specific proof-template validation happen before a
  custom entry becomes eligible for scanner use.
- Target artifact export may fetch only URLs admitted by the target request
  identity. Every redirect hop is scope-checked and failed assets remain visible
  in the bundle manifest.

## Network boundaries and retired tokens

- Network execution is never implied by a web profile. A compatible asset and
  explicit Network Fast, Normal, or Deep selection are both required.
- Recognized CDN/WAF edges and configured IP/CIDR exclusions are removed before
  probing. ICMP is evidence only and never a liveness gate.
- `network_backup`, `network_ingram`, `network_devices`, and their legacy alias
  tokens remain rejected because they have no v3.4 executor or proof contract.
  Existing historical rows remain readable/exportable so upgrades do not
  destroy user data.
- There is no separate camera/DVR credential or device-takeover executor.
  Service fingerprints may still appear as network discovery evidence, but
  discovery is not promoted into a vulnerability by product name alone.
