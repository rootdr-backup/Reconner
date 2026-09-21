# Reconner v3.2 XSS quality evidence

Release candidate: v3.2.0.

This document reports bounded local evidence, not a universal internet-wide
detection percentage. Validation used only loopback `httptest` fixtures created
inside the repository and a local headless Chromium process.

## Design basis

Payload choice follows the exact reflection location and transformation, in line
with [PortSwigger's XSS context model](https://portswigger.net/web-security/cross-site-scripting/contexts).
RCDATA, RAWTEXT, script data, attribute values and nested documents are kept
distinct according to the
[HTML Living Standard parser states](https://html.spec.whatwg.org/multipage/parsing.html).
Runtime instrumentation covers direct HTML injection APIs catalogued by the
[Trusted Types API](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API),
but an API call remains routing evidence until the nonce executes.

The corpus is capability-based rather than count-based. A vector stays when it
covers a distinct parser constraint, tag/attribute semantic or transformation.
Redundant templates are deduplicated before navigation. Execution payloads set a
random title nonce and post the same nonce across frame boundaries; they do not
read cookies, storage or application data and perform no exfiltration.

## Positive matrix

The required Chromium suite covers 19 named contexts:

- HTML text;
- double-, single- and unquoted attributes;
- single- and double-quoted JavaScript inside event-handler attributes;
- `textarea` and `title` RCDATA;
- `xmp`, `noembed` and `iframe` RAWTEXT;
- nested `iframe[srcdoc]`;
- style RAWTEXT and HTML comments;
- single-, double- and template-literal JavaScript strings;
- JavaScript expressions;
- a scriptable URL attribute.

Observed result on the release workstation: **19/19 (100%)**. This percentage
describes only this named matrix.

## Negative matrix

The browser precision suite requires all five controls to remain non-executing:

- HTML-entity encoded text;
- encoded quoted attributes;
- raw markup under `script-src 'none'` CSP;
- reflected JSON with `nosniff`;
- a client-side `textContent` assignment.

Observed result: **5/5 negative controls produced no nonce execution**.

## Transformation and semantics matrix

Deterministic tests cover ordinary, URL, compound URL, event and `srcdoc`
attributes across quote states. URL-scheme capability is decided from both the
tag and attribute. Encoding mutations cover raw bytes, HTML entities, percent
encoding, double percent encoding and JavaScript hex/Unicode escapes.

The analyzer retains all distinct context signatures and orders executable
locations first. Equivalent copies share one browser payload ladder. Seed fuzzing
exercises malformed markup, repeated unfinished tags, comments, script strings
and nested documents and asserts bounded, internally consistent results.

## Performance evidence

The v3.1 path escalated any canary visible in the rendered DOM. A safe
`textContent` fixture therefore paid for the entire unknown-context payload
ladder and took 36.53 seconds locally. v3.2 preserves that reflection for
inventory but sees no dangerous runtime sink and stops after the 0.87-second
canary navigation, a **97.6% reduction for this safe route**.

Positive sink paths retain full coverage and early-exit on nonce proof. The
expanded 19-context matrix completed in 10.29 seconds on the release workstation;
event-handler fixtures intentionally exercise fallback syntax and account for
most of that duration. These timings are environment-specific and are regression
evidence, not a performance promise for arbitrary applications.

## Reproduction

```bash
go test ./internal/scanner -run 'Test(XSSV32|AnalyzeReflections|RawTextAndSrcdoc|JSQuoteEscaping)' -count=1

RECONNER_BROWSER_TEST=1 RECONNER_CHROME=/path/to/chromium \
  go test ./internal/scanner \
  -run '^(TestBrowserXSSConfirmLive|TestBrowserXSSContextCoverageLive|TestBrowserXSSNegativeCoverageLive|TestBrowserDOMSourceModesLive)$' \
  -count=1 -timeout=10m -v
```

The release still requires the repository's complete formatting, module, unit,
race, deterministic detector, migration, frontend, security, amd64 and arm64
container gates on the same commit.
