# Reconner v4.6.7 — the real cause of "XSS finds nothing, even with it selected"

A deep, line-by-line audit of the entire XSS pipeline — confirmation
budgeting, the payload ladders, reflection/context detection, and the
modules that feed it parameters — found and fixed three real correctness
bugs. Unlike v4.6.5 (the chromedp race), these all bite even on a perfectly
healthy browser, and even when the operator manually selects the XSS module
on every scan.

## 1. A shared browser-proof budget silently capped confirmed findings on large scans

`dastBrowserBudget` (150) was one counter shared between two very different
kinds of work:

- the main reflected-XSS confirmation path (`proveExecutingXSS`), which only
  runs *after* a real breakout signal has already survived — a strongly
  signaled candidate, not a guess;
- the genuinely speculative DOM/SPA canary escalation, which has no prior
  signal at all (every non-reflected parameter gets a speculative browser
  navigation).

On a scan with more than ~150 already-signaled candidates — trivial on a
multi-asset target with thousands of parameters — the shared counter
exhausted the scan's *entire* browser allowance on the confirmed-signal path
alone. Every candidate after that fell back to the browserless differential
ladder, which can mark a candidate "Inconclusive" but — per this system's own
no-finding-without-proof design — can never produce a CONFIRMED finding, no
matter how real the vulnerability was.

Fixed: the main confirmation path no longer consumes or accepts a budget at
all (the single shared browser tab already serializes real navigations to
one at a time, so this only costs more wall-clock time, never more
concurrent load). The budget now exclusively bounds the two genuinely
speculative paths, and is raised from 150 to 20000 — effectively unbounded
for any real target, consistent with this release's broader "don't impose a
silent ceiling" theme (see v4.6.6).

## 2. JS-mined parameter names were discovered but never tested

Reconner's own JS analysis already mines real parameter names straight out
of `fetch`/`axios`/`JSON.stringify`/`URLSearchParams` request bodies and DOM
reads — a JSON body shaped like `{postId, body, authorDisplayName}` gets
`authorDisplayName` recorded. But nothing that populates the `parameters`
table (the only source every active detector tests from) ever read those
hints back out. A parameter name Reconner's own JS analysis had *already
identified* was therefore never tested by XSS, SQLi, SSTI, or anything else
— unless that exact name also happened to independently show up in a
crawled query string or HTML form. The hidden-parameter-mining module
(`paramfuzz.go`) inherited the identical gap, since its own wordlist read
from the same table.

Fixed: these hint names are now paired, as speculative JSON-body insertion
points, with the live JS-derived endpoints Reconner already resolves and
probes — the same best-effort name-to-endpoint pairing the hidden-parameter
miner already relies on elsewhere.

## 3. A real reflected XSS in an unquoted inline event handler could never be proven

Both the browser-proof and browserless payload ladders for event-handler
contexts (`onclick=`, `onerror=`, …) assumed the reflection sits either
inside an existing JS string or right after an open function-call
parenthesis. Neither assumption holds for a bare, fully-unquoted handler
like `<button onclick=trackClick(USERNAME)>` or `<div onclick=USERNAME>` —
injecting a leading quote there opens an unterminated string (a syntax
error) instead of closing one, so no payload in either ladder could ever
form valid, executing JavaScript for this very real, common markup pattern.
Fixed: both ladders now carry a dedicated payload for this case.

A fourth candidate issue (an edge case in how the context engine attributes
surviving breakout characters when a filter strips an injected value
entirely) was investigated and deliberately left alone — it's a genuine
ambiguity a single-response heuristic can't safely resolve without
regressing a different, legitimate detection it also handles, and the
existing independent re-verification step already prevents it from ever
producing a false CONFIRMED finding.

## Upgrade

No migration, no config changes. Rebuild/redeploy.
