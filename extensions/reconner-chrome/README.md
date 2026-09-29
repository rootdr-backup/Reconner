# Reconner Guided Capture (Chrome MV3)

This unpacked DevTools extension passively records request/response pairs that
match an explicit hostname or URL-prefix scope. It exports
`reconner-capture/v1` JSON for the Reconner **Guided Analyze** importer.

As of v0.2 it also runs a **local, passive triage pass** over the traffic it
captures, so obvious cross-identity access-control candidates surface live in
the panel instead of only after import.

## Install and use

1. Open `chrome://extensions`, enable Developer mode, and choose **Load unpacked**.
2. Select this directory.
3. Open DevTools on the target tab and select the **Reconner** panel.
4. Enter one or more authorized target hostnames/URL prefixes and an identity
   label, then start capture and browse the application normally.
5. Stop and export the JSON file. Import it from Reconner's Guided Analyze page.

The collector requires DevTools to remain open. It does not attach the debugger,
modify traffic, replay requests, or contact Reconner/targets on its own. Request
and response bodies larger than 2 MiB are omitted (and, since v0.2, are never
even fetched from DevTools once it reports a larger declared size — nothing
about what gets stored changed, it just gets there faster). The exported file
can contain cookies, tokens and private response data; handle it as a
credential file and delete it after encrypted import.

## Cross-identity IDOR / BAC triage (new in v0.2)

The panel now ships a small triage engine (`lib/analyze.js`, unit-tested under
`test/`) that watches the traffic you're already capturing and flags
candidates worth verifying — **entirely from history, with zero replay**:
everything it flags is something the *tester's own two browsing sessions*
already produced.

It runs in two modes, matching how you already work:

- **Automatic** — the moment traffic from a second, different *Identity
  label* shows up (switch the field above when you switch logged-in user and
  keep capturing), the engine starts comparing requests across identities.
- **Configured** — add role tiers to identities and/or sensitive-path
  patterns in the panel's collapsible sections, and two extra checks turn
  on. Nothing needs configuring for the automatic checks to work.

### What it flags

| Category | Trigger | Needs config? |
| --- | --- | --- |
| **Cross-identity object access** (`object_idor`) | Two different identities both got a success-looking response for the *exact same* concrete object (same id in the path, a query param, or a JSON response field — see the built-in id-parameter list, extendable in the panel) | No — automatic once 2 identities appear |
| **Sensitive-path access** (`sensitive_path`) | A captured request matched a configured path pattern (e.g. `/admin`, `/internal/`) and succeeded | Yes — add a pattern |
| **Cross-tier function access** (`cross_tier_function`) | A lower-tier identity succeeded on an endpoint a higher-tier identity is also seen using | Yes — assign role tiers |

A response only counts as "success" if it's a 2xx with a real, non-hollow,
non-error-shaped body (redirects, 401/403/404/429, and 200s that look like a
soft-denial are all treated as denied) — the same denial vocabulary
Reconner's server-side active authz engine uses
(`internal/scanner/idor.go`), so a passive candidate and an active proof
agree on what "denied" looks like. Object-id extraction deliberately ignores
bare 1–2 digit path/query values (a very common source of false positives
from shared pagination, e.g. `?page=2`) unless the parameter name itself
looks like an object reference (`user_id`, `order_id`, `uuid`, …).

### What it is not

This is a heuristic triage aid, not a vulnerability scanner — it can both
miss real issues (e.g. an IDOR that never shows an id in the URL/query/JSON
body) and flag things that turn out to be legitimate (shared/public
resources, intentionally shared objects, etc.). Every finding is meant to be
**manually reviewed, then proven** — ideally by replaying it through
Reconner's server-side Guided Analyze / active authz engine, which actually
re-issues the request across identities live against the target instead of
just diffing what already happened.

### Findings panel

Findings are shown live, grouped by severity, each expandable to the exact
request/response evidence (identity, tier if set, status, URL, timestamp)
that produced it. Two export options are independent of the normal capture
export and do **not** change the `reconner-capture/v1` schema Guided Analyze
imports — they're for the tester's own record:

- **Export findings JSON** (`reconner-triage-findings/v1`) — the full
  findings + identity list, for keeping or sharing.
- **Copy as Markdown** — a quick paste into a report or ticket.

Sensitive-path patterns and role tiers persist in `chrome.storage.local`
(same as scope/identity) so they survive closing and reopening DevTools.
Setting a role tier or adding a sensitive-path pattern **after** you've
already captured traffic re-runs triage over everything captured so far, so
you don't have to re-browse the app just to pick up findings that only
become detectable once that config exists.

### Testing the triage logic

The triage engine is pure JS with no `chrome.*`/DOM dependency, so it's unit
tested directly with Node's built-in test runner:

```sh
node --test extensions/reconner-chrome/test/
```
