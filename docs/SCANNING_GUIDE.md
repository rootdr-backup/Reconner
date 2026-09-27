# Reconner scanning guide

This guide explains how Reconner maps scope to compatible pipelines, what each
profile changes, and how to interpret coverage and proof states.

## Start with authorization and exact scope

Reconner accepts manually created Projects and selected assets imported from
public bug-bounty catalogs. A catalog entry is not authorization by itself.
Verify the official program brief, eligible asset type, exclusions, request
limits, identifying headers, test-account rules, and stop conditions before
starting a scan.

Supported scope shapes include:

- domains and wildcards;
- exact HTTP(S) pages, API roots, and JavaScript URLs;
- single IP addresses;
- CIDRs;
- inclusive IP ranges such as `192.168.1.1-192.168.1.10`.

Exact page and JavaScript assets preserve their path-level identity. Projects
containing both web and network scope are scanned one asset at a time so the two
pipelines cannot be combined accidentally.

## Web scan planning

Web profiles are module presets, not claims about coverage completeness.

- **Safe** prioritizes surface mapping and low-impact observation: HTTP,
  JavaScript, endpoints, parameters, passive checks, exposures, and technology
  intelligence.
- **Standard** adds reflection, backup discovery, API data-exposure correlation,
  open redirect, XSS, SQLi, CORS, and JWT checks.
- **Custom** lets the operator select individual modules and higher-cost or
  timing-sensitive checks.

Slow, normal, and fast request profiles tune pacing and concurrency. They do
not change the positive-proof contract. Single-endpoint mode confines work to
the selected seed and paths beneath it; ASN discovery remains a separate,
explicit opt-in after scope ownership is reviewed.

The broad pipeline is:

```text
scope → DNS/HTTP → crawling/rendered states → JS/APIs/parameters
      → candidate detectors → replay/browser/OAST proof → findings
```

## Network scan planning

Network controls are shown only for compatible IP, CIDR, or range assets.
Recognized CDN/WAF edges and configured exclusions are removed before any port
request. Host expansion is bounded.

| Profile | Port surface | Modules selected by the preset |
|---|---|---|
| **Network Fast** | Curated high-signal TCP ports | Port, banner, service, and bounded OS discovery |
| **Network Normal** | Top 1,000 TCP ports | Discovery, service-aware network Nuclei, and 401/403 verification |
| **Network Deep** | All TCP ports | Normal modules plus explicit HTTP Basic credential audit |

ICMP is stored as a hint and never suppresses TCP discovery. Naabu performs TCP
connect discovery; Nmap fingerprints only verified open ports. Small scopes can
use bounded native TCP/banner fallback when an external tool is unavailable.

Network Nuclei receives verified services rather than speculative host/port
pairs. The HTTP Basic audit requires a real Basic challenge, is paced, stops on
lockout or rate limiting, and requires two identical successful replays before
promotion.

## Request identity and authenticated scans

Program-required user agents or identifying headers can be configured globally
or per Project. Project values win and are restricted to admitted project hosts.
Authenticated scans can attach a session cookie, bearer token, or custom
header. Authorization modules require distinct, correctly bound identities;
with insufficient identities they are excluded or blocked instead of emitting a
false clean result.

Treat authentication material as sensitive. Use dedicated test accounts with
the minimum privileges required by the program rules.

## Evidence states

| State | Operator interpretation |
|---|---|
| **Confirmed** | The class-specific independent proof succeeded |
| **Candidate** | A meaningful signal still needs review or a verifier |
| **Rejected** | Replay, controls, encoding, response family, or instability disproved it |
| **Blocked** | A required credential, identity, callback, browser, tool, or eligible input was absent |
| **Failed / timed out** | Execution did not complete; inspect the phase log |
| **Skipped / cancelled** | The operator ended the phase or task intentionally |

A phase that completed means eligible work was attempted. It never means the
entire target is clean. Use the coverage counters—discovered, eligible,
attempted, candidate, confirmed, rejected, blocked, and errored—to understand
what actually happened.

## Pause, resume, skip, and cancel

- **Pause** prevents the task from advancing while preserving durable state.
- **Resume** continues a paused task.
- **Skip phase** cancels the current phase, performs bounded cleanup, records it
  as skipped, and advances without changing the parallel phase model.
- **Cancel** ends the task rather than only the current phase.

Chromium-backed phases use task-owned process groups and temporary profiles.
Skip terminates that browser group and releases the scheduler after a bounded
cleanup grace even if third-party work ignores context cancellation.

## Custom wordlists and payloads

Open **System & updates → Wordlists & payloads** to extend operator-facing
corpora. Categories include subdomains, vhosts, directories, backups,
exposures, API/GraphQL paths, extensions, hidden parameters, JWT secrets, web
payload families, and network auth.

Paste entries or import a text file. Reconner:

1. normalizes category-specific syntax;
2. rejects invalid entries;
3. deduplicates against compiled defaults and earlier additions;
4. reports input, added, duplicate, invalid, and effective totals;
5. stores custom entries separately in the persistent volume.

**Restore default** removes only the custom layer for that category. Imported
payloads can widen candidate generation but cannot weaken class-specific proof.

## Admin and high-sensitive panels

Panels are classified from product fingerprints, credential forms, final
content, or authorization-response evidence. Redirects are followed within a
bounded same-host policy; an unresolved `301`/`302` is not a finding. Generic
path hits and soft-404 families are rejected.

Equivalent content and common redirect destinations are grouped into one row
with an expandable affected-URL list. This prevents the same shared console on
many subdomains from flooding the target view.

## Target research bundles

Use **Report → Download scan bundle — ZIP** on a target page. The archive can
include:

- a versioned manifest;
- target, discovery, finding, evidence, task, and phase JSON;
- coverage counters and browser-state graph;
- stored screenshots;
- bounded snapshots of admitted JavaScript and chunks.

Every redirect hop is scope-checked. Failed asset fetches remain listed instead
of disappearing silently. The bundle may contain secrets and authenticated
evidence; store and share it accordingly.

## Telegram operations

Configure the bot under **System → Integrations → Telegram**. Chats are
allowlisted individually as viewer, operator, or admin. Notifications can cover
scan start, each terminal phase status, final results, monitoring changes, and
validated findings.

The bot uses long polling and a durable per-chat outbox. Operator actions are
audited. Admin target deletion always requires inline confirmation.

## Reading a zero-result scan

Before treating zero findings as meaningful, verify:

- the intended assets were admitted and not suspended or excluded;
- DNS/HTTP/service discovery produced eligible inputs;
- authenticated identity was attached where required;
- provider credentials and callback services were available;
- browser and external-tool phases did not block, fail, time out, or get skipped;
- URL, host, request, and resource caps did not truncate the relevant surface;
- coverage counters show attempted work rather than only discovered work.

For detector-by-detector prerequisites and proof requirements, use the
[capability matrix](V3_CAPABILITY_MATRIX.md). For deployment problems, use the
[operator guide](OPERATOR_GUIDE.md).
