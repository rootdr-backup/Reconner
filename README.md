<p align="center">
  <img src="assets/reconner-logo.svg" alt="Reconner" width="500">
</p>

<p align="center">
  <strong>Self-hosted bug-bounty platform — verification-first recon &amp; DAST.</strong><br>
  Web scanning, live evidence, and continuous monitoring. Your data stays on your machine.
</p>
<p align="center">
  <a href="https://github.com/rootdr-backup/Reconner/actions/workflows/docker-image.yml"><img src="https://github.com/rootdr-backup/Reconner/actions/workflows/docker-image.yml/badge.svg" alt="Docker build"></a>
  <a href="https://github.com/rootdr-backup/Reconner/releases/latest"><img src="https://img.shields.io/github/v/release/rootdr-backup/Reconner?display_name=tag&sort=semver" alt="Latest release"></a>
  <img src="https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white" alt="Go 1.26">
  <img src="https://img.shields.io/badge/React-TypeScript-22d3ee?logo=react&logoColor=white" alt="React and TypeScript">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-14b8a6" alt="MIT license"></a>
</p>

> [!IMPORTANT]
> Reconner performs active security testing. Use it only on systems you own or
> have explicit permission to test. You are responsible for scope, rate limits,
> rules of engagement, and the handling of collected evidence.

## Why Reconner

Most recon stacks stop at tool output. Reconner maintains a target model,
discovers insertion points, runs native and external detectors, verifies strong
signals, and keeps candidates separate from confirmed findings. The result is a
workflow built for triage—not another folder full of uncorrelated text files.

- **One deployment:** backend, responsive web UI, SQLite, WebSocket updates,
  Chromium and the complete external toolchain ship in one container image.
- **Verification first:** candidate lifecycle and detector evidence reduce noisy
  reports while preserving inconclusive signals for review.
- **Deep web coverage:** crawling, JavaScript analysis, parameters, APIs,
  reflected and DOM XSS, SQL injection, access control and server-side classes.
- **Designed for long scans:** resumable tasks, persistent data, monitoring,
  live logs, hard-cancellable browser phases, reports and resource-aware
  scheduling.
- **Operator-tunable coverage:** manage deduplicated wordlists and proof-safe
  payload templates from the dashboard without rebuilding the image; every
  category can be restored to its compiled defaults.
- **Portable research bundles:** download a target's structured scan state,
  evidence metadata, task ledger and current in-scope JavaScript/chunks as one
  manifest-backed ZIP archive.
- **Program-aware projects:** browse public HackerOne, Bugcrowd, Intigriti and
  YesWeHack programs, filter their declared scope, import only selected assets
  and review scope changes before Reconner expands a scan.
- **Works on phones:** the operations dashboard, navigation, scan activity and
  update center adapt to mobile screens and touch input.

<p align="center">
  <img src="docs/screenshots/dashboard.png" alt="Reconner dashboard" width="920">
</p>

## Quick start

### Recommended: prebuilt image

The host only needs Docker and Docker Compose v2.

```bash
git clone https://github.com/rootdr-backup/Reconner.git
cd Reconner
cp .env.example .env
docker compose pull reconner
docker compose up -d reconner
```

Open `http://<server-ip>:8080`.

On the first boot, Reconner creates a strong admin password unless
`ADMIN_PASSWORD` was provided in `.env`. Retrieve the generated password with:

```bash
docker compose logs reconner
```

The password is printed only when the persistent configuration is first
created. To inspect it later:

```bash
docker compose exec reconner sh -c 'grep admin_password "$RECON_CONFIG"'
```

### Build the checked-out source

Use this path when developing Reconner or building for a non-amd64 host:

```bash
git clone https://github.com/rootdr-backup/Reconner.git
cd Reconner
cp .env.example .env
docker compose up -d --build reconner
```

A clean local build downloads and compiles the full toolchain and can take a
while. Pulling the prebuilt image is significantly faster.

## Updating

Reconner checks the latest stable GitHub release when an authenticated dashboard
is open. The backend caches the result for six hours and uses GitHub ETags, so a
multi-user deployment normally makes at most four release requests per day.

When a newer release is available, the dashboard shows one non-blocking notice,
release notes, and the correct commands for both deployment methods. Dismissing
the notice hides that release only; the next version appears normally. Reconner
never restarts itself or interrupts an active scan.

For the prebuilt image, wait for active scans to finish and run:

```bash
docker compose pull reconner
docker compose up -d --no-deps reconner
docker compose ps
```

The service runs as uid/gid `10001` instead of root. Starting with v3.0.1, the
Compose entrypoint repairs ownership of a pre-v3 root-owned volume once and
then drops privileges before Reconner starts. No manual migration is normally
needed. If a custom orchestrator forces the container user and bypasses that
init step, repair ownership once, then start Reconner again:

```bash
docker compose run --rm --user 0 --entrypoint chown reconner -R 10001:10001 /data
docker compose up -d --no-deps reconner
```

If an old deployment's `config.json` and database contain mismatched encryption
keys, v3.0.1 preserves scan identities and evidence fail-closed. The optional
Telegram BotFather token is the only recoverable exception: Reconner clears and
disables that unusable token, keeps the chat allowlist, and asks an administrator
to enter the token again instead of crash-looping the whole service.

For a local source build:

```bash
git pull --ff-only origin main
docker compose up -d --build reconner
docker compose ps
```

Targets, findings, users, configuration, screenshots, wordlists and templates
live in the persistent `reconner-data` volume and survive image replacement.

## Release model

Reconner follows semantic versioning:

- **Patch** (`1.1.1`): compatible fixes and detector corrections.
- **Minor** (`1.2.0`): compatible features, detection coverage and UI changes.
- **Major** (`2.0.0`): changes that require operator migration or break behavior.

`VERSION` is the source of truth. The Docker build injects the version, commit
and build date into the service and OCI image; that identity is exposed in the
dashboard's update center. A `v<version>` tag is accepted only when it matches
`VERSION`; CI builds and publishes the image first, then creates the GitHub
Release. This prevents users from seeing an update before its image exists.

### v3 stability contract

The v3 work freezes the existing feature surface and treats correctness as a
release artifact, not a slogan. Every one of the 42 supported scheduler modules
has a declared prerequisite, proof contract and regression-suite owner. A phase
can finish as `completed`, `blocked`, `failed`, `timed_out`, `skipped`,
`cancelled`, `unsupported` or `unknown`; a missing tool, credential, identity,
browser or callback can never be reported as a clean scan.

Every pull request must pass Go formatting, module verification, unit and race
tests, deterministic detector benchmarks, migrations, frontend coverage and
production-browser workflows, release smoke tests, dependency/source/secret
scans, and production container scans. Both `linux/amd64` and `linux/arm64`
images are built and scanned independently before a multi-platform image can be
published. A failed or skipped required job blocks publication.

The deterministic corpus is required to score zero known false positives and
zero known false negatives. This is deliberately not presented as a guarantee
for arbitrary internet targets: uncertain signals remain candidates, and
unattempted coverage is visible in the phase ledger. See the complete
[v3 stability and release plan](docs/V3_STABILITY_RELEASE_PLAN.md) and the
[supported capability matrix](docs/V3_CAPABILITY_MATRIX.md).

> [!NOTE]
> Reconner v3.0.0 is published only from a commit that passes the required
> correctness, race, migration, production-browser, security and native
> amd64/arm64 image gates. The final evidence and the explicitly disclosed
> fast-track constraint are recorded in the
> [v3 release audit](docs/V3_RELEASE_AUDIT.md).

## Detection pipeline

```text
Target + authorization
        │
        ▼
Asset discovery ── DNS ── HTTP probing ── crawling ── JS/API analysis
        │
        ▼
Insertion points + request reconstruction + authentication context
        │
        ├── native detectors (XSS, SQLi, SSRF, LFI, SSTI, …)
        ├── Nuclei and specialized external engines
        └── passive enrichment and takeover checks
        │
        ▼
Candidate lifecycle ── reproducibility ── browser/OAST/timing proof
        │
        ▼
Confirmed findings + candidates + evidence + reports + monitoring diff
```

Heavy XSS, SQLi and external verification stages are coordinated per target.
Requests also share a bounded per-host gate so independently scheduled modules
do not multiply into accidental WAF pressure. Different targets can still make
progress in parallel within the configured CPU and memory budget.

## Bug bounty catalog and Projects

The **Bounty programs** menu normalizes public HackerOne, Bugcrowd, Intigriti
and YesWeHack programs into one local catalog. It supports search and server-side pagination plus
filters for provider, live status, bounty/VDP, declared in-scope asset count,
wildcards, asset type, reward, industry, Safe Harbor and start/update order.
The cache refreshes every six hours; an administrator can also request a
background refresh from the dashboard. Provider indexes are cached first;
structured scope is fetched lazily when a program is opened/imported, while
programs linked to monitored Projects refresh every six hours. This keeps memory,
bandwidth and provider load bounded. A provider outage leaves the last good
catalog available and retries with backoff.

Opening a program loads its current structured scope. Select the assets you want
and create a Project, or create a Project manually from domains, wildcards,
exact URLs/pages, JavaScript files and APIs. Exact page and JS assets are seeded
directly into their relevant analysis pipeline instead of being reduced to a
hostname. IP/CIDR assets remain visible when imported from a provider or an old
database, but this stability release rejects network execution instead of
pretending an unsupported scan succeeded.

Program scope remains controlled by the operator:

- newly published upstream assets become pending scope events and are never
  scanned before explicit approval;
- removed, private or submission-ineligible assets are suspended immediately,
  while their findings and history remain intact;
- modified scope instructions or eligibility generate a review event and a
  dashboard notification;
- monitoring records normalized page/HTTP/security/JavaScript diffs, then
  schedules only the relevant verification modules when something changes.

The catalog is a convenience cache, not legal authorization. Always verify the
official program brief, exclusions and rules of engagement before scanning.

## Web reconnaissance and DAST

Reconner includes:

- passive and adaptive active subdomain discovery with a DNS/CNAME admission
  gate, wildcard-aware vhost proof and live-host probing—unresolved/wildcard
  guesses never enter the expensive web pipeline;
- scope-gated ASN/CIDR discovery (explicit opt-in after program/WHOIS review),
  historical URLs, crawling and headless browsing;
- recursive same-site JavaScript dependency analysis with cycle prevention,
  redirect/content validation, source-map recovery and bounded resource use;
- parameter discovery across query, path, forms, JSON, XML, GraphQL and OpenAPI;
- directory, backup/config exposure, takeover and broken-link checks;
- reflected and DOM XSS with context classification and browser execution proof;
- error, boolean, time-based and second-order SQL injection detection with
  optional sqlmap confirmation;
- SSRF/OAST, LFI, SSTI, command injection, XXE, NoSQLi and open redirects;
- IDOR/authz workflows, CSRF, CORS, JWT, account takeover and session analysis;
- cache poisoning, request smuggling and race-condition checks;
- verified Nuclei findings and structured evidence.

Reconner's XSS pipeline focuses on **reflected XSS and DOM XSS**. It does not
run stored-XSS injection as part of the general scan pipeline.

Static JavaScript source-to-sink analysis is routing intelligence, not proof. It
stays internal until Chromium observes a nonce payload execute; only then does a
DOM-XSS row become a confirmed finding with an `alert(document.domain)` PoC.

### Custom wordlists and payloads

Administrators can open **System & updates → Wordlists & payloads** to extend
every operator-facing fuzz/brute-force corpus: subdomains, virtual hosts,
directories, backup/exposure/GraphQL/API-spec paths, file extensions, hidden
parameters, JWT HMAC secrets, XSS, SQLi, LFI, SSRF, SSTI, CSTI, NoSQLi,
command injection and open redirects.

Imports accept pasted lines or a text file. Reconner normalizes category-specific
syntax, deduplicates against both compiled defaults and earlier additions, and
reports exact input, added, duplicate and invalid counts. Custom entries are
stored separately under the persistent wordlist directory; **Restore default
wordlist/payloads** removes only the custom layer.

Payload additions cannot weaken verification. XSS templates still require a
real Chromium nonce execution; SQLi and NoSQLi additions require a reproducible
new database/driver error; template and command payloads retain their independent
computed-marker contracts. An imported string is extra coverage, never proof by
itself.

The v3.1 verifier also observes nonce proof messages from cross-origin frames,
traces modern injection sinks such as `setHTMLUnsafe()` and
`Document.parseHTMLUnsafe()`, and runs a real-Chromium 13-context coverage matrix
in CI. Passing that named matrix is a concrete regression guarantee, not a
universal detection percentage for every application or CSP policy.

Backup discovery prioritizes contextual nested paths such as `/back/.env`, uses
bounded Range validation, and retains the complete generic corpus behind those
high-signal candidates. SQLi timing requires a successful sample quorum and
linear baseline/sleep(0)/sleep(2)/sleep(5) evidence. Browser XSS proof uses
adaptive polling rather than a fixed delay, so synchronous execution returns
quickly while late SPA hydration remains covered. See the reproducible scope and
results in [scanner quality evidence](docs/QUALITY_EVIDENCE_REVIEW.md).

### Target artifact bundles

From a target page, open **Report → Download scan bundle — ZIP**. The archive
contains a versioned `manifest.json`, structured JSON for the target's discovery,
findings, evidence metadata and phase/task state, stored target screenshots, plus
live-fetched snapshots of up to 2,000 known JavaScript assets under
`javascript/`. Fetches reuse the target's request identity, reject every redirect
that leaves scope, enforce bounded file/total budgets, and record individual
failures instead of silently omitting an artifact. Treat the resulting archive
as sensitive research material.

### Skip Phase guarantees

Skip cancels the phase context and, for Chromium-backed XSS work, terminates the
task-owned browser process group and its temporary profile. The scheduler waits
for a short cleanup grace, then records the phase as skipped and releases its
execution slot even if a third-party goroutine ignores cancellation. A fresh
browser lease is created for later work, so this safety net does not serialize
or disable the existing parallel phase model.

The evidence model, public-data prioritization and detector-by-detector upgrade
plan are documented in the [vulnerability engine roadmap](docs/VULNERABILITY_ENGINE_ROADMAP.md).

## Telegram control bot

Administrators can connect a BotFather bot from **System → Integrations →
Telegram**. The integration uses long polling, so the Reconner host does not
need a public webhook. The token is encrypted at rest and the API never returns
the raw value after it is saved.

One bot can allowlist multiple private chats or trusted groups. Each chat has an
independent role and notification policy:

- **Viewer:** inspect platform status, targets, scans and validated findings.
- **Operator:** start, pause, resume, cancel and skip the current scan phase.
- **Admin:** also add, edit and delete targets; deletion requires confirmation.

Scan start, every completed/failed/timed-out/skipped phase, final results,
monitoring changes and validated findings can be toggled per chat. Alerts use a
durable per-chat outbox with deduplication and retry, so a temporary Telegram
failure or Reconner restart does not silently lose them. Buttons attached to
scan messages expose Target, Pause, Resume, Cancel and **Skip phase** actions.

After adding the bot to a chat, send `/start`. An unapproved chat replies with
its numeric Chat ID; add that ID in the web panel, choose `viewer`, `operator`
or `admin`, then use **Test** to verify delivery. Chat roles apply to everyone
in that chat, so reserve `admin` for private chats or fully trusted groups.

Available commands include `/status`, `/targets`, `/target`, `/scans`,
`/findings`, `/scan`, `/pause`, `/resume`, `/skip` (also `/skipphase`),
`/cancel`, `/addtarget`, `/edittarget` and `/deletetarget`.

## Network targets

Direct IP/CIDR/range execution is intentionally unavailable in this release.
Legacy network projects remain readable and exportable. Both the API and scan
planner fail closed with a clear unsupported-capability error, so no empty or
successful-looking phantom scan can be created.

The frozen prerequisite and proof surface for all 42 supported modules is in
[the v3 capability matrix](docs/V3_CAPABILITY_MATRIX.md).

## Toolchain

The official image bundles and verifies every external command before it is
published:

| Area | Bundled tools |
|---|---|
| Discovery | subfinder, assetfinder, findomain, alterx, asnmap, scilla |
| DNS | dnsx, massdns, puredns, shuffledns |
| HTTP/crawling | httpx, katana, hakrawler, gau, waybackurls, waymore, uro |
| Content | dirsearch, feroxbuster |
| Detection | nuclei, subzy, sqlmap |
| Runtime | Chromium, Python 3 and git |

The container receives no `NET_RAW` or `NET_ADMIN` capability. Tool versions
and downloaded release checksums are pinned so rebuilds cannot silently change
the scanner stack.

## Configuration

The initial `.env` controls the host-facing bootstrap values:

| Variable | Purpose | Default |
|---|---|---|
| `HOST_PORT` | Dashboard port on the Docker host | `8080` |
| `ADMIN_USER` | Initial administrator username | `admin` |
| `ADMIN_PASSWORD` | Initial password; blank generates a random value | blank |

Persistent scanner settings live in `/data/config.json`. Important controls
include worker counts, target/resource ceilings, request rate, per-module URL
caps, Nuclei surface limits, SQLi timing/sqlmap options, passive intelligence
API keys and update-check settings. Environment-provided secrets override file
values where supported; never commit `.env` or a populated config file.

Bug-bounty programs that require an identifying User-Agent or program header can
set deployment-wide defaults in `config.json`:

```json
{
  "scan_user_agent": "Mozilla/5.0 researcher-id ywh-public",
  "scan_headers": {
    "X-Bug-Bounty": "program-token"
  }
}
```

`RECON_SCAN_USER_AGENT` overrides the global User-Agent from the environment.
Both values can also be set per project beside its scope fields; project values
win over global defaults. Custom identity headers are sent only to approved
project hosts and are not forwarded to passive data providers or third-party
browser resources. When no override is configured, existing module/tool
User-Agent behavior is preserved.

## Web application

Reconner is operated through its authenticated web interface. Target and asset
management, scan planning, live logs, finding triage, reports, monitoring, user
administration and system settings all use the same persistent service runtime.
The `reconner` executable starts that service directly and does not expose a
separate command-line scanning or maintenance interface.

## Development

Requirements for a direct source build are Go, Node.js/npm, a C compiler for
SQLite, and any external scanner tools you want available locally.

```bash
make frontend
make backend
go test ./...
go vet ./...
```

Frontend-only development:

```bash
cd frontend
npm ci
npm run dev
npm run build
```

Useful project documents:

- [Docker deployment and operations](README.Docker.md)
- [Vulnerability engine roadmap](docs/VULNERABILITY_ENGINE_ROADMAP.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [License](LICENSE)

## Data safety

Normal updates do not delete data. The destructive command is:

```bash
docker compose down -v
```

The `-v` flag deletes the persistent volume and therefore removes targets,
findings, users and configuration. Do not use it during a normal update.

## Responsible use

Reconner is intended for authorized security research, bug-bounty programs and
defensive assessment. Do not scan third-party assets without explicit prior
permission. Respect program scope, excluded assets, request limits, privacy
requirements and stop conditions. The maintainers are not responsible for
misuse or damage caused by unauthorized operation.

## Support and feedback

Found a false positive, a missed case or a UI issue? Open a
[GitHub issue](https://github.com/rootdr-backup/Reconner/issues) with a minimal
reproduction and sanitized logs, or contact
[@rootdr_research](https://t.me/rootdr_research).

If Reconner saves you time:

- Iranian gateway: [daramet.com/RootDR](https://daramet.com/RootDR)
- Solana: `BBdEFMnnMFX8ZqeoXbnmYYLE49gNEygdUDy4ctuB9EiT`
- Bitcoin: `bc1qefw45vhpwy6k0hw4gayu9qmrje9ml34l8ap7ly`
- EVM: `0x58e7c01913D6eA354DEaB1f83AD9A95B4D9EAfCa`
- Tron: `TYE2DKJZ7nNkBNEJ7uSr374ZVfKfBUYTic`

---

<p align="center">
  Built by <strong>RootDR</strong> for the bug-bounty community.
</p>
