<p align="center">
  <img src="assets/reconner-logo.svg" alt="Reconner" width="500">
</p>

<p align="center">
  <strong>Self-hosted attack-surface intelligence and verification-first DAST for authorized bug bounty.</strong><br>
  Recon, web and network scanning, live evidence, and continuous monitoring in one responsive dashboard.
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
- **Network coverage:** ports, services, CVEs and explicitly opt-in credential
  testing for authorized network engagements.
- **Designed for long scans:** resumable tasks, persistent data, monitoring,
  live logs, reports and resource-aware scheduling.
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
and build date into the binary and OCI image. `reconner version` prints that
identity. A `v<version>` tag is accepted only when it matches `VERSION`; CI
builds and publishes the image first, then creates the GitHub Release. This
prevents users from seeing an update before its image exists.

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
        └── network/service modules
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
and create a Project, or create a Project manually and mix domains, wildcards,
exact URLs/pages, JavaScript files, APIs, IPs and CIDRs. Exact page and JS assets
are seeded directly into their relevant analysis pipeline instead of being
reduced to a hostname.

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

The evidence model, public-data prioritization and detector-by-detector upgrade
plan are documented in the [vulnerability engine roadmap](docs/VULNERABILITY_ENGINE_ROADMAP.md).

## Network reconnaissance

Network targets may be a single IP, CIDR or range. The pipeline covers port and
service discovery, version/CVE analysis, network Nuclei templates and optional
camera/DVR/NVR checks. Credential spraying and brute-force modules are active,
lockout-sensitive features and remain opt-in. Confirm authorization and the
engagement's account-lockout policy before enabling them.

## Toolchain

The official image bundles and verifies every external command before it is
published:

| Area | Bundled tools |
|---|---|
| Discovery | subfinder, assetfinder, findomain, alterx, asnmap, uncover |
| DNS | dnsx, massdns, puredns, shuffledns |
| HTTP/crawling | httpx, katana, hakrawler, gau, waybackurls, waymore, uro |
| Content | dirsearch, feroxbuster, qsreplace |
| Detection | nuclei, dalfox, subzy, sqlmap |
| Network/evidence | naabu, nmap, hydra, gowitness, scilla |
| Runtime | Chromium, Python 3 and git |

The container runs with `NET_RAW` and `NET_ADMIN` because SYN scanning requires
raw sockets. Remove those capabilities if the deployment only performs web
application scanning.

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

## CLI

The same engine is available without the dashboard:

```bash
reconner scan example.com
reconner scan example.com --quick
reconner scan example.com --single
reconner scan example.com --modules subdomain_enum,http_probe,nuclei,xss,sqli
reconner report example.com --html --md --pdf
reconner list
reconner modules
reconner version
```

Use `reconner --help` for the complete command reference.

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
