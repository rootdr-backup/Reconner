<p align="center">
  <img src="assets/reconner-logo.svg" alt="Reconner" width="520">
</p>

<p align="center">
  <b>A free & open-source, self-hosted bug-bounty watchtower.</b><br>
  Web + network reconnaissance, vulnerability scanning, and continuous monitoring — one dashboard, all on your own machine.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/backend-Go-00ADD8?style=flat-square" alt="Go">
  <img src="https://img.shields.io/badge/frontend-React%20%2B%20TS-22d3ee?style=flat-square" alt="React">
  <img src="https://img.shields.io/badge/self--hosted-yes-2dd4bf?style=flat-square" alt="Self-hosted">
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License: MIT">
  <a href="https://t.me/rootdr_research"><img src="https://img.shields.io/badge/telegram-%40rootdr__research-3b82f6?style=flat-square" alt="Telegram"></a>
</p>

---

## What is Reconner?

Reconner is a self-hosted reconnaissance platform for bug-bounty hunters and
security researchers. Point it at a domain or an IP range and it runs a full
pipeline — discovery, fingerprinting, vulnerability checks and continuous
monitoring — then presents everything in a single live dashboard. Nothing is
sent to a third party: the app, its database and all findings stay on your box.

> **Authorized testing only.** Reconner is an active offensive-security tool.
> Only run it against assets you own or are explicitly permitted to test. See
> the [disclaimer](#disclaimer).

## What's new

- **Single-endpoint mode.** Point Reconner at one exact URL
  (`https://site/appointment?h=…`) and the whole pipeline — param discovery,
  crawl, JS analysis, XSS/SQLi and every other check — runs against *that*
  endpoint and the paths under it, **including path parameters** (`/orders/{id}`),
  not just query params.
- **Global Findings page.** One place that aggregates confirmed findings across
  every target, with severity filters and per-target drill-down.
- **In-app tool installer.** The System page shows every scanner's status and can
  install the missing Go/pip tools one-click (no root), or hand you the exact
  command + docs for the rest.
- **Docker image.** One reproducible container bundles the backend, dashboard and
  the entire tool-chain + headless Chromium — `docker compose up -d --build`.
- **Quieter, sharper findings.** Reflected-XSS is only reported when a real
  headless browser confirms execution (JSON/RSC/redirect reflections go to
  *Needs Review*); DOM-XSS uses framework-aware sinks with bounded taint;
  time-based SQLi requires linear-scaling proof; and host-level hygiene
  (missing CSP/HSTS/…) is reported **once per domain**, not once per URL.
- **Live ETA.** Per-module and whole-scan time-remaining while a scan runs.

## Why Reconner?

- **One box, full pipeline.** Recon, active scanning and monitoring in a single
  dashboard — instead of gluing a dozen CLIs together by hand.
- **Findings you can trust.** Every injection class is confirmed with
  differential / out-of-band / control-based checks and re-verified before it's
  reported, so you get far less noise than fire-and-grep scanning.
- **Web *and* network.** Subdomains, JS, parameters and DAST on one side; ports,
  service CVEs and edge-device checks on the other — one tool, one view.
- **Truly self-hosted.** No account, no cloud, no telemetry — the app, its
  database and every finding stay on your machine.
- **Open and hackable.** MIT-licensed Go + React; drop in a Nuclei template or a
  detection module without asking anyone.

## Features

**Web reconnaissance**
- Subdomain enumeration (passive + active), live HTTP probing and fingerprinting
- JavaScript analysis — endpoints, secrets and API keys
- Parameter discovery, reflected-parameter detection and hidden-param mining
- Directory / backup / config-file discovery
- Native context-aware DAST: XSS, SQLi, NoSQLi, SSRF, IDOR, LFI, SSTI, XXE, CMDi, open redirects, and more
- Out-of-band (OAST) detection for blind SSRF / RCE / SQLi / SSTI
- Nuclei integration with a curated template pack and false-positive filtering

**Network reconnaissance**
- Port scanning and service/version detection over IP / CIDR / range / list scopes
- Network-CVE scanning
- Credential brute-force for SSH / SMB / RDP / VNC (opt-in, scope-guarded)
- Initial-access checks for unauthenticated services and pre-auth edge-device CVEs
- IP-camera / DVR / NVR auditing (via [Ingram](https://github.com/jorhelp/Ingram)) with snapshot capture

**Platform**
- Live dashboard with real-time logs and results
- Correlation / attack-path view
- Continuous change monitoring
- One-click reports: HTML, Markdown and PDF
- Fully self-hosted — your data never leaves your machine

## Screenshots

<p align="center">
  <img src="docs/screenshots/dashboard.png" alt="Dashboard" width="49%">
  <img src="docs/screenshots/findings.png" alt="Findings, evidence and attack paths" width="49%">
</p>
<p align="center">
  <img src="docs/screenshots/live-logs.png" alt="Live scan logs" width="49%">
  <img src="docs/screenshots/report.png" alt="Exportable PoC report" width="49%">
</p>

<p align="center"><sub>Dashboard · findings with evidence &amp; attack paths · live scan logs · exportable PoC report.</sub></p>

## Quick start

Reconner is a single Go binary plus a static dashboard. Build and run it as a
**normal user** — no root required.

**Requirements:** Go ≥ 1.23 (with a C compiler for the embedded SQLite driver)
and Node.js ≥ 18. The external scanners are optional and auto-detected on your
`PATH` (see [Prerequisites](#prerequisites)).

```bash
git clone https://github.com/rootdr-backup/reconner.git
cd reconner

make            # builds the frontend bundle and the `reconner` binary
./reconner serve
```

Then open **http://localhost:8080** and log in:

| Username | Password      |
|----------|---------------|
| `admin`  | `change_m)_e` |

You'll be required to set a new password on first login.

> Web reconnaissance runs entirely unprivileged. Some **network**-scan features
> (raw-socket port scanning, etc.) may need elevated privileges — the same as
> any port scanner (e.g. `nmap`, `naabu`). Run those with the capability or
> privilege your OS requires; everything else works as a normal user.

### Run with Docker (recommended for servers)

A single, reproducible image bundles the backend, the built dashboard, **and**
the whole tool-chain (nuclei, dalfox, katana, subfinder, httpx, naabu, …) plus
headless Chromium and nmap — nothing to install on the host.

```bash
cp .env.example .env          # (optional) set a fixed admin password / host port
docker compose up -d --build  # starts on http://localhost:8080
docker compose logs -f        # the random admin password prints here on first boot
```

The admin user is `admin`; leave `ADMIN_PASSWORD` blank in `.env` for a strong
random password generated on first boot. Data (DB, config, screenshots,
templates) persists in the `reconner-data` volume, so updates never lose it. Full
details in **[README.Docker.md](README.Docker.md)** (or `make docker-up`,
`make docker-logs`, `make docker-password`).

### Running on a server (remote access)

By default Reconner binds **`127.0.0.1`** — local only, so a fresh VPS install
isn't exposed to the internet. To reach the dashboard from your own machine, pick
one:

```bash
# A) SSH tunnel — nothing exposed publicly (recommended)
ssh -L 8080:127.0.0.1:8080 user@your-server
#   then browse http://localhost:8080 on your laptop

# B) Bind publicly — ONLY behind a firewall / VPN / security group
#   edit ~/.recon-platform/config.json →  "host": "0.0.0.0"   then restart
```

Option B puts an admin dashboard on the open internet, so gate it at the firewall
(or front it with a reverse proxy + TLS + auth). The startup banner reminds you
which mode you're in.

## Prerequisites

Reconner shells out to standard, widely-used recon tools when they're present
and silently skips the ones that aren't. Install whatever you need from the
[ProjectDiscovery suite](https://github.com/projectdiscovery) plus `nmap`,
`sqlmap`, `dirsearch`, `hydra` and friends.

For convenience, an optional installer fetches the common set and (optionally)
registers a background service. It uses `sudo` **only** for system-level steps
(placing binaries in `/usr/local/bin`, installing a systemd unit); the app
itself never requires it:

```bash
# Linux — optional convenience installer
bash setup.sh

# macOS — optional
bash scripts/reconner-macos-deps.sh
```

## Configuration

On first run Reconner writes a config to `~/.recon-platform/config.json`. Every
scanner, worker pool, rate limit and optional API key is tunable there — the
fields are documented inline in
[`internal/config/config.go`](internal/config/config.go).

The optional AI-assisted orchestrator is **off by default**. If you enable it,
it reads an Anthropic API key strictly from the `ANTHROPIC_API_KEY` environment
variable — nothing is hardcoded and nothing is transmitted unless you turn it on.

## Reports

Every target exports a self-contained report from the UI or the API:

```
/api/targets/{id}/report        # Markdown
/api/targets/{id}/report.html   # standalone HTML
/api/targets/{id}/report.pdf    # PDF
```

## Tech stack

- **Backend:** Go (embedded SQLite)
- **Frontend:** React + TypeScript + Tailwind (Vite)
- **Scanners:** the ProjectDiscovery suite, plus nmap, sqlmap, dirsearch, hydra, Ingram and others

## Feedback & bug reports

Found a bug, a false positive, or have an idea? Please
[open an issue](https://github.com/rootdr-backup/reconner/issues) — reproduction
steps and log output help a lot. You can also reach out on Telegram
[@rootdr_research](https://t.me/rootdr_research). For security-sensitive reports,
follow [SECURITY.md](SECURITY.md).

## Support

If Reconner saves you time, you can support its development:

- 🇮🇷 **Iranian:** [daramet.com/RootDR](https://daramet.com/RootDR)
- 🌍 **International (crypto):**

  | Chain | Address |
  |-------|---------|
  | Solana | `BBdEFMnnMFX8ZqeoXbnmYYLE49gNEygdUDy4ctuB9EiT` |
  | Bitcoin | `bc1qefw45vhpwy6k0hw4gayu9qmrje9ml34l8ap7ly` |
  | EVM (ETH/BSC/Polygon…) | `0x58e7c01913D6eA354DEaB1f83AD9A95B4D9EAfCa` |
  | Tron (TRC20) | `TYE2DKJZ7nNkBNEJ7uSr374ZVfKfBUYTic` |

## Disclaimer

This project is for **authorized security testing and educational purposes
only**. Running it against systems without explicit, prior permission is
illegal and unethical. The author assumes no liability and is not responsible
for any misuse or damage caused by this tool. **You** are responsible for your
own actions.

## License

Released under the [MIT License](LICENSE).

---

<p align="center">
  Crafted by <b>RootDR</b> · <a href="https://t.me/rootdr_research">@rootdr_research</a>
</p>
