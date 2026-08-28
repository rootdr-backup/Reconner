<p align="center">
  <img src="assets/reconner-logo.svg" alt="Reconner" width="520">
</p>

<p align="center">
  <b>A free & open-source, self-hosted bug-bounty watchtower.</b><br>
  Web + network reconnaissance, active DAST, and continuous monitoring — one dashboard, one Docker command, entirely on your own infrastructure.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/backend-Go-00ADD8?style=flat-square" alt="Go">
  <img src="https://img.shields.io/badge/frontend-React%20%2B%20TS-22d3ee?style=flat-square" alt="React">
  <img src="https://img.shields.io/badge/self--hosted-yes-2dd4bf?style=flat-square" alt="Self-hosted">
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License: MIT">
  <a href="https://t.me/rootdr_research"><img src="https://img.shields.io/badge/telegram-%40rootdr__research-3b82f6?style=flat-square" alt="Telegram"></a>
</p>

---

# Reconner

Reconner is a self-hosted reconnaissance and DAST platform for bug-bounty
hunters and security researchers. Point it at a domain, a single endpoint, or
an IP range, and it runs a full recon → injection → verification pipeline,
then shows everything — subdomains, live hosts, parameters, confirmed
vulnerabilities, and continuous change diffs — in one live dashboard. The
Docker image ships **all 30 external tools the app can invoke, built in**, so
a fresh clone needs nothing but Docker.

> **Authorized testing only.** Reconner is an active offensive-security tool
> that sends real requests — including injection payloads, brute-force
> attempts, and port scans — at whatever you point it to. Only run it against
> assets you own or are explicitly authorized to test. See
> [Security / Authorization](#security--authorization).

## Features

- **Web reconnaissance** — subdomain enumeration, live-host probing &
  fingerprinting, JavaScript analysis, headless-browser crawling, historical
  URL mining, parameter discovery/reflection/fuzzing, directory & backup
  discovery, subdomain-takeover and broken-link-hijacking detection.
- **Active DAST** — native, context-aware detectors for XSS (headless-browser
  confirmed), SQLi (incl. timing-proof blind SQLi + optional sqlmap
  verification), NoSQLi, SSTI, XXE, command injection, LFI, SSRF (with
  built-in out-of-band confirmation), IDOR, authz bypass, account takeover,
  open redirect, CORS, CSRF, JWT weaknesses, cache poisoning, request
  smuggling, race conditions, plus curated Nuclei template scanning.
- **Network reconnaissance** — port/service scanning (IP/CIDR/range), network
  CVE scanning, opt-in credential brute-force (SSH/SMB/RDP/VNC), and IP
  camera/DVR/NVR auditing.
- **Verification-first findings** — every finding is re-confirmed and scored
  before it reaches you, instead of raw fire-and-grep tool output.
- **Continuous monitoring and reports** alongside the dashboard.
- **A completely bundled tool-chain** — all 30 external tools the app can
  invoke, plus headless Chromium, are built into the Docker image. See
  [Toolchain](#toolchain).

## Architecture

Reconner is a single Go binary (embedded SQLite, WebSocket for live updates)
plus a React/TypeScript dashboard, distributed as one multi-stage Docker
image:

```
┌─────────────────────────────────────────────────────────────────┐
│ Docker image (ghcr.io/rootdr-backup/reconner)                    │
│                                                                    │
│  frontend  → React/Vite dashboard build                          │
│  gotools   → 20 Go recon tools (go install, GOBIN=/out)          │
│  massdns   → massdns compiled from source (gcc/libc6-dev/make)   │
│  external  → feroxbuster + findomain, official GitHub releases,  │
│              arch-selected via TARGETARCH (amd64/arm64)          │
│  pytools   → dirsearch/uro/waymore in a self-contained venv      │
│  backend   → Reconner Go binary (CGO + embedded SQLite)          │
│       │                                                           │
│       ▼                                                           │
│  runtime   → slim Debian + Chromium + nmap + hydra + sqlmap +    │
│              python3, all of the above copied in, then a         │
│              build-time verification of all 30 tools + Chromium  │
└─────────────────────────────────────────────────────────────────┘
                              │
                     docker-compose.yml
                              │
                    binds :8080, mounts /data
```

Every tool is compiled or downloaded **during the image build** — never at
container startup — and build-time verification fails the build outright if
any required tool is missing or doesn't actually run. See the top of
[`Dockerfile`](Dockerfile) for the full stage-by-stage design rationale,
including why `puredns`/`shuffledns` (which both depend on `massdns` for DNS
resolution) always land on `PATH` together.

## Requirements

For the normal (Docker) workflow, the **only** things you need on the host
are:

- [Docker](https://docs.docker.com/get-docker/) (with BuildKit — the default on modern installs)
- [Docker Compose](https://docs.docker.com/compose/) (the `docker compose` plugin, v2)

You do **not** need any of the following on the host to run Reconner via
Docker — all of it is built or downloaded inside the image and never touches
your machine:

Go · Node.js / npm · Python / pip · Rust / Cargo · gcc / make · or any of the
30 bundled reconnaissance tools themselves.

(If you want to build the Go binary or dashboard directly on your own
machine instead of via Docker, that's a separate, optional path — see
[Development](#development).)

## Quick start

**Option A — build locally (always matches the exact commit you checked out):**

```bash
git clone https://github.com/rootdr-backup/Reconner.git
cd Reconner
cp .env.example .env
docker compose up -d --build
```

**Option B — use the prebuilt image from GHCR:**

[`.github/workflows/docker-image.yml`](.github/workflows/docker-image.yml)
builds and pushes `ghcr.io/rootdr-backup/reconner:latest` to GitHub Container
Registry on every push to `main`, and `docker-compose.yml` already references
that image, so you can skip `--build`:

```bash
git clone https://github.com/rootdr-backup/Reconner.git
cd Reconner
cp .env.example .env
docker compose pull
docker compose up -d
```

> **Architecture note:** the CI workflow currently builds for the runner's
> native platform only (no multi-platform `buildx` configuration) — in
> practice this means the published `:latest` tag is a **linux/amd64** image.
> On an **arm64** host (Apple Silicon, AWS Graviton, etc.), use **Option A**
> (`docker compose up -d --build`) so the Dockerfile's own architecture
> detection (`TARGETARCH`) builds the correct Feroxbuster/Findomain binaries
> for your CPU.

Either way, the first successful build/pull compiles or fetches all 30 tools
plus headless Chromium — a local `--build` from scratch can take **15–25+
minutes** depending on your network and CPU; pulling the prebuilt image is
much faster. Once it's up, open:

```
http://<server-ip>:8080
```

and continue to [First Login](#first-login) to get your admin password.

## First Login

This behavior comes directly from
[`docker/entrypoint.sh`](docker/entrypoint.sh), which runs on every container
start and only *writes* a new config the first time (i.e. when `/data` is
empty):

1. **Start Reconner**: `docker compose up -d --build` (Option A) or
   `docker compose up -d` after a `pull` (Option B).
2. **Wait for the container to finish booting** — a few seconds after the
   healthcheck starts passing.
3. **Retrieve the generated password** from the logs:
   ```bash
   docker compose logs reconner
   ```
   On the very first boot only (when `config.json` doesn't exist yet), the
   entrypoint prints a boxed banner:
   ```
   ┌───────────────────────────────────────────────────────────────┐
   │  Reconner — generated admin credentials (FIRST BOOT ONLY)      │
   ├───────────────────────────────────────────────────────────────┤
   │  username: admin                                                │
   │  password: <20-character random string>                         │
   ├───────────────────────────────────────────────────────────────┤
   │  Save it now. It is stored in the config inside the volume;    │
   │  retrieve later with: ...                                       │
   └───────────────────────────────────────────────────────────────┘
   ```
4. **Default username** is `admin` — or whatever `ADMIN_USER` is set to in
   `.env` (only read on the boot that creates the config).
5. **URL**: open `http://<server-ip>:8080` and log in with that
   username/password.
6. **If `ADMIN_PASSWORD` is set in `.env` before the first start**, the
   entrypoint writes *that* value into `config.json` instead of generating a
   random one — in that case nothing is printed in the logs, because nothing
   was generated (there is nothing secret to reveal that you didn't already
   choose).
7. **The generated password is printed exactly once** — only on the boot
   where `config.json` is created. It is not re-printed on subsequent starts.
8. **Where it's persisted**: in plaintext inside `config.json`, under the
   `admin_password` key, at the path `$RECON_CONFIG` (`/data/config.json`
   inside the container — physically the `reconner-data` named volume on the
   host). Retrieve it any time with:
   ```bash
   docker compose exec reconner sh -c 'grep admin_password "$RECON_CONFIG"'
   ```
   (equivalently: `make docker-password`, which runs this exact command.)
9. **After restarting the container** (`docker compose restart`, `stop` +
   `start`, or a rebuild with the same volume attached), the entrypoint finds
   the existing `config.json` and explicitly leaves it — and the database —
   untouched, logging `Existing config found ... leaving it (and the
   database) untouched.` You keep the same login every time.
10. **If you delete the persistent volume** (`docker compose down -v`), the
    next start has no `config.json`, so the entrypoint treats it as a first
    boot again: a brand-new random password is generated (or `.env`'s
    `ADMIN_PASSWORD` is used, if set) — but this also means **all prior scan
    data, targets, and findings are gone**, since they lived in that same
    volume.

There is currently **no built-in password-reset command** in the repository
— don't expect a `reconner reset-password` or similar. To change the admin
password on an existing install without losing your data, edit the persisted
`config.json` directly and restart. `vi`/`nano` are **not** installed in the
runtime image, but `sed` is (it ships with Debian by default), so this works
without adding anything to the container:

```bash
docker compose exec reconner sh -c \
  'sed -i "s/\"admin_password\": \"[^\"]*\"/\"admin_password\": \"YOUR-NEW-PASSWORD\"/" "$RECON_CONFIG"'
docker compose restart reconner
```

## Updating Reconner

```bash
git pull                        # get the latest source
docker compose up -d --build    # rebuild the image, restart the container
```

or, if you're tracking the prebuilt GHCR image instead of building locally:

```bash
docker compose pull
docker compose up -d
```

Either path is safe to run at any time. The database, `config.json` (and
therefore your admin login), screenshots, wordlists and nuclei templates all
live in the `reconner-data` **named volume**, not in the image — rebuilding
or pulling a new image replaces the tool-chain and application binary, but
**never touches `/data`**, so nothing in it is lost across an update.

## Toolchain

All 30 of the following are required, built or downloaded during the Docker
**image build**, and individually confirmed to actually execute by a
build-time verification step before the image is considered done — none of
it is installed at container startup, and none of it requires the host to
have Go, Python, Node, or Rust.

| Tool | Purpose | How it's bundled |
|---|---|---|
| subfinder | Passive subdomain enumeration | Go build |
| httpx | Live-host HTTP probing & fingerprinting | Go build |
| nuclei | Template-based vulnerability scanning | Go build |
| katana | Web crawling | Go build |
| naabu | Fast port scanning (SYN, needs `NET_RAW`) | Go build |
| dnsx | DNS resolution/toolkit | Go build |
| alterx | Subdomain permutation wordlist generation | Go build |
| asnmap | ASN → IP-range mapping | Go build |
| uncover | Search-engine-based asset discovery | Go build |
| gau | Historical URL mining (GetAllUrls) | Go build |
| waybackurls | Wayback Machine URL mining | Go build |
| assetfinder | Subdomain/asset discovery | Go build |
| qsreplace | Query-string parameter replacement | Go build |
| dalfox | XSS scanning | Go build |
| subzy | Subdomain-takeover detection | Go build |
| gowitness | Web screenshotting | Go build |
| hakrawler | Fast web crawling | Go build |
| puredns | Massively parallel DNS resolution/brute-force (uses massdns) | Go build |
| scilla | DNS/subdomain/port enumeration | Go build |
| shuffledns | Mass DNS resolution & subdomain brute-force (uses massdns) | Go build |
| massdns | High-performance DNS resolver — backs puredns/shuffledns | Compiled from source |
| dirsearch | Directory/file brute-forcing | Python venv |
| uro | URL de-duplication/filtering | Python venv |
| waymore | Extended historical URL mining | Python venv |
| feroxbuster | Recursive content discovery | Official release binary (pinned `2.13.1`) |
| findomain | Subdomain enumeration | Official release binary (pinned `10.0.1`) |
| hydra | Network credential brute-force (opt-in in-app) | apt |
| sqlmap | SQLi confirmation/exploitation (opt-in in-app) | apt |
| nmap | Port/service/version scanning | apt |
| python3 | Runs the Python tool-chain + the Ingram camera scanner | apt |

**Plus, bundled but outside the 30-tool count above:** headless **Chromium**,
used for XSS/DOM execution proof and screenshotting — also verified to run at
build time.

Every module in the app degrades gracefully if a tool is somehow unavailable,
but in the official Docker image, all 30 tools plus Chromium are present and
verified at build time (see [Troubleshooting](#troubleshooting) for how to
re-check this yourself in a running container).

## Configuration

Copy `.env.example` to `.env` and adjust before the **first** `docker compose
up` (these are only read when `config.json` doesn't exist yet):

| Variable | Purpose | Default |
|---|---|---|
| `HOST_PORT` | Host port the dashboard is published on (container always listens on 8080 internally) | `8080` |
| `ADMIN_USER` | Initial admin username, written on first boot only | `admin` |
| `ADMIN_PASSWORD` | Initial admin password. Leave **blank** for a strong random password generated on first boot (see [First Login](#first-login)); set a value to pin a known password instead | *(blank → random)* |

Beyond `.env`, every scanner, worker pool, rate limit, and optional API key
(e.g. Shodan) is tunable in the persisted `config.json` — see
[`internal/config/config.go`](internal/config/config.go) for the full,
documented field list.

## Ports

- The application **always listens on `8080` inside the container** — fixed,
  not configurable via environment variable.
- `docker-compose.yml` maps it to the host with `${HOST_PORT:-8080}:8080`.
  Set `HOST_PORT` in `.env` to publish on a different host port.
- The dashboard is an admin panel with no additional network authentication
  in front of it by default — expose the *host* port only behind a
  firewall/VPN/security group, or front it with a reverse proxy + TLS.

## Persistent Data

Everything Reconner writes at runtime — the SQLite database, `config.json`
(and therefore the admin password), screenshots, wordlists, and nuclei
templates — lives under `/data` inside the container, mounted from the named
volume `reconner-data` in `docker-compose.yml`:

```yaml
volumes:
  - reconner-data:/data
```

- Rebuilding the image (`docker compose up -d --build`), pulling an update
  (`docker compose pull`), or `docker compose down` followed by `up` again
  **never touches this volume** — targets, findings, and your login persist
  across every upgrade.
- Tool binaries and application code live **in the image**, not the volume,
  so every rebuild replaces them cleanly — no stale/leftover tool versions.
- To wipe everything and start completely fresh: `docker compose down -v`
  (irreversible — deletes the database, config, and admin password).

## Troubleshooting

**Container doesn't start / exits immediately**
```bash
docker compose logs reconner
```
Look at the actual error near the bottom — most first-boot failures are
either a port conflict (below) or a permissions issue if `/data` was changed
to a host bind mount instead of the named volume as shipped.

**Port already in use**
Set a different `HOST_PORT` in `.env` (the container always uses `8080`
internally), then:
```bash
docker compose down
docker compose up -d
```

**Viewing logs**
```bash
docker compose logs -f reconner     # follow live
docker compose logs --tail 200 reconner
```

**Verifying the bundled tool-chain inside a running container**
```bash
docker compose exec reconner sh -c '
  for t in subfinder httpx nuclei katana naabu dnsx alterx asnmap uncover \
           gau waybackurls assetfinder qsreplace dalfox subzy \
           gowitness hakrawler puredns scilla shuffledns \
           dirsearch feroxbuster findomain hydra sqlmap uro waymore \
           massdns nmap python3 chromium; do
    command -v "$t" >/dev/null 2>&1 && echo "OK      $t" || echo "MISSING $t"
  done'
```
That is all 30 required tools plus Chromium (31 lines). Every line should
read `OK` — the image build already enforces this, so a `MISSING` line here
would mean the container is running an older or custom image, not one built
from the current Dockerfile.

**Rebuilding from scratch (no cache)**
```bash
docker compose build --no-cache
docker compose up -d
```

**Stopping / starting**
```bash
docker compose stop      # stop, keep the container
docker compose start     # resume it
docker compose down      # stop and remove the container (volume is kept)
docker compose up -d     # recreate and start
```

## Development

The Docker workflow above is for **running** Reconner and needs nothing but
Docker. Developing the Go backend or the React dashboard directly on your
machine is a separate, optional workflow with its own requirements — these
are **not** needed to run Reconner via Docker:

**Requirements (development only):** Go ≥ 1.26, Node.js ≥ 18, a C compiler
(for the embedded-SQLite CGO driver).

```bash
git clone https://github.com/rootdr-backup/Reconner.git
cd Reconner

make            # builds the frontend bundle and the `reconner` binary
./reconner serve
```
Useful `make` targets: `make test` (Go test suite), `make tidy` (`go mod
tidy`), `make clean` (remove build artifacts), and the `docker-*` targets
(`make docker-up`, `make docker-logs`, `make docker-password`,
`make docker-shell`, `make docker-destroy`, `make docker-buildx`), which wrap
the exact `docker compose` commands documented above.

## Security / Authorization

Reconner is built for **authorized** security testing — bug-bounty programs
you're enrolled in, and assets you own or have explicit written permission to
test. It actively sends injection payloads, brute-force attempts, and port
scans; running it against systems without authorization is illegal and
unethical, and is entirely the operator's responsibility. Additional
container-level notes:

- The container runs as **root** on purpose: `naabu`/`nmap` SYN scans need
  raw sockets. `docker-compose.yml` grants only `NET_RAW` and `NET_ADMIN`
  (not full `privileged`) for exactly this; remove them if you only ever run
  web/DAST scans with no port/service scanning.
- **No secret is ever baked into the image.** `ADMIN_PASSWORD` is not set in
  the Dockerfile; it's generated (or read from `.env`) by the entrypoint at
  container start and stored only in the `/data` volume.
- Don't commit your `.env` — it's already in `.gitignore`.
- For security-sensitive reports about Reconner itself, see
  [SECURITY.md](SECURITY.md).

## Feedback & bug reports

Found a bug, a false positive, or have an idea? Please
[open an issue](https://github.com/rootdr-backup/reconner/issues) —
reproduction steps and log output help a lot. You can also reach out on
Telegram [@rootdr_research](https://t.me/rootdr_research).

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
for any misuse or damage caused by this tool. **You** are responsible for
your own actions.

## License

Released under the [MIT License](LICENSE).

---

<p align="center">
  Crafted by <b>RootDR</b> · <a href="https://t.me/rootdr_research">@rootdr_research</a>
</p>
