# Reconner — Setup Guide

Self-hosted offensive-security recon & vulnerability platform.
**Backend:** Go (embedded SQLite, WebSocket). **Frontend:** React + TypeScript + Vite + Tailwind.

Everything below runs as a **normal user** — no root required. (Some *network*-scan
features need raw sockets and thus elevated privileges, the same as `nmap`/`naabu`.)

---

## 1. Requirements

| Tool | Version | Why |
|------|---------|-----|
| **Go** | **≥ 1.23** | backend build (chromedp for the DOM-XSS engine) |
| **GCC / build-essential** | any | `CGO_ENABLED=1` for the embedded SQLite driver |
| **Node.js** | ≥ 18 | frontend build |
| **Chromium/Chrome** | recent | DOM-XSS module (auto-detected; optional) |

Optional external CLI tools (auto-used if on `PATH`, silently skipped if absent):
`subfinder`, `httpx`, `dnsx`, `katana`, `naabu`, `nuclei`, `sqlmap`, `dirsearch`,
`hydra`, and friends.

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y build-essential nodejs npm chromium-browser
# Go 1.23+ (if your distro ships an older one): download from https://go.dev/dl/
# and put /usr/local/go/bin on your PATH.
```

---

## 2. Get the code & build

```bash
git clone https://github.com/rootdr-backup/reconner.git
cd reconner

make            # builds the frontend bundle AND the `reconner` binary
```

`make` is the whole build. Individual targets exist too: `make frontend`,
`make backend`, `make test`, `make clean`.

Upgrading an existing install? The database auto-migrates on start (new
tables/columns are added, nothing is dropped) — no manual step needed. To be
safe you can back it up first:

```bash
cp ~/.recon-platform/recon.db ~/.recon-platform/recon.db.bak 2>/dev/null || true
```

---

## 3. Run

```bash
./reconner serve
```

Then open **http://127.0.0.1:8080** and log in as `admin` (default password
`change_m)_e` — you'll be forced to change it on first login).

> By default the server binds **127.0.0.1** (local only). To expose the dashboard
> on a VPS, set `"host": "0.0.0.0"` in the config — **only behind a firewall or
> VPN**. The startup banner prints a warning when it's bound to all interfaces.

Reconner is also a full CLI:

```bash
./reconner scan example.com            # full scan (subdomains + everything)
./reconner scan example.com --single   # just this host, no subdomain enum
./reconner scan example.com --quick    # fast pass
./reconner report example.com --html --md --pdf --out ./reports
./reconner list                        # targets + finding counts
./reconner modules                     # list every scan module
```

---

## 4. Configuration

Config lives at `~/.recon-platform/config.json` (created on first run from
defaults). Every field is documented inline in
[`internal/config/config.go`](internal/config/config.go). Key ones:

| Field | Purpose |
|-------|---------|
| `host` / `port` | Bind address (default `127.0.0.1:8080`). |
| `blind_xss_callback_url` | **This app's public URL** (e.g. `http://YOUR_PUBLIC_IP:8080`). Enables blind-XSS / OAST beacons that call back here and raise confirmed out-of-band findings. Empty → blind XSS is skipped (stored XSS still runs). |
| `interactsh_server` | OAST server for blind SSRF/RCE out-of-band detection. |
| `limits.max_urls_per_module` | Cap URLs/params per module (0 = unlimited). |
| `securitytrails_api_key` / `shodan_api_key` | Optional passive-intel keys — set per deployment, never hardcode. |

**DOM-XSS browser:** auto-detected. To force a path:
`export RECON_CHROME_PATH=/usr/bin/chromium-browser` before starting.

The optional AI-assisted orchestrator is **off by default**; when enabled it reads
`ANTHROPIC_API_KEY` from the environment only.

---

## 5. Scan modules

Toggle per scan in the UI (or `--modules a,b,c` on the CLI). Highlights:

- **Native DAST** — context-aware reflected/stored XSS, SQLi, NoSQLi, SSRF, IDOR, LFI, SSTI, XXE, CmdI, open redirects.
- **Out-of-band (OAST)** — blind SSRF / RCE / SQLi / SSTI / Log4Shell via callback correlation.
- **Verification engine** — re-confirms findings and assigns confidence + priority (a major false-positive killer).
- **Exposure** — GraphQL introspection + deep analysis, API specs, open buckets, `.git`/`.svn`/`.env` disclosure, JWT weaknesses.
- **Network** — port/service/version detection, network-CVE scanning, SSH/SMB/RDP/VNC brute (opt-in), initial-access & edge-device checks, IP-camera auditing.

> Intrusive modules — **race conditions, request smuggling, network brute-force,
> initial-access, and camera auditing** — are **off by default** and clearly
> marked "authorized targets only" in the UI.

Reports export as **Markdown**, **standalone HTML**, and **PDF** per target.

---

## 6. Troubleshooting

- **`go build` fails on sqlite** → ensure `CGO_ENABLED=1` and a C compiler is installed.
- **`go` version error** → need ≥ 1.23 (`go version` to check).
- **DOM-XSS skipped** → no Chromium found; install it or set `RECON_CHROME_PATH`.
- **A scanner "finds nothing"** → make sure the real ProjectDiscovery binary is on
  `PATH` (e.g. `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`),
  not a stale shim.
- **Can't reach the dashboard remotely** → by design it binds `127.0.0.1`; set
  `"host": "0.0.0.0"` in the config (behind a firewall/VPN) and restart.
