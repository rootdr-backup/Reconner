#!/usr/bin/env bash
# Reconner CLI — Linux server setup (Debian/Ubuntu).
# Installs EVERY prerequisite (Go, build deps, Chromium, all recon tools),
# builds the reconner CLI, and installs it to /usr/local/bin so `reconner`
# works from anywhere. Safe to re-run: it skips what's already present.
#
#   sudo bash scripts/reconner-linux-setup.sh
set -uo pipefail

BOLD=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; B=$'\033[36m'; N=$'\033[0m'
ok(){ echo "${G}✓${N} $*"; }
info(){ echo "${BOLD}${B}▶ $*${N}"; }
warn(){ echo "${Y}!${N} $*"; }
err(){ echo "${R}✗${N} $*"; }

# Find the repo root (the dir with go.mod) whether this script sits at the repo
# root (setup.sh) or in scripts/.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/go.mod" ]; then
  REPO_DIR="$SCRIPT_DIR"
elif [ -f "$SCRIPT_DIR/../go.mod" ]; then
  REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
else
  REPO_DIR="$SCRIPT_DIR"
fi
GO_VERSION="1.23.6"
# Where go-installed tools land; make sure it's on PATH for the build user.
export GOBIN="/usr/local/bin"          # install recon tools straight into PATH
export PATH="/usr/local/go/bin:/usr/local/bin:${HOME}/.local/bin:$PATH"

SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"

# ── 1. system packages ───────────────────────────────────────────────────────
info "Installing system packages (apt)…"
if command -v apt-get >/dev/null 2>&1; then
  $SUDO apt-get update -qq
  $SUDO apt-get install -y -qq \
      build-essential libsqlite3-dev pkg-config \
      git curl wget unzip ca-certificates \
      python3 python3-pip pipx \
      chromium-browser massdns feroxbuster 2>/dev/null \
    || $SUDO apt-get install -y -qq build-essential libsqlite3-dev git curl wget python3 python3-pip pipx
  # chromium package name varies across distros
  command -v chromium >/dev/null 2>&1 || command -v chromium-browser >/dev/null 2>&1 || \
    $SUDO apt-get install -y -qq chromium 2>/dev/null || true
  ok "system packages"
else
  warn "apt-get not found — install build-essential, libsqlite3-dev, git, curl, python3, chromium manually"
fi

# ── 2. Go (needs >=1.23 for chromedp) ────────────────────────────────────────
NEED_GO=1
if command -v go >/dev/null 2>&1; then
  cur="$(go version | grep -oE 'go[0-9]+\.[0-9]+' | tr -d go)"
  major="${cur%%.*}"; minor="${cur##*.}"
  if [ "$major" -gt 1 ] || { [ "$major" -eq 1 ] && [ "$minor" -ge 23 ]; }; then NEED_GO=0; fi
fi
if [ "$NEED_GO" -eq 1 ]; then
  info "Installing Go ${GO_VERSION}…"
  ARCH="$(uname -m)"; GOARCH="amd64"; [ "$ARCH" = "aarch64" ] && GOARCH="arm64"
  wget -qO /tmp/go.tgz "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz"
  $SUDO rm -rf /usr/local/go && $SUDO tar -C /usr/local -xzf /tmp/go.tgz && rm -f /tmp/go.tgz
  ok "Go $($(command -v /usr/local/go/bin/go) version | awk '{print $3}')"
else
  ok "Go $(go version | awk '{print $3}')"
fi
GO=/usr/local/go/bin/go

# A Python "httpx" (the HTTP library's CLI) commonly shadows ProjectDiscovery's
# httpx and breaks http_probe. Remove it before installing the real one.
if command -v httpx >/dev/null 2>&1 && ! httpx -version 2>&1 | grep -qi projectdiscovery; then
  warn "removing a non-ProjectDiscovery 'httpx' (python) that would shadow the real tool…"
  pipx uninstall httpx >/dev/null 2>&1 || true
  $SUDO pip3 uninstall -y httpx >/dev/null 2>&1 || true
  # remove the shim wherever it is (python httpx is a script, not a Go binary,
  # so `go install` refuses to overwrite it).
  for p in "$HOME/.local/bin/httpx" /usr/bin/httpx /usr/local/bin/httpx; do
    [ -e "$p" ] && ! head -c4 "$p" 2>/dev/null | grep -q ELF && $SUDO rm -f "$p" 2>/dev/null || true
  done
fi

# ── 3. recon tools ───────────────────────────────────────────────────────────
# Install straight into $GOBIN and check for THAT binary (not just any name in
# PATH) so a shadowing python tool can never cause a skip.
gi(){ # gi <cmd> <module@version>
  if [ -x "$GOBIN/$1" ]; then ok "$1"; return; fi
  info "go install $1…"
  if $SUDO env PATH="$PATH" GOBIN="$GOBIN" "$GO" install "$2" >/dev/null 2>&1; then ok "$1"; else err "$1 failed"; fi
}
info "Installing recon tools…"
gi subfinder   github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
gi httpx       github.com/projectdiscovery/httpx/cmd/httpx@latest
gi nuclei      github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
gi katana      github.com/projectdiscovery/katana/cmd/katana@latest
gi naabu       github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
gi dnsx        github.com/projectdiscovery/dnsx/cmd/dnsx@latest
gi alterx      github.com/projectdiscovery/alterx/cmd/alterx@latest
gi asnmap      github.com/projectdiscovery/asnmap/cmd/asnmap@latest
gi shuffledns  github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
gi dalfox      github.com/hahwul/dalfox/v2@latest
gi gau         github.com/lc/gau/v2/cmd/gau@latest
gi waybackurls github.com/tomnomnom/waybackurls@latest
gi assetfinder github.com/tomnomnom/assetfinder@latest
gi hakrawler   github.com/hakluke/hakrawler@latest
gi gowitness   github.com/sensepost/gowitness@latest
gi puredns     github.com/d3mondev/puredns/v2@latest
gi subzy       github.com/PentestPad/subzy@latest
gi scilla      github.com/edoardottt/scilla/cmd/scilla@latest

# ── 4. python tools ──────────────────────────────────────────────────────────
# Install SYSTEM-WIDE (into /usr/local) so the scripts + their libs are world-
# readable. pipx installs into ~/.local (and under sudo that means /root/.local,
# which the service user can't read → tools show "missing"). So we use pip.
info "Installing python tools (pip, system-wide)…"
$SUDO pip3 install --break-system-packages -q dirsearch waymore uro sqlmap 2>/dev/null \
  || $SUDO pip3 install -q dirsearch waymore uro sqlmap 2>/dev/null || true
for pkg in dirsearch waymore uro sqlmap; do
  command -v "$pkg" >/dev/null 2>&1 && ok "$pkg" || err "$pkg failed"
done

# ── 4b. release-binary tools (not go-installable) ─────────────────────────────
# findomain (Rust) and feroxbuster (Rust) ship as prebuilt binaries — grab them
# straight from GitHub releases into /usr/local/bin so nothing stays "missing".
ARCH="$(uname -m)"

# findomain
if [ -x /usr/local/bin/findomain ]; then ok "findomain"; else
  info "installing findomain…"
  fd_url="https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip"
  [ "$ARCH" = "aarch64" ] && fd_url="https://github.com/findomain/findomain/releases/latest/download/findomain-aarch64.zip"
  if curl -fsSL "$fd_url" -o /tmp/findomain.zip 2>/dev/null && unzip -o /tmp/findomain.zip -d /tmp >/dev/null 2>&1; then
    $SUDO mv /tmp/findomain /usr/local/bin/findomain && $SUDO chmod +x /usr/local/bin/findomain && ok "findomain" || err "findomain failed"
  else err "findomain download failed"; fi
  rm -f /tmp/findomain.zip
fi

# feroxbuster
if [ -x /usr/local/bin/feroxbuster ] || command -v feroxbuster >/dev/null 2>&1; then ok "feroxbuster"; else
  info "installing feroxbuster…"
  if curl -fsSL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh -o /tmp/ferox.sh 2>/dev/null; then
    ( cd /tmp && $SUDO bash /tmp/ferox.sh /usr/local/bin >/dev/null 2>&1 ) && ok "feroxbuster" \
      || { $SUDO apt-get install -y -qq feroxbuster >/dev/null 2>&1 && ok "feroxbuster (apt)" || err "feroxbuster failed"; }
  else err "feroxbuster download failed"; fi
  rm -f /tmp/ferox.sh
fi

# massdns (needed by puredns/shuffledns for fast resolution)
if command -v massdns >/dev/null 2>&1; then ok "massdns"; else
  info "installing massdns…"
  if $SUDO apt-get install -y -qq massdns >/dev/null 2>&1; then ok "massdns (apt)"; else
    if git clone --depth 1 https://github.com/blechschmidt/massdns /tmp/massdns >/dev/null 2>&1 \
       && make -C /tmp/massdns >/dev/null 2>&1; then
      $SUDO mv /tmp/massdns/bin/massdns /usr/local/bin/ && ok "massdns (built)" || err "massdns failed"
    else err "massdns failed"; fi
    rm -rf /tmp/massdns
  fi
fi

# ── 5a. consolidate every tool into /usr/local/bin ───────────────────────────
# Depending on how `go install` / pipx resolved HOME under sudo, some binaries
# can land in /root/go/bin or a user's ~/go/bin instead of GOBIN. The service
# looks in /usr/local/bin, so copy/link anything found elsewhere into it. This
# is what prevents the "tools show red in the UI even though setup said ✓" bug.
info "Consolidating tools into /usr/local/bin…"
GO_TOOLS="subfinder httpx nuclei katana naabu dnsx alterx asnmap shuffledns dalfox gau waybackurls assetfinder hakrawler gowitness puredns subzy scilla"
# Copy REAL, dereferenced binaries (cp -L) and make them world-readable. A
# symlink into /root/go/bin looks fine to root but the non-root service account
# can't traverse /root (mode 0700), so os.Stat fails and the tool shows red.
# Real copies in /usr/local/bin dodge that entirely.
SRC_BINS="/root/go/bin ${HOME}/go/bin /usr/local/bin"
for t in $GO_TOOLS; do
  # if /usr/local/bin/$t is already a REAL file (not a symlink), leave it
  if [ -f "/usr/local/bin/$t" ] && [ ! -L "/usr/local/bin/$t" ]; then continue; fi
  for d in $SRC_BINS; do
    if [ -f "$d/$t" ]; then
      $SUDO rm -f "/usr/local/bin/$t" 2>/dev/null
      $SUDO cp -L "$d/$t" "/usr/local/bin/$t" 2>/dev/null && $SUDO chmod 755 "/usr/local/bin/$t" && break
    fi
  done
done
$SUDO chmod 755 /usr/local/bin/* 2>/dev/null || true

# ── 5. nuclei templates + resolvers ──────────────────────────────────────────
# CRITICAL: install templates for the SERVICE USER, not root. `sudo nuclei
# -update-templates` drops them in /root/nuclei-templates, which the service
# (running as $RUN_USER) can't read → nuclei exits 1 and finds nothing. Run the
# update AS the run-user so templates land in their home where the service looks.
RUN_USER="${SUDO_USER:-$(whoami)}"
RUN_HOME="$(getent passwd "$RUN_USER" | cut -d: -f6)"; RUN_HOME="${RUN_HOME:-$HOME}"
if command -v nuclei >/dev/null 2>&1; then
  info "Updating nuclei templates (as $RUN_USER)…"
  if [ "$RUN_USER" != "root" ] && [ -n "$SUDO" ]; then
    $SUDO -u "$RUN_USER" env HOME="$RUN_HOME" PATH="$PATH" nuclei -update-templates -silent >/dev/null 2>&1 || true
  else
    nuclei -update-templates -silent >/dev/null 2>&1 || true
  fi
  # sanity: report how many templates the run-user can actually see
  tdir="$RUN_HOME/nuclei-templates"; [ -d "$RUN_HOME/.local/nuclei-templates" ] && tdir="$RUN_HOME/.local/nuclei-templates"
  tn=$($SUDO -u "$RUN_USER" sh -c "find '$tdir' -name '*.yaml' 2>/dev/null | wc -l" 2>/dev/null | tr -dc '0-9')
  [ "${tn:-0}" -gt 0 ] 2>/dev/null && ok "nuclei templates: $tn ($tdir)" || warn "nuclei templates not found for $RUN_USER — run: nuclei -update-templates"
fi
mkdir -p "$RUN_HOME/.config/reconner"
[ -s "$RUN_HOME/.config/reconner/resolvers.txt" ] || \
  $SUDO -u "$RUN_USER" curl -fsSL https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
    -o "$RUN_HOME/.config/reconner/resolvers.txt" 2>/dev/null || true

# ── 6a. build the web UI (frontend) ──────────────────────────────────────────
# A prebuilt frontend/dist ships in the repo, so this is optional. If node is
# present we rebuild it fresh; otherwise we use the shipped dist.
if [ -d "$REPO_DIR/frontend" ]; then
  if command -v npm >/dev/null 2>&1; then
    info "Building web UI (npm)…"
    ( cd "$REPO_DIR/frontend" && npm install --no-audit --no-fund >/dev/null 2>&1 && npm run build >/dev/null 2>&1 ) \
      && ok "web UI built" || warn "npm build failed — using the prebuilt frontend/dist that ships with the repo"
  fi
  [ -f "$REPO_DIR/frontend/dist/index.html" ] && ok "web UI ready (frontend/dist)" \
    || warn "frontend/dist missing — the web UI will 404 until it's built"
fi

# ── 6b. build + install the CLI/server ───────────────────────────────────────
info "Building reconner…"
cd "$REPO_DIR"
if CGO_ENABLED=1 "$GO" build -o /tmp/reconner ./cmd/reconner; then
  $SUDO mv /tmp/reconner /usr/local/bin/reconner
  $SUDO chmod +x /usr/local/bin/reconner
  ok "reconner installed to /usr/local/bin/reconner"
else
  err "build failed — check the Go/CGO/libsqlite3-dev setup above"; exit 1
fi

# persist PATH for future logins
if ! grep -q '/usr/local/go/bin' /etc/profile.d/reconner.sh 2>/dev/null; then
  echo 'export PATH="/usr/local/go/bin:/usr/local/bin:$HOME/.local/bin:$PATH"' | $SUDO tee /etc/profile.d/reconner.sh >/dev/null
fi

# ── 7. install the ALWAYS-ON web watchtower service ───────────────────────────
# Runs `reconner serve` 24/7 (the web UI): survives crashes (Restart=always)
# and reboots (enabled). WorkingDirectory MUST be the repo so the server can
# find ./frontend/dist. Host/port and admin login live in
# ~/.recon-platform/config.json.
if command -v systemctl >/dev/null 2>&1; then
  info "Installing always-on web watchtower service (systemd)…"
  RUN_USER="${SUDO_USER:-$(whoami)}"
  $SUDO tee /etc/systemd/system/reconner.service >/dev/null <<UNIT
[Unit]
Description=Reconner web watchtower (always on)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${REPO_DIR}
Environment=PATH=/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=/usr/local/bin/reconner serve
Restart=always
RestartSec=5
StartLimitIntervalSec=0

[Install]
WantedBy=multi-user.target
UNIT
  # remove the old telegram-era unit name if it exists
  $SUDO systemctl disable --now reconner-bot 2>/dev/null || true
  $SUDO rm -f /etc/systemd/system/reconner-bot.service 2>/dev/null || true
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable reconner 2>/dev/null || true
  # restart (not just start) so a freshly rebuilt binary actually replaces the
  # running one — `enable --now` alone leaves an already-running old process up.
  $SUDO systemctl restart reconner 2>/dev/null && ok "web watchtower running latest build (always on)" \
    || warn "service installed but not started — run: sudo systemctl start reconner"
else
  warn "systemd not found — start the web UI manually with: reconner serve"
fi

# figure out the URL to print
PORT="$(grep -oE '\"port\"[[:space:]]*:[[:space:]]*[0-9]+' "$HOME/.recon-platform/config.json" 2>/dev/null | grep -oE '[0-9]+' | tail -1)"
PORT="${PORT:-8080}"
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"; IP="${IP:-<server-ip>}"

echo
ok "Setup complete."
echo "The web watchtower runs 24/7 as a service. Open it in your browser:"
echo "  ${BOLD}http://${IP}:${PORT}${N}"
echo "  login: ${BOLD}admin${N} / (the admin_password in ~/.recon-platform/config.json)"
echo
echo "Manage the service:"
echo "  ${BOLD}sudo systemctl status reconner${N}      # is it running?"
echo "  ${BOLD}journalctl -u reconner -f${N}            # live logs"
echo "  ${BOLD}sudo systemctl restart reconner${N}      # restart after an update"
echo
echo "One-off CLI scans still work too:"
echo "  ${BOLD}reconner scan example.com${N}"
