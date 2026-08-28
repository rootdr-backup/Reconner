#!/usr/bin/env bash
# Reconner CLI — macOS installer (Intel / MacBook Pro 2017 friendly).
# Builds the full-power CLI, installs it so `reconner` works from anywhere,
# and optionally installs a launchd service for scheduled monitoring.
set -euo pipefail

BOLD=$'\033[1m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; NC=$'\033[0m'
info(){ echo "${BOLD}▶ $*${NC}"; }
ok(){ echo "${GREEN}✓ $*${NC}"; }
warn(){ echo "${YELLOW}! $*${NC}"; }

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="/usr/local/bin"
cd "$REPO_DIR"

# ── 1. prerequisites ────────────────────────────────────────────────────────
if ! command -v go >/dev/null 2>&1; then
  warn "Go not found. Install with: brew install go   (then re-run this script)"
  exit 1
fi
# CGO (SQLite) needs the Xcode command-line tools.
if ! xcode-select -p >/dev/null 2>&1; then
  warn "Xcode command-line tools missing — installing (a dialog may pop up)…"
  xcode-select --install || true
  echo "Re-run this script once the tools finish installing."
  exit 1
fi

# ── 2. build (Intel amd64, CGO on for SQLite) ───────────────────────────────
info "Building reconner (darwin/amd64, CGO on)…"
ARCH="$(uname -m)"
GOARCH="amd64"; [ "$ARCH" = "arm64" ] && GOARCH="arm64"   # also fine on Apple Silicon
CGO_ENABLED=1 GOOS=darwin GOARCH="$GOARCH" go build -o reconner ./cmd/reconner
ok "Built ./reconner"

# ── 3. install so it works everywhere ───────────────────────────────────────
info "Installing to $BIN_DIR/reconner (may prompt for sudo)…"
sudo mkdir -p "$BIN_DIR"
sudo cp -f reconner "$BIN_DIR/reconner"
sudo chmod +x "$BIN_DIR/reconner"
# macOS Gatekeeper: clear the quarantine flag on our own binary.
sudo xattr -d com.apple.quarantine "$BIN_DIR/reconner" 2>/dev/null || true
ok "reconner installed — try:  reconner scan example.com"

# ── 4. recon tools (optional but recommended) ───────────────────────────────
cat <<'EOF'

Install the external recon tools for full power (Homebrew + Go):
  brew install chromium                       # DOM-XSS + screenshots
  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest
  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  go install github.com/projectdiscovery/katana/cmd/katana@latest
  go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
  go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
  go install github.com/hahwul/dalfox/v2@latest
  go install github.com/tomnomnom/waybackurls@latest
  go install github.com/lc/gau/v2/cmd/gau@latest
  go install github.com/tomnomnom/assetfinder@latest
  go install github.com/sensepost/gowitness@latest
  go install github.com/d3mondev/puredns/v2@latest
  go install github.com/projectdiscovery/alterx/cmd/alterx@latest
  pipx install dirsearch waymore
  brew install feroxbuster

Make sure your Go bin is on PATH (add to ~/.zshrc):
  export PATH="$HOME/go/bin:$HOME/.local/bin:/usr/local/bin:$PATH"

EOF
ok "Setup complete. 'reconner' is available in every new terminal."
