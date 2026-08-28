#!/usr/bin/env bash
# Reconner — macOS dependency doctor.
# Detects every required tool (Homebrew, Go, pipx, Chromium + all recon tools)
# and installs whatever is missing. Safe to re-run: it skips what's present.
set -uo pipefail

BOLD=$'\033[1m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; BLUE=$'\033[36m'; NC=$'\033[0m'
ok(){   echo "${GREEN}✓${NC} $*"; }
miss(){ echo "${YELLOW}•${NC} $*"; }
err(){  echo "${RED}✗${NC} $*"; }
hdr(){  echo "\n${BOLD}${BLUE}$*${NC}"; }

INSTALLED=(); FAILED=(); SKIPPED=()

have(){ command -v "$1" >/dev/null 2>&1; }

# ── 0. macOS + Xcode CLT ─────────────────────────────────────────────────────
if [ "$(uname)" != "Darwin" ]; then err "This script is for macOS."; exit 1; fi
if ! xcode-select -p >/dev/null 2>&1; then
  miss "Xcode command-line tools — installing (accept the popup, then re-run)…"
  xcode-select --install || true
  exit 1
fi
ok "Xcode command-line tools"

# ── 1. Homebrew ──────────────────────────────────────────────────────────────
if ! have brew; then
  miss "Homebrew — installing…"
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" \
    && INSTALLED+=(homebrew) || FAILED+=(homebrew)
fi
# Load brew into this shell (Intel = /usr/local, Apple Silicon = /opt/homebrew).
if [ -x /opt/homebrew/bin/brew ]; then eval "$(/opt/homebrew/bin/brew shellenv)";
elif [ -x /usr/local/bin/brew ]; then eval "$(/usr/local/bin/brew shellenv)"; fi
have brew && ok "Homebrew"

# ── 2. Go + pipx (via brew) ──────────────────────────────────────────────────
brew_need(){ # brew_need <cmd> <formula> [--cask]
  local cmd="$1" formula="$2" cask="${3:-}"
  if have "$cmd"; then ok "$cmd"; return; fi
  miss "$cmd — brew install $formula $cask"
  if brew install $cask "$formula" >/dev/null 2>&1; then ok "$cmd installed"; INSTALLED+=("$cmd"); else err "$cmd failed"; FAILED+=("$cmd"); fi
}
hdr "Core toolchain"
brew_need go go
brew_need pipx pipx
have pipx && pipx ensurepath >/dev/null 2>&1 || true

# PATH for go/pipx bins (needed both now and in future shells).
export PATH="$HOME/go/bin:$HOME/.local/bin:/usr/local/bin:/opt/homebrew/bin:$PATH"

# ── 3. Recon tools ───────────────────────────────────────────────────────────
go_need(){ # go_need <cmd> <module@version>
  local cmd="$1" mod="$2"
  if have "$cmd"; then ok "$cmd"; return; fi
  miss "$cmd — go install $mod"
  if go install "$mod" >/dev/null 2>&1; then ok "$cmd installed"; INSTALLED+=("$cmd"); else err "$cmd failed"; FAILED+=("$cmd"); fi
}
pipx_need(){ # pipx_need <cmd> <package>
  local cmd="$1" pkg="$2"
  if have "$cmd"; then ok "$cmd"; return; fi
  miss "$cmd — pipx install $pkg"
  if pipx install "$pkg" >/dev/null 2>&1; then ok "$cmd installed"; INSTALLED+=("$cmd"); else err "$cmd failed"; FAILED+=("$cmd"); fi
}

hdr "Browser (DOM-XSS + screenshots)"
brew_need chromium chromium --cask

hdr "ProjectDiscovery + Go recon tools"
go_need subfinder    github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go_need httpx        github.com/projectdiscovery/httpx/cmd/httpx@latest
go_need nuclei       github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go_need katana       github.com/projectdiscovery/katana/cmd/katana@latest
go_need naabu        github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go_need dnsx         github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go_need alterx       github.com/projectdiscovery/alterx/cmd/alterx@latest
go_need asnmap       github.com/projectdiscovery/asnmap/cmd/asnmap@latest
go_need shuffledns   github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go_need dalfox       github.com/hahwul/dalfox/v2@latest
go_need gau          github.com/lc/gau/v2/cmd/gau@latest
go_need waybackurls  github.com/tomnomnom/waybackurls@latest
go_need assetfinder  github.com/tomnomnom/assetfinder@latest
go_need hakrawler    github.com/hakluke/hakrawler@latest
go_need gowitness    github.com/sensepost/gowitness@latest
go_need puredns      github.com/d3mondev/puredns/v2@latest
go_need subzy        github.com/PentestPad/subzy@latest

hdr "Python-based tools"
pipx_need dirsearch dirsearch
pipx_need waymore   waymore
pipx_need uro       uro

hdr "Rust / brew tools"
brew_need feroxbuster feroxbuster
brew_need massdns     massdns      # DNS resolver puredns/shuffledns use

# massdns needs a resolvers file for puredns; download a fresh one.
mkdir -p "$HOME/.config/reconner"
if [ ! -s "$HOME/.config/reconner/resolvers.txt" ]; then
  curl -fsSL https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt \
    -o "$HOME/.config/reconner/resolvers.txt" 2>/dev/null && ok "resolvers.txt" || true
fi

# ── 4. persist PATH in ~/.zshrc ──────────────────────────────────────────────
ZSHRC="$HOME/.zshrc"
LINE='export PATH="$HOME/go/bin:$HOME/.local/bin:/usr/local/bin:/opt/homebrew/bin:$PATH"'
if ! grep -qF "$HOME/go/bin" "$ZSHRC" 2>/dev/null; then
  echo "$LINE" >> "$ZSHRC"
  ok "added Go/pipx bin to ~/.zshrc PATH"
fi

# ── 5. summary ───────────────────────────────────────────────────────────────
hdr "Summary"
echo "${GREEN}installed now:${NC} ${INSTALLED[*]:-none}"
[ ${#FAILED[@]} -gt 0 ] && echo "${RED}failed:${NC} ${FAILED[*]}  (re-run, or install manually)"
echo
echo "Open a NEW terminal (or: source ~/.zshrc), then verify:"
echo "  reconner scan example.com     # the tool audit line shows what's active"
echo
[ ${#FAILED[@]} -eq 0 ] && ok "All dependencies present." || err "Some tools failed — see above."
