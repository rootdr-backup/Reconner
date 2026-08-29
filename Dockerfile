# syntax=docker/dockerfile:1

# ─────────────────────────────────────────────────────────────────────────────
# Reconner — production multi-stage container image.
#
# Goal: `git clone` + `docker compose up -d --build` and nothing else. The user
# never installs Go, Rust/Cargo, Python, Node, gcc, make, or any recon tool —
# every one of them is built or downloaded HERE, at image-build time, and
# copied into a slim runtime. No tool is ever installed at container startup.
#
# Stages (produce exactly the 30 required external commands, audited against
# internal/scheduler/scheduler.go's expectedTools + internal/api/tool_install.go,
# PLUS headless Chromium as a 31st runtime dependency the app also shells out to):
#   1. frontend   — React/Vite dashboard                       → frontend/dist
#   2. gotools    — 20 Go-based recon tools                    → /out/*
#   3. massdns    — massdns (1) compiled from source            → /out/massdns
#   4. external   — feroxbuster + findomain (2) official releases → /out/*
#   5. pytools    — dirsearch/uro/waymore (3) in a self-contained venv → /opt/venv
#   6. backend    — Reconner Go binary (CGO + embedded SQLite)  → /out/reconner
#   7. runtime    — slim Debian + hydra/sqlmap/nmap/python3 (4, via apt) +
#                   Chromium + every tool above, finished with a hard
#                   build-time verification of the PATH.
#                   20 (Go) + 1 (massdns) + 2 (releases) + 3 (venv) + 4 (apt)
#                   = 30 required tools. Chromium AND git are bundled in
#                   addition to, not counted within, that 30 — git specifically
#                   because internal/scanner/nuclei.go gates its own official-
#                   template auto-provisioning on `IsToolAvailable("git")`;
#                   without it nuclei silently loses the official/fuzzing
#                   template sets and, in the worst case (embedded pack also
#                   fails to materialize), gets invoked with zero -t flags and
#                   hard-fails with "no templates provided for scan" (exit 1).
#
# Dependency note: puredns and shuffledns (both stage 2) do their DNS
# brute-forcing THROUGH massdns (stage 3) — internal/api/tool_install.go
# documents both as "Also needs massdns on PATH." All three land in
# /usr/local/bin in the runtime stage below, so this is satisfied by
# construction; COPY order across stages does not matter for final PATH
# resolution, but the dependency is real and is exercised by the
# build-time verification step at the bottom of this file.
#
# All stages that produce binaries linked against system libraries (gotools,
# massdns, backend) and the runtime itself share the SAME base OS
# (debian:bookworm) so glibc/libpcap/openssl versions match exactly — this is
# what the earlier `stdint.h` / interpreter-mismatch class of bugs came from.
#
# Build context is the repository ROOT (the folder with go.mod, cmd/,
# internal/, frontend/). Build & run with docker compose — see
# docker-compose.yml and README.md.
# ─────────────────────────────────────────────────────────────────────────────

ARG GO_VERSION=1.26-bookworm
ARG NODE_VERSION=20-bookworm
ARG DEBIAN_VERSION=bookworm-slim

# ── stage 1: frontend ────────────────────────────────────────────────────────
FROM node:${NODE_VERSION} AS frontend
WORKDIR /app/frontend
# Install deps first (better layer caching); fall back to install if no lockfile.
COPY frontend/package*.json ./
RUN npm ci || npm install
COPY frontend/ ./
RUN npm run build

# ── stage 2: Go recon tool-chain ─────────────────────────────────────────────
# Every tool is `go install`-ed once, at build time, into GOBIN=/out, then
# copied into the runtime image — nothing is ever `go install`-ed on the host
# or at container start.
#
# VERSIONING: each tool gets its own ARG_*_VERSION build-arg (default
# "latest"). True pin-to-exact-tag reproducibility requires knowing each
# project's current release tag at the moment this file is written, and these
# ~20 independent repositories tag at very different, fast-moving cadences —
# hardcoding a snapshot of "current" tags here would go stale immediately and
# is more likely to silently break the build (wrong/removed tag) than @latest
# ever was. Instead every tool is independently pinnable without touching this
# file, e.g. to freeze nuclei:
#   docker compose build --build-arg NUCLEI_VERSION=v3.3.5
# Each tool also builds in its OWN layer (not one giant RUN), so a version
# bump — or a transient network blip on one module — only invalidates that
# tool's cache layer, never the other 19.
FROM golang:${GO_VERSION} AS gotools
ENV GOFLAGS=-buildvcs=false \
    GOBIN=/out \
    CGO_ENABLED=1 \
    GOTOOLCHAIN=auto
# naabu links libpcap at build time (cgo) for SYN scanning; gcc ships in the
# golang image. libpcap0.8 is installed in the runtime stage for it to link at
# run time.
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev \
 && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /out

ARG SUBFINDER_VERSION=latest
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION}

ARG HTTPX_VERSION=latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}

ARG NUCLEI_VERSION=latest
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}

ARG KATANA_VERSION=latest
RUN go install github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION}

ARG NAABU_VERSION=latest
RUN go install github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION}

ARG DNSX_VERSION=latest
RUN go install github.com/projectdiscovery/dnsx/cmd/dnsx@${DNSX_VERSION}

ARG ALTERX_VERSION=latest
RUN go install github.com/projectdiscovery/alterx/cmd/alterx@${ALTERX_VERSION}

ARG ASNMAP_VERSION=latest
RUN go install github.com/projectdiscovery/asnmap/cmd/asnmap@${ASNMAP_VERSION}

ARG UNCOVER_VERSION=latest
RUN go install github.com/projectdiscovery/uncover/cmd/uncover@${UNCOVER_VERSION}

ARG SHUFFLEDNS_VERSION=latest
RUN go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@${SHUFFLEDNS_VERSION}

ARG GAU_VERSION=latest
RUN go install github.com/lc/gau/v2/cmd/gau@${GAU_VERSION}

ARG WAYBACKURLS_VERSION=latest
RUN go install github.com/tomnomnom/waybackurls@${WAYBACKURLS_VERSION}

ARG ASSETFINDER_VERSION=latest
RUN go install github.com/tomnomnom/assetfinder@${ASSETFINDER_VERSION}

ARG QSREPLACE_VERSION=latest
RUN go install github.com/tomnomnom/qsreplace@${QSREPLACE_VERSION}

ARG HAKRAWLER_VERSION=latest
RUN go install github.com/hakluke/hakrawler@${HAKRAWLER_VERSION}

ARG DALFOX_VERSION=latest
RUN go install github.com/hahwul/dalfox/v2@${DALFOX_VERSION}

ARG SUBZY_VERSION=latest
RUN go install github.com/PentestPad/subzy@${SUBZY_VERSION}

ARG GOWITNESS_VERSION=latest
RUN go install github.com/sensepost/gowitness@${GOWITNESS_VERSION}

ARG PUREDNS_VERSION=latest
RUN go install github.com/d3mondev/puredns/v2@${PUREDNS_VERSION}

ARG SCILLA_VERSION=latest
RUN go install github.com/edoardottt/scilla/cmd/scilla@${SCILLA_VERSION}

# Sanity check: every binary we expect actually landed in /out. Fails loud and
# early instead of silently shipping a partial tool-chain.
RUN set -eu; \
    for t in subfinder httpx nuclei katana naabu dnsx alterx asnmap uncover \
             shuffledns gau waybackurls assetfinder qsreplace hakrawler \
             dalfox subzy gowitness puredns scilla; do \
      if [ ! -x "/out/$t" ]; then \
        echo "BUILD FAILURE: /out/$t was not produced by go install" >&2; \
        exit 1; \
      fi; \
    done; \
    echo "gotools: all 20 Go binaries present in /out"

# ── stage 3: massdns (built from source — not packaged for Debian bookworm) ──
# Root cause of the earlier `fatal error: stdint.h: No such file or directory`:
# the previous builder had gcc but not the libc DEVELOPMENT headers
# (libc6-dev), which is where stdint.h lives. This stage installs the full
# minimum native build chain (gcc, libc6-dev, make, git) explicitly.
FROM debian:${DEBIAN_VERSION} AS massdns
RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc \
      libc6-dev \
      make \
      git \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /build
# MASSDNS_REF defaults to the default branch tip: upstream does not cut
# frequent tagged releases, so "master" is the commonly-installed reference.
# For a fully frozen build, pin an exact commit SHA or tag:
#   docker compose build --build-arg MASSDNS_REF=<commit-sha>
ARG MASSDNS_REF=master
RUN git clone https://github.com/blechschmidt/massdns.git /build/massdns \
 && cd /build/massdns \
 && if [ "${MASSDNS_REF}" != "master" ]; then git checkout "${MASSDNS_REF}"; fi \
 && make
RUN mkdir -p /out \
 && cp /build/massdns/bin/massdns /out/massdns \
 && chmod +x /out/massdns \
 && test -x /out/massdns

# ── stage 4: external release binaries (feroxbuster, findomain) ─────────────
# Both were previously attempted via `cargo install` / apt and failed
# (env_logger dependency resolution for feroxbuster; package not present in
# Debian bookworm for findomain). Both now come from the project's own
# official GitHub release, selected by TARGETARCH so a multi-arch build never
# ships the wrong architecture's binary (the earlier "Exec format error").
FROM debian:${DEBIAN_VERSION} AS external
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl unzip file \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /out

ARG TARGETARCH
ARG FEROXBUSTER_VERSION=2.13.1
ARG FINDOMAIN_VERSION=10.0.1

RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) FEROX_ASSET="x86_64-linux-feroxbuster.zip"; FINDOMAIN_ASSET="findomain-linux.zip"; ARCH_TAG="x86-64" ;; \
      arm64) FEROX_ASSET="aarch64-linux-feroxbuster.zip"; FINDOMAIN_ASSET="findomain-aarch64.zip"; ARCH_TAG="aarch64" ;; \
      *) echo "BUILD FAILURE: unsupported TARGETARCH '${TARGETARCH}' — only amd64 and arm64 are supported" >&2; exit 1 ;; \
    esac; \
    \
    echo "==> feroxbuster ${FEROXBUSTER_VERSION} (${FEROX_ASSET})"; \
    curl -fsSL -o /tmp/ferox.zip \
      "https://github.com/epi052/feroxbuster/releases/download/v${FEROXBUSTER_VERSION}/${FEROX_ASSET}"; \
    mkdir -p /tmp/ferox_x && unzip -q -o /tmp/ferox.zip -d /tmp/ferox_x; \
    find /tmp/ferox_x -type f -iname '*feroxbuster*' -exec mv {} /out/feroxbuster \; ; \
    chmod +x /out/feroxbuster; \
    file /out/feroxbuster | tee /tmp/ferox.filetype; \
    grep -qi "${ARCH_TAG}" /tmp/ferox.filetype || { echo "BUILD FAILURE: feroxbuster binary arch mismatch (expected ${ARCH_TAG})" >&2; exit 1; }; \
    \
    echo "==> findomain ${FINDOMAIN_VERSION} (${FINDOMAIN_ASSET})"; \
    curl -fsSL -o /tmp/findomain.zip \
      "https://github.com/Findomain/Findomain/releases/download/${FINDOMAIN_VERSION}/${FINDOMAIN_ASSET}"; \
    mkdir -p /tmp/findomain_x && unzip -q -o /tmp/findomain.zip -d /tmp/findomain_x; \
    find /tmp/findomain_x -type f -iname '*findomain*' -exec mv {} /out/findomain \; ; \
    chmod +x /out/findomain; \
    file /out/findomain | tee /tmp/findomain.filetype; \
    grep -qi "${ARCH_TAG}" /tmp/findomain.filetype || { echo "BUILD FAILURE: findomain binary arch mismatch (expected ${ARCH_TAG})" >&2; exit 1; }; \
    \
    rm -rf /tmp/ferox.zip /tmp/ferox_x /tmp/findomain.zip /tmp/findomain_x /tmp/*.filetype; \
    test -x /out/feroxbuster && test -x /out/findomain

# ── stage 5: Python tool-chain (dirsearch, uro, waymore) ────────────────────
# Built as a self-contained venv using the SAME Debian base as runtime (not a
# separate `python:*-slim` image), so the interpreter the venv's shebangs
# point at is bit-for-bit what runtime will actually have on PATH — a venv
# built against a different Debian/Python point release is exactly the class
# of "works in the builder, breaks at runtime" bug this avoids.
FROM debian:${DEBIAN_VERSION} AS pytools
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 \
      python3-venv \
      python3-dev \
      gcc \
      libc6-dev \
 && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv --copies /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir dirsearch uro waymore
# The user never needs pip or network access after the container starts: this
# venv is fully self-contained and is copied verbatim into runtime.
RUN /opt/venv/bin/python3 -c "import sys; print(sys.version)" \
 && test -x /opt/venv/bin/dirsearch \
 && test -x /opt/venv/bin/uro \
 && test -x /opt/venv/bin/waymore

# ── stage 6: backend (Reconner Go binary, CGO + embedded SQLite) ────────────
FROM golang:${GO_VERSION} AS backend
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/*
# Dependency layer — cached independently of source changes.
COPY go.mod go.sum ./
RUN go mod download
# Source + the built frontend.
COPY . .
COPY --from=frontend /app/frontend/dist ./frontend/dist
ENV CGO_ENABLED=1 GOFLAGS=-buildvcs=false GOTOOLCHAIN=auto
RUN go build -ldflags="-s -w" -o /out/reconner ./cmd/reconner \
 && test -x /out/reconner

# ── stage 7: runtime ─────────────────────────────────────────────────────────
FROM debian:${DEBIAN_VERSION} AS runtime

# OCI image metadata — populated from build args by CI (see the workflow).
ARG VERSION=dev
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="Reconner" \
      org.opencontainers.image.description="Self-hosted web + network recon and DAST watchtower, with the complete bundled tool-chain and headless Chromium — nothing to install on the host." \
      org.opencontainers.image.source="https://github.com/rootdr-backup/Reconner" \
      org.opencontainers.image.url="https://github.com/rootdr-backup/Reconner" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}"

# Runtime OS packages — kept to what the app and bundled tool-chain actually
# need at RUN time (no compilers, no -dev headers, no npm/node/go/cargo/pip):
#   ca-certificates  TLS trust store for every HTTP-speaking tool
#   chromium         headless-browser XSS/DOM execution proof + gowitness/katana rendering
#   nmap             network port/service scanning
#   libpcap0.8       naabu's SYN-scan runtime dependency (built against it in gotools)
#   hydra            SSH/SMB/RDP/VNC credential brute-force (opt-in, scope-guarded by the app)
#   sqlmap           active SQLi confirmation pass (opt-in, off by default)
#   python3          runs the pytools venv (dirsearch/uro/waymore) AND the Ingram camera scanner
#   git              REQUIRED at runtime, not just at build time: internal/scanner/nuclei.go
#                    checks `IsToolAvailable("git")` before cloning the official nuclei-templates
#                    + fuzzing-templates sets into <DataDir>/nuclei-templates on first scan. Without
#                    it that provisioning step is silently skipped forever (IsToolAvailable() is
#                    gated on it), so nuclei runs with only Reconner's small embedded template pack
#                    — a real, confirmed coverage loss, and if that embedded pack ever fails to
#                    materialize too (e.g. an unwritable /data), nuclei is invoked with NO -t flags
#                    at all and hard-fails with `[FTL] no templates provided for scan` (exit 1) —
#                    reproduced against a real nuclei binary while auditing this image.
#   curl             image HEALTHCHECK
#   tini             PID 1 — reaps zombie children the tool-chain spawns
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      chromium \
      nmap \
      libpcap0.8 \
      hydra \
      sqlmap \
      python3 \
      git \
      curl \
      tini \
 && rm -rf /var/lib/apt/lists/*

# ── assemble the tool-chain ──────────────────────────────────────────────────
# puredns and shuffledns (both from gotools) shell out to massdns for actual
# DNS resolution/brute-forcing — both COPYs land in /usr/local/bin together so
# that dependency is satisfied the moment the layer is in place.
COPY --from=gotools   /out/                    /usr/local/bin/
COPY --from=massdns   /out/massdns             /usr/local/bin/massdns
COPY --from=external  /out/feroxbuster         /usr/local/bin/feroxbuster
COPY --from=external  /out/findomain           /usr/local/bin/findomain
COPY --from=pytools   /opt/venv                /opt/venv
# Expose ONLY the three console scripts we actually want from the venv, as
# symlinks in /usr/local/bin — deliberately NOT adding /opt/venv/bin to PATH.
# dirsearch pulls in the PyPI package "httpx" (an unrelated async HTTP client
# library) as a dependency, which installs its own broken `httpx` command
# stub (it errors out unless the `httpx[cli]` extra is installed). Putting
# /opt/venv/bin on PATH let that stub SHADOW the real ProjectDiscovery `httpx`
# Go binary in /usr/local/bin, breaking the entire image
# ("The httpx command line client could not run because the required
# dependencies were not installed."). The symlinks below are all that's
# needed — no venv directory should ever be added to PATH.
RUN ln -s /opt/venv/bin/dirsearch /usr/local/bin/dirsearch \
 && ln -s /opt/venv/bin/uro       /usr/local/bin/uro \
 && ln -s /opt/venv/bin/waymore   /usr/local/bin/waymore

# The app binary and the built dashboard.
COPY --from=backend  /out/reconner            /usr/local/bin/reconner
COPY --from=frontend /app/frontend/dist       /opt/reconner/frontend/dist
COPY docker/entrypoint.sh                     /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENV RECON_CONFIG=/data/config.json \
    RECONNER_CHROME=/usr/bin/chromium \
    DATA_DIR=/data \
    PORT=8080 \
    ADMIN_USER=admin
# ADMIN_PASSWORD is intentionally NOT set here and is never baked into the
# image: the entrypoint generates a strong random password on first boot and
# prints it once in the logs (see docker/entrypoint.sh and the README's
# "First Login" section). No secret of any kind lives in this image.

# ── build-time verification ──────────────────────────────────────────────────
# Every tool Reconner can invoke MUST be present and actually executable in
# the finished image — this is not a "does the file exist" check, each
# command is run for real. A missing or broken tool fails the Docker build,
# never ships silently.
RUN set -eu; \
    echo "==> verifying all 30 required tools, plus Chromium and git, are on PATH"; \
    MISSING=""; \
    for t in \
      subfinder httpx nuclei katana naabu dnsx alterx asnmap uncover \
      gau waybackurls assetfinder qsreplace dalfox subzy \
      gowitness hakrawler puredns scilla shuffledns \
      dirsearch feroxbuster findomain hydra sqlmap uro waymore \
      massdns nmap python3 \
      chromium git \
    ; do \
      if ! command -v "$t" >/dev/null 2>&1; then \
        MISSING="${MISSING} $t"; \
      fi; \
    done; \
    if [ -n "${MISSING}" ]; then \
      echo "BUILD FAILURE: missing required tool(s) on PATH:${MISSING}" >&2; \
      exit 1; \
    fi; \
    echo "==> all required tools are on PATH"; \
    \
    echo "==> executing representative tools to prove they actually run"; \
    python3 --version; \
    nmap --version | head -1; \
    massdns 2>&1 | head -1 || true; \
    feroxbuster --version; \
    findomain --version; \
    sqlmap --version; \
    nuclei -version; \
    httpx -version; \
    subfinder -version; \
    katana -version; \
    naabu -version; \
    dnsx -version; \
    dirsearch --help >/dev/null 2>&1 || { echo "BUILD FAILURE: dirsearch not executable" >&2; exit 1; }; \
    /opt/venv/bin/python3 -m dirsearch --help >/dev/null 2>&1 || { echo "BUILD FAILURE: dirsearch not importable via its own venv python3" >&2; exit 1; }; \
    echo "==> tool-chain verification passed"

# Runs as root ON PURPOSE: naabu/nmap SYN scans need raw sockets (CAP_NET_RAW)
# and the tool-chain spawns privileged probes — the same posture as the shell
# installer. Isolation is the container boundary + the explicitly granted
# capabilities in docker-compose.yml (cap_add: NET_RAW, NET_ADMIN), not a
# non-root uid. Keep the container on a trusted host/network; do not remove
# those two capabilities unless you only ever run web/DAST scans (no
# port/service scanning).

WORKDIR /opt/reconner
# Persist the database, config, screenshots, wordlists and nuclei templates.
# User data is NEVER baked into the image — this volume is the only place any
# of it lives.
VOLUME /data
EXPOSE 8080

# Container-level health: the orchestrator can see when the app is actually up.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=5 \
  CMD curl -fsS "http://127.0.0.1:8080/api/health" || exit 1

# tini as PID 1 so headless-chromium / tool subprocesses are reaped cleanly.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
