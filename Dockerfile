# syntax=docker/dockerfile:1

# ─────────────────────────────────────────────────────────────────────────────
# Reconner — multi-stage container image.
#
#   • stage 1 (frontend)  builds the React/Vite dashboard  → frontend/dist
#   • stage 2 (tools)     compiles the recon tool-chain     → /out/*
#   • stage 3 (backend)   builds the Go binary (CGO/SQLite) → /out/reconner
#   • stage 4 (runtime)   slim Debian + Chromium + nmap + the tools + the binary
#
# Build context is the repository ROOT (the folder that contains go.mod, cmd/,
# internal/, frontend/). Build & run with docker compose (see docker-compose.yml).
# ─────────────────────────────────────────────────────────────────────────────

# ── stage 1: frontend ────────────────────────────────────────────────────────
FROM node:20-bookworm AS frontend
WORKDIR /app/frontend
# Install deps first (better layer caching); fall back to install if no lockfile.
COPY frontend/package*.json ./
RUN npm ci || npm install
COPY frontend/ ./
RUN npm run build

# ── stage 2: recon tool-chain ────────────────────────────────────────────────
# Compiled once, pinned by the module proxy at build time, then copied into the
# slim runtime — so the image ships a complete, reproducible tool-chain instead
# of `go install`-ing on every host at first run.
FROM golang:1.25-bookworm AS tools
ENV GOFLAGS=-buildvcs=false \
    GOBIN=/out \
    CGO_ENABLED=1
# naabu links libpcap at build time (cgo) for SYN scanning; gcc ships in the
# golang image. libpcap0.8 is installed in the runtime stage for it to link at run.
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev \
 && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /out
# ProjectDiscovery + tomnomnom + friends. Pin to @latest to match the shell
# installer; change a line to a tagged version (…@v1.2.3) for a frozen build.
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && go install github.com/projectdiscovery/katana/cmd/katana@latest \
 && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
 && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
 && go install github.com/projectdiscovery/alterx/cmd/alterx@latest \
 && go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest \
 && go install github.com/projectdiscovery/uncover/cmd/uncover@latest \
 && go install github.com/lc/gau/v2/cmd/gau@latest \
 && go install github.com/tomnomnom/waybackurls@latest \
 && go install github.com/tomnomnom/assetfinder@latest \
 && go install github.com/tomnomnom/qsreplace@latest \
 && go install github.com/hahwul/dalfox/v2@latest \
 && go install github.com/PentestPad/subzy@latest

# ── stage 3: backend (Go, CGO + SQLite) ──────────────────────────────────────
FROM golang:1.25-bookworm AS backend
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/*
# Dependency layer.
COPY go.mod go.sum ./
RUN go mod download
# Source + the built frontend (some builds embed it; it is also shipped on disk).
COPY . .
COPY --from=frontend /app/frontend/dist ./frontend/dist
ENV CGO_ENABLED=1 GOFLAGS=-buildvcs=false
RUN go build -ldflags="-s -w" -o /out/reconner ./cmd/reconner

# ── stage 4: runtime ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# OCI image metadata — populated from build args by CI (see the workflow). These
# make the published image self-describing on ghcr (source, version, revision).
ARG VERSION=dev
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="Reconner" \
      org.opencontainers.image.description="Enterprise web recon + DAST watchtower (XSS/SQLi/single-endpoint), bundled tool-chain + headless Chromium." \
      org.opencontainers.image.source="https://github.com/rootdr-backup/Reconner" \
      org.opencontainers.image.url="https://github.com/rootdr-backup/Reconner" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}"

# Chromium powers the headless XSS/DOM execution proof; nmap + libpcap back the
# port/service scans; tini reaps zombie child processes the tool-chain spawns.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      chromium \
      nmap \
      libpcap0.8 \
      curl \
      tini \
 && rm -rf /var/lib/apt/lists/*

# Tool-chain, the binary, and the built dashboard.
COPY --from=tools   /out/                    /usr/local/bin/
COPY --from=backend /out/reconner            /usr/local/bin/reconner
COPY --from=frontend /app/frontend/dist      /opt/reconner/frontend/dist
COPY docker/entrypoint.sh                    /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENV RECON_CONFIG=/data/config.json \
    RECONNER_CHROME=/usr/bin/chromium \
    DATA_DIR=/data \
    PORT=8080 \
    ADMIN_USER=admin
# ADMIN_PASSWORD is intentionally NOT set: the entrypoint generates a strong
# random password on first boot and prints it once in the logs.

# Runs as root ON PURPOSE: naabu/nmap SYN scans need raw sockets (CAP_NET_RAW)
# and the tool-chain spawns privileged probes — the same posture as the shell
# installer. Isolation is the container boundary + the granted caps, not a
# non-root uid. Keep the container on a trusted host/network.

WORKDIR /opt/reconner
# Persist the database, config, screenshots, wordlists and nuclei templates.
VOLUME /data
EXPOSE 8080

# Container-level health: the orchestrator can see when the app is actually up.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=5 \
  CMD curl -fsS "http://127.0.0.1:8080/api/health" || exit 1

# tini as PID 1 so headless-chromium / tool subprocesses are reaped cleanly.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
