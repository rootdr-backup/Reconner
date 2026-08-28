# Reconner — build & run (no root required)
#
# Quick start:
#   make            # build the frontend + the `reconner` binary
#   ./reconner serve
#
# Individual targets are below. Nothing here needs sudo —
# Docker is the recommended way to get the full tool-chain.

BINARY      ?= reconner
PKG         := ./cmd/reconner
GO          ?= go
NPM         ?= npm
LDFLAGS     := -s -w
CGO_ENABLED ?= 1

.PHONY: all build backend frontend run test tidy clean

## Build everything (frontend bundle + Go binary).
all: build

build: frontend backend

## Compile the Go binary. CGO is required for the embedded SQLite driver.
backend:
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -ldflags="$(LDFLAGS)" -o $(BINARY) $(PKG)

## Build the React/TypeScript dashboard into frontend/dist (embedded/served by the app).
frontend:
	cd frontend && $(NPM) install && $(NPM) run build

## Run the server (dashboard on http://localhost:8080 by default).
run: build
	./$(BINARY) serve

## Run the Go test suite.
test:
	$(GO) test ./...

## Tidy Go module dependencies.
tidy:
	$(GO) mod tidy

## Remove build artifacts.
clean:
	rm -f $(BINARY)
	rm -rf frontend/dist

# ── Docker / container operations ────────────────────────────────────────────
# Self-contained image (backend + dashboard + full tool-chain + headless
# Chromium). See README.Docker.md. Requires Docker with the compose plugin.
COMPOSE    ?= docker compose
IMAGE      ?= ghcr.io/rootdr-backup/reconner
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
VCS_REF    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

.PHONY: docker-build docker-up docker-down docker-logs docker-password docker-shell docker-ps docker-update docker-destroy docker-buildx

## Build the container image locally.
docker-build:
	$(COMPOSE) build --build-arg VERSION=$(VERSION) --build-arg VCS_REF=$(VCS_REF) --build-arg BUILD_DATE=$(BUILD_DATE)

## Build (if needed) and start in the background on :8080.
docker-up:
	$(COMPOSE) up -d --build

## Stop and remove the container (the data volume is kept).
docker-down:
	$(COMPOSE) down

## Follow logs (the admin password prints here on first boot).
docker-logs:
	$(COMPOSE) logs -f

## Print the current admin password from the running container.
docker-password:
	$(COMPOSE) exec reconner sh -c 'grep admin_password "$$RECON_CONFIG"'

## Open a shell inside the running container.
docker-shell:
	$(COMPOSE) exec reconner bash

## Show container status + health.
docker-ps:
	$(COMPOSE) ps

## Pull/rebuild and restart without losing data.
docker-update:
	$(COMPOSE) up -d --build

## Stop AND delete the data volume (irreversible).
docker-destroy:
	$(COMPOSE) down -v

## Multi-arch build+push (amd64,arm64) — requires `docker login ghcr.io`.
docker-buildx:
	docker buildx build --push --platform linux/amd64,linux/arm64 \
		--build-arg VERSION=$(VERSION) --build-arg VCS_REF=$(VCS_REF) --build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(IMAGE):$(VERSION) -t $(IMAGE):latest .
