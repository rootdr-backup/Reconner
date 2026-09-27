# Running Reconner with Docker

A single, reproducible container image that bundles the Go backend, the built
React dashboard, the pinned recon toolchain, headless Chromium, and Nmap. There
is nothing to `go install` on the host and the finished image executes every
required command during its build before publication.

## Files

| File | Purpose |
|------|---------|
| `Dockerfile` | Multi-stage build: frontend → tool-chain → Go binary (CGO/SQLite) → slim runtime. |
| `docker-compose.yml` | Runs the image on port **8080**, persists data in a named volume. |
| `docker/entrypoint.sh` | Writes `config.json` on first boot, then starts the `reconner` service. |
| `.dockerignore` | Keeps the build context lean. |
| `.env.example` | Copy to `.env` for host port + initial admin credentials. |
| `.github/workflows/docker-image.yml` | Builds and pushes the image to `ghcr.io` on push/tag. |

Drop these into the **root of the repository** (next to `go.mod`, `cmd/`,
`internal/`, `frontend/`).

## Quick start with the published image

```bash
cp .env.example .env
docker compose pull reconner
docker compose up -d reconner
docker compose ps
curl -fsS http://127.0.0.1:8080/api/health
```

Open the dashboard at `http://<host>:8080/`.

```bash
docker compose logs -f        # follow logs
docker compose down           # stop (data is kept in the volume)
```

For a local build of the checked-out source, use
`docker compose up -d --build reconner` instead. A clean build compiles the
complete multi-stage toolchain and takes substantially longer than pulling the
published image.

## Upgrade

Back up `/data`, wait for active scans to finish, then run:

```bash
git fetch --tags origin
git switch main
git pull --ff-only origin main
docker compose pull reconner
docker compose up -d --no-deps reconner
docker compose ps
curl -fsS http://127.0.0.1:8080/api/health
```

Normal replacement keeps the named volume. Never add `-v` to `docker compose
down` during an update; it deletes the persistent data volume. See the
[operator guide](docs/OPERATOR_GUIDE.md) for backups, version pinning, resource
sizing, and recovery.

## Login credentials

The admin **username** is `admin`. If you leave `ADMIN_PASSWORD` blank in `.env`
(the default), a **strong random password is generated on first boot** and
printed once in the logs — grab it there:

```bash
docker compose logs reconner | grep -A1 password
```

It is stored in the config inside the volume; retrieve it any time with:

```bash
docker compose exec reconner sh -c 'grep admin_password "$RECON_CONFIG"'
```

To pin a known password instead, set `ADMIN_PASSWORD=...` in `.env` **before**
the first `up` (it is only read on first boot, when the config is created).

## Data persistence

Everything the app persists — the SQLite database, `config.json`, screenshots,
wordlists and nuclei templates — lives under `/data`, mounted from the
`reconner-data` named volume. Rebuilding or updating the image never loses your
data. To wipe it, remove the volume: `docker compose down -v`.

## Container sizing and host protection

Compose limits the complete Reconner process tree by default to `3g` of memory
and 512 PIDs. This covers Chromium and external tools as well as the Go service.
Reconner reads the cgroup limit and usage, sizes `limits.max_memory_mb` from the
smaller of host/container memory, and pauses new scan admission under pressure.

Set `RECON_MEMORY_LIMIT` in `.env` for the host. For an existing `config.json`
that already contains an explicit `limits` object, also align the two fields
shown below; fresh/partial configurations are auto-tuned.

| Host RAM | `RECON_MEMORY_LIMIT` | `limits.max_memory_mb` | `limits.max_concurrent_targets` |
|---:|---:|---:|---:|
| 2 GB | `1536m` | `1024` | `1` |
| 4 GB | `3g` | `2304` | `1` |
| 8 GB | `6g` | `4608` | `2` |
| 16 GB | `12g` | `9216` | `4` |

Keep `RECON_PIDS_LIMIT=512` unless measurements show a legitimate need to
raise it. A PID-limit failure is preferable to exhausting the host-wide PID
table. Do not set `limits.max_memory_mb` above the Compose memory limit.

## Notes

- **Port**: the app always listens on `8080` inside the container. Publish it on
  a different host port by setting `HOST_PORT` in `.env` (the mapping is
  `HOST_PORT:8080`).
- **Port/service scans**: Naabu always uses unprivileged TCP-connect discovery.
  Compose retains `NET_RAW`/`NET_ADMIN` only for the file-capability-scoped Nmap
  OS fingerprint step; remove `cap_add` to disable OS detection while keeping
  port, banner and service discovery.
- **Headless Chromium**: bundled and auto-detected (`RECONNER_CHROME=/usr/bin/chromium`);
  it runs `--no-sandbox` (already handled in code) and gets `shm_size: 512m`.
- **First-run nuclei templates**: provisioned automatically on the first scan;
  they are cached in the volume afterwards.
- **Reproducible tool versions**: every Go and downloaded binary version is
  pinned by a Docker build argument; release-asset checksums are verified.
- **Registry image name**: the CI workflow pushes to
  `ghcr.io/rootdr-backup/reconner` (lowercase, as ghcr requires). Adjust the
  `IMAGE` env in the workflow and the `image:` in compose if your path differs.
