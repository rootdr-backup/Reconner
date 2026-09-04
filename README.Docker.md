# Running Reconner with Docker

A single, reproducible container image that bundles the Go backend, the built
React dashboard, **and** the whole recon tool-chain (subfinder, httpx, nuclei,
katana, naabu, dnsx, dalfox, subzy, gau, waybackurls, …) plus headless Chromium
and nmap — so there is nothing to `go install` on the host and no version drift.

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

## Quick start

```bash
cp .env.example .env          # set HOST_PORT + admin credentials
docker compose up -d --build  # build the image and start it
```

Open the dashboard at `http://<host>:8080/`.

```bash
docker compose logs -f        # follow logs
docker compose down           # stop (data is kept in the volume)
docker compose up -d --build  # update to newer code, DB untouched
```

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

## Notes

- **Port**: the app always listens on `8080` inside the container. Publish it on
  a different host port by setting `HOST_PORT` in `.env` (the mapping is
  `HOST_PORT:8080`).
- **Port/service scans**: `naabu`/`nmap` SYN scans need `NET_RAW`/`NET_ADMIN`,
  which the compose file grants. Remove `cap_add` if you only run web-app scans.
- **Headless Chromium**: bundled and auto-detected (`RECONNER_CHROME=/usr/bin/chromium`);
  it runs `--no-sandbox` (already handled in code) and gets `shm_size: 512m`.
- **First-run nuclei templates**: provisioned automatically on the first scan;
  they are cached in the volume afterwards.
- **Reproducible tool versions**: the tool-chain is pinned by the module proxy at
  build time. To freeze exact versions, change an `@latest` in the `Dockerfile`
  tools stage to a tag (e.g. `nuclei/v3/cmd/nuclei@v3.3.5`).
- **Registry image name**: the CI workflow pushes to
  `ghcr.io/rootdr-backup/reconner` (lowercase, as ghcr requires). Adjust the
  `IMAGE` env in the workflow and the `image:` in compose if your path differs.
