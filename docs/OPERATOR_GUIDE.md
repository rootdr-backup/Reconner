# Reconner operator guide

This guide covers a single-host Docker Compose deployment. It assumes Docker
Engine and Docker Compose v2 are already installed.

> [!IMPORTANT]
> Reconner performs active security testing. Keep the dashboard behind a
> firewall, VPN, or authenticated TLS reverse proxy, and scan only explicitly
> authorized assets.

## Install the current release

```bash
git clone https://github.com/rootdr-backup/Reconner.git
cd Reconner
cp .env.example .env
docker compose pull reconner
docker compose up -d reconner
```

Confirm that the container and API are healthy:

```bash
docker compose ps
curl -fsS http://127.0.0.1:8080/api/health
```

Open `http://<server-ip>:8080/`. The application always listens on port `8080`
inside the container; `HOST_PORT` in `.env` controls the host-facing port.

## First login

The default username is `admin`. If `ADMIN_PASSWORD` was blank on first boot,
the entrypoint generated a random password. Retrieve it with:

```bash
docker compose logs reconner | grep -A1 password
```

The password is persisted in `/data/config.json`. It can be inspected later
with:

```bash
docker compose exec reconner sh -c 'grep admin_password "$RECON_CONFIG"'
```

`ADMIN_USER` and `ADMIN_PASSWORD` are bootstrap values. Changing them in `.env`
after the persistent configuration exists does not rewrite existing users.

## Safe upgrade

Wait for or stop active scans, create a data backup, then update the checkout
and container image:

```bash
git fetch --tags origin
git switch main
git pull --ff-only origin main
docker compose pull reconner
docker compose up -d --no-deps reconner
docker compose ps
curl -fsS http://127.0.0.1:8080/api/health
```

To run the repository state for a specific release, check out its tag before
starting. The published container also has immutable semantic-version tags such
as `ghcr.io/rootdr-backup/reconner:3.4.0`; replace `:latest` in
`docker-compose.yml` when the image itself must remain pinned.

For a local source build:

```bash
git switch main
git pull --ff-only origin main
docker compose up -d --build reconner
```

Do not use `docker compose down -v` during an update. The `-v` flag deletes the
persistent volume.

## Back up persistent data

All durable state lives under `/data` in the `reconner-data` volume: the SQLite
database, configuration, users, screenshots, corpora, templates, and evidence.
Stop the service briefly so the SQLite copy is consistent:

```bash
mkdir -p backups
docker compose stop reconner
docker compose cp reconner:/data "./backups/reconner-data-$(date +%Y%m%d-%H%M%S)"
docker compose start reconner
curl -fsS http://127.0.0.1:8080/api/health
```

Protect backups as sensitive research data. They can contain credentials,
cookies, request evidence, discovered assets, and private program information.
Test restoration on a separate deployment before relying on a backup policy.

## Resource sizing

Compose bounds the complete process tree—including Chromium and external tools—
to `3g` of memory and 512 PIDs by default. Reconner reads the cgroup limit and
uses it when admitting new work.

| Host RAM | `RECON_MEMORY_LIMIT` | Suggested `limits.max_memory_mb` | Suggested concurrent targets |
|---:|---:|---:|---:|
| 2 GB | `1536m` | `1024` | `1` |
| 4 GB | `3g` | `2304` | `1` |
| 8 GB | `6g` | `4608` | `2` |
| 16 GB | `12g` | `9216` | `4` |

Keep `RECON_PIDS_LIMIT=512` unless measurement shows a legitimate need to
raise it. Do not configure Reconner's internal memory ceiling above the
container memory limit.

## Network capabilities

Naabu uses unprivileged TCP-connect discovery. Nmap receives only the file
capabilities needed for bounded OS fingerprinting, and Compose retains
`NET_RAW`/`NET_ADMIN` in the container bounding set for that binary. Remove
`cap_add` from Compose to disable OS detection while keeping port, banner, and
service discovery.

## Logs and health

```bash
docker compose ps
docker compose logs --tail=200 reconner
docker compose logs -f reconner
curl -fsS http://127.0.0.1:8080/api/health
```

Useful first checks:

- `Restarting (1)` means the service is failing before the health check; inspect
  logs instead of repeatedly restarting it.
- `health: starting` is normal during the configured startup grace period.
- a healthy container with an unreachable remote dashboard usually indicates a
  host firewall, cloud security group, reverse proxy, or `HOST_PORT` issue.
- missing module capability is recorded in the phase ledger; inspect the phase
  status and logs rather than interpreting zero findings as a successful run.

## Repair a legacy read-only volume

Current images run Reconner as uid/gid `10001`. The Compose entrypoint normally
repairs ownership for a volume created by older root-running releases. If a
custom orchestrator bypassed that init step and SQLite reports `attempt to write
a readonly database`, run the one-time repair:

```bash
docker compose down
docker compose run --rm --user 0 --entrypoint chown reconner -R 10001:10001 /data
docker compose up -d reconner
docker compose ps
```

Then verify `/api/health`. Do not delete or recreate the volume to solve an
ownership problem.

## Recovery checklist

1. Capture `docker compose ps` and the last 200 log lines.
2. Confirm the checked-out tag/commit and configured image name.
3. Confirm free disk, memory, PID headroom, and volume ownership.
4. Confirm `.env` contains no accidental quotes or stale host port.
5. Back up `/data` before database or configuration repair.
6. Apply the narrowest fix and re-check the health endpoint.

For detector behavior and phase controls, continue with the
[scanning guide](SCANNING_GUIDE.md). For image internals, see the
[Docker reference](../README.Docker.md).
