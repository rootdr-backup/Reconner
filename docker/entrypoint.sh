#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Reconner container entrypoint.
#
# On first boot it writes config.json into the /data volume (idempotent — an
# existing config, and therefore an existing database, is left untouched). If no
# ADMIN_PASSWORD was supplied, a strong RANDOM password is generated and printed
# ONCE in the logs. Everything the app persists (SQLite DB, screenshots,
# wordlists, nuclei templates) lives under /data so it survives container
# re-creation via the mounted volume.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

DATA_DIR="${DATA_DIR:-/data}"
CFG="${RECON_CONFIG:-${DATA_DIR}/config.json}"
PORT="${PORT:-8080}"
ADMIN_USER="${ADMIN_USER:-admin}"

mkdir -p \
  "${DATA_DIR}" \
  "${DATA_DIR}/tools" \
  "${DATA_DIR}/screenshots" \
  "${DATA_DIR}/wordlists" \
  "${DATA_DIR}/nuclei-templates"

if [ ! -f "${CFG}" ]; then
  # Generate a strong random password when none was provided. base64 of 32
  # random bytes, filtered to alphanumerics, trimmed to 20 chars.
  GENERATED=0
  if [ -z "${ADMIN_PASSWORD:-}" ]; then
    ADMIN_PASSWORD="$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-20)"
    GENERATED=1
  fi

  echo "==> First boot: writing ${CFG} (0.0.0.0:${PORT}, data in ${DATA_DIR})"
  cat > "${CFG}" <<JSON
{
  "host": "0.0.0.0",
  "port": ${PORT},
  "admin_username": "${ADMIN_USER}",
  "admin_password": "${ADMIN_PASSWORD}",
  "data_dir": "${DATA_DIR}",
  "database_path": "${DATA_DIR}/recon.db",
  "tools_dir": "${DATA_DIR}/tools",
  "screenshots_dir": "${DATA_DIR}/screenshots",
  "wordlists_dir": "${DATA_DIR}/wordlists",
  "nuclei_templates": "${DATA_DIR}/nuclei-templates"
}
JSON

  if [ "${GENERATED}" = "1" ]; then
    echo ""
    echo "  ┌───────────────────────────────────────────────────────────────┐"
    echo "  │  Reconner — generated admin credentials (FIRST BOOT ONLY)      │"
    echo "  ├───────────────────────────────────────────────────────────────┤"
    printf '  │  username: %-51s │\n' "${ADMIN_USER}"
    printf '  │  password: %-51s │\n' "${ADMIN_PASSWORD}"
    echo "  ├───────────────────────────────────────────────────────────────┤"
    echo "  │  Save it now. It is stored in the config inside the volume;    │"
    echo "  │  retrieve later with:                                          │"
    echo "  │    docker compose exec reconner \\                              │"
    echo "  │      sh -c 'grep admin_password \$RECON_CONFIG'                 │"
    echo "  └───────────────────────────────────────────────────────────────┘"
    echo ""
  fi
else
  echo "==> Existing config found at ${CFG} — leaving it (and the database) untouched."
  echo "    (Retrieve the admin password with: grep admin_password ${CFG})"
fi

# The server serves the dashboard from ./frontend/dist relative to the working
# directory, so run from the install dir where the built dist was copied.
cd /opt/reconner
echo "==> Starting Reconner on port ${PORT} ..."
exec reconner serve
