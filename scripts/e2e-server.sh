#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
e2e_root=$(mktemp -d "${TMPDIR:-/tmp}/reconner-e2e.XXXXXX")
server_pid=""

cleanup() {
	if [ -n "$server_pid" ]; then
		kill "$server_pid" 2>/dev/null || true
		wait "$server_pid" 2>/dev/null || true
	fi
	case "$e2e_root" in
		*/reconner-e2e.*) rm -rf -- "$e2e_root" ;;
	esac
}
trap cleanup EXIT INT TERM

e2e_port=${RECON_E2E_PORT:-18080}
config_path="$e2e_root/config.json"
binary_path="$e2e_root/reconner-e2e"

printf '%s\n' "{
  \"host\": \"127.0.0.1\",
  \"port\": $e2e_port,
  \"database_path\": \"$e2e_root/recon.db\",
  \"data_dir\": \"$e2e_root/data\",
  \"tools_dir\": \"$e2e_root/tools\",
  \"screenshots_dir\": \"$e2e_root/screenshots\",
  \"wordlists_dir\": \"$e2e_root/wordlists\",
  \"nuclei_templates\": \"$e2e_root/nuclei-templates\",
  \"session_secret\": \"e2e-session-secret-32-bytes-long!\",
  \"csrf_secret\": \"e2e-csrf-secret-32-bytes-long!!!\",
  \"admin_username\": \"admin\",
  \"admin_password\": \"change_m)_e\",
  \"update_check_enabled\": false,
  \"log_level\": \"error\",
  \"limits\": {
    \"max_concurrent_targets\": 1,
    \"max_scans_per_target\": 1,
    \"max_tool_executions\": 1,
    \"max_memory_mb\": 512,
    \"parallel_modules\": false,
    \"http_rate_limit\": 30
  }
}" > "$config_path"

cd "$repo_root"
go build -o "$binary_path" ./cmd/reconner
RECON_CONFIG="$config_path" RECON_NO_AUTOTUNE=1 "$binary_path" &
server_pid=$!
wait "$server_pid"
