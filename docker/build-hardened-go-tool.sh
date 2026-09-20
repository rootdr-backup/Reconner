#!/bin/sh
set -eu

module="$1"
version="$2"
package="$3"
binary="$4"
output_dir="${OUTPUT_DIR:-/out}"

module_dir="$(go mod download -json "${module}@${version}" | awk -F '"' '/"Dir":/ { print $4; exit }')"
if [ -z "$module_dir" ] || [ ! -d "$module_dir" ]; then
	echo "BUILD FAILURE: could not resolve ${module}@${version}" >&2
	exit 1
fi

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT INT TERM
cp -a "${module_dir}/." "$work_dir/"
chmod -R u+w "$work_dir"
cd "$work_dir"

# A few deliberately pinned legacy tools (notably assetfinder v0.1.1) predate
# Go modules.  The module cache can still resolve and verify their source, but
# module-aware hardening commands below require a local go.mod.  Create one in
# this disposable copy only; the downloaded source and upstream release remain
# untouched.
if [ ! -f go.mod ]; then
	go mod init "$module"
fi

upgrade_if_present() {
	dependency="$1"
	fixed_version="$2"
	if go list -m -f '{{.Path}}' all | grep -Fqx "$dependency"; then
		go get "${dependency}@${fixed_version}"
	fi
}

# Tool releases can lag security-only transitive dependency updates. Rebuild
# their unchanged tagged source against the minimum audited fixed versions.
case "$binary" in
	asnmap)
		upgrade_if_present github.com/quic-go/quic-go v0.54.1
		upgrade_if_present golang.org/x/oauth2 v0.27.0
		;;
	gau)
		upgrade_if_present github.com/sirupsen/logrus v1.10.2
		upgrade_if_present github.com/valyala/fasthttp v1.34.0
		;;
	hakrawler)
		upgrade_if_present github.com/antchfx/xpath v1.3.6
		;;
	katana)
		upgrade_if_present github.com/jackc/pgx/v5 v5.9.0
		;;
	nuclei)
		upgrade_if_present github.com/go-git/go-git/v5 v5.19.2
		upgrade_if_present google.golang.org/grpc v1.83.2
		;;
esac
# Keep the coordinated Go subrepository set last. Updating one of these can
# otherwise downgrade another through minimal-version selection.
upgrade_if_present golang.org/x/crypto v0.55.0
upgrade_if_present golang.org/x/text v0.41.0
upgrade_if_present golang.org/x/mod v0.40.0
upgrade_if_present golang.org/x/net v0.58.0

mkdir -p "$output_dir"
go build -trimpath -ldflags='-s -w' -o "${output_dir}/${binary}" "$package"
