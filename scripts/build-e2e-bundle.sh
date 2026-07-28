#!/usr/bin/env bash
set -euo pipefail
umask 077

server_image="${1:-}"
output_directory="${2:-}"
postgres_image='postgres:18-alpine@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15'

fail() {
  echo "Windows E2E bundle: $*" >&2
  exit 1
}

if [[ -z "$server_image" || -z "$output_directory" ]]; then
  echo "Usage: $0 <server-image> <output-directory>" >&2
  exit 2
fi

for command in docker jq sha256sum tar; do
  command -v "$command" >/dev/null || {
    echo "$command is required to build the Windows/WSL E2E bundle" >&2
    exit 2
  }
done

if [[ -e "$output_directory" ]]; then
  echo "Refusing to replace an existing E2E bundle: $output_directory" >&2
  exit 1
fi

temporary_directory="$(mktemp -d)"
containers=()
cleanup() {
  if ((${#containers[@]})); then
    docker rm --force "${containers[@]}" >/dev/null 2>&1 || true
  fi
  rm -rf "$temporary_directory"
}
trap cleanup EXIT HUP INT TERM

docker image inspect "$server_image" >/dev/null
docker image inspect "$postgres_image" >/dev/null 2>&1 || docker pull "$postgres_image" >/dev/null
for image in "$server_image" "$postgres_image"; do
  [[ "$(docker image inspect --format '{{.Architecture}}' "$image")" == amd64 ]] ||
    fail "image must target linux/amd64: $image"
done

postgres_version_output="$(docker run --rm --entrypoint postgres "$postgres_image" --version)"
[[ "$postgres_version_output" =~ ^postgres\ \(PostgreSQL\)\ (18(\.[0-9]+){1,2})$ ]] ||
  fail "PostgreSQL 18.x is required; found: $postgres_version_output"
postgres_version="${BASH_REMATCH[1]}"

export_rootfs() {
  local image="$1"
  local output="$2"
  local container
  container="$(docker create --entrypoint /bin/true "$image")"
  containers+=("$container")
  docker export --output "$output" "$container"
  test -s "$output"
}

server_rootfs="$temporary_directory/server-rootfs.tar"
postgres_rootfs="$temporary_directory/postgres-rootfs.tar"
export_rootfs "$server_image" "$server_rootfs"
export_rootfs "$postgres_image" "$postgres_rootfs"

require_rootfs_entries() {
  local archive="$1"
  shift
  local entry
  for entry in "$@"; do
    tar -tf "$archive" "$entry" >/dev/null || fail "root filesystem is missing $entry"
  done
}
require_rootfs_entries "$server_rootfs" \
  bin \
  usr/bin/sh \
  usr/local/bin/camellia-nexus-management-server
require_rootfs_entries "$postgres_rootfs" \
  bin/sh \
  usr/local/bin/docker-entrypoint.sh \
  usr/local/bin/postgres

server_version="$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.version" }}' "$server_image")"
server_revision="$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$server_image")"
[[ "$server_version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
[[ "$server_revision" =~ ^[0-9a-f]{40}$ ]]

mkdir -m 0700 "$output_directory"
mv "$server_rootfs" "$output_directory/server-rootfs.tar"
mv "$postgres_rootfs" "$output_directory/postgres-rootfs.tar"

server_sha="$(sha256sum "$output_directory/server-rootfs.tar" | cut -d' ' -f1)"
postgres_sha="$(sha256sum "$output_directory/postgres-rootfs.tar" | cut -d' ' -f1)"
server_size="$(stat --format '%s' "$output_directory/server-rootfs.tar")"
postgres_size="$(stat --format '%s' "$output_directory/postgres-rootfs.tar")"

jq -n \
  --arg server_image "$server_image" \
  --arg server_version "$server_version" \
  --arg server_revision "$server_revision" \
  --arg postgres_image "$postgres_image" \
  --arg postgres_version "$postgres_version" \
  --arg server_sha "$server_sha" \
  --arg postgres_sha "$postgres_sha" \
  --argjson server_size "$server_size" \
  --argjson postgres_size "$postgres_size" \
  '{
    schemaVersion: 2,
    purpose: "Camellia Nexus Windows native E2E only",
    runtime: {
      wslVersion: 2,
      architecture: "x86_64",
      networking: "shared-loopback"
    },
    server: {
      image: $server_image,
      version: $server_version,
      revision: $server_revision,
      rootfs: { file: "server-rootfs.tar", sha256: $server_sha, bytes: $server_size }
    },
    postgres: {
      image: $postgres_image,
      version: $postgres_version,
      majorVersion: 18,
      rootfs: { file: "postgres-rootfs.tar", sha256: $postgres_sha, bytes: $postgres_size }
    }
  }' >"$output_directory/manifest.json"
chmod 0600 "$output_directory/manifest.json" "$output_directory"/*.tar

jq -e '
  .schemaVersion == 2 and
  .purpose == "Camellia Nexus Windows native E2E only" and
  .runtime == {wslVersion: 2, architecture: "x86_64", networking: "shared-loopback"} and
  (.server.version | test("^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$")) and
  (.server.revision | test("^[0-9a-f]{40}$")) and
  (.server.rootfs.sha256 | test("^[0-9a-f]{64}$")) and
  (.postgres.version | test("^18\\.[0-9]+(\\.[0-9]+)?$")) and
  .postgres.majorVersion == 18 and
  (.postgres.rootfs.sha256 | test("^[0-9a-f]{64}$"))
' "$output_directory/manifest.json" >/dev/null

echo "Portable Windows/WSL2 E2E bundle created at $output_directory"
