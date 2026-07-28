#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
unit_dir="$repo_root/deploy/systemd"

fail() {
  echo "systemd deployment regression failed: $*" >&2
  exit 1
}

assert_contains() {
  local file=$1
  local value=$2
  grep -Fq "$value" "$file" || fail "$(basename "$file") is missing: $value"
}

migrate="$unit_dir/camellia-nexus-management-migrate.service"
public="$unit_dir/camellia-nexus-management-server.service"
admin_web="$unit_dir/camellia-nexus-management-admin-web.service"
admin_worker="$unit_dir/camellia-nexus-management-admin-worker.service"

for file in "$migrate" "$public" "$admin_web" "$admin_worker"; do
  test -f "$file" || fail "missing unit $file"
  assert_contains "$file" 'User=camellia-license'
  assert_contains "$file" 'NoNewPrivileges=true'
  assert_contains "$file" 'ProtectSystem=strict'
  assert_contains "$file" 'CapabilityBoundingSet='
  assert_contains "$file" 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6'
done

assert_contains "$migrate" 'Type=oneshot'
assert_contains "$migrate" 'ExecStart=/usr/local/bin/camellia-nexus-management-server migrate'
assert_contains "$migrate" 'RemainAfterExit=yes'

for entry in \
  "$public|serve|public-api.env" \
  "$admin_web|admin-web|admin-web.env" \
  "$admin_worker|admin-worker|admin-worker.env"; do
  IFS='|' read -r file role environment_file <<<"$entry"
  assert_contains "$file" "Requires=camellia-nexus-management-migrate.service"
  assert_contains "$file" "ExecStart=/usr/local/bin/camellia-nexus-management-server $role"
  assert_contains "$file" "EnvironmentFile=/etc/camellia-nexus/$environment_file"
  assert_contains "$file" 'TimeoutStopSec=30s'
done

assert_contains "$repo_root/deploy/management-common.env.example" 'CAMELLIA_NEXUS_DATABASE_MIGRATE=false'
assert_contains "$repo_root/deploy/public-api.env.example" 'CAMELLIA_NEXUS_METRICS_BIND=127.0.0.1:9091'
assert_contains "$repo_root/deploy/admin-web.env.example" 'CAMELLIA_NEXUS_METRICS_BIND=127.0.0.1:9092'
assert_contains "$repo_root/deploy/admin-worker.env.example" 'CAMELLIA_NEXUS_METRICS_BIND=127.0.0.1:9093'
if rg -n '^CAMELLIA_NEXUS_DATABASE_MIGRATE=true$' "$repo_root/deploy"; then
  fail 'production systemd examples must not enable automatic migrations'
fi

if command -v systemd-analyze >/dev/null 2>&1; then
  verification_dir=$(mktemp -d)
  trap 'rm -rf "$verification_dir"' EXIT
  for file in "$unit_dir"/*.service; do
    sed \
      -e 's#^ExecStart=.*#ExecStart=/usr/bin/true#' \
      -e 's#^EnvironmentFile=#EnvironmentFile=-#' \
      "$file" >"$verification_dir/$(basename "$file")"
  done
  if ! verification=$(systemd-analyze verify "$verification_dir"/*.service 2>&1); then
    printf '%s\n' "$verification" >&2
    fail 'systemd-analyze rejected a deployment unit'
  fi
fi

echo 'systemd runtime roles, migration ordering, and hardening verified'
