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
  assert_contains "$file" 'NoNewPrivileges=true'
  assert_contains "$file" 'ProtectSystem=strict'
  assert_contains "$file" 'ProtectProc=invisible'
  assert_contains "$file" 'ProcSubset=pid'
  assert_contains "$file" 'CapabilityBoundingSet='
  assert_contains "$file" 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6'
done

assert_contains "$migrate" 'User=camellia-nexus-migrate'
assert_contains "$public" 'User=camellia-nexus-public'
assert_contains "$admin_web" 'User=camellia-nexus-admin-web'
assert_contains "$admin_worker" 'User=camellia-nexus-admin-worker'
users=$(sed -n 's/^User=//p' "$migrate" "$public" "$admin_web" "$admin_worker" | sort -u | wc -l)
[[ "$users" -eq 4 ]] || fail 'every runtime boundary must use a distinct operating-system user'

assert_contains "$migrate" 'Type=oneshot'
assert_contains "$migrate" 'ExecStart=/usr/local/bin/camellia-nexus-management-server migrate'
assert_contains "$migrate" 'EnvironmentFile=/etc/camellia-nexus/migrate.env'
assert_contains "$migrate" 'InaccessiblePaths=-/etc/camellia-nexus/secrets -/var/lib/camellia-nexus'
assert_contains "$migrate" 'RemainAfterExit=yes'
assert_contains "$public" 'InaccessiblePaths=-/etc/camellia-nexus/secrets/admin -/var/lib/camellia-nexus/admin-objects'
assert_contains "$admin_web" 'InaccessiblePaths=-/etc/camellia-nexus/secrets/public'
assert_contains "$admin_worker" 'InaccessiblePaths=-/etc/camellia-nexus/secrets/public'
assert_contains "$admin_web" 'ReadWritePaths=/var/lib/camellia-nexus/admin-objects'
assert_contains "$admin_worker" 'ReadWritePaths=/var/lib/camellia-nexus/admin-objects'
assert_contains "$admin_web" 'SupplementaryGroups=camellia-nexus-admin'
assert_contains "$admin_worker" 'SupplementaryGroups=camellia-nexus-admin'

for entry in \
  "$public|serve|public-api.env|30s" \
  "$admin_web|admin-web|admin-web.env|210s" \
  "$admin_worker|admin-worker|admin-worker.env|30s"; do
  IFS='|' read -r file role environment_file stop_timeout <<<"$entry"
  assert_contains "$file" "Requires=camellia-nexus-management-migrate.service"
  assert_contains "$file" "ExecStart=/usr/local/bin/camellia-nexus-management-server $role"
  assert_contains "$file" "EnvironmentFile=/etc/camellia-nexus/$environment_file"
  assert_contains "$file" "TimeoutStopSec=$stop_timeout"
done

assert_contains "$repo_root/deploy/management-common.env.example" 'CAMELLIA_NEXUS_DATABASE_MIGRATE=false'
if grep -q '^DATABASE_URL=' "$repo_root/deploy/management-common.env.example"; then
  fail 'the shared environment must not expose one database owner credential to every role'
fi
for file in \
  "$repo_root/deploy/migrate.env.example" \
  "$repo_root/deploy/public-api.env.example" \
  "$repo_root/deploy/admin-web.env.example" \
  "$repo_root/deploy/admin-worker.env.example"; do
  assert_contains "$file" 'DATABASE_URL=postgres://'
done
assert_contains "$repo_root/deploy/migrate.env.example" 'CAMELLIA_NEXUS_DATABASE_PUBLIC_ROLE='
assert_contains "$repo_root/deploy/migrate.env.example" 'CAMELLIA_NEXUS_DATABASE_ADMIN_WEB_ROLE='
assert_contains "$repo_root/deploy/migrate.env.example" 'CAMELLIA_NEXUS_DATABASE_ADMIN_WORKER_ROLE='
assert_contains "$repo_root/deploy/public-api.env.example" 'CAMELLIA_NEXUS_METRICS_BIND=127.0.0.1:9091'
assert_contains "$repo_root/deploy/public-api.env.example" '/secrets/public/'
assert_contains "$repo_root/deploy/admin-web.env.example" 'CAMELLIA_NEXUS_METRICS_BIND=127.0.0.1:9092'
assert_contains "$repo_root/deploy/admin-web.env.example" '/secrets/admin/'
assert_contains "$repo_root/deploy/admin-worker.env.example" 'CAMELLIA_NEXUS_METRICS_BIND=127.0.0.1:9093'
assert_contains "$repo_root/deploy/admin-worker.env.example" '/secrets/admin/'
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
