#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

fail() {
  echo "database secret boundary regression failed: $*" >&2
  exit 1
}

deployment="$repo_root/src/deployment.rs"
compose="$repo_root/docker-compose.yml"
test -f "$deployment" || fail 'database bootstrap implementation is missing'

for variable in \
  CAMELLIA_NEXUS_DATABASE_BOOTSTRAP_PASSWORD_FILE \
  CAMELLIA_NEXUS_DATABASE_MIGRATE_PASSWORD_FILE \
  CAMELLIA_NEXUS_DATABASE_PUBLIC_PASSWORD_FILE \
  CAMELLIA_NEXUS_DATABASE_ADMIN_WEB_PASSWORD_FILE \
  CAMELLIA_NEXUS_DATABASE_ADMIN_WORKER_PASSWORD_FILE; do
  rg -Fq "$variable" "$deployment" || fail "bootstrap does not read $variable"
done

rg -Fq '.bind(managed.password.as_str())' "$deployment" ||
  fail 'managed database role passwords must use prepared file values'
if rg -n 'config\.bootstrap\.password|bootstrap-password-next|rotate-bootstrap|adopt-existing|RECONCILE_BOOTSTRAP_ROLE_SQL' \
  "$deployment"; then
  fail 'bootstrap password rotation and legacy adoption must not be part of the deployment CLI'
fi
rg -Fq 'WHERE granted.rolname = $1 OR member.rolname = $1' "$deployment" ||
  fail 'bootstrap must remove both inbound and outbound managed-role memberships'
if rg -n 'format!\([^\n]*(password|PASSWORD)|AssertSqlSafe\([^\n]*(password|PASSWORD)' "$deployment"; then
  fail 'a database password may be interpolated into dynamic SQL'
fi
if rg -n 'CAMELLIA_NEXUS_DATABASE_(BOOTSTRAP|MIGRATE|PUBLIC|ADMIN_WEB|ADMIN_WORKER)_PASSWORD:' \
  "$compose"; then
  fail 'Compose exposes a database password as an environment value'
fi
rg -Fq 'DATABASE_PASSWORD_FILE: /run/secrets/database_bootstrap_password' "$compose" ||
  fail 'bootstrap authentication must receive only a projected file path'
rg -Fq 'DATABASE_PASSWORD_FILE: /run/secrets/database_migrate_password' "$compose" ||
  fail 'migration authentication must receive only a projected file path'

echo 'database bootstrap keeps passwords in file and bound-parameter boundaries'
