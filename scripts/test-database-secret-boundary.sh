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
  grep -Fq -- "$variable" "$deployment" || fail "bootstrap does not read $variable"
done

grep -Fq -- "set_config('camellia_nexus.bootstrap_password', \$2, true)" "$deployment" ||
  fail 'database passwords must cross the SQL boundary as bind parameters'
grep -Fq -- '.bind(config.bootstrap.password.as_str())' "$deployment" ||
  fail 'bootstrap password rotation must use the prepared file value'
grep -Fq -- '.bind(managed.password.as_str())' "$deployment" ||
  fail 'managed database role passwords must use prepared file values'
grep -Fq -- "WHERE granted.rolname = \$1 OR member.rolname = \$1" "$deployment" ||
  fail 'bootstrap must remove both inbound and outbound managed-role memberships'
if grep -En -- 'format!\(.*(password|PASSWORD)|AssertSqlSafe\(.*(password|PASSWORD)' \
  "$deployment"; then
  fail 'a database password may be interpolated into dynamic SQL'
fi
if grep -En -- 'CAMELLIA_NEXUS_DATABASE_(BOOTSTRAP|MIGRATE|PUBLIC|ADMIN_WEB|ADMIN_WORKER)_PASSWORD:' \
  "$compose"; then
  fail 'Compose exposes a database password as an environment value'
fi
grep -Fq -- 'DATABASE_PASSWORD_FILE: /run/secrets/database_bootstrap_password' "$compose" ||
  fail 'bootstrap authentication must receive only a projected file path'
grep -Fq -- 'DATABASE_PASSWORD_FILE: /run/secrets/database_migrate_password' "$compose" ||
  fail 'migration authentication must receive only a projected file path'

echo 'database bootstrap keeps passwords in file and bound-parameter boundaries'
