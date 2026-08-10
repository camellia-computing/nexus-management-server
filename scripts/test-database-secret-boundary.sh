#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

fail() {
  echo "database secret boundary regression failed: $*" >&2
  exit 1
}

search_fixed_quiet() {
  local pattern=$1
  local path=$2

  if command -v rg >/dev/null 2>&1; then
    rg -Fq -- "$pattern" "$path"
  else
    grep -Fq -- "$pattern" "$path"
  fi
}

search_regex_lines() {
  local pattern=$1
  local path=$2

  if command -v rg >/dev/null 2>&1; then
    rg -n -- "$pattern" "$path"
  else
    grep -En -- "$pattern" "$path"
  fi
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
  search_fixed_quiet "$variable" "$deployment" || fail "bootstrap does not read $variable"
done

search_fixed_quiet "set_config('camellia_nexus.bootstrap_password', \$2, true)" "$deployment" ||
  fail 'database passwords must cross the SQL boundary as bind parameters'
search_fixed_quiet '.bind(config.bootstrap.password.as_str())' "$deployment" ||
  fail 'bootstrap password rotation must use the prepared file value'
search_fixed_quiet '.bind(managed.password.as_str())' "$deployment" ||
  fail 'managed database role passwords must use prepared file values'
search_fixed_quiet "WHERE granted.rolname = \$1 OR member.rolname = \$1" "$deployment" ||
  fail 'bootstrap must remove both inbound and outbound managed-role memberships'
if search_regex_lines 'format!\(.*(password|PASSWORD)|AssertSqlSafe\(.*(password|PASSWORD)' \
  "$deployment"; then
  fail 'a database password may be interpolated into dynamic SQL'
fi
if search_regex_lines \
  'CAMELLIA_NEXUS_DATABASE_(BOOTSTRAP|MIGRATE|PUBLIC|ADMIN_WEB|ADMIN_WORKER)_PASSWORD:' \
  "$compose"; then
  fail 'Compose exposes a database password as an environment value'
fi
search_fixed_quiet 'DATABASE_PASSWORD_FILE: /run/secrets/database_bootstrap_password' "$compose" ||
  fail 'bootstrap authentication must receive only a projected file path'
search_fixed_quiet 'DATABASE_PASSWORD_FILE: /run/secrets/database_migrate_password' "$compose" ||
  fail 'migration authentication must receive only a projected file path'

echo 'database bootstrap keeps passwords in file and bound-parameter boundaries'
