#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary_directory=$(mktemp -d)
trap 'rm -rf "$temporary_directory"' EXIT
mkdir -p "$temporary_directory/bin" "$temporary_directory/passwords" "$temporary_directory/capture"

fail() {
  echo "database secret boundary regression failed: $*" >&2
  exit 1
}

cat >"$temporary_directory/bin/psql" <<'PSQL'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" >"$CAPTURE_DIR/args"
env >"$CAPTURE_DIR/env"
cat >"$CAPTURE_DIR/stdin"
PSQL
chmod 0700 "$temporary_directory/bin/psql"

public_password='public.boundary.0123456789ABCDEFGHIJ'
admin_web_password='admin.web.boundary.0123456789ABCDEF'
admin_worker_password='admin.worker.boundary.0123456789ABCD'
printf '%s\n' "$public_password" >"$temporary_directory/passwords/public"
printf '%s\n' "$admin_web_password" >"$temporary_directory/passwords/admin-web"
printf '%s\n' "$admin_worker_password" >"$temporary_directory/passwords/admin-worker"

PATH="$temporary_directory/bin:$PATH" \
CAPTURE_DIR="$temporary_directory/capture" \
CAMELLIA_NEXUS_DATABASE_PUBLIC_ROLE=nexus_public \
CAMELLIA_NEXUS_DATABASE_PUBLIC_PASSWORD_FILE="$temporary_directory/passwords/public" \
CAMELLIA_NEXUS_DATABASE_ADMIN_WEB_ROLE=nexus_admin_web \
CAMELLIA_NEXUS_DATABASE_ADMIN_WEB_PASSWORD_FILE="$temporary_directory/passwords/admin-web" \
CAMELLIA_NEXUS_DATABASE_ADMIN_WORKER_ROLE=nexus_admin_worker \
CAMELLIA_NEXUS_DATABASE_ADMIN_WORKER_PASSWORD_FILE="$temporary_directory/passwords/admin-worker" \
POSTGRES_USER=nexus_migrate \
POSTGRES_DB=nexus \
  bash "$repo_root/deploy/postgres/init-runtime-roles.sh"

for secret in "$public_password" "$admin_web_password" "$admin_worker_password"; do
  if grep -Fq -- "$secret" "$temporary_directory/capture/args"; then
    fail 'a password was exposed through psql argv'
  fi
  if grep -Fq -- "$secret" "$temporary_directory/capture/env"; then
    fail 'a password was exported to the psql environment'
  fi
  grep -Fq -- "$secret" "$temporary_directory/capture/stdin"
done
grep -Fxq -- '--set' "$temporary_directory/capture/args"
for variable in public_password admin_web_password admin_worker_password; do
  if grep -Fq -- "$variable" "$temporary_directory/capture/args"; then
    fail 'a password variable was supplied through psql argv'
  fi
done

echo 'database bootstrap keeps passwords out of psql argv and environment'
