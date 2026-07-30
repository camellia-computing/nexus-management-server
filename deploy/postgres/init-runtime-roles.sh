#!/usr/bin/env bash
set -euo pipefail

required=(
  CAMELLIA_NEXUS_DATABASE_PUBLIC_ROLE
  CAMELLIA_NEXUS_DATABASE_PUBLIC_PASSWORD
  CAMELLIA_NEXUS_DATABASE_ADMIN_WEB_ROLE
  CAMELLIA_NEXUS_DATABASE_ADMIN_WEB_PASSWORD
  CAMELLIA_NEXUS_DATABASE_ADMIN_WORKER_ROLE
  CAMELLIA_NEXUS_DATABASE_ADMIN_WORKER_PASSWORD
)
for name in "${required[@]}"; do
  [[ -n "${!name:-}" ]] || {
    printf 'database bootstrap variable %s is required\n' "$name" >&2
    exit 1
  }
done

for name in \
  CAMELLIA_NEXUS_DATABASE_PUBLIC_ROLE \
  CAMELLIA_NEXUS_DATABASE_ADMIN_WEB_ROLE \
  CAMELLIA_NEXUS_DATABASE_ADMIN_WORKER_ROLE; do
  [[ "${!name}" =~ ^[a-z_][a-z0-9_]{0,62}$ ]] || {
    printf 'database role %s is not a safe lowercase PostgreSQL identifier\n' "$name" >&2
    exit 1
  }
done

for name in \
  CAMELLIA_NEXUS_DATABASE_PUBLIC_PASSWORD \
  CAMELLIA_NEXUS_DATABASE_ADMIN_WEB_PASSWORD \
  CAMELLIA_NEXUS_DATABASE_ADMIN_WORKER_PASSWORD; do
  [[ "${!name}" =~ ^[A-Za-z0-9._~-]{32,128}$ ]] || {
    printf 'database password %s must be 32-128 URL-safe random characters\n' "$name" >&2
    exit 1
  }
done

if [[ "$CAMELLIA_NEXUS_DATABASE_PUBLIC_ROLE" == "$CAMELLIA_NEXUS_DATABASE_ADMIN_WEB_ROLE" ||
  "$CAMELLIA_NEXUS_DATABASE_PUBLIC_ROLE" == "$CAMELLIA_NEXUS_DATABASE_ADMIN_WORKER_ROLE" ||
  "$CAMELLIA_NEXUS_DATABASE_ADMIN_WEB_ROLE" == "$CAMELLIA_NEXUS_DATABASE_ADMIN_WORKER_ROLE" ]]; then
  printf 'database runtime roles must be distinct\n' >&2
  exit 1
fi

psql --set ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" \
  --set public_role="$CAMELLIA_NEXUS_DATABASE_PUBLIC_ROLE" \
  --set public_password="$CAMELLIA_NEXUS_DATABASE_PUBLIC_PASSWORD" \
  --set admin_web_role="$CAMELLIA_NEXUS_DATABASE_ADMIN_WEB_ROLE" \
  --set admin_web_password="$CAMELLIA_NEXUS_DATABASE_ADMIN_WEB_PASSWORD" \
  --set admin_worker_role="$CAMELLIA_NEXUS_DATABASE_ADMIN_WORKER_ROLE" \
  --set admin_worker_password="$CAMELLIA_NEXUS_DATABASE_ADMIN_WORKER_PASSWORD" <<'SQL'
SELECT format(
  'CREATE ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
  :'public_role',
  :'public_password'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'public_role') \gexec
SELECT format(
  'CREATE ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
  :'admin_web_role',
  :'admin_web_password'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'admin_web_role') \gexec
SELECT format(
  'CREATE ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
  :'admin_worker_role',
  :'admin_worker_password'
) WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'admin_worker_role') \gexec
SQL
