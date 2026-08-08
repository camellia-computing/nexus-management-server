#!/usr/bin/env bash
set -euo pipefail

required=(
  CAMELLIA_NEXUS_DATABASE_PUBLIC_ROLE
  CAMELLIA_NEXUS_DATABASE_PUBLIC_PASSWORD_FILE
  CAMELLIA_NEXUS_DATABASE_ADMIN_WEB_ROLE
  CAMELLIA_NEXUS_DATABASE_ADMIN_WEB_PASSWORD_FILE
  CAMELLIA_NEXUS_DATABASE_ADMIN_WORKER_ROLE
  CAMELLIA_NEXUS_DATABASE_ADMIN_WORKER_PASSWORD_FILE
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

read_password_file() {
  local file_variable=$1
  local password_variable=$2
  local path="${!file_variable}"
  [[ -f "$path" && -r "$path" ]] || {
    printf 'database password file %s must be a regular readable file\n' "$file_variable" >&2
    exit 1
  }
  local password
  password="$(cat -- "$path"; printf x)"
  password="${password%x}"
  if [[ "$password" == *$'\n' ]]; then
    password="${password%$'\n'}"
    if [[ "$password" == *$'\r' ]]; then
      password="${password%$'\r'}"
    fi
  fi
  [[ "$password" =~ ^[A-Za-z0-9._~-]{32,128}$ ]] || {
    printf 'database password file %s must contain 32-128 URL-safe random characters\n' \
      "$file_variable" >&2
    exit 1
  }
  # Keep the value as a shell-local variable. It is supplied to psql through
  # stdin below, never as an argument or exported environment variable.
  printf -v "$password_variable" '%s' "$password"
}

public_password=
admin_web_password=
admin_worker_password=
read_password_file \
  CAMELLIA_NEXUS_DATABASE_PUBLIC_PASSWORD_FILE public_password
read_password_file \
  CAMELLIA_NEXUS_DATABASE_ADMIN_WEB_PASSWORD_FILE admin_web_password
read_password_file \
  CAMELLIA_NEXUS_DATABASE_ADMIN_WORKER_PASSWORD_FILE admin_worker_password

if [[ "$CAMELLIA_NEXUS_DATABASE_PUBLIC_ROLE" == "$CAMELLIA_NEXUS_DATABASE_ADMIN_WEB_ROLE" ||
  "$CAMELLIA_NEXUS_DATABASE_PUBLIC_ROLE" == "$CAMELLIA_NEXUS_DATABASE_ADMIN_WORKER_ROLE" ||
  "$CAMELLIA_NEXUS_DATABASE_ADMIN_WEB_ROLE" == "$CAMELLIA_NEXUS_DATABASE_ADMIN_WORKER_ROLE" ]]; then
  printf 'database runtime roles must be distinct\n' >&2
  exit 1
fi

{
  printf '\\set public_role %s\n' "$CAMELLIA_NEXUS_DATABASE_PUBLIC_ROLE"
  printf '\\set public_password %s\n' "$public_password"
  printf '\\set admin_web_role %s\n' "$CAMELLIA_NEXUS_DATABASE_ADMIN_WEB_ROLE"
  printf '\\set admin_web_password %s\n' "$admin_web_password"
  printf '\\set admin_worker_role %s\n' "$CAMELLIA_NEXUS_DATABASE_ADMIN_WORKER_ROLE"
  printf '\\set admin_worker_password %s\n' "$admin_worker_password"
  cat <<'SQL'
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
} | psql --set ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB"
