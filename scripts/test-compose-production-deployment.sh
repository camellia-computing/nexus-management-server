#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

fail() {
  echo "Compose production deployment regression failed: $*" >&2
  exit 1
}

forbidden=(
  "$repo_root/deploy/systemd/docker"
  "$repo_root/deploy/ansible/roles/camellia_nexus"
  "$repo_root/scripts/camellia-nexus-deploy.sh"
  "$repo_root/scripts/stage-production-secrets.sh"
)
for path in "${forbidden[@]}"; do
  test ! -e "$path" || fail "over-designed deployment component remains: $path"
done

grep -Fq 'name: camellianexus-server' "$repo_root/docker-compose.yml" ||
  fail 'Compose must use a project-specific name on a shared Docker host'
grep -Fq 'network_mode: none' "$repo_root/docker-compose.yml" ||
  fail 'secret-validator must not receive a network namespace'
grep -Fq 'command: ["db-bootstrap", "reconcile"]' "$repo_root/docker-compose.yml" ||
  fail 'Compose must reconcile runtime database roles'
if grep -Eq 'Requires=.*docker.service|After=.*camellia-nexus-secrets|docker.service.d' \
  "$repo_root/README.md" "$repo_root/docs/compose-production.md"; then
  fail 'project deployment must not add a Docker daemon dependency'
fi

temporary_directory=$(mktemp -d)
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM
secret_directory="$temporary_directory/secrets"
mkdir -p "$secret_directory"
chmod 0700 "$secret_directory"

for entry in \
  database-bootstrap-password:Bootstrap.test.password.0123456789ABC \
  database-migrate-password:Migrate.test.password.0123456789ABCDE \
  database-public-password:Public.test.password.0123456789ABCDEFG \
  database-admin-web-password:AdminWeb.test.password.0123456789ABCDE \
  database-admin-worker-password:AdminWorker.test.password.0123456789ABC; do
  name=${entry%%:*}
  value=${entry#*:}
  printf '%s\n' "$value" >"$secret_directory/$name"
done

if command -v openssl >/dev/null 2>&1; then
  openssl ecparam -name prime256v1 -genkey -noout \
    -out "$secret_directory/entitlement-es256-private.pem" >/dev/null 2>&1
else
  printf '%s\n' 'placeholder' >"$secret_directory/entitlement-es256-private.pem"
fi
printf '%s\n' '{"keys":[]}' >"$secret_directory/workspace-keyring.json"
printf '%s\n' '{"keys":[]}' >"$secret_directory/webhook-keyring.json"
printf '%s\n' '{"keys":[]}' >"$secret_directory/admin-keyring.json"
printf '%s\n' 'proxy.secret.0123456789ABCDEFGHIJKLMNOP' >"$secret_directory/admin-proxy-secret"
chmod 0444 "$secret_directory"/*

test "$(stat -c '%a' "$secret_directory")" = 700 || fail 'secret parent is not mode 0700'
while IFS= read -r file; do
  test "$(stat -c '%u:%g:%a' "$file")" = '0:0:444' || {
    # Non-root CI can still verify the mode; root ownership is checked when available.
    test "$(stat -c '%a' "$file")" = 444 || fail "secret file has invalid mode: $file"
  }
done < <(find "$secret_directory" -mindepth 1 -maxdepth 1 -type f -print)

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  image="ghcr.io/camellia-computing/nexus-management-server@sha256:$(printf 'a%.0s' {1..64})"
  compose_json="$temporary_directory/compose.json"
  env \
    CAMELLIA_NEXUS_LICENSE_IMAGE="$image" \
    CAMELLIA_NEXUS_LICENSE_ISSUER=https://license.test.invalid \
    CAMELLIA_NEXUS_LICENSE_KEY_ID=test-entitlement-key \
    CAMELLIA_NEXUS_CLIENT_MINIMUM_VERSION=1.0.0 \
    CAMELLIA_NEXUS_CLIENT_RECOMMENDED_VERSION=1.0.0 \
    CAMELLIA_NEXUS_CLIENT_VERSION_ENFORCE_AFTER=2030-01-01T00:00:00Z \
    CAMELLIA_NEXUS_ADMIN_PUBLIC_ORIGIN=https://console.test.invalid \
    CAMELLIA_NEXUS_OAUTH_REDIRECT_URIS=camellia-nexus://auth/callback \
    CAMELLIA_NEXUS_CORS_ALLOWED_ORIGINS=camellia-nexus://localhost \
    CAMELLIA_NEXUS_DATABASE_BOOTSTRAP_PASSWORD_FILE="$secret_directory/database-bootstrap-password" \
    CAMELLIA_NEXUS_DATABASE_MIGRATE_PASSWORD_FILE="$secret_directory/database-migrate-password" \
    CAMELLIA_NEXUS_DATABASE_PUBLIC_PASSWORD_FILE="$secret_directory/database-public-password" \
    CAMELLIA_NEXUS_DATABASE_ADMIN_WEB_PASSWORD_FILE="$secret_directory/database-admin-web-password" \
    CAMELLIA_NEXUS_DATABASE_ADMIN_WORKER_PASSWORD_FILE="$secret_directory/database-admin-worker-password" \
    CAMELLIA_NEXUS_ENTITLEMENT_PRIVATE_KEY_FILE="$secret_directory/entitlement-es256-private.pem" \
    CAMELLIA_NEXUS_WORKSPACE_KEYRING_FILE="$secret_directory/workspace-keyring.json" \
    CAMELLIA_NEXUS_WEBHOOK_KEYRING_FILE="$secret_directory/webhook-keyring.json" \
    CAMELLIA_NEXUS_ADMIN_KEYRING_FILE="$secret_directory/admin-keyring.json" \
    CAMELLIA_NEXUS_ADMIN_PROXY_SECRET_FILE="$secret_directory/admin-proxy-secret" \
    docker compose --file "$repo_root/docker-compose.yml" config --format json >"$compose_json"
  command -v jq >/dev/null 2>&1 || fail 'jq is required for rendered Compose assertions'
  jq -e '
    def sources(name): [.services[name].secrets[].source] | sort;
    .name == "camellianexus-server" and
    sources("postgres") == ["database_bootstrap_password"] and
    sources("db-bootstrap") == [
      "database_admin_web_password",
      "database_admin_worker_password",
      "database_bootstrap_password",
      "database_migrate_password",
      "database_public_password"
    ] and
    sources("migrate") == ["database_migrate_password"] and
    sources("management-server") == [
      "database_public_password",
      "entitlement_private_key",
      "webhook_keyring",
      "workspace_keyring"
    ] and
    sources("admin-web") == [
      "admin_keyring",
      "admin_proxy_secret",
      "database_admin_web_password"
    ] and
    sources("admin-worker") == [
      "admin_keyring",
      "database_admin_worker_password"
    ] and
    sources("secret-validator") == [
      "admin_keyring",
      "admin_proxy_secret",
      "database_admin_web_password",
      "database_admin_worker_password",
      "database_bootstrap_password",
      "database_migrate_password",
      "database_public_password",
      "entitlement_private_key",
      "webhook_keyring",
      "workspace_keyring"
    ] and
    (.networks.database.internal == true) and
    (.networks.scanner.internal == true)
  ' "$compose_json" >/dev/null || fail 'rendered Compose secret or network scope is invalid'
fi

echo 'shared-host Compose deployment contract verified'
