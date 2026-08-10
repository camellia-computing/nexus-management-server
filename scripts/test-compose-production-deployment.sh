#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)

fail() {
  echo "Compose production deployment regression failed: $*" >&2
  exit 1
}

for file in \
  "$repo_root/scripts/stage-production-secrets.sh" \
  "$repo_root/scripts/camellia-nexus-deploy.sh"; do
  bash -n "$file"
  test -x "$file" || fail "$(basename "$file") must be executable"
done

if grep -En -- 'docker (compose )?(down -v|volume rm|system prune)' \
  "$repo_root/scripts/camellia-nexus-deploy.sh"; then
  fail 'the deployment entrypoint contains destructive volume cleanup'
fi
grep -Fq -- 'runtime_is_ready' "$repo_root/scripts/camellia-nexus-deploy.sh" ||
  fail 'status must return a readiness-sensitive exit status'
grep -Fq -- 'adopt-existing <release-directory>' "$repo_root/scripts/camellia-nexus-deploy.sh" ||
  fail 'legacy adoption must select the candidate release explicitly'
grep -Fq -- 'database credential drift detected' "$repo_root/scripts/camellia-nexus-deploy.sh" ||
  fail 'ordinary deployment must reject an uncoordinated database password change'
grep -Fq -- 'activate-prepared' "$repo_root/scripts/camellia-nexus-deploy.sh" ||
  fail 'database rotation must use two-phase secret activation'
grep -Fq -- 'deployment-state.json' "$repo_root/scripts/camellia-nexus-deploy.sh" ||
  fail 'successful deployment operations must record non-secret audit state'
grep -Fq -- 'compose up -d --no-deps --force-recreate management-server admin-web admin-worker' \
  "$repo_root/scripts/camellia-nexus-deploy.sh" ||
  fail 'release reconciliation must recreate every long-running secret consumer'

if sudo -n true >/dev/null 2>&1; then
  unsafe_runtime_root="/run/camellia-nexus/../compose-path-escape-$$"
  if sudo -n env \
    "CAMELLIA_NEXUS_RUNTIME_ROOT=$unsafe_runtime_root" \
    "$repo_root/scripts/stage-production-secrets.sh" prepare >/dev/null 2>&1; then
    fail 'secret staging accepted a runtime path containing a parent traversal'
  fi
fi

temporary_directory=$(mktemp -d)
runtime_root="/run/camellia-nexus/test-compose-production-$$"
deployment_state_file="/var/lib/camellia-nexus/test-compose-production-$$.json"
case "$runtime_root" in
  /run/camellia-nexus/test-compose-production-[0-9]*) ;;
  *) fail 'unsafe runtime test path' ;;
esac
cleanup() {
  sudo -n rm -rf -- "$runtime_root" >/dev/null 2>&1 || true
  sudo -n rm -f -- "$deployment_state_file" >/dev/null 2>&1 || true
  rm -rf -- "$temporary_directory"
}
trap cleanup EXIT HUP INT TERM

fixture_directory=$temporary_directory/fixture
fake_bin=$temporary_directory/bin
mkdir -p "$fixture_directory" "$fake_bin"
printf '%s\n' \
  'Bootstrap.test.password.0123456789ABC' >"$fixture_directory/database-bootstrap-password"
printf '%s\n' \
  'Migrate.test.password.0123456789ABCDE' >"$fixture_directory/database-migrate-password"
printf '%s\n' \
  'Public.test.password.0123456789ABCDEFG' >"$fixture_directory/database-public-password"
printf '%s\n' \
  'AdminWeb.test.password.0123456789ABCDE' >"$fixture_directory/database-admin-web-password"
printf '%s\n' \
  'AdminWorker.test.password.0123456789ABC' >"$fixture_directory/database-admin-worker-password"
"$repo_root/scripts/generate-entitlement-key.sh" \
  "$fixture_directory/entitlement-es256-private.pem" \
  "$fixture_directory/entitlement-es256-public.pem" >/dev/null
"$repo_root/scripts/generate-keyring.sh" workspace "$fixture_directory/workspace-keyring.json" >/dev/null
"$repo_root/scripts/generate-keyring.sh" webhook "$fixture_directory/webhook-keyring.json" >/dev/null
"$repo_root/scripts/generate-keyring.sh" admin "$fixture_directory/admin-keyring.json" >/dev/null
"$repo_root/scripts/generate-proxy-secret.sh" "$fixture_directory/admin-proxy-secret" >/dev/null

apply_fake_sops() {
  local fake=$1
  local marker='__FIXTURE_DIRECTORY__'
  cp "$repo_root/scripts/test-fixtures/fake-sops.sh" "$fake"
  sed -i "s#$marker#$fixture_directory#g" "$fake"
  chmod 0555 "$fake"
}

test -f "$repo_root/scripts/test-fixtures/fake-sops.sh" ||
  fail 'fake SOPS fixture is missing'
apply_fake_sops "$fake_bin/sops"
printf 'fixture encrypted bundle\n' >"$temporary_directory/secrets.sops.yaml"
printf 'invalid-age-identity-for-fake-sops-only\n' >"$temporary_directory/age-identity.txt"
chmod 0600 "$temporary_directory/secrets.sops.yaml"
chmod 0400 "$temporary_directory/age-identity.txt"

run_stage() {
  sudo -n env \
    "PATH=$fake_bin:$PATH" \
    "CAMELLIA_NEXUS_TEST_FIXTURE_DIRECTORY=$fixture_directory" \
    "CAMELLIA_NEXUS_SOPS_FILE=$temporary_directory/secrets.sops.yaml" \
    "SOPS_AGE_KEY_FILE=$temporary_directory/age-identity.txt" \
    "CAMELLIA_NEXUS_RUNTIME_ROOT=$runtime_root" \
    "CAMELLIA_NEXUS_DEPLOYMENT_STATE_FILE=$deployment_state_file" \
    "$repo_root/scripts/stage-production-secrets.sh" "$@"
}

if sudo -n true >/dev/null 2>&1; then
  sudo -n chown root:root \
    "$temporary_directory/secrets.sops.yaml" \
    "$temporary_directory/age-identity.txt"
  run_stage prepare >/dev/null
  test ! -e "$runtime_root/secrets" || fail 'prepare changed the active secret set'
  test "$(sudo -n stat -c '%u:%g:%a' "$runtime_root/secrets-next")" = 0:0:700 ||
    fail 'prepared secret directory ownership or mode is invalid'
  prepared_count=$(sudo -n find "$runtime_root/secrets-next" -mindepth 1 -maxdepth 1 -type f | wc -l)
  test "$prepared_count" -eq 10 || fail 'prepared secret set is incomplete'
  while IFS= read -r staged_file; do
    test "$(sudo -n stat -c '%u:%g:%a' "$staged_file")" = 0:0:444 ||
      fail "staged secret has invalid ownership or mode: $staged_file"
  done < <(sudo -n find "$runtime_root/secrets-next" -mindepth 1 -maxdepth 1 -type f)
  run_stage activate-prepared >/dev/null
  test "$(sudo -n stat -c '%u:%g:%a' "$runtime_root/secrets")" = 0:0:700 ||
    fail 'active secret directory ownership or mode is invalid'

  active_digest=$(sudo -n sha256sum "$runtime_root/secrets/database-public-password" | awk '{print $1}')
  printf '%s\n' 'Public.rotated.password.0123456789ABCDE' \
    >"$fixture_directory/database-public-password"
  run_stage prepare >/dev/null
  test "$(sudo -n sha256sum "$runtime_root/secrets/database-public-password" | awk '{print $1}')" = "$active_digest" ||
    fail 'preparing a rotation modified the active inode'
  test "$(sudo -n sha256sum "$runtime_root/secrets-next/database-public-password" | awk '{print $1}')" != "$active_digest" ||
    fail 'prepared rotation did not contain the candidate value'

  printf '{"sopsBundleSha256":"%064d"}\n' 0 >"$temporary_directory/deployment-state.json"
  sudo -n install -D -o root -g root -m 0600 \
    "$temporary_directory/deployment-state.json" "$deployment_state_file"
  if run_stage activate >/dev/null 2>&1; then
    fail 'boot-time secret staging accepted a bundle that was not recorded by a successful deployment'
  fi
else
  echo 'sudo -n is unavailable; skipped root-owned SOPS staging execution' >&2
fi

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  compose_json=$temporary_directory/compose.json
  image="ghcr.io/camellia-computing/nexus-management-server@sha256:$(printf 'a%.0s' {1..64})"
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
    CAMELLIA_NEXUS_DATABASE_BOOTSTRAP_PASSWORD_FILE="$fixture_directory/database-bootstrap-password" \
    CAMELLIA_NEXUS_DATABASE_MIGRATE_PASSWORD_FILE="$fixture_directory/database-migrate-password" \
    CAMELLIA_NEXUS_DATABASE_PUBLIC_PASSWORD_FILE="$fixture_directory/database-public-password" \
    CAMELLIA_NEXUS_DATABASE_ADMIN_WEB_PASSWORD_FILE="$fixture_directory/database-admin-web-password" \
    CAMELLIA_NEXUS_DATABASE_ADMIN_WORKER_PASSWORD_FILE="$fixture_directory/database-admin-worker-password" \
    CAMELLIA_NEXUS_ENTITLEMENT_PRIVATE_KEY_FILE="$fixture_directory/entitlement-es256-private.pem" \
    CAMELLIA_NEXUS_WORKSPACE_KEYRING_FILE="$fixture_directory/workspace-keyring.json" \
    CAMELLIA_NEXUS_WEBHOOK_KEYRING_FILE="$fixture_directory/webhook-keyring.json" \
    CAMELLIA_NEXUS_ADMIN_KEYRING_FILE="$fixture_directory/admin-keyring.json" \
    CAMELLIA_NEXUS_ADMIN_PROXY_SECRET_FILE="$fixture_directory/admin-proxy-secret" \
    docker compose --file "$repo_root/docker-compose.yml" config --format json >"$compose_json"
  jq -e '
    def sources(name): [.services[name].secrets[].source] | sort;
    .name == "camellianexus-server" and
    sources("postgres") == ["database_bootstrap_password"] and
    sources("migrate") == ["database_migrate_password"] and
    sources("management-server") == ["database_public_password", "entitlement_private_key", "webhook_keyring", "workspace_keyring"] and
    sources("admin-web") == ["admin_keyring", "admin_proxy_secret", "database_admin_web_password"] and
    sources("admin-worker") == ["admin_keyring", "database_admin_worker_password"] and
    (sources("db-bootstrap") | length) == 5 and
    (sources("secret-validator") | length) == 10 and
    .networks.database.internal == true and
    .networks.scanner.internal == true
  ' "$compose_json" >/dev/null || fail 'rendered Compose secret or network scope is invalid'
fi

echo 'Compose production staging, deployment policy, and secret scope verified'
