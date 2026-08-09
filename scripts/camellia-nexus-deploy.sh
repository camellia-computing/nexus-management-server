#!/usr/bin/env bash
set -euo pipefail

install_root=$(realpath -m -- "${CAMELLIA_NEXUS_INSTALL_ROOT:-/opt/camellia-nexus}")
config_file=${CAMELLIA_NEXUS_CONFIG_FILE:-/etc/camellia-nexus/config.env}
stage_command=${CAMELLIA_NEXUS_STAGE_COMMAND:-/usr/local/libexec/camellia-nexus/stage-production-secrets}
evidence_validator=${CAMELLIA_NEXUS_RELEASE_EVIDENCE_VALIDATOR:-/usr/local/libexec/camellia-nexus/validate-release-evidence}
lock_file=${CAMELLIA_NEXUS_DEPLOY_LOCK:-/run/lock/camellia-nexus-deploy.lock}
state_root=$(realpath -m -- "${CAMELLIA_NEXUS_STATE_ROOT:-/var/lib/camellia-nexus}")
current_release=$install_root/current

case $install_root in
  /opt/camellia-nexus | /opt/camellia-nexus/*) ;;
  *)
    echo 'CAMELLIA_NEXUS_INSTALL_ROOT must stay below /opt/camellia-nexus' >&2
    exit 1
    ;;
esac

[[ ${EUID:-$(id -u)} == 0 ]] || {
  echo 'camellia-nexus-deploy must run as root' >&2
  exit 1
}
for required_command in docker flock realpath stat; do
  command -v "$required_command" >/dev/null 2>&1 || {
    echo "$required_command is required" >&2
    exit 1
  }
done
docker compose version >/dev/null
[[ -f $config_file && ! -L $config_file ]] || {
  echo "missing non-secret configuration file: $config_file" >&2
  exit 1
}
[[ $(stat -c '%u:%g:%a' "$config_file") == 0:0:640 ]] || {
  echo "non-secret configuration must be root:root 0640: $config_file" >&2
  exit 1
}
install -d -o root -g root -m 0755 "$(dirname "$lock_file")"
exec 9>"$lock_file"
flock -n 9 || {
  echo 'another Camellia Nexus deployment operation is active' >&2
  exit 1
}

release_directory=${CAMELLIA_NEXUS_RELEASE_DIRECTORY:-$current_release}

compose() {
  docker compose \
    --project-name camellianexus-server \
    --project-directory "$release_directory" \
    --env-file "$config_file" \
    --file "$release_directory/compose.yaml" \
    "$@"
}

compose_with_override() {
  local override=$1
  shift
  docker compose \
    --project-name camellianexus-server \
    --project-directory "$release_directory" \
    --env-file "$config_file" \
    --file "$release_directory/compose.yaml" \
    --file "$override" \
    "$@"
}

require_release() {
  [[ -d $release_directory && ! -L $release_directory ]] || {
    echo "release directory is missing or unsafe: $release_directory" >&2
    exit 1
  }
  [[ -f $release_directory/compose.yaml && ! -L $release_directory/compose.yaml ]] || {
    echo 'release compose.yaml must be a regular non-symlink file' >&2
    exit 1
  }
  [[ $(stat -c '%u:%g:%a' "$release_directory") == 0:0:755 ]] || {
    echo 'release directory must be root:root 0755' >&2
    exit 1
  }
  [[ $(stat -c '%u:%g:%a' "$release_directory/compose.yaml") == 0:0:444 ]] || {
    echo 'release compose.yaml must be root:root 0444' >&2
    exit 1
  }
  for required_command in cosign jq python3; do
    command -v "$required_command" >/dev/null 2>&1 || {
      echo "$required_command is required for release verification" >&2
      exit 1
    }
  done
  local evidence=$release_directory/release-evidence.json
  [[ -f $evidence && ! -L $evidence ]] || {
    echo 'release-evidence.json is required' >&2
    exit 1
  }
  [[ $(stat -c '%u:%g:%a' "$evidence") == 0:0:444 ]] || {
    echo 'release-evidence.json must be root:root 0444' >&2
    exit 1
  }
  [[ -x $evidence_validator && ! -L $evidence_validator ]] || {
    echo "release evidence validator is missing or unsafe: $evidence_validator" >&2
    exit 1
  }
  [[ $(stat -c '%u:%g:%a' "$evidence_validator") == 0:0:555 ]] || {
    echo 'release evidence validator must be root:root 0555' >&2
    exit 1
  }
  "$evidence_validator" "$evidence" >/dev/null
  compose config --quiet
  local reference
  while IFS= read -r reference; do
    [[ $reference =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]] || {
      echo "production Compose image is not pinned by canonical digest: $reference" >&2
      exit 1
    }
  done < <(compose config --images)

  local application_image repository digest version expected_identity
  application_image=$(compose config --format json | jq -er '.services["management-server"].image')
  repository=${application_image%@*}
  digest=${application_image##*@}
  version=$(jq -er '.version' "$evidence")
  expected_identity="https://github.com/camellia-computing/nexus-management-server/.github/workflows/publish-release.yml@refs/tags/v$version"
  jq -e \
    --arg repository "$repository" \
    --arg digest "$digest" \
    --arg identity "$expected_identity" '
      .repository == "nexus-management" and
      .release_kind == "formal" and
      ([.images[] | select(
        .name == "nexus-management-service" and
        .digest == $digest and
        any(.registries[];
          .status == "published" and
          .repository == $repository and
          .digest == $digest and
          .readback == "verified" and
          .signature.mechanism == "keyless-cosign" and
          .signature.verification == "verified" and
          .signature.identity == $identity and
          .signature.issuer == "https://token.actions.githubusercontent.com"
        )
      )] | length) == 1
    ' "$evidence" >/dev/null || {
      echo 'Compose application image does not match trusted formal release evidence' >&2
      exit 1
    }
  cosign verify "$application_image" \
    --certificate-identity "$expected_identity" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    >/dev/null
}

require_runtime_model() {
  [[ -d $release_directory && ! -L $release_directory ]] || {
    echo "release directory is missing or unsafe: $release_directory" >&2
    exit 1
  }
  [[ -f $release_directory/compose.yaml && ! -L $release_directory/compose.yaml ]] || {
    echo 'release compose.yaml must be a regular non-symlink file' >&2
    exit 1
  }
  [[ $(stat -c '%u:%g:%a' "$release_directory") == 0:0:755 ]] || {
    echo 'current release directory must be root:root 0755' >&2
    exit 1
  }
  [[ $(stat -c '%u:%g:%a' "$release_directory/compose.yaml") == 0:0:444 ]] || {
    echo 'current release compose.yaml must be root:root 0444' >&2
    exit 1
  }
  compose config --quiet
}

record_deployment() (
  case $state_root in
    /var/lib/camellia-nexus | /var/lib/camellia-nexus/*) ;;
    *) echo 'CAMELLIA_NEXUS_STATE_ROOT must stay below /var/lib/camellia-nexus' >&2; return 1 ;;
  esac
  local evidence=$release_directory/release-evidence.json
  local secret_state=/run/camellia-nexus/secrets-stage.state
  [[ -f $secret_state && ! -L $secret_state ]] || {
    echo 'secret staging audit state is missing' >&2
    return 1
  }
  local bundle_digest staged_at application_image temporary=
  bundle_digest=$(sed -n 's/^sops_bundle_sha256=//p' "$secret_state")
  staged_at=$(sed -n 's/^staged_at_utc=//p' "$secret_state")
  [[ $bundle_digest =~ ^[0-9a-f]{64}$ \
    && $staged_at =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || {
    echo 'secret staging audit state is invalid' >&2
    return 1
  }
  application_image=$(compose config --format json | jq -er '.services["management-server"].image')
  install -d -o root -g root -m 0700 "$state_root"
  [[ ! -L $state_root && $(realpath -e -- "$state_root") == "$state_root" ]] || {
    echo 'deployment state directory is unsafe' >&2
    return 1
  }
  temporary=$(mktemp "$state_root/.deployment-state.XXXXXX")
  trap 'rm -f -- "${temporary:-}"' EXIT
  jq -n \
    --arg recorded_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg release_directory "$release_directory" \
    --arg release_version "$(jq -er '.version' "$evidence")" \
    --arg source_commit "$(jq -er '.source.commit' "$evidence")" \
    --arg application_image "$application_image" \
    --arg compose_sha256 "$(sha256sum "$release_directory/compose.yaml" | awk '{print $1}')" \
    --arg config_sha256 "$(sha256sum "$config_file" | awk '{print $1}')" \
    --arg sops_bundle_sha256 "$bundle_digest" \
    --arg secrets_staged_at "$staged_at" \
    '{
      schemaVersion: 1,
      recordedAt: $recorded_at,
      releaseDirectory: $release_directory,
      releaseVersion: $release_version,
      sourceCommit: $source_commit,
      migrationContract: $source_commit,
      applicationImage: $application_image,
      composeSha256: $compose_sha256,
      configSha256: $config_sha256,
      sopsBundleSha256: $sops_bundle_sha256,
      secretsStagedAt: $secrets_staged_at
    }' >"$temporary"
  chown root:root "$temporary"
  chmod 0600 "$temporary"
  mv -- "$temporary" "$state_root/deployment-state.json"
  temporary=
)

replace_current_link() {
  local target=$1
  local next=$install_root/.current.next
  if [[ -e $next && ! -L $next ]]; then
    echo "temporary current-release path is unsafe: $next" >&2
    return 1
  fi
  rm -f -- "$next"
  ln -s -- "$target" "$next"
  mv -Tf -- "$next" "$current_release"
}

activate_release() {
  local previous=
  if [[ -L $current_release ]]; then
    previous=$(realpath -e -- "$current_release") || {
      echo 'current release symlink is dangling or unsafe' >&2
      return 1
    }
  elif [[ -e $current_release ]]; then
    echo 'current release path must be a symlink' >&2
    return 1
  fi

  replace_current_link "$release_directory"
  if ! record_deployment; then
    echo 'deployment audit recording failed; restoring the previous current-release link' >&2
    if [[ -n $previous ]]; then
      replace_current_link "$previous" || \
        echo 'failed to restore the previous current-release link' >&2
    else
      rm -f -- "$current_release"
    fi
    return 1
  fi
}

write_secret_override() {
  local output=$1
  local desired_directory=$2
  local connection_directory=${3:-}
  {
    if [[ -n $connection_directory ]]; then
      printf '%s\n' \
        'services:' \
        '  db-bootstrap:' \
        '    environment:' \
        '      DATABASE_PASSWORD_FILE: /run/secrets/database_bootstrap_connection_password' \
        '    secrets:' \
        '      - database_bootstrap_connection_password'
    fi
    printf '%s\n' \
      'secrets:' \
      "  database_bootstrap_password: {file: $desired_directory/database-bootstrap-password}" \
      "  database_migrate_password: {file: $desired_directory/database-migrate-password}" \
      "  database_public_password: {file: $desired_directory/database-public-password}" \
      "  database_admin_web_password: {file: $desired_directory/database-admin-web-password}" \
      "  database_admin_worker_password: {file: $desired_directory/database-admin-worker-password}" \
      "  entitlement_private_key: {file: $desired_directory/entitlement-es256-private.pem}" \
      "  workspace_keyring: {file: $desired_directory/workspace-keyring.json}" \
      "  webhook_keyring: {file: $desired_directory/webhook-keyring.json}" \
      "  admin_keyring: {file: $desired_directory/admin-keyring.json}" \
      "  admin_proxy_secret: {file: $desired_directory/admin-proxy-secret}"
    if [[ -n $connection_directory ]]; then
      printf '%s\n' \
        "  database_bootstrap_connection_password: {file: $connection_directory/database-bootstrap-password}"
    fi
  } >"$output"
  chown root:root "$output"
  chmod 0600 "$output"
}

validate_prepared_secrets() {
  local override result=0
  override=$(mktemp /run/camellia-nexus/.compose-preflight.XXXXXX.yaml)
  write_secret_override "$override" /run/camellia-nexus/secrets-next
  compose_with_override "$override" config --quiet || result=$?
  if [[ $result == 0 ]]; then
    compose_with_override "$override" run --rm --no-deps secret-validator || result=$?
  fi
  rm -f -- "$override"
  return "$result"
}

prepare_and_validate() {
  [[ -f $stage_command && ! -L $stage_command && -x $stage_command ]] || {
    echo "secret staging command is missing or unsafe: $stage_command" >&2
    return 1
  }
  [[ $(stat -c '%u:%g:%a' "$stage_command") == 0:0:555 ]] || {
    echo 'secret staging command must be root:root 0555' >&2
    return 1
  }
  "$stage_command" prepare
  validate_prepared_secrets
}

stage_and_validate() {
  prepare_and_validate
  if [[ -d /run/camellia-nexus/secrets && ! -L /run/camellia-nexus/secrets ]]; then
    local name
    for name in \
      database-bootstrap-password \
      database-migrate-password \
      database-public-password \
      database-admin-web-password \
      database-admin-worker-password; do
      cmp -s "/run/camellia-nexus/secrets/$name" "/run/camellia-nexus/secrets-next/$name" || {
        echo "database credential drift detected for $name; use rotate-database-password" >&2
        return 1
      }
    done
  fi
  "$stage_command" activate-prepared
  compose run --rm --no-deps secret-validator
}

rotate_database_password() {
  local target=$1
  local target_file
  case $target in
    bootstrap) target_file=database-bootstrap-password ;;
    migrate) target_file=database-migrate-password ;;
    public) target_file=database-public-password ;;
    admin-web) target_file=database-admin-web-password ;;
    admin-worker) target_file=database-admin-worker-password ;;
    *) echo 'unknown database role' >&2; return 2 ;;
  esac
  [[ -d /run/camellia-nexus/secrets && ! -L /run/camellia-nexus/secrets ]] || {
    echo 'active runtime secrets are required before database password rotation' >&2
    return 1
  }

  "$stage_command" prepare
  local candidate_override rollback_override
  candidate_override=$(mktemp /run/camellia-nexus/.compose-candidate.XXXXXX.yaml)
  rollback_override=$(mktemp /run/camellia-nexus/.compose-rollback.XXXXXX.yaml)
  trap 'rm -f -- "${candidate_override:-}" "${rollback_override:-}"' EXIT HUP INT TERM
  write_secret_override "$candidate_override" /run/camellia-nexus/secrets-next /run/camellia-nexus/secrets
  write_secret_override "$rollback_override" /run/camellia-nexus/secrets /run/camellia-nexus/secrets-next
  compose_with_override "$candidate_override" config --quiet
  compose_with_override "$candidate_override" run --rm --no-deps secret-validator

  local name changed=0
  for name in \
    database-bootstrap-password \
    database-migrate-password \
    database-public-password \
    database-admin-web-password \
    database-admin-worker-password \
    entitlement-es256-private.pem \
    workspace-keyring.json \
    webhook-keyring.json \
    admin-keyring.json \
    admin-proxy-secret; do
    if ! cmp -s "/run/camellia-nexus/secrets/$name" "/run/camellia-nexus/secrets-next/$name"; then
      [[ $name == "$target_file" ]] || {
        echo "rotation bundle changes unexpected secret: $name" >&2
        return 1
      }
      changed=1
    fi
  done
  [[ $changed == 1 ]] || {
    echo "prepared $target database password is unchanged" >&2
    return 1
  }

  compose up -d --wait postgres
  compose_with_override "$candidate_override" run --rm --no-deps \
    db-bootstrap db-bootstrap reconcile
  if ! "$stage_command" activate-prepared; then
    echo 'secret activation failed; attempting to restore active database credentials' >&2
    compose_with_override "$rollback_override" run --rm --no-deps \
      db-bootstrap db-bootstrap reconcile || \
      echo 'automatic credential recovery failed; retain /run/camellia-nexus/secrets-next and follow the recovery runbook' >&2
    return 1
  fi

  case $target in
    bootstrap) compose up -d --no-deps --force-recreate --wait postgres ;;
    migrate) compose run --rm --no-deps migrate ;;
    public) compose up -d --no-deps --force-recreate management-server ;;
    admin-web) compose up -d --no-deps --force-recreate admin-web ;;
    admin-worker) compose up -d --no-deps --force-recreate admin-worker ;;
  esac
  compose run --rm --no-deps db-bootstrap db-bootstrap check
  wait_for_runtime
  rm -f -- "$candidate_override" "$rollback_override"
  trap - EXIT HUP INT TERM
}

service_state() {
  local service=$1
  local expected_health=$2
  local ids state
  ids=$(compose ps --all --quiet "$service")
  [[ $(wc -w <<<"$ids") == 1 ]] || return 1
  state=$(docker inspect --format '{{.State.Running}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$ids")
  [[ $state == "true $expected_health" ]]
}

runtime_is_ready() {
  service_state postgres healthy \
    && service_state clamav healthy \
    && service_state management-server healthy \
    && service_state admin-web healthy \
    && service_state admin-worker healthy
}

wait_for_runtime() {
  local deadline=$((SECONDS + 180))
  while ((SECONDS < deadline)); do
    if runtime_is_ready; then
      return 0
    fi
    sleep 3
  done
  compose ps -a
  return 1
}

run_release() {
  stage_and_validate
  compose pull --policy always
  compose up -d --wait postgres clamav
  compose run --rm --no-deps db-bootstrap db-bootstrap reconcile
  compose run --rm --no-deps db-bootstrap db-bootstrap check
  compose run --rm --no-deps migrate
  compose up -d --no-deps --force-recreate management-server admin-web admin-worker
  wait_for_runtime
  compose ps -a
}

case ${1:-} in
  preflight)
    [[ $# == 2 ]] || { echo 'usage: camellia-nexus-deploy preflight <release-directory>' >&2; exit 2; }
    release_directory=$(realpath -e -- "$2")
    require_release
    prepare_and_validate
    ;;
  deploy)
    [[ $# == 2 ]] || { echo 'usage: camellia-nexus-deploy deploy <release-directory>' >&2; exit 2; }
    release_directory=$(realpath -e -- "$2")
    require_release
    run_release
    activate_release
    ;;
  boot | reconcile)
    [[ $# == 1 ]] || { echo "usage: camellia-nexus-deploy $1" >&2; exit 2; }
    release_directory=$(realpath -e -- "$current_release")
    require_release
    run_release
    record_deployment
    ;;
  adopt-existing)
    [[ $# == 2 ]] || { echo 'usage: camellia-nexus-deploy adopt-existing <release-directory>' >&2; exit 2; }
    release_directory=$(realpath -e -- "$2")
    require_release
    stage_and_validate
    compose up -d --wait postgres
    migration_url=$(compose config --format json | jq -er '.services.migrate.environment.DATABASE_URL')
    compose run --rm --no-deps \
      --env "DATABASE_URL=$migration_url" \
      --env DATABASE_PASSWORD_FILE=/run/secrets/database_migrate_password \
      db-bootstrap db-bootstrap adopt-existing --confirm-adopt-existing-production
    compose run --rm --no-deps db-bootstrap db-bootstrap check
    ;;
  rotate-database-password)
    [[ $# == 2 ]] || { echo 'usage: camellia-nexus-deploy rotate-database-password <bootstrap|migrate|public|admin-web|admin-worker>' >&2; exit 2; }
    release_directory=$(realpath -e -- "$current_release")
    require_release
    rotate_database_password "$2"
    record_deployment
    ;;
  status)
    [[ $# == 1 ]] || { echo 'usage: camellia-nexus-deploy status' >&2; exit 2; }
    release_directory=$(realpath -e -- "$current_release")
    require_runtime_model
    compose ps -a
    runtime_is_ready
    ;;
  stop)
    [[ $# == 1 ]] || { echo 'usage: camellia-nexus-deploy stop' >&2; exit 2; }
    release_directory=$(realpath -e -- "$current_release")
    require_runtime_model
    compose stop
    ;;
  admin)
    [[ $# -ge 2 ]] || { echo 'usage: camellia-nexus-deploy admin <group> <operation> [...]' >&2; exit 2; }
    release_directory=$(realpath -e -- "$current_release")
    require_runtime_model
    shift
    compose run --rm --no-deps admin-web admin "$@"
    ;;
  rollback)
    [[ $# == 2 ]] || { echo 'usage: camellia-nexus-deploy rollback <release-directory>' >&2; exit 2; }
    release_directory=$(realpath -e -- "$2")
    require_release
    run_release
    activate_release
    ;;
  *)
    echo 'usage: camellia-nexus-deploy <preflight|deploy|boot|reconcile|adopt-existing|rotate-database-password|status|stop|admin|rollback> [...]' >&2
    exit 2
    ;;
esac
