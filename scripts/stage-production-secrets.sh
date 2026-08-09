#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} != 0 ]]; then
  echo 'production secret staging must run as root' >&2
  exit 1
fi

bundle=${CAMELLIA_NEXUS_SOPS_FILE:-/etc/camellia-nexus/secrets.sops.yaml}
age_identity=${SOPS_AGE_KEY_FILE:-/etc/camellia-nexus/sops/age-identity.txt}
runtime_root=$(realpath -m -- "${CAMELLIA_NEXUS_RUNTIME_ROOT:-/run/camellia-nexus}")
deployment_state_file=$(realpath -m -- "${CAMELLIA_NEXUS_DEPLOYMENT_STATE_FILE:-/var/lib/camellia-nexus/deployment-state.json}")
secrets_directory=$runtime_root/secrets
prepared_directory=$runtime_root/secrets-next
mode=${1:-activate}
required_secrets=(
  database-bootstrap-password
  database-migrate-password
  database-public-password
  database-admin-web-password
  database-admin-worker-password
  entitlement-es256-private.pem
  workspace-keyring.json
  webhook-keyring.json
  admin-keyring.json
  admin-proxy-secret
)

case "$mode" in
  activate | prepare | activate-prepared) ;;
  *)
    echo 'usage: stage-production-secrets [activate|prepare|activate-prepared]' >&2
    exit 2
    ;;
esac

case "$runtime_root" in
  /run/camellia-nexus | /run/camellia-nexus/*) ;;
  *)
    echo 'CAMELLIA_NEXUS_RUNTIME_ROOT must stay below /run/camellia-nexus' >&2
    exit 1
    ;;
esac
case "$deployment_state_file" in
  /var/lib/camellia-nexus/deployment-state.json | /var/lib/camellia-nexus/*) ;;
  *)
    echo 'CAMELLIA_NEXUS_DEPLOYMENT_STATE_FILE must stay below /var/lib/camellia-nexus' >&2
    exit 1
    ;;
esac

install -d -o root -g root -m 0700 "$runtime_root"

validate_directory() {
  local directory=$1
  [[ -d $directory && ! -L $directory ]] || return 1
  [[ $(stat -c '%u:%g:%a' "$directory") == 0:0:700 ]] || return 1
  [[ $(find "$directory" -mindepth 1 -maxdepth 1 -type f | wc -l) -eq ${#required_secrets[@]} ]] || return 1
  [[ $(find "$directory" -mindepth 1 -maxdepth 1 ! -type f | wc -l) -eq 0 ]] || return 1
  local name
  for name in "${required_secrets[@]}"; do
    [[ -f $directory/$name && ! -L $directory/$name && -s $directory/$name ]] || return 1
    [[ $(stat -c '%u:%g:%a' "$directory/$name") == 0:0:444 ]] || return 1
    [[ $(stat -c %s "$directory/$name") -le 65536 ]] || return 1
  done
}

validate_state_file() {
  local state=$1
  [[ -f $state && ! -L $state ]] || return 1
  [[ $(stat -c '%u:%g:%a' "$state") == 0:0:600 ]] || return 1
  [[ $(wc -l <"$state") -eq 2 ]] || return 1
  local digest staged_at
  digest=$(sed -n 's/^sops_bundle_sha256=//p' "$state")
  staged_at=$(sed -n 's/^staged_at_utc=//p' "$state")
  [[ $digest =~ ^[0-9a-f]{64}$ ]] || return 1
  [[ $staged_at =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || return 1
}

activate_directory() {
  local source=$1
  local source_state=$2
  local previous=$runtime_root/.secrets-previous
  validate_directory "$source" || {
    echo "prepared secret directory is missing or unsafe: $source" >&2
    exit 1
  }
  validate_state_file "$source_state" || {
    echo "prepared secret state is missing or unsafe: $source_state" >&2
    exit 1
  }
  if [[ -e $previous ]]; then
    rm -rf -- "$previous"
  fi
  if [[ -e $secrets_directory ]] && ! validate_directory "$secrets_directory"; then
    echo "active secret directory is unsafe: $secrets_directory" >&2
    exit 1
  fi
  if [[ -d $secrets_directory ]]; then
    mv -- "$secrets_directory" "$previous"
  fi
  if ! mv -- "$source" "$secrets_directory"; then
    if [[ -d $previous && ! -e $secrets_directory ]]; then
      mv -- "$previous" "$secrets_directory"
    fi
    exit 1
  fi
  if ! mv -- "$source_state" "$runtime_root/secrets-stage.state"; then
    mv -- "$secrets_directory" "$source"
    if [[ -d $previous ]]; then
      mv -- "$previous" "$secrets_directory"
    fi
    exit 1
  fi
  if [[ -d $previous ]]; then
    rm -rf -- "$previous"
  fi
}

if [[ $mode == activate-prepared ]]; then
  activate_directory "$prepared_directory" "$runtime_root/secrets-next.state"
  echo 'Camellia Nexus prepared production secrets activated successfully'
  exit 0
fi

command -v sops >/dev/null 2>&1 || {
  echo 'sops is required for production secret staging' >&2
  exit 1
}
[[ -f "$bundle" && ! -L "$bundle" ]] || {
  echo 'the encrypted SOPS bundle must be a regular non-symlink file' >&2
  exit 1
}
[[ $(stat -c '%u:%g:%a' "$bundle") == 0:0:600 ]] || {
  echo 'the encrypted SOPS bundle must be root:root 0600' >&2
  exit 1
}
[[ -f "$age_identity" && ! -L "$age_identity" ]] || {
  echo 'the age identity must be a regular non-symlink file' >&2
  exit 1
}
[[ $(stat -c '%u:%g:%a' "$age_identity") == 0:0:400 ]] || {
  echo 'the age identity must be root:root 0400' >&2
  exit 1
}

bundle_digest=$(sha256sum "$bundle" | awk '{print $1}')
if [[ $mode == activate && -e $deployment_state_file ]]; then
  [[ -f $deployment_state_file && ! -L $deployment_state_file ]] || {
    echo 'the previous deployment audit state is unsafe' >&2
    exit 1
  }
  [[ $(stat -c '%u:%g:%a' "$deployment_state_file") == 0:0:600 ]] || {
    echo 'the previous deployment audit state must be root:root 0600' >&2
    exit 1
  }
  command -v jq >/dev/null 2>&1 || {
    echo 'jq is required to verify the previous deployment audit state' >&2
    exit 1
  }
  expected_bundle_digest=$(jq -er '.sopsBundleSha256 | select(test("^[0-9a-f]{64}$"))' \
    "$deployment_state_file") || {
    echo 'the previous deployment audit state is invalid' >&2
    exit 1
  }
  [[ $bundle_digest == "$expected_bundle_digest" ]] || {
    echo 'the encrypted SOPS bundle differs from the last successful deployment; use the locked deployment or rotation workflow' >&2
    exit 1
  }
fi

staging=$(mktemp -d "$runtime_root/.secrets-staging.XXXXXX")
state_file=
cleanup() {
  if [[ -n ${staging:-} && -d $staging ]]; then
    rm -rf -- "$staging"
  fi
  if [[ -n ${state_file:-} && -f $state_file ]]; then
    rm -f -- "$state_file"
  fi
}
trap cleanup EXIT
umask 077
export SOPS_AGE_KEY_FILE=$age_identity

extract() {
  local expression=$1
  local destination=$2
  sops --decrypt --extract "$expression" --output-type binary "$bundle" >"$staging/$destination"
  [[ -s "$staging/$destination" && ! -L "$staging/$destination" ]] || {
    echo "staged secret $destination is empty or invalid" >&2
    exit 1
  }
  if [[ $(stat -c %s "$staging/$destination") -gt 65536 ]]; then
    echo "staged secret $destination exceeds 64 KiB" >&2
    exit 1
  fi
  chown root:root "$staging/$destination"
  chmod 0444 "$staging/$destination"
}

extract '["database"]["bootstrap_password"]' database-bootstrap-password
extract '["database"]["migrate_password"]' database-migrate-password
extract '["database"]["public_password"]' database-public-password
extract '["database"]["admin_web_password"]' database-admin-web-password
extract '["database"]["admin_worker_password"]' database-admin-worker-password
extract '["crypto"]["entitlement_private_pem"]' entitlement-es256-private.pem
extract '["crypto"]["workspace_keyring_json"]' workspace-keyring.json
extract '["crypto"]["webhook_keyring_json"]' webhook-keyring.json
extract '["crypto"]["admin_keyring_json"]' admin-keyring.json
extract '["proxy"]["admin_secret"]' admin-proxy-secret

chmod 0700 "$staging"
chown root:root "$staging"

state_file=$(mktemp "$runtime_root/.secrets-state.XXXXXX")
printf 'sops_bundle_sha256=%s\nstaged_at_utc=%s\n' \
  "$bundle_digest" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  >"$state_file"
chown root:root "$state_file"
chmod 0600 "$state_file"

if [[ $mode == prepare ]]; then
  if [[ -e $prepared_directory ]]; then
    rm -rf -- "$prepared_directory"
  fi
  mv -- "$staging" "$prepared_directory"
  staging=
  mv -- "$state_file" "$runtime_root/secrets-next.state"
  state_file=
  echo 'Camellia Nexus production secrets prepared successfully'
else
  activate_directory "$staging" "$state_file"
  staging=
  state_file=
  echo 'Camellia Nexus production secrets staged successfully'
fi
