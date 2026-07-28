#!/usr/bin/env bash
set -euo pipefail
umask 077

command_name="${1:-}"
shift || true
state_root="${CAMELLIA_NEXUS_E2E_STATE_ROOT:-${XDG_RUNTIME_DIR:-/tmp}/camellia-nexus-e2e}"

usage() {
  cat >&2 <<'EOF'
Usage:
  scripts/provision-e2e-compose.sh up [--source PATH] [--host-port PORT] [--bind ADDRESS]
  scripts/provision-e2e-compose.sh logs <environment-id>
  scripts/provision-e2e-compose.sh pause <environment-id>
  scripts/provision-e2e-compose.sh resume <environment-id>
  scripts/provision-e2e-compose.sh account-state <environment-id> <account-id> <active|suspended|denylisted>
  scripts/provision-e2e-compose.sh down <environment-id>

Creates an isolated, disposable Docker Compose environment for native desktop E2E tests.
The `up` command writes one JSON descriptor to stdout. It contains one-use activation codes;
capture it securely and never persist it in source control or ordinary logs.
EOF
  exit 2
}

valid_id() {
  [[ "$1" =~ ^[a-f0-9]{12}$ ]]
}

environment_directory() {
  local environment_id="$1"
  valid_id "$environment_id" || {
    echo "Invalid E2E environment identifier" >&2
    exit 2
  }
  printf '%s/%s\n' "$state_root" "$environment_id"
}

case "$command_name" in
  up)
    source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    host_port=0
    bind_address=127.0.0.1
    while (($#)); do
      case "$1" in
        --source)
          (($# >= 2)) || usage
          source_root="$2"
          shift 2
          ;;
        --host-port)
          (($# >= 2)) || usage
          host_port="$2"
          shift 2
          ;;
        --bind)
          (($# >= 2)) || usage
          bind_address="$2"
          shift 2
          ;;
        *) usage ;;
      esac
    done
    ;;
  logs|pause|resume|down)
    (($# == 1)) || usage
    environment_id="$1"
    directory="$(environment_directory "$environment_id")"
    compose_file="$directory/compose.yaml"
    [[ -f "$compose_file" ]] || {
      echo "E2E environment does not exist: $environment_id" >&2
      exit 1
    }
    if [[ "$command_name" == logs ]]; then
      docker compose --project-directory "$directory" --file "$compose_file" logs --no-color
      exit 0
    fi
    if [[ "$command_name" == pause ]]; then
      docker compose --project-directory "$directory" --file "$compose_file" stop server >/dev/null
      exit 0
    fi
    if [[ "$command_name" == resume ]]; then
      docker compose --project-directory "$directory" --file "$compose_file" \
        up --detach --wait server >/dev/null
      exit 0
    fi
    image="$(<"$directory/image")"
    docker compose --project-directory "$directory" --file "$compose_file" \
      down --volumes --remove-orphans >/dev/null
    docker image rm "$image" >/dev/null 2>&1 || true
    rm -rf "$directory"
    rmdir "$state_root" >/dev/null 2>&1 || true
    echo "Removed E2E environment $environment_id" >&2
    exit 0
    ;;
  account-state)
    (($# == 3)) || usage
    environment_id="$1"
    account_id="$2"
    account_state="$3"
    directory="$(environment_directory "$environment_id")"
    compose_file="$directory/compose.yaml"
    [[ -f "$compose_file" ]] || {
      echo "E2E environment does not exist: $environment_id" >&2
      exit 1
    }
    [[ "$account_id" =~ ^[A-Za-z0-9_-]{1,128}$ ]] || {
      echo "Invalid E2E account identifier" >&2
      exit 2
    }
    case "$account_state" in
      active|suspended|denylisted) ;;
      *) usage ;;
    esac
    docker compose --project-directory "$directory" --file "$compose_file" \
      run --rm --no-deps server admin --raw account set-state "$account_id" "$account_state" \
      --actor native_e2e_control --reason 'native E2E controlled account transition' >/dev/null
    exit 0
    ;;
  *) usage ;;
esac

for dependency in curl docker jq openssl; do
  command -v "$dependency" >/dev/null || {
    echo "$dependency is required to provision an E2E Compose environment" >&2
    exit 2
  }
done
docker compose version >/dev/null
[[ -f "$source_root/Dockerfile" && -f "$source_root/Cargo.toml" ]] || {
  echo "The E2E source directory is not a management-server checkout: $source_root" >&2
  exit 2
}
if [[ ! "$host_port" =~ ^[0-9]+$ ]] || ((host_port < 0 || host_port > 65535)); then
  echo "--host-port must be 0 or an available TCP port" >&2
  exit 2
fi
case "$bind_address" in
  127.0.0.1|0.0.0.0) ;;
  *) echo "--bind must be 127.0.0.1 or 0.0.0.0" >&2; exit 2 ;;
esac
mkdir -p "$state_root"
chmod 0700 "$state_root"
environment_id="$(openssl rand -hex 6)"
directory="$(environment_directory "$environment_id")"
mkdir -m 0700 "$directory"
compose_file="$directory/compose.yaml"
image="nexus-management-e2e:$environment_id"
project="camellia-e2e-$environment_id"
docker_bind_directory="$directory"
if [[ "$(docker info --format '{{.OperatingSystem}}')" == "Docker Desktop" &&
      "$directory" =~ ^/mnt/([A-Za-z])/(.+)$ ]]; then
  docker_bind_directory="/run/desktop/mnt/host/${BASH_REMATCH[1],,}/${BASH_REMATCH[2]}"
fi
entitlement_private_source="$(jq -Rn --arg value "$docker_bind_directory/entitlement-private.pem" '$value')"
admin_keyring_source="$(jq -Rn --arg value "$docker_bind_directory/admin-keyring.json" '$value')"
workspace_keyring_source="$(jq -Rn --arg value "$docker_bind_directory/workspace-keyring.json" '$value')"
webhook_keyring_source="$(jq -Rn --arg value "$docker_bind_directory/webhook-keyring.json" '$value')"
started=false
cleanup_failed_up() {
  local status=$?
  trap - EXIT HUP INT TERM
  if [[ "$started" == true ]]; then
    if ((status != 0)); then
      echo "==> Disposable management-server startup failed; container logs follow" >&2
      docker compose --project-name "$project" --project-directory "$directory" \
        --file "$compose_file" logs --no-color >&2 || true
    fi
    docker compose --project-name "$project" --project-directory "$directory" \
      --file "$compose_file" down --volumes --remove-orphans >/dev/null 2>&1 || true
  fi
  docker image rm "$image" >/dev/null 2>&1 || true
  rm -rf "$directory"
  exit "$status"
}
trap cleanup_failed_up EXIT HUP INT TERM

version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$source_root/Cargo.toml" | head -1)"
revision="$(git -C "$source_root" rev-parse HEAD 2>/dev/null || true)"
[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
[[ "$revision" =~ ^[0-9a-f]{40}$ ]] || revision="$(printf '%040d' 0)"
source_url='https://example.invalid/camellia-nexus-management-server'

echo "==> Building disposable management-server image" >&2
DOCKER_BUILDKIT=1 docker build \
  --tag "$image" \
  --build-arg "VERSION=$version" \
  --build-arg "REVISION=$revision" \
  --build-arg "SOURCE=$source_url" \
  "$source_root" >/dev/null
printf '%s\n' "$image" >"$directory/image"

"$source_root/scripts/generate-entitlement-key.sh" \
  "$directory/entitlement-private.pem" "$directory/entitlement-public.pem" >/dev/null
"$source_root/scripts/generate-keyring.sh" admin "$directory/admin-keyring.json" >/dev/null
"$source_root/scripts/generate-keyring.sh" workspace "$directory/workspace-keyring.json" >/dev/null
"$source_root/scripts/generate-keyring.sh" webhook "$directory/webhook-keyring.json" >/dev/null
chmod 0444 "$directory/entitlement-private.pem" "$directory"/*-keyring.json

issuer="https://native-e2e-$environment_id.invalid"
cat >"$compose_file" <<EOF
name: $project
services:
  postgres:
    image: postgres:18-alpine@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15
    environment:
      POSTGRES_DB: camellia_license
      POSTGRES_USER: camellia
      POSTGRES_PASSWORD: e2e-only-password
    healthcheck:
      test: [CMD-SHELL, pg_isready -U camellia -d camellia_license]
      interval: 2s
      timeout: 3s
      retries: 30
    volumes:
      - postgres-data:/var/lib/postgresql
  server:
    image: $image
    command: [serve]
    depends_on:
      postgres:
        condition: service_healthy
    environment: &server-environment
      CAMELLIA_NEXUS_LICENSE_ENV: development
      CAMELLIA_NEXUS_LICENSE_STORAGE: postgres
      DATABASE_URL: postgres://camellia:e2e-only-password@postgres:5432/camellia_license
      CAMELLIA_NEXUS_LICENSE_ISSUER: $issuer
      CAMELLIA_NEXUS_LICENSE_AUDIENCE: camellia-nexus-desktop
      CAMELLIA_NEXUS_LICENSE_KEY_ID: entitlement-e2e
      CAMELLIA_NEXUS_LICENSE_PRIVATE_KEY_PEM_PATH: /run/secrets/entitlement-private.pem
      CAMELLIA_NEXUS_ADMIN_KEYRING_PATH: /run/secrets/admin-keyring.json
      CAMELLIA_NEXUS_WORKSPACE_KEYRING_PATH: /run/secrets/workspace-keyring.json
      CAMELLIA_NEXUS_WEBHOOK_KEYRING_PATH: /run/secrets/webhook-keyring.json
      CAMELLIA_NEXUS_OAUTH_CLIENT_ID: camellia-nexus-desktop
      CAMELLIA_NEXUS_OAUTH_REDIRECT_URIS: camellia-nexus://auth/callback
      CAMELLIA_NEXUS_CLIENT_MINIMUM_VERSION: 1.0.0
      CAMELLIA_NEXUS_CLIENT_RECOMMENDED_VERSION: 1.0.0
      CAMELLIA_NEXUS_CLIENT_VERSION_ENFORCE_AFTER: "2030-01-01T00:00:00Z"
      CAMELLIA_NEXUS_CORS_ALLOWED_ORIGINS: camellia-nexus://localhost
      CAMELLIA_NEXUS_DATABASE_MIGRATE: "false"
      CAMELLIA_NEXUS_LICENSE_BIND: 0.0.0.0:8088
      CAMELLIA_NEXUS_LOG_FORMAT: json
      CAMELLIA_NEXUS_LOG_LEVEL: trace
      CAMELLIA_NEXUS_HTTP_LOG_LEVEL: trace
      CAMELLIA_NEXUS_HTTP_FAILURE_LOG_LEVEL: trace
    ports:
      - target: 8088
        host_ip: $bind_address
        published: "$host_port"
        protocol: tcp
    volumes: &server-secrets
      - type: bind
        source: $entitlement_private_source
        target: /run/secrets/entitlement-private.pem
        read_only: true
        bind:
          create_host_path: false
      - type: bind
        source: $admin_keyring_source
        target: /run/secrets/admin-keyring.json
        read_only: true
        bind:
          create_host_path: false
      - type: bind
        source: $workspace_keyring_source
        target: /run/secrets/workspace-keyring.json
        read_only: true
        bind:
          create_host_path: false
      - type: bind
        source: $webhook_keyring_source
        target: /run/secrets/webhook-keyring.json
        read_only: true
        bind:
          create_host_path: false
    read_only: true
    tmpfs:
      - /tmp:size=64m,mode=1777
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
volumes:
  postgres-data:
EOF

docker compose --project-name "$project" --project-directory "$directory" \
  --file "$compose_file" up --detach --wait postgres >/dev/null
started=true
docker compose --project-name "$project" --project-directory "$directory" \
  --file "$compose_file" run --rm --no-deps server migrate >/dev/null

run_admin() {
  docker compose --project-name "$project" --project-directory "$directory" \
    --file "$compose_file" run --rm --no-deps server admin --raw "$@"
}

operator=native_e2e
reason='native desktop end-to-end verification'
free_account="acct_e2e_free_$environment_id"
free_license="lic_e2e_free_$environment_id"
pro_account="acct_e2e_pro_$environment_id"
pro_license="lic_e2e_pro_$environment_id"
team_account="acct_e2e_team_$environment_id"
team_license="lic_e2e_team_$environment_id"
offer_id="offer_e2e_pro_$environment_id"
payment_method_id="method_e2e_$environment_id"
invoice_id="invoice_e2e_pro_$environment_id"
run_admin account create "$pro_account" --actor "$operator" --reason "$reason" >/dev/null
run_admin license create "$pro_license" --account "$pro_account" --plan pro \
  --actor "$operator" --reason "$reason" >/dev/null
issue_code() {
  local account="$1"
  local license="$2"
  local operation_id="$3"
  local delivery
  delivery="$(run_admin code issue --account "$account" --license "$license" \
    --issued-by "$operator" --reason "$reason" --operation-id "$operation_id")"
  jq -er '
  if type == "array" and length == 1 and (.[0].code | type) == "string" and
      (.[0].code | length) > 0
  then .[0].code
  else error("expected exactly one issued activation code")
  end
' <<<"$delivery"
}
run_admin account create "$free_account" --actor "$operator" --reason "$reason" >/dev/null
run_admin license create "$free_license" --account "$free_account" --plan free \
  --actor "$operator" --reason "$reason" >/dev/null
free_primary_code="$(issue_code "$free_account" "$free_license" \
  "native-e2e-$environment_id-free-primary-code")"
free_second_device_code="$(issue_code "$free_account" "$free_license" \
  "native-e2e-$environment_id-free-second-device-code")"
pro_primary_code="$(issue_code "$pro_account" "$pro_license" \
  "native-e2e-$environment_id-pro-primary-code")"
pro_recovery_code="$(issue_code "$pro_account" "$pro_license" \
  "native-e2e-$environment_id-pro-recovery-code")"
run_admin billing offer create "$offer_id" --plan pro --duration-days 365 --currency USD \
  --amount 99.00 --name-en 'Native E2E Pro annual' --name-zh 'Native E2E Pro annual' \
  --actor "$operator" --reason "$reason" >/dev/null
run_admin billing method create "$payment_method_id" --name-en 'Native E2E bank transfer' \
  --name-zh 'Native E2E bank transfer' --instructions-en 'Use the synthetic E2E reference.' \
  --instructions-zh 'Use the synthetic E2E reference.' --asset USD \
  --destination-hint 'E2E-ONLY' --actor "$operator" --reason "$reason" >/dev/null
run_admin billing invoice create "$invoice_id" --account "$pro_account" --license "$pro_license" \
  --offer "$offer_id" --due-at 30d --actor "$operator" --reason "$reason" >/dev/null
run_admin account create "$team_account" --actor "$operator" --reason "$reason" >/dev/null
run_admin license create "$team_license" --account "$team_account" --plan team --seats 3 \
  --actor "$operator" --reason "$reason" >/dev/null
team_owner_code="$(issue_code "$team_account" "$team_license" \
  "native-e2e-$environment_id-team-owner-code")"
team_member_code="$(issue_code "$team_account" "$team_license" \
  "native-e2e-$environment_id-team-member-code")"
team_additional_device_code="$(issue_code "$team_account" "$team_license" \
  "native-e2e-$environment_id-team-additional-device-code")"

docker compose --project-name "$project" --project-directory "$directory" \
  --file "$compose_file" up --detach --wait server >/dev/null
published_address="$(docker compose --project-name "$project" --project-directory "$directory" \
  --file "$compose_file" port server 8088)"
host_port="${published_address##*:}"
if [[ ! "$host_port" =~ ^[1-9][0-9]*$ ]] || ((host_port > 65535)); then
  echo "Docker Compose did not publish a valid server port" >&2
  exit 1
fi
base_url="http://127.0.0.1:$host_port"
for _ in {1..60}; do
  if curl --fail --silent --show-error "$base_url/readyz" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl --fail --silent --show-error "$base_url/readyz" >/dev/null

descriptor="$directory/descriptor.json"
jq -n \
  --arg environment_id "$environment_id" \
  --arg base_url "$base_url" \
  --arg issuer "$issuer" \
  --arg public_key "$(base64 -w 0 "$directory/entitlement-public.pem")" \
  --arg free_account "$free_account" \
  --arg free_license "$free_license" \
  --arg free_primary_code "$free_primary_code" \
  --arg free_second_device_code "$free_second_device_code" \
  --arg pro_account "$pro_account" \
  --arg pro_license "$pro_license" \
  --arg pro_primary_code "$pro_primary_code" \
  --arg pro_recovery_code "$pro_recovery_code" \
  --arg offer_id "$offer_id" \
  --arg payment_method_id "$payment_method_id" \
  --arg invoice_id "$invoice_id" \
  --arg team_account "$team_account" \
  --arg team_license "$team_license" \
  --arg team_owner_code "$team_owner_code" \
  --arg team_member_code "$team_member_code" \
  --arg team_additional_device_code "$team_additional_device_code" \
  '{schemaVersion: 3, environmentId: $environment_id, baseUrl: $base_url, issuer: $issuer,
    publicKeyPemBase64: $public_key,
    fixtures: {
      free: {
        accountId: $free_account,
        licenseId: $free_license,
        activationCodes: {primary: $free_primary_code, secondDevice: $free_second_device_code}
      },
      pro: {
        accountId: $pro_account,
        licenseId: $pro_license,
        activationCodes: {primary: $pro_primary_code, recovery: $pro_recovery_code},
        billing: {offerId: $offer_id, paymentMethodId: $payment_method_id, invoiceId: $invoice_id}
      },
      team: {
        accountId: $team_account,
        licenseId: $team_license,
        activationCodes: {
          owner: $team_owner_code,
          member: $team_member_code,
          additionalDevice: $team_additional_device_code
        }
      }
    }
  }' \
  >"$descriptor"
chmod 0600 "$descriptor"
cat "$descriptor"
trap - EXIT HUP INT TERM
