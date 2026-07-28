#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Start a local Camellia Nexus management server for desktop client testing.

Usage:
  scripts/start-local.sh [options]

Options:
  --bind ADDRESS:PORT       Bind address. Default: 127.0.0.1:8088
  --storage memory|postgres Storage backend. Default: memory
  --client-root PATH        Camellia Nexus client repository. Default: ../nexus when present
  --no-client               Do not read client defaults or print client launch hints
  --issuer URL              Entitlement issuer. Default: client trust metadata issuer
  --audience VALUE          Entitlement audience. Default: client trust metadata audience
  --key-id VALUE            Entitlement key id. Default: first client key id
  --json-logs               Emit JSON logs from the server
  --log-level LEVEL         Application log level. Default: debug
  --http-log-level LEVEL    HTTP access-log level. Default: info
  --no-compose              Do not start docker compose postgres for --storage postgres
  --release                 Run cargo in release profile
  --prepare-only            Generate local key/config files and exit without starting the server
  -h, --help                Show this help

Client local run:
  source .local/client-env.sh
  cd ../nexus
  pnpm --dir ui desktop:dev
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

info() {
    printf '==> %s\n' "$*"
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
server_root="$(CDPATH='' cd -- "$script_dir/.." && pwd)"

default_client_root=""
if [[ -d "$server_root/../nexus/src-tauri" ]]; then
    default_client_root="$(CDPATH='' cd -- "$server_root/../nexus" && pwd)"
fi

bind="${CAMELLIA_NEXUS_LICENSE_BIND:-127.0.0.1:8088}"
storage="${CAMELLIA_NEXUS_LICENSE_STORAGE:-memory}"
local_dir="${CAMELLIA_NEXUS_LICENSE_LOCAL_DIR:-$server_root/.local}"
client_root="${CAMELLIA_NEXUS_CLIENT_ROOT:-$default_client_root}"
issuer_override="${CAMELLIA_NEXUS_LICENSE_ISSUER:-}"
audience_override="${CAMELLIA_NEXUS_LICENSE_AUDIENCE:-}"
key_id_override="${CAMELLIA_NEXUS_LICENSE_KEY_ID:-}"
log_format="${CAMELLIA_NEXUS_LOG_FORMAT:-compact}"
log_level="${CAMELLIA_NEXUS_LOG_LEVEL:-debug}"
http_log_level="${CAMELLIA_NEXUS_HTTP_LOG_LEVEL:-info}"
http_failure_log_level="${CAMELLIA_NEXUS_HTTP_FAILURE_LOG_LEVEL:-warn}"
start_compose=1
release_profile=0
prepare_only=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bind)
            [[ $# -ge 2 ]] || die "--bind requires a value"
            bind="$2"
            shift 2
            ;;
        --storage)
            [[ $# -ge 2 ]] || die "--storage requires a value"
            storage="$2"
            shift 2
            ;;
        --client-root)
            [[ $# -ge 2 ]] || die "--client-root requires a value"
            client_root="$2"
            shift 2
            ;;
        --no-client)
            client_root=""
            shift
            ;;
        --issuer)
            [[ $# -ge 2 ]] || die "--issuer requires a value"
            issuer_override="$2"
            shift 2
            ;;
        --audience)
            [[ $# -ge 2 ]] || die "--audience requires a value"
            audience_override="$2"
            shift 2
            ;;
        --key-id)
            [[ $# -ge 2 ]] || die "--key-id requires a value"
            key_id_override="$2"
            shift 2
            ;;
        --json-logs)
            log_format="json"
            shift
            ;;
        --log-level)
            [[ $# -ge 2 ]] || die "--log-level requires a value"
            log_level="$2"
            shift 2
            ;;
        --http-log-level)
            [[ $# -ge 2 ]] || die "--http-log-level requires a value"
            http_log_level="$2"
            shift 2
            ;;
        --no-compose)
            start_compose=0
            shift
            ;;
        --release)
            release_profile=1
            shift
            ;;
        --prepare-only)
            prepare_only=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1"
            ;;
    esac
done

case "$storage" in
    memory|postgres) ;;
    *) die "--storage must be memory or postgres" ;;
esac

need_cmd openssl
need_cmd python3

client_authority=""
if [[ -n "$client_root" ]]; then
    client_root="$(CDPATH='' cd -- "$client_root" 2>/dev/null && pwd)" || die "client root does not exist: $client_root"
    client_authority="$client_root/src-tauri/entitlement-keys.json"
fi

client_json_value() {
    local field="$1"
    [[ -f "$client_authority" ]] || return 1
    python3 - "$client_authority" "$field" <<'PY'
import json
import sys

path, field = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as handle:
    data = json.load(handle)

if field == "keyId":
    keys = data.get("keys") or []
    if not keys:
        raise SystemExit(1)
    print(keys[0].get("keyId", ""))
else:
    print(data.get(field, ""))
PY
}

issuer="${issuer_override:-}"
audience="${audience_override:-}"
key_id="${key_id_override:-}"

if [[ -z "$issuer" ]]; then
    issuer="$(client_json_value issuer 2>/dev/null || true)"
fi
if [[ -z "$audience" ]]; then
    audience="$(client_json_value audience 2>/dev/null || true)"
fi
if [[ -z "$key_id" ]]; then
    key_id="$(client_json_value keyId 2>/dev/null || true)"
fi

issuer="${issuer:-http://127.0.0.1:8088}"
audience="${audience:-camellia-nexus-desktop}"
key_id="${key_id:-entitlement-local-dev}"

mkdir -p "$local_dir"
private_key="$local_dir/entitlement-es256-private.pem"
public_key="$local_dir/entitlement-es256-public.pem"
authority_file="$local_dir/entitlement-keys.local.json"
client_env_sh="$local_dir/client-env.sh"
client_env_ps1="$local_dir/client-env.ps1"

if [[ ! -f "$private_key" ]]; then
    info "generating local ES256 entitlement key"
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$private_key" >/dev/null 2>&1
fi

openssl pkey -in "$private_key" -pubout -out "$public_key" >/dev/null 2>&1

python3 - "$authority_file" "$issuer" "$audience" "$key_id" "$public_key" <<'PY'
import json
import sys

output, issuer, audience, key_id, public_key_path = sys.argv[1:6]
with open(public_key_path, "r", encoding="utf-8") as handle:
    public_key = handle.read().strip()

authority = {
    "issuer": issuer,
    "audience": audience,
    "minimumLicenseEpoch": 0,
    "keys": [
        {
            "keyId": key_id,
            "publicKeyPem": public_key,
        }
    ],
}

with open(output, "w", encoding="utf-8") as handle:
    json.dump(authority, handle, indent=2)
    handle.write("\n")
PY

host="${bind%:*}"
port="${bind##*:}"
if [[ "$host" == "0.0.0.0" || "$host" == "::" || "$host" == "[::]" ]]; then
    host="127.0.0.1"
fi
base_url="http://$host:$port"

{
    printf '# Source this before starting the Camellia Nexus desktop client locally.\n'
    printf 'export CAMELLIA_NEXUS_LICENSE_URL=%q\n' "$base_url"
    printf 'export CAMELLIA_NEXUS_ENTITLEMENT_KEYS_PATH=%q\n' "$authority_file"
} > "$client_env_sh"

python3 - "$client_env_ps1" "$base_url" "$authority_file" <<'PY'
import sys

output, base_url, authority_file = sys.argv[1:4]
def ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"

with open(output, "w", encoding="utf-8") as handle:
    handle.write("# Run this before starting the Camellia Nexus desktop client locally.\n")
    handle.write(f"$env:CAMELLIA_NEXUS_LICENSE_URL = {ps_quote(base_url)}\n")
    handle.write(f"$env:CAMELLIA_NEXUS_ENTITLEMENT_KEYS_PATH = {ps_quote(authority_file)}\n")
PY

if [[ "$storage" == "postgres" ]]; then
    export DATABASE_URL="${DATABASE_URL:-postgres://camellia:camellia-dev-password@127.0.0.1:5432/camellia_license}"
    if [[ "$start_compose" -eq 1 ]]; then
        need_cmd docker
        info "starting local PostgreSQL"
        (cd "$server_root" && docker compose up -d postgres)
    fi
fi

export CAMELLIA_NEXUS_LICENSE_BIND="$bind"
export CAMELLIA_NEXUS_LICENSE_ISSUER="$issuer"
export CAMELLIA_NEXUS_LICENSE_AUDIENCE="$audience"
export CAMELLIA_NEXUS_LICENSE_KEY_ID="$key_id"
export CAMELLIA_NEXUS_LICENSE_ENV="development"
export CAMELLIA_NEXUS_LICENSE_STORAGE="$storage"
export CAMELLIA_NEXUS_LICENSE_PRIVATE_KEY_PEM_PATH="$private_key"
export CAMELLIA_NEXUS_CORS_ALLOWED_ORIGINS="${CAMELLIA_NEXUS_CORS_ALLOWED_ORIGINS:-camellia-nexus://localhost,http://127.0.0.1:1420,http://localhost:1420}"
export CAMELLIA_NEXUS_LOG_FORMAT="$log_format"
export CAMELLIA_NEXUS_LOG_LEVEL="$log_level"
export CAMELLIA_NEXUS_HTTP_LOG_LEVEL="$http_log_level"
export CAMELLIA_NEXUS_HTTP_FAILURE_LOG_LEVEL="$http_failure_log_level"

info "local management server prepared"
printf '    url:       %s\n' "$base_url"
printf '    storage:   %s\n' "$storage"
printf '    issuer:    %s\n' "$issuer"
printf '    audience:  %s\n' "$audience"
printf '    key id:    %s\n' "$key_id"
printf '    client sh: %s\n' "$client_env_sh"
printf '    client ps: %s\n' "$client_env_ps1"

if [[ -n "$client_root" ]]; then
    printf '\nClient test command:\n'
    printf '    source %q\n' "$client_env_sh"
    printf '    cd %q\n' "$client_root"
    printf '    pnpm --dir ui desktop:dev\n'
fi

if [[ "$prepare_only" -eq 1 ]]; then
    exit 0
fi

cd "$server_root"
if [[ "$release_profile" -eq 1 ]]; then
    exec cargo run --release
fi
exec cargo run
