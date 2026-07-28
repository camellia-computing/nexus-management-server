#!/usr/bin/env bash
set -euo pipefail
umask 077

image="${1:-}"
if [[ -z "$image" ]]; then
  echo "Usage: $0 <locally-loaded-image>" >&2
  exit 2
fi

for command in curl docker jq python3; do
  command -v "$command" >/dev/null || {
    echo "$command is required for the container runtime test" >&2
    exit 2
  }
done

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
temporary_directory="$(mktemp -d)"
suffix="${GITHUB_RUN_ID:-local}-$$"
network="camellia-runtime-$suffix"
postgres="camellia-postgres-$suffix"
clamav="camellia-clamav-$suffix"
public="camellia-public-$suffix"
admin="camellia-admin-$suffix"
worker="camellia-worker-$suffix"
admin_live="camellia-admin-live-$suffix"

run_live_admin_ui="${CAMELLIA_NEXUS_RUN_ADMIN_UI_LIVE:-0}"
case "$run_live_admin_ui" in
  0|1) ;;
  *)
    echo "CAMELLIA_NEXUS_RUN_ADMIN_UI_LIVE must be 0 or 1" >&2
    exit 2
    ;;
esac
if [[ "$run_live_admin_ui" == 1 ]]; then
  for command in node pnpm; do
    command -v "$command" >/dev/null || {
      echo "$command is required when CAMELLIA_NEXUS_RUN_ADMIN_UI_LIVE=1" >&2
      exit 2
    }
  done
fi

cleanup() {
  docker rm --force "$worker" "$admin_live" "$admin" "$public" "$clamav" "$postgres" \
    >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  rm -rf "$temporary_directory"
}
trap cleanup EXIT HUP INT TERM

docker image inspect "$image" >/dev/null
docker network create "$network" >/dev/null
docker run --detach --name "$postgres" --network "$network" --network-alias postgres \
  --env POSTGRES_DB=camellia_license \
  --env POSTGRES_USER=camellia \
  --env POSTGRES_PASSWORD=container-smoke-only \
  postgres:18-alpine@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15 \
  >/dev/null

for _ in {1..30}; do
  # The PostgreSQL entrypoint briefly exposes a bootstrap server before it
  # replaces PID 1 with the final database process. Do not accept that
  # transitional ready state: it is immediately followed by a clean shutdown.
  if docker exec "$postgres" sh -ec \
      'test "$(cat /proc/1/comm)" = postgres && pg_isready --username camellia --dbname camellia_license' \
      >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "$postgres" sh -ec \
  'test "$(cat /proc/1/comm)" = postgres && pg_isready --username camellia --dbname camellia_license' \
  >/dev/null

if [[ "$run_live_admin_ui" == 1 ]]; then
  echo "==> Start the pinned production evidence scanner"
  docker run --detach --name "$clamav" --network "$network" --network-alias clamav \
    --platform linux/amd64 \
    clamav/clamav:1.4.3_base@sha256:be37f82c9cccf6c2559a44b8fb537e6f11e8547b37988650b169c4540c2f298c \
    >/dev/null
  for _ in {1..90}; do
    if docker exec "$clamav" clamdscan --ping 1 >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  docker exec "$clamav" clamdscan --ping 1 >/dev/null
fi

"$repository_root/scripts/generate-entitlement-key.sh" \
  "$temporary_directory/entitlement-private.pem" \
  "$temporary_directory/entitlement-public.pem" >/dev/null
"$repository_root/scripts/generate-keyring.sh" admin "$temporary_directory/admin-keyring.json" >/dev/null
"$repository_root/scripts/generate-keyring.sh" workspace "$temporary_directory/workspace-keyring.json" >/dev/null
"$repository_root/scripts/generate-keyring.sh" webhook "$temporary_directory/webhook-keyring.json" >/dev/null
chmod 0444 "$temporary_directory/entitlement-private.pem" "$temporary_directory"/*-keyring.json

common=(
  --network "$network"
  --env CAMELLIA_NEXUS_LICENSE_ENV=production
  --env CAMELLIA_NEXUS_LICENSE_STORAGE=postgres
  --env DATABASE_URL=postgres://camellia:container-smoke-only@postgres:5432/camellia_license
  --env CAMELLIA_NEXUS_LICENSE_ISSUER=https://license.invalid.example
  --env CAMELLIA_NEXUS_LICENSE_AUDIENCE=camellia-nexus-desktop
  --env CAMELLIA_NEXUS_LICENSE_KEY_ID=entitlement-container-smoke
  --env CAMELLIA_NEXUS_LICENSE_PRIVATE_KEY_PEM_PATH=/run/secrets/entitlement-private.pem
  --env CAMELLIA_NEXUS_WORKSPACE_KEYRING_PATH=/run/secrets/workspace-keyring.json
  --env CAMELLIA_NEXUS_WEBHOOK_KEYRING_PATH=/run/secrets/webhook-keyring.json
  --env CAMELLIA_NEXUS_OAUTH_CLIENT_ID=camellia-nexus-desktop
  --env CAMELLIA_NEXUS_OAUTH_REDIRECT_URIS=camellia-nexus://auth/callback
  --env CAMELLIA_NEXUS_CLIENT_MINIMUM_VERSION=1.0.0
  --env CAMELLIA_NEXUS_CLIENT_RECOMMENDED_VERSION=1.0.0
  --env CAMELLIA_NEXUS_CLIENT_VERSION_ENFORCE_AFTER=2030-01-01T00:00:00Z
  --env CAMELLIA_NEXUS_CORS_ALLOWED_ORIGINS=camellia-nexus://localhost
  --env CAMELLIA_NEXUS_DATABASE_MIGRATE=false
  --env CAMELLIA_NEXUS_LOG_LEVEL=warn
  --env CAMELLIA_NEXUS_METRICS_BIND=0.0.0.0:9091
  --env CAMELLIA_NEXUS_METRICS_ALLOW_NON_LOOPBACK=true
  --volume "$temporary_directory/entitlement-private.pem:/run/secrets/entitlement-private.pem:ro"
  --volume "$temporary_directory/workspace-keyring.json:/run/secrets/workspace-keyring.json:ro"
  --volume "$temporary_directory/webhook-keyring.json:/run/secrets/webhook-keyring.json:ro"
)

runtime_security=(
  --read-only
  --tmpfs '/tmp:size=64m,mode=1777'
  --cap-drop ALL
  --security-opt no-new-privileges:true
)

totp_code() {
  python3 -c '
import base64, hashlib, hmac, struct, sys, time
secret, offset = sys.stdin.read().splitlines()
counter = int(time.time()) // 30 + int(offset)
digest = hmac.new(base64.b32decode(secret, casefold=True), struct.pack(">Q", counter), hashlib.sha1).digest()
position = digest[-1] & 0x0f
value = struct.unpack(">I", digest[position:position + 4])[0] & 0x7fffffff
print(f"{value % 1_000_000:06d}")
'
}

totp_now() {
  python3 -c '
import base64, hashlib, hmac, struct, sys, time
secret = sys.stdin.read().strip()
counter = int(time.time()) // 30
digest = hmac.new(base64.b32decode(secret, casefold=True), struct.pack(">Q", counter), hashlib.sha1).digest()
position = digest[-1] & 0x0f
value = struct.unpack(">I", digest[position:position + 4])[0] & 0x7fffffff
print(counter, f"{value % 1_000_000:06d}")
'
}

cookie_pair() {
  local headers="$1"
  local name="$2"
  python3 -c '
import sys
headers, name = sys.argv[1:]
for line in open(headers, encoding="utf-8"):
    if not line.lower().startswith("set-cookie:"):
        continue
    pair = line.split(":", 1)[1].strip().split(";", 1)[0]
    if pair.startswith(name + "="):
        print(pair)
        raise SystemExit(0)
raise SystemExit(1)
' "$headers" "$name"
}

admin_post() {
  local path="$1"
  local body="$2"
  local output="$3"
  shift 3
  if ! printf '%s' "$body" | curl --fail-with-body --silent --show-error \
      --request POST \
      --header "Origin: $admin_origin" \
      --header 'Content-Type: application/json' \
      "$@" \
      --data-binary @- \
      --output "$output" \
      "$admin_base/api/v1$path"; then
    jq -c '{code, message, field}' "$output" >&2 2>/dev/null || true
    return 1
  fi
}

docker run --rm "${common[@]}" "${runtime_security[@]}" "$image" migrate

resource_suffix="${suffix//-/}"
account_id="acct_runtime_${resource_suffix}"
license_id="lic_runtime_${resource_suffix}"
operator_id="container_runtime_smoke"
reason="candidate image runtime verification"

run_admin() {
  docker run --rm "${common[@]}" "${runtime_security[@]}" "$image" admin --raw "$@"
}

echo "==> Verify container account and Team license mutations"
account="$(run_admin account create "$account_id" --actor "$operator_id" --reason "$reason")"
grep -Fq "\"id\": \"$account_id\"" <<<"$account"
license="$(run_admin license create "$license_id" --account "$account_id" --plan team \
  --seats 3 --actor "$operator_id" --reason "$reason")"
grep -Fq "\"id\": \"$license_id\"" <<<"$license"
grep -Fq '"purchased_seats": 3' <<<"$license"

echo "==> Verify activation-code idempotency and single-display behavior"
read -r code_operation </proc/sys/kernel/random/uuid
issued="$(run_admin code issue --account "$account_id" --license "$license_id" \
  --issued-by "$operator_id" --reason "$reason" --operation-id "$code_operation")"
grep -Fq '"code": "CNX1-' <<<"$issued"
if replay_error="$(run_admin code issue --account "$account_id" --license "$license_id" \
  --issued-by "$operator_id" --reason "$reason" --operation-id "$code_operation" 2>&1)"; then
  echo "activation-code plaintext was unexpectedly replayed" >&2
  exit 1
fi
grep -Fq 'plaintext cannot be replayed' <<<"$replay_error"
codes="$(run_admin code list --account "$account_id")"
test "$(grep -Foc "\"order_id\": \"$code_operation:1\"" <<<"$codes")" -eq 1

echo "==> Verify first administrator bootstrap"
owner="$(docker run --rm "${common[@]}" "${runtime_security[@]}" \
  --env CAMELLIA_NEXUS_ADMIN_KEYRING_PATH=/run/secrets/admin-keyring.json \
  --volume "$temporary_directory/admin-keyring.json:/run/secrets/admin-keyring.json:ro" \
  "$image" admin --raw operator bootstrap runtimeowner --display-name 'Runtime Owner' \
  --actor "$operator_id" --reason "$reason")"
grep -Fq '"enrollmentToken":' <<<"$owner"
unset account license issued replay_error codes

echo "==> Verify public and administration runtime roles"
docker run --detach --name "$public" "${common[@]}" "${runtime_security[@]}" \
  --env CAMELLIA_NEXUS_LICENSE_BIND=0.0.0.0:8088 \
  "$image" serve >/dev/null

for _ in {1..30}; do
  if docker exec "$public" camellia-nexus-management-server healthcheck \
    http://127.0.0.1:8088/readyz >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "$public" camellia-nexus-management-server healthcheck \
  http://127.0.0.1:8088/readyz >/dev/null

admin_common=(
  "${common[@]}"
  --env CAMELLIA_NEXUS_ADMIN_BIND=0.0.0.0:8090
  --env CAMELLIA_NEXUS_ADMIN_PUBLIC_ORIGIN=https://admin.invalid.example
  --env CAMELLIA_NEXUS_ADMIN_KEYRING_PATH=/run/secrets/admin-keyring.json
  --env CAMELLIA_NEXUS_OBJECT_STORAGE=database
  --volume "$temporary_directory/admin-keyring.json:/run/secrets/admin-keyring.json:ro"
)
if [[ "$run_live_admin_ui" == 1 ]]; then
  admin_common+=(
    --env CAMELLIA_NEXUS_EVIDENCE_SCANNER=clamav
    --env CAMELLIA_NEXUS_CLAMAV_ADDRESS=clamav:3310
  )
fi

docker run --detach --name "$admin" --publish 127.0.0.1::8090 \
  "${admin_common[@]}" "${runtime_security[@]}" \
  "$image" admin-web >/dev/null
for _ in {1..30}; do
  if docker exec "$admin" camellia-nexus-management-server healthcheck \
    http://127.0.0.1:8090/readyz >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "$admin" camellia-nexus-management-server healthcheck \
  http://127.0.0.1:8090/readyz >/dev/null

echo "==> Verify real administrator enrollment, login, resources, and Team workflow"
admin_address="$(docker port "$admin" 8090/tcp)"
admin_port="${admin_address##*:}"
[[ "$admin_port" =~ ^[0-9]+$ ]]
admin_base="http://127.0.0.1:$admin_port"
admin_origin='https://admin.invalid.example'

curl --fail-with-body --silent --show-error --dump-header "$temporary_directory/manifest.headers" \
  --output "$temporary_directory/manifest.webmanifest" "$admin_base/manifest.webmanifest"
jq -e '.id == "/" and .name == "Camellia Console" and .start_url == "/" and .scope == "/"
  and .display == "standalone" and (.icons | length >= 4)' \
  "$temporary_directory/manifest.webmanifest" >/dev/null
grep -Eiq '^content-type:[[:space:]]*application/manifest\+json' \
  "$temporary_directory/manifest.headers"
grep -Eiq '^cache-control:[[:space:]]*no-store, max-age=0' \
  "$temporary_directory/manifest.headers"
grep -Fiq "worker-src 'self'" "$temporary_directory/manifest.headers"

curl --fail-with-body --silent --show-error --dump-header \
  "$temporary_directory/service-worker.headers" --output "$temporary_directory/service-worker.js" \
  "$admin_base/service-worker.js"
grep -Eiq '^content-type:[[:space:]]*text/javascript' \
  "$temporary_directory/service-worker.headers"
grep -Eiq '^cache-control:[[:space:]]*no-store, max-age=0' \
  "$temporary_directory/service-worker.headers"
grep -Fq '/_app/immutable/' "$temporary_directory/service-worker.js"
grep -Fq '/icons/' "$temporary_directory/service-worker.js"
if grep -Eq '/api/v1|index\.html|fallback\.html|manifest\.webmanifest|appearance-init\.js' \
  "$temporary_directory/service-worker.js"; then
  echo 'service worker precaches a mutable or authenticated resource' >&2
  exit 1
fi

for icon in \
  camellia-console.v1-192.png \
  camellia-console.v1-512.png \
  camellia-console-maskable.v1-512.png \
  camellia-console-apple.v1-180.png; do
  curl --fail-with-body --silent --show-error --dump-header \
    "$temporary_directory/$icon.headers" --output "$temporary_directory/$icon" \
    "$admin_base/icons/$icon"
  grep -Eiq '^content-type:[[:space:]]*image/png' "$temporary_directory/$icon.headers"
  grep -Eiq '^cache-control:[[:space:]]*public, max-age=31536000, immutable' \
    "$temporary_directory/$icon.headers"
done
python3 - "$temporary_directory" <<'PY'
import pathlib
import struct
import sys

directory = pathlib.Path(sys.argv[1])
expected = {
    "camellia-console.v1-192.png": 192,
    "camellia-console.v1-512.png": 512,
    "camellia-console-maskable.v1-512.png": 512,
    "camellia-console-apple.v1-180.png": 180,
}
for name, size in expected.items():
    data = (directory / name).read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", name
    assert struct.unpack(">II", data[16:24]) == (size, size), name
PY

api_status="$(curl --silent --show-error --dump-header "$temporary_directory/admin-missing.headers" \
  --output "$temporary_directory/admin-missing.json" --write-out '%{http_code}' \
  "$admin_base/api/v1/pwa-does-not-exist")"
test "$api_status" = 404
grep -Eiq '^content-type:[[:space:]]*application/json' \
  "$temporary_directory/admin-missing.headers"
jq -e '.code == "admin_not_found"' "$temporary_directory/admin-missing.json" >/dev/null
echo "==> Administration PWA assets and API fallback verified"

admin_password="$(python3 -c 'import secrets; print("A9!" + secrets.token_urlsafe(24))')"
enrollment_token="$(jq -er '.enrollmentToken' <<<"$owner")"

enrollment_body="$(printf '%s' "$enrollment_token" | python3 -c \
  'import json, sys; print(json.dumps({"token": sys.stdin.read()}))')"
admin_post '/auth/enrollment' "$enrollment_body" "$temporary_directory/enrollment.json"
totp_secret="$(jq -er '.totpSecret' "$temporary_directory/enrollment.json")"
enrollment_totp="$(printf '%s\n-1\n' "$totp_secret" | totp_code)"
complete_body="$(printf '%s\n%s\n%s\n' "$enrollment_token" "$admin_password" "$enrollment_totp" | \
  python3 -c '
import json, sys
token, password, totp = sys.stdin.read().splitlines()
print(json.dumps({"token": token, "password": password, "totp": totp}))
')"
admin_post '/auth/enrollment/complete' "$complete_body" \
  "$temporary_directory/enrollment-complete.json" \
  --dump-header "$temporary_directory/enrollment-complete.headers"
jq -e '.user.username == "runtimeowner" and (.recoveryCodes | length > 0)' \
  "$temporary_directory/enrollment-complete.json" >/dev/null
echo "==> Administrator enrollment completed"

login_totp="$(printf '%s\n0\n' "$totp_secret" | totp_code)"
login_body="$(printf '%s\n%s\n' "$admin_password" "$login_totp" | python3 -c '
import json, sys
password, totp = sys.stdin.read().splitlines()
print(json.dumps({"username": "runtimeowner", "password": password, "totp": totp}))
')"
admin_post '/auth/login' "$login_body" "$temporary_directory/login.json" \
  --dump-header "$temporary_directory/login.headers"
jq -e '.user.username == "runtimeowner"' "$temporary_directory/login.json" >/dev/null
session_cookie="$(cookie_pair "$temporary_directory/login.headers" '__Host-camellia_admin')"
csrf_cookie="$(cookie_pair "$temporary_directory/login.headers" '__Host-camellia_admin_csrf')"
csrf_token="${csrf_cookie#*=}"
auth_config="$temporary_directory/curl-auth.conf"
printf 'header = "Cookie: %s; %s"\nheader = "X-CSRF-Token: %s"\n' \
  "$session_cookie" "$csrf_cookie" "$csrf_token" >"$auth_config"
echo "==> Administrator login completed"

curl --fail-with-body --silent --show-error --config "$auth_config" \
  --output "$temporary_directory/me.json" "$admin_base/api/v1/auth/me"
jq -e '.user.username == "runtimeowner" and (.permissions | index("team.write"))' \
  "$temporary_directory/me.json" >/dev/null

step_up_totp="$(printf '%s\n1\n' "$totp_secret" | totp_code)"
step_up_body="$(printf '%s\n%s\n' "$admin_password" "$step_up_totp" | python3 -c '
import json, sys
password, totp = sys.stdin.read().splitlines()
print(json.dumps({"password": password, "totp": totp}))
')"
admin_post '/auth/step-up' "$step_up_body" "$temporary_directory/step-up.json" \
  --config "$auth_config"
jq -e '.elevatedUntil > 0' "$temporary_directory/step-up.json" >/dev/null
echo "==> Administrator step-up completed"

echo "==> Provision an independent administrator for the live browser"
live_admin_username=runtimebrowser
live_admin_display_name='Runtime Browser'
live_admin_password="$(python3 -c 'import secrets; print("B8!" + secrets.token_urlsafe(24))')"
read -r live_admin_operation </proc/sys/kernel/random/uuid
live_admin_body="$(jq -nc \
  --arg username "$live_admin_username" \
  --arg display_name "$live_admin_display_name" \
  --arg reason "$reason" \
  '{username: $username, displayName: $display_name, roles: ["platform_owner"], reason: $reason}')"
admin_post '/admin-users' "$live_admin_body" "$temporary_directory/live-admin.json" \
  --config "$auth_config" --header "Idempotency-Key: $live_admin_operation"
live_delivery_id="$(jq -er '.delivery.id' "$temporary_directory/live-admin.json")"
live_claim_token="$(jq -er '.delivery.claimToken' "$temporary_directory/live-admin.json")"
live_claim_body="$(printf '%s' "$live_claim_token" | python3 -c \
  'import json, sys; print(json.dumps({"claimToken": sys.stdin.read()}))')"
admin_post "/secret-deliveries/$live_delivery_id/claim" "$live_claim_body" \
  "$temporary_directory/live-enrollment-token.json" --config "$auth_config"
live_enrollment_token="$(jq -er '.enrollmentToken' \
  "$temporary_directory/live-enrollment-token.json")"
live_enrollment_body="$(printf '%s' "$live_enrollment_token" | python3 -c \
  'import json, sys; print(json.dumps({"token": sys.stdin.read()}))')"
admin_post '/auth/enrollment' "$live_enrollment_body" \
  "$temporary_directory/live-enrollment.json"
live_totp_secret="$(jq -er '.totpSecret' "$temporary_directory/live-enrollment.json")"
live_enrollment_totp="$(printf '%s\n-1\n' "$live_totp_secret" | totp_code)"
live_complete_body="$(printf '%s\n%s\n%s\n' \
  "$live_enrollment_token" "$live_admin_password" "$live_enrollment_totp" | python3 -c '
import json, sys
token, password, totp = sys.stdin.read().splitlines()
print(json.dumps({"token": token, "password": password, "totp": totp}))
')"
admin_post '/auth/enrollment/complete' "$live_complete_body" \
  "$temporary_directory/live-enrollment-complete.json"
jq -e --arg username "$live_admin_username" '.user.username == $username' \
  "$temporary_directory/live-enrollment-complete.json" >/dev/null
admin_post "/secret-deliveries/$live_delivery_id/acknowledge" "$live_claim_body" \
  "$temporary_directory/live-enrollment-acknowledged" --config "$auth_config"

http_account_id="http_${account_id}"
http_license_id="http_${license_id}"
read -r account_operation </proc/sys/kernel/random/uuid
account_body="$(jq -nc --arg id "$http_account_id" --arg reason "$reason" \
  '{id: $id, note: "Admin HTTP runtime verification", reason: $reason}')"
admin_post '/accounts' "$account_body" "$temporary_directory/account.json" \
  --config "$auth_config" --header "Idempotency-Key: $account_operation"
jq -e --arg id "$http_account_id" '.id == $id' "$temporary_directory/account.json" >/dev/null

read -r license_operation </proc/sys/kernel/random/uuid
license_body="$(jq -nc --arg id "$http_license_id" --arg account "$http_account_id" \
  --arg reason "$reason" \
  '{id: $id, accountId: $account, plan: "team", status: "active", expiresAt: null,
    purchasedSeats: 3, reason: $reason}')"
admin_post '/licenses' "$license_body" "$temporary_directory/license.json" \
  --config "$auth_config" --header "Idempotency-Key: $license_operation"
jq -e --arg id "$http_license_id" \
  '.id == $id and .plan == "team" and .purchasedSeats == 3' \
  "$temporary_directory/license.json" >/dev/null
echo "==> HTTP account and Team license created"

billing_offer_id="offer_${resource_suffix}"
billing_method_id="method_${resource_suffix}"
billing_invoice_id="invoice_${resource_suffix}"
billing_claim_id="claim_${resource_suffix}"
run_admin billing offer create "$billing_offer_id" --plan team --duration-days 365 \
  --currency USD --amount 99.00 --seat-amount 20.00 --name-en 'Runtime Team annual' \
  --name-zh 'Runtime Team annual' --actor "$operator_id" --reason "$reason" >/dev/null
run_admin billing method create "$billing_method_id" --name-en 'Runtime bank transfer' \
  --name-zh 'Runtime bank transfer' --instructions-en 'Synthetic runtime settlement only.' \
  --instructions-zh 'Synthetic runtime settlement only.' --asset USD \
  --destination-hint 'RUNTIME-ONLY' --actor "$operator_id" --reason "$reason" >/dev/null
run_admin billing invoice create "$billing_invoice_id" --account "$http_account_id" \
  --license "$http_license_id" --offer "$billing_offer_id" --seats 3 --due-at 30d \
  --actor "$operator_id" --reason "$reason" >/dev/null
run_admin billing payment submit "$billing_claim_id" --invoice "$billing_invoice_id" \
  --method "$billing_method_id" --transaction "runtime-$resource_suffix" --amount 159.00 \
  --asset USD --paid-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --submitted-by runtime_customer \
  --payer 'Runtime Customer' --note 'Synthetic clean-evidence scenario' >/dev/null
printf '%%PDF-1.7\n1 0 obj<</Type/Catalog>>endobj\n%%%%EOF\n' \
  >"$temporary_directory/runtime-clean-receipt.pdf"
chmod 0600 "$temporary_directory/runtime-clean-receipt.pdf"
echo "==> Billing fixtures created for live evidence scanning"

read -r issue_operation </proc/sys/kernel/random/uuid
code_expiry="$(( $(date +%s) + 30 * 24 * 60 * 60 ))"
code_body="$(jq -nc --arg account "$http_account_id" --arg license "$http_license_id" \
  --arg expiry "$code_expiry" --arg reason "$reason" \
  '{accountId: $account, licenseId: $license, count: 1, maxRedemptions: 1,
    expiresAt: $expiry, channel: "container_runtime", note: null, reason: $reason}')"
admin_post '/activation-codes' "$code_body" "$temporary_directory/code-delivery.json" \
  --config "$auth_config" --header "Idempotency-Key: $issue_operation"
admin_post '/activation-codes' "$code_body" "$temporary_directory/code-delivery-replay.json" \
  --config "$auth_config" --header "Idempotency-Key: $issue_operation"
delivery_id="$(jq -er '.delivery.id' "$temporary_directory/code-delivery.json")"
test "$(jq -er '.delivery.id' "$temporary_directory/code-delivery-replay.json")" = "$delivery_id"
claim_token="$(jq -er '.delivery.claimToken' "$temporary_directory/code-delivery.json")"
claim_body="$(printf '%s' "$claim_token" | python3 -c \
  'import json, sys; print(json.dumps({"claimToken": sys.stdin.read()}))')"
admin_post "/secret-deliveries/$delivery_id/claim" "$claim_body" \
  "$temporary_directory/codes.json" --config "$auth_config"
jq -e 'length == 1 and (.[0].code | startswith("CNX1-"))' \
  "$temporary_directory/codes.json" >/dev/null
admin_post "/secret-deliveries/$delivery_id/acknowledge" "$claim_body" \
  "$temporary_directory/code-acknowledged" --config "$auth_config"
echo "==> HTTP activation-code delivery and replay verified"

read -r invitation_operation </proc/sys/kernel/random/uuid
invitation_body="$(jq -nc --arg reason "$reason" \
  '{email: "runtime.member@example.invalid", displayName: "Runtime Member",
    role: "viewer", reason: $reason}')"
admin_post "/team-workspaces/$http_account_id/invitations" "$invitation_body" \
  "$temporary_directory/invitation.json" --config "$auth_config" \
  --header "Idempotency-Key: $invitation_operation"
invitation_delivery_id="$(jq -er '.delivery.id' "$temporary_directory/invitation.json")"
invitation_claim_token="$(jq -er '.delivery.claimToken' "$temporary_directory/invitation.json")"
invitation_claim_body="$(printf '%s' "$invitation_claim_token" | python3 -c \
  'import json, sys; print(json.dumps({"claimToken": sys.stdin.read()}))')"
admin_post "/secret-deliveries/$invitation_delivery_id/claim" "$invitation_claim_body" \
  "$temporary_directory/invitation-secret.json" --config "$auth_config"
jq -e '.invitationToken | length > 20' "$temporary_directory/invitation-secret.json" >/dev/null
admin_post "/secret-deliveries/$invitation_delivery_id/acknowledge" \
  "$invitation_claim_body" "$temporary_directory/invitation-acknowledged" \
  --config "$auth_config"
echo "==> Team invitation delivery verified"

curl --fail-with-body --silent --show-error --config "$auth_config" \
  --output "$temporary_directory/workspaces.json" "$admin_base/api/v1/team-workspaces"
jq -e --arg account "$http_account_id" \
  '.items | any(.accountId == $account and .purchasedSeats == 3 and .occupiedMembers == 2)' \
  "$temporary_directory/workspaces.json" >/dev/null
curl --fail-with-body --silent --show-error --config "$auth_config" \
  --output "$temporary_directory/system-status.json" "$admin_base/api/v1/system/status"
jq -e '.status == "ready" and .database == "ready" and .timeAuthority == "ready"
  and .objectStorage.backend == "database"' \
  "$temporary_directory/system-status.json" >/dev/null
echo "==> Team workspace and system status verified"

admin_post '/auth/logout' '' "$temporary_directory/logout" --config "$auth_config"
status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
  --config "$auth_config" "$admin_base/api/v1/auth/me")"
test "$status" = 401
echo "==> Administrator logout invalidated the session"

if [[ "$run_live_admin_ui" == 1 ]]; then
  echo "==> Verify the real administration UI against the final container"
  live_admin_port="$(python3 -c '
import socket
with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    print(listener.getsockname()[1])
')"
  live_admin_origin="http://127.0.0.1:$live_admin_port"
  docker run --detach --name "$admin_live" --publish "127.0.0.1:$live_admin_port:8090" \
    "${admin_common[@]}" "${runtime_security[@]}" \
    --env CAMELLIA_NEXUS_LICENSE_ENV=development \
    --env "CAMELLIA_NEXUS_ADMIN_PUBLIC_ORIGIN=$live_admin_origin" \
    "$image" admin-web >/dev/null
  for _ in {1..30}; do
    if curl --fail --silent --show-error "$live_admin_origin/readyz" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  curl --fail --silent --show-error "$live_admin_origin/readyz" >/dev/null
  admin_base="$live_admin_origin"
  admin_origin="$live_admin_origin"
  read -r live_login_counter live_login_totp < <(printf '%s' "$live_totp_secret" | totp_now)
  live_login_body="$(printf '%s\n%s\n' "$live_admin_password" "$live_login_totp" | python3 -c '
import json, sys
password, totp = sys.stdin.read().splitlines()
print(json.dumps({"username": "runtimebrowser", "password": password, "totp": totp}))
')"
  admin_post '/auth/login' "$live_login_body" "$temporary_directory/live-login.json" \
    --dump-header "$temporary_directory/live-login.headers"
  jq -e '.user.username == "runtimebrowser"' "$temporary_directory/live-login.json" >/dev/null
  live_session_cookie="$(cookie_pair "$temporary_directory/live-login.headers" \
    'camellia_admin_development')"
  live_csrf_cookie="$(cookie_pair "$temporary_directory/live-login.headers" \
    'camellia_admin_csrf_development')"
  expired_sessions="$(docker exec "$postgres" psql --username camellia \
    --dbname camellia_license --tuples-only --no-align --set ON_ERROR_STOP=1 \
    --command "WITH expired AS (UPDATE admin_sessions SET elevated_until = 0 WHERE user_id = (SELECT id FROM admin_users WHERE username = 'runtimebrowser') RETURNING 1) SELECT count(*) FROM expired;")"
  [[ "$expired_sessions" =~ ^[1-9][0-9]*$ ]]
  CAMELLIA_NEXUS_ADMIN_E2E_BASE_URL="$live_admin_origin" \
  CAMELLIA_NEXUS_ADMIN_E2E_USERNAME="$live_admin_username" \
  CAMELLIA_NEXUS_ADMIN_E2E_PASSWORD="$live_admin_password" \
  CAMELLIA_NEXUS_ADMIN_E2E_TOTP_SECRET="$live_totp_secret" \
  CAMELLIA_NEXUS_ADMIN_E2E_LAST_TOTP_COUNTER="$live_login_counter" \
  CAMELLIA_NEXUS_ADMIN_E2E_SESSION_COOKIE_NAME='camellia_admin_development' \
  CAMELLIA_NEXUS_ADMIN_E2E_SESSION_COOKIE_VALUE="${live_session_cookie#*=}" \
  CAMELLIA_NEXUS_ADMIN_E2E_CSRF_COOKIE_NAME='camellia_admin_csrf_development' \
  CAMELLIA_NEXUS_ADMIN_E2E_CSRF_COOKIE_VALUE="${live_csrf_cookie#*=}" \
  CAMELLIA_NEXUS_ADMIN_E2E_DISPLAY_NAME="$live_admin_display_name" \
  CAMELLIA_NEXUS_ADMIN_E2E_ACCOUNT_ID="$http_account_id" \
  CAMELLIA_NEXUS_ADMIN_E2E_LICENSE_ID="$http_license_id" \
  CAMELLIA_NEXUS_ADMIN_E2E_BILLING_OFFER_ID="$billing_offer_id" \
  CAMELLIA_NEXUS_ADMIN_E2E_PAYMENT_CLAIM_ID="$billing_claim_id" \
  CAMELLIA_NEXUS_ADMIN_E2E_EVIDENCE_PATH="$temporary_directory/runtime-clean-receipt.pdf" \
  CAMELLIA_NEXUS_ADMIN_E2E_OUTPUT_DIR="$temporary_directory/admin-ui-live" \
    pnpm --dir "$repository_root/admin-ui" test:live
fi

unset owner enrollment_token totp_secret enrollment_totp login_totp step_up_totp admin_password
unset session_cookie csrf_cookie csrf_token claim_token invitation_claim_token
unset live_admin_password live_totp_secret live_enrollment_token live_enrollment_totp
unset live_claim_token
unset live_login_counter live_login_totp live_login_body live_session_cookie live_csrf_cookie
unset expired_sessions

docker run --detach --name "$worker" "${admin_common[@]}" "${runtime_security[@]}" \
  "$image" admin-worker >/dev/null
sleep 2
test "$(docker inspect --format '{{.State.Running}}' "$worker")" = true

for container in "$public" "$admin" "$worker"; do
  test "$(docker inspect --format '{{.Config.User}}' "$container")" = 10001:10001
  test "$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container")" = true
  test "$(docker inspect --format '{{json .HostConfig.CapDrop}}' "$container")" = '["ALL"]'
  test "$(docker inspect --format '{{json .HostConfig.SecurityOpt}}' "$container")" = '["no-new-privileges:true"]'
done

echo "Container business flow, runtime roles, migrations, readiness, and hardening verified"
