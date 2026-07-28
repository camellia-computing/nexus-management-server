#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temporary_directory=$(mktemp -d)
cleanup() {
  rm -rf "$temporary_directory"
}
trap cleanup EXIT HUP INT TERM

admin_keyring="$temporary_directory/secrets/admin-keyring.json"
workspace_keyring="$temporary_directory/secrets/workspace-keyring.json"
webhook_keyring="$temporary_directory/secrets/webhook-keyring.json"
proxy_secret="$temporary_directory/secrets/admin-proxy-secret"
private_key="$temporary_directory/keys/entitlement-private.pem"
public_key="$temporary_directory/public/entitlement-public.pem"

"$repository_root/scripts/generate-keyring.sh" admin "$admin_keyring"
"$repository_root/scripts/generate-keyring.sh" workspace "$workspace_keyring"
"$repository_root/scripts/generate-keyring.sh" webhook "$webhook_keyring"
"$repository_root/scripts/generate-proxy-secret.sh" "$proxy_secret"
"$repository_root/scripts/generate-entitlement-key.sh" "$private_key" "$public_key"

[[ $(stat -c '%a' "$admin_keyring") == 600 ]]
[[ $(stat -c '%a' "$workspace_keyring") == 600 ]]
[[ $(stat -c '%a' "$webhook_keyring") == 600 ]]
[[ $(stat -c '%a' "$proxy_secret") == 600 ]]
[[ $(stat -c '%a' "$private_key") == 600 ]]
[[ $(stat -c '%a' "$public_key") == 644 ]]
node -e 'const fs=require("node:fs"); const value=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); if (!value.activeKeyId || !value.keys[value.activeKeyId]) process.exit(1)' "$admin_keyring"
node -e 'const fs=require("node:fs"); const value=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); if (!value.activeKeyId.startsWith("workspace-") || !value.keys[value.activeKeyId]) process.exit(1)' "$workspace_keyring"
node -e 'const fs=require("node:fs"); const value=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); if (!value.activeKeyId.startsWith("webhook-") || !value.keys[value.activeKeyId]) process.exit(1)' "$webhook_keyring"
grep -Eq '^[[:xdigit:]]{64}$' "$proxy_secret"
openssl pkey -in "$private_key" -check -noout >/dev/null
openssl pkey -in "$private_key" -pubout -out "$temporary_directory/derived-public.pem"
cmp "$public_key" "$temporary_directory/derived-public.pem"

before=$(sha256sum "$admin_keyring" "$workspace_keyring" "$webhook_keyring" "$proxy_secret" "$private_key" "$public_key")
for entry in "admin:$admin_keyring" "workspace:$workspace_keyring" "webhook:$webhook_keyring"; do
  kind=${entry%%:*}
  path=${entry#*:}
  if "$repository_root/scripts/generate-keyring.sh" "$kind" "$path" >/dev/null 2>&1; then
    echo "$kind keyring generator overwrote an existing file" >&2
    exit 1
  fi
done
if "$repository_root/scripts/generate-proxy-secret.sh" "$proxy_secret" >/dev/null 2>&1; then
  echo "Admin proxy secret generator overwrote an existing file" >&2
  exit 1
fi
if "$repository_root/scripts/generate-entitlement-key.sh" "$private_key" "$public_key" >/dev/null 2>&1; then
  echo "entitlement key generator overwrote existing files" >&2
  exit 1
fi
after=$(sha256sum "$admin_keyring" "$workspace_keyring" "$webhook_keyring" "$proxy_secret" "$private_key" "$public_key")
[[ "$before" == "$after" ]]

preexisting_public="$temporary_directory/preexisting-public.pem"
blocked_private="$temporary_directory/blocked-private.pem"
printf 'preexisting\n' >"$preexisting_public"
if "$repository_root/scripts/generate-entitlement-key.sh" "$blocked_private" "$preexisting_public" >/dev/null 2>&1; then
  echo "entitlement key generator accepted a preexisting public key" >&2
  exit 1
fi
[[ ! -e "$blocked_private" ]]

echo "key generator safety checks passed"
