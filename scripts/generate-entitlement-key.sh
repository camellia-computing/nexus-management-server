#!/usr/bin/env bash
set -euo pipefail

private_path="${1:-entitlement-es256-private.pem}"
public_path="${2:-entitlement-es256-public.pem}"

umask 077

for path in "$private_path" "$public_path"; do
  if [[ -e "$path" || -L "$path" ]]; then
    echo "Refusing to overwrite existing key: $path" >&2
    exit 1
  fi
done

private_directory=$(dirname "$private_path")
public_directory=$(dirname "$public_path")
mkdir -p "$private_directory" "$public_directory"
private_temporary=$(mktemp "$private_directory/.entitlement-private.XXXXXX")
public_temporary=$(mktemp "$public_directory/.entitlement-public.XXXXXX")
private_published=false
public_published=false
completed=false
cleanup() {
  rm -f "$private_temporary" "$public_temporary"
  if [[ "$completed" != true && "$public_published" == true ]]; then
    rm -f "$public_path"
  fi
  if [[ "$completed" != true && "$private_published" == true ]]; then
    rm -f "$private_path"
  fi
}
trap cleanup EXIT HUP INT TERM

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$private_temporary"
openssl pkey -in "$private_temporary" -pubout -out "$public_temporary"
chmod 600 "$private_temporary"
chmod 644 "$public_temporary"

if ! ln "$private_temporary" "$private_path"; then
  echo "Refusing to overwrite existing key: $private_path" >&2
  exit 1
fi
private_published=true
if ! ln "$public_temporary" "$public_path"; then
  echo "Refusing to overwrite existing key: $public_path" >&2
  exit 1
fi
public_published=true
completed=true
rm -f "$private_temporary" "$public_temporary"
trap - EXIT HUP INT TERM

echo "Private key: $private_path"
echo "Public key:  $public_path"
