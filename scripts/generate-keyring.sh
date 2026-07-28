#!/usr/bin/env sh
set -eu

kind="${1:-}"
case "$kind" in
  admin|workspace|webhook) ;;
  *)
    echo "Usage: $0 <admin|workspace|webhook> [output] / 用法：$0 <admin|workspace|webhook> [输出路径]" >&2
    exit 2
    ;;
esac

output="${2:-secrets/$kind-keyring.json}"
directory=$(dirname "$output")
key_id="$kind-$(date -u +%Y-%m)"

umask 077

command -v openssl >/dev/null 2>&1 || {
  echo "openssl is required / 需要安装 openssl" >&2
  exit 1
}

mkdir -p "$directory"
if [ -e "$output" ] || [ -L "$output" ]; then
  echo "Refusing to overwrite existing $kind keyring: $output / 拒绝覆盖已有 $kind 密钥环" >&2
  exit 1
fi

temporary=$(mktemp "$directory/.$kind-keyring.XXXXXX")
cleanup() {
  rm -f "$temporary"
}
trap cleanup EXIT HUP INT TERM

key=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')
printf '{\n  "activeKeyId": "%s",\n  "keys": {\n    "%s": "%s"\n  }\n}\n' \
  "$key_id" "$key_id" "$key" >"$temporary"
chmod 600 "$temporary"
if ! ln "$temporary" "$output"; then
  echo "Refusing to overwrite existing $kind keyring: $output / 拒绝覆盖已有 $kind 密钥环" >&2
  exit 1
fi
rm -f "$temporary"
trap - EXIT HUP INT TERM
echo "$kind keyring created at $output / $kind 密钥环已创建：$output"
