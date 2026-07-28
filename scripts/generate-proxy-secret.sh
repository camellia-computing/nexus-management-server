#!/usr/bin/env sh
set -eu

output="${1:-secrets/admin-proxy-secret}"
directory=$(dirname "$output")

umask 077

command -v openssl >/dev/null 2>&1 || {
  echo "openssl is required / 需要安装 openssl" >&2
  exit 1
}

mkdir -p "$directory"
if [ -e "$output" ] || [ -L "$output" ]; then
  echo "Refusing to overwrite existing Admin proxy secret: $output / 拒绝覆盖已有管理代理密钥" >&2
  exit 1
fi

temporary=$(mktemp "$directory/.admin-proxy-secret.XXXXXX")
cleanup() {
  rm -f "$temporary"
}
trap cleanup EXIT HUP INT TERM

openssl rand -hex 32 >"$temporary"
chmod 600 "$temporary"
if ! ln "$temporary" "$output"; then
  echo "Refusing to overwrite existing Admin proxy secret: $output / 拒绝覆盖已有管理代理密钥" >&2
  exit 1
fi
rm -f "$temporary"
trap - EXIT HUP INT TERM
echo "Admin proxy secret created at $output / 管理代理密钥已创建：$output"
