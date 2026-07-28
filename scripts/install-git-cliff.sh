#!/usr/bin/env bash
set -euo pipefail

readonly VERSION=2.13.1
readonly SHA512=e716cce3a07dda41b1e370d6afbd7a59eb3d4739509fb7856aeec8da2be28c0396584e29e106141c1a1c535c1827dbc1f60417524f5cfb1da9e11f700bd00f30
readonly ARCHIVE_NAME="git-cliff-${VERSION}-x86_64-unknown-linux-gnu.tar.gz"

: "${RUNNER_TEMP:?RUNNER_TEMP must be set}"
: "${GITHUB_PATH:?GITHUB_PATH must be set}"

archive="$RUNNER_TEMP/$ARCHIVE_NAME"
extract_dir="$(mktemp -d "$RUNNER_TEMP/git-cliff.XXXXXX")"
trap 'rm -rf "$extract_dir"' EXIT

curl --fail --silent --show-error --location \
  "https://github.com/orhun/git-cliff/releases/download/v${VERSION}/${ARCHIVE_NAME}" \
  --output "$archive"
printf '%s  %s\n' "$SHA512" "$archive" | sha512sum --check --strict
tar -xzf "$archive" -C "$extract_dir"

binary="$(find "$extract_dir" -type f -name git-cliff -print -quit)"
[[ -n "$binary" ]] || {
  echo 'git-cliff binary was not present in the verified archive' >&2
  exit 1
}

mkdir -p "$RUNNER_TEMP/bin"
install -m 0755 "$binary" "$RUNNER_TEMP/bin/git-cliff"
printf '%s\n' "$RUNNER_TEMP/bin" >> "$GITHUB_PATH"
