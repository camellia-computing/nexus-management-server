#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/update-toolchains.sh [options]

Update one or more coupled toolchain and runtime versions as a validated transaction:
  --node <24.x.y>            Update .node-version and the Node.js builder tag
  --node-digest <sha256:...> Immutable digest for node:<version>-bookworm-slim
  --pnpm <x.y.z>             Update admin-ui/package.json packageManager
  --rust <x.y.z>             Update Rust sources and the Rust builder tag
  --rust-digest <sha256:...> Immutable digest for rust:<version>-bookworm
  --postgres <tag>           Update the shared PostgreSQL tag, for example 18-alpine
  --postgres-digest <sha256:...>
                             Immutable digest for postgres:<tag>
  -h, --help                 Show this help

Each image version and its digest must be supplied together.
EOF
}

fail() {
  echo "toolchain update: $*" >&2
  exit 1
}

node_version=
node_digest=
pnpm_version=
rust_version=
rust_digest=
postgres_tag=
postgres_digest=
while (($# > 0)); do
  case "$1" in
    --node|--node-digest|--pnpm|--rust|--rust-digest|--postgres|--postgres-digest)
      (($# >= 2)) || fail "$1 requires a value"
      case "$1" in
        --node) node_version="$2" ;;
        --node-digest) node_digest="$2" ;;
        --pnpm) pnpm_version="$2" ;;
        --rust) rust_version="$2" ;;
        --rust-digest) rust_digest="$2" ;;
        --postgres) postgres_tag="$2" ;;
        --postgres-digest) postgres_digest="$2" ;;
      esac
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) fail "unknown option: $1" ;;
  esac
done

[[ -n "$node_version$pnpm_version$rust_version$postgres_tag" ]] || fail 'at least one version option is required'
[[ -n "$node_version" && -n "$node_digest" || -z "$node_version" && -z "$node_digest" ]] || fail 'Node.js version and digest must be supplied together'
[[ -n "$rust_version" && -n "$rust_digest" || -z "$rust_version" && -z "$rust_digest" ]] || fail 'Rust version and digest must be supplied together'
[[ -n "$postgres_tag" && -n "$postgres_digest" || -z "$postgres_tag" && -z "$postgres_digest" ]] || fail 'PostgreSQL tag and digest must be supplied together'

semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
digest='^sha256:[0-9a-f]{64}$'
if [[ -n "$node_version" ]]; then
  [[ "$node_version" =~ $semver ]] || fail 'Node.js must be exact stable SemVer'
  [[ "${node_version%%.*}" == 24 ]] || fail 'Node.js must remain on the supported 24.x major'
  [[ "$node_digest" =~ $digest ]] || fail 'Node.js digest must be a lowercase SHA-256 digest'
fi
[[ -z "$pnpm_version" || "$pnpm_version" =~ $semver ]] || fail 'pnpm must be exact stable SemVer'
if [[ -n "$rust_version" ]]; then
  [[ "$rust_version" =~ $semver ]] || fail 'Rust must be exact stable SemVer'
  [[ "$rust_digest" =~ $digest ]] || fail 'Rust digest must be a lowercase SHA-256 digest'
fi
if [[ -n "$postgres_tag" ]]; then
  [[ "$postgres_tag" =~ ^(0|[1-9][0-9]*)(\.[0-9]+){0,2}-alpine$ ]] || fail 'PostgreSQL must use a stable Alpine version tag'
  [[ "$postgres_digest" =~ $digest ]] || fail 'PostgreSQL digest must be a lowercase SHA-256 digest'
fi

for command in cp git grep jq mktemp sed; do
  command -v "$command" >/dev/null || fail "required command is unavailable: $command"
done

repository_root="$(git rev-parse --show-toplevel 2>/dev/null)" || fail 'run this command from a Git worktree'
cd "$(dirname "${BASH_SOURCE[0]}")/.."
[[ "$PWD" == "$repository_root" ]] || fail 'script location and Git worktree root do not match'

targets=()
add_target() {
  local candidate="$1" existing
  for existing in "${targets[@]}"; do
    [[ "$existing" != "$candidate" ]] || return 0
  done
  targets+=("$candidate")
}
if [[ -n "$node_version" ]]; then
  add_target .node-version
  add_target Dockerfile
fi
[[ -z "$pnpm_version" ]] || add_target admin-ui/package.json
if [[ -n "$rust_version" ]]; then
  add_target rust-toolchain.toml
  add_target Cargo.toml
  add_target Dockerfile
fi
if [[ -n "$postgres_tag" ]]; then
  add_target docker-compose.yml
  add_target .github/workflows/ci.yml
  add_target scripts/build-e2e-bundle.sh
  add_target scripts/test-container-runtime.sh
fi
for file in "${targets[@]}"; do
  [[ -f "$file" ]] || fail "target file is missing: $file"
  [[ -z "$(git status --porcelain=v1 -- "$file")" ]] || fail "target file has uncommitted changes: $file"
done

backup_dir="$(mktemp -d "${TMPDIR:-/tmp}/camellia-toolchains.XXXXXX")"
completed=false
cleanup() {
  local status=$?
  trap - EXIT
  if [[ "$completed" != true ]]; then
    for file in "${targets[@]}"; do
      cp -p "$backup_dir/original/$file" "$file"
    done
    echo 'toolchain update: validation failed; original files restored' >&2
  fi
  rm -rf "$backup_dir"
  exit "$status"
}
trap cleanup EXIT

for file in "${targets[@]}"; do
  mkdir -p "$backup_dir/original/$(dirname "$file")"
  cp -p "$file" "$backup_dir/original/$file"
done

replace_line() {
  local file="$1" pattern="$2" replacement="$3" rendered
  [[ "$(grep -Ec "$pattern" "$file")" == 1 ]] || fail "expected exactly one matching line in $file"
  rendered="$(mktemp "$backup_dir/rendered.XXXXXX")"
  sed -E "s|$pattern|$replacement|" "$file" > "$rendered"
  cp "$rendered" "$file"
}

if [[ -n "$node_version" ]]; then
  printf '%s\n' "$node_version" > .node-version
  replace_line Dockerfile \
    '^FROM node:[^@[:space:]]+@sha256:[0-9a-f]{64} AS admin-ui-builder$' \
    "FROM node:$node_version-bookworm-slim@$node_digest AS admin-ui-builder"
fi
if [[ -n "$pnpm_version" ]]; then
  rendered="$(mktemp "$backup_dir/package.XXXXXX")"
  jq --arg version "pnpm@$pnpm_version" '.packageManager = $version' admin-ui/package.json > "$rendered"
  cp "$rendered" admin-ui/package.json
fi
if [[ -n "$rust_version" ]]; then
  replace_line rust-toolchain.toml '^channel = "[^"]+"$' "channel = \"$rust_version\""
  replace_line Cargo.toml '^rust-version = "[^"]+"$' "rust-version = \"${rust_version%.*}\""
  replace_line Dockerfile \
    '^FROM rust:[^@[:space:]]+@sha256:[0-9a-f]{64} AS builder$' \
    "FROM rust:$rust_version-bookworm@$rust_digest AS builder"
fi
if [[ -n "$postgres_tag" ]]; then
  replace_line docker-compose.yml \
    '^    image: postgres:[^@[:space:]]+@sha256:[0-9a-f]{64}$' \
    "    image: postgres:$postgres_tag@$postgres_digest"
  replace_line .github/workflows/ci.yml \
    '^        image: postgres:[^@[:space:]]+@sha256:[0-9a-f]{64}$' \
    "        image: postgres:$postgres_tag@$postgres_digest"
  replace_line scripts/build-e2e-bundle.sh \
    "^postgres_image='postgres:[^@[:space:]]+@sha256:[0-9a-f]{64}'$" \
    "postgres_image='postgres:$postgres_tag@$postgres_digest'"
  replace_line scripts/test-container-runtime.sh \
    "^postgres_image='postgres:[^@[:space:]]+@sha256:[0-9a-f]{64}'$" \
    "postgres_image='postgres:$postgres_tag@$postgres_digest'"
fi

bash scripts/check-version-policy.sh
completed=true
echo 'Toolchain and image sources updated. Review the diff and run the complete quality gates before committing.'
