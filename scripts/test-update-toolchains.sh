#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "toolchain updater test: $*" >&2
  exit 1
}

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/camellia-toolchains-test.XXXXXX")"
trap 'rm -rf "$fixture"' EXIT

mkdir -p "$fixture/admin-ui" "$fixture/scripts" "$fixture/docs" "$fixture/.github" \
  "$fixture/deploy/postgres" "$fixture/deploy/systemd" "$fixture/src"
cp "$repository_root/.dockerignore" "$repository_root/.node-version" \
  "$repository_root/Cargo.toml" "$repository_root/rust-toolchain.toml" \
  "$repository_root/Dockerfile" "$repository_root/docker-compose.yml" "$fixture/"
cp "$repository_root/admin-ui/package.json" "$repository_root/admin-ui/pnpm-workspace.yaml" \
  "$fixture/admin-ui/"
cp "$repository_root/scripts/check-version-policy.sh" "$repository_root/scripts/update-toolchains.sh" "$fixture/scripts/"
cp "$repository_root/scripts/build-e2e-bundle.sh" "$repository_root/scripts/provision-e2e-compose.sh" \
  "$repository_root/scripts/test-container-runtime.sh" "$fixture/scripts/"
cp "$repository_root/docs/dependency-management.md" "$fixture/docs/"
cp "$repository_root/deploy/"*.env.example "$fixture/deploy/"
cp "$repository_root/deploy/postgres/init-runtime-roles.sh" "$fixture/deploy/postgres/"
cp "$repository_root/deploy/systemd/"*.service "$fixture/deploy/systemd/"
cp "$repository_root/src/admin_jobs.rs" "$repository_root/src/main.rs" "$fixture/src/"
cp -R "$repository_root/.github/workflows" "$fixture/.github/"
cp "$repository_root/.github/dependabot.yml" "$fixture/.github/"
chmod +x "$fixture/scripts/update-toolchains.sh"

git -C "$fixture" init -q
git -C "$fixture" add .
git -C "$fixture" -c user.name=test -c user.email=test@example.invalid -c commit.gpgsign=false commit -q --no-gpg-sign -m fixture

node_digest="sha256:$(printf 'a%.0s' {1..64})"
rust_digest="sha256:$(printf 'b%.0s' {1..64})"
postgres_digest="sha256:$(printf 'c%.0s' {1..64})"
(
  cd "$fixture"
  bash scripts/update-toolchains.sh \
    --node 24.99.1 --node-digest "$node_digest" \
    --pnpm 11.99.1 \
    --rust 1.99.1 --rust-digest "$rust_digest" \
    --postgres 19-alpine --postgres-digest "$postgres_digest" >/dev/null
)
[[ "$(tr -d '[:space:]' < "$fixture/.node-version")" == 24.99.1 ]] || fail 'Node.js source was not updated'
[[ "$(jq -r .packageManager "$fixture/admin-ui/package.json")" == pnpm@11.99.1 ]] || fail 'pnpm source was not updated'
grep -Fxq "FROM node:24.99.1-bookworm-slim@$node_digest AS admin-ui-builder" "$fixture/Dockerfile" || fail 'Node.js image was not updated'
grep -Fxq "FROM rust:1.99.1-bookworm@$rust_digest AS builder" "$fixture/Dockerfile" || fail 'Rust image was not updated'
grep -Fxq 'channel = "1.99.1"' "$fixture/rust-toolchain.toml" || fail 'Rust toolchain source was not updated'
grep -Fxq 'rust-version = "1.99"' "$fixture/Cargo.toml" || fail 'Cargo rust-version was not updated'
grep -Fq "postgres:19-alpine@$postgres_digest" "$fixture/docker-compose.yml" || fail 'Compose PostgreSQL image was not updated'
grep -Fq "postgres:19-alpine@$postgres_digest" "$fixture/.github/workflows/ci.yml" || fail 'CI PostgreSQL image was not updated'
grep -Fq "postgres_image='postgres:19-alpine@$postgres_digest'" "$fixture/scripts/build-e2e-bundle.sh" ||
  fail 'Windows E2E bundle PostgreSQL image was not updated'

git -C "$fixture" reset -q --hard HEAD
sed -i -E "s|clamav_image='clamav/clamav:[0-9]+\\.[0-9]+\\.[0-9]+@|clamav_image='clamav/clamav:9.9.9@|" \
  "$fixture/scripts/test-container-runtime.sh"
if (cd "$fixture" && bash scripts/check-version-policy.sh >/dev/null 2>&1); then
  fail 'a runtime scanner patch that differs from Compose was accepted'
fi

git -C "$fixture" reset -q --hard HEAD
before="$(git -C "$fixture" status --porcelain=v1)"
if (cd "$fixture" && bash scripts/update-toolchains.sh --node 24.99.1 --node-digest sha256:invalid >/dev/null 2>&1); then
  fail 'invalid image digest was accepted'
fi
[[ "$(git -C "$fixture" status --porcelain=v1)" == "$before" ]] || fail 'invalid input changed the worktree'

git -C "$fixture" reset -q --hard HEAD
sed -i '/package-ecosystem: github-actions/,/open-pull-requests-limit:/ {
  /open-pull-requests-limit:/a\    ignore:\
      - dependency-name: pnpm/action-setup\
        versions: ["~> 6.0"]
}' "$fixture/.github/dependabot.yml"
if (cd "$fixture" && bash scripts/check-version-policy.sh >/dev/null 2>&1); then
  fail 'the removed pnpm/action-setup ignore was accepted'
fi

for ecosystem in github-actions docker docker-compose; do
  git -C "$fixture" reset -q --hard HEAD
  sed -i "/package-ecosystem: $ecosystem\$/,\/open-pull-requests-limit:/ {
    /default-days: 7/a\\      semver-patch-days: 3
  }" "$fixture/.github/dependabot.yml"
  if (cd "$fixture" && bash scripts/check-version-policy.sh >/dev/null 2>&1); then
    fail "unsupported $ecosystem tiered cooldown was accepted"
  fi
done

git -C "$fixture" reset -q --hard HEAD
sed -i "/'@napi-rs\\/wasm-runtime': 1.1.6/d" "$fixture/admin-ui/pnpm-workspace.yaml"
if (cd "$fixture" && bash scripts/check-version-policy.sh >/dev/null 2>&1); then
  fail 'the unsupported Rolldown WASI peer graph was accepted'
fi

git -C "$fixture" reset -q --hard HEAD
sed -i '/pnpm peers check/d' "$fixture/.github/workflows/ci.yml"
if (cd "$fixture" && bash scripts/check-version-policy.sh >/dev/null 2>&1); then
  fail 'the missing Admin UI peer dependency gate was accepted'
fi

git -C "$fixture" reset -q --hard HEAD
sed -i '/uses: astral-sh\/setup-uv@/d' "$fixture/.github/workflows/ci.yml"
if (cd "$fixture" && bash scripts/check-version-policy.sh >/dev/null 2>&1); then
  fail 'the missing workflow security runtime was accepted'
fi

git -C "$fixture" reset -q --hard HEAD
sed -i 's/zizmor==1.28.0/zizmor==1.27.0/' "$fixture/.github/workflows/ci.yml"
if (cd "$fixture" && bash scripts/check-version-policy.sh >/dev/null 2>&1); then
  fail 'an unreviewed workflow security scanner version was accepted'
fi

git -C "$fixture" reset -q --hard HEAD
sed -i '/CAMELLIA_NEXUS_DATABASE_PUBLIC_PASSWORD/d' "$fixture/docker-compose.yml"
if (cd "$fixture" && bash scripts/check-version-policy.sh >/dev/null 2>&1); then
  fail 'a shared or missing public database credential boundary was accepted'
fi

git -C "$fixture" reset -q --hard HEAD
sed -i 's/lease_generation = lease_generation + 1/lease_generation = lease_generation/' \
  "$fixture/src/admin_jobs.rs"
if (cd "$fixture" && bash scripts/check-version-policy.sh >/dev/null 2>&1); then
  fail 'a non-fencing bulk-job lease was accepted'
fi

printf '%s\n' 'Toolchain updater tests passed.'
