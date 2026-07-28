#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_STEP_SUMMARY:?GITHUB_STEP_SUMMARY must be set}"

runner_name="${ImageOS:-${RUNNER_OS:-unknown}}"
runner_version="${ImageVersion:-unknown}"
node_version="$(node --version)"
pnpm_version="$(pnpm --version)"
rust_version="$(rustc --version)"

{
  echo '## Toolchains'
  printf -- '- Runner: `%s %s`\n' "$runner_name" "$runner_version"
  printf -- '- Node.js: `%s`\n' "$node_version"
  printf -- '- pnpm: `%s`\n' "$pnpm_version"
  printf -- '- Rust: `%s`\n' "$rust_version"
} >> "$GITHUB_STEP_SUMMARY"
