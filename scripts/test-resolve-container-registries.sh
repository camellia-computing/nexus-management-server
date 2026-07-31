#!/usr/bin/env bash
set -euo pipefail

root="$(mktemp -d)"
trap 'find "$root" -maxdepth 1 -type f -delete; rmdir "$root"' EXIT

resolve() {
  local map="$1"
  GITHUB_OUTPUT="$root/output" \
  GITHUB_REPOSITORY_OWNER=Example-Organization \
  LOGICAL_REPOSITORY_ID=nexus-management \
  CONTAINER_REGISTRY_MAP="$map" \
    bash scripts/resolve-container-registries.sh
}

resolve '{"remote-server":{"dockerhub":null,"ghcr":"remote-server"},"nexus-management":{"dockerhub":null,"ghcr":"management"}}'
grep -Fxq 'ghcr=ghcr.io/example-organization/management' "$root/output"
grep -Fxq 'dockerhub=' "$root/output"
grep -Fxq 'primary=ghcr.io/example-organization/management' "$root/output"

: > "$root/output"
resolve '{"nexus-management":{"dockerhub":"example/management","ghcr":null}}'
grep -Fxq 'ghcr=' "$root/output"
grep -Fxq 'dockerhub=docker.io/example/management' "$root/output"
grep -Fxq 'primary=docker.io/example/management' "$root/output"

for invalid in \
  '{}' \
  '{"nexus-management":{"dockerhub":null,"ghcr":null}}' \
  '{"nexus-management":{"dockerhub":"UPPER/name","ghcr":null}}' \
  '{"nexus-management":{"dockerhub":null,"ghcr":"owner/name"}}' \
  '{"nexus-management":{"dockerhub":null,"ghcr":"valid","extra":"invalid"}}'
do
  : > "$root/output"
  if resolve "$invalid" >/dev/null 2>&1; then
    echo "Invalid registry map was accepted: $invalid" >&2
    exit 1
  fi
done

echo "Container registry map tests passed"
