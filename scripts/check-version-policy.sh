#!/usr/bin/env bash
# Workflow expressions and shell fragments are intentionally matched literally.
# shellcheck disable=SC2016
set -euo pipefail

fail() {
  echo "version policy: $*" >&2
  exit 1
}

for command in awk grep head jq sed tr; do
  command -v "$command" >/dev/null || fail "required command is unavailable: $command"
done

node_version="$(tr -d '[:space:]' < .node-version)"
[[ "$node_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail '.node-version must contain exact stable SemVer'
[[ "${node_version%%.*}" == 24 ]] || fail 'Node.js must remain on the supported 24.x major'
[[ "$(jq -r '.engines.node // empty' admin-ui/package.json)" == '>=24 <25' ]] || fail 'admin UI engines.node must express the supported major window'
jq -e '.engines.pnpm == null' admin-ui/package.json >/dev/null || fail 'pnpm must not be repeated in engines'
package_manager="$(jq -r '.packageManager // empty' admin-ui/package.json)"
[[ "$package_manager" =~ ^pnpm@[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'packageManager must pin an exact pnpm version'
[[ "$(jq -r '.scripts["test:live"] // empty' admin-ui/package.json)" == \
  'svelte-kit sync && playwright test --config playwright.live.config.ts' ]] ||
  fail 'live Admin UI tests must generate the SvelteKit TypeScript configuration'
jq -e '
  [(.dependencies // {}), (.devDependencies // {})]
  | add
  | to_entries
  | all(.value | test("^[0-9]+\\.[0-9]+\\.[0-9]+(?:-[0-9A-Za-z.-]+)?$"))
' admin-ui/package.json >/dev/null || fail 'direct JavaScript dependencies must use exact versions'
grep -Fxq "  '@napi-rs/wasm-runtime': 1.1.6" admin-ui/pnpm-workspace.yaml ||
  fail 'the Rolldown WASI fallback must use the stable emnapi-compatible runtime'

rust_toolchain="$(sed -nE 's/^channel = "([^"]+)"/\1/p' rust-toolchain.toml)"
rust_version="$(sed -nE 's/^rust-version = "([^"]+)"/\1/p' Cargo.toml | head -n 1)"
[[ "$rust_toolchain" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'Rust toolchain must be exact stable SemVer'
[[ "${rust_toolchain%.*}" == "$rust_version" ]] || fail 'Cargo rust-version must match the toolchain major.minor'

shopt -s nullglob
workflow_files=(.github/workflows/*.yml .github/workflows/*.yaml)
((${#workflow_files[@]} > 0)) || fail 'no workflows found'

if grep -nE 'RUSTUP_TOOLCHAIN|^[[:space:]]+toolchain:|^[[:space:]]+node-version:' "${workflow_files[@]}"; then
  fail 'workflows must read Rust and Node.js versions from repository source files'
fi
if grep -h -A4 'uses: pnpm/action-setup@' "${workflow_files[@]}" | grep -qE '^[[:space:]]+version:'; then
  fail 'workflows must read pnpm from packageManager'
fi
setup_node_count="$({ grep -hEc 'uses: actions/setup-node@' "${workflow_files[@]}" || true; } | awk '{ total += $1 } END { print total + 0 }')"
node_file_count="$({ grep -hEc 'node-version-file:[[:space:]]+(client/)?\.node-version' "${workflow_files[@]}" || true; } | awk '{ total += $1 } END { print total + 0 }')"
[[ "$setup_node_count" -gt 0 && "$setup_node_count" == "$node_file_count" ]] || fail 'every setup-node step must use the owning checkout .node-version'
pnpm_setup_count="$({ grep -hEc 'uses: pnpm/action-setup@' "${workflow_files[@]}" || true; } | awk '{ total += $1 } END { print total + 0 }')"
pnpm_file_count="$({ grep -hEc 'package_json_file:[[:space:]]+(admin-ui|client/ui)/package.json' "${workflow_files[@]}" || true; } | awk '{ total += $1 } END { print total + 0 }')"
[[ "$pnpm_setup_count" -gt 0 && "$pnpm_setup_count" == "$pnpm_file_count" ]] || fail 'every pnpm setup step must use the owning checkout package.json'
checkout_count="$({ grep -hEc 'uses: actions/checkout@' "${workflow_files[@]}" || true; } | awk '{ total += $1 } END { print total + 0 }')"
nonpersistent_checkout_count="$({ grep -hEc 'persist-credentials:[[:space:]]+false' "${workflow_files[@]}" || true; } | awk '{ total += $1 } END { print total + 0 }')"
[[ "$checkout_count" -gt 0 && "$checkout_count" == "$nonpersistent_checkout_count" ]] || fail 'every checkout must disable persisted credentials'
if grep -q 'secrets:[[:space:]]+inherit' "${workflow_files[@]}"; then
  fail 'reusable workflows must receive only explicitly declared secrets'
fi

require_workflow_text() {
  local file="$1"
  local text="$2"
  local message="$3"
  grep -Fq -- "$text" "$file" || fail "$message"
}

cross_repo_action='uses: actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1'
cross_repo_workflows=(
  .github/workflows/ci.yml
  .github/workflows/contract-monitor.yml
)
[[ "$({ grep -hFc "$cross_repo_action" "${cross_repo_workflows[@]}" || true; } | awk '{ total += $1 } END { print total + 0 }')" == 2 ]] ||
  fail 'each server cross-repository workflow must mint one optional read token'
for workflow in "${cross_repo_workflows[@]}"; do
  require_workflow_text "$workflow" 'APP_CLIENT_ID: ${{ vars.CROSS_REPO_READ_APP_CLIENT_ID }}' \
    "$workflow does not read the cross-repository App client ID"
  require_workflow_text "$workflow" 'APP_PRIVATE_KEY: ${{ secrets.CROSS_REPO_READ_APP_PRIVATE_KEY }}' \
    "$workflow does not read the cross-repository App private key"
  require_workflow_text "$workflow" "TRUSTED_CONTEXT: \${{ (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository) && github.actor != 'dependabot[bot]' }}" \
    "$workflow does not isolate fork and Dependabot pull requests from App authentication"
  require_workflow_text "$workflow" 'if: ${{ steps.sibling-auth.outputs.mode == '\''public'\'' }}' \
    "$workflow does not verify the public fallback"
  require_workflow_text "$workflow" "$cross_repo_action" \
    "$workflow does not use the pinned cross-repository token action"
  require_workflow_text "$workflow" 'owner: ${{ github.repository_owner }}' \
    "$workflow hard-codes the cross-repository App owner"
  require_workflow_text "$workflow" 'CURRENT_LOGICAL_ID: nexus-management' \
    "$workflow does not bind the current repository to its stable logical identity"
  require_workflow_text "$workflow" 'REPOSITORY_MAP: ${{ vars.NEXUS_REPOSITORY_MAP }}' \
    "$workflow does not read the centrally audited repository map"
  require_workflow_text "$workflow" 'SIBLING_LOGICAL_ID: nexus-client' \
    "$workflow does not select the desktop repository by stable logical identity"
  require_workflow_text "$workflow" 'repositories: ${{ steps.sibling-auth.outputs.repository_name }}' \
    "$workflow does not scope the App token to the mapped desktop repository"
  require_workflow_text "$workflow" 'permission-contents: read' \
    "$workflow does not request read-only sibling contents"
  require_workflow_text "$workflow" 'permission-metadata: read' \
    "$workflow does not request read-only sibling metadata"
  require_workflow_text "$workflow" 'repository: ${{ steps.sibling-auth.outputs.repository }}' \
    "$workflow does not check out the validated mapped sibling"
  require_workflow_text "$workflow" 'token: ${{ steps.sibling-token.outputs.token || github.token }}' \
    "$workflow does not select App or public checkout credentials"
  if grep -qE 'permission-[^:]+:[[:space:]]+(write|admin)' "$workflow"; then
    fail "$workflow grants write or administration permission to cross-repository access"
  fi
done
require_workflow_text .github/workflows/ci.yml \
  "\$expectedKeys = @('nexus-client', 'nexus-management')" \
  'the Windows native workflow does not reject incomplete repository maps'
require_workflow_text .github/workflows/ci.yml \
  'Add-Content -Path $env:GITHUB_OUTPUT -Value "repository=$env:GITHUB_REPOSITORY_OWNER/$siblingName"' \
  'the Windows native workflow does not resolve the mapped sibling under the runtime owner'
require_workflow_text .github/workflows/ci.yml \
  'Add-Content -Path $env:GITHUB_OUTPUT -Value "repository_name=$siblingName"' \
  'the Windows native workflow does not expose one validated sibling name for token scoping'
require_workflow_text .github/workflows/contract-monitor.yml \
  'keys == ["nexus-client", "nexus-management"]' \
  'the contract monitor does not reject incomplete repository maps'
require_workflow_text .github/workflows/contract-monitor.yml \
  'echo "repository=$GITHUB_REPOSITORY_OWNER/$sibling_name"' \
  'the contract monitor does not resolve the mapped sibling under the runtime owner'
require_workflow_text .github/workflows/contract-monitor.yml \
  'echo "repository_name=$sibling_name"' \
  'the contract monitor does not expose one validated sibling name for token scoping'
require_workflow_text .github/workflows/ci.yml '$repository.private' \
  'the Windows native workflow does not reject a private repository in public mode'
require_workflow_text .github/workflows/contract-monitor.yml '.private == false' \
  'the contract monitor does not reject a private repository in public mode'
if grep -qE 'client-repository|camellia-computing/nexus|github\.repository_owner }}/nexus|repositories:[[:space:]]+nexus' \
  "${cross_repo_workflows[@]}"; then
  fail 'server cross-repository workflows must resolve siblings from the centrally audited map'
fi
require_workflow_text .github/workflows/ci.yml 'CROSS_REPO_READ_APP_PRIVATE_KEY:' \
  'server CI does not declare its optional App secret'
require_workflow_text .github/workflows/main.yml \
  'CROSS_REPO_READ_APP_PRIVATE_KEY: ${{ secrets.CROSS_REPO_READ_APP_PRIVATE_KEY }}' \
  'Main does not explicitly pass the optional App secret to server CI'
native_e2e_job="$(awk '/^  native-e2e:/ { in_job = 1 } /^  gate:/ { in_job = 0 } in_job' \
  .github/workflows/ci.yml)"
if grep -q 'RELEASE_APP_' .github/workflows/contract-monitor.yml ||
  grep -q 'RELEASE_APP_' <<< "$native_e2e_job"; then
  fail 'cross-repository validation must not reuse the Release App'
fi
require_workflow_text .github/workflows/ci.yml 'uses: astral-sh/setup-uv@' \
  'CI does not install the pinned workflow security runtime'
require_workflow_text .github/workflows/ci.yml 'version: 0.12.0' \
  'CI does not select the reviewed exact uv release'
require_workflow_text .github/workflows/ci.yml \
  'run: uvx --from zizmor==1.28.0 zizmor --strict-collection --persona=pedantic --format=github .' \
  'CI does not block on the reviewed pedantic workflow security scan'

grep -q 'rustup toolchain install --no-self-update' "${workflow_files[@]}" || fail 'workflows must install the repository Rust toolchain'
if grep -qE 'runs-on:[[:space:]]+(ubuntu|windows|macos)-latest' "${workflow_files[@]}"; then
  fail 'hosted runner families must be explicit'
fi
grep -q 'pnpm install --frozen-lockfile' "${workflow_files[@]}" || fail 'CI must install the admin UI from the frozen lockfile'
grep -Fq 'pnpm peers check' .github/workflows/ci.yml ||
  fail 'CI must reject unsupported Admin UI peer dependency graphs'
grep -qE 'cargo .*(--locked.*(test|clippy)|(test|clippy).*--locked)' "${workflow_files[@]}" || fail 'CI must use locked Cargo gates'

while IFS= read -r reference; do
  case "$reference" in
    ./*) ;;
    docker://*)
      [[ "$reference" =~ ^docker://[^@[:space:]]+@sha256:[0-9a-f]{64}$ ]] || fail "container action is not digest-pinned: $reference"
      ;;
    *)
      [[ "$reference" =~ ^[^@[:space:]]+@[0-9a-f]{40}$ ]] || fail "action is not commit-pinned: $reference"
      ;;
  esac
done < <(sed -nE 's/^[[:space:]]*-?[[:space:]]*uses:[[:space:]]+([^[:space:]#]+).*/\1/p' "${workflow_files[@]}")

full_revision='rev[[:space:]]*=[[:space:]]*"[0-9a-f]{40}"'
while IFS= read -r dependency; do
  [[ "$dependency" =~ $full_revision ]] || fail "Cargo git dependency lacks a full revision: $dependency"
done < <(grep -hE 'git[[:space:]]*=' -- */Cargo.toml Cargo.toml 2>/dev/null || true)

first_docker_line="$(head -n 1 Dockerfile)"
[[ "$first_docker_line" =~ ^#[[:space:]]syntax=docker/dockerfile:[^@]+@sha256:[0-9a-f]{64}$ ]] || fail 'Dockerfile frontend must be digest-pinned'
while IFS= read -r reference; do
  [[ "$reference" =~ @sha256:[0-9a-f]{64}$ ]] || fail "Docker stage is not digest-pinned: $reference"
done < <(awk '$1 == "FROM" { print $2 }' Dockerfile)

node_image="$(awk '$1 == "FROM" && $2 ~ /^node:/ { print $2 }' Dockerfile)"
rust_image="$(awk '$1 == "FROM" && $2 ~ /^rust:/ { print $2 }' Dockerfile)"
[[ "$node_image" == "node:${node_version}-bookworm-slim@"* ]] || fail 'Docker Node.js tag must match .node-version'
[[ "$rust_image" == "rust:${rust_toolchain}-bookworm@"* ]] || fail 'Docker Rust tag must match rust-toolchain.toml'
grep -qE '^COPY[[:space:]]+\.node-version[[:space:]]' Dockerfile || fail 'Docker build must copy .node-version for verification'
grep -qE '^COPY[[:space:]]+rust-toolchain\.toml[[:space:]]' Dockerfile || fail 'Docker build must copy rust-toolchain.toml for verification'
if grep -qE 'pnpm@[0-9]+\.[0-9]+\.[0-9]+' Dockerfile; then
  fail 'Docker must read pnpm from packageManager'
fi
runtime_stage="$(awk '/^FROM debian:/ { runtime = 1 } runtime { print }' Dockerfile)"
[[ -n "$runtime_stage" ]] || fail 'Docker runtime stage is missing'
if grep -qE 'apt-get|useradd|[[:space:]]curl([[:space:]]|$)' <<< "$runtime_stage"; then
  fail 'Docker runtime stage must not install mutable packages'
fi
grep -q '^USER 10001:10001$' Dockerfile || fail 'Docker runtime must use the production numeric UID and GID'
grep -q '^COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt$' Dockerfile || fail 'Docker runtime must copy the verified CA bundle'
grep -Fxq 'admin-ui/**' .dockerignore ||
  fail 'Docker context must deny Admin UI children before the production allowlist'
for local_output in node_modules .svelte-kit build test-results playwright-report; do
  grep -Fq "admin-ui/$local_output/" .dockerignore ||
    fail "Docker context must exclude admin-ui/$local_output"
done

container_build_count="$({ grep -hEc 'uses: docker/build-push-action@' "${workflow_files[@]}" || true; } | awk '{ total += $1 } END { print total + 0 }')"
amd64_platform_count="$({ grep -hEc 'platforms:[[:space:]]+linux/amd64' "${workflow_files[@]}" || true; } | awk '{ total += $1 } END { print total + 0 }')"
[[ "$container_build_count" -gt 0 && "$container_build_count" == "$amd64_platform_count" ]] || fail 'every server image build must declare linux/amd64'
[[ "$(grep -Fc 'camellia-nexus-management-server", "healthcheck"' docker-compose.yml)" == 3 ]] || fail 'every runtime service healthcheck must use the runtime binary'
if grep -q '"curl"' docker-compose.yml; then
  fail 'Compose healthchecks must not depend on a runtime curl package'
fi
[[ "$(grep -Fc 'CAMELLIA_NEXUS_DATABASE_MIGRATE: false' docker-compose.yml)" == 3 ]] ||
  fail 'every long-lived Compose role must explicitly disable automatic migrations'
for required_policy in \
  'CAMELLIA_NEXUS_LICENSE_ISSUER: ${CAMELLIA_NEXUS_LICENSE_ISSUER:?' \
  'CAMELLIA_NEXUS_LICENSE_KEY_ID: ${CAMELLIA_NEXUS_LICENSE_KEY_ID:?' \
  'CAMELLIA_NEXUS_CLIENT_MINIMUM_VERSION: ${CAMELLIA_NEXUS_CLIENT_MINIMUM_VERSION:?' \
  'CAMELLIA_NEXUS_CLIENT_RECOMMENDED_VERSION: ${CAMELLIA_NEXUS_CLIENT_RECOMMENDED_VERSION:?' \
  'CAMELLIA_NEXUS_CLIENT_VERSION_ENFORCE_AFTER: "${CAMELLIA_NEXUS_CLIENT_VERSION_ENFORCE_AFTER:?' \
  'CAMELLIA_NEXUS_ADMIN_PUBLIC_ORIGIN: ${CAMELLIA_NEXUS_ADMIN_PUBLIC_ORIGIN:?'; do
  grep -Fq "$required_policy" docker-compose.yml ||
    fail "Compose must require deployment policy: $required_policy"
done
for host_port in \
  CAMELLIA_NEXUS_LICENSE_HOST_PORT \
  CAMELLIA_NEXUS_LICENSE_METRICS_HOST_PORT \
  CAMELLIA_NEXUS_ADMIN_HOST_PORT \
  CAMELLIA_NEXUS_ADMIN_METRICS_HOST_PORT; do
  grep -Fq "127.0.0.1:\${${host_port}:-" docker-compose.yml ||
    fail "Compose must keep ${host_port} on host loopback"
done
if grep -Eq 'CAMELLIA_NEXUS_(LICENSE_ISSUER|ADMIN_PUBLIC_ORIGIN):[[:space:]]+https://' docker-compose.yml; then
  fail 'Compose must not hard-code deployment domains'
fi
if grep -Eq '^DATABASE_URL=postgres://[^@/]+:[^@]*@' .env.example; then
  fail '.env.example must not embed a database password in DATABASE_URL'
fi
for required_template_value in \
  CAMELLIA_NEXUS_LICENSE_IMAGE \
  CAMELLIA_NEXUS_LICENSE_ISSUER \
  CAMELLIA_NEXUS_LICENSE_KEY_ID \
  CAMELLIA_NEXUS_CLIENT_MINIMUM_VERSION \
  CAMELLIA_NEXUS_CLIENT_RECOMMENDED_VERSION \
  CAMELLIA_NEXUS_CLIENT_VERSION_ENFORCE_AFTER \
  CAMELLIA_NEXUS_ADMIN_PUBLIC_ORIGIN; do
  grep -Fxq "${required_template_value}=" .env.example ||
    fail ".env.example must leave ${required_template_value} empty for fail-closed operator input"
done
grep -Fxq '/.env.*' .gitignore || fail 'root environment variants must be ignored'
grep -Fxq '!/.env.example' .gitignore || fail 'the non-secret environment template must remain tracked'
for private_override in \
  /docker-compose.override.yml \
  /docker-compose.override.yaml \
  /compose.override.yml \
  /compose.override.yaml; do
  grep -Fxq "$private_override" .gitignore ||
    fail "private deployment override must be ignored: $private_override"
done

while IFS= read -r reference; do
  [[ "$reference" == \$\{* ]] && continue
  [[ "$reference" =~ @sha256:[0-9a-f]{64}$ ]] || fail "Compose image is not digest-pinned: $reference"
done < <(sed -nE 's/^[[:space:]]+image:[[:space:]]+([^[:space:]]+).*/\1/p' docker-compose.yml)

compose_postgres="$(sed -nE 's/^[[:space:]]+image:[[:space:]]+(postgres:[^[:space:]]+).*/\1/p' docker-compose.yml)"
workflow_postgres="$(sed -nE 's/^[[:space:]]+image:[[:space:]]+(postgres:[^[:space:]]+).*/\1/p' .github/workflows/ci.yml)"
bundle_postgres="$(sed -nE "s/^postgres_image='(postgres:[^']+)'$/\1/p" scripts/build-e2e-bundle.sh)"
[[ -n "$compose_postgres" && "$compose_postgres" == "$workflow_postgres" &&
  "$compose_postgres" == "$bundle_postgres" ]] ||
  fail 'CI, Compose, and the Windows E2E bundle must use the same PostgreSQL digest'
compose_clamav="$(sed -nE 's/^[[:space:]]+image:[[:space:]]+(clamav\/clamav:[^[:space:]]+).*/\1/p' docker-compose.yml)"
runtime_clamav="$(sed -nE "s/^clamav_image='(clamav\\/clamav:[^']+)'$/\\1/p" scripts/test-container-runtime.sh)"
[[ "$runtime_clamav" =~ ^clamav/clamav:[0-9]+\.[0-9]+\.[0-9]+@sha256:[0-9a-f]{64}$ ]] ||
  fail 'the runtime test ClamAV image must use an exact patch tag and immutable digest'
compose_clamav_version="$(sed -nE 's|^clamav/clamav:([0-9]+\.[0-9]+\.[0-9]+)_base@sha256:[0-9a-f]{64}$|\1|p' <<< "$compose_clamav")"
runtime_clamav_version="$(sed -nE 's|^clamav/clamav:([0-9]+\.[0-9]+\.[0-9]+)@sha256:[0-9a-f]{64}$|\1|p' <<< "$runtime_clamav")"
[[ -n "$compose_clamav_version" && "$compose_clamav_version" == "$runtime_clamav_version" ]] ||
  fail 'Compose and the runtime test must use the same exact ClamAV patch'
grep -Fq -- '- postgres-18-data:/var/lib/postgresql' docker-compose.yml ||
  fail 'PostgreSQL 18 Compose data must be mounted at /var/lib/postgresql'
if grep -Fq '/docker-entrypoint-initdb.d' docker-compose.yml; then
  fail 'production Compose must not bind host initialization scripts into PostgreSQL'
fi
grep -Fq 'command: ["db-bootstrap", "reconcile"]' docker-compose.yml ||
  fail 'Compose must reconcile database identities independently of first initdb'
grep -Fq 'condition: service_completed_successfully' docker-compose.yml ||
  fail 'Compose must gate later services on successful one-shot roles'
grep -Fq 'POSTGRES_USER: ${CAMELLIA_NEXUS_DATABASE_BOOTSTRAP_ROLE:-nexus_bootstrap}' \
  docker-compose.yml ||
  fail 'PostgreSQL must initialize with the dedicated bootstrap identity'
for role in BOOTSTRAP MIGRATE PUBLIC ADMIN_WEB ADMIN_WORKER; do
  grep -Fq "CAMELLIA_NEXUS_DATABASE_${role}_PASSWORD_FILE" docker-compose.yml ||
    fail "Compose is missing the ${role} database credential boundary"
done
for secret in database_bootstrap_password database_migrate_password database_public_password database_admin_web_password database_admin_worker_password; do
  grep -Fq "$secret" docker-compose.yml ||
    fail "Compose is missing the ${secret} Docker secret"
done
for source in \
  database-bootstrap-password \
  database-migrate-password \
  database-public-password \
  database-admin-web-password \
  database-admin-worker-password \
  entitlement-es256-private.pem \
  workspace-keyring.json \
  webhook-keyring.json \
  admin-keyring.json \
  admin-proxy-secret; do
  grep -Fq "/run/camellia-nexus/secrets/$source" docker-compose.yml ||
    fail "Compose secret source must default to the root-only runtime directory: $source"
done
if grep -Eq 'CAMELLIA_NEXUS_DATABASE_(BOOTSTRAP|MIGRATE|PUBLIC|ADMIN_WEB|ADMIN_WORKER)_PASSWORD:' docker-compose.yml; then
  fail 'Compose must not expose database passwords as environment values'
fi
grep -Fq 'network_mode: none' docker-compose.yml ||
  fail 'the deployment secret validator must not receive a network namespace'
grep -Fq 'chmod 0444 "$staging/$destination"' scripts/stage-production-secrets.sh ||
  fail 'staged Compose secrets must use the UID-independent read-only projection mode'
grep -Fq 'install -d -o root -g root -m 0700 "$runtime_root"' scripts/stage-production-secrets.sh ||
  fail 'the staged secret parent must remain root-only'
if grep -Eq 'docker (compose )?(down -v|volume rm|system prune)' scripts/camellia-nexus-deploy.sh; then
  fail 'the production deployment entrypoint must not contain destructive volume cleanup'
fi
if grep -q '^DATABASE_URL=' deploy/management-common.env.example; then
  fail 'the common systemd environment must not share one database credential across roles'
fi
for role_file in migrate public-api admin-web admin-worker; do
  grep -q '^DATABASE_URL=postgres://' "deploy/${role_file}.env.example" ||
    fail "${role_file} must declare its own database login"
  if grep -Eq '^DATABASE_URL=postgres://[^@/]+:[^@]*@' "deploy/${role_file}.env.example"; then
    fail "${role_file} must not embed a database password in DATABASE_URL"
  fi
done
for unit in deploy/systemd/*.service; do
  grep -Fq 'LoadCredential=database_password:' "$unit" ||
    fail "$(basename "$unit") must load a role-specific database credential"
  grep -Fq 'Environment=DATABASE_PASSWORD_FILE=%d/database_password' "$unit" ||
    fail "$(basename "$unit") must pass only the credential path to the process"
done
grep -Fq 'apply_runtime_database_grants' src/main.rs ||
  fail 'the migration role must atomically apply explicit runtime database grants'
grep -Fq 'lease_generation = lease_generation + 1' src/admin_jobs.rs ||
  fail 'bulk-job leases must use a monotonic fencing generation'
if grep -Fq 'worker_lease_lost' src/admin_jobs.rs; then
  fail 'lease takeover must reconcile ambiguous items instead of reporting terminal failure'
fi
grep -Fq -- '- postgres-data:/var/lib/postgresql' scripts/provision-e2e-compose.sh ||
  fail 'the disposable E2E stack must use the PostgreSQL 18 data mount'
grep -Fq '/run/desktop/mnt/host/' scripts/provision-e2e-compose.sh ||
  fail 'the disposable E2E stack must translate Windows volumes for Docker Desktop'
[[ "$(grep -Fc 'create_host_path: false' scripts/provision-e2e-compose.sh)" -eq 4 ]] ||
  fail 'every disposable E2E secret bind must reject a missing host file'
grep -Fq 'CAMELLIA_NEXUS_CLIENT_VERSION_ENFORCE_AFTER: "2030-01-01T00:00:00Z"' \
  scripts/provision-e2e-compose.sh ||
  fail 'the disposable E2E enforcement timestamp must remain a quoted YAML string'
if grep -Rq -- '/var/lib/postgresql/data' docker-compose.yml scripts/provision-e2e-compose.sh; then
  fail 'PostgreSQL 18 must not use the legacy /var/lib/postgresql/data volume mount'
fi
for scenario in \
  free-primary free-second-device \
  pro-primary pro-recovery \
  team-owner team-member team-additional-device; do
  grep -Fq -- "\"native-e2e-\$environment_id-$scenario-code\"" \
    scripts/provision-e2e-compose.sh ||
    fail "the disposable E2E $scenario activation code must have a stable operation identifier"
done
grep -Fq 'expected exactly one issued activation code' scripts/provision-e2e-compose.sh ||
  fail 'the disposable E2E activation response must be validated as a one-item batch'
for fixture in \
  'schemaVersion: 3' \
  "activationCodes: {primary: \$free_primary_code, secondDevice: \$free_second_device_code}" \
  "activationCodes: {primary: \$pro_primary_code, recovery: \$pro_recovery_code}" \
  "billing: {offerId: \$offer_id, paymentMethodId: \$payment_method_id, invoiceId: \$invoice_id}" \
  "additionalDevice: \$team_additional_device_code"; do
  grep -Fq "$fixture" scripts/provision-e2e-compose.sh ||
    fail "the disposable E2E schema-3 descriptor is missing: $fixture"
done
for control in pause resume account-state; do
  grep -Fq "scripts/provision-e2e-compose.sh $control" scripts/provision-e2e-compose.sh ||
    fail "the disposable E2E provider is missing the $control control contract"
done

policy=docs/dependency-management.md
[[ -f "$policy" ]] || fail 'dependency policy documentation is missing'
for exception in 'pnpm 11' cookie '@napi-rs/wasm-runtime' 'TypeScript 7' RUSTSEC-2026-0235 workflow_run; do
  grep -q "$exception" "$policy" || fail "dependency exception is undocumented: $exception"
done
grep -Fq 'cargo audit --deny yanked --ignore RUSTSEC-2026-0235' .github/workflows/ci.yml ||
  fail 'Cargo audit must deny yanked packages and ignore only the registered unreachable rkyv advisory'
audit_ignore_count="$(
  grep -RhoE -- '--ignore[[:space:]]+RUSTSEC-[0-9]{4}-[0-9]{4}' .github/workflows |
    wc -l |
    tr -d '[:space:]'
)"
[[ "$audit_ignore_count" == 1 ]] || fail 'exactly one registered Rust advisory ignore is permitted'

dependabot=.github/dependabot.yml
[[ -f "$dependabot" ]] || fail 'Dependabot configuration is missing'
ecosystem_count="$(grep -c 'package-ecosystem:' "$dependabot")"
default_cooldown_count="$(grep -c 'default-days: 7' "$dependabot")"
[[ "$ecosystem_count" == "$default_cooldown_count" ]] || fail 'every Dependabot ecosystem must define the default cooldown'
if grep -qE 'package-ecosystem:[[:space:]]+(npm|rust-toolchain)' "$dependabot"; then
  fail 'pnpm 11 and coupled Rust toolchain updates must use scripts/update-toolchains.sh'
fi
unsupported_cooldowns="$(awk '
  /package-ecosystem:/ {
    ecosystem = $NF
    gsub(/"/, "", ecosystem)
    next
  }
  /semver-(major|minor|patch)-days:/ && ecosystem != "cargo" {
    print ecosystem ":" $1
  }
' "$dependabot")"
[[ -z "$unsupported_cooldowns" ]] ||
  fail "only Cargo supports tiered cooldowns in this policy: $unsupported_cooldowns"
awk '
  /package-ecosystem:[[:space:]]+cargo$/ { cargo = 1; next }
  /package-ecosystem:/ { cargo = 0 }
  cargo && /semver-major-days:[[:space:]]+30$/ { major++ }
  cargo && /semver-minor-days:[[:space:]]+7$/ { minor++ }
  cargo && /semver-patch-days:[[:space:]]+3$/ { patch++ }
  END { exit !(major == 1 && minor == 1 && patch == 1) }
' "$dependabot" || fail 'Cargo cooldowns must be major=30, minor=7, and patch=3 days'
if grep -qE 'dependency-name:[[:space:]]+pnpm/action-setup' "$dependabot"; then
  fail 'pnpm/action-setup must not remain ignored after the supported v6 migration'
fi
awk '
  /package-ecosystem: docker$/ { ecosystem = "docker"; next }
  /package-ecosystem: docker-compose$/ { ecosystem = "compose"; next }
  /package-ecosystem:/ { ecosystem = "" }
  ecosystem == "docker" && /dependency-name: node$/ { node = 1 }
  ecosystem == "docker" && /dependency-name: rust$/ { rust = 1 }
  ecosystem == "compose" && /dependency-name: postgres$/ { postgres = 1 }
  END { exit !(node && rust && postgres) }
' "$dependabot" || fail 'coupled Node.js, Rust, and PostgreSQL images must be excluded from standalone updates'
[[ -x scripts/update-toolchains.sh ]] || fail 'atomic toolchain updater is missing or not executable'

echo 'Version policy is consistent.'
