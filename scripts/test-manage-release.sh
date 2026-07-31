#!/usr/bin/env bash
# shellcheck disable=SC2034,SC2329
set -euo pipefail

# shellcheck disable=SC1091
source "$(dirname "$0")/manage-release.sh"

GH_TOKEN=synthetic-release-token
credential_test_dir="$(mktemp -d)"
git -C "$credential_test_dir" init -q
git -C "$credential_test_dir" remote add origin https://github.example.invalid/product/repository.git
credential="$(cd "$credential_test_dir" && printf 'protocol=https\nhost=github.example.invalid\n\n' | git_remote credential fill)"
grep -Fxq 'username=x-access-token' <<< "$credential" || exit 1
grep -Fxq 'password=synthetic-release-token' <<< "$credential" || exit 1
if (cd "$credential_test_dir" && printf 'protocol=https\nhost=example.invalid\n\n' | git_remote credential fill >/dev/null 2>&1); then
  exit 1
fi
rm -rf "$credential_test_dir"
unset GH_TOKEN credential credential_test_dir
git_remote() { git "$@"; }

fail() {
  echo "$*" >&2
  exit 1
}

assert_eq() {
  [[ "$1" == "$2" ]] || fail "expected <$2>, got <$1>"
}

assert_eq "$(release_pr_pending_mode false)" required
assert_eq "$(release_pr_pending_mode true)" optional
if release_pr_pending_mode invalid >/dev/null 2>&1; then
  fail "invalid managed Release completion state selected a pending-label mode"
fi
pending_pr_json='{"labels":[{"name":"release:pending"}]}'
completed_pr_json='{"labels":[]}'
validate_release_pr_pending_state "$pending_pr_json" 17 required
validate_release_pr_pending_state "$pending_pr_json" 17 optional
validate_release_pr_pending_state "$completed_pr_json" 17 optional
if validate_release_pr_pending_state "$completed_pr_json" 17 required >/dev/null 2>&1; then
  fail "incomplete publication accepted a Release PR without the pending label"
fi
if validate_release_pr_pending_state "$pending_pr_json" 17 invalid >/dev/null 2>&1; then
  fail "invalid Release PR pending-label mode was accepted"
fi
unset pending_pr_json completed_pr_json

release_workflow="$(dirname "$0")/../.github/workflows/release-manager.yml"
grep -Fq 'VALIDATION_RUN_ID: ${{ inputs.validation-run-id' "$release_workflow" ||
  fail "release workflow does not forward the validation run"
grep -Fq 'VERIFIED_SHA: ${{ inputs.verified-sha' "$release_workflow" ||
  fail "release workflow does not forward the validated commit"
if grep -Fq "github.event_name == 'workflow_call'" "$release_workflow"; then
  fail "release workflow incorrectly treats workflow_call as the caller event"
fi
unset release_workflow

main_workflow="$(dirname "$0")/../.github/workflows/main.yml"
grep -Fq 'permission-administration: read' "$main_workflow" || fail "main policy token lacks Administration read"
grep -Fq 'permission-metadata: read' "$main_workflow" || fail "main policy token lacks Metadata read"
grep -Fq 'permission-contents: write' "$main_workflow" ||
  fail "main policy token cannot read the complete merge policy"
unset main_workflow

ci_workflow="$(dirname "$0")/../.github/workflows/ci.yml"
grep -Fq 'ready_for_review' "$ci_workflow" || fail "CI does not validate a fully initialized Release PR"
grep -Fq "github.event.pull_request.draft == false" "$ci_workflow" || fail "CI does not defer draft PR validation"
grep -Fq "group: ci-\${{ github.workflow }}-\${{ github.ref }}-draft-\${{ github.event_name == 'pull_request' && github.event.pull_request.draft == true }}" "$ci_workflow" ||
  fail "draft CI can cancel a review-ready validation"
grep -Fq "always() && !cancelled() && needs.metadata.result != 'skipped'" "$ci_workflow" ||
  fail "cancelled CI can emit a derived Gate failure"
grep -Fq 'scripts/manage-release.sh resolve-merged-pr "$GITHUB_SHA"' "$ci_workflow" ||
  fail "merged release CI does not resolve the exact managed PR"
if grep -Fq 'commits/$GITHUB_SHA/pulls' "$ci_workflow"; then
  fail "merged release CI still depends on commit-association indexing"
fi
unset ci_workflow

grep -Fq -- '-F draft=true' "$(dirname "$0")/manage-release.sh" || fail "Release PR is not initialized as a draft"
grep -Fq 'gh pr ready' "$(dirname "$0")/manage-release.sh" || fail "Release PR is never opened for review"

publish_workflow="$(dirname "$0")/../.github/workflows/publish-release.yml"
grep -Fq 'CONTAINER_REGISTRY_MAP: ${{ vars.CONTAINER_REGISTRY_MAP }}' "$publish_workflow" ||
  fail "publication does not consume the reviewed container registry map"
grep -Fq 'outputs: type=oci,dest=${{ runner.temp }}/release-image.oci.tar' "$publish_workflow" ||
  fail "publication does not freeze an OCI layout before approval"
grep -Fq 'environment: release' "$publish_workflow" ||
  fail "publication has no protected release environment"
if grep -Fq 'publish_ghcr:' "$publish_workflow" ||
   grep -Fq 'publish_dockerhub:' "$publish_workflow"; then
  fail "registry selection can be overridden by dispatch input"
fi
[[ "$(grep -Fc 'RELEASE_APP_SLUG: ${{ steps.policy-token.outputs.app-slug }}' "$publish_workflow")" == 5 ]] ||
  fail "publication boundaries do not all receive the installation App slug"
[[ "$(grep -Fc 'permission-metadata: read' "$publish_workflow")" == 2 ]] ||
  fail "publication policy tokens do not use the documented Metadata-read scope"
[[ "$(grep -Fc 'permission-contents: write' "$publish_workflow")" == 2 ]] ||
  fail "publication policy tokens cannot read the complete merge policy"
[[ "$(grep -Fc '      pull-requests: write' "$publish_workflow")" == 1 ]] ||
  fail "publication completion does not have exact PR write permission"
if grep -Fq '      issues: write' "$publish_workflow"; then
  fail "publication completion retains unnecessary Issues write permission"
fi
grep -Fq 'Existing managed release tag to recover' "$publish_workflow" ||
  fail "publication has no explicit managed-tag recovery input"
grep -Fq 'Release recovery must use the workflow on main' "$publish_workflow" ||
  fail "release recovery can execute an untrusted workflow ref"
grep -Fq 'git show "$GITHUB_WORKFLOW_SHA:scripts/manage-release.sh"' "$publish_workflow" ||
  fail "release recovery does not use its trusted control revision"
grep -Fq 'RELEASE_SHA: ${{ needs.metadata.outputs.sha }}' "$publish_workflow" ||
  fail "publication does not use the resolved tag commit"
if grep -Fq '/releases/tags/' "$(dirname "$0")/manage-release.sh"; then
  fail "managed draft lookup still uses the published-only tag endpoint"
fi
grep -Fq 'RECORDED_DIGEST: ${{ steps.reauthorize.outputs.release-digest }}' "$publish_workflow" ||
  fail "published image recovery is not bound to Release metadata"
unset publish_workflow

publish_script="$(dirname "$0")/publish_image_release.sh"
[[ "$(grep -Fc 'for alias in "$VERSION" "sha-$RELEASE_SHA"; do' "$publish_script")" == 2 ]] ||
  fail "formal image aliases do not consistently use version and full release SHA"
grep -Fq 'Draft release cannot contain a recorded container digest' "$publish_script" ||
  fail "published image recovery can rebuild without a recorded digest"
if grep -Fq 'sha-${GITHUB_SHA::12}' "$publish_script" ||
   grep -Fq 'for alias in "v$VERSION"' "$publish_script"; then
  fail "publication contains a non-canonical immutable image alias"
fi
unset publish_script

merge_workflow="$(dirname "$0")/../.github/workflows/merge.yml"
grep -Fq 'pull_request_review:' "$merge_workflow" || fail "merge workflow does not react to approval"
grep -Fq 'workflow_run:' "$merge_workflow" || fail "merge workflow does not recover approval-before-Gate ordering"
grep -Fq 'permission-contents: write' "$merge_workflow" || fail "merge App token cannot execute the approved merge"
grep -Fq 'permission-pull-requests: read' "$merge_workflow" || fail "merge App token has an invalid PR permission"
if grep -Fq 'permission-pull-requests: write' "$merge_workflow"; then
  fail "merge App token has unnecessary PR write permission"
fi
grep -Fq 'EXPECTED_FOCUSED_RUN_ID:' "$merge_workflow" || fail "merge workflow does not bind the focused run"
grep -Fq 'trusted/scripts/manage-release.sh" merge-ready' "$merge_workflow" ||
  fail "merge workflow does not perform lightweight readiness validation"
grep -Fq 'trusted/scripts/manage-release.sh" merge-approved' "$merge_workflow" ||
  fail "merge workflow does not execute trusted merge policy"
if grep -Fq 'pull_request_target:' "$merge_workflow"; then
  fail "merge workflow uses pull_request_target"
fi
unset merge_workflow

valid_product_version 1.0.0 || fail "canonical server version rejected"
valid_product_version 18446744073709551615.0.0 || fail "Cargo u64 boundary rejected"
if valid_product_version 18446744073709551616.0.0; then fail "Cargo u64 overflow accepted"; fi
if valid_product_version 01.0.0; then fail "non-canonical version accepted"; fi
version_ge 10.0.0 2.99.99 || fail "numeric SemVer comparison failed"
if version_ge 1.9.9 2.0.0; then fail "descending SemVer comparison accepted"; fi
release_version_allowed 1.2.3 1.2.3 false || fail "automatic release minimum rejected"
if release_version_allowed 1.2.4 1.2.3 false; then fail "unlocked version above the automatic minimum accepted"; fi
release_version_allowed 1.2.4 1.2.3 true || fail "locked version above the automatic minimum rejected"
if release_version_allowed 1.2.2 1.2.3 true; then fail "locked version below the automatic minimum accepted"; fi

generation_dir="$(mktemp -d)"
generation_manifest="$generation_dir/Cargo.toml"
printf '%s\n' \
  '[package]' \
  'name = "fixture"' \
  'version = "1.2.2"' \
  '' \
  '[dependencies]' \
  'fixture-dependency = { version = "9.9.9" }' > "$generation_manifest"
rewrite_release_manifest 1.2.3 "$generation_manifest"
grep -Fxq 'version = "1.2.3"' "$generation_manifest" || fail 'package version was not rewritten'
grep -Fxq 'fixture-dependency = { version = "9.9.9" }' "$generation_manifest" || fail 'dependency version was rewritten'
printf '%s\n' \
  'version = 4' \
  '' \
  '[[package]]' \
  'name = "camellia-nexus-management-server"' \
  'version = "1.2.2"' \
  '' \
  '[[package]]' \
  'name = "fixture"' \
  'version = "9.9.9"' \
  'source = "registry+https://github.com/rust-lang/crates.io-index"' > "$generation_dir/Cargo.lock"
rewrite_release_lock 1.2.3 "$generation_dir/Cargo.lock" 'camellia-nexus-management-server'
[[ "$(grep -Fxc 'version = "1.2.3"' "$generation_dir/Cargo.lock")" == 1 ]] ||
  fail 'package lock version was not rewritten exactly'
grep -Fxq 'version = "9.9.9"' "$generation_dir/Cargo.lock" || fail 'registry lock version was rewritten'
printf '# Changelog\n\n## [1.1.0] - 2026-01-01\n' > "$generation_dir/base.md"
printf '## [1.2.3] - 2026-07-15\n' > "$generation_dir/fragment.md"
merge_changelog_fragment "$generation_dir/base.md" "$generation_dir/fragment.md" "$generation_dir/merged.md"
assert_eq "$(sed -n '3p' "$generation_dir/merged.md")" '## [1.2.3] - 2026-07-15'
assert_eq "$(sed -n '5p' "$generation_dir/merged.md")" '## [1.1.0] - 2026-01-01'
rm -rf "$generation_dir"
unset generation_dir generation_manifest

validated_base=0123456789abcdef0123456789abcdef01234567
parse_release_provenance "$(printf '<!-- release-base:%s -->\n<!-- release-validation-run:42 -->' "$validated_base")"
assert_eq "$RELEASE_BASE_SHA" "$validated_base"
assert_eq "$RELEASE_VALIDATION_RUN_ID" 42
if parse_release_provenance "$(printf '<!-- release-base:%s -->\n<!-- release-base:%s -->\n<!-- release-validation-run:42 -->' "$validated_base" "$validated_base")" 2>/dev/null; then
  fail "duplicate release provenance was accepted"
fi
if parse_release_provenance "$(printf '<!-- release-base:%s -->\nprefix <!-- release-base:%s -->\n<!-- release-validation-run:42 -->' "$validated_base" "$validated_base")" 2>/dev/null; then
  fail "malformed release provenance was accepted"
fi
if parse_release_provenance "$(printf '<!-- release-base:%s -->\n<!-- release-validation-run:0 -->' "$validated_base")" 2>/dev/null; then
  fail "invalid validation run identity was accepted"
fi

RELEASE_APP_SLUG=release-bot
RELEASE_APP_LOGIN='release-bot[bot]'
validate_policy_token_identity
RELEASE_APP_LOGIN='other-release-bot[bot]'
if validate_policy_token_identity >/dev/null 2>&1; then
  fail "mismatched release policy token identity was accepted"
fi
unset RELEASE_APP_LOGIN RELEASE_APP_SLUG

GITHUB_REPOSITORY=test/repository
RELEASE_APP_LOGIN='release-bot[bot]'
open_pr_json="$(jq -nc '{
  user: {login: "release-bot[bot]"},
  state: "open",
  merged: false,
  draft: false,
  base: {ref: "main"},
  head: {ref: "release/next", repo: {full_name: "test/repository"}}
}')"
validate_open_release_pr_envelope 17 "$open_pr_json"
if validate_open_release_pr_envelope 17 "$(jq -c '.draft = true' <<< "$open_pr_json")" >/dev/null 2>&1; then
  fail "draft Release PR was accepted as review-ready"
fi
validate_open_release_pr_envelope 17 "$(jq -c '.draft = true' <<< "$open_pr_json")" true
if validate_open_release_pr_envelope 17 "$(jq -c '.merged = true' <<< "$open_pr_json")" >/dev/null 2>&1; then
  fail "merged Release PR was accepted as open"
fi
if validate_open_release_pr_envelope 17 "$(jq -c 'del(.merged)' <<< "$open_pr_json")" >/dev/null 2>&1; then
  fail "Release PR without a merged state was accepted as open"
fi
if validate_open_release_pr_envelope 17 "$(jq -c '.user.login = "other[bot]"' <<< "$open_pr_json")" >/dev/null 2>&1; then
  fail "Release PR from another App was accepted"
fi
if validate_open_release_pr_envelope 17 "$(jq -c '.head.repo.full_name = "other/repository"' <<< "$open_pr_json")" >/dev/null 2>&1; then
  fail "Release PR from another repository was accepted"
fi
unset open_pr_json RELEASE_APP_LOGIN

GH_TOKEN=release-token
ACTIONS_TOKEN=actions-token
GITHUB_RUN_ID=42
immutable_enabled=true
merge_commit_enabled=false
auto_merge_enabled=false
merge_fields_visible=true
actions_enabled=true
sha_pinning_required=true
default_workflow_permissions=read
workflow_can_approve=false
RELEASE_POLICY_TOKEN=policy-token
gh() {
  if [[ "$1" == api && "$2" == repos/test/repository ]]; then
    [[ "$GH_TOKEN" == policy-token ]] || fail "merge policy did not use the Administration-read token"
    jq -nc --argjson merge "$merge_commit_enabled" --argjson auto "$auto_merge_enabled" \
      --argjson visible "$merge_fields_visible" '{
      allow_auto_merge: $auto,
      allow_squash_merge: true,
      allow_merge_commit: $merge,
      allow_rebase_merge: false,
      delete_branch_on_merge: true,
      squash_merge_commit_title: "PR_TITLE",
      squash_merge_commit_message: "BLANK"
    } | if $visible then . else del(
      .allow_auto_merge,
      .allow_squash_merge,
      .allow_merge_commit,
      .allow_rebase_merge,
      .delete_branch_on_merge,
      .squash_merge_commit_title,
      .squash_merge_commit_message
    ) end'
  elif [[ "$1" == api && "$2" == repos/test/repository/immutable-releases ]]; then
    [[ "$GH_TOKEN" == policy-token ]] || fail "immutable policy did not use the Administration-read token"
    jq -nc --argjson enabled "$immutable_enabled" '{enabled:$enabled}'
  elif [[ "$1" == api && "$2" == repos/test/repository/actions/permissions ]]; then
    [[ "$GH_TOKEN" == policy-token ]] || fail "Actions policy did not use the Administration-read token"
    jq -nc --argjson enabled "$actions_enabled" --argjson pin "$sha_pinning_required" \
      '{enabled:$enabled,allowed_actions:"all",sha_pinning_required:$pin}'
  elif [[ "$1" == api && "$2" == repos/test/repository/actions/permissions/workflow ]]; then
    [[ "$GH_TOKEN" == policy-token ]] || fail "workflow-token policy did not use the Administration-read token"
    jq -nc --arg permission "$default_workflow_permissions" --argjson approve "$workflow_can_approve" \
      '{default_workflow_permissions:$permission,can_approve_pull_request_reviews:$approve}'
  else
    fail "unexpected release-policy API call: $*"
  fi
}
validate_repository_release_policy
merge_fields_visible=false
policy_error="$(mktemp)"
if validate_repository_release_policy >/dev/null 2>"$policy_error"; then
  fail "incomplete merge-policy metadata was accepted"
fi
grep -Fq 'Repository merge settings are unavailable' "$policy_error" ||
  fail "incomplete merge-policy metadata was misreported as a settings conflict"
rm -f "$policy_error"
merge_fields_visible=true
merge_commit_enabled=true
if validate_repository_release_policy >/dev/null 2>&1; then
  fail "merge commits were accepted by the release policy"
fi
merge_commit_enabled=false
auto_merge_enabled=true
if validate_repository_release_policy >/dev/null 2>&1; then
  fail "auto-merge was accepted by the release policy"
fi
auto_merge_enabled=false
immutable_enabled=false
if validate_repository_release_policy >/dev/null 2>&1; then
  fail "disabled immutable Releases were accepted"
fi
immutable_enabled=true
actions_enabled=false
if validate_repository_release_policy >/dev/null 2>&1; then
  fail "disabled Actions were accepted"
fi
actions_enabled=true
sha_pinning_required=false
if validate_repository_release_policy >/dev/null 2>&1; then
  fail "unpinned Actions policy was accepted"
fi
sha_pinning_required=true
default_workflow_permissions=write
if validate_repository_release_policy >/dev/null 2>&1; then
  fail "default write workflow tokens were accepted"
fi
default_workflow_permissions=read
workflow_can_approve=true
if validate_repository_release_policy >/dev/null 2>&1; then
  fail "workflow PR approval permission was accepted"
fi
workflow_can_approve=false
unset RELEASE_POLICY_TOKEN

reviewed_sha=1111111111111111111111111111111111111111
review_mode=approved
reviewer_permission=write
other_permission=write
gh() {
  if [[ "$1" == api && "$2" == --paginate && "$3" == --slurp && "$4" == 'repos/test/repository/pulls/17/reviews?per_page=100' ]]; then
    case "$review_mode" in
    none)
      jq -nc '[[]]'
      ;;
    approved)
      jq -nc --arg sha "$reviewed_sha" '[[{id:1,commit_id:$sha,state:"APPROVED",submitted_at:"2026-07-14T00:00:00Z",user:{login:"reviewer",type:"User"}}]]'
      ;;
    commented)
      jq -nc --arg sha "$reviewed_sha" '[[
        {id:1,commit_id:$sha,state:"APPROVED",submitted_at:"2026-07-14T00:00:00Z",user:{login:"reviewer",type:"User"}},
        {id:2,commit_id:$sha,state:"COMMENTED",submitted_at:"2026-07-14T00:01:00Z",user:{login:"reviewer",type:"User"}}
      ]]'
      ;;
    stale)
      jq -nc '[[{id:1,commit_id:"2222222222222222222222222222222222222222",state:"APPROVED",submitted_at:"2026-07-14T00:00:00Z",user:{login:"reviewer",type:"User"}}]]'
      ;;
    bot)
      jq -nc --arg sha "$reviewed_sha" '[[{id:1,commit_id:$sha,state:"APPROVED",submitted_at:"2026-07-14T00:00:00Z",user:{login:"automation",type:"Bot"}}]]'
      ;;
    changes)
      jq -nc --arg sha "$reviewed_sha" '[[
        {id:1,commit_id:$sha,state:"APPROVED",submitted_at:"2026-07-14T00:00:00Z",user:{login:"reviewer",type:"User"}},
        {id:2,commit_id:$sha,state:"CHANGES_REQUESTED",submitted_at:"2026-07-14T00:01:00Z",user:{login:"other",type:"User"}}
      ]]'
      ;;
    esac
  elif [[ "$1" == api && "$2" == repos/test/repository/collaborators/*/permission ]]; then
    login="${2%/permission}"
    login="${login##*/}"
    permission="$reviewer_permission"
    [[ "$login" == other ]] && permission="$other_permission"
    jq -nc --arg login "$login" --arg permission "$permission" '{permission:$permission,user:{login:$login}}'
  else
    fail "unexpected review API call: $*"
  fi
}
RELEASE_APP_LOGIN=release-bot
validate_release_approval 17 "$reviewed_sha"
reviewer_permission=read
if validate_release_approval 17 "$reviewed_sha" >/dev/null 2>&1; then
  fail "read-only approval accepted"
fi
reviewer_permission=write
review_mode=commented
validate_release_approval 17 "$reviewed_sha"
review_mode=stale
if validate_release_approval 17 "$reviewed_sha" >/dev/null 2>&1; then
  fail "stale approval accepted"
fi
review_mode=bot
if validate_release_approval 17 "$reviewed_sha" >/dev/null 2>&1; then
  fail "bot approval accepted"
fi
review_mode=none
if validate_release_approval 17 "$reviewed_sha" >/dev/null 2>&1; then
  fail "Release PR without approval was accepted"
fi
review_mode=changes
other_permission=read
validate_release_approval 17 "$reviewed_sha"
other_permission=write
if validate_release_approval 17 "$reviewed_sha" >/dev/null 2>&1; then
  fail "active change request accepted"
fi
validate_release_executor 17 "$RELEASE_APP_LOGIN" Bot
if validate_release_executor 17 reviewer User >/dev/null 2>&1; then
  fail "direct human merge was accepted"
fi
if validate_release_executor 17 other-bot Bot >/dev/null 2>&1; then
  fail "merge by an unrelated bot was accepted"
fi

(
  ready_output="$(mktemp)"
  trap 'rm -f "$ready_output"' EXIT
  GITHUB_OUTPUT="$ready_output"
  EXPECTED_HEAD_SHA="$reviewed_sha"
  EXPECTED_FOCUSED_RUN_ID=73
  RELEASE_APP_LOGIN=release-bot
  RELEASE_PR_NUMBER=
  ready_review=approved
  ready_gate=success
  ready_pr="$(jq -nc --arg sha "$reviewed_sha" '{
    number:17,user:{login:"release-bot"},state:"open",merged:false,draft:false,
    base:{ref:"main"},head:{ref:"release/next",sha:$sha,repo:{full_name:"test/repository"}},
    labels:[{name:"release:pending"}]
  }')"
  gh() {
    if [[ "$*" == 'api --paginate --slurp repos/test/repository/pulls?state=open&base=main&per_page=100' ]]; then
      jq -nc --argjson pr "$ready_pr" '[[$pr]]'
    elif [[ "$*" == 'api repos/test/repository/pulls/17' ]]; then
      printf '%s\n' "$ready_pr"
    elif [[ "$*" == 'api --paginate --slurp repos/test/repository/pulls/17/reviews?per_page=100' ]]; then
      if [[ "$ready_review" == approved ]]; then
        jq -nc --arg sha "$reviewed_sha" '[[{id:1,commit_id:$sha,state:"APPROVED",submitted_at:"2026-07-14T00:00:00Z",user:{login:"reviewer",type:"User"}}]]'
      else
        jq -nc '[[]]'
      fi
    elif [[ "$*" == 'api repos/test/repository/collaborators/reviewer/permission' ]]; then
      jq -nc '{permission:"write",user:{login:"reviewer"}}'
    elif [[ "$*" == "api --paginate --slurp repos/test/repository/actions/workflows/ci.yml/runs?event=pull_request&branch=release%2Fnext&head_sha=$reviewed_sha&per_page=100" ]]; then
      if [[ "$ready_gate" == success ]]; then
        jq -nc --arg sha "$reviewed_sha" '[{workflow_runs:[
          {id:73,path:".github/workflows/ci.yml",head_sha:$sha,head_branch:"release/next",event:"pull_request",head_repository:{full_name:"test/repository"},status:"completed",conclusion:"success",run_started_at:"2026-07-14T00:01:00Z"}
        ]}]'
      elif [[ "$ready_gate" == pending ]]; then
        jq -nc --arg sha "$reviewed_sha" '[{workflow_runs:[
          {id:73,path:".github/workflows/ci.yml",head_sha:$sha,head_branch:"release/next",event:"pull_request",head_repository:{full_name:"test/repository"},status:"in_progress",conclusion:null,run_started_at:"2026-07-14T00:01:00Z"}
        ]}]'
      else
        jq -nc --arg sha "$reviewed_sha" '[{workflow_runs:[
          {id:74,path:".github/workflows/ci.yml",head_sha:$sha,head_branch:"release/next",event:"pull_request",head_repository:{full_name:"test/repository"},status:"completed",conclusion:"success",run_started_at:"2026-07-14T00:02:00Z"}
        ]}]'
      fi
    else
      fail "unexpected approval-readiness API call: $*"
    fi
  }
  release_merge_ready
  grep -Fxq 'pr-number=17' "$ready_output" || fail "approval readiness did not resolve its PR"
  [[ "$(grep -Fxc 'ready=true' "$ready_output")" == 1 ]] || fail "approved Release PR was not uniquely ready"
  if grep -Fxq 'ready=false' "$ready_output"; then fail "ready Release PR also emitted a wait state"; fi
  : > "$ready_output"
  ready_review=pending
  release_merge_ready
  [[ "$(grep -Fxc 'ready=false' "$ready_output")" == 1 ]] || fail "pending approval did not emit one clean wait"
  if grep -Fxq 'ready=true' "$ready_output"; then fail "pending approval was also marked ready"; fi
  : > "$ready_output"
  ready_review=approved
  ready_gate=pending
  release_merge_ready
  [[ "$(grep -Fxc 'ready=false' "$ready_output")" == 1 ]] || fail "pending Gate did not emit one clean wait"
  if grep -Fxq 'ready=true' "$ready_output"; then fail "pending Gate was also marked ready"; fi
  : > "$ready_output"
  ready_gate=superseded
  release_merge_ready
  [[ "$(grep -Fxc 'ready=false' "$ready_output")" == 1 ]] || fail "superseded Gate event did not wait"
  if grep -Fxq 'ready=true' "$ready_output"; then fail "superseded Gate event was marked ready"; fi
  : > "$ready_output"
  ready_pr="$(jq '.draft=true' <<< "$ready_pr")"
  release_merge_ready
  [[ "$(grep -Fxc 'ready=false' "$ready_output")" == 1 ]] || fail "draft Release PR did not emit one clean wait"
  if grep -Fxq 'ready=true' "$ready_output"; then fail "draft Release PR was marked ready"; fi
  : > "$ready_output"
  RELEASE_PR_NUMBER=17
  ready_pr="$(jq '.draft=false | .state="closed" | .merged=true' <<< "$ready_pr")"
  release_merge_ready
  [[ "$(grep -Fxc 'ready=false' "$ready_output")" == 1 ]] || fail "completed merge event was not idempotent"
  if grep -Fxq 'ready=true' "$ready_output"; then fail "closed Release PR was marked ready"; fi
)

focused_mode=success
focused_expected_run=73
ACTIONS_TOKEN=actions-token
gh() {
  [[ "$GH_TOKEN" == actions-token && "$1" == api && "$2" == --paginate && "$3" == --slurp &&
     "$4" == "repos/test/repository/actions/workflows/ci.yml/runs?event=pull_request&branch=release%2Fnext&head_sha=$reviewed_sha&per_page=100" ]] ||
    fail "unexpected focused-run API call: $*"
  case "$focused_mode" in
    success)
      jq -nc --arg sha "$reviewed_sha" '[{workflow_runs:[
        {id:72,path:".github/workflows/ci.yml",head_sha:$sha,head_branch:"release/next",event:"pull_request",head_repository:{full_name:"test/repository"},status:"completed",conclusion:"failure",run_started_at:"2026-07-14T00:00:00Z"},
        {id:73,path:".github/workflows/ci.yml",head_sha:$sha,head_branch:"release/next",event:"pull_request",head_repository:{full_name:"test/repository"},status:"completed",conclusion:"success",run_started_at:"2026-07-14T00:01:00Z"}
      ]}]'
      ;;
    latest_skipped)
      jq -nc --arg sha "$reviewed_sha" '[{workflow_runs:[
        {id:73,path:".github/workflows/ci.yml",head_sha:$sha,head_branch:"release/next",event:"pull_request",head_repository:{full_name:"test/repository"},status:"completed",conclusion:"success",run_started_at:"2026-07-14T00:01:00Z"},
        {id:74,path:".github/workflows/ci.yml",head_sha:$sha,head_branch:"release/next",event:"pull_request",head_repository:{full_name:"test/repository"},status:"completed",conclusion:"skipped",run_started_at:"2026-07-14T00:02:00Z"}
      ]}]'
      ;;
    latest_failed)
      jq -nc --arg sha "$reviewed_sha" '[{workflow_runs:[
        {id:73,path:".github/workflows/ci.yml",head_sha:$sha,head_branch:"release/next",event:"pull_request",head_repository:{full_name:"test/repository"},status:"completed",conclusion:"success",run_started_at:"2026-07-14T00:01:00Z"},
        {id:74,path:".github/workflows/ci.yml",head_sha:$sha,head_branch:"release/next",event:"pull_request",head_repository:{full_name:"test/repository"},status:"completed",conclusion:"failure",run_started_at:"2026-07-14T00:02:00Z"}
      ]}]'
      ;;
    latest_pending)
      jq -nc --arg sha "$reviewed_sha" '[{workflow_runs:[
        {id:73,path:".github/workflows/ci.yml",head_sha:$sha,head_branch:"release/next",event:"pull_request",head_repository:{full_name:"test/repository"},status:"completed",conclusion:"success",run_started_at:"2026-07-14T00:01:00Z"},
        {id:74,path:".github/workflows/ci.yml",head_sha:$sha,head_branch:"release/next",event:"pull_request",head_repository:{full_name:"test/repository"},status:"in_progress",conclusion:null,run_started_at:"2026-07-14T00:02:00Z"}
      ]}]'
      ;;
    latest_cancelled)
      jq -nc --arg sha "$reviewed_sha" '[{workflow_runs:[
        {id:73,path:".github/workflows/ci.yml",head_sha:$sha,head_branch:"release/next",event:"pull_request",head_repository:{full_name:"test/repository"},status:"completed",conclusion:"success",run_started_at:"2026-07-14T00:01:00Z"},
        {id:74,path:".github/workflows/ci.yml",head_sha:$sha,head_branch:"release/next",event:"pull_request",head_repository:{full_name:"test/repository"},status:"completed",conclusion:"cancelled",run_started_at:"2026-07-14T00:02:00Z"}
      ]}]'
      ;;
    wrong_repository)
      jq -nc --arg sha "$reviewed_sha" '[{workflow_runs:[
        {id:73,path:".github/workflows/ci.yml",head_sha:$sha,head_branch:"release/next",event:"pull_request",head_repository:{full_name:"other/repository"},status:"completed",conclusion:"success",run_started_at:"2026-07-14T00:01:00Z"}
      ]}]'
      ;;
  esac
}
validate_focused_release_run 17 "$reviewed_sha" "$focused_expected_run"
assert_eq "$RELEASE_FOCUSED_RUN_ID" 73
if validate_focused_release_run 17 "$reviewed_sha" 72 >/dev/null 2>&1; then
  fail "stale focused run was accepted"
fi
focused_mode=latest_skipped
validate_focused_release_run 17 "$reviewed_sha" 73
focused_mode=latest_failed
if validate_focused_release_run 17 "$reviewed_sha" >/dev/null 2>&1; then
  fail "older successful focused run hid the latest failure"
fi
focused_mode=latest_pending
if validate_focused_release_run 17 "$reviewed_sha" >/dev/null 2>&1; then
  fail "older successful focused run hid the latest in-progress attempt"
fi
focused_mode=latest_cancelled
if validate_focused_release_run 17 "$reviewed_sha" >/dev/null 2>&1; then
  fail "older successful focused run hid the latest cancelled attempt"
fi
focused_mode=wrong_repository
if validate_focused_release_run 17 "$reviewed_sha" >/dev/null 2>&1; then
  fail "focused run from another repository was accepted"
fi
unset focused_expected_run focused_mode

(
  expected_head=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  expected_base=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  merged_sha=cccccccccccccccccccccccccccccccccccccccc
  RELEASE_APP_LOGIN=release-bot
  RELEASE_APP_SLUG=release-bot
  RELEASE_PR_NUMBER=17
  EXPECTED_HEAD_SHA="$expected_head"
  EXPECTED_FOCUSED_RUN_ID=73
  validate_repository_release_policy() { :; }
  git_remote() { [[ "$*" == 'fetch --force origin main --tags' ]] || fail "unexpected merge fetch: $*"; }
  git() {
    [[ "$*" == 'rev-parse HEAD' ]] || fail "unexpected merge git call: $*"
    echo "$expected_head"
  }
  validate_release_pr() {
    [[ "$1" == 17 && "$2" == open ]] || fail "automatic merge validated the wrong PR"
    VALIDATED_RELEASE_SHA="$expected_head"
    VALIDATED_RELEASE_VERSION=1.2.3
    RELEASE_BASE_SHA="$expected_base"
    RELEASE_VALIDATION_RUN_ID=81
  }
  validate_focused_release_run() {
    [[ "$1" == 17 && "$2" == "$expected_head" && "$3" == 73 ]] ||
      fail "automatic merge accepted the wrong focused run"
  }
  validate_release_approval() {
    [[ "$1" == 17 && "$2" == "$expected_head" ]] || fail "automatic merge accepted the wrong approval"
  }
  gh() {
    if [[ "$*" == 'api repos/test/repository/pulls/17' ]]; then
      jq -nc --arg app "$RELEASE_APP_LOGIN" --arg base "$expected_base" --arg sha "$expected_head" \
        --arg body "<!-- release-base:$expected_base -->
<!-- release-validation-run:81 -->" '{
        user:{login:$app},state:"open",merged:false,draft:false,title:"chore(release): v1.2.3",
        base:{ref:"main",sha:$base},head:{ref:"release/next",sha:$sha,repo:{full_name:"test/repository"}},
        labels:[{name:"release:pending"}],body:$body
      }'
    elif [[ "$*" == 'api -X PUT repos/test/repository/pulls/17/merge --input -' ]]; then
      merge_payload="$(cat)"
      jq -e --arg sha "$expected_head" '
        .sha == $sha and .merge_method == "squash" and
        .commit_title == "chore(release): v1.2.3" and .commit_message == ""
      ' <<< "$merge_payload" >/dev/null || fail "automatic merge payload changed"
      jq -nc --arg sha "$merged_sha" '{merged:true,sha:$sha}'
    else
      fail "unexpected automatic-merge API call: $*"
    fi
  }
  merge_approved_release >/dev/null
)

proposal_sha=3333333333333333333333333333333333333333
proposal_parent=4444444444444444444444444444444444444444
proposal_title='chore(release): v1.2.3'
proposal_mode=valid
gh() {
  [[ "$1" == api && "$2" == "repos/test/repository/commits/$proposal_sha" ]] ||
    fail "unexpected proposal commit API call: $*"
  case "$proposal_mode" in
    valid)
      jq -nc --arg app "$RELEASE_APP_LOGIN" --arg message "$proposal_title" \
        --arg parent "$proposal_parent" --arg sha "$proposal_sha" \
        '{sha:$sha,author:{login:$app},committer:{login:$app},commit:{message:$message},parents:[{sha:$parent}]}'
      ;;
    author)
      jq -nc --arg app "$RELEASE_APP_LOGIN" --arg message "$proposal_title" \
        --arg parent "$proposal_parent" --arg sha "$proposal_sha" \
        '{sha:$sha,author:{login:"user"},committer:{login:$app},commit:{message:$message},parents:[{sha:$parent}]}'
      ;;
    committer)
      jq -nc --arg app "$RELEASE_APP_LOGIN" --arg message "$proposal_title" \
        --arg parent "$proposal_parent" --arg sha "$proposal_sha" \
        '{sha:$sha,author:{login:$app},committer:{login:"user"},commit:{message:$message},parents:[{sha:$parent}]}'
      ;;
    message)
      jq -nc --arg app "$RELEASE_APP_LOGIN" --arg parent "$proposal_parent" --arg sha "$proposal_sha" \
        '{sha:$sha,author:{login:$app},committer:{login:$app},commit:{message:"chore(release): v9.9.9"},parents:[{sha:$parent}]}'
      ;;
    noncanonical)
      jq -nc --arg app "$RELEASE_APP_LOGIN" --arg parent "$proposal_parent" --arg sha "$proposal_sha" \
        '{sha:$sha,author:{login:$app},committer:{login:$app},commit:{message:"release 1.2.3"},parents:[{sha:$parent}]}'
      ;;
    parents)
      jq -nc --arg app "$RELEASE_APP_LOGIN" --arg message "$proposal_title" \
        --arg parent "$proposal_parent" --arg sha "$proposal_sha" \
        '{sha:$sha,author:{login:$app},committer:{login:$app},commit:{message:$message},parents:[{sha:$parent},{sha:"5555555555555555555555555555555555555555"}]}'
      ;;
  esac
}
validate_release_proposal_commit "$proposal_sha" "$proposal_title" "$proposal_parent"
assert_eq "$RELEASE_PROPOSAL_PARENT" "$proposal_parent"
assert_eq "$RELEASE_PROPOSAL_VERSION" 1.2.3
validate_release_proposal_commit "$proposal_sha"
assert_eq "$RELEASE_PROPOSAL_TITLE" "$proposal_title"
proposal_mode=author
if validate_release_proposal_commit "$proposal_sha" "$proposal_title" "$proposal_parent" >/dev/null 2>&1; then
  fail "proposal commit from an untrusted author was accepted"
fi
proposal_mode=committer
if validate_release_proposal_commit "$proposal_sha" "$proposal_title" "$proposal_parent" >/dev/null 2>&1; then
  fail "proposal commit from an untrusted committer was accepted"
fi
proposal_mode=message
if validate_release_proposal_commit "$proposal_sha" "$proposal_title" "$proposal_parent" >/dev/null 2>&1; then
  fail "proposal commit with another message was accepted"
fi
proposal_mode=noncanonical
if validate_release_proposal_commit "$proposal_sha" >/dev/null 2>&1; then
  fail "proposal commit with a non-canonical message was accepted"
fi
proposal_mode=parents
if validate_release_proposal_commit "$proposal_sha" "$proposal_title" "$proposal_parent" >/dev/null 2>&1; then
  fail "multi-parent proposal commit was accepted"
fi
unset proposal_mode proposal_parent proposal_sha proposal_title

validation_status=completed
validation_conclusion=success
validation_sha="$validated_base"
gh() {
  [[ "$GH_TOKEN" == actions-token && "$1" == api && "$2" == repos/test/repository/actions/runs/42 ]] ||
    fail "unexpected validation-run API call: $*"
  jq -nc --arg sha "$validation_sha" --arg status "$validation_status" --arg conclusion "$validation_conclusion" '{
    id: 42,
    head_sha: $sha,
    head_branch: "main",
    event: "push",
    path: ".github/workflows/main.yml",
    status: $status,
    conclusion: $conclusion
  }'
}
validate_validation_run "$validated_base" 42
validation_sha=ffffffffffffffffffffffffffffffffffffffff
if validate_validation_run "$validated_base" 42 >/dev/null 2>&1; then
  fail "validation run for another commit was accepted"
fi
validation_sha="$validated_base"
validation_status=in_progress
validation_conclusion=
validate_validation_run "$validated_base" 42 true
if validate_validation_run "$validated_base" 42 >/dev/null 2>&1; then
  fail "unfinished historical validation run was accepted"
fi
GITHUB_ACTIONS=true
sleep() {
  [[ "$1" == 3 ]] || fail "validation polling used an unexpected delay"
  validation_status=completed
  validation_conclusion=success
}
validate_validation_run "$validated_base" 42
unset -f sleep
unset GITHUB_ACTIONS
git() {
  [[ "$*" == "rev-parse origin/main" ]] || fail "unexpected provenance git call: $*"
  echo "$validated_base"
}
VERIFIED_SHA="$validated_base"
VALIDATION_RUN_ID=42
resolve_validation_provenance
assert_eq "$RELEASE_VALIDATED_SHA" "$validated_base"
validation_sha=ffffffffffffffffffffffffffffffffffffffff
if resolve_validation_provenance >/dev/null 2>&1; then
  fail "failed validation run was converted into successful provenance"
fi
unset VERIFIED_SHA VALIDATION_RUN_ID
unset ACTIONS_TOKEN GITHUB_RUN_ID

test_dir="$(mktemp -d)"
trap 'rm -rf "$test_dir"' EXIT
changelog="$test_dir/CHANGELOG.md"
changelog_base=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
changelog_timestamp="$(jq -nr '"2026-07-14T00:00:00Z" | fromdateiso8601')"
git() {
  if [[ "$#" == 2 && "$1" == show && "$2" == "$changelog_base:CHANGELOG.md" ]]; then
    printf '# Changelog\n\nProduct history.\n'
  elif [[ "$#" == 5 && "$1 $2 $3 $4 $5" == "cliff --tag v1.2.3 --context $changelog_base" ]]; then
    jq -nc '[{version:"v1.2.3",timestamp:1,commits:[]}]'
  elif [[ "$#" == 7 && "$1" == cliff && "$2" == --from-context &&
          "$4 $5 $6" == '--strip header --output' ]]; then
    jq -e --argjson timestamp "$changelog_timestamp" '
      length == 1 and .[0].version == "v1.2.3" and .[0].timestamp == $timestamp
    ' "$3" >/dev/null || fail "changelog context was not normalized"
    printf '## [1.2.3] - 2026-07-14\n' > "$7"
  else
    fail "unexpected changelog generation call: $*"
  fi
}
printf '# Changelog\n\nProduct history.\n' > "$changelog"
if generate_changelog 1.2.3 "$changelog" HEAD "$changelog_timestamp" 2>/dev/null; then
  fail "symbolic changelog base was accepted"
fi
generate_changelog 1.2.3 "$changelog" "$changelog_base" "$changelog_timestamp"
[[ "$(head -n 1 "$changelog")" == "# Changelog" ]] || fail "release section was inserted before the document header"
(
  before="$test_dir/changelog-before-reused-version.md"
  cp "$changelog" "$before"
  committed_release_baseline() { printf '1.2.3\t%s\n' "$changelog_base"; }
  git() { fail "reused release version reached git-cliff: $*"; }
  if generate_changelog 1.2.3 "$changelog" "$changelog_base" "$changelog_timestamp" 2>/dev/null; then
    fail "recorded release version was reused"
  fi
  cmp -s "$before" "$changelog" || fail "reused release version changed the Changelog"
)
(
  before="$test_dir/changelog-before-failed-validation.md"
  cp "$changelog" "$before"
  committed_release_baseline() { return 0; }
  validate_generated_changelog() { return 1; }
  if generate_changelog 1.2.3 "$changelog" "$changelog_base" "$changelog_timestamp" 2>/dev/null; then
    fail "failed generated Changelog validation was ignored"
  fi
  cmp -s "$before" "$changelog" || fail "failed generated Changelog validation changed the destination"
)
printf '# Changelog\n\n# Changelog\n\n## [1.2.3] - 2026-07-14\n' > "$changelog"
if validate_generated_changelog 1.2.3 "$changelog" 2>/dev/null; then
  fail "duplicate changelog headers accepted"
fi
printf '# Changelog\n\n## [1.2.3] - 2026-07-14\n## [1.2.3] - 2026-07-14\n' > "$changelog"
if validate_generated_changelog 1.2.3 "$changelog" 2>/dev/null; then
  fail "duplicate release sections accepted"
fi
unset changelog_base changelog_timestamp

(
  fixture_baseline_sha=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  git() {
    case "$1" in
      show)
        [[ "$2" == "HEAD:CHANGELOG.md" ]] || fail "release baseline read the wrong tree"
        printf '# Changelog\n\n## [1.2.3] - 2026-07-14\n'
        ;;
      log)
        echo "$fixture_baseline_sha"
        ;;
      merge-base)
        [[ "$2" == --is-ancestor && "$3" == "$fixture_baseline_sha" && "$4" == HEAD ]] ||
          fail "release baseline checked the wrong ancestry"
        ;;
      *) fail "unexpected release baseline git call: $*" ;;
    esac
  }
  assert_eq "$(committed_release_baseline HEAD)" $'1.2.3\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
)

(
  fixture_baseline_sha=cccccccccccccccccccccccccccccccccccccccc
  fixture_target_sha=dddddddddddddddddddddddddddddddddddddddd
  operations="$test_dir/synthetic-release-tag-operations"
  committed_release_baseline() {
    [[ "$1" == "$fixture_target_sha" ]] || fail "automatic version used the wrong target"
    printf '1.2.3\t%s\n' "$fixture_baseline_sha"
  }
  git() {
    case "$1" in
      rev-parse)
        if [[ "$2" == --verify && "$3" == 'HEAD^{commit}' ]]; then
          echo "$fixture_target_sha"
        else
          return 1
        fi
        ;;
      update-ref)
        if [[ "$#" == 4 && "$2" == refs/tags/v1.2.3 && "$3" == "$fixture_baseline_sha" && -z "$4" ]]; then
          echo create >> "$operations"
        elif [[ "$#" == 4 && "$2" == -d && "$3" == refs/tags/v1.2.3 && "$4" == "$fixture_baseline_sha" ]]; then
          echo delete >> "$operations"
        else
          fail "unexpected synthetic tag mutation: $*"
        fi
        ;;
      cliff)
        [[ "$2" == --bumped-version && "$3" == "refs/tags/v1.2.3..$fixture_target_sha" ]] ||
          fail "release baseline bumped the wrong history"
        echo v1.2.4
        ;;
      *) fail "unexpected automatic version git call: $*" ;;
    esac
  }
  assert_eq "$(automatic_release_version HEAD)" v1.2.4
  grep -Fxq create "$operations" ||
    fail "automatic version did not create the consumed-version baseline"
  grep -Fxq delete "$operations" ||
    fail "automatic version did not remove the consumed-version baseline"
)

(
  fixture_baseline_sha=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
  fixture_target_sha=ffffffffffffffffffffffffffffffffffffffff
  fixture_tag_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  committed_release_baseline() { printf '1.2.3\t%s\n' "$fixture_baseline_sha"; }
  git() {
    if [[ "$1 $2 $3" == 'rev-parse --verify HEAD^{commit}' ]]; then
      echo "$fixture_target_sha"
    elif [[ "$1 $2 $3" == 'rev-parse --verify refs/tags/v1.2.3^{commit}' ]]; then
      echo "$fixture_tag_sha"
    else
      fail "tag conflict reached an unexpected git operation: $*"
    fi
  }
  if automatic_release_version HEAD >/dev/null 2>&1; then
    fail "a release tag at the wrong commit was accepted"
  fi
)

record="$(printf '%s' '[[{"id":42,"draft":true,"target_commitish":"abc","tag_name":"v1.0.0"}]]' | parse_release_record v1.0.0)"
assert_eq "$record" $'42\ttrue\tabc'
record="$(printf '%s' '[[{"id":42,"draft":true,"target_commitish":"abc","tag_name":"v1.0.0"}]]' | parse_release_record v2.0.0)"
assert_eq "$record" ""
if printf '%s' '[[{"id":1,"draft":true,"target_commitish":"abc","tag_name":"v1.0.0"},{"id":2,"draft":true,"target_commitish":"abc","tag_name":"v1.0.0"}]]' |
  parse_release_record v1.0.0 >/dev/null 2>&1; then
  fail "duplicate release records accepted"
fi
managed="$(printf '%s' '[[{"id":42,"draft":true,"target_commitish":"abc","tag_name":"v1.0.0"}]]' | parse_managed_release v1.0.0)"
assert_eq "$(jq -r .id <<< "$managed")" 42
if printf '%s' '[[]]' | parse_managed_release v1.0.0 >/dev/null 2>&1; then
  fail "missing managed Release accepted"
fi
if printf '%s' '[[{"id":1,"tag_name":"v1.0.0"},{"id":2,"tag_name":"v1.0.0"}]]' |
  parse_managed_release v1.0.0 >/dev/null 2>&1; then
  fail "duplicate managed Releases accepted"
fi

assert_eq "$(release_transition abc "" "" "" "")" create
assert_eq "$(release_transition abc abc "" "" "")" create-release
assert_eq "$(release_transition abc "" 42 true abc)" create-tag
assert_eq "$(release_transition abc abc 42 true abc)" prepared
assert_eq "$(release_transition abc abc 42 false abc)" published
assert_eq "$(release_transition abc def "" "" "")" conflict
assert_eq "$(release_transition abc abc 42 true def)" conflict
assert_eq "$(release_transition abc "" 42 false abc)" conflict

(
  expected_release_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  release_exists=false
  release_visibility_delay=0
  tag_exists=false
  create_count=0
  tag_push_count=0
  sleep_count=0
  GITHUB_ACTIONS=true
  RUNNER_TEMP="$test_dir"

  load_release_state() {
    [[ "$1" == v1.2.3 ]] || fail "release reconciliation loaded the wrong tag"
    RELEASE_TAG_SHA=""
    RELEASE_ID=""
    RELEASE_DRAFT=""
    RELEASE_TARGET=""
    if [[ "$tag_exists" == true ]]; then
      RELEASE_TAG_SHA="$expected_release_sha"
    fi
    if [[ "$release_exists" == true ]]; then
      if ((release_visibility_delay > 0)); then
        release_visibility_delay=$((release_visibility_delay - 1))
      else
        RELEASE_ID=42
        RELEASE_DRAFT=true
        RELEASE_TARGET="$expected_release_sha"
      fi
    fi
  }
  sleep() {
    [[ "$1" == 3 ]] || fail "release reconciliation used an unexpected delay"
    ((sleep_count += 1))
  }
  git_remote() {
    case "$1" in
      fetch) return 0 ;;
      push)
        [[ "$2" == origin && "$3" == "$expected_release_sha:refs/tags/v1.2.3" ]] ||
          fail "release reconciliation pushed the wrong tag"
        [[ "$release_exists" == true ]] || fail "release tag was pushed before the draft Release existed"
        tag_exists=true
        ((tag_push_count += 1))
        ;;
      *) fail "unexpected release reconciliation git call: $*" ;;
    esac
  }
  write_release_notes() {
    [[ "$1" == 1.2.3 && "$2" == 17 && "$3" == "$expected_release_sha" ]] ||
      fail "release reconciliation generated notes for the wrong release"
  }
  gh() {
    if [[ "$1" == release && "$2" == create && "$3" == v1.2.3 ]]; then
      [[ "$release_exists" == false ]] || fail "draft Release creation was repeated"
      release_exists=true
      release_visibility_delay=2
      ((create_count += 1))
    elif [[ "$1" == api && "$2" == repos/test/repository/releases/42 ]]; then
      printf '{}\n'
    else
      fail "unexpected release reconciliation API call: $*"
    fi
  }
  validate_managed_release_metadata() {
    [[ "$2" == 1.2.3 && "$3" == "$expected_release_sha" && "$4" == 17 ]] ||
      fail "release reconciliation validated the wrong release"
    MANAGED_RELEASE_ID=42
    MANAGED_RELEASE_COMPLETE=false
  }

  ensure_release 17 "$expected_release_sha" 1.2.3 >/dev/null
  assert_eq "$RELEASE_STATE" prepared
  assert_eq "$create_count" 1
  assert_eq "$tag_push_count" 1
  assert_eq "$sleep_count" 2
  ensure_release 17 "$expected_release_sha" 1.2.3 >/dev/null
  assert_eq "$create_count" 1
  assert_eq "$tag_push_count" 1
  assert_eq "$sleep_count" 2
)

(
  expected_release_sha=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  create_count=0
  GITHUB_ACTIONS=true
  RUNNER_TEMP="$test_dir"

  load_release_state() {
    RELEASE_TAG_SHA=""
    RELEASE_ID=""
    RELEASE_DRAFT=""
    RELEASE_TARGET=""
  }
  git_remote() {
    [[ "$1" == fetch ]] || fail "non-converging release attempted another mutation"
  }
  write_release_notes() { return 0; }
  gh() {
    [[ "$1" == release && "$2" == create ]] || fail "non-converging release used an unexpected API"
    ((create_count += 1))
  }
  sleep() {
    [[ "$1" == 3 ]] || fail "release reconciliation used an unexpected delay"
  }

  if ensure_release 18 "$expected_release_sha" 1.2.4 >/dev/null 2>&1; then
    fail "non-converging Release state was accepted"
  fi
  assert_eq "$create_count" 1
)

gh() { return 22; }
if release_record v1.0.0 >/dev/null 2>&1; then
  fail "release API failure was treated as an absent release"
fi
if load_release_state v1.0.0 >/dev/null 2>&1; then
  fail "release API failure was converted into an empty release state"
fi

GITHUB_REPOSITORY=test/repository
main_release_sha=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
git() {
  [[ "$*" == 'rev-parse origin/main' ]] || fail "unexpected candidate git call: $*"
  echo "$main_release_sha"
}
gh() {
  if [[ "$*" == 'api --paginate --slurp -X GET repos/test/repository/pulls -f state=closed -f base=main -f head=test:release/next -F per_page=100' ]]; then
    jq -nc --arg sha "$main_release_sha" '[[{
      number:14,merged_at:"2026-07-15T00:00:00Z",merge_commit_sha:$sha,
      state:"closed",labels:[{name:"release:pending"}],
      base:{ref:"main"},head:{ref:"release/next",repo:{full_name:"test/repository"}}
    },{
      number:15,merged_at:null,merge_commit_sha:null,state:"closed",labels:[{name:"release:pending"}],
      base:{ref:"main"},head:{ref:"release/next",repo:{full_name:"test/repository"}}
    }]]'
  else
    fail "unexpected candidate gh call: $*"
  fi
}
assert_eq "$(managed_release_pr_records | jq -r 'length')" 1
assert_eq "$(merged_release_pr_candidates)" 14
assert_eq "$(resolve_merged_release_pr "$main_release_sha")" 14
if resolve_merged_release_pr aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa >/dev/null 2>&1; then
  fail "unrelated main commit resolved to a managed Release PR"
fi
gh() {
  [[ "$*" == 'api --paginate --slurp -X GET repos/test/repository/pulls -f state=closed -f base=main -f head=test:release/next -F per_page=100' ]] ||
    fail "unexpected malformed candidate gh call: $*"
  echo '{}'
}
if managed_release_pr_records >/dev/null 2>&1; then
  fail "invalid merged Release PR page metadata was accepted"
fi

(
  resolution_counter="$test_dir/merged-release-resolution-count"
  printf '0\n' > "$resolution_counter"
  GITHUB_ACTIONS=true
  managed_release_pr_records() {
    local count
    count="$(<"$resolution_counter")"
    ((count += 1))
    printf '%s\n' "$count" > "$resolution_counter"
    if ((count < 3)); then
      echo '[]'
    else
      jq -nc --arg sha "$main_release_sha" '[{number:14,mergedAt:"2026-07-15T00:00:00Z",mergeSha:$sha}]'
    fi
  }
  sleep() { [[ "$1" == 3 ]] || fail "merged PR resolution used an unexpected delay"; }
  assert_eq "$(resolve_merged_release_pr "$main_release_sha")" 14
  assert_eq "$(<"$resolution_counter")" 3
)

(
  GITHUB_ACTIONS=false
  managed_release_pr_records() {
    jq -nc --arg sha "$main_release_sha" '[
      {number:14,mergedAt:"2026-07-15T00:00:00Z",mergeSha:$sha},
      {number:15,mergedAt:"2026-07-15T00:01:00Z",mergeSha:$sha}
    ]'
  }
  if resolve_merged_release_pr "$main_release_sha" >/dev/null 2>&1; then
    fail "ambiguous merged Release PR identity was accepted"
  fi
)
unset main_release_sha

merged_release_pr_candidates() { echo 14; }
pending_label_present=true
gh() {
  if [[ "$1" == pr && "$2" == list ]]; then
    echo 14
  elif [[ "$1" == api && "$2" == */pulls/14 ]]; then
    if [[ "$pending_label_present" == true ]]; then
      jq -nc '{merge_commit_sha:"old-release-sha",labels:[{name:"release:pending"}]}'
    else
      jq -nc '{merge_commit_sha:"old-release-sha",labels:[]}'
    fi
  else
    fail "unexpected gh call: $*"
  fi
}
git() {
  case "$1" in merge-base|checkout) return 0 ;; *) fail "unexpected git call: $*" ;; esac
}
validate_release_pr() {
  [[ "$1" == 14 && "$2" == merged ]] || fail "pending PR was not validated as merged"
  VALIDATED_PR_NUMBER=14
  VALIDATED_RELEASE_SHA=old-release-sha
  VALIDATED_RELEASE_VERSION=1.0.0
}
ensure_release() {
  [[ "$1" == 14 && "$2" == old-release-sha && "$3" == 1.0.0 ]] || fail "pending release identity changed"
  RELEASE_STATE=prepared
}
remove_pending_label() { fail "prepared release was marked complete"; }
recover_pending_releases
assert_eq "$RECOVERY_STATE" prepared

ensure_release() {
  RELEASE_STATE=published
  MANAGED_RELEASE_COMPLETE=false
}
recover_pending_releases 2>/dev/null
assert_eq "$RECOVERY_STATE" incomplete

completion_cleanup=false
ensure_release() {
  RELEASE_STATE=published
  MANAGED_RELEASE_COMPLETE=true
}
remove_pending_label() {
  [[ "$1" == 14 ]] || fail "completed recovery removed the wrong pending label"
  completion_cleanup=true
}
recover_pending_releases
assert_eq "$RECOVERY_STATE" none
assert_eq "$completion_cleanup" true

pending_label_present=false
recovery_touched=false
git() { recovery_touched=true; fail "stale search result reached Git recovery"; }
validate_release_pr() { recovery_touched=true; fail "stale search result reached PR validation"; }
ensure_release() { recovery_touched=true; fail "stale search result reached Release recovery"; }
recover_pending_releases
assert_eq "$RECOVERY_STATE" none
assert_eq "$recovery_touched" false

merged_release_pr_candidates() { printf '14\n15\n'; }
gh() {
  if [[ "$1" == api && ( "$2" == */pulls/14 || "$2" == */pulls/15 ) ]]; then
    jq -nc '{labels:[{name:"release:pending"}]}'
  else
    fail "unexpected multiple-pending gh call: $*"
  fi
}
if recover_pending_releases >/dev/null 2>&1; then
  fail "multiple pending Release PRs were accepted"
fi

release_body_mode=valid
mock_release_author='release-bot[bot]'
GITHUB_OUTPUT="$(mktemp)"
RELEASE_APP_LOGIN='release-bot[bot]'
RELEASE_APP_SLUG=release-bot
RELEASE_POLICY_TOKEN=policy-token
RELEASE_SHA=release-sha
RELEASE_TAG=v1.2.3
cargo_version() { echo 1.2.3; }
git() {
  case "$1" in
    fetch|merge-base) return 0 ;;
    rev-parse|rev-list) echo release-sha ;;
    *) fail "unexpected publish-validation git call: $*" ;;
  esac
}
gh() {
  if [[ "$1" == api && "$2" == repos/test/repository ]]; then
    [[ "$GH_TOKEN" == policy-token ]] || fail "release policy did not use the App token"
    jq -nc '{allow_auto_merge:false,allow_squash_merge:true,allow_merge_commit:false,allow_rebase_merge:false,delete_branch_on_merge:true,squash_merge_commit_title:"PR_TITLE",squash_merge_commit_message:"BLANK"}'
  elif [[ "$1" == api && "$2" == repos/test/repository/immutable-releases ]]; then
    [[ "$GH_TOKEN" == policy-token ]] || fail "immutable policy did not use the App token"
    jq -nc '{enabled:true}'
  elif [[ "$1" == api && "$2" == repos/test/repository/actions/permissions ]]; then
    [[ "$GH_TOKEN" == policy-token ]] || fail "Actions policy did not use the App token"
    jq -nc '{enabled:true,allowed_actions:"all",sha_pinning_required:true}'
  elif [[ "$1" == api && "$2" == repos/test/repository/actions/permissions/workflow ]]; then
    [[ "$GH_TOKEN" == policy-token ]] || fail "workflow policy did not use the App token"
    jq -nc '{default_workflow_permissions:"read",can_approve_pull_request_reviews:false}'
  elif [[ "$1" == api && "$2" == --paginate && "$3" == --slurp &&
          "$4" == 'repos/test/repository/releases?per_page=100' ]]; then
    [[ "$GH_TOKEN" == policy-token ]] || fail "draft Release lookup did not use the App token"
    body=$'## [1.2.3] - 2026-07-14\n\n<!-- release-pr:17 -->\n<!-- release-commit:release-sha -->'
    if [[ "$release_body_mode" == duplicate ]]; then
      body+=$'\n<!-- release-commit:release-sha -->'
    elif [[ "$release_body_mode" == malformed ]]; then
      body+=$'\nprefix <!-- release-commit:release-sha -->'
    fi
    jq -nc --arg author "$mock_release_author" --arg body "$body" \
      '[[{id:42,draft:true,immutable:false,target_commitish:"release-sha",tag_name:"v1.2.3",name:"Camellia Nexus Management Server 1.2.3",author:{login:$author},body:$body}]]'
  else
    fail "unexpected publish-validation gh call: $*"
  fi
}
validate_release_pr() {
  [[ "$1" == 17 && "$2" == merged ]] || fail "publish validation used the wrong Release PR"
  [[ "${5:-}" == required ]] || fail "incomplete publication did not require the pending label"
  VALIDATED_PR_NUMBER=17
  VALIDATED_RELEASE_SHA=release-sha
  VALIDATED_RELEASE_VERSION=1.2.3
  RELEASE_VALIDATION_RUN_ID=4242
}
validate_publish_release 1.2.3
grep -Fxq 'release-id=42' "$GITHUB_OUTPUT" || fail "publish validation did not expose the Release identity"
grep -Fxq 'release-draft=true' "$GITHUB_OUTPUT" || fail "publish validation did not expose the draft state"
grep -Fxq 'validation-run-id=4242' "$GITHUB_OUTPUT" ||
  fail "publish validation did not expose the exact CI run"
RELEASE_APP_SLUG=other-release-bot
if validate_publish_release 1.2.3 >/dev/null 2>&1; then
  fail "publish validation accepted a mismatched App identity"
fi
RELEASE_APP_SLUG=release-bot
grep -Fxq 'release-digest=' "$GITHUB_OUTPUT" || fail "draft publication exposed a container digest"
release_body_mode=duplicate
if validate_publish_release 1.2.3 >/dev/null 2>&1; then
  fail "duplicate managed release markers were accepted"
fi
release_body_mode=malformed
if validate_publish_release 1.2.3 >/dev/null 2>&1; then
  fail "malformed managed release markers were accepted"
fi
release_body_mode=valid
mock_release_author=untrusted-user
if validate_publish_release 1.2.3 >/dev/null 2>&1; then
  fail "Release created outside the release App was accepted"
fi
mock_release_author='release-bot[bot]'
managed_release_json="$(managed_release v1.2.3)"
if validate_managed_release_metadata "$managed_release_json" 1.2.3 release-sha 18 >/dev/null 2>&1; then
  fail "Release Manager accepted metadata belonging to another Release PR"
fi
malformed_digest_json="$(jq -c '.body += "\nprefix <!-- container-digest:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb -->"' <<< "$managed_release_json")"
if validate_managed_release_metadata "$malformed_digest_json" 1.2.3 release-sha 17 >/dev/null 2>&1; then
  fail "Malformed container digest metadata was accepted"
fi
completion_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
container_digest=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
completion_body="$(printf '<!-- release-pr:17 -->\n<!-- release-commit:%s -->\n<!-- container-digest:%s -->\n<!-- release-complete:%s -->' \
  "$completion_sha" "$container_digest" "$completion_sha")"
completion_json="$(jq -nc --arg body "$completion_body" --arg sha "$completion_sha" \
  '{id:42,draft:false,immutable:true,target_commitish:$sha,tag_name:"v1.2.3",name:"Camellia Nexus Management Server 1.2.3",author:{login:"release-bot[bot]"},body:$body}')"
validate_managed_release_metadata "$completion_json" 1.2.3 "$completion_sha" 17
assert_eq "$MANAGED_RELEASE_COMPLETE" true
assert_eq "$MANAGED_RELEASE_CONTAINER_DIGEST" "$container_digest"
if validate_managed_release_metadata "$(jq -c '.body |= gsub("\\n<!-- container-digest:[^\\n]+ -->"; "")' <<< "$completion_json")" 1.2.3 "$completion_sha" 17 >/dev/null 2>&1; then
  fail "Published Release without a container digest was accepted"
fi
if validate_managed_release_metadata "$(jq -c '.immutable = false' <<< "$completion_json")" 1.2.3 "$completion_sha" 17 >/dev/null 2>&1; then
  fail "Published mutable Release was accepted"
fi
if validate_managed_release_metadata "$(jq -c '.draft = true' <<< "$completion_json")" 1.2.3 "$completion_sha" 17 >/dev/null 2>&1; then
  fail "Draft Release completion proof was accepted"
fi
completion_json="$(jq -c --arg marker "<!-- release-complete:$completion_sha -->" '.body += "\n" + $marker' <<< "$completion_json")"
if validate_managed_release_metadata "$completion_json" 1.2.3 "$completion_sha" 17 >/dev/null 2>&1; then
  fail "Duplicate release completion proof was accepted"
fi

completion_state="$test_dir/server-release.json"
jq --arg digest "$container_digest" --arg sha "$completion_sha" \
  '.body = ("<!-- release-pr:17 -->\n<!-- release-commit:" + $sha + " -->\n<!-- container-digest:" + $digest + " -->")' \
  <<< "$completion_json" > "$completion_state"
RELEASE_SHA="$completion_sha"
validate_publish_release() {
  MANAGED_RELEASE_ID=42
  MANAGED_RELEASE_PR_NUMBER=17
}
completion_label_removed=false
remove_pending_label() {
  [[ "$1" == 17 ]] || fail "publication completed the wrong Release PR"
  completion_label_removed=true
}
gh() {
  if [[ "$*" == "api repos/test/repository/releases/42" ]]; then
    cat "$completion_state"
  elif [[ "$*" == "api -X PATCH repos/test/repository/releases/42 --input -" ]]; then
    payload="$(cat)"
    jq --arg body "$(jq -r .body <<< "$payload")" '.body = $body' "$completion_state" > "$completion_state.next"
    mv "$completion_state.next" "$completion_state"
  else
    fail "unexpected completion-proof gh call: $*"
  fi
}
mark_publish_complete 1.2.3
assert_eq "$completion_label_removed" true
[[ "$(jq -r .body "$completion_state" | grep -Fxc "<!-- release-complete:$completion_sha -->" || true)" == 1 ]] ||
  fail "Publication completion proof was not recorded exactly once"

latest_selected=
gh() {
  if [[ "$*" == "api repos/test/repository/releases/42" ]]; then
    cat "$completion_state"
  elif [[ "$1" == api && "$2" == --paginate && "$3" == --slurp &&
          "$4" == 'repos/test/repository/releases?per_page=100' ]]; then
    jq -nc --arg current "$completion_sha" --arg current_digest "$container_digest" '
      [[
        {
          draft:false, immutable:true, tag_name:"v1.2.3",
          target_commitish:$current,
          body:(
            "<!-- release-complete:" + $current + " -->\n" +
            "<!-- container-digest:" + $current_digest + " -->"
          )
        },
        {
          draft:false, immutable:true, tag_name:"v1.10.0",
          target_commitish:"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          body:(
            "<!-- release-complete:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb -->\n" +
            "<!-- container-digest:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc -->"
          )
        },
        {
          draft:false, immutable:true, tag_name:"v2.0.0",
          target_commitish:"dddddddddddddddddddddddddddddddddddddddd",
          body:"publication is incomplete"
        }
      ]]'
  elif [[ "$*" == "release edit v1.10.0 --repo test/repository --latest" ]]; then
    latest_selected=v1.10.0
  elif [[ "$*" == "api repos/test/repository/releases/latest --jq .tag_name // empty" ]]; then
    printf '%s\n' "$latest_selected"
  else
    fail "unexpected latest-reconciliation gh call: $*"
  fi
}
reconcile_latest_release 1.2.3
assert_eq "$latest_selected" v1.10.0
grep -Fxq 'latest-digest=sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' "$GITHUB_OUTPUT" ||
  fail "latest reconciliation did not expose the selected image digest"
grep -Fxq 'owns-latest=false' "$GITHUB_OUTPUT" ||
  fail "older release incorrectly claimed latest ownership"
rm -f "$GITHUB_OUTPUT"

echo "Release manager state tests passed"
