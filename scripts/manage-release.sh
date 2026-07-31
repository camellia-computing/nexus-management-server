#!/usr/bin/env bash
set -euo pipefail

branch=release/next
lock_label=release:version-locked
pending_label=release:pending
release_ci_path=.github/workflows/ci.yml
release_title_prefix="Camellia Nexus Management Server"

valid_version() {
  [[ "$1" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
}

decimal_le() {
  local value="$1" limit="$2"
  ((${#value} < ${#limit})) || { ((${#value} == ${#limit})) && [[ "$value" < "$limit" || "$value" == "$limit" ]]; }
}

valid_product_version() {
  local major minor patch limit
  valid_version "$1" || return 1
  ((${#1} <= 127)) || return 1
  IFS=. read -r major minor patch <<< "$1"
  limit=18446744073709551615
  decimal_le "$major" "$limit" &&
    decimal_le "$minor" "$limit" &&
    decimal_le "$patch" "$limit"
}

version_ge() {
  local left_part right_part index
  local -a left right
  IFS=. read -r -a left <<< "$1"
  IFS=. read -r -a right <<< "$2"
  for index in 0 1 2; do
    left_part="${left[$index]}"
    right_part="${right[$index]}"
    if ((${#left_part} != ${#right_part})); then
      ((${#left_part} > ${#right_part}))
      return
    fi
    if [[ "$left_part" != "$right_part" ]]; then
      [[ "$left_part" > "$right_part" ]]
      return
    fi
  done
  return 0
}

release_version_allowed() {
  local version="$1" minimum="$2" locked="$3"
  if [[ "$locked" == true ]]; then
    version_ge "$version" "$minimum"
  else
    [[ "$version" == "$minimum" ]]
  fi
}

cargo_version() {
  local package_id
  package_id="$(cargo pkgid --locked -p camellia-nexus-management-server)" || return 1
  printf '%s\n' "${package_id##*@}"
}

committed_release_baseline() {
  local treeish="${1:-HEAD}" path="${2:-CHANGELOG.md}"
  local changelog version marker baseline_sha

  changelog="$(git show "$treeish:$path")" || {
    echo "Unable to read $path at $treeish" >&2
    return 1
  }
  version="$(sed -n 's/^## \[\([^]]*\)\] - [0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}$/\1/p' <<< "$changelog" | head -n 1)" || return 1
  [[ -n "$version" ]] || return 0
  valid_product_version "$version" || {
    echo "$path contains an invalid latest release version" >&2
    return 1
  }
  marker="## [$version] -"
  [[ "$(grep -Fc "$marker" <<< "$changelog" || true)" == 1 ]] || {
    echo "$path must contain exactly one recorded v$version release" >&2
    return 1
  }
  baseline_sha="$(git log --format=%H -S"$marker" "$treeish" -- "$path" | tail -n 1)" || return 1
  [[ "$baseline_sha" =~ ^[0-9a-f]{40}$ ]] || {
    echo "Unable to resolve the commit that recorded v$version" >&2
    return 1
  }
  git merge-base --is-ancestor "$baseline_sha" "$treeish" || {
    echo "Recorded release v$version is not in the validated history" >&2
    return 1
  }
  printf '%s\t%s\n' "$version" "$baseline_sha"
}

automatic_release_version() (
  local treeish="${1:-HEAD}" tree_sha baseline baseline_version baseline_sha tag_ref tag_sha range created=false

  tree_sha="$(git rev-parse --verify "$treeish^{commit}")" || {
    echo "Unable to resolve release version history at $treeish" >&2
    return 1
  }
  [[ "$tree_sha" =~ ^[0-9a-f]{40}$ ]] || return 1
  baseline="$(committed_release_baseline "$tree_sha")" || return 1
  if [[ -n "$baseline" ]]; then
    IFS=$'\t' read -r baseline_version baseline_sha <<< "$baseline"
    tag_ref="refs/tags/v$baseline_version"
    tag_sha="$(git rev-parse --verify "$tag_ref^{commit}" 2>/dev/null || true)"
    if [[ -n "$tag_sha" && "$tag_sha" != "$baseline_sha" ]]; then
      echo "Tag v$baseline_version does not match its recorded release commit" >&2
      return 1
    fi
    if [[ -z "$tag_sha" ]]; then
      git update-ref "$tag_ref" "$baseline_sha" "" || {
        echo "Unable to establish the local v$baseline_version release baseline" >&2
        return 1
      }
      created=true
      trap '[[ "$created" == false ]] || git update-ref -d "$tag_ref" "$baseline_sha"' EXIT
    fi
    range="$tag_ref..$tree_sha"
  else
    range="$tree_sha"
  fi
  git cliff --bumped-version "$range" | tail -n 1
)

validate_generated_changelog() {
  local version="$1" path="$2" header_count release_count
  header_count="$(grep -c '^# Changelog$' "$path" || true)"
  release_count="$(grep -Fc "## [$version] -" "$path" || true)"
  [[ "$header_count" == 1 ]] || { echo "Changelog must contain exactly one document header" >&2; return 1; }
  [[ "$release_count" == 1 ]] || { echo "Changelog must contain exactly one v$version section" >&2; return 1; }
}

merge_changelog_fragment() {
  local source="$1" fragment="$2" destination="$3"
  awk -v fragment="$fragment" '
    function emit_fragment(    line) {
      while ((getline line < fragment) > 0) print line
      close(fragment)
      inserted = 1
    }
    !inserted && /^## \[/ {
      emit_fragment()
      print ""
    }
    { print }
    END {
      if (!inserted) {
        print ""
        emit_fragment()
      }
    }
  ' "$source" > "$destination"
}

generate_changelog() (
  local version="$1" path="$2" base_sha="$3" release_timestamp="${4:-}"
  local directory scratch context adjusted fragment merged baseline baseline_version baseline_sha context_ref
  [[ "$base_sha" =~ ^[0-9a-f]{40}$ ]] || {
    echo 'Changelog generation requires an exact base commit' >&2
    return 1
  }
  if [[ -z "$release_timestamp" ]]; then
    release_timestamp="$(jq -nr 'now | strftime("%Y-%m-%dT00:00:00Z") | fromdateiso8601')" || return 1
  fi
  directory="$(dirname "$path")" || return 1
  scratch="$(mktemp -d "$directory/.changelog.XXXXXX")" || return 1
  trap 'rm -rf "$scratch"' EXIT
  context="$scratch/context.json"
  adjusted="$scratch/adjusted.json"
  fragment="$scratch/fragment.md"
  merged="$scratch/merged.md"

  context_ref="$base_sha"
  baseline="$(committed_release_baseline "$base_sha")" || return 1
  if [[ -n "$baseline" ]]; then
    IFS=$'\t' read -r baseline_version baseline_sha <<< "$baseline"
    if [[ "$version" == "$baseline_version" ]] || ! version_ge "$version" "$baseline_version"; then
      echo "Release version v$version must be newer than recorded v$baseline_version" >&2
      return 1
    fi
    context_ref="$baseline_sha..$base_sha"
  fi

  # The explicit context is the complete release range. `--unreleased` would make the same range
  # generate different bytes after the target tag exists, breaking an interrupted publication's
  # exact-delta recovery.
  git cliff --tag "v$version" --context "$context_ref" > "$context" || return 1
  jq -e --arg version "v$version" --argjson timestamp "$release_timestamp" '
    if length == 1 and .[0].version == $version then
      .[0].timestamp = $timestamp
    else
      error("unexpected generated changelog context")
    end
  ' "$context" > "$adjusted" || return 1
  git cliff --from-context "$adjusted" --strip header --output "$fragment" || return 1
  [[ "$(grep -c '^# Changelog$' "$fragment" || true)" == 0 ]] || return 1
  [[ "$(grep -Fc "## [$version] -" "$fragment" || true)" == 1 ]] || return 1
  merge_changelog_fragment "$path" "$fragment" "$merged" || return 1
  validate_generated_changelog "$version" "$merged" || return 1
  chmod --reference="$path" "$merged" || return 1
  mv "$merged" "$path" || return 1
)

rewrite_release_manifest() {
  local version="$1" path="$2" rewritten
  rewritten="$(mktemp "$(dirname "$path")/.Cargo.toml.XXXXXX")" || return 1
  if ! awk -v version="$version" '
    $0 == "[package]" { target = 1; print; next }
    /^\[/ { target = 0 }
    target && /^version = "[^"]+"$/ {
      print "version = \"" version "\""
      changed++
      next
    }
    { print }
    END { if (changed != 1) exit 1 }
  ' "$path" > "$rewritten"; then
    rm -f "$rewritten"
    echo 'Cargo.toml must contain exactly one package version' >&2
    return 1
  fi
  chmod --reference="$path" "$rewritten" || { rm -f "$rewritten"; return 1; }
  mv "$rewritten" "$path" || { rm -f "$rewritten"; return 1; }
}

rewrite_release_lock() {
  local version="$1" path="$2" workspace_names="$3" rewritten
  [[ -n "$workspace_names" ]] || {
    echo 'Cargo metadata returned no workspace packages' >&2
    return 1
  }
  rewritten="$(mktemp "$(dirname "$path")/.Cargo.lock.XXXXXX")" || return 1
  if ! awk -v names="$workspace_names" -v version="$version" '
    BEGIN {
      expected = split(names, package_names, "\n")
      for (package_index = 1; package_index <= expected; package_index++) {
        workspace[package_names[package_index]] = 1
      }
    }
    function flush(    line_index, line, update) {
      update = package_block && (package_name in workspace) && !has_source
      for (line_index = 1; line_index <= line_count; line_index++) {
        line = lines[line_index]
        if (update && line ~ /^version = "[^"]+"$/) {
          line = "version = \"" version "\""
          changed++
        }
        print line
      }
      delete lines
      line_count = 0
      package_block = 0
      package_name = ""
      has_source = 0
    }
    /^\[\[package\]\]$/ {
      flush()
      package_block = 1
    }
    {
      lines[++line_count] = $0
      if (package_block && /^name = "[^"]+"$/) {
        package_name = $0
        sub(/^name = "/, "", package_name)
        sub(/"$/, "", package_name)
      } else if (package_block && /^source = /) {
        has_source = 1
      }
    }
    END {
      flush()
      if (changed != expected) exit 1
    }
  ' "$path" > "$rewritten"; then
    rm -f "$rewritten"
    echo 'Cargo.lock does not contain exactly one local entry for every workspace package' >&2
    return 1
  fi
  chmod --reference="$path" "$rewritten" || { rm -f "$rewritten"; return 1; }
  mv "$rewritten" "$path" || { rm -f "$rewritten"; return 1; }
}

set_release_version() {
  local version="$1" manifest="${2:-Cargo.toml}" lock="${3:-Cargo.lock}" workspace_names
  workspace_names="$(CARGO_NET_OFFLINE=true cargo metadata --manifest-path "$manifest" \
    --locked --offline --format-version 1 --no-deps |
    jq -r '[.packages[] | select(.source == null) | .name] | unique | .[]')" || return 1
  rewrite_release_manifest "$version" "$manifest" || return 1
  rewrite_release_lock "$version" "$lock" "$workspace_names" || return 1
}

validate_generated_release_delta() (
  local base_sha="$1" version="$2" root
  local release_timestamp
  local -a release_dates

  root="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/release-delta.XXXXXX")" || return 1
  trap 'rm -rf "$root"' EXIT
  git archive "$base_sha" | tar -x -C "$root" || return 1

  set_release_version "$version" "$root/Cargo.toml" "$root/Cargo.lock" || return 1
  cmp -s "$root/Cargo.toml" Cargo.toml || {
    echo 'Release proposal contains Cargo.toml changes outside the generated version update' >&2
    return 1
  }
  cmp -s "$root/Cargo.lock" Cargo.lock || {
    echo 'Release proposal contains Cargo.lock changes outside the generated package update' >&2
    return 1
  }

  mapfile -t release_dates < <(awk -v header="## [$version] - " '
    index($0, header) == 1 { print substr($0, length(header) + 1) }
  ' CHANGELOG.md)
  [[ "${#release_dates[@]}" == 1 ]] || {
    echo "CHANGELOG.md must contain exactly one canonical v$version release date" >&2
    return 1
  }
  release_timestamp="$(jq -nr --arg date "${release_dates[0]}" \
    '$date + "T00:00:00Z" | fromdateiso8601' 2>/dev/null)" || {
    echo "CHANGELOG.md contains an invalid v$version release date" >&2
    return 1
  }
  [[ "$(jq -nr --argjson timestamp "$release_timestamp" '$timestamp | strftime("%Y-%m-%d")')" == "${release_dates[0]}" ]] || {
    echo "CHANGELOG.md contains a non-canonical v$version release date" >&2
    return 1
  }

  generate_changelog "$version" "$root/CHANGELOG.md" "$base_sha" "$release_timestamp" || return 1
  cmp -s "$root/CHANGELOG.md" CHANGELOG.md || {
    echo 'Release proposal CHANGELOG.md is not the exact generated release history' >&2
    return 1
  }
)

has_label() {
  jq -e --arg label "$2" 'any(.labels[]; .name == $label)' <<< "$1" >/dev/null
}

count_literal_occurrences() {
  local value="$1" literal="$2"
  awk -v literal="$literal" '
    {
      value = $0
      while ((position = index(value, literal)) > 0) {
        count++
        value = substr(value, position + length(literal))
      }
    }
    END { print count + 0 }
  ' <<< "$value"
}

parse_release_provenance() {
  local body="$1" base_lines run_lines base_count run_count valid_base_count valid_run_count
  base_lines="$(sed -n 's/^<!-- release-base:\([0-9a-f]\{40\}\) -->$/\1/p' <<< "$body")"
  run_lines="$(sed -n 's/^<!-- release-validation-run:\([1-9][0-9]*\) -->$/\1/p' <<< "$body")"
  base_count="$(count_literal_occurrences "$body" '<!-- release-base:')"
  run_count="$(count_literal_occurrences "$body" '<!-- release-validation-run:')"
  valid_base_count="$(grep -Ec '^<!-- release-base:[0-9a-f]{40} -->$' <<< "$body" || true)"
  valid_run_count="$(grep -Ec '^<!-- release-validation-run:[1-9][0-9]* -->$' <<< "$body" || true)"
  [[ "$base_count" == "$valid_base_count" && "$valid_base_count" == 1 && "$base_lines" =~ ^[0-9a-f]{40}$ ]] || {
    echo "Release PR must contain exactly one valid release-base marker" >&2
    return 1
  }
  [[ "$run_count" == "$valid_run_count" && "$valid_run_count" == 1 && "$run_lines" =~ ^[1-9][0-9]*$ ]] || {
    echo "Release PR must contain exactly one valid release-validation-run marker" >&2
    return 1
  }
  RELEASE_BASE_SHA="$base_lines"
  RELEASE_VALIDATION_RUN_ID="$run_lines"
}

actions_api() {
  GH_TOKEN="${ACTIONS_TOKEN:-$GH_TOKEN}" gh api "$@"
}

validate_policy_token_identity() {
  [[ "${RELEASE_APP_SLUG:-}" =~ ^[a-z0-9][a-z0-9-]*$ &&
     "$RELEASE_APP_LOGIN" == "${RELEASE_APP_SLUG}[bot]" ]] || {
    echo 'Release policy token identity does not match RELEASE_APP_LOGIN' >&2
    return 1
  }
}

validate_repository_merge_policy() {
  local repository_json
  repository_json="$(GH_TOKEN="${RELEASE_POLICY_TOKEN:-$GH_TOKEN}" gh api "repos/$GITHUB_REPOSITORY")" || {
    echo 'Unable to read repository merge settings' >&2
    return 1
  }
  jq -e '
    (.allow_auto_merge | type) == "boolean" and
    (.allow_squash_merge | type) == "boolean" and
    (.allow_merge_commit | type) == "boolean" and
    (.allow_rebase_merge | type) == "boolean" and
    (.delete_branch_on_merge | type) == "boolean" and
    (.squash_merge_commit_title | type) == "string" and
    (.squash_merge_commit_message | type) == "string"
  ' <<< "$repository_json" >/dev/null || {
    echo 'Repository merge settings are unavailable; the policy token requires Contents write and Metadata read' >&2
    return 1
  }
  jq -e '
    .allow_auto_merge == false and
    .allow_squash_merge == true and
    .allow_merge_commit == false and
    .allow_rebase_merge == false and
    .delete_branch_on_merge == true and
    .squash_merge_commit_title == "PR_TITLE" and
    .squash_merge_commit_message == "BLANK"
  ' <<< "$repository_json" >/dev/null || {
    echo 'Repository must disable auto-merge and use squash-only PR-title merges with blank messages and automatic branch deletion' >&2
    return 1
  }
}

validate_immutable_release_policy() {
  local immutable_json
  immutable_json="$(GH_TOKEN="${RELEASE_POLICY_TOKEN:-$GH_TOKEN}" gh api \
    "repos/$GITHUB_REPOSITORY/immutable-releases")" || {
    echo 'Unable to read immutable Release settings; the policy token needs Administration read access' >&2
    return 1
  }
  jq -e '.enabled == true' <<< "$immutable_json" >/dev/null || {
    echo 'Immutable Releases must be enabled before release management can run' >&2
    return 1
  }
}

validate_repository_actions_policy() {
  local actions_json workflow_json
  actions_json="$(GH_TOKEN="${RELEASE_POLICY_TOKEN:-$GH_TOKEN}" gh api \
    "repos/$GITHUB_REPOSITORY/actions/permissions")" || {
    echo 'Unable to read repository Actions settings' >&2
    return 1
  }
  jq -e '
    .enabled == true and
    .sha_pinning_required == true and
    (.allowed_actions == "all" or .allowed_actions == "local_only" or .allowed_actions == "selected")
  ' <<< "$actions_json" >/dev/null || {
    echo 'Repository Actions must be enabled and require full-length commit SHA references' >&2
    return 1
  }

  workflow_json="$(GH_TOKEN="${RELEASE_POLICY_TOKEN:-$GH_TOKEN}" gh api \
    "repos/$GITHUB_REPOSITORY/actions/permissions/workflow")" || {
    echo 'Unable to read default workflow token settings' >&2
    return 1
  }
  jq -e '
    .default_workflow_permissions == "read" and
    .can_approve_pull_request_reviews == false
  ' <<< "$workflow_json" >/dev/null || {
    echo 'Repository workflows must default to read-only tokens and must not approve pull requests' >&2
    return 1
  }
}

validate_repository_release_policy() {
  validate_repository_merge_policy || return 1
  validate_immutable_release_policy || return 1
  validate_repository_actions_policy || return 1
}

git_remote() {
  local origin_url origin_host
  : "${GH_TOKEN:?GH_TOKEN is required for remote Git operations}"
  origin_url="$(git remote get-url origin)"
  [[ "$origin_url" == https://*/* && "$origin_url" != https://*@* ]] || {
    echo 'The release Git remote must use credential-free HTTPS' >&2
    return 1
  }
  origin_host="${origin_url#https://}"
  origin_host="${origin_host%%/*}"
  export GH_TOKEN CAMELLIA_NEXUS_GIT_AUTH_HOST="$origin_host" GIT_ASKPASS=false GIT_TERMINAL_PROMPT=0
  # The single-quoted helper is a shell program evaluated later by Git.
  # shellcheck disable=SC2016
  git \
    -c credential.helper= \
    -c 'credential.helper=!f() { test "$1" = get || exit 0; host=; while IFS="=" read -r key value; do test -n "$key" || break; test "$key" = host && host="$value"; done; test "$host" = "$CAMELLIA_NEXUS_GIT_AUTH_HOST" || exit 1; printf "%s\n" "username=x-access-token" "password=$GH_TOKEN"; }; f' \
    "$@"
}

validate_validation_run() {
  local base_sha="$1" run_id="$2" allow_current="${3:-false}" run_json status conclusion
  local attempt attempts=1
  [[ "${GITHUB_ACTIONS:-}" == true && "$allow_current" != true ]] && attempts=11
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    run_json="$(actions_api "repos/$GITHUB_REPOSITORY/actions/runs/$run_id")" || {
      echo "Unable to read validation run $run_id" >&2
      return 1
    }
    [[ "$(jq -r '.id // empty' <<< "$run_json")" == "$run_id" ]] || {
      echo "Validation run identity changed" >&2
      return 1
    }
    [[ "$(jq -r '.head_sha // empty' <<< "$run_json")" == "$base_sha" &&
        "$(jq -r '.head_branch // empty' <<< "$run_json")" == main &&
        "$(jq -r '.event // empty' <<< "$run_json")" == push &&
        "$(jq -r '.path // empty' <<< "$run_json")" == .github/workflows/main.yml ]] || {
      echo "Validation run $run_id does not prove main at $base_sha" >&2
      return 1
    }
    status="$(jq -r '.status // empty' <<< "$run_json")"
    conclusion="$(jq -r '.conclusion // empty' <<< "$run_json")"
    if [[ "$status" == completed && "$conclusion" == success ]]; then
      return 0
    fi
    if [[ "$allow_current" == true && "$run_id" == "${GITHUB_RUN_ID:-}" && "$status" == in_progress ]]; then
      return 0
    fi
    if [[ "$status" =~ ^(queued|in_progress|waiting|pending|requested)$ && "$attempt" -lt "$attempts" ]]; then
      sleep 3
      continue
    fi
    break
  done
  echo "Validation run $run_id is not successful" >&2
  return 1
}

resolve_validation_provenance() {
  local main_sha run_json
  main_sha="$(git rev-parse origin/main)" || return 1
  if [[ -n "${VERIFIED_SHA:-}" || -n "${VALIDATION_RUN_ID:-}" ]]; then
    [[ -n "${VERIFIED_SHA:-}" && -n "${VALIDATION_RUN_ID:-}" ]] || {
      echo "VERIFIED_SHA and VALIDATION_RUN_ID must be provided together" >&2
      return 1
    }
    [[ "$VERIFIED_SHA" == "$main_sha" ]] || {
      echo "Main advanced beyond verified commit $VERIFIED_SHA; release proposal skipped"
      return 2
    }
    validate_validation_run "$VERIFIED_SHA" "$VALIDATION_RUN_ID" true || return 1
    RELEASE_VALIDATED_SHA="$VERIFIED_SHA"
    RELEASE_VALIDATED_RUN_ID="$VALIDATION_RUN_ID"
    return 0
  fi

  run_json="$(actions_api "repos/$GITHUB_REPOSITORY/actions/runs?branch=main&event=push&status=success&per_page=100")" || {
    echo "Unable to list successful main validation runs" >&2
    return 1
  }
  RELEASE_VALIDATED_RUN_ID="$(jq -r --arg sha "$main_sha" '
    [.workflow_runs[] | select(
      .head_sha == $sha and
      .path == ".github/workflows/main.yml" and
      .status == "completed" and
      .conclusion == "success"
    )] | sort_by(.created_at) | last | .id // empty
  ' <<< "$run_json")"
  [[ "$RELEASE_VALIDATED_RUN_ID" =~ ^[1-9][0-9]*$ ]] || {
    echo "No successful main validation exists for $main_sha" >&2
    return 1
  }
  validate_validation_run "$main_sha" "$RELEASE_VALIDATED_RUN_ID" || return 1
  RELEASE_VALIDATED_SHA="$main_sha"
}

release_approval_state() {
  local number="$1" reviewed_sha="$2" reviews reviewer_logins login encoded_login permission_json permission
  local authorized_reviewers='[]'
  reviews="$(gh api --paginate --slurp \
    "repos/$GITHUB_REPOSITORY/pulls/$number/reviews?per_page=100")" || {
    echo "Unable to read reviews for Release PR #$number" >&2
    return 1
  }
  reviewer_logins="$(jq -r '
    [.[][] |
      select((.user.type // "") == "User") |
      select(.state == "APPROVED" or .state == "CHANGES_REQUESTED" or .state == "DISMISSED") |
      .user.login // empty
    ] | unique | .[]
  ' <<< "$reviews")" || {
    echo "Unable to parse reviewers for Release PR #$number" >&2
    return 1
  }
  while IFS= read -r login; do
    [[ -n "$login" ]] || continue
    encoded_login="$(jq -nr --arg login "$login" '$login | @uri')" || return 1
    permission_json="$(GH_TOKEN="${RELEASE_POLICY_TOKEN:-$GH_TOKEN}" gh api \
      "repos/$GITHUB_REPOSITORY/collaborators/$encoded_login/permission")" || {
      echo "Unable to read current repository permission for reviewer $login" >&2
      return 1
    }
    jq -e --arg login "$login" '
      (.user.login // "") == $login and
      (.permission == "admin" or .permission == "write" or .permission == "read" or .permission == "none")
    ' <<< "$permission_json" >/dev/null || {
      echo "GitHub returned invalid repository permission for reviewer $login" >&2
      return 1
    }
    permission="$(jq -r '.permission' <<< "$permission_json")"
    if [[ "$permission" == admin || "$permission" == write ]]; then
      authorized_reviewers="$(jq -c --arg login "$login" '. + [$login] | unique' <<< "$authorized_reviewers")" || return 1
    fi
  done <<< "$reviewer_logins"
  RELEASE_APPROVAL_STATE="$(jq -r \
    --arg app "$RELEASE_APP_LOGIN" \
    --argjson authorized "$authorized_reviewers" \
    --arg sha "$reviewed_sha" '
    def latest_by_user:
      sort_by([(.submitted_at // ""), (.id // 0)]) |
      reduce .[] as $review ({}; .[$review.user.login] = $review.state);
    [
      .[][] |
      select((.user.type // "") == "User") |
      select((.user.login // "") != "" and (.user.login // "") != $app) |
      select(.user.login as $login | $authorized | index($login)) |
      select(.state == "APPROVED" or .state == "CHANGES_REQUESTED" or .state == "DISMISSED")
    ] as $reviews |
    ($reviews | latest_by_user) as $latest |
    ($reviews | map(select(.commit_id == $sha)) | latest_by_user) as $head |
    if any($latest[]; . == "CHANGES_REQUESTED") then "blocked"
    elif any($head[]; . == "APPROVED") then "approved"
    else "pending"
    end
  ' <<< "$reviews")" || {
    echo "Unable to evaluate reviews for Release PR #$number" >&2
    return 1
  }
}

validate_release_approval() {
  local number="$1" reviewed_sha="$2"
  release_approval_state "$number" "$reviewed_sha" || return 1
  [[ "$RELEASE_APPROVAL_STATE" == approved ]] || {
    if [[ "$RELEASE_APPROVAL_STATE" == blocked ]]; then
      echo "Release PR #$number has an active human change request" >&2
    else
      echo "Release PR #$number requires exact-head human approval" >&2
    fi
    return 1
  }
}

validate_release_executor() {
  local number="$1" merger_login="$2" merger_type="$3"
  [[ "$merger_login" == "$RELEASE_APP_LOGIN" && "$merger_type" == Bot ]] || {
    echo "Release PR #$number was not merged by $RELEASE_APP_LOGIN" >&2
    return 1
  }
}

release_merge_ready() {
  local number="${RELEASE_PR_NUMBER:-}" expected_head="${EXPECTED_HEAD_SHA:-}"
  local expected_run_id="${EXPECTED_FOCUSED_RUN_ID:-}" pr_json draft
  : "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
  [[ "$expected_head" =~ ^[0-9a-f]{40}$ ]] || {
    echo 'EXPECTED_HEAD_SHA must identify the reviewed Release PR head' >&2
    return 1
  }
  if [[ -z "$number" ]]; then
    pr_json="$(gh api --paginate --slurp \
      "repos/$GITHUB_REPOSITORY/pulls?state=open&base=main&per_page=100")" || {
      echo "Unable to list open Release PRs for $expected_head" >&2
      return 1
    }
    number="$(jq -r --arg repository "$GITHUB_REPOSITORY" --arg sha "$expected_head" '
      [.[][] | select(
        .state == "open" and
        .base.ref == "main" and
        .head.ref == "release/next" and
        .head.sha == $sha and
        (.head.repo.full_name // "") == $repository
      )] |
      if length == 1 then .[0].number
      elif length == 0 then empty
      else error("multiple open Release PRs use the expected head")
      end
    ' <<< "$pr_json")" || return 1
  fi
  if [[ -z "$number" ]]; then
    echo 'ready=false' >> "$GITHUB_OUTPUT"
    echo "Release event for $expected_head is no longer current"
    return 0
  fi
  [[ "$number" =~ ^[1-9][0-9]*$ ]] || {
    echo "Unable to identify one open Release PR for $expected_head" >&2
    return 1
  }
  pr_json="$(gh api "repos/$GITHUB_REPOSITORY/pulls/$number")" || {
    echo "Unable to read reviewed Release PR #$number" >&2
    return 1
  }
  if [[ "$(jq -r '.state // ""' <<< "$pr_json")" != open ||
        "$(jq -r '.merged // false' <<< "$pr_json")" != false ]]; then
    echo "pr-number=$number" >> "$GITHUB_OUTPUT"
    echo 'ready=false' >> "$GITHUB_OUTPUT"
    echo "Release PR #$number is no longer open"
    return 0
  fi
  draft="$(jq -r '.draft | if . == true then "true" elif . == false then "false" else empty end' <<< "$pr_json")"
  [[ -n "$draft" ]] || { echo "Release PR #$number has invalid draft metadata" >&2; return 1; }
  if [[ "$draft" == true ]]; then
    echo "pr-number=$number" >> "$GITHUB_OUTPUT"
    echo 'ready=false' >> "$GITHUB_OUTPUT"
    echo "Release PR #$number is still being initialized"
    return 0
  fi
  validate_open_release_pr_envelope "$number" "$pr_json" || return 1
  if [[ "$(jq -r '.head.sha // ""' <<< "$pr_json")" != "$expected_head" ]]; then
    echo "pr-number=$number" >> "$GITHUB_OUTPUT"
    echo 'ready=false' >> "$GITHUB_OUTPUT"
    echo "Release event for PR #$number was superseded by a new head"
    return 0
  fi
  has_label "$pr_json" "$pending_label" || {
    echo "Release PR #$number is not pending" >&2
    return 1
  }
  release_approval_state "$number" "$expected_head" || return 1
  echo "pr-number=$number" >> "$GITHUB_OUTPUT"
  case "$RELEASE_APPROVAL_STATE" in
    approved)
      ;;
    pending)
      echo 'ready=false' >> "$GITHUB_OUTPUT"
      echo "Release PR #$number is waiting for exact-head approval"
      return 0
      ;;
    blocked)
      echo "Release PR #$number has an active human change request" >&2
      return 1
      ;;
    *)
      echo "Release PR #$number has an invalid approval state" >&2
      return 1
      ;;
  esac

  load_focused_release_run "$number" "$expected_head" || return 1
  if [[ -z "$RELEASE_FOCUSED_RUN_ID" ||
        "$RELEASE_FOCUSED_RUN_STATUS" != completed ||
        "$RELEASE_FOCUSED_RUN_CONCLUSION" != success ||
        ( -n "$expected_run_id" && "$RELEASE_FOCUSED_RUN_ID" != "$expected_run_id" ) ]]; then
    echo 'ready=false' >> "$GITHUB_OUTPUT"
    echo "Release PR #$number is waiting for its latest exact-head required check"
    return 0
  fi
  echo 'ready=true' >> "$GITHUB_OUTPUT"
}

load_focused_release_run() {
  local number="$1" head_sha="$2" runs_json run_json run_id
  [[ "$number" =~ ^[1-9][0-9]*$ && "$head_sha" =~ ^[0-9a-f]{40}$ ]] || {
    echo 'Focused Release validation received an invalid PR or commit identity' >&2
    return 1
  }
  runs_json="$(actions_api --paginate --slurp \
    "repos/$GITHUB_REPOSITORY/actions/workflows/${release_ci_path##*/}/runs?event=pull_request&branch=release%2Fnext&head_sha=$head_sha&per_page=100")" || {
    echo "Unable to list focused validation runs for Release PR #$number" >&2
    return 1
  }
  run_json="$(jq -c \
    --arg path "$release_ci_path" \
    --arg repository "$GITHUB_REPOSITORY" \
    --arg sha "$head_sha" '
      [.[]?.workflow_runs[]? | select(
        .path == $path and
        .head_sha == $sha and
        .head_branch == "release/next" and
        .event == "pull_request" and
        (.head_repository.full_name // "") == $repository and
        .conclusion != "skipped"
      )] |
      sort_by([(.run_started_at // .created_at // ""), .id]) |
      last // empty
    ' <<< "$runs_json")"
  RELEASE_FOCUSED_RUN_ID=
  RELEASE_FOCUSED_RUN_STATUS=missing
  RELEASE_FOCUSED_RUN_CONCLUSION=
  [[ -n "$run_json" ]] || return 0
  run_id="$(jq -r '.id // empty' <<< "$run_json")"
  [[ "$run_id" =~ ^[1-9][0-9]*$ ]] || {
    echo "Release PR #$number has an invalid focused validation identity" >&2
    return 1
  }
  RELEASE_FOCUSED_RUN_ID="$run_id"
  RELEASE_FOCUSED_RUN_STATUS="$(jq -r '.status // empty' <<< "$run_json")"
  RELEASE_FOCUSED_RUN_CONCLUSION="$(jq -r '.conclusion // empty' <<< "$run_json")"
}

validate_focused_release_run() {
  local number="$1" head_sha="$2" expected_run_id="${3:-}"
  load_focused_release_run "$number" "$head_sha" || return 1
  [[ -n "$RELEASE_FOCUSED_RUN_ID" ]] || {
    echo "Release PR #$number has no focused validation for $head_sha" >&2
    return 1
  }
  if [[ -n "$expected_run_id" && "$RELEASE_FOCUSED_RUN_ID" != "$expected_run_id" ]]; then
    echo "Focused validation run $expected_run_id is not current for Release PR #$number" >&2
    return 1
  fi
  [[ "$RELEASE_FOCUSED_RUN_STATUS" == completed &&
      "$RELEASE_FOCUSED_RUN_CONCLUSION" == success ]] || {
    echo "Focused validation run $RELEASE_FOCUSED_RUN_ID is not successful for Release PR #$number" >&2
    return 1
  }
}

validate_release_proposal_commit() {
  local sha="$1" expected_title="${2:-}" expected_parent="${3:-}" commit_json message
  [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || {
    echo "Release proposal has an invalid commit identity: $sha" >&2
    return 1
  }
  commit_json="$(gh api "repos/$GITHUB_REPOSITORY/commits/$sha")" || {
    echo "Unable to read release proposal commit $sha" >&2
    return 1
  }
  jq -e \
    --arg app "$RELEASE_APP_LOGIN" \
    --arg parent "$expected_parent" \
    --arg sha "$sha" '
      .sha == $sha and
      (.author.login // "") == $app and
      (.committer.login // "") == $app and
      (.parents | length) == 1 and
      ($parent == "" or .parents[0].sha == $parent)
    ' <<< "$commit_json" >/dev/null || {
    echo "Release proposal commit $sha is not the exact App-authored single-parent proposal" >&2
    return 1
  }
  message="$(jq -r '.commit.message // ""' <<< "$commit_json")"
  [[ "$message" =~ ^chore\(release\):\ v((0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*))$ ]] &&
    valid_product_version "${BASH_REMATCH[1]}" || {
    echo "Release proposal commit $sha has a non-canonical message" >&2
    return 1
  }
  [[ -z "$expected_title" || "$message" == "$expected_title" ]] || {
    echo "Release proposal commit $sha does not match the Release PR title" >&2
    return 1
  }
  RELEASE_PROPOSAL_PARENT="$(jq -r '.parents[0].sha' <<< "$commit_json")"
  RELEASE_PROPOSAL_TITLE="$message"
  RELEASE_PROPOSAL_VERSION="${message#chore(release): v}"
}

validate_open_release_pr_envelope() {
  local number="$1" pr_json="$2" allow_draft="${3:-false}"
  jq -e \
    --arg app "$RELEASE_APP_LOGIN" \
    --arg branch "$branch" \
    --arg repository "$GITHUB_REPOSITORY" \
    --argjson allow_draft "$allow_draft" '
      (.user.login // "") == $app and
      .state == "open" and
      .merged == false and
      ($allow_draft or .draft == false) and
      .base.ref == "main" and
      .head.ref == $branch and
      (.head.repo.full_name // "") == $repository
    ' <<< "$pr_json" >/dev/null || {
    echo "Open Release PR #$number does not match the managed App and source contract" >&2
    return 1
  }
}

validate_release_pr() {
  local number="$1" expected_state="$2" allow_current_validation="${3:-false}"
  local verify_generated_delta="${4:-true}"
  local pr_json author title state merged base head head_repo sha body merge_subject merge_body
  local version minimum locked files existing_tag_sha parent_line parent_sha reviewed_sha

  pr_json="$(gh api "repos/$GITHUB_REPOSITORY/pulls/$number")" || {
    echo "Unable to read Release PR #$number" >&2
    return 1
  }
  author="$(jq -r .user.login <<< "$pr_json")"
  title="$(jq -r .title <<< "$pr_json")"
  state="$(jq -r .state <<< "$pr_json")"
  merged="$(jq -r .merged <<< "$pr_json")"
  base="$(jq -r .base.ref <<< "$pr_json")"
  head="$(jq -r .head.ref <<< "$pr_json")"
  head_repo="$(jq -r '.head.repo.full_name // ""' <<< "$pr_json")"
  reviewed_sha="$(jq -r '.head.sha // ""' <<< "$pr_json")"
  body="$(jq -r '.body // ""' <<< "$pr_json")"

  [[ "$author" == "$RELEASE_APP_LOGIN" ]] || { echo "Release PR #$number was not created by $RELEASE_APP_LOGIN" >&2; return 1; }
  [[ "$base" == main && "$head" == "$branch" && "$head_repo" == "$GITHUB_REPOSITORY" ]] || {
    echo "Release PR #$number has an invalid source" >&2
    return 1
  }
  has_label "$pr_json" "$pending_label" || { echo "Release PR #$number is not pending" >&2; return 1; }
  parse_release_provenance "$body" || return 1
  validate_validation_run "$RELEASE_BASE_SHA" "$RELEASE_VALIDATION_RUN_ID" "$allow_current_validation" || return 1
  validate_release_proposal_commit "$reviewed_sha" "$title" "$RELEASE_BASE_SHA" || return 1

  case "$expected_state" in
    open)
      [[ "$state" == open && "$merged" == false ]] || { echo "Release PR #$number is not open" >&2; return 1; }
      sha="$(jq -r .head.sha <<< "$pr_json")"
      [[ "$(jq -r '.base.sha // empty' <<< "$pr_json")" == "$RELEASE_BASE_SHA" ]] || {
        echo "Release PR #$number base advanced after validation" >&2
        return 1
      }
      git merge-base --is-ancestor origin/main "$sha" || { echo "Release PR #$number is not based on current main" >&2; return 1; }
      ;;
    merged)
      [[ "$state" == closed && "$merged" == true ]] || { echo "Release PR #$number is not merged" >&2; return 1; }
      [[ "$reviewed_sha" =~ ^[0-9a-f]{40}$ ]] || { echo "Release PR #$number has an invalid reviewed commit" >&2; return 1; }
      validate_release_approval "$number" "$reviewed_sha" || return 1
      validate_release_executor "$number" \
        "$(jq -r '.merged_by.login // ""' <<< "$pr_json")" \
        "$(jq -r '.merged_by.type // ""' <<< "$pr_json")" || return 1
      sha="$(jq -r '.merge_commit_sha // ""' <<< "$pr_json")"
      [[ -n "$sha" ]] || { echo "Release PR #$number has no merge commit" >&2; return 1; }
      git merge-base --is-ancestor "$sha" origin/main || { echo "Release PR #$number is not on main" >&2; return 1; }
      ;;
    *)
      echo "Unknown release PR state: $expected_state" >&2
      return 1
      ;;
  esac

  parent_line="$(git rev-list --parents -n 1 "$sha")"
  [[ "$(wc -w <<< "$parent_line" | tr -d ' ')" == 2 ]] || {
    echo "Release commit $sha must have exactly one parent" >&2
    return 1
  }
  parent_sha="${parent_line#* }"
  [[ "$parent_sha" == "$RELEASE_BASE_SHA" ]] || {
    echo "Release commit $sha is not based on validated commit $RELEASE_BASE_SHA" >&2
    return 1
  }
  if [[ "$expected_state" == merged ]]; then
    merge_subject="$(git log -1 --format=%s "$sha")"
    merge_body="$(git log -1 --format=%b "$sha")"
    [[ "$merge_subject" == "$title" && -z "$merge_body" ]] || {
      echo "Merged release commit $sha does not preserve the required PR title and blank body" >&2
      return 1
    }
  fi

  [[ "$(git rev-parse HEAD)" == "$sha" ]] || { echo "Release PR #$number checkout does not match $sha" >&2; return 1; }

  files="$(gh api --paginate "repos/$GITHUB_REPOSITORY/pulls/$number/files?per_page=100" --jq '.[].filename')" || {
    echo "Unable to read files for Release PR #$number" >&2
    return 1
  }
  grep -Fxq CHANGELOG.md <<< "$files" || { echo "Release PR #$number does not update CHANGELOG.md" >&2; return 1; }
  while IFS= read -r file; do
    case "$file" in Cargo.toml|Cargo.lock|CHANGELOG.md) ;; *) echo "Release PR changed forbidden file: $file" >&2; return 1 ;; esac
  done <<< "$files"

  version="$RELEASE_PROPOSAL_VERSION"
  valid_product_version "$version" || { echo "Release PR #$number contains an invalid server version: $version" >&2; return 1; }
  [[ "$title" == "chore(release): v$version" ]] || { echo "Release PR #$number title does not match v$version" >&2; return 1; }
  existing_tag_sha="$(git rev-list -n 1 "refs/tags/v$version" 2>/dev/null || true)"
  if [[ -n "$existing_tag_sha" ]]; then
    [[ "$expected_state" == merged && "$existing_tag_sha" == "$sha" ]] || {
      echo "v$version exists before the Release PR reaches its managed merged state" >&2
      return 1
    }
  else
    minimum="$(automatic_release_version "$RELEASE_BASE_SHA")" || return 1
    minimum="${minimum#v}"
    valid_product_version "$minimum" || { echo "git-cliff proposed invalid version: $minimum" >&2; return 1; }
    locked=false
    has_label "$pr_json" "$lock_label" && locked=true
    release_version_allowed "$version" "$minimum" "$locked" || {
      echo "Release PR #$number version $version is invalid for minimum $minimum and locked=$locked" >&2
      return 1
    }
  fi

  if [[ "$verify_generated_delta" == true ]]; then
    validate_generated_release_delta "$RELEASE_BASE_SHA" "$version" || return 1
  fi
  [[ "$(cargo_version)" == "$version" ]] || {
    echo "Release PR #$number Cargo metadata does not match v$version" >&2
    return 1
  }
  grep -Fq "## [$version] -" CHANGELOG.md || { echo "CHANGELOG.md has no v$version entry" >&2; return 1; }

  VALIDATED_PR_NUMBER="$number"
  VALIDATED_RELEASE_SHA="$sha"
  VALIDATED_RELEASE_VERSION="$version"
}

merge_approved_release() {
  local number="${RELEASE_PR_NUMBER:-}" expected_head="${EXPECTED_HEAD_SHA:-}"
  local expected_run_id="${EXPECTED_FOCUSED_RUN_ID:-}" pr_json title body payload merge_json merge_sha
  local validated_base validated_run
  [[ "$number" =~ ^[1-9][0-9]*$ && "$expected_head" =~ ^[0-9a-f]{40}$ ]] || {
    echo 'RELEASE_PR_NUMBER and EXPECTED_HEAD_SHA must identify the approved Release PR' >&2
    return 1
  }
  validate_repository_release_policy || return 1
  git_remote fetch --force origin main --tags || return 1
  [[ "$(git rev-parse HEAD)" == "$expected_head" ]] || {
    echo "Release PR #$number checkout does not match approved head $expected_head" >&2
    return 1
  }
  validate_release_pr "$number" open || return 1
  [[ "$VALIDATED_RELEASE_SHA" == "$expected_head" ]] || {
    echo "Release PR #$number changed during validation" >&2
    return 1
  }
  title="chore(release): v$VALIDATED_RELEASE_VERSION"
  validated_base="$RELEASE_BASE_SHA"
  validated_run="$RELEASE_VALIDATION_RUN_ID"
  validate_focused_release_run "$number" "$expected_head" "$expected_run_id" || return 1
  validate_release_approval "$number" "$expected_head" || return 1

  pr_json="$(gh api "repos/$GITHUB_REPOSITORY/pulls/$number")" || {
    echo "Unable to reread approved Release PR #$number" >&2
    return 1
  }
  jq -e \
    --arg app "$RELEASE_APP_LOGIN" \
    --arg base "$validated_base" \
    --arg branch "$branch" \
    --arg repository "$GITHUB_REPOSITORY" \
    --arg sha "$expected_head" \
    --arg title "$title" '
      .user.login == $app and
      .state == "open" and
      .merged == false and
      .draft == false and
      .title == $title and
      .base.ref == "main" and
      .base.sha == $base and
      .head.ref == $branch and
      .head.sha == $sha and
      (.head.repo.full_name // "") == $repository
    ' <<< "$pr_json" >/dev/null || {
    echo "Release PR #$number changed before automatic merge" >&2
    return 1
  }
  has_label "$pr_json" "$pending_label" || {
    echo "Release PR #$number lost its pending release state" >&2
    return 1
  }
  body="$(jq -r '.body // ""' <<< "$pr_json")"
  parse_release_provenance "$body" || return 1
  [[ "$RELEASE_BASE_SHA" == "$validated_base" &&
      "$RELEASE_VALIDATION_RUN_ID" == "$validated_run" ]] || {
    echo "Release PR #$number provenance changed before automatic merge" >&2
    return 1
  }
  payload="$(jq -nc \
    --arg sha "$expected_head" \
    --arg title "$title" \
    '{sha:$sha,merge_method:"squash",commit_title:$title,commit_message:""}')"
  merge_json="$(gh api -X PUT "repos/$GITHUB_REPOSITORY/pulls/$number/merge" --input - <<< "$payload")" || {
    echo "Unable to merge approved Release PR #$number" >&2
    return 1
  }
  merge_sha="$(jq -r '.sha // ""' <<< "$merge_json")"
  [[ "$(jq -r '.merged // false' <<< "$merge_json")" == true && "$merge_sha" =~ ^[0-9a-f]{40}$ ]] || {
    echo "GitHub did not merge approved Release PR #$number" >&2
    return 1
  }
  echo "Merged approved Release PR #$number at $merge_sha"
}

validate_managed_release_metadata() {
  local release_json="$1" version="$2" sha="$3" expected_pr="${4:-}"
  local tag body release_pr_lines commit_marker release_id release_draft release_immutable
  local commit_count valid_commit_count release_pr_count valid_release_pr_count
  local completion_count valid_completion_count completion_sha digest_count valid_digest_count

  tag="v$version"
  [[ "$(jq -r '.tag_name // empty' <<< "$release_json")" == "$tag" ]] || { echo "Release tag metadata does not match $tag" >&2; return 1; }
  release_id="$(jq -r '.id // empty' <<< "$release_json")"
  release_draft="$(jq -r '.draft | if . == true then "true" elif . == false then "false" else empty end' <<< "$release_json")"
  release_immutable="$(jq -r '.immutable | if . == true then "true" elif . == false then "false" else empty end' <<< "$release_json")"
  [[ "$release_id" =~ ^[1-9][0-9]*$ && -n "$release_draft" && -n "$release_immutable" ]] || { echo "Release $tag has invalid state metadata" >&2; return 1; }
  [[ "$release_draft" == true || "$release_immutable" == true ]] || { echo "Published Release $tag is not immutable" >&2; return 1; }
  [[ "$(jq -r '.target_commitish // empty' <<< "$release_json")" == "$sha" ]] || { echo "Release $tag targets a different commit" >&2; return 1; }
  [[ "$(jq -r '.name // empty' <<< "$release_json")" == "$release_title_prefix $version" ]] || { echo "Release $tag has an unexpected title" >&2; return 1; }
  [[ "$(jq -r '.author.login // empty' <<< "$release_json")" == "$RELEASE_APP_LOGIN" ]] || { echo "Release $tag was not created by $RELEASE_APP_LOGIN" >&2; return 1; }

  body="$(jq -r '.body // ""' <<< "$release_json")"
  commit_marker="<!-- release-commit:$sha -->"
  commit_count="$(count_literal_occurrences "$body" '<!-- release-commit:')"
  valid_commit_count="$(grep -Fxc "$commit_marker" <<< "$body" || true)"
  [[ "$commit_count" == "$valid_commit_count" && "$valid_commit_count" == 1 ]] || {
    echo "Release $tag must contain exactly one managed commit marker" >&2
    return 1
  }
  release_pr_lines="$(sed -n 's/^<!-- release-pr:\([1-9][0-9]*\) -->$/\1/p' <<< "$body")"
  release_pr_count="$(count_literal_occurrences "$body" '<!-- release-pr:')"
  valid_release_pr_count="$(grep -Ec '^<!-- release-pr:[1-9][0-9]* -->$' <<< "$body" || true)"
  [[ "$release_pr_count" == "$valid_release_pr_count" && "$valid_release_pr_count" == 1 && "$release_pr_lines" =~ ^[1-9][0-9]*$ ]] || {
    echo "Release $tag must contain exactly one managed PR marker" >&2
    return 1
  }
  [[ -z "$expected_pr" || "$release_pr_lines" == "$expected_pr" ]] || { echo "Release $tag belongs to a different Release PR" >&2; return 1; }

  digest_count="$(count_literal_occurrences "$body" '<!-- container-digest:')"
  valid_digest_count="$(grep -Ec '^<!-- container-digest:sha256:[0-9a-f]{64} -->$' <<< "$body" || true)"
  [[ "$digest_count" == "$valid_digest_count" && "$valid_digest_count" -le 1 ]] || {
    echo "Release $tag contains invalid container digest metadata" >&2
    return 1
  }
  MANAGED_RELEASE_CONTAINER_DIGEST=""
  if [[ "$release_draft" == true ]]; then
    [[ "$valid_digest_count" == 0 ]] || {
      echo "Draft Release $tag cannot claim a published container digest" >&2
      return 1
    }
  else
    [[ "$valid_digest_count" == 1 ]] || {
      echo "Published Release $tag must contain exactly one container digest" >&2
      return 1
    }
    MANAGED_RELEASE_CONTAINER_DIGEST="$(sed -n 's/^<!-- container-digest:\(sha256:[0-9a-f]\{64\}\) -->$/\1/p' <<< "$body")"
  fi

  completion_count="$(count_literal_occurrences "$body" '<!-- release-complete:')"
  valid_completion_count="$(grep -Ec '^<!-- release-complete:[0-9a-f]{40} -->$' <<< "$body" || true)"
  [[ "$completion_count" == "$valid_completion_count" && "$valid_completion_count" -le 1 ]] || {
    echo "Release $tag contains invalid completion metadata" >&2
    return 1
  }
  MANAGED_RELEASE_COMPLETE=false
  if [[ "$valid_completion_count" == 1 ]]; then
    completion_sha="$(sed -n 's/^<!-- release-complete:\([0-9a-f]\{40\}\) -->$/\1/p' <<< "$body")"
    [[ "$completion_sha" == "$sha" ]] || { echo "Release $tag completion metadata targets another commit" >&2; return 1; }
    [[ "$release_draft" == false ]] || { echo "Draft Release $tag cannot be marked complete" >&2; return 1; }
    MANAGED_RELEASE_COMPLETE=true
  fi

  MANAGED_RELEASE_ID="$release_id"
  MANAGED_RELEASE_DRAFT="$release_draft"
  MANAGED_RELEASE_PR_NUMBER="$release_pr_lines"
}

parse_managed_release() {
  local tag="$1"
  jq -ce --arg tag "$tag" '
    [.[][] | select(.tag_name == $tag)] as $matches |
    if ($matches | length) == 1 then $matches[0]
    elif ($matches | length) == 0 then error("managed release not found")
    else error("multiple releases use the same tag") end
  '
}

managed_release() {
  local tag="$1"
  : "${RELEASE_POLICY_TOKEN:?RELEASE_POLICY_TOKEN is required}"
  GH_TOKEN="$RELEASE_POLICY_TOKEN" gh api --paginate --slurp \
    "repos/$GITHUB_REPOSITORY/releases?per_page=100" | parse_managed_release "$tag"
}

validate_publish_release() {
  local version="$1" tag release_json release_pr_number release_id release_draft tag_sha checkout_sha committed_version

  : "${RELEASE_SHA:?RELEASE_SHA is required}"
  : "${RELEASE_TAG:?RELEASE_TAG is required}"
  : "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
  valid_product_version "$version" || { echo "Publish version is invalid: $version" >&2; return 1; }
  validate_policy_token_identity || return 1
  validate_repository_release_policy || return 1

  tag="v$version"
  [[ "$RELEASE_TAG" == "$tag" ]] || { echo "Release ref $RELEASE_TAG does not match $tag" >&2; return 1; }
  git_remote fetch --force origin main --tags || return 1
  checkout_sha="$(git rev-parse HEAD)" || return 1
  tag_sha="$(git rev-list -n 1 "refs/tags/$tag" 2>/dev/null || true)"
  [[ "$checkout_sha" == "$RELEASE_SHA" && "$tag_sha" == "$RELEASE_SHA" ]] || {
    echo "Release tag $tag, checkout and resolved SHA do not identify the same commit" >&2
    return 1
  }
  git merge-base --is-ancestor "$RELEASE_SHA" origin/main || {
    echo "Release commit $RELEASE_SHA is not on main" >&2
    return 1
  }
  committed_version="$(cargo_version)" || {
    echo "Unable to read the committed server version" >&2
    return 1
  }
  [[ "$committed_version" == "$version" ]] || { echo "Committed server version does not match $tag" >&2; return 1; }

  release_json="$(managed_release "$tag")" || {
    echo "Release Manager did not create the required Release $tag" >&2
    return 1
  }
  validate_managed_release_metadata "$release_json" "$version" "$RELEASE_SHA" || return 1
  release_id="$MANAGED_RELEASE_ID"
  release_draft="$MANAGED_RELEASE_DRAFT"
  release_pr_number="$MANAGED_RELEASE_PR_NUMBER"

  validate_release_pr "$release_pr_number" merged false false || return 1
  [[ "$VALIDATED_RELEASE_SHA" == "$RELEASE_SHA" && "$VALIDATED_RELEASE_VERSION" == "$version" ]] || {
    echo "Release PR #$release_pr_number does not authorize $tag at $RELEASE_SHA" >&2
    return 1
  }

  {
    echo "release-id=$release_id"
    echo "release-draft=$release_draft"
    echo "release-digest=$MANAGED_RELEASE_CONTAINER_DIGEST"
    echo "release-pr-number=$release_pr_number"
    echo "validation-run-id=$RELEASE_VALIDATION_RUN_ID"
  } >> "$GITHUB_OUTPUT"
  echo "Validated managed release $tag from PR #$release_pr_number"
}

mark_publish_complete() {
  local version="$1" release_json body marker payload

  validate_publish_release "$version" || return 1
  release_json="$(GH_TOKEN="$RELEASE_POLICY_TOKEN" gh api "repos/$GITHUB_REPOSITORY/releases/$MANAGED_RELEASE_ID")" || {
    echo "Unable to read Release v$version before recording completion" >&2
    return 1
  }
  validate_managed_release_metadata "$release_json" "$version" "$RELEASE_SHA" "$MANAGED_RELEASE_PR_NUMBER" || return 1
  [[ "$MANAGED_RELEASE_DRAFT" == false ]] || { echo "Release v$version is still a draft" >&2; return 1; }

  if [[ "$MANAGED_RELEASE_COMPLETE" != true ]]; then
    body="$(jq -r '.body // ""' <<< "$release_json")"
    marker="<!-- release-complete:$RELEASE_SHA -->"
    body="$(printf '%s\n\n%s\n' "$body" "$marker")"
    payload="$(jq -nc --arg body "$body" '{body:$body}')"
    GH_TOKEN="$RELEASE_POLICY_TOKEN" gh api -X PATCH \
      "repos/$GITHUB_REPOSITORY/releases/$MANAGED_RELEASE_ID" --input - <<< "$payload" >/dev/null || {
      echo "Unable to record completion for Release v$version" >&2
      return 1
    }
  fi

  release_json="$(GH_TOKEN="$RELEASE_POLICY_TOKEN" gh api "repos/$GITHUB_REPOSITORY/releases/$MANAGED_RELEASE_ID")" || {
    echo "Unable to re-read Release v$version after recording completion" >&2
    return 1
  }
  validate_managed_release_metadata "$release_json" "$version" "$RELEASE_SHA" "$MANAGED_RELEASE_PR_NUMBER" || return 1
  [[ "$MANAGED_RELEASE_DRAFT" == false && "$MANAGED_RELEASE_COMPLETE" == true ]] || {
    echo "Release v$version did not reach the completed state" >&2
    return 1
  }
  remove_pending_label "$MANAGED_RELEASE_PR_NUMBER" || return 1
  echo "Recorded completed publication for v$version"
}

reconcile_latest_release() {
  local version="$1" release_json highest_record highest_tag highest_digest latest_tag

  validate_publish_release "$version" || return 1
  release_json="$(GH_TOKEN="$RELEASE_POLICY_TOKEN" gh api \
    "repos/$GITHUB_REPOSITORY/releases/$MANAGED_RELEASE_ID")" || {
    echo "Unable to read Release v$version before reconciling latest" >&2
    return 1
  }
  validate_managed_release_metadata \
    "$release_json" "$version" "$RELEASE_SHA" "$MANAGED_RELEASE_PR_NUMBER" || return 1
  [[ "$MANAGED_RELEASE_DRAFT" == false && "$MANAGED_RELEASE_COMPLETE" == true ]] || {
    echo "Only a completed immutable release can participate in latest selection" >&2
    return 1
  }

  highest_record="$(
    GH_TOKEN="$RELEASE_POLICY_TOKEN" gh api --paginate --slurp \
      "repos/$GITHUB_REPOSITORY/releases?per_page=100" |
      jq -r '
        [
          .[][] |
          select(.draft == false and .immutable == true) |
          (.tag_name // "") as $tag |
          ($tag | capture(
            "^v(?<major>0|[1-9][0-9]*)\\.(?<minor>0|[1-9][0-9]*)\\.(?<patch>0|[1-9][0-9]*)$"
          )) as $version |
          (.target_commitish // "") as $sha |
          (.body // "") as $body |
          select($sha | test("^[0-9a-f]{40}$")) |
          select(
            ([
              $body | split("\n")[] |
              select(. == ("<!-- release-complete:" + $sha + " -->"))
            ] | length) == 1
          ) |
          ([
            $body | split("\n")[] |
            capture("^<!-- container-digest:(?<digest>sha256:[0-9a-f]{64}) -->$")
          ]) as $digests |
          select(($digests | length) == 1) |
          {
            tag: $tag,
            major: ($version.major | tonumber),
            minor: ($version.minor | tonumber),
            patch: ($version.patch | tonumber),
            digest: $digests[0].digest
          }
        ] |
        sort_by(.major, .minor, .patch) |
        last |
        if . == null then empty else [.tag, .digest] | @tsv end
      '
  )" || {
    echo "Unable to resolve the highest completed stable release" >&2
    return 1
  }
  IFS=$'\t' read -r highest_tag highest_digest <<< "$highest_record"
  [[ "$highest_tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
    echo "No completed stable release is eligible for latest" >&2
    return 1
  }
  [[ "$highest_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo "Latest-eligible release has no valid container digest" >&2
    return 1
  }
  GH_TOKEN="$RELEASE_POLICY_TOKEN" gh release edit "$highest_tag" \
    --repo "$GITHUB_REPOSITORY" --latest >/dev/null || {
    echo "Unable to set latest to $highest_tag" >&2
    return 1
  }
  latest_tag="$(
    GH_TOKEN="$RELEASE_POLICY_TOKEN" gh api \
      "repos/$GITHUB_REPOSITORY/releases/latest" --jq '.tag_name // empty'
  )" || {
    echo "Unable to read back the latest release" >&2
    return 1
  }
  [[ "$latest_tag" == "$highest_tag" ]] || {
    echo "Latest readback differs: expected $highest_tag, found $latest_tag" >&2
    return 1
  }
  {
    echo "latest-tag=$highest_tag"
    echo "latest-version=${highest_tag#v}"
    echo "latest-digest=$highest_digest"
    if [[ "$highest_tag" == "v$version" ]]; then
      echo "owns-latest=true"
    else
      echo "owns-latest=false"
    fi
  } >> "$GITHUB_OUTPUT"
  echo "Latest stable release resolves to $highest_tag"
}

parse_release_record() {
  local tag="$1"
  jq -r --arg tag "$tag" '
    [.[][] | select(.tag_name == $tag)] as $matches |
    if ($matches | length) == 0 then empty
    elif ($matches | length) == 1 then
      $matches[0] | [.id, .draft, .target_commitish] | @tsv
    else error("multiple releases use the same tag") end
  '
}

release_record() {
  local tag="$1"
  gh api --paginate --slurp "repos/$GITHUB_REPOSITORY/releases?per_page=100" | parse_release_record "$tag"
}

release_transition() {
  local expected_sha="$1" tag_sha="$2" release_id="$3" release_draft="$4" release_target="$5"
  if [[ -n "$tag_sha" && "$tag_sha" != "$expected_sha" ]]; then
    echo conflict
  elif [[ -n "$release_id" && "$release_target" != "$expected_sha" ]]; then
    echo conflict
  elif [[ -z "$tag_sha" && -z "$release_id" ]]; then
    echo create
  elif [[ -n "$tag_sha" && -z "$release_id" ]]; then
    echo create-release
  elif [[ -z "$tag_sha" && "$release_draft" == true ]]; then
    echo create-tag
  elif [[ -z "$tag_sha" ]]; then
    echo conflict
  elif [[ "$release_draft" == true ]]; then
    echo prepared
  else
    echo published
  fi
}

load_release_state() {
  local tag="$1" row
  RELEASE_TAG_SHA="$(git rev-list -n 1 "refs/tags/$tag" 2>/dev/null || true)"
  row="$(release_record "$tag")" || {
    echo "Unable to read Release state for $tag" >&2
    return 1
  }
  RELEASE_ID=""
  RELEASE_DRAFT=""
  RELEASE_TARGET=""
  if [[ -n "$row" ]]; then
    IFS=$'\t' read -r RELEASE_ID RELEASE_DRAFT RELEASE_TARGET <<< "$row"
  fi
}

observe_release_transition() {
  local sha="$1" tag="$2"
  git_remote fetch --force origin main --tags || return 1
  load_release_state "$tag" || return 1
  RELEASE_TRANSITION="$(release_transition "$sha" "$RELEASE_TAG_SHA" "$RELEASE_ID" "$RELEASE_DRAFT" "$RELEASE_TARGET")" || return 1
}

wait_for_release_transition() {
  local sha="$1" tag="$2" previous="$3" attempt attempts=1
  [[ "${GITHUB_ACTIONS:-}" == true ]] && attempts=11
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    observe_release_transition "$sha" "$tag" || return 1
    [[ "$RELEASE_TRANSITION" == "$previous" ]] || return 0
    if ((attempt < attempts)); then
      sleep 3
    fi
  done
  echo "Release $tag did not advance from $previous after bounded observation" >&2
  return 1
}

write_release_notes() {
  local version="$1" number="$2" sha="$3" destination="$4"
  awk -v marker="## [$version] -" '
    index($0, marker) == 1 { capture = 1 }
    capture && index($0, "## [") == 1 && index($0, marker) != 1 { exit }
    capture { print }
  ' CHANGELOG.md > "$destination"
  [[ -s "$destination" ]] || { echo "Unable to extract release notes for v$version" >&2; return 1; }
  printf '\n<!-- release-pr:%s -->\n<!-- release-commit:%s -->\n' "$number" "$sha" >> "$destination"
}

ensure_release() {
  local number="$1" sha="$2" version="$3" tag transition notes release_json mutation_status
  tag="v$version"
  RELEASE_STATE=""

  observe_release_transition "$sha" "$tag" || return 1
  for _ in 1 2 3; do
    transition="$RELEASE_TRANSITION"
    mutation_status=0

    case "$transition" in
      create)
        notes="$RUNNER_TEMP/release-notes.md"
        write_release_notes "$version" "$number" "$sha" "$notes" || return 1
        gh release create "$tag" --repo "$GITHUB_REPOSITORY" --target "$sha" --draft \
          --title "Camellia Nexus Management Server $version" --notes-file "$notes" >/dev/null || mutation_status=$?
        ;;
      create-release)
        notes="$RUNNER_TEMP/release-notes.md"
        write_release_notes "$version" "$number" "$sha" "$notes" || return 1
        gh release create "$tag" --repo "$GITHUB_REPOSITORY" --verify-tag --target "$sha" --draft \
          --title "Camellia Nexus Management Server $version" --notes-file "$notes" >/dev/null || mutation_status=$?
        ;;
      create-tag)
        git_remote push origin "$sha:refs/tags/$tag" || mutation_status=$?
        ;;
      conflict)
        echo "Existing $tag tag or release does not match $sha" >&2
        return 1
        ;;
      prepared|published)
        release_json="$(gh api "repos/$GITHUB_REPOSITORY/releases/$RELEASE_ID")" || {
          echo "Unable to re-read managed Release $tag" >&2
          return 1
        }
        validate_managed_release_metadata "$release_json" "$version" "$sha" "$number" || return 1
        [[ "$MANAGED_RELEASE_ID" == "$RELEASE_ID" ]] || {
          echo "Release $tag identity changed during reconciliation" >&2
          return 1
        }
        RELEASE_STATE="$transition"
        if [[ "$transition" == prepared ]]; then
          echo "Release $tag is prepared at $sha"
        else
          echo "Release $tag is already published at $sha"
        fi
        return 0
        ;;
      *)
        echo "Unknown release transition: $transition" >&2
        return 1
        ;;
    esac
    if ! wait_for_release_transition "$sha" "$tag" "$transition"; then
      if ((mutation_status != 0)); then
        echo "Release $tag $transition mutation exited with status $mutation_status" >&2
      fi
      return 1
    fi
  done

  echo "Release $tag did not converge to a stable state" >&2
  return 1
}

remove_pending_label() {
  local number="$1" pr_json
  pr_json="$(gh api "repos/$GITHUB_REPOSITORY/pulls/$number")" || {
    echo "Unable to read Release PR #$number before completing it" >&2
    return 1
  }
  if has_label "$pr_json" "$pending_label"; then
    gh api -X DELETE "repos/$GITHUB_REPOSITORY/issues/$number/labels/release%3Apending" >/dev/null || {
      echo "Unable to complete Release PR #$number" >&2
      return 1
    }
  fi
}

managed_release_pr_records() {
  local owner pages
  owner="${GITHUB_REPOSITORY%%/*}"
  [[ -n "$owner" && "$GITHUB_REPOSITORY" == */* ]] || {
    echo 'GITHUB_REPOSITORY must identify an owner and repository' >&2
    return 1
  }
  pages="$(gh api --paginate --slurp -X GET "repos/$GITHUB_REPOSITORY/pulls" \
    -f state=closed -f base=main -f "head=$owner:$branch" -F per_page=100)" || {
    echo 'Unable to list managed Release PRs' >&2
    return 1
  }
  jq -c \
    --arg branch "$branch" \
    --arg pending "$pending_label" \
    --arg repository "$GITHUB_REPOSITORY" \
    '
      if type == "array" and all(.[]; type == "array") then
        [
          .[][] |
          select(.merged_at != null) |
          {
            number,
            state,
            baseRef: .base.ref,
            headRef: .head.ref,
            headRepository: (.head.repo.full_name // ""),
            mergedAt: .merged_at,
            mergeSha: .merge_commit_sha,
            pending: any(.labels[]?; .name == $pending)
          }
        ] as $records |
        if all($records[];
          (.number | type) == "number" and .number > 0 and
          .state == "closed" and
          .baseRef == "main" and
          .headRef == $branch and
          .headRepository == $repository and
          (.mergedAt | type) == "string" and
          (.mergeSha | type) == "string" and (.mergeSha | test("^[0-9a-f]{40}$")) and
          (.pending | type) == "boolean"
        ) and (($records | unique_by(.number) | length) == ($records | length)) then
          $records |
          map({number, mergedAt, mergeSha, pending}) |
          sort_by(.mergedAt, .number)
        else
          error("GitHub returned invalid merged Release PR metadata")
        end
      else
        error("GitHub returned an invalid merged Release PR page shape")
      end
    ' <<< "$pages" || {
    echo 'Unable to normalize merged Release PR candidates' >&2
    return 1
  }
}

resolve_merged_release_pr() {
  local sha="$1" records matches count attempt attempts=1
  [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || {
    echo 'Merged Release PR resolution requires an exact commit SHA' >&2
    return 1
  }
  [[ "${GITHUB_ACTIONS:-}" == true ]] && attempts=11
  for ((attempt = 1; attempt <= attempts; attempt++)); do
    records="$(managed_release_pr_records)" || return 1
    matches="$(jq -c --arg sha "$sha" '[.[] | select(.mergeSha == $sha)]' <<< "$records")" || return 1
    count="$(jq -r 'length' <<< "$matches")" || return 1
    case "$count" in
      1)
        jq -r '.[0].number' <<< "$matches"
        return 0
        ;;
      0)
        if ((attempt < attempts)); then
          sleep 3
          continue
        fi
        ;;
      *)
        echo "Multiple managed Release PRs resolve to $sha" >&2
        return 1
        ;;
    esac
  done
  echo "No managed merged Release PR resolves to $sha" >&2
  return 1
}

merged_release_pr_candidates() {
  local main_sha records
  main_sha="$(git rev-parse origin/main)" || return 1
  [[ "$main_sha" =~ ^[0-9a-f]{40}$ ]] || {
    echo 'origin/main does not resolve to an exact commit SHA' >&2
    return 1
  }
  records="$(managed_release_pr_records)" || return 1
  jq -r --arg main "$main_sha" '.[] | select(.pending or .mergeSha == $main) | .number' <<< "$records"
}

recover_pending_releases() {
  local number sha numbers pr_json
  local -a pending_numbers=()
  RECOVERY_STATE=none
  numbers="$(merged_release_pr_candidates)" || return 1
  while IFS= read -r number; do
    [[ -n "$number" ]] || continue
    pr_json="$(gh api "repos/$GITHUB_REPOSITORY/pulls/$number")" || {
      echo "Unable to read pending release PR #$number" >&2
      return 1
    }
    has_label "$pr_json" "$pending_label" && pending_numbers+=("$number")
  done <<< "$numbers"
  ((${#pending_numbers[@]} <= 1)) || {
    echo 'Multiple merged Release PRs are pending; operator reconciliation is required' >&2
    return 1
  }

  for number in "${pending_numbers[@]}"; do
    pr_json="$(gh api "repos/$GITHUB_REPOSITORY/pulls/$number")" || {
      echo "Unable to re-read pending Release PR #$number" >&2
      return 1
    }
    has_label "$pr_json" "$pending_label" || continue
    sha="$(jq -r '.merge_commit_sha // empty' <<< "$pr_json")"
    [[ -n "$sha" ]] || { echo "Pending release PR #$number has no merge commit" >&2; return 1; }
    git merge-base --is-ancestor "$sha" origin/main || { echo "Pending release PR #$number is not on main" >&2; return 1; }
    git checkout --detach "$sha" >/dev/null || return 1
    validate_release_pr "$number" merged || return 1
    ensure_release "$VALIDATED_PR_NUMBER" "$VALIDATED_RELEASE_SHA" "$VALIDATED_RELEASE_VERSION" || return 1
    if [[ "$RELEASE_STATE" == prepared ]]; then
      RECOVERY_STATE=prepared
      return 0
    fi
    if [[ "$MANAGED_RELEASE_COMPLETE" != true ]]; then
      echo "Published release v$VALIDATED_RELEASE_VERSION has no completion proof; rerun its tag workflow" >&2
      RECOVERY_STATE=incomplete
      return 0
    fi
    remove_pending_label "$number" || return 1
    git checkout --detach origin/main >/dev/null || return 1
  done
}

close_stale_release_pr() {
  local number locked
  number="$(gh pr list --repo "$GITHUB_REPOSITORY" --state open --base main --head "$branch" --json number --jq '.[0].number // empty')" || {
    echo 'Unable to find an open Release PR' >&2
    return 1
  }
  [[ -n "$number" ]] || return 0
  locked="$(gh api "repos/$GITHUB_REPOSITORY/issues/$number/labels" --jq 'any(.[]; .name == "release:version-locked")')" || {
    echo "Unable to read labels for Release PR #$number" >&2
    return 1
  }
  [[ "$locked" == false ]] || { echo "Release PR #$number is version-locked; leaving it open"; return 0; }
  gh api -X PATCH "repos/$GITHUB_REPOSITORY/pulls/$number" -f state=closed >/dev/null || return 1
  gh api -X DELETE "repos/$GITHUB_REPOSITORY/git/refs/heads/$branch" >/dev/null 2>&1 || true
  echo "Closed stale release PR #$number"
}

manage_release() {
  local requested_version="${REQUESTED_VERSION:-}" open_pr open_pr_json open_pr_title open_pr_body
  local open_pr_draft created_pr_json
  local proposal_sha proposal_parent proposal_version existing_version automatic_version target_version remote_sha body changed_files
  local baseline baseline_version baseline_sha
  local locked=false target_locked=false current_contract=false provenance_status
  : "${RUNNER_TEMP:?RUNNER_TEMP is required}"
  if [[ "${GITHUB_EVENT_NAME:-}" == repository_dispatch && -z "$requested_version" ]]; then
    echo 'A release-request dispatch must provide client_payload.version' >&2
    return 1
  fi
  validate_repository_release_policy || return 1
  git_remote fetch --force origin main --tags || return 1
  recover_pending_releases || return 1
  if [[ "$RECOVERY_STATE" == prepared ]]; then
    exit 0
  fi
  if [[ "$RECOVERY_STATE" == incomplete ]]; then
    return 1
  fi

  provenance_status=0
  resolve_validation_provenance || provenance_status=$?
  [[ "$provenance_status" == 0 ]] || {
    [[ "$provenance_status" == 2 ]] && exit 0
    return "$provenance_status"
  }

  git checkout -B main origin/main >/dev/null || return 1
  automatic_version="$(automatic_release_version HEAD)" || return 1
  automatic_version="${automatic_version#v}"
  valid_product_version "$automatic_version" || { echo "git-cliff proposed invalid version: $automatic_version" >&2; return 1; }
  target_version="$automatic_version"
  if [[ -n "$requested_version" ]]; then
    valid_product_version "$requested_version" || {
      echo "Override must be canonical stable SemVer within Cargo's u64 limits" >&2
      return 1
    }
    version_ge "$requested_version" "$automatic_version" || {
      echo "Override $requested_version is below automatic minimum $automatic_version" >&2
      return 1
    }
    target_version="$requested_version"
    target_locked=true
  fi

  baseline="$(committed_release_baseline HEAD)" || return 1
  if [[ -n "$baseline" ]]; then
    IFS=$'\t' read -r baseline_version baseline_sha <<< "$baseline"
    if [[ "$target_version" == "$baseline_version" ]]; then
      if [[ -n "$requested_version" ]]; then
        echo "Release version v$target_version is already recorded and cannot be reused" >&2
        return 1
      fi
      close_stale_release_pr || return 1
      echo "No releasable changes after recorded v$baseline_version"
      exit 0
    fi
    version_ge "$target_version" "$baseline_version" || {
      echo "Release version v$target_version is older than recorded v$baseline_version" >&2
      return 1
    }
  fi

  open_pr="$(gh pr list --repo "$GITHUB_REPOSITORY" --state open --base main --head "$branch" \
    --limit 2 --json number --jq '
      if length > 1 then error("multiple open Release PRs use release/next")
      elif length == 1 then .[0].number
      else empty
      end
    ')" || {
    echo 'Unable to resolve the current open Release PR' >&2
    return 1
  }
  if [[ -n "$open_pr" ]]; then
    open_pr_json="$(gh api "repos/$GITHUB_REPOSITORY/pulls/$open_pr")" || {
      echo "Unable to read open Release PR #$open_pr" >&2
      return 1
    }
    validate_open_release_pr_envelope "$open_pr" "$open_pr_json" true || return 1
    open_pr_title="$(jq -r '.title // ""' <<< "$open_pr_json")"
    open_pr_body="$(jq -r '.body // ""' <<< "$open_pr_json")"
    open_pr_draft="$(jq -r '.draft | if . == true then "true" elif . == false then "false" else empty end' <<< "$open_pr_json")"
    [[ -n "$open_pr_draft" ]] || { echo "Release PR #$open_pr has invalid draft metadata" >&2; return 1; }
    proposal_sha="$(jq -r '.head.sha // ""' <<< "$open_pr_json")"
    validate_release_proposal_commit "$proposal_sha" || return 1
    proposal_parent="$RELEASE_PROPOSAL_PARENT"
    proposal_version="$RELEASE_PROPOSAL_VERSION"

    if has_label "$open_pr_json" "$lock_label"; then
      locked=true
      target_locked=true
    fi
    if [[ -z "$requested_version" && "$locked" == true ]]; then
      version_ge "$proposal_version" "$automatic_version" || {
        echo "Locked version $proposal_version is below automatic minimum $automatic_version" >&2
        return 1
      }
      target_version="$proposal_version"
    fi

    if [[ "$proposal_parent" == "$RELEASE_VALIDATED_SHA" ]]; then
      if [[ "$open_pr_title" == "$RELEASE_PROPOSAL_TITLE" ]] &&
        has_label "$open_pr_json" "$pending_label" &&
        parse_release_provenance "$open_pr_body" >/dev/null 2>&1 &&
        [[ "$RELEASE_BASE_SHA" == "$RELEASE_VALIDATED_SHA" ]]; then
        current_contract=true
      fi
      if [[ "$current_contract" == true ]]; then
        git_remote fetch --force origin "refs/heads/$branch:refs/remotes/origin/$branch" || return 1
        git checkout --detach "refs/remotes/origin/$branch" >/dev/null || return 1
        validate_release_pr "$open_pr" open true || return 1
        existing_version="$VALIDATED_RELEASE_VERSION"
        git checkout -B main origin/main >/dev/null || return 1
        if [[ -z "$requested_version" || "$requested_version" == "$existing_version" ]]; then
          if [[ "$target_locked" == true && "$locked" == false ]]; then
            gh api -X POST "repos/$GITHUB_REPOSITORY/issues/$open_pr/labels" -f "labels[]=$lock_label" >/dev/null || return 1
          fi
          if [[ "$open_pr_draft" == true ]]; then
            gh pr ready "$open_pr" --repo "$GITHUB_REPOSITORY" >/dev/null || return 1
          fi
          echo "Release PR #$open_pr already represents validated main at v$existing_version"
          exit 0
        fi
      fi
    fi
  fi

  if git show-ref --verify --quiet "refs/tags/v$target_version"; then
    close_stale_release_pr || return 1
    echo "No releasable changes after v$target_version"
    exit 0
  fi

  git checkout -B "$branch" origin/main >/dev/null || return 1
  set_release_version "$target_version" || return 1
  generate_changelog "$target_version" CHANGELOG.md "$RELEASE_VALIDATED_SHA" || return 1
  changed_files="$(git diff --name-only)" || return 1
  while IFS= read -r file; do
    case "$file" in Cargo.toml|Cargo.lock|CHANGELOG.md) ;; *) echo "Release generation changed forbidden file: $file" >&2; exit 1 ;; esac
  done <<< "$changed_files"
  if git diff --quiet; then
    close_stale_release_pr || return 1
    echo "No releasable changes for v$target_version"
    exit 0
  fi

  : "${RELEASE_APP_EMAIL:?RELEASE_APP_EMAIL is required}"
  git config user.name "$RELEASE_APP_LOGIN" || return 1
  git config user.email "$RELEASE_APP_EMAIL" || return 1
  git add Cargo.toml Cargo.lock CHANGELOG.md || return 1
  git commit --no-gpg-sign -m "chore(release): v$target_version" || return 1
  remote_sha="$(git_remote ls-remote --heads origin "refs/heads/$branch" | awk '{print $1}')" || return 1

  body="$(printf '%s\n\n%s\n\n%s\n\n<!-- release-base:%s -->\n<!-- release-validation-run:%s -->\n' \
    "Automated release proposal for **v$target_version**." \
    "Merge only after the focused release checks pass. The trusted main workflow creates the draft release and tag; the tag workflow publishes the verified image." \
    "License-server and client versions advance independently." \
    "$RELEASE_VALIDATED_SHA" "$RELEASE_VALIDATED_RUN_ID")" || return 1
  if [[ -z "$open_pr" ]]; then
    git_remote push --force-with-lease="refs/heads/$branch:$remote_sha" origin "HEAD:refs/heads/$branch" || return 1
    created_pr_json="$(gh api -X POST "repos/$GITHUB_REPOSITORY/pulls" \
      -f base=main -f "body=$body" -F draft=true -f "head=$branch" \
      -f "title=chore(release): v$target_version")" || {
      echo 'Unable to create the draft Release PR' >&2
      return 1
    }
    open_pr="$(jq -r '.number // empty' <<< "$created_pr_json")"
    [[ "$open_pr" =~ ^[1-9][0-9]*$ ]] || { echo 'GitHub returned no Release PR identity' >&2; return 1; }
    validate_open_release_pr_envelope "$open_pr" "$created_pr_json" true || return 1
    [[ "$(jq -r '.draft // false' <<< "$created_pr_json")" == true ]] || { echo "Release PR #$open_pr was not created as a draft" >&2; return 1; }
    gh api -X POST "repos/$GITHUB_REPOSITORY/issues/$open_pr/labels" -f "labels[]=$pending_label" >/dev/null || return 1
    if [[ "$target_locked" == true ]]; then
      gh api -X POST "repos/$GITHUB_REPOSITORY/issues/$open_pr/labels" -f "labels[]=$lock_label" >/dev/null || return 1
    fi
    gh pr ready "$open_pr" --repo "$GITHUB_REPOSITORY" >/dev/null || return 1
  else
    gh api -X PATCH "repos/$GITHUB_REPOSITORY/pulls/$open_pr" \
      -f "title=chore(release): v$target_version" -f "body=$body" >/dev/null || return 1
    gh api -X POST "repos/$GITHUB_REPOSITORY/issues/$open_pr/labels" -f "labels[]=$pending_label" >/dev/null || return 1
    if [[ "$target_locked" == true ]]; then
      gh api -X POST "repos/$GITHUB_REPOSITORY/issues/$open_pr/labels" -f "labels[]=$lock_label" >/dev/null || return 1
    fi
    git_remote push --force-with-lease="refs/heads/$branch:$remote_sha" origin "HEAD:refs/heads/$branch" || return 1
    if [[ "$open_pr_draft" == true ]]; then
      gh pr ready "$open_pr" --repo "$GITHUB_REPOSITORY" >/dev/null || return 1
    fi
  fi
  echo "Updated release PR #$open_pr for v$target_version"
}

main() {
  local command="${1:-manage}"
  : "${GH_TOKEN:?GH_TOKEN is required}"
  : "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
  if [[ "$command" != resolve-merged-pr ]]; then
    : "${RELEASE_APP_LOGIN:?RELEASE_APP_LOGIN is required}"
  fi
  case "$command" in
    resolve-merged-pr)
      resolve_merged_release_pr "${2:-}"
      ;;
    manage)
      manage_release
      ;;
    validate-policy)
      validate_policy_token_identity
      validate_repository_release_policy
      echo "Validated repository release policy"
      ;;
    merge-ready)
      release_merge_ready
      ;;
    validate-pr)
      : "${RELEASE_PR_NUMBER:?RELEASE_PR_NUMBER is required}"
      git_remote fetch --force origin main --tags
      validate_release_pr "$RELEASE_PR_NUMBER" open
      echo "Validated release PR #$VALIDATED_PR_NUMBER for v$VALIDATED_RELEASE_VERSION"
      ;;
    validate-main)
      : "${RELEASE_PR_NUMBER:?RELEASE_PR_NUMBER is required}"
      git_remote fetch --force origin main --tags
      validate_release_pr "$RELEASE_PR_NUMBER" merged
      echo "Validated merged release PR #$VALIDATED_PR_NUMBER for v$VALIDATED_RELEASE_VERSION"
      ;;
    merge-approved)
      validate_policy_token_identity
      merge_approved_release
      ;;
    validate-publish)
      : "${EXPECTED_VERSION:?EXPECTED_VERSION is required}"
      validate_publish_release "$EXPECTED_VERSION"
      ;;
    complete-publish)
      : "${EXPECTED_VERSION:?EXPECTED_VERSION is required}"
      mark_publish_complete "$EXPECTED_VERSION"
      ;;
    reconcile-latest)
      : "${EXPECTED_VERSION:?EXPECTED_VERSION is required}"
      reconcile_latest_release "$EXPECTED_VERSION"
      ;;
    *) echo "Usage: $0 [manage|resolve-merged-pr|validate-policy|merge-ready|validate-pr|validate-main|merge-approved|validate-publish|complete-publish|reconcile-latest]" >&2; exit 2 ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
