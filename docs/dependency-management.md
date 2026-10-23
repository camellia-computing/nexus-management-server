# Dependency and Toolchain Management

This policy keeps server, administration UI, database-test, and container builds reproducible while preserving normal dependency maintenance. The server and desktop client have independent product versions; this repository's stable SemVer is owned by the root `Cargo.toml`.

## Canonical version sources

| Concern | Canonical source | Policy |
| --- | --- | --- |
| Rust toolchain | `rust-toolchain.toml` | Exact stable patch, including required components |
| Rust minimum version | Root `Cargo.toml` `rust-version` | Must match the toolchain major and minor |
| Node.js | `.node-version` | Exact 24.x LTS patch; the Docker builder uses the same value |
| Supported Node.js range | `admin-ui/package.json` `engines.node` | Current supported major only |
| pnpm | `admin-ui/package.json` `packageManager` | Exact patch; CI and Corepack read this field |
| JavaScript direct dependencies | `admin-ui/package.json` | Exact versions, with the lockfile fixing the full graph |
| Rust dependencies | Cargo manifests plus `Cargo.lock` | Normal Cargo-compatible ranges; the lockfile fixes builds |
| GitHub Actions | Workflow `uses` entries | Full commit SHA with a readable release comment |
| Workflow security tools | Quality workflow | Exact stable uv and zizmor releases; online pedantic findings fail CI |
| Container inputs | Dockerfile, Compose, and runtime-test image references | Readable tag plus immutable manifest digest; the production service image supports `linux/amd64` |
| Hosted runners | Workflow `runs-on` entries | Explicit image family; hosted image patching remains provider-managed |

Workflow files must not repeat Node.js, pnpm, or Rust version literals. `scripts/check-version-policy.sh` checks the canonical-file relationships, action and image immutability, blocking actionlint and zizmor gates, PostgreSQL parity between CI and Compose, Git revisions, and the exception register below. Use `scripts/update-toolchains.sh` for Node.js, pnpm, Rust, or PostgreSQL changes so every coupled source and digest is updated and validated as one worktree transaction.

## Update policy

Dependabot opens separate major upgrades and groups only compatible minor and patch updates. Cargo updates use a cooldown of 3 days for patches, 7 days for minors, and 30 days for majors. GitHub Actions, Docker, and Docker Compose use the supported 7-day default cooldown. Security updates are not delayed by this routine cooldown.

Automated commit titles use `build(deps)` for application and independently updatable container dependencies and `ci(deps)` for GitHub Actions. Reviewed coupled toolchain or image changes use `build(toolchain)`. An update that fixes a concrete product or security defect may instead use `fix(deps)` or `fix(security)`.

Every non-release pull request, including dependency, toolchain, image, and workflow updates, must pass the complete server, PostgreSQL, administration UI, browser, audit, and candidate-image gates. Frozen installation is followed by `pnpm peers check`, so a resolvable lockfile with an internally unsupported peer graph still fails. The exact `main` commit is validated again after merge. Trusted release proposals reuse the recorded validation of their exact base commit, validate only the generated release delta, and leave signing and publication to the protected tag workflow. Updates are never auto-merged. A maintainer reviews release notes, lockfile and image-digest scope, licensing, security impact, data-format or migration implications, and rollback risk. Node.js, pnpm, Rust, PostgreSQL, runner-family, base-image major, and major framework changes require an explicit compatibility review.

Dependabot updates the frontend's npm ecosystem, including its pnpm lockfile. Keep a single-document application lockfile: GitHub does not yet index the two-document format for dependency alerts and security updates. The version-policy gate rejects that format. The exact pnpm release remains owned by `packageManager`; coupled toolchain updates use `scripts/update-toolchains.sh`.

Rust and Node.js image tags are coupled to the canonical toolchain files, and the PostgreSQL image digest is shared by Compose and CI. Dependabot therefore ignores those three image inputs and does not update the Rust toolchain independently. Apply them atomically, supplying registry-resolved digests:

```bash
bash scripts/update-toolchains.sh \
  --node 24.22.1 --node-digest sha256:<64-hex-digest> \
  --rust 1.99.1 --rust-digest sha256:<64-hex-digest> \
  --postgres 18-alpine --postgres-digest sha256:<64-hex-digest> \
  --pnpm 11.28.7
```

The command rejects dirty target files, prepares every related edit, runs the version policy, and restores the original files if validation fails. Resolve each digest from the named upstream registry tag, review its manifest and release notes, and run the complete quality, PostgreSQL, administration UI, browser and container gates before merging. CI denies yanked Cargo packages in addition to audited vulnerabilities.

The evidence scanner tracks the latest patch of ClamAV 1.4 LTS until its August 2027
support boundary or a reviewed successor LTS migration. Compose uses the matching
`_base` image with a persistent signature volume; the disposable runtime gate uses
the database-preloaded image so each CI run does not download the complete signature
set. Both references use registry-resolved immutable digests, and the version policy
requires their exact patch versions to remain aligned.

## Exceptions

| Exception | Reason | Owner | Review by | Removal condition |
| --- | --- | --- | --- | --- |
| Checkout-relative workflow references | The released actionlint 1.7.12 rejects GitHub's self-repository syntax. Line-scoped zizmor annotations retain same-commit references without disabling other workflow checks. | Release maintainers | 2026-11-23 | Adopt self-repository references when a released actionlint validates them. |
| TypeScript 6.0.3 while TypeScript 7 is current | `svelte-check` 4.7.7 declares support for TypeScript 5 and 6 only. Moving the authoritative Svelte/TypeScript gate to an unsupported compiler major would make a green check non-contractual. | Admin UI maintainers | 2026-11-23 | Upgrade when a supported current `svelte-check` release declares TypeScript 7 compatibility, then run Svelte check, browser E2E, and the production container gates. |
| ClamAV 1.4 LTS while 1.5 is current | Upstream supports 1.4 with critical patches through 2027-08-15 and requires the latest 1.4 patch for signature access. The LTS line limits scanner feature churn while retaining current critical fixes. | Service maintainers | 2026-10-15 | Move to the next reviewed LTS, or earlier if upstream support, signature access, or a security advisory requires it; validate evidence scanning and the complete container gate. |
| `@napi-rs/wasm-runtime` 1.1.6 override | `@rolldown/binding-wasm32-wasi` 1.1.5 pins `@emnapi/core` and `@emnapi/runtime` 1.11.1 but its compatible range otherwise resolves `wasm-runtime` 1.2.0, which requires the incompatible pre-release emnapi 2.0 pair. The exact stable runtime removes peer drift from Vite's optional WASI fallback without introducing alpha dependencies. | Admin UI maintainers | 2026-09-15 | Remove the override when the current Rolldown WASI binding and runtime resolve one stable compatible emnapi generation, then require `pnpm peers check`, frontend build, browser E2E, and the production container gates. |
| Release merge `workflow_run` trigger | Approval and CI can complete in either order, so the merge controller must re-evaluate readiness after either event. The privileged path checks out only trusted `main` control, accepts only the same-repository `release/next` branch and exact successful CI SHA, revalidates approval and repository policy, and mints the scoped write token only after readiness succeeds. | Release maintainers | 2026-09-15 | Remove the trigger when GitHub provides an order-independent protected merge primitive that preserves the exact reviewed-SHA and trusted-control guarantees; otherwise re-audit every change to the merge controller or release readiness checks. |

No other ignored advisory, accepted maintenance warning, floating action, mutable external image, unbounded JavaScript range, or unpinned Git revision is permitted without a dated entry here.

## Hosted repository checklist

For every repository location used to run CI or publish a release, verify after the first push that:

- the dependency graph, vulnerability alerts, and automated security updates are enabled where the hosting plan provides them;
- branch protection requires the current gate job and prevents bypass of reviewed release changes;
- the release application variables and secrets are complete for that repository installation;
- workflow and package permissions remain least-privilege and publication environments retain their configured protections;
- a candidate run validates database services, the container build, and registry authentication before a production release.

These are repository capabilities, not account identities. Workflows must behave the same on any correctly configured repository and must not contain account- or remote-specific branches.
