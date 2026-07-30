# Camellia Nexus Management Server engineering guide

This file is the durable starting point for review and implementation in the management-server
repository. Keep it synchronized with the current service, administration UI, database schema,
deployment, and desktop contract. Do not record transient Actions runs, release digests, deployment
addresses, customer data, credentials, or machine-local procedures here.

## Product and authority model

- This service is the production authority for accounts, licenses, plans, activation codes, devices,
  refresh sessions, entitlement issuance, billing state, Team membership, cloud workspace data,
  control-plane identities, jobs, and audit evidence.
- The desktop and both Web UIs are untrusted clients. They present server-confirmed state but never
  decide commercial standing, roles, limits, trusted time, row versions, or mutation authorization.
- The public licensing listener and private administration listener are separate trust zones with
  independent ingress, origins, routes, cookies, rate limits, and readiness checks.
- PostgreSQL is the production source of truth. The in-memory repository exists only for isolated
  development/tests and does not provide replica-safe idempotency, rate limits, or trusted time.
- Client and server versions advance independently. Protocol compatibility is enforced with
  canonical client SemVer policy, not by coupling product versions.

## Runtime roles and repository map

- One Rust binary exposes `serve`, `migrate`, `admin-web`, `admin-worker`, `healthcheck`, and the
  hierarchical `admin` CLI. Help and version output must work before configuration/database startup.
- `src/domain.rs` and `src/contracts.rs`: authoritative domain and public wire models.
- `src/service.rs`: public activation, session, entitlement, billing, device, and orchestration rules.
- `src/store.rs`: in-memory/PostgreSQL repository implementations, transactions, trusted-time state,
  persistence, pagination, idempotency, rate limits, and readiness queries.
- `src/http.rs`: bounded public Axum router, middleware, protocol validation, error normalization,
  health/readiness, and public request handlers.
- `src/config.rs`, `src/crypto.rs`, `src/es256_provider.rs`, `src/plan_catalog.rs`,
  `src/time_format.rs`, and `src/request_id.rs`: validated configuration, cryptographic providers,
  fixed plan policy, canonical time input/output, and correlation metadata.
- `src/team.rs`, `src/workspace.rs`, and `src/webhooks.rs`: Team governance, cloud configuration/sync/
  alerts/audit, Webhook security, transactional outbox, delivery, and retention.
- `src/billing.rs`: offers, invoices, customer payment claims, and commercial transition rules.
- `src/admin_app.rs`, `src/admin_auth.rs`, `src/admin_identity.rs`, `src/admin_operation.rs`,
  `src/admin_storage.rs`, `src/admin_jobs.rs`, `src/admin_contracts.rs`, and `src/admin_http.rs`: the
  private control plane, authentication, authorization, secret delivery, object storage, bulk jobs,
  worker, typed contracts, and static Admin UI host.
- `src/admin.rs` and `src/cli_help.rs`: production CLI operations and strict bilingual help.
- Top-level and nested CLI help must remain available before environment, logging, keyring, or
  database initialization. Every runtime role and every declared Admin operation has authoritative
  bilingual usage, constraints, options, and examples derived from current handlers.
- `migrations/`: the normalized SQLx `0001_prelaunch_baseline` for this unreleased service. It covers
  licensing, trusted time, billing, Team, administrator identity/jobs/storage, governance, cloud
  workspace, and Webhooks. Once a release has deployed the baseline, every schema change must use a
  new immutable incrementing migration.
- `admin-ui`: SvelteKit static administration console with typed API contracts, localization,
  accessibility utilities, unit/static checks, deterministic Playwright tests, and a live final-image
  browser suite.
- `scripts`, `deploy`, `Dockerfile`, `docker-compose.yml`, and `.env.example`: local integration,
  disposable native-E2E environments, portable verified test bundles, secret generation, release
  policy, immutable image build, container/systemd deployment templates, and production examples.

## Public protocol surface

- Browser activation uses `/oauth/authorize` GET/POST with one exact scope
  `camellia.nexus.license`, Authorization Code, PKCE S256, bounded state, exact redirect matching, and
  strict rejection of unknown fields. It is not OIDC and does not issue ID tokens.
- Device lifecycle covers registration, activation verify/confirm, entitlement challenge/refresh/
  status, session recovery challenge/recovery, paginated device listing, proof-bound removal, logout,
  and liveness/readiness.
- Billing covers a device-proven summary and idempotent payment-evidence submission. Billing recovery
  authority does not grant protected product capabilities.
- Team governance covers profile/member pages, member updates, invitations, additional-device
  enrollment, voluntary leave, and ownership transfer. Every public Team write uses a canonical
  operation ID with transactional encrypted exact-response replay; ambiguous leave recovery is
  restricted to the original session/device plus matching member and row-version status query.
- Workspace cloud covers encrypted configuration documents/revisions/publish/delete/restore/purge,
  ordered sync changes/checkpoints, alert rules/incidents, bounded audit view/export, and Webhook
  endpoints/secret rotation/deletion/delivery metadata.
- Every sensitive public mutation requires a valid refresh session and a fresh, single-use,
  scope-bound device proof where the contract requires it. Consume and bind challenges atomically.
- Keep public JSON fields, error codes, HTTP statuses, pagination, body limits, and canonical forms
  stable. Unknown fields are rejected where strict protocol parsing is part of the security boundary.
- With both sibling repositories checked out, run `node scripts/check-cross-repo-contract.mjs` for
  every public protocol change. Keep the checker, semantic manifest, and mutation test byte-identical
  in both repositories; they verify serialized wire types, method/path pairs, proof scopes, limits,
  mutation/concurrency identities, and mapped business error codes.
- Do not reveal account existence, device state, database detail, signing state, or cryptographic
  validation detail before the required proof succeeds. Synthetic recovery subjects preserve response
  shape for unknown canonical device IDs.

## Activation, session, and entitlement invariants

- Activation codes are high-entropy, single-display values stored only as hashes plus safe metadata.
  Registration creates a pending device; code redemption occurs transactionally only after device
  proof and activation confirmation.
- Authorization codes and device challenges are short-lived and single-use. Identical registration
  retries may recover one already committed result only inside the fixed non-sliding ambiguity window.
- Refresh sessions rotate and belong to one device/family. Reuse detection revokes the family; older
  session records remain long enough to detect replay after absolute expiry.
- Device proofs use a registered P-256 public key and a canonical, domain-separated payload. Treat
  device IDs, public keys, thumbprints, app versions, scopes, nonces, and timestamps as untrusted until
  parsed and verified.
- Entitlements are ES256, signed with the configured key ID, and include authoritative capabilities,
  limits, commercial state, license epoch, device binding, client-version policy, trusted server time,
  refresh target, and expiry.
- Account, license, device, and activation-code state machines are explicit audited business state.
  Do not physically delete durable commercial entities or add shortcuts that bypass allowed
  transitions.
- An already issued lease is offline authority until its signed expiry. Later server state prevents
  refresh but cannot retroactively recall bytes already accepted by an offline client.
- Client-version enforcement coordinates protocol upgrades for honest clients; it is not executable
  attestation. Protect paid server resources with signed state and authorization, never an app-version
  string alone.

## Database, time, and consistency rules

- Use the persistent service-time authority for every security or commercial decision. Do not add
  direct wall-clock reads to authenticated, administration, billing, job, storage, Webhook, or audit
  paths.
- Trusted time advances from database time, the persisted high-water mark, and process-monotonic
  progress. Rollback cannot make expired state valid; an excessive forward jump fails readiness and
  dependent operations closed.
- State-changing database operations are transactional, concurrency safe, and retry safe. Use row
  versions, unique business keys, persisted canonical idempotency keys, or leases; in-memory locks do
  not coordinate replicas.
- Reusing an idempotency key/operation ID with different canonical content returns a conflict. A
  retry of the same request returns or reconstructs the committed result without duplicating seats,
  codes, deliveries, jobs, or audit events. Public Team secret-bearing responses are retained only
  as bounded, authenticated ciphertext and replayed for the same device/command/request. One-display
  CLI issuance instead reports that committed plaintext cannot be replayed; Admin HTTP secret
  delivery replays only its session-bound ticket.
- Cross-table state changes commit their authorization recheck, business rows, quota accounting,
  sessions, sync records, audit event, object metadata, and outbox item together as applicable.
- List endpoints use bounded keyset pagination with canonical opaque cursors. Never load an account,
  workspace, audit history, job, or delivery inventory into an unbounded response or memory vector.
- Production starts long-lived roles with automatic migrations disabled. The same immutable image's
  `migrate` role applies migrations first; every service role then performs non-destructive schema
  readiness before binding/serving.
- Readiness must prove a relation exists before referencing it. Never rewrite a migration contained
  in a published or deployed release or edit `_sqlx_migrations`; append a deterministic migration and
  test a fresh database plus the latest actually released schema when one exists. Development-only
  schemas before the normalized baseline have no compatibility path and must be recreated.

## Team and cloud workspace invariants

- Product roles are Owner, Admin, Billing, Operator, Viewer, and Auditor. Control-plane roles are a
  separate identity domain and never become product entitlements.
- Every Team operation rechecks active membership and the exact permission in the final transaction.
  A cached profile, visible UI control, or previously signed capability is not commit authority.
- Invitations reserve seats; active/suspended members consume seats; removed members remain audit
  identities without consuming a seat. Additional devices use separate one-use enrollment tokens.
- Invalid, expired, consumed, or wrong-kind Team tokens return dedicated recoverable errors without
  invalidating an otherwise valid refresh session. Repeating an accepted token from the device it
  just linked is idempotent even after later expiry, allowing safe recovery from a lost response.
- Free and Pro licenses always carry zero purchased seats. Team licenses carry 3 through 10,000
  seats; entering Team requires an explicit valid quantity, leaving Team clears it, and every change
  advances the license epoch and row version exactly once when authoritative state changes.
- Account creation establishes one stable internal Owner placeholder, and the first registered
  device is bound to it. The private control plane may replace that placeholder's email and display
  name exactly once without changing its identity, role, device bindings, or authority.
- Suspend revokes sessions but preserves bindings. Remove/leave revokes sessions and outstanding
  tokens, removes bindings, marks devices removed, and releases the seat atomically. The Owner cannot
  leave; ownership transfer atomically swaps one active Admin with the current Owner using row
  versions.
- Shared configuration revisions are immutable encrypted records. Draft/published/deleted/retained
  state, row versions, document count, per-revision size, and workspace quota remain authoritative.
- Sync uses monotonic changes, canonical operation IDs, base row versions, and device checkpoints.
  Never silently last-write-wins.
- Alert incidents move only `open -> acknowledged -> resolved`; acknowledgement does not grant alert
  rule authority. Audit events are append-only, tenant-scoped, redacted, paginated evidence.
- Webhooks are HTTPS-only, reject redirects and local/private/reserved destinations, revalidate DNS,
  pin the selected address, sign payloads, and use transactional outbox plus bounded leased retries.
  Endpoint secrets are shown once and auditors see only delivery metadata.

## Administration and UI boundaries

- `admin-web` hosts a private Svelte console and `/api/v1` control-plane API. It must remain behind
  authenticated HTTPS ingress with the exact configured public origin.
- Authentication uses one-time enrollment, Argon2id password verification, TOTP, recovery, secure
  HttpOnly cookies, CSRF, session rotation, rate limits, and recent step-up for sensitive actions.
- Administrator sessions have a 30-minute idle limit, a non-renewable eight-hour absolute limit,
  and a ten-minute step-up window. The Admin UI may keep an active session alive only at low
  frequency while the page is visible and recent user interaction is present; background or
  unattended tabs must not be kept alive.
- Administrator usernames are immutable sign-in and audit identifiers. An active administrator may
  change their own display name or password with step-up, reason, idempotency, and row-version
  protection; a password change revokes every session. Offline Owner recovery requires exact
  normalized-username confirmation, clears all authentication factors and sessions, and returns one
  ten-minute reset token. A credential-free pending Owner remains recoverable so an undelivered
  token can be replaced; replacement invalidates every earlier enrollment token.
- Administrator roles/permissions are explicit. Mutations require the documented permission, reason,
  persisted idempotency key, and `If-Match` row version where applicable. Self-disable, self-reset, and
  removal of the final active Platform Owner fail closed.
- Enrollment tokens, activation-code batches, invitation tokens, and other one-display material use
  encrypted, session-bound, expiring secret deliveries and are erased after acknowledgement. Ordinary
  resource records never contain the plaintext.
- Admin surfaces include dashboard, accounts, licenses, activation codes, devices, jobs, audit,
  billing, Team governance, administrator identities, and system status. Keep UI availability aligned
  with backend permissions and step-up requirements, but enforce all decisions again on the server.
- Shared layout, status badges, tables, dialogs, focus traps, loading/empty/error/conflict states,
  responsive widths, localization, and destructive confirmations belong in shared UI primitives.
- Verify keyboard navigation, visible focus, focus restoration, readable long errors, reduced motion,
  compact laptop widths, and representative populated/empty/failure states in Playwright.
- The live Admin UI suite authenticates against the API and static assets from the final candidate
  image. Keep credentials ephemeral, test real resource reads and logout, and preserve deterministic
  fixture-based browser coverage for destructive and rare visual states.

## Secrets, encryption, uploads, and network safety

- Production secrets come from restricted files or the deployment secret system, not ordinary
  environment values, JSON state, command lines, logs, images, tickets, or frontend stores.
- Secret generators use `umask 077`, publish atomically, refuse overwrite, and write only to ignored
  locations. Runtime files mounted into the image must be readable by numeric UID/GID `10001:10001`
  with the narrowest mode.
- Entitlement private key, Admin keyring, Workspace keyring, Webhook keyring, and forwarded-address
  proxy secret are independent trust domains. Never reuse roots or remove an old key while a row or
  unexpired artifact still references it.
- Back up PostgreSQL, evidence objects, all keyrings, entitlement recovery material, migration
  manifest, and image digest as one named recovery point. A partial database/key restore is invalid.
- Object storage encrypts content with per-object data keys, validates digests and quotas, and keeps
  plaintext out of audit/log data. Production supports database, filesystem, and S3 backends.
- Payment evidence is bounded, signature-checked, quarantined, scanned, and accepted only when every
  attachment is clean. Production fails closed when the configured scanner is unavailable.
- `CAMELLIA_NEXUS_CLAMAV_ADDRESS` is strict `host:port` with DNS, IPv4, or bracketed IPv6. Compose uses the
  service DNS name rather than an ephemeral container address.
- Forwarded client addresses are ignored unless a trusted proxy strips inbound headers and supplies a
  verified address with the shared proxy secret. Normalize addresses and request IDs before audit.
- Webhook, object-store, payment, database, release, and signing credentials must be redacted from
  diagnostics. Public errors never expose internal filesystem/database/cryptographic detail.

## Jobs, observability, and operations

- Job preview/create, leasing, cancellation, retry, and result commit are idempotent across worker
  crashes. A canceled job cannot be leased again; a stale worker cannot overwrite a newer lease.
- Workers use bounded batches, concurrency, timeouts, retry schedules, retention, and `SKIP LOCKED`
  where appropriate. Expired leases are recoverable and never imply success.
- Every commercial/security-sensitive success and denial writes a structured audit event with trusted
  time, canonical actor/tenant/resource/action/reason, row version, request ID, and safe metadata.
- `/healthz` is process liveness without dependency access. `/readyz` checks repository, required
  schema, key material as applicable, and trusted time with a bounded deadline and no-store response.
- Every production runtime role exposes low-cardinality Prometheus text metrics on its separately
  configured operations listener. Keep that listener private by default and never label metrics with
  tenant, account, device, URL, token, operation, or other user-controlled identifiers.
- Bound request bodies, responses, pagination, database pool waits, total request time, concurrency,
  upload size, object quota, worker drain, retries, and log retention. Overload and timeouts remain
  explicit machine-readable failures.
- On shutdown, stop accepting traffic, drain in-flight requests and claimed worker work within the
  configured platform grace, and leave incomplete work retryable.

## Toolchain and quality gates

- Use the exact Rust toolchain in `rust-toolchain.toml`, Node.js 24.x from `.node-version`, and the
  exact pnpm version in `admin-ui/package.json`.
- Before committing Rust changes run `cargo fmt --all -- --check`,
  `cargo test --locked --all-targets --all-features`, and
  `cargo clippy --locked --all-targets --all-features -- -D warnings`.
- Database behavior also runs with `TEST_DATABASE_URL` against isolated PostgreSQL databases,
  including every ignored integration test. Required database coverage must run in CI; do not leave
  permanently ignored tests that no gate executes.
- Administration UI changes run `pnpm --dir admin-ui install --frozen-lockfile`,
  `pnpm --dir admin-ui format:check`, `pnpm --dir admin-ui check`, and
  `pnpm --dir admin-ui build`. Interaction changes run the relevant Playwright tests.
- Container/release changes also run version policy, release-manager tests, Docker build, runtime
  smoke, OCI label/version/source checks, vulnerability audit, and secret-generation regressions.
  Runtime smoke uses isolated PostgreSQL and exercises migrations, every runtime role, administrator
  enrollment/login/step-up/logout, account/Team-license/code/invitation flows, delivery replay, and
  container hardening against the final image.
- Non-container deployment changes run `scripts/test-systemd-deployment.sh`; the migrate, public,
  Admin Web, and worker units must remain explicit, ordered, independently restartable, and hardened.
- Candidate-image validation runs the live Admin UI against the real final-image API and exports a
  digest-verified, credential-free server/PostgreSQL rootfs bundle for native Windows E2E. Disposable
  Compose providers may emit activation codes only through their protected descriptor stdout and
  must remove their image, volumes, database, keys, and state directory on teardown.
- Use the narrowest relevant test during iteration, then every gate required by the touched boundary.
  Never weaken, skip, or delete a required check merely to obtain a green run.

## CI/CD and deployment contract

- The root `Cargo.toml` is the sole committed server version source. Normal PR and `main` work passes
  Rust, PostgreSQL, Admin UI, Playwright, audit, and candidate-image gates.
- Managed Release PRs contain only the generated Cargo/lock/changelog delta tied to an exact validated
  `main` parent. Exact-head write/admin human approval plus the focused gate authorizes the Release
  App's SHA-guarded squash merge.
- Formal publication verifies the managed tag/commit/release identity, builds the supported
  `linux/amd64` image, verifies runtime and OCI labels, scans it, signs the canonical digest with the
  exact workflow identity, creates immutable aliases, publishes the GitHub Release, and reads it back.
- Production pins the canonical digest from the formal Release; never deploy `latest`, a candidate
  tag, or an unverified local build. `migrate`, `serve`, `admin-web`, and `admin-worker` use exactly the
  same digest.
- Deployment order is recovery point/config validation, image verification/pull, one-shot migration,
  readiness-gated public/Admin rollout, then workers. Preserve data volumes during normal rollback;
  destructive resets require explicit scope and confirmation.
- Verify both readiness endpoints, expected version/revision, Admin authentication, core public
  activation/entitlement flow, evidence scanning, worker processing, audit continuity, and rollback
  criteria before accepting a production rollout.

## Documentation and repository hygiene

- `README.md` is the bilingual deployment, protocol, CLI, configuration, and operations reference.
  Keep both languages semantically aligned with current handlers and flags.
- `docs/team-workspace.md` is the product/control-plane role, lifecycle, cloud, keyring, concurrency,
  and release-acceptance contract. Update it with every Team/cloud authority change.
- `docs/releasing.md`, `docs/dependency-management.md`, and `docs/testing.md` own release, toolchain,
  and production-verification governance.
  `SECURITY.md` and `docs/runbooks/` own disclosure, incidents, key rotation, backup/restore, and
  rollout/rollback.
- Documentation describes one current production contract. Remove obsolete pre-release plans and
  superseded compatibility prose instead of presenting them as live behavior.
- Preserve unrelated user changes and local-only files. Stage only files in the current change, and
  never inspect, print, delete, or commit sensitive ignored files.
- Keep commits focused and independently revertible. Do not amend, rebase, merge historical commits,
  sign commits, or push unless the user explicitly requests it.
- Never commit production keys, tokens, passwords, customer identifiers, evidence, backups, local
  deployment state, temporary exports, or generated secret directories.
