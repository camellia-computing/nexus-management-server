# Key and credential rotation runbook

Rotation is a controlled security change, not a file replacement. Use a named change record, two
operators for production secret custody, an immutable candidate digest, and a verified joint
database/object/keyring recovery point. Record key IDs, public-key fingerprints, file checksums and
UTC cutover times only. Never record private material or place it in an environment variable,
command line, repository, container layer, log, or ticket.

## Common preparation and acceptance

1. Confirm both readiness endpoints, worker health, current formal image digest, migration manifest,
   trusted time, and backup restore verification.
2. Generate independent random material in the production secret manager. Use a canonical new key
   ID; never overwrite or reuse an existing ID.
3. Publish restricted files atomically with the expected owner, mode, and read-only mount. Every
   replica of a role must see the same complete version before any writer selects a new key.
4. After cutover, verify real encrypt/decrypt or sign/verify paths, audit persistence, replica
   readiness, rollback criteria, and reference inventory. Retire old material only in a later
   change after its maximum validity/retention window and authoritative references are clear.

## Entitlement ES256 signing key

The server signs with one configured private key, while the desktop embeds a set of trusted public
keys. Rotation therefore uses release order, not dynamic network trust:

1. Generate the next P-256 key in secret custody. Independently derive its public key and compare
   the public-key fingerprint with the reviewed client trust entry and the server-mounted private
   key. Keep the current key configured on the server.
2. Release the desktop with both current and next public keys in `src-tauri/entitlement-keys.json`.
   Verify a build from that release accepts test leases from both keys and rejects unknown IDs.
3. After adoption is sufficient for the declared enforcement policy, atomically mount the next
   private PEM, set `CAMELLIA_NEXUS_LICENSE_KEY_ID` to its exact ID, and roll every public service replica.
   Reject a deployment where ID and PEM do not match the reviewed fingerprint.
4. Verify new entitlement headers and signed claims use the new ID, old client sessions can refresh
   according to policy, and no replica still issues with the old ID.
5. Keep the old public key in supported desktop releases until every lease signed by it has expired
   and the rollback window has closed. Keep its private key only in restricted recovery custody,
   then destroy it under dual control. For compromise, skip coexistence: stop issuance, remove trust
   through an urgent desktop release, enforce that minimum version, and never reactivate the key.

## Admin keyring

Admin roots derive password peppers and encrypt TOTP, enrollment, delivery, and stored-object
material. Existing rows remain bound to their recorded key ID.

1. Add a new `admin-*` root to `keys` on every replica while retaining the old `activeKeyId` and all
   old roots. Roll `admin-web` and `admin-worker`; readiness must pass.
2. Switch `activeKeyId` everywhere in one controlled rollout. Verify a new administrator enrollment,
   password+TOTP login, one-time secret delivery and acknowledgement, evidence write/read/scan, and
   restart recovery.
3. Inventory references before retirement:

   ```sql
   SELECT key_id, count(*) FROM (
     SELECT key_id FROM admin_password_credentials
     UNION ALL SELECT key_id FROM admin_totp_credentials
     UNION ALL SELECT key_id FROM admin_enrollment_states
     UNION ALL SELECT key_id FROM admin_secret_deliveries WHERE key_id <> ''
     UNION ALL SELECT key_id FROM stored_objects
   ) AS referenced_admin_keys
   GROUP BY key_id ORDER BY key_id;
   ```

   There is no blanket safe-delete shortcut. Reset/re-encrypt every remaining reference through a
   reviewed operation before removing a root. A readiness failure after removal requires restoring
   the correct keyring, not modifying rows.

## Workspace and Webhook keyrings

Follow the same add-everywhere, select-everywhere, retire-later sequence. Workspace and Webhook roots
must be independent from each other and from Admin. Acceptance includes historical configuration
decrypt, create/revise/publish, endpoint secret rotation, and a real signed delivery. Before removal,
run the reference queries in the [Team workspace contract](../team-workspace.md#team-keyring-operations--team-密钥环运维).

## Admin forwarded-address proxy secret

This secret authenticates ingress-provided client addresses and has no multi-key overlap. Schedule a
short Admin maintenance window: stop external Admin traffic, generate a staged replacement with
`scripts/generate-proxy-secret.sh <staged-path>`, apply the deployment's application-secret access
policy, and verify that every effective `admin-web` identity can read the staged regular file while
unrelated identities cannot. Atomically install it and update the trusted proxy and every
`admin-web` replica as one change, restart, then verify a known client address is audited and forged
forwarding headers are ignored. Roll back both sides together. Never temporarily disable validation
to avoid downtime. The mounted file is subject to the common 64 KiB secret-file ceiling, and its
single header value must contain 32–256 visible ASCII characters.

## PostgreSQL and object-store credentials

Create a new least-privilege credential first and test it from an isolated deployment. Quiesce
workers and writes, atomically update deployment secret files, roll `migrate`/public/Admin/worker
roles, verify readiness and a transaction, then revoke the old credential at the authority. If the
database account cannot overlap credentials, use a maintenance window and update the password only
after all writers are stopped. Do not embed reserved characters unescaped in a Compose URL; use a
URL-safe generated value or a correctly percent-encoded secret.

## GitHub Release App and registry authority

Add a new App private key, update the Actions secret, run repository-policy validation and a
non-publishing candidate workflow, then revoke the old App key. Confirm App slug/login, installation
scope, least-privilege permissions, environment protection, immutable Release setting, package
write access, and audit events. OIDC/Cosign uses short-lived workflow identity and has no stored
signing key to rotate; investigate identity or workflow compromise through the incident runbook.

## 中文执行摘要

所有轮换都先创建新材料、在全体副本中加入但不启用、完成 readiness 后统一切换，旧材料仅在权威
引用与最长有效期清零后的后续变更中移除。Entitlement 必须先发布同时信任新旧公钥的客户端，再
切换服务端私钥与 key ID；泄露时不得保留旧信任。Admin 根密钥仍被密码、TOTP、交付或对象引用时
不能删除。代理密钥不支持双轨，必须在维护窗口同步更新代理与 Admin。数据库/对象凭据需在新凭据
验证并完成滚动后从签发端撤销旧凭据。
