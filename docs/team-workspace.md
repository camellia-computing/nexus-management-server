# Team workspace production contract / Team 工作区生产契约

This document defines the fixed responsibility, authority, and lifecycle boundaries of a
Camellia Nexus Team workspace. Product authorization is enforced by the license service and the
desktop Rust boundary; the frontend only presents the resulting state.

本文定义 Camellia Nexus Team 工作区固定的职责、权限和生命周期边界。产品授权由授权服务与桌面端
Rust 边界强制执行，前端仅呈现服务端确认的状态。

## Distribution and commercial scope / 分发与商业范围

- GitHub Releases, GHCR, Actions, OIDC, and the other capabilities available to GitHub Free are
  trusted parts of the current distribution pipeline. The release workflow adds App-only
  authorization, exact-SHA checks, checksums, and Sigstore verification as defense in depth.
- The project never sells or requires a GitHub Pro feature. GitHub account tiers are unrelated to
  Camellia Nexus product entitlements.
- Cloud Sync, Shared Configurations, Alerts, Audit Log, and Webhooks may be advertised or signed
  into a Team entitlement only after their schema, API, client UI, worker, migration, and rollback
  gates for the same release are all green.

- GitHub Releases、GHCR、Actions、OIDC 及 GitHub Free 可用的其他能力是当前可信分发链的一部分；
  发布流程额外使用仅 GitHub App 可授权、精确 SHA、校验和与 Sigstore 验证进行纵深防御。
- 项目不会售卖或要求 GitHub Pro 能力；GitHub 账户等级与 Camellia Nexus 产品权益无关。
- Cloud Sync、Shared Configurations、Alerts、Audit Log、Webhooks 只有在同一版本的数据库、API、
  客户端 UI、后台任务、迁移和回滚门禁全部通过后，才允许宣传或签入 Team 权益。

## Fixed roles / 固定角色

| Role | Responsibility and permitted authority | Explicit exclusions |
| --- | --- | --- |
| Owner | Workspace governance, member administration, ownership transfer, billing read/manage, shared configuration publish and retained-item purge, sync, alerts, audit export, and webhook management | Ownership cannot be removed or suspended; transfer must target an active Admin |
| Admin | Day-to-day member operations, billing read, shared configuration draft/publish, sync, alerts, audit, and webhook management | No billing mutation, ownership transfer, workspace deletion, or peer-Admin mutation |
| Billing | Read billing and submit payment evidence | No member, configuration, sync, alert, audit, webhook, remote-control, or lifecycle authority |
| Operator | Read members, edit shared drafts, read/write sync, read remote status, read/acknowledge alerts | No publish, member administration, alert-rule management, audit export, or webhook management |
| Viewer | Read members, published/shared configuration, sync state, remote status, and current alerts | No writes or acknowledgements |
| Auditor | Read members, alert history, audit log/export, and webhook delivery metadata | No shared configuration content mutation, endpoint URL/secret access, billing, member mutation, or alert acknowledgement |

The permission strings returned by `TeamProfile` are the public capability contract. API handlers
must re-check the active member and required permission inside the final database transaction;
having a visible control or a previously issued entitlement is never sufficient authority.

`TeamProfile` 返回的权限字符串是公开能力契约。API 必须在最终数据库事务内重新检查成员仍为
Active 且具备所需权限；界面上存在控件或曾经签发过权益都不能单独作为授权依据。

### Control-plane responsibility / 控制面责任

Product workspace roles and private control-plane roles are independent identities. A control-plane
role never becomes a product entitlement and a Team Owner never gains administrator-console access.

Account creation establishes one stable internal Owner placeholder, and the first registered device
is bound to that Owner. The private control plane exposes a one-time, version-guarded completion
operation that replaces only the placeholder email and display name. It does not create another
member, consume another seat, change the Owner role, or alter existing device bindings. The internal
non-routable address is never treated as a deliverable invitation address.

| Control-plane role | Team responsibility |
| --- | --- |
| Platform Owner | Emergency governance and all Team read/write operations; use only for bootstrap, recovery, or explicitly approved intervention |
| Licensing Admin | Routine invitation, suspension, removal, re-invitation, and ownership-transfer operations with reason, idempotency key, row-version precondition, and immutable audit |
| Billing Admin | Team workspace and seat-usage read access needed to reconcile invoices; no member mutation |
| Support Operator | Read-only membership diagnostics; no role, status, invitation, ownership, billing, or cloud-data mutation |
| Auditor | Read-only membership and control-plane audit evidence; no secret delivery or mutation |
| Security Admin | No Team membership access by default; security investigations use the dedicated device and audit boundaries |

产品工作区角色与私有控制面角色属于彼此独立的身份域：控制面角色不会成为产品权益，Team Owner 也
不会因此获得管理控制台权限。所有控制面成员变更与产品 API 使用同一成员状态机；移除和撤销邀请
必须在同一事务内终止会话、移除设备绑定并撤销未使用令牌，不能通过控制台绕过产品规则。

创建账户时会建立一个稳定的内部 Owner 占位身份，首台注册设备自动绑定到该 Owner。私有控制面仅
提供一次受 row version 保护的资料完善操作，用真实邮箱与显示名称替换占位值；该操作不会新建成员、
额外占用席位、改变 Owner 角色或改动既有设备绑定。内部不可投递地址绝不能作为真实邀请地址使用。

## Membership and device lifecycle / 成员与设备生命周期

```text
invited --accept one-use invitation--> active <--> suspended
   |                                      |
   +-------------------------------> removed

removed --new invitation--> invited
```

- A valid invitation reserves one seat. Active and Suspended members consume one seat. Removed
  members remain as audit identities but consume no seat. Expired or revoked invitations consume
  no seat.
- Free and Pro licenses have zero purchased seats. A Team license has 3 through 10,000 purchased
  seats. Each member may bind at most three separately proven devices; the account-wide device
  ceiling remains authoritative as well.
- A seven-day invitation is single-use and activates the first member device. It must never be
  reused to add another device. Before accepting it, that device must first activate against the
  same Team license with its own activation code. An active member adds a device with a separate
  single-use, 15-minute enrollment token created from an already bound device. Replaying a consumed
  invitation from the accepted device is idempotent. Repeating a consumed device-enrollment token
  from the device it just linked is likewise idempotent, so a lost response can be recovered safely.
  Token expiry does not overturn that already-committed same-device result. Replay of either token
  from another device is denied and recorded without creating another binding or audit success.
- Invalid, expired, consumed, or wrong-kind invitation and device-enrollment tokens return distinct
  recoverable business errors. They never use the session-level `authorization_required` error and
  therefore never invalidate an otherwise valid device refresh session.
- Removing one registered device is distinct from removing its member. It atomically revokes that
  device's sessions and deletes its binding while the member remains Active. Reactivating the same
  registered identity or activating a replacement identity never recreates the old binding.
  Owner/Admin may issue a 15-minute recovery enrollment for an Active, zero-device member; Admin
  cannot recover the Owner. The operation is unavailable once any device is bound, preventing it
  from becoming a second invitation path.
- Suspending a member invalidates refresh sessions but preserves device bindings for an explicit
  later reactivation. Removing or leaving invalidates sessions, marks every bound device Removed,
  deletes bindings, releases the seat, and revokes all outstanding invitations/enrollments in one
  transaction.
- An Owner cannot leave. Ownership transfer atomically demotes the current Owner to Admin and
  promotes exactly one active Admin, using both row versions.
- Every public invitation, acceptance, member update, device-enrollment creation/acceptance, leave,
  and ownership-transfer write carries a canonical UUIDv4 `operationId`. The mutation, audit, and
  encrypted exact response commit in one transaction. An identical retry from the same device
  replays that response, including a one-time secret; changed command or canonical content returns
  `idempotency_conflict`. For voluntary leave, the original refresh session and device may query
  `GET /v1/team/operations/{operation_id}` with the original member ID and row version after an
  ambiguous result. Only a matching stored `leave_workspace` command reports committed; another
  Team operation cannot trigger local deauthorization. This narrow status recovery remains
  available after leave revoked that session, but exposes no Team profile or response body. Records
  are retained for 37 days; replay never extends token expiry.
- Member records use stable keyset pagination (100 by default, 200 maximum). Clients and the
  private control plane must follow `nextCursor`; neither may infer that one response contains a
  whole workspace. Removed audit identities therefore remain accessible without unbounded payloads
  or UI rendering.

- 有效邀请预占一个席位；Active 与 Suspended 成员占用一个席位；Removed 成员仅保留审计身份且不占
  席位；过期或撤销的邀请不占席位。
- Free 与 Pro 的购买席位恒为零；Team 必须购买 3 至 10,000 席。每个成员最多绑定三台分别完成设备
  证明的设备，同时仍受账户总设备额度约束。
- 七天邀请仅可使用一次并激活成员首台设备，不能用于追加设备。接受邀请前，该设备必须先使用属于
  同一 Team 授权的激活码完成自身激活。Active 成员追加设备时，必须从已绑定设备创建独立的、
  一次性、15 分钟设备入组令牌。已接受设备重复提交同一邀请属于幂等成功；设备入组请求已在服务端
  提交但响应丢失时，刚完成关联的同一设备重复提交该已消费令牌同样属于幂等成功；令牌随后到期不会
  推翻已提交的同设备结果。其他设备重放任一已消费令牌会被拒绝并记录，且不会新增绑定或重复写入
  成功审计。
- 无效、过期、已消费或类型错误的邀请令牌与设备入组令牌返回各自独立且可恢复的业务错误；这些
  情况不得复用会话级 `authorization_required`，也不得使仍然有效的设备刷新会话失效。
- 移除单台已登记设备与移除成员是两个独立状态变化：前者在同一事务内撤销该设备会话并删除其成员
  绑定，但成员仍保持 Active；该设备身份或替代身份再次激活时都不会自动恢复旧绑定。Owner/Admin
  可为 Active 且绑定设备数为零的成员签发 15 分钟恢复入组令牌，Admin 不得恢复 Owner；一旦已有
  任一绑定设备，该入口即不可用，不能被当作第二种成员邀请。
- Suspended 会终止刷新会话但保留设备绑定，供显式恢复；Removed 或主动离组必须在同一事务中终止
  会话、将全部设备标记为 Removed、删除绑定、释放席位并撤销未使用令牌。
- Owner 不能直接离组；所有权转移使用双方 row version，在一个事务内将原 Owner 降为 Admin、将一名
  Active Admin 升为唯一 Owner。
- 所有公开邀请、接受邀请、成员更新、设备入组签发/接受、主动离组和所有权转移写入都必须携带规范
  UUIDv4 `operationId`。业务变更、审计和加密的精确响应在同一事务提交；同一设备使用相同命令与规范
  内容重试会取得原响应（包括一次性秘密），修改命令或内容却复用操作标识会返回
  `idempotency_conflict`。主动离组结果不明确时，只有原 refresh session 与原设备可携带原成员 ID 和
  row version 通过 `GET /v1/team/operations/{operation_id}` 查询；只有与已存 `leave_workspace` 命令
  全部匹配才返回已提交，其他 Team 操作不能触发本地注销。即使离组已撤销该会话，该窄恢复接口也不
  返回 Team 资料或响应正文。操作记录保留 37 天，响应重放不会延长令牌期限。
- 成员记录使用稳定的键集分页（默认 100、最大 200）；客户端和私有控制面必须继续读取
  `nextCursor`，不得假定单次响应包含完整工作区。由此既保留 Removed 审计身份，又避免无界响应和
  无界界面渲染。

## Cloud capability boundaries / 云能力边界

- **Shared Configurations:** immutable encrypted revisions, an explicit draft/published pointer,
  optimistic row versions, a maximum of 200 active documents, 4 MiB per revision, and a 2 GiB
  workspace plaintext quota. The service stores encrypted content and never returns encryption
  key material. Production startup requires `CAMELLIA_NEXUS_WORKSPACE_KEYRING_PATH` to name a read-only
  JSON keyring whose `activeKeyId` selects one of the URL-safe, unpadded base64-encoded 32-byte
  root keys in `keys`; old keys remain present until all referenced revisions are retired.
- **Cloud Sync:** monotonically ordered changes and device checkpoints. Every mutation has a
  canonical operation ID and base row version. Concurrent changes return a conflict and are never
  resolved by silent last-write-wins.
- **Alerts:** validated rules and a one-way incident state machine (`open -> acknowledged ->
  resolved`). Acknowledgement never grants rule-management authority.
- **Audit Log:** keyset pagination and bounded export over redacted, tenant-scoped events. The
  unfiltered product feed omits high-frequency `challenge_issued` events; an explicit event-type
  filter can retrieve them for a focused investigation. Audit records are append-only product
  evidence, not an unrestricted diagnostic-data endpoint.
- **Webhooks:** HTTPS-only endpoints, secrets shown once, encrypted secret storage, signed payloads,
  transactional outbox delivery, bounded retry, DNS revalidation and address pinning, no redirects,
  and rejection of local/private/reserved destinations. Auditor access is limited to delivery
  metadata. Production requires an independent `CAMELLIA_NEXUS_WEBHOOK_KEYRING_PATH`; it must never
  reuse the Admin or Workspace root keys, and every replica must retain referenced old key IDs
  during rotation. Active deliveries have a seven-day absolute ceiling, while terminal delivery
  metadata, outbox events, idempotency records, and deleted endpoint material are retained for 30
  days before bounded maintenance removes them. The event-ID idempotency window is therefore 30
  days.

## Team keyring operations / Team 密钥环运维

`scripts/generate-keyring.sh <admin|workspace|webhook> [output]` is an initial-provisioning helper.
It creates a new mode-`0600` file and refuses to overwrite any existing path. Generate the three
keyrings independently; never copy a root key between them, print key material, place it in an
environment variable, or commit it to the repository. Each mounted keyring must resolve to a
readable regular file no larger than 64 KiB and contain 1–64 keys.

`scripts/generate-keyring.sh <admin|workspace|webhook> [output]` 仅用于首次创建。脚本创建权限为
`0600` 的新文件并拒绝覆盖任何已有路径。三类密钥环必须分别生成；不得跨用途复制根密钥、输出
密钥内容、通过环境变量传递或提交到仓库。每个挂载的 keyring 必须解析为服务可读的常规文件、
不超过 64 KiB，并包含 1–64 个 key。

Workspace and Webhook key rotation is a two-phase deployment:

1. Create a new canonical key ID and 32-byte random root in the secret manager. Add it to `keys`
   on every replica while leaving `activeKeyId` and all existing keys unchanged. Publish the file
   as an atomic, read-only replacement and restart or roll every replica. A partially rolled fleet
   must not write with a key another replica cannot read.
2. After every replica is ready, atomically change `activeKeyId` to the new ID everywhere and roll
   the fleet again. Verify create/read/update, webhook rotation and a real signed delivery before
   accepting the rollout.
3. Keep old Workspace keys while any stored revision or retained public Team operation response
   references them. Keep old Webhook keys while any non-deleted endpoint references them. Check the
   authoritative database before removal:

   ```sql
   SELECT DISTINCT key_id
   FROM workspace_document_revisions
   UNION
   SELECT response_key_id
   FROM team_operations
   ORDER BY key_id;

   SELECT DISTINCT secret_key_id
   FROM workspace_webhook_endpoints
   WHERE deleted_at IS NULL
   ORDER BY secret_key_id;
   ```

4. Remove an old key only in a later controlled rollout after the corresponding query no longer
   returns it and backup-retention policy permits retirement. Never remove a key merely because it
   is no longer active.

Workspace 与 Webhook 密钥轮换采用两阶段发布：先在所有副本增加新 key、保持 `activeKeyId`
不变并完成滚动；确认全体 ready 后，再统一切换 active key 并重新滚动。旧 Workspace key 必须
保留到所有历史修订和仍在保留期内的公开 Team 操作响应都不再引用；旧 Webhook key 必须保留到所有未删除端点都不再引用。只能在上方
数据库核验和备份保留策略均允许后，于后续受控发布中移除旧 key，不能仅因其不再 active 而删除。

Back up PostgreSQL and all three keyrings as one named recovery point. Store encrypted, access-
controlled keyring backups separately from the database backup, but keep their recovery-point
identity together. A restore is complete only when the database and matching keyring versions are
restored, file ownership and mode are verified, every replica mounts the same files, startup and
`/readyz` pass, referenced key IDs match the queries above, and representative historical content
and a webhook secret can be decrypted. Missing or mismatched Team key material is a fail-closed
incident: stop writes and restore the correct keyring; do not delete ciphertext, replace keys, or
silently discard history.

PostgreSQL 与三类密钥环必须作为同一个具名恢复点备份。密钥环备份需加密、受访问控制并与数据库
备份分离保存，但两者必须共享恢复点标识。只有数据库与匹配版本的密钥环均已恢复、文件属主与权限
正确、所有副本挂载同一文件、启动和 `/readyz` 通过、引用 key ID 与上述查询一致，并能解密代表性
历史内容及 Webhook secret，恢复才算完成。密钥缺失或不匹配时必须失败关闭、停止写入并恢复正确
密钥环；不得删除密文、替换错误 key 或静默丢弃历史。

## Concurrency, errors, and recovery / 并发、错误与恢复

- `rowVersion` is mandatory for every mutable resource. A stale version returns HTTP 409
  `workspace_version_conflict`; clients reload and require the user to review the new state.
- A canonical UUIDv4 `operationId` makes retryable writes idempotent. Reusing it with different
  canonical content returns HTTP 409 `idempotency_conflict` and must not be retried automatically.
- Trusted service time supplies all business timestamps. Database wall time is operational
  metadata only.
- Cross-table state changes, audit insertion, sync change insertion, quota accounting, and outbox
  insertion commit together. Workers use leases and `SKIP LOCKED`; an expired lease is recoverable
  and does not imply success.
- Safety actions such as view, export, stop, and local removal remain available when commercial
  authorization is lost. Terminal authorization transitions stop managed programs and disable
  automatic restarts.

## Release acceptance / 发布验收

Before enabling Team cloud capabilities in a signed plan policy, the release owner must verify:

1. Forward migration, mixed-version rollout behavior, backup restore, and rollback rehearsal.
2. Tenant-isolation, role-matrix, stale-row, duplicate-operation, quota, crash-recovery, and worker
   lease integration tests against PostgreSQL.
3. Desktop contract tests plus keyboard, focus, reduced-motion, three-theme, light/dark, compact
   width, loading, empty, error, conflict, and destructive-confirmation UI coverage.
4. GitHub App authorization, exact tag/SHA/version linkage, artifact checksums, Cosign bundles,
   GHCR digest aliases, and post-publish readback using only GitHub Free-compatible controls.
5. Required production keyrings, DNS/network policy, retention jobs, metrics, alerts, and runbooks
   are configured; missing security configuration fails closed.

Run `node scripts/check-cross-repo-contract.mjs` from either adjacent sibling checkout before a
coordinated public protocol change is merged, followed by
`node scripts/test-cross-repo-contract.mjs`. The byte-identical checker and semantic manifest compare
serialized types, HTTP method/path pairs, proof scopes, body/page limits, mutation/concurrency
identities, and business error mappings; the mutation test proves these drifts fail the gate.

合并跨仓库公共协议变更前，应在任一相邻仓库中执行
`node scripts/check-cross-repo-contract.mjs`，随后执行
`node scripts/test-cross-repo-contract.mjs`。双端字节一致的检查器和语义清单会比较序列化类型、HTTP
方法/路径、proof scope、正文/分页上限、mutation/concurrency 标识及业务错误；mutation test 证明任一
偏移都会使门禁失败。
