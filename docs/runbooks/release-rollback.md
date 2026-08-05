# Release and rollback runbook

This runbook governs production rollout of the public service, private administration console,
workers, and migrations. Deploy only an immutable image digest recorded by a completed managed
GitHub Release. Mutable aliases such as `latest` are discovery aids and are never deployment inputs.

## Preconditions

1. Verify the release tag resolves to the recorded commit and that the GitHub Release is public,
   immutable, complete, and records exactly one container digest.
2. Verify the digest's Cosign workflow identity and OCI `version`, `revision`, and `source` labels.
   Confirm the vulnerability and runtime checks in the formal release completed successfully.
3. Record the current and candidate digests. Create and verify a joint recovery point covering
   PostgreSQL, object storage, all keyrings, entitlement recovery material, and migration checksums
   using the writer-quiesced procedure in `docs/runbooks/backup-restore.md`. Do not accept separately
   timed online database and external-object snapshots as one recovery point.
4. Validate the candidate configuration without printing secrets. Confirm file ownership/mode,
   HTTPS origins, key IDs, scanner and object-store reachability, database capacity, trusted UTC
   time, ingress policy, and both rollback and abort criteria.
5. Confirm every role will use the same candidate digest. Do not combine a candidate migration with
   an older public, Admin, or worker binary.

## Rollout

1. Pull the candidate by digest before stopping a healthy role. A registry failure is an abort, not
   permission to substitute a mutable tag or a locally built image.
2. Quiesce work only when the migration requires it. Stop workers before a change that could create
   mixed-version writes; preserve public safety/read paths whenever the schema contract allows it.
3. Run the candidate image's one-shot `migrate` role. Stop immediately on a checksum mismatch,
   trusted-time anomaly, schema error, or failed migration. Never edit `_sqlx_migrations` manually.
4. Roll out the public service and `admin-web`, keeping traffic gated by their separate readiness
   endpoints. Start `admin-worker` only after both serving roles and required dependencies are ready.
5. Verify expected version/revision, health/readiness, public activation and entitlement refresh,
   Admin password+TOTP and step-up, a representative authorized mutation, evidence upload and scan,
   job processing, Webhook delivery, tenant isolation, and audit continuity.
6. Observe request failures, denial rates, database saturation, trusted time, object scanning, lease
   backlog, Webhook retries, and audit persistence through the declared acceptance window. Record the
   accepted digest and evidence in the change record.

## Rollback

1. Declare the failed acceptance criterion and preserve logs, audit ranges, image/config checksums,
   and database state before cleanup. Stop candidate workers first so they cannot create newer work.
2. A binary rollback is permitted only when the previous image remains compatible with the expanded
   schema. Restore the previous digest for `serve`, `admin-web`, and `admin-worker`, then verify both
   readiness endpoints and the representative flows above.
3. If the migration is intentionally incompatible, stop all writers and restore PostgreSQL, objects,
   keyrings, signing material, migration manifest, and image digest from the same named recovery
   point. Never restore only the database or only a keyring.
4. Do not delete Compose volumes, run a global prune, hand-patch a container, move a release tag,
   overwrite a published alias, or back-sign unknown bytes as part of rollback.
5. Keep the incident/change record open until service, Admin authentication, workers, scanner,
   Webhooks, trusted time, tenant isolation, and audit continuity are verified and temporary recovery
   credentials have been revoked.

Use expand/contract migrations by default. Destructive contract migrations belong in a later,
separately approved release after the previous-binary rollback window has closed and a tested joint
restore is available.

## 中文执行摘要

生产部署只使用已完成受管 Release 中记录的不可变镜像摘要，并先核对 tag、提交、Cosign 身份、OCI
标签、扫描结果与联合恢复点。所有角色使用同一摘要；先运行一次性迁移，再按公开服务、管理端、Worker
顺序完成 readiness 与端到端验收。回滚先停止新 Worker；仅当旧二进制兼容扩展后 schema 时回退镜像。
若迁移不兼容，必须从同一具名恢复点整体恢复数据库、对象、密钥环、签发材料、迁移清单与镜像，禁止
删除数据卷、全局清理、手改 migration 记录、移动 tag 或使用 `latest` 代替正式摘要。
