# Incident response runbook

This runbook covers the public licensing API, private Admin control plane, workers, PostgreSQL,
object storage, keyrings, release pipeline, and desktop trust contract. Never paste secret material,
raw payment evidence, activation codes, session tokens, or full customer records into tickets or
chat. Record only redacted identifiers, hashes, immutable digests, UTC times, and evidence custody.

## 1. Declare and contain

1. Assign an incident commander, operations lead, security lead, and recorder. Open a restricted
   incident record and establish one UTC timeline.
2. Classify impact: active compromise or unsafe issuance is critical; loss of authorization,
   audit, trusted time, or tenant isolation is high; bounded availability loss is medium unless it
   blocks containment.
3. Preserve evidence before cleanup: image digest, deployment manifest, configuration checksums,
   audit-event range, ingress/database/object-store logs, GitHub workflow run IDs, and host time.
   Export through approved evidence storage; do not copy secrets.
4. Stop the smallest unsafe write path. Scale down `admin-worker` before changing shared state. Stop
   `admin-web` for administrator compromise and stop `management-server` for signing, entitlement,
   tenant-isolation, or trusted-time compromise. Keep read-only evidence access where safe.
5. Revoke exposed human and automation access through the authority that issued it. Do not merely
   delete local files while the credential remains valid.

## 2. Diagnose without destroying evidence

- Compare every running image ID with the recorded formal digest. Verify the Cosign identity,
  provenance subject, SBOM, OCI source/revision/version labels, tag commit, and immutable GitHub
  Release marker. Treat any mismatch as a supply-chain incident.
- Check public and Admin readiness separately, PostgreSQL UTC time and persisted trusted-time high
  water, migration checksums, worker lease backlog, object scanner state, and audit continuity.
- Identify the first known bad and last known good UTC instants. Query by opaque IDs and bounded
  time ranges; avoid broad exports of customer or secret-bearing tables.
- Determine whether confidentiality, integrity, availability, tenant isolation, signing authority,
  or recovery material was affected. Unknown scope is not evidence of limited scope.

## 3. Containment by incident type

### Administrator or Admin keyring

Use a separate uncompromised Platform Owner to disable the identity; this revokes its sessions and
pending enrollment material. If no trusted owner remains, stop `admin-web` and use the offline
recovery procedure. A leaked Admin root key can expose password peppers and encrypted TOTP,
delivery, and object material: reset every administrator credential, invalidate pending deliveries,
rotate the keyring using the key-rotation runbook, and retain an old key only while authoritative
rows still require it.

### Entitlement signing key

Stop issuance immediately and preserve the affected key ID and first/last suspected use. A stolen
private key can forge leases accepted by clients that trust its public key; changing only the
server does not contain that trust. Ship a signed desktop trust update that removes the compromised
key, move the server to a pre-staged new key, enforce the remediated minimum client version, and
invalidate affected sessions/license epochs as the investigation requires. Never reuse a
compromised key for rollback.

### Workspace or Webhook keyring

Stop Workspace writes and Webhook delivery/rotation. Preserve ciphertext and key IDs. Restore the
matching recovery-point keyring if material is missing; if material was disclosed, add and activate
a new key fleet-wide, rotate all affected endpoint secrets, and remove an old root only after the
reference queries and backup-retention policy allow it. Never delete unreadable ciphertext to make
readiness pass.

### Database, object storage, or payment evidence

Block writes, revoke database/object credentials, snapshot evidence, and determine whether an
attacker could combine ciphertext with a keyring. Quarantine evidence objects whose scanner result
or digest is uncertain. Restore PostgreSQL, objects, keyrings, signing metadata, migration manifest,
and image digest from one named recovery point; partial restores are invalid.

### Trusted-time anomaly

Do not edit `service_time_authority`. Verify host NTP and PostgreSQL UTC time. A large legitimate
advance after a proven outage may use the documented temporary forward-jump allowance only in a
controlled window; rollback or unexplained advance remains a security incident.

## 4. Eradicate, recover, and verify

1. Remediate the root cause in reviewed code or infrastructure. Rotate through the issuing system,
   update restricted files atomically, and record only key IDs/checksums.
2. Build and publish through the normal managed release path. Do not hand-patch a container or
   back-sign an existing unknown digest.
3. Restore from the joint recovery point when integrity cannot be established. Apply migrations
   only from the selected image digest.
4. Before traffic, verify schema/readiness, signing and client verification, Admin password+TOTP,
   tenant isolation, representative encrypted reads, Webhook signed delivery, scanner behavior,
   audit persistence, and worker recovery. Use synthetic accounts and remove them afterward.
5. Re-enable public reads, public writes, Admin, then workers in that order while monitoring errors,
   denial rates, audit continuity, database saturation, trusted time, and delivery lag.

## 5. Closeout

Document affected data and tenants, notification decisions, exact revocations/rotations, recovery
point, formal digest, verification evidence, and residual risk. Schedule corrective work with an
owner and deadline, test the detection gap, and run a restore/rollback rehearsal. Destroy temporary
credentials and plaintext evidence exports through the approved custody process.

## 中文执行摘要

先指定负责人并建立 UTC 时间线，保全镜像摘要、发布证明、审计区间与配置校验值，再停止最小的不
安全写路径。签发密钥泄露必须同时更新客户端信任集；Admin/Workspace/Webhook 密钥问题不得通过
删除密文规避。数据库、对象与全部密钥环只能按同一个具名恢复点恢复。所有修复继续走正式发布流，
通过签发、Admin 登录、租户隔离、加密历史读取、Webhook、扫描、审计和 Worker 恢复验收后，按
公开读取、公开写入、Admin、Worker 的顺序恢复流量。
