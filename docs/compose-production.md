# Production Compose deployment / 生产 Compose 部署

This is the authoritative single-host production contract. Operators do not invoke `docker compose`
directly, copy runtime scripts, or assign host files to container numeric users. The versioned
deployment entrypoint is `camellia-nexus-deploy`; Ansible installs immutable releases, systemd units,
the encrypted SOPS bundle, and the host age identity.

本文是单机生产部署的权威契约。运维人员不得直接执行 `docker compose`、复制运行脚本，或把宿主机文件
分配给容器数字 UID/GID。唯一部署入口是版本化的 `camellia-nexus-deploy`；Ansible 负责安装不可变
release、systemd unit、SOPS 密文包和宿主机 age identity。

## Trust and filesystem model / 信任与文件系统模型

- `/etc/camellia-nexus/secrets.sops.yaml` is the encrypted source of truth (`0600 root:root`).
- `/etc/camellia-nexus/sops/age-identity.txt` is the host root of trust (`0400 root:root`) and is
  provisioned once through the organization secret-custody process.
- `camellia-nexus-secrets.service` decrypts into `/run/camellia-nexus/secrets`; the directory is
  `0700 root:root` and every projected file is `0444 root:root`.
- `0444` does not make a source secret available to host users because they cannot traverse the
  root-only parent. Inside a container, Compose projects only the explicitly authorized files.
- Plaintext secrets never live beside `compose.yaml`, in `.env`, image layers, argv, or Docker
  environment metadata. `/run` is recreated on every boot.
- `/var/lib/camellia-nexus/deployment-state.json` is `0600 root:root` below a `0700 root:root`
  directory. It records only release/config/image/SOPS hashes and UTC version metadata, never secret
  values, and is updated atomically after a successful rollout, reconciliation, rotation, or rollback.
- The dedicated host orders secret staging before Docker, preventing old containers from starting
  before their file mounts exist.
- This contract assumes a dedicated rootful Docker daemon, because only root can traverse the host
  staging parent. Rootless Docker or user namespaces require an orchestrator-native secret
  projection with independently controlled mount ownership/mode; do not weaken the host directory.

`config.env` contains non-secret configuration and immutable image digests only. The application,
PostgreSQL, and ClamAV images are pinned by digest. The release directory is immutable and the
`current` symlink changes only after readiness succeeds.

## Database identities and ordering / 数据库身份及顺序

PostgreSQL initially creates `nexus_bootstrap`. The bootstrap credential is visible only to
PostgreSQL and the one-shot `db-bootstrap` container. `db-bootstrap reconcile` idempotently owns the
database/schema with `nexus_migrate`, creates or corrects the three runtime logins, removes unexpected
memberships in both directions, clears role-level configuration drift, and enforces non-administrative
attributes with unlimited validity and the canonical connection limit. `migrate` then applies append-only SQLx
migrations and explicit runtime grants. Long-running services start only after both one-shot roles
succeed.

PostgreSQL 首次创建 `nexus_bootstrap`。bootstrap 凭据只对 PostgreSQL 和一次性 `db-bootstrap`
容器可见。`db-bootstrap reconcile` 幂等地把数据库/schema 所有权交给 `nexus_migrate`，创建或校正
三个运行登录、双向移除意外成员关系、清除 role-level 配置漂移，并强制无限有效期、标准连接上限及
无管理属性。随后 `migrate` 执行追加式 SQLx migration 和显式
运行授权；两个一次性角色均成功后才启动常驻服务。

An existing installation whose `nexus_migrate` is still the initial superuser performs exactly one
guarded transition:

```bash
sudo camellia-nexus-deploy adopt-existing /opt/camellia-nexus/releases/<release-id>
sudo camellia-nexus-deploy deploy /opt/camellia-nexus/releases/<release-id>
```

The command creates and verifies `nexus_bootstrap`, reconnects with it, transfers ownership, and only
then removes superuser/role-creation/database-creation privileges from `nexus_migrate`. It never
deletes or recreates the PostgreSQL volume.

## Installation and release / 安装与发布

Use the Ansible role at `deploy/ansible/roles/camellia_nexus`. Required inputs are the formal release
source, `release-evidence.json`, encrypted SOPS bundle, host age identity, release ID, and a
non-secret environment mapping containing the application image digest. The role refuses
secret values in `config.env` and verifies Docker, Compose, SOPS, age, Cosign, jq, and Python before
installation. It installs but does not activate the release; only the readiness-gated deployment
command changes the `current` symlink.

Create the encrypted bundle on a controlled workstation, never on the production host or inside the
repository checkout:

```bash
umask 077
work=$(mktemp -d)
cp deploy/secrets.template.yaml "$work/secrets.yaml"
# Populate every placeholder from approved generators and custody systems.
age_recipient=$(age-keygen -y /secure/custody/production-age-identity.txt)
sops --encrypt --age "$age_recipient" \
  "$work/secrets.yaml" > /secure/deployment-inputs/secrets.sops.yaml
sops --decrypt /secure/deployment-inputs/secrets.sops.yaml >/dev/null
```

Securely remove the populated plaintext after independent validation. The host age identity is
delivered through the organization custody channel, not copied from a developer key. A minimal
controller play is:

```yaml
- hosts: nexus_management
  become: true
  roles:
    - role: camellia_nexus
  vars:
    camellia_nexus_release_id: "1.2.3-<commit>"
    camellia_nexus_release_source: /secure/releases/nexus-management-server-1.2.3
    camellia_nexus_release_evidence_source: /secure/evidence/release-evidence.json
    camellia_nexus_sops_bundle_source: /secure/deployment-inputs/secrets.sops.yaml
    camellia_nexus_age_identity_source: /secure/custody/host-age-identity.txt
    camellia_nexus_environment:
      CAMELLIA_NEXUS_LICENSE_IMAGE: "ghcr.io/camellia-computing/nexus-management-server@sha256:<digest>"
      CAMELLIA_NEXUS_LICENSE_ISSUER: "https://license.example.org"
      CAMELLIA_NEXUS_LICENSE_KEY_ID: "example-entitlement-key"
      CAMELLIA_NEXUS_CLIENT_MINIMUM_VERSION: "1.0.0"
      CAMELLIA_NEXUS_CLIENT_RECOMMENDED_VERSION: "1.0.0"
      CAMELLIA_NEXUS_CLIENT_VERSION_ENFORCE_AFTER: "2030-01-01T00:00:00Z"
      CAMELLIA_NEXUS_ADMIN_PUBLIC_ORIGIN: "https://console.example.org"
      CAMELLIA_NEXUS_OAUTH_REDIRECT_URIS: "camellia-nexus://auth/callback"
      CAMELLIA_NEXUS_CORS_ALLOWED_ORIGINS: "camellia-nexus://localhost"
```

The release source contains the reviewed `docker-compose.yml`; the evidence file is the exact formal
artifact produced for the same digest. `config.env` is rendered from the mapping with quoted dotenv
values and cannot contain secret values.

The standard release command is:

```bash
sudo camellia-nexus-deploy preflight /opt/camellia-nexus/releases/<release-id>
sudo camellia-nexus-deploy deploy /opt/camellia-nexus/releases/<release-id>
```

It holds a global deployment lock, validates formal evidence, the exact trusted Cosign/OIDC identity,
and Compose, prepares and validates every secret, rejects uncoordinated database password drift,
pulls immutable images, gates PostgreSQL and ClamAV health, reconciles database identities, runs
migration, rolls the three runtime roles, waits for readiness, and finally changes `current`.
It never runs `down -v`, `volume rm`, `system prune`, or a destructive database reset.

Bootstrap the first control-plane owner only after the stack is ready:

```bash
sudo camellia-nexus-deploy admin operator bootstrap owner \
  --display-name 'Primary owner' \
  --actor deployment \
  --reason 'initial control-plane bootstrap'
```

Treat the returned enrollment token as a one-display secret. Do not record it in tickets, terminal
transcripts, automation logs, or deployment state.

## Rotation / 轮换

Update the encrypted SOPS value under review, then run:

```bash
sudo camellia-nexus-deploy rotate-database-password public
```

Allowed targets are `bootstrap`, `migrate`, `public`, `admin-web`, and `admin-worker`. The command
prepares and validates the complete bundle without replacing the active files, requires exactly the
named database password to have changed, authenticates with the active bootstrap credential, and
updates desired role passwords in one database transaction. It then atomically activates the
prepared files, verifies the new bootstrap login, and recreates only the affected runtime (or
PostgreSQL itself for bootstrap rotation). If activation fails after the database transaction, the
command attempts to reconcile the database back to the still-active secret set. Replacing a source
file alone is insufficient: an existing bind mount can retain the old inode until recreation.

Keyring rotation follows add, distribute, activate, retire. Every replica receives the complete new
key set before `activeKeyId` changes, and an old key is retained while any database row, unexpired
artifact, or retained backup references it. After each reviewed SOPS change, run
`camellia-nexus-deploy reconcile`; the release path force-recreates all three long-running services so
no container retains a bind to the previous inode.

## Failure and recovery / 故障与恢复

- A secret validation, bootstrap, migration, or readiness failure stops the release before `current`
  changes. Inspect the retained failed one-shot logs without printing secret files.
- Boot-time staging compares the encrypted SOPS bundle with the hash in the last successful
  `/var/lib/camellia-nexus/deployment-state.json`. An uncoordinated bundle update keeps Docker stopped;
  restore the previous reviewed bundle or complete the locked deployment/rotation workflow.
- Roll back only to a formally verified release. If its migrations remain compatible, run
  `camellia-nexus-deploy rollback <release-directory>`; incompatible migration rollback requires the
  joint PostgreSQL/object/keyring recovery point.
- Never delete a production volume to repair bootstrap. `db-bootstrap reconcile` is safe for existing
  and restored databases.
- Back up PostgreSQL, object storage, all keyrings, entitlement recovery material, image digest, SOPS
  revision, and migration checksums as one named recovery point, then perform the documented isolated
  restore drill.

The host is dedicated to this stack because Docker is ordered after secret staging. If unrelated
Docker workloads must share the host, remove the Docker-wide dependency and migrate to a separate
Docker daemon or an orchestrator-native secret projection rather than weakening this contract.
