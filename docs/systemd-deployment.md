# systemd deployment / systemd 部署

The non-container deployment uses four explicit units from `deploy/systemd/`. A long-lived process
never applies migrations on startup.

非容器部署使用 `deploy/systemd/` 中的四个显式 unit。任何常驻进程都不会在启动时自动迁移。

| Unit | Role / 角色 | Environment / 环境文件 |
| --- | --- | --- |
| `camellia-nexus-management-migrate.service` | one-shot schema migration and runtime grants / 一次性迁移及运行时授权 | common + `migrate.env` |
| `camellia-nexus-management-server.service` | public license API / 公开授权 API | common + `public-api.env` |
| `camellia-nexus-management-admin-web.service` | private Admin UI/API / 私有管理面 | common + `admin-web.env` |
| `camellia-nexus-management-admin-worker.service` | jobs, scanning and cleanup / 任务、扫描与清理 | common + `admin-worker.env` |

## Installation / 安装

Create one unprivileged identity per trust boundary. Public API code must not share a UID, secret
group, writable directory, or database login with either administration role. Admin Web and Worker
share only the encrypted Admin keyring and object directory required by their joint workflow.
Install the verified binary and Admin assets read-only. The example assumes PostgreSQL and ClamAV
are already reachable.

每个信任边界使用独立非特权身份。公开 API 不得与任一管理角色共用 UID、secret 组、可写目录或
数据库登录；Admin Web 与 Worker 仅共享两者协作所必需的加密 keyring 和对象目录。以只读方式安装
经过验证的二进制与 Admin 静态资源。示例假设 PostgreSQL 与 ClamAV 已可访问。

```bash
sudo groupadd --system camellia-nexus-admin
for role in migrate public admin-web admin-worker; do
  sudo useradd --system --no-create-home --home-dir /nonexistent \
    --shell /usr/sbin/nologin "camellia-nexus-$role"
done
sudo usermod --append --groups camellia-nexus-admin camellia-nexus-admin-web
sudo usermod --append --groups camellia-nexus-admin camellia-nexus-admin-worker
sudo install -o root -g root -m 0755 camellia-nexus-management-server \
  /usr/local/bin/camellia-nexus-management-server
sudo install -d -o root -g root -m 0755 /usr/share/camellia-nexus/admin-ui
sudo install -d -o root -g root -m 0700 /etc/camellia-nexus
sudo install -d -o root -g root -m 0711 /etc/camellia-nexus/secrets
sudo install -d -o root -g camellia-nexus-public -m 0750 \
  /etc/camellia-nexus/secrets/public
sudo install -d -o root -g camellia-nexus-admin -m 0750 \
  /etc/camellia-nexus/secrets/admin
sudo install -d -o camellia-nexus-admin-web -g camellia-nexus-admin -m 0770 \
  /var/lib/camellia-nexus/admin-objects
sudo install -o root -g root -m 0644 deploy/systemd/*.service /etc/systemd/system/
```

Copy the five `deploy/*.env.example` files to `/etc/camellia-nexus/` without `.example`.
`management-common.env` contains only non-secret shared settings; every `DATABASE_URL` belongs in
its role file. Environment files are `0600 root:root` because systemd reads them before changing
UID. Public private keys are `0640 root:camellia-nexus-public`; Admin keyrings and proxy secrets are
`0640 root:camellia-nexus-admin`. Secret inputs must be regular files no larger than 64 KiB, and a
keyring may contain 1–64 keys. Never place secret material directly in a unit or the common file.

将五个 `deploy/*.env.example` 复制到 `/etc/camellia-nexus/` 并去掉 `.example`。
`management-common.env` 只含非敏感公共设置，每个 `DATABASE_URL` 均放入对应角色文件。systemd 会在
切换 UID 前读取环境文件，因此权限设为 `0600 root:root`。公开面私钥使用
`0640 root:camellia-nexus-public`，管理 keyring 与代理 secret 使用
`0640 root:camellia-nexus-admin`。secret 必须是不超过 64 KiB 的常规文件，每个 keyring 可含
1–64 个 key。不得把 secret 写入 unit 或公共文件。

## Database identities / 数据库身份

Use a dedicated database owned by the migration login and three non-administrative runtime logins.
Passwords used inside PostgreSQL URLs should be independently generated 32–128 character URL-safe
values. Before first start, create the logins and database as a PostgreSQL administrator; enter
passwords interactively with `\password`, not in shell history.

使用由迁移账号拥有的专用数据库，以及三个无管理属性的运行时登录。放入 PostgreSQL URL 的密码应分别
生成 32–128 位 URL-safe 随机值。首次启动前以 PostgreSQL 管理员创建登录和数据库，并通过
`\password` 交互录入密码，避免写入 shell 历史。

```sql
CREATE ROLE nexus_migrate LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE nexus_public LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE nexus_admin_web LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE nexus_admin_worker LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE DATABASE nexus OWNER nexus_migrate;
\password nexus_migrate
\password nexus_public
\password nexus_admin_web
\password nexus_admin_worker
```

The migration command revokes ambient `PUBLIC` access and atomically reapplies an explicit table
allowlist after every migration. It fails if any runtime role is missing, privileged, duplicated, or
if a new table has not been classified. The public login has no DDL or Admin identity/job/storage
table access. Validate this from the deployment network before accepting a rollout.

迁移命令会撤销环境中的 `PUBLIC` 权限，并在每次迁移后按显式表清单原子重授。任何运行角色缺失、带有
管理属性、重复，或新增表未分类时都会失败。公开登录不具备 DDL，也不能访问 Admin 身份、任务和对象
存储表。接受发布前必须从部署网络验证该边界。

Each role has a distinct operations port (`9091`, `9092`, `9093` in the examples). These ports serve
only `/healthz` and `/metrics`; keep them loopback-bound or behind a private metrics network. Public
and Admin product traffic retain their own listeners.

每个角色使用独立运维端口（示例为 `9091`、`9092`、`9093`），且只提供 `/healthz` 与 `/metrics`。
端口必须绑定回环或位于私有指标网络；公开业务与 Admin 流量继续使用各自独立监听器。

## First start and upgrade / 首次启动与升级

```bash
sudo systemctl daemon-reload
sudo systemctl start camellia-nexus-management-migrate.service
sudo systemctl enable --now \
  camellia-nexus-management-server.service \
  camellia-nexus-management-admin-web.service \
  camellia-nexus-management-admin-worker.service
```

The migration unit uses `RemainAfterExit=yes` to order the long-lived units at boot. For every new
verified release, explicitly restart the migration unit before restarting the other roles; do not
assume the previous successful state applies to a new binary.

迁移 unit 通过 `RemainAfterExit=yes` 保证开机顺序。每次部署新的已验证版本时，都必须先显式重启迁移
unit，再重启其他角色；不得把旧二进制的成功状态当作新版本已完成迁移。

```bash
sudo systemctl restart camellia-nexus-management-migrate.service
sudo systemctl restart camellia-nexus-management-server.service
sudo systemctl restart camellia-nexus-management-admin-web.service
sudo systemctl restart camellia-nexus-management-admin-worker.service
```

Accept the rollout only after public and Admin `/readyz`, all three metrics `/healthz` endpoints,
the expected binary version, Admin authentication and one worker operation succeed. All units use a
30-second stop timeout to cover request draining and claimed work.

只有公开/Admin `/readyz`、三个指标 `/healthz`、预期二进制版本、Admin 登录和一次 Worker 任务均成功
后才能接受发布。所有 unit 均保留 30 秒退出窗口，以覆盖请求排空与已认领工作。

## Rollback / 回滚

Rollback uses a previously verified binary and assets. Never edit `_sqlx_migrations` or run a schema
downgrade. If the new release applied an incompatible migration, restore the joint database/keyring/
object-store recovery point described in `docs/runbooks/backup-restore.md`; otherwise roll the
long-lived units back after confirming the older binary's readiness against the current schema.

回滚使用此前已验证的二进制和静态资源。不得编辑 `_sqlx_migrations` 或执行 schema downgrade。若新版
应用了不兼容迁移，按 `docs/runbooks/backup-restore.md` 恢复数据库、keyring 与对象存储联合恢复点；若
schema 兼容，则在确认旧二进制对当前 schema readiness 通过后回滚常驻 unit。

Run `bash scripts/test-systemd-deployment.sh` after changing any unit, environment example, role,
shutdown behavior, metrics listener or migration ordering.

修改 unit、环境示例、运行角色、退出行为、指标监听器或迁移顺序后，必须运行
`bash scripts/test-systemd-deployment.sh`。
