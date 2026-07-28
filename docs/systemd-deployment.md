# systemd deployment / systemd 部署

The non-container deployment uses four explicit units from `deploy/systemd/`. A long-lived process
never applies migrations on startup.

非容器部署使用 `deploy/systemd/` 中的四个显式 unit。任何常驻进程都不会在启动时自动迁移。

| Unit | Role / 角色 | Environment / 环境文件 |
| --- | --- | --- |
| `camellia-nexus-management-migrate.service` | one-shot schema migration / 一次性迁移 | `management-common.env` |
| `camellia-nexus-management-server.service` | public license API / 公开授权 API | common + `public-api.env` |
| `camellia-nexus-management-admin-web.service` | private Admin UI/API / 私有管理面 | common + `admin-web.env` |
| `camellia-nexus-management-admin-worker.service` | jobs, scanning and cleanup / 任务、扫描与清理 | common + `admin-worker.env` |

## Installation / 安装

Create a dedicated unprivileged account, install the verified binary and Admin assets read-only, and
create the state and secret directories with restrictive ownership. The example assumes the
PostgreSQL and ClamAV endpoints are already reachable from the service account.

创建专用非特权账号，以只读方式安装经过验证的二进制与 Admin 静态资源，并使用严格所有权建立状态和
secret 目录。示例假设 PostgreSQL 与 ClamAV 已可由该服务账号访问。

```bash
sudo useradd --system --home-dir /var/lib/camellia-nexus \
  --shell /usr/sbin/nologin camellia-license
sudo install -o root -g root -m 0755 camellia-nexus-management-server \
  /usr/local/bin/camellia-nexus-management-server
sudo install -d -o root -g root -m 0755 /usr/share/camellia-nexus/admin-ui
sudo install -d -o camellia-license -g camellia-license -m 0700 \
  /var/lib/camellia-nexus
sudo install -d -o root -g camellia-license -m 0750 \
  /etc/camellia-nexus /etc/camellia-nexus/secrets
sudo install -o root -g root -m 0644 deploy/systemd/*.service /etc/systemd/system/
```

Copy the four `deploy/*.env.example` files to `/etc/camellia-nexus/` without the `.example` suffix.
Keep `management-common.env` limited to database/log/trusted-time settings and place role-specific
secrets only in the role file that consumes them. Environment files should be `0640 root:camellia-license`;
private key and keyring files should be `0640` or stricter, regular files, and no larger than 64 KiB.
Each keyring may contain 1–64 keys. Do not put PEM, keyring JSON, proxy secrets, passwords or tokens
directly in a unit.

将四个 `deploy/*.env.example` 复制到 `/etc/camellia-nexus/` 并去掉 `.example`。公共文件只保存数据库、
日志与可信时间设置，各角色 secret 只放在实际消费它的角色文件中。环境文件应为
`0640 root:camellia-license`，私钥和 keyring 权限应为 `0640` 或更严格，且必须为不超过 64 KiB 的
常规文件；每个 keyring 可包含 1–64 个 key。不得把 PEM、keyring JSON、代理 secret、密码或 token
直接写入 unit。

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
