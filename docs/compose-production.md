# Shared-host Docker Compose deployment / 共享 Docker 主机上的 Compose 部署

This document is the production runbook for the Camellia Nexus Compose project. It assumes that
the Docker daemon is shared with other projects. No service in this project changes Docker daemon
startup, stops unrelated containers, or performs global cleanup.

本文是 Camellia Nexus Compose 项目的生产 runbook。Docker daemon 可以与其他项目共享。本项目不会
改变 Docker daemon 的启动顺序、停止其他容器，也不会执行全局清理。

## Filesystem contract / 文件系统契约

Run the project from `/usr/local/etc/docker/camellianexus-server` (or another dedicated project
directory):

```text
docker-compose.yml   root:root 0644
.env                 root:root 0600, non-secret values only
secrets/             root:root 0700
secrets/*            root:root 0444, regular non-symlink files
```

The `secrets/` directory is the host-side source for Compose file secrets. `0444` is intentional:
the root-only parent prevents ordinary host users from traversing the directory, while containers
do not need to know image-internal numeric UIDs. Compose mounts only the files declared for each
service and mounts them read-only. Do not use host `chown` rules tied to PostgreSQL or application
image UIDs.

Secret files must be replaced atomically in the same directory. Do not edit a mounted file in place:

```bash
install -o root -g root -m 0444 prepared-secret secrets/name.next
mv -T secrets/name.next secrets/name
```

The deployment `.env` contains image digests, URLs, ports, and runtime policy only. It must not
contain a password, private key, keyring, token, or proxy secret. SOPS, Vault, or another custody
system may be used to produce the root-owned files, but is not a runtime dependency of Compose.

## Database identities / 数据库身份

An empty PostgreSQL volume creates `nexus_bootstrap` from `POSTGRES_USER` and
`POSTGRES_PASSWORD_FILE`. The one-shot `db-bootstrap reconcile` connects with that role and:

- creates or corrects `nexus_migrate`, `nexus_public`, `nexus_admin_web`, and `nexus_admin_worker`;
- sets runtime roles to LOGIN, INHERIT, NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION,
  NOBYPASSRLS, unlimited validity, and the canonical connection limit;
- clears role configuration and unexpected memberships;
- transfers the database and `public` schema ownership to `nexus_migrate`.

`migrate` applies SQLx migrations and explicit grants using the non-superuser migration role. Long-
lived roles start only after migration succeeds. `db-bootstrap check` is read-only and verifies the
same contract. This deployment path supports a fresh volume; it does not automatically adopt a
legacy database whose migration role is still a superuser.

## Initial deployment / 首次部署

Prepare `.env` and all ten secret files, then run the following commands from the project directory:

```bash
docker compose config --quiet
docker compose pull
docker compose run --rm --no-deps secret-validator
docker compose up -d --no-deps --wait postgres clamav
docker compose run --rm --no-deps db-bootstrap
docker compose run --rm --no-deps migrate
docker compose up -d --no-deps --wait management-server admin-web
docker compose up -d --no-deps --wait admin-worker
docker compose ps
```

The one-shot containers are run with `--rm`, so every deployment evaluates the current image and
secret files. The named PostgreSQL and ClamAV volumes are preserved.

## Release or configuration change / 发布或配置变更

Before a schema-changing release, create a recovery point containing PostgreSQL, object data,
keyrings, entitlement material, migration version, and image digest. Stop the long-lived application
roles before applying a migration:

```bash
docker compose pull
docker compose stop management-server admin-web admin-worker
docker compose run --rm --no-deps secret-validator
docker compose up -d --no-deps --wait postgres clamav
docker compose run --rm --no-deps db-bootstrap
docker compose run --rm --no-deps migrate
docker compose up -d --no-deps --force-recreate --wait management-server admin-web
docker compose up -d --no-deps --force-recreate --wait admin-worker
```

`--force-recreate` recreates only application containers; it does not rebuild images or recreate
volumes. The final `--wait` requires the configured readiness healthchecks to pass.

## Manually changing a runtime database secret / 人工修改运行数据库 secret

Changing a long-lived application role password has two separate effects:

1. `db-bootstrap reconcile` executes `ALTER ROLE` in PostgreSQL; PostgreSQL itself does not need to
   restart.
2. The application reads `DATABASE_PASSWORD_FILE` when its connection pool is created. After the
   role password changes, recreate the affected application container so it receives the new file
   mount and creates a pool with the new password.

For a single application role, stop only its service, replace the file atomically, then run:

```bash
docker compose run --rm --no-deps secret-validator
docker compose run --rm --no-deps db-bootstrap
docker compose up -d --no-deps --force-recreate --wait <affected-service>
```

The service mapping is `nexus_public` → `management-server`, `nexus_admin_web` → `admin-web`, and
`nexus_admin_worker` → `admin-worker`. The PostgreSQL container and volume remain untouched.

The migration password has no long-lived consumer. After atomically replacing
`database-migrate-password`, run `secret-validator`, `db-bootstrap`, and `migrate`; no application or
PostgreSQL container needs to be recreated. `db-bootstrap` reconciles all four managed non-bootstrap
passwords from their current files, so stop all affected application services before reconciling
when multiple application password files change.

The bootstrap password is different: `POSTGRES_PASSWORD_FILE` is consumed only when an empty volume
is initialized. Replacing that file does not change `nexus_bootstrap` in an existing database and
must not be used as an ordinary rotation procedure. A bootstrap credential change requires a
separately reviewed DBA maintenance operation.

Keyring or entitlement-key changes also require recreation of every service that mounts the changed
file. Existing connections and processes do not reload those files automatically.

## Restart, rollback, and monitoring / 重启、回滚与监控

- Docker restarts this project's long-lived containers according to their Compose restart policy;
  no project systemd unit is required.
- A host reboot does not require secret staging because the root-only source files are persistent.
- Roll back by changing the application image digest to a migration-compatible release and running
  the same ordered commands. Do not delete volumes or run `docker system prune`.
- Monitor `/healthz`, `/readyz`, and the private metrics listeners through the host's existing
  monitoring system. This repository does not install a health timer.
- `docker compose down` is project-scoped. Never use `down -v` in production.

## Verification / 验证

CI and release checks must cover a fresh volume, repeated reconcile, role and ownership drift,
secret permissions, atomic secret replacement, targeted container recreation, readiness, and a
sentinel container from an unrelated Compose project. The test must assert that no Docker daemon
drop-in, project systemd unit, release-state directory, or SOPS runtime dependency is installed.
