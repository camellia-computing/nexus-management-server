# Backup and restore runbook

Camellia Nexus recovery is valid only when PostgreSQL, payment-evidence objects, the administrator,
Workspace and Webhook keyrings, the entitlement signing key set, the application image digest, and
the migration manifest come from one recorded recovery point. Restoring only the database or only
the keyrings can make administrator credentials, TOTP material, secret deliveries, shared
configurations, webhook secrets, and evidence permanently unreadable.

## Required recovery-point manifest

Record the UTC timestamp, PostgreSQL WAL/backup identifier, object-store snapshot/version,
all three keyring versions and checksums, entitlement public key IDs, immutable application image
digest, and `_sqlx_migrations` version/checksum list. Store the manifest and encrypted key material
in a separately controlled backup system. Never place keys or backup credentials in this repository.

## Backup procedure

1. Confirm `/readyz` for public and administrator roles and verify the worker is processing jobs.
2. Capture a PostgreSQL base backup and retain WAL for point-in-time recovery. Snapshot the object
   backend at the same logical recovery point.
3. Export all three complete keyrings, including retired keys still referenced by rows, and the
   entitlement signing recovery material through the organization secret-custody process.
4. Record image digests and migration checksums in the recovery-point manifest.
5. Restore the backup into an isolated environment and run the verification below before marking it
   usable. A backup that has not passed restore verification is not a production backup.

## Restore and verification

1. Provision an isolated PostgreSQL instance and object backend. Restore PostgreSQL to the chosen
   WAL point, then restore the matching object snapshot.
2. Mount the matching administrator, Workspace and Webhook keyrings and entitlement material
   read-only. Deploy `migrate`, `serve`, `admin-web`, and `admin-worker` from the single digest in
   the manifest.
3. Run schema readiness without changing data, then apply only migrations contained in the deployed
   digest. Stop if any applied checksum differs.
4. Verify public and administrator readiness, administrator password+TOTP login, sampled encrypted
   payment evidence and historical shared-configuration reads, Webhook secret rotation and a signed
   delivery, entitlement signing/verification, trusted-time status, and audit continuity.
5. Revoke every temporary restore credential, destroy plaintext exports, and retain the drill report.

Production owners must set and review explicit RPO/RTO targets and perform this drill at least once
per release train and after any keyring, object-storage, or migration mechanism change.
