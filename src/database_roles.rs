use std::{collections::BTreeSet, env};

use sqlx::{AssertSqlSafe, PgPool, Row};
use thiserror::Error;

use crate::{config::Environment, store::PostgresRepository};

const PUBLIC_ROLE_ENV: &str = "CAMELLIA_NEXUS_DATABASE_PUBLIC_ROLE";
const ADMIN_WEB_ROLE_ENV: &str = "CAMELLIA_NEXUS_DATABASE_ADMIN_WEB_ROLE";
const ADMIN_WORKER_ROLE_ENV: &str = "CAMELLIA_NEXUS_DATABASE_ADMIN_WORKER_ROLE";

const ALL_APPLICATION_TABLES: &[&str] = &[
    "accounts",
    "activation_codes",
    "admin_bulk_job_items",
    "admin_bulk_jobs",
    "admin_bulk_previews",
    "admin_enrollment_states",
    "admin_enrollment_tokens",
    "admin_login_buckets",
    "admin_operations",
    "admin_password_credentials",
    "admin_recovery_codes",
    "admin_role_bindings",
    "admin_secret_deliveries",
    "admin_sessions",
    "admin_totp_credentials",
    "admin_users",
    "audit_archive_manifests",
    "audit_events",
    "authorization_codes",
    "billing_invoices",
    "commercial_offers",
    "customer_payment_operations",
    "device_challenges",
    "device_member_bindings",
    "device_removal_operations",
    "devices",
    "licenses",
    "manual_payment_claims",
    "manual_payment_methods",
    "member_device_enrollments",
    "payment_evidence_attachments",
    "rate_limit_buckets",
    "refresh_sessions",
    "service_time_authority",
    "stored_object_chunks",
    "stored_objects",
    "team_invitations",
    "team_operations",
    "workspace_alert_incidents",
    "workspace_alert_rules",
    "workspace_changes",
    "workspace_device_checkpoints",
    "workspace_document_revisions",
    "workspace_documents",
    "workspace_members",
    "workspace_operations",
    "workspace_storage_usage",
    "workspace_webhook_deliveries",
    "workspace_webhook_endpoints",
    "workspace_webhook_events",
    "workspace_webhook_operations",
];

const PUBLIC_TABLES: &[&str] = &[
    "accounts",
    "activation_codes",
    "audit_events",
    "authorization_codes",
    "billing_invoices",
    "commercial_offers",
    "customer_payment_operations",
    "device_challenges",
    "device_member_bindings",
    "device_removal_operations",
    "devices",
    "licenses",
    "manual_payment_claims",
    "manual_payment_methods",
    "member_device_enrollments",
    "rate_limit_buckets",
    "refresh_sessions",
    "service_time_authority",
    "team_invitations",
    "team_operations",
    "workspace_alert_incidents",
    "workspace_alert_rules",
    "workspace_changes",
    "workspace_device_checkpoints",
    "workspace_document_revisions",
    "workspace_documents",
    "workspace_members",
    "workspace_operations",
    "workspace_storage_usage",
    "workspace_webhook_deliveries",
    "workspace_webhook_endpoints",
    "workspace_webhook_events",
    "workspace_webhook_operations",
];

const ADMIN_WORKER_TABLES: &[&str] = &[
    "accounts",
    "activation_codes",
    "admin_bulk_job_items",
    "admin_bulk_jobs",
    "admin_enrollment_states",
    "admin_enrollment_tokens",
    "admin_operations",
    "admin_role_bindings",
    "admin_secret_deliveries",
    "admin_users",
    "audit_events",
    "billing_invoices",
    "device_member_bindings",
    "devices",
    "licenses",
    "manual_payment_claims",
    "payment_evidence_attachments",
    "service_time_authority",
    "stored_object_chunks",
    "stored_objects",
];

const ADMIN_WORKER_UPDATE_TABLES: &[&str] = &[
    "accounts",
    "activation_codes",
    "admin_bulk_job_items",
    "admin_bulk_jobs",
    "admin_operations",
    "billing_invoices",
    "devices",
    "licenses",
    "manual_payment_claims",
    "payment_evidence_attachments",
    "service_time_authority",
    "stored_objects",
];

const ADMIN_WORKER_INSERT_TABLES: &[&str] = &["admin_operations", "audit_events"];

const ADMIN_WORKER_DELETE_TABLES: &[&str] = &[
    "admin_enrollment_states",
    "admin_secret_deliveries",
    "device_member_bindings",
    "stored_objects",
];

#[derive(Debug, Error)]
pub enum DatabaseRoleError {
    #[error("database runtime-role configuration is incomplete: {0}")]
    Configuration(String),
    #[error("database runtime-role contract is invalid: {0}")]
    Contract(String),
    #[error("database runtime grants failed")]
    Database(#[source] sqlx::Error),
}

#[derive(Debug, Clone)]
struct RuntimeDatabaseRoles {
    public: String,
    admin_web: String,
    admin_worker: String,
}

impl RuntimeDatabaseRoles {
    fn from_environment(environment: Environment) -> Result<Option<Self>, DatabaseRoleError> {
        let values = [
            (PUBLIC_ROLE_ENV, env::var(PUBLIC_ROLE_ENV).ok()),
            (ADMIN_WEB_ROLE_ENV, env::var(ADMIN_WEB_ROLE_ENV).ok()),
            (ADMIN_WORKER_ROLE_ENV, env::var(ADMIN_WORKER_ROLE_ENV).ok()),
        ];
        if values.iter().all(|(_, value)| value.is_none()) {
            return if environment == Environment::Production {
                Err(DatabaseRoleError::Configuration(format!(
                    "{PUBLIC_ROLE_ENV}, {ADMIN_WEB_ROLE_ENV}, and {ADMIN_WORKER_ROLE_ENV} are required in production"
                )))
            } else {
                Ok(None)
            };
        }
        let missing = values
            .iter()
            .filter_map(|(name, value)| value.is_none().then_some(*name))
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(DatabaseRoleError::Configuration(format!(
                "missing {}",
                missing.join(", ")
            )));
        }
        let roles = Self {
            public: values[0].1.clone().unwrap_or_default(),
            admin_web: values[1].1.clone().unwrap_or_default(),
            admin_worker: values[2].1.clone().unwrap_or_default(),
        };
        let distinct = [&roles.public, &roles.admin_web, &roles.admin_worker]
            .into_iter()
            .collect::<BTreeSet<_>>();
        if distinct.len() != 3 {
            return Err(DatabaseRoleError::Contract(
                "public, Admin Web, and Admin Worker roles must be distinct".to_owned(),
            ));
        }
        for role in [&roles.public, &roles.admin_web, &roles.admin_worker] {
            validate_role_name(role)?;
        }
        Ok(Some(roles))
    }
}

/// Replaces ambient PostgreSQL privileges with explicit per-runtime grants.
///
/// This runs after every schema migration. A newly added table fails closed until
/// it is classified here, preventing a migration from silently widening the
/// public runtime's database access.
pub async fn apply_runtime_database_grants(
    repository: &PostgresRepository,
    environment: Environment,
) -> Result<bool, DatabaseRoleError> {
    let Some(roles) = RuntimeDatabaseRoles::from_environment(environment)? else {
        return Ok(false);
    };
    apply_runtime_database_grants_for_roles(&repository.pool, &roles).await?;
    Ok(true)
}

async fn apply_runtime_database_grants_for_roles(
    pool: &PgPool,
    roles: &RuntimeDatabaseRoles,
) -> Result<(), DatabaseRoleError> {
    validate_schema_contract(pool).await?;
    validate_roles(pool, roles).await?;

    let mut transaction = pool.begin().await.map_err(DatabaseRoleError::Database)?;
    let database_name: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&mut *transaction)
        .await
        .map_err(DatabaseRoleError::Database)?;
    let database = quote_identifier(&database_name);
    execute(
        &mut transaction,
        &format!("REVOKE CONNECT, TEMPORARY ON DATABASE {database} FROM PUBLIC"),
    )
    .await?;
    execute(
        &mut transaction,
        "REVOKE CREATE ON SCHEMA public FROM PUBLIC",
    )
    .await?;
    execute(
        &mut transaction,
        "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM PUBLIC",
    )
    .await?;
    execute(
        &mut transaction,
        "REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC",
    )
    .await?;
    execute(
        &mut transaction,
        "REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC",
    )
    .await?;

    for role in [&roles.public, &roles.admin_web, &roles.admin_worker] {
        let role = quote_identifier(role);
        execute(
            &mut transaction,
            &format!("REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM {role}"),
        )
        .await?;
        execute(
            &mut transaction,
            &format!("REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM {role}"),
        )
        .await?;
        execute(
            &mut transaction,
            &format!("REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM {role}"),
        )
        .await?;
        execute(
            &mut transaction,
            &format!("GRANT CONNECT ON DATABASE {database} TO {role}"),
        )
        .await?;
        execute(
            &mut transaction,
            &format!("GRANT USAGE ON SCHEMA public TO {role}"),
        )
        .await?;
        execute(
            &mut transaction,
            &format!("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role}"),
        )
        .await?;
        execute(
            &mut transaction,
            &format!("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO {role}"),
        )
        .await?;
    }

    grant_table_privileges(
        &mut transaction,
        &roles.public,
        "SELECT, INSERT, UPDATE, DELETE",
        PUBLIC_TABLES,
    )
    .await?;
    grant_table_privileges(
        &mut transaction,
        &roles.admin_web,
        "SELECT, INSERT, UPDATE, DELETE",
        ALL_APPLICATION_TABLES,
    )
    .await?;
    grant_table_privileges(
        &mut transaction,
        &roles.admin_worker,
        "SELECT",
        ADMIN_WORKER_TABLES,
    )
    .await?;
    grant_table_privileges(
        &mut transaction,
        &roles.admin_worker,
        "UPDATE",
        ADMIN_WORKER_UPDATE_TABLES,
    )
    .await?;
    grant_table_privileges(
        &mut transaction,
        &roles.admin_worker,
        "INSERT",
        ADMIN_WORKER_INSERT_TABLES,
    )
    .await?;
    grant_table_privileges(
        &mut transaction,
        &roles.admin_worker,
        "DELETE",
        ADMIN_WORKER_DELETE_TABLES,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(DatabaseRoleError::Database)?;
    Ok(())
}

async fn validate_schema_contract(pool: &PgPool) -> Result<(), DatabaseRoleError> {
    let actual = sqlx::query_scalar::<_, String>(
        "SELECT tablename FROM pg_tables
         WHERE schemaname = 'public' AND tablename <> '_sqlx_migrations'
         ORDER BY tablename",
    )
    .fetch_all(pool)
    .await
    .map_err(DatabaseRoleError::Database)?
    .into_iter()
    .collect::<BTreeSet<_>>();
    let expected = ALL_APPLICATION_TABLES
        .iter()
        .map(|table| (*table).to_owned())
        .collect::<BTreeSet<_>>();
    if actual != expected {
        let unclassified = actual.difference(&expected).cloned().collect::<Vec<_>>();
        let missing = expected.difference(&actual).cloned().collect::<Vec<_>>();
        return Err(DatabaseRoleError::Contract(format!(
            "schema table classification drift (unclassified: {}; missing: {})",
            display_names(&unclassified),
            display_names(&missing)
        )));
    }
    let security_definers = sqlx::query_scalar::<_, String>(
        "SELECT procedure.proname
         FROM pg_proc AS procedure
         JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
         WHERE namespace.nspname = 'public' AND procedure.prosecdef
         ORDER BY procedure.proname",
    )
    .fetch_all(pool)
    .await
    .map_err(DatabaseRoleError::Database)?;
    if !security_definers.is_empty() {
        return Err(DatabaseRoleError::Contract(format!(
            "SECURITY DEFINER functions require an explicit privilege design: {}",
            display_names(&security_definers)
        )));
    }
    Ok(())
}

async fn validate_roles(
    pool: &PgPool,
    roles: &RuntimeDatabaseRoles,
) -> Result<(), DatabaseRoleError> {
    let requested = vec![
        roles.public.clone(),
        roles.admin_web.clone(),
        roles.admin_worker.clone(),
    ];
    let rows = sqlx::query(
        "SELECT rolname, rolcanlogin, rolsuper, rolcreaterole, rolcreatedb, rolreplication,
                rolbypassrls, rolname = current_user AS is_current_user
         FROM pg_roles WHERE rolname = ANY($1)",
    )
    .bind(&requested)
    .fetch_all(pool)
    .await
    .map_err(DatabaseRoleError::Database)?;
    if rows.len() != requested.len() {
        let found = rows
            .iter()
            .filter_map(|row| row.try_get::<String, _>("rolname").ok())
            .collect::<BTreeSet<_>>();
        let missing = requested
            .into_iter()
            .filter(|role| !found.contains(role))
            .collect::<Vec<_>>();
        return Err(DatabaseRoleError::Contract(format!(
            "runtime roles do not exist: {}",
            display_names(&missing)
        )));
    }
    for row in rows {
        let role: String = row
            .try_get("rolname")
            .map_err(|_| DatabaseRoleError::Contract("invalid role metadata".to_owned()))?;
        let can_login = row.try_get::<bool, _>("rolcanlogin").unwrap_or(false);
        let is_current_user = row.try_get::<bool, _>("is_current_user").unwrap_or(true);
        let privileged = [
            "rolsuper",
            "rolcreaterole",
            "rolcreatedb",
            "rolreplication",
            "rolbypassrls",
        ]
        .into_iter()
        .any(|column| row.try_get::<bool, _>(column).unwrap_or(true));
        if !can_login || is_current_user || privileged {
            return Err(DatabaseRoleError::Contract(format!(
                "runtime role {role} must be a distinct non-administrative login"
            )));
        }
    }
    Ok(())
}

async fn grant_table_privileges(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    role: &str,
    privileges: &'static str,
    tables: &[&str],
) -> Result<(), DatabaseRoleError> {
    let table_list = tables
        .iter()
        .map(|table| format!("public.{}", quote_identifier(table)))
        .collect::<Vec<_>>()
        .join(", ");
    execute(
        transaction,
        &format!(
            "GRANT {privileges} ON TABLE {table_list} TO {}",
            quote_identifier(role)
        ),
    )
    .await
}

async fn execute(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    statement: &str,
) -> Result<(), DatabaseRoleError> {
    // Every dynamic identifier is either a catalog-derived database name escaped
    // by quote_identifier or a role/table name from the strict static contract.
    sqlx::query(AssertSqlSafe(statement))
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(DatabaseRoleError::Database)
}

fn validate_role_name(role: &str) -> Result<(), DatabaseRoleError> {
    let valid = !role.is_empty()
        && role.len() <= 63
        && role.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'_' => true,
            b'0'..=b'9' => index > 0,
            _ => false,
        });
    if valid {
        Ok(())
    } else {
        Err(DatabaseRoleError::Configuration(format!(
            "runtime role {role:?} must be a lowercase PostgreSQL identifier"
        )))
    }
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn display_names(names: &[String]) -> String {
    if names.is_empty() {
        "none".to_owned()
    } else {
        names.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random_id;

    #[test]
    fn role_names_are_strict_and_injection_safe() {
        for valid in ["nexus_public", "_nexus_worker", "role1"] {
            assert!(validate_role_name(valid).is_ok());
        }
        for invalid in ["", "Nexus", "1role", "role-name", "role\";DROP ROLE owner"] {
            assert!(validate_role_name(invalid).is_err());
        }
    }

    #[test]
    fn every_narrow_role_table_is_classified() {
        let all = ALL_APPLICATION_TABLES
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        assert!(PUBLIC_TABLES.iter().all(|table| all.contains(table)));
        assert!(ADMIN_WORKER_TABLES.iter().all(|table| all.contains(table)));
        assert!(
            ADMIN_WORKER_UPDATE_TABLES
                .iter()
                .all(|table| ADMIN_WORKER_TABLES.contains(table))
        );
        assert!(
            ADMIN_WORKER_INSERT_TABLES
                .iter()
                .all(|table| ADMIN_WORKER_TABLES.contains(table))
        );
        assert!(
            ADMIN_WORKER_DELETE_TABLES
                .iter()
                .all(|table| ADMIN_WORKER_TABLES.contains(table))
        );
        assert!(
            !PUBLIC_TABLES
                .iter()
                .any(|table| table.starts_with("admin_"))
        );
        assert!(!PUBLIC_TABLES.contains(&"stored_objects"));
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL and a migration owner that can create test roles"]
    async fn runtime_grants_deny_public_admin_data_and_worker_credentials() {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the PostgreSQL integration test");
        let repository =
            PostgresRepository::connect(&database_url, 2, std::time::Duration::from_secs(5))
                .await
                .expect("connect PostgreSQL");
        repository.migrate().await.expect("run migrations");
        let suffix = random_id("role_test")
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect::<String>()
            .to_ascii_lowercase();
        let roles = RuntimeDatabaseRoles {
            public: format!("test_public_{suffix}"),
            admin_web: format!("test_admin_web_{suffix}"),
            admin_worker: format!("test_worker_{suffix}"),
        };
        for role in [&roles.public, &roles.admin_web, &roles.admin_worker] {
            validate_role_name(role).expect("generated role must be valid");
            sqlx::query(AssertSqlSafe(format!(
                "CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE \
                 NOREPLICATION NOBYPASSRLS",
                quote_identifier(role)
            )))
            .execute(&repository.pool)
            .await
            .expect("create test runtime role");
        }
        apply_runtime_database_grants_for_roles(&repository.pool, &roles)
            .await
            .expect("apply runtime grants");

        let public_account: bool =
            sqlx::query_scalar("SELECT has_table_privilege($1, 'accounts', 'SELECT')")
                .bind(&roles.public)
                .fetch_one(&repository.pool)
                .await
                .expect("inspect public account privilege");
        let public_admin: bool =
            sqlx::query_scalar("SELECT has_table_privilege($1, 'admin_users', 'SELECT')")
                .bind(&roles.public)
                .fetch_one(&repository.pool)
                .await
                .expect("inspect public Admin privilege");
        let public_ddl: bool =
            sqlx::query_scalar("SELECT has_schema_privilege($1, 'public', 'CREATE')")
                .bind(&roles.public)
                .fetch_one(&repository.pool)
                .await
                .expect("inspect public schema privilege");
        let worker_jobs: bool =
            sqlx::query_scalar("SELECT has_table_privilege($1, 'admin_bulk_jobs', 'UPDATE')")
                .bind(&roles.admin_worker)
                .fetch_one(&repository.pool)
                .await
                .expect("inspect Worker job privilege");
        let worker_passwords: bool = sqlx::query_scalar(
            "SELECT has_table_privilege($1, 'admin_password_credentials', 'SELECT')",
        )
        .bind(&roles.admin_worker)
        .fetch_one(&repository.pool)
        .await
        .expect("inspect Worker credential privilege");
        let worker_identity_insert: bool =
            sqlx::query_scalar("SELECT has_table_privilege($1, 'admin_users', 'INSERT')")
                .bind(&roles.admin_worker)
                .fetch_one(&repository.pool)
                .await
                .expect("inspect Worker identity mutation privilege");

        let test_owner: String = sqlx::query_scalar("SELECT current_user")
            .fetch_one(&repository.pool)
            .await
            .expect("inspect test database owner");
        for role in [&roles.public, &roles.admin_web, &roles.admin_worker] {
            sqlx::query(AssertSqlSafe(format!(
                "GRANT {} TO {}",
                quote_identifier(role),
                quote_identifier(&test_owner)
            )))
            .execute(&repository.pool)
            .await
            .expect("allow the test owner to assume and clean up each runtime role");
        }
        let worker_role = quote_identifier(&roles.admin_worker);
        let worker_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .after_connect(move |connection, _| {
                let statement = AssertSqlSafe(format!("SET ROLE {worker_role}"));
                Box::pin(async move {
                    sqlx::query(statement).execute(connection).await?;
                    Ok(())
                })
            })
            .connect(&database_url)
            .await
            .expect("connect through restricted Worker role");
        let worker_repository = PostgresRepository { pool: worker_pool };
        crate::store::LicenseRepository::readiness_check(&worker_repository)
            .await
            .expect("shared schema readiness must not require hidden credential tables");
        crate::admin_http::admin_schema_ready(&worker_repository)
            .await
            .expect("Admin schema readiness must remain privilege independent");
        worker_repository.pool.close().await;

        for role in [&roles.public, &roles.admin_web, &roles.admin_worker] {
            sqlx::query(AssertSqlSafe(format!(
                "DROP OWNED BY {}",
                quote_identifier(role)
            )))
            .execute(&repository.pool)
            .await
            .expect("drop test role grants");
            sqlx::query(AssertSqlSafe(format!(
                "DROP ROLE {}",
                quote_identifier(role)
            )))
            .execute(&repository.pool)
            .await
            .expect("drop test runtime role");
        }
        repository.pool.close().await;

        assert!(public_account);
        assert!(!public_admin);
        assert!(!public_ddl);
        assert!(worker_jobs);
        assert!(!worker_passwords);
        assert!(!worker_identity_insert);
    }
}
