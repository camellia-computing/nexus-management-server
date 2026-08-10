use std::{
    collections::BTreeSet,
    env,
    path::{Path, PathBuf},
    time::Duration,
};

use sqlx::{AssertSqlSafe, Row};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    admin_auth::AdminKeyring,
    config::{Environment, database_connection_config_from_env},
    crypto::EntitlementSigner,
    secret_file::read_secret_file,
    store::PostgresRepository,
    webhooks::WebhookKeyring,
    workspace::WorkspaceKeyring,
};

const BOOTSTRAP_LOCK_ID: i64 = 0x4341_4d45_4c4c_4941;
const BOOTSTRAP_ROLE_ENV: &str = "CAMELLIA_NEXUS_DATABASE_BOOTSTRAP_ROLE";
const DATABASE_BOOTSTRAP_PASSWORD_FILE_ENV: &str =
    "CAMELLIA_NEXUS_DATABASE_BOOTSTRAP_PASSWORD_FILE";
const MIGRATE_ROLE_ENV: &str = "CAMELLIA_NEXUS_DATABASE_MIGRATE_ROLE";
const MIGRATE_PASSWORD_FILE_ENV: &str = "CAMELLIA_NEXUS_DATABASE_MIGRATE_PASSWORD_FILE";
const PUBLIC_ROLE_ENV: &str = "CAMELLIA_NEXUS_DATABASE_PUBLIC_ROLE";
const PUBLIC_PASSWORD_FILE_ENV: &str = "CAMELLIA_NEXUS_DATABASE_PUBLIC_PASSWORD_FILE";
const ADMIN_WEB_ROLE_ENV: &str = "CAMELLIA_NEXUS_DATABASE_ADMIN_WEB_ROLE";
const ADMIN_WEB_PASSWORD_FILE_ENV: &str = "CAMELLIA_NEXUS_DATABASE_ADMIN_WEB_PASSWORD_FILE";
const ADMIN_WORKER_ROLE_ENV: &str = "CAMELLIA_NEXUS_DATABASE_ADMIN_WORKER_ROLE";
const ADMIN_WORKER_PASSWORD_FILE_ENV: &str = "CAMELLIA_NEXUS_DATABASE_ADMIN_WORKER_PASSWORD_FILE";

const RECONCILE_ROLE_SQL: &str = r#"
DO $camellia_nexus_bootstrap$
DECLARE
  target_role text := current_setting('camellia_nexus.bootstrap_role');
  target_password text := current_setting('camellia_nexus.bootstrap_password');
BEGIN
  IF target_role = current_user THEN
    RAISE EXCEPTION 'bootstrap cannot reconcile its own login role';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = target_role) THEN
    EXECUTE format(
      'ALTER ROLE %I WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT',
      target_role,
      target_password
    );
  ELSE
    EXECUTE format(
      'CREATE ROLE %I LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT',
      target_role,
      target_password
    );
  END IF;
  EXECUTE format('ALTER ROLE %I CONNECTION LIMIT -1 VALID UNTIL %L', target_role, 'infinity');
  EXECUTE format('ALTER ROLE %I RESET ALL', target_role);
END
$camellia_nexus_bootstrap$;
"#;

const RECONCILE_OWNERSHIP_SQL: &str = r#"
DO $camellia_nexus_bootstrap$
DECLARE
  migrate_role text := current_setting('camellia_nexus.migrate_role');
BEGIN
  EXECUTE format('ALTER DATABASE %I OWNER TO %I', current_database(), migrate_role);
  EXECUTE format('ALTER SCHEMA public OWNER TO %I', migrate_role);
END
$camellia_nexus_bootstrap$;
"#;

const RECONCILE_BOOTSTRAP_ATTRIBUTES_SQL: &str = r#"
ALTER ROLE CURRENT_USER WITH
  LOGIN SUPERUSER CREATEDB CREATEROLE NOREPLICATION NOBYPASSRLS INHERIT
  CONNECTION LIMIT -1 VALID UNTIL 'infinity'
"#;

#[derive(Debug, Error)]
pub enum DeploymentError {
    #[error("deployment configuration is invalid: {0}")]
    Configuration(String),
    #[error("deployment secret {0} is invalid")]
    Secret(&'static str),
    #[error("database bootstrap connection failed")]
    Connection,
    #[error("database bootstrap operation failed")]
    Database(#[source] sqlx::Error),
    #[error("database bootstrap contract is invalid: {0}")]
    Contract(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapMode {
    Reconcile,
    Check,
}

struct LoginRoleSecret {
    role: String,
    password: Zeroizing<String>,
}

struct BootstrapConfig {
    bootstrap_role: String,
    migrate: LoginRoleSecret,
    public: LoginRoleSecret,
    admin_web: LoginRoleSecret,
    admin_worker: LoginRoleSecret,
}

impl BootstrapConfig {
    fn from_env(read_passwords: bool) -> Result<Self, DeploymentError> {
        let bootstrap_role = role_from_env(BOOTSTRAP_ROLE_ENV, "nexus_bootstrap")?;
        let migrate = login_role_from_env(
            MIGRATE_ROLE_ENV,
            "nexus_migrate",
            MIGRATE_PASSWORD_FILE_ENV,
            read_passwords,
        )?;
        let public = login_role_from_env(
            PUBLIC_ROLE_ENV,
            "nexus_public",
            PUBLIC_PASSWORD_FILE_ENV,
            read_passwords,
        )?;
        let admin_web = login_role_from_env(
            ADMIN_WEB_ROLE_ENV,
            "nexus_admin_web",
            ADMIN_WEB_PASSWORD_FILE_ENV,
            read_passwords,
        )?;
        let admin_worker = login_role_from_env(
            ADMIN_WORKER_ROLE_ENV,
            "nexus_admin_worker",
            ADMIN_WORKER_PASSWORD_FILE_ENV,
            read_passwords,
        )?;
        let names = [
            &bootstrap_role,
            &migrate.role,
            &public.role,
            &admin_web.role,
            &admin_worker.role,
        ];
        if names.into_iter().collect::<BTreeSet<_>>().len() != names.len() {
            return Err(DeploymentError::Configuration(
                "bootstrap, migration, and runtime role names must be distinct".to_owned(),
            ));
        }
        Ok(Self {
            bootstrap_role,
            migrate,
            public,
            admin_web,
            admin_worker,
        })
    }

    fn managed_roles(&self) -> [&LoginRoleSecret; 4] {
        [
            &self.migrate,
            &self.public,
            &self.admin_web,
            &self.admin_worker,
        ]
    }

    fn role_names(&self) -> Vec<String> {
        self.managed_roles()
            .into_iter()
            .map(|role| role.role.clone())
            .collect()
    }
}

pub fn validate_deployment_secrets() -> Result<(), DeploymentError> {
    let password_secrets = [
        (
            "database-bootstrap-password",
            DATABASE_BOOTSTRAP_PASSWORD_FILE_ENV,
        ),
        ("database-migrate-password", MIGRATE_PASSWORD_FILE_ENV),
        ("database-public-password", PUBLIC_PASSWORD_FILE_ENV),
        ("database-admin-web-password", ADMIN_WEB_PASSWORD_FILE_ENV),
        (
            "database-admin-worker-password",
            ADMIN_WORKER_PASSWORD_FILE_ENV,
        ),
    ];
    for (name, variable) in password_secrets {
        let path = required_path(variable)?;
        let _password = read_database_password(&path, name)?;
        println!("{name}: valid");
    }

    let entitlement_path = required_path("CAMELLIA_NEXUS_LICENSE_PRIVATE_KEY_PEM_PATH")?;
    let entitlement_key_id = required_env("CAMELLIA_NEXUS_LICENSE_KEY_ID")?;
    let entitlement = read_secret_file(&entitlement_path)
        .map_err(|_| DeploymentError::Secret("entitlement-private-key"))?;
    EntitlementSigner::from_pem(entitlement_key_id, &entitlement)
        .map_err(|_| DeploymentError::Secret("entitlement-private-key"))?;
    println!("entitlement-private-key: valid");

    let workspace_path = required_path("CAMELLIA_NEXUS_WORKSPACE_KEYRING_PATH")?;
    WorkspaceKeyring::load(workspace_path)
        .map_err(|_| DeploymentError::Secret("workspace-keyring"))?;
    println!("workspace-keyring: valid");

    let webhook_path = required_path("CAMELLIA_NEXUS_WEBHOOK_KEYRING_PATH")?;
    WebhookKeyring::load(webhook_path).map_err(|_| DeploymentError::Secret("webhook-keyring"))?;
    println!("webhook-keyring: valid");

    let admin_path = required_path("CAMELLIA_NEXUS_ADMIN_KEYRING_PATH")?;
    AdminKeyring::load(admin_path).map_err(|_| DeploymentError::Secret("admin-keyring"))?;
    println!("admin-keyring: valid");

    let proxy_path = required_path("CAMELLIA_NEXUS_ADMIN_FORWARDED_FOR_SECRET_PATH")?;
    let proxy =
        read_secret_file(proxy_path).map_err(|_| DeploymentError::Secret("admin-proxy-secret"))?;
    validate_proxy_secret(&proxy)?;
    println!("admin-proxy-secret: valid");
    Ok(())
}

pub async fn run_database_bootstrap(mode: BootstrapMode) -> Result<(), DeploymentError> {
    match mode {
        BootstrapMode::Reconcile => {
            let config = BootstrapConfig::from_env(true)?;
            let repository = connect_from_environment().await?;
            reconcile(&repository, &config).await?;
            check(&repository, &config).await
        }
        BootstrapMode::Check => {
            let config = BootstrapConfig::from_env(false)?;
            let repository = connect_from_environment().await?;
            check(&repository, &config).await
        }
    }
}

async fn connect_from_environment() -> Result<PostgresRepository, DeploymentError> {
    let database = database_connection_config_from_env(Environment::Production)
        .map_err(|error| DeploymentError::Configuration(error.to_string()))?;
    PostgresRepository::connect_config(&database, 1, Duration::from_secs(15))
        .await
        .map_err(|_| DeploymentError::Connection)
}

async fn reconcile(
    repository: &PostgresRepository,
    config: &BootstrapConfig,
) -> Result<(), DeploymentError> {
    validate_current_bootstrap(repository, &config.bootstrap_role, false).await?;
    let mut transaction = repository
        .pool
        .begin()
        .await
        .map_err(DeploymentError::Database)?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(BOOTSTRAP_LOCK_ID)
        .execute(&mut *transaction)
        .await
        .map_err(DeploymentError::Database)?;

    sqlx::query(RECONCILE_BOOTSTRAP_ATTRIBUTES_SQL)
        .execute(&mut *transaction)
        .await
        .map_err(DeploymentError::Database)?;
    sqlx::query("ALTER ROLE CURRENT_USER RESET ALL")
        .execute(&mut *transaction)
        .await
        .map_err(DeploymentError::Database)?;

    for managed in config.managed_roles() {
        sqlx::query(
            "SELECT set_config('camellia_nexus.bootstrap_role', $1, true),
                    set_config('camellia_nexus.bootstrap_password', $2, true)",
        )
        .bind(&managed.role)
        .bind(managed.password.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(DeploymentError::Database)?;
        sqlx::query(RECONCILE_ROLE_SQL)
            .execute(&mut *transaction)
            .await
            .map_err(DeploymentError::Database)?;
        revoke_role_memberships(&mut transaction, &managed.role).await?;
    }
    revoke_role_memberships(&mut transaction, &config.bootstrap_role).await?;

    sqlx::query("SELECT set_config('camellia_nexus.migrate_role', $1, true)")
        .bind(&config.migrate.role)
        .execute(&mut *transaction)
        .await
        .map_err(DeploymentError::Database)?;
    sqlx::query(RECONCILE_OWNERSHIP_SQL)
        .execute(&mut *transaction)
        .await
        .map_err(DeploymentError::Database)?;
    transaction
        .commit()
        .await
        .map_err(DeploymentError::Database)
}

async fn revoke_role_memberships(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    managed_role: &str,
) -> Result<(), DeploymentError> {
    let memberships = sqlx::query_as::<_, (String, String)>(
        "SELECT granted.rolname, member.rolname
         FROM pg_auth_members AS membership
         JOIN pg_roles AS granted ON granted.oid = membership.roleid
         JOIN pg_roles AS member ON member.oid = membership.member
         WHERE granted.rolname = $1 OR member.rolname = $1
         ORDER BY granted.rolname, member.rolname",
    )
    .bind(managed_role)
    .fetch_all(&mut **transaction)
    .await
    .map_err(DeploymentError::Database)?;
    for (granted, member) in memberships {
        let statement = format!(
            "REVOKE {} FROM {}",
            quote_identifier(&granted),
            quote_identifier(&member)
        );
        sqlx::query(AssertSqlSafe(statement))
            .execute(&mut **transaction)
            .await
            .map_err(DeploymentError::Database)?;
    }
    Ok(())
}

async fn check(
    repository: &PostgresRepository,
    config: &BootstrapConfig,
) -> Result<(), DeploymentError> {
    validate_current_bootstrap(repository, &config.bootstrap_role, true).await?;
    let requested = config.role_names();
    let rows = sqlx::query(
        "SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole,
                rolreplication, rolbypassrls, rolinherit, rolconnlimit,
                (rolvaliduntil IS NULL OR rolvaliduntil = 'infinity'::timestamptz) AS unlimited_validity,
                COALESCE(cardinality(rolconfig), 0) = 0 AS no_role_config
         FROM pg_roles WHERE rolname = ANY($1)",
    )
    .bind(&requested)
    .fetch_all(&repository.pool)
    .await
    .map_err(DeploymentError::Database)?;
    if rows.len() != requested.len() {
        let found = rows
            .iter()
            .filter_map(|row| row.try_get::<String, _>("rolname").ok())
            .collect::<BTreeSet<_>>();
        let missing = requested
            .iter()
            .filter(|role| !found.contains(*role))
            .cloned()
            .collect::<Vec<_>>();
        return Err(DeploymentError::Contract(format!(
            "managed roles do not exist: {}",
            missing.join(", ")
        )));
    }
    for row in rows {
        let role: String = row
            .try_get("rolname")
            .map_err(|_| DeploymentError::Contract("invalid role metadata".to_owned()))?;
        let can_login = row.try_get::<bool, _>("rolcanlogin").unwrap_or(false);
        let privileged = [
            "rolsuper",
            "rolcreatedb",
            "rolcreaterole",
            "rolreplication",
            "rolbypassrls",
        ]
        .into_iter()
        .any(|column| row.try_get::<bool, _>(column).unwrap_or(true));
        let canonical_runtime = row.try_get::<bool, _>("rolinherit").unwrap_or(false)
            && row.try_get::<i32, _>("rolconnlimit").unwrap_or(0) == -1
            && row
                .try_get::<bool, _>("unlimited_validity")
                .unwrap_or(false)
            && row.try_get::<bool, _>("no_role_config").unwrap_or(false);
        if !can_login || privileged || !canonical_runtime {
            return Err(DeploymentError::Contract(format!(
                "managed role {role} must be an unprivileged login"
            )));
        }
    }
    let mut membership_roles = requested.clone();
    membership_roles.push(config.bootstrap_role.clone());
    let unexpected_memberships: Vec<String> = sqlx::query_scalar(
        "SELECT granted.rolname || '->' || member.rolname
         FROM pg_auth_members AS membership
         JOIN pg_roles AS granted ON granted.oid = membership.roleid
         JOIN pg_roles AS member ON member.oid = membership.member
         WHERE granted.rolname = ANY($1) OR member.rolname = ANY($1)
         ORDER BY granted.rolname, member.rolname",
    )
    .bind(&membership_roles)
    .fetch_all(&repository.pool)
    .await
    .map_err(DeploymentError::Database)?;
    if !unexpected_memberships.is_empty() {
        return Err(DeploymentError::Contract(format!(
            "managed roles have unexpected memberships: {}",
            unexpected_memberships.join(", ")
        )));
    }
    let database_owner: String = sqlx::query_scalar(
        "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database()",
    )
    .fetch_one(&repository.pool)
    .await
    .map_err(DeploymentError::Database)?;
    let schema_owner: String = sqlx::query_scalar(
        "SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = 'public'",
    )
    .fetch_one(&repository.pool)
    .await
    .map_err(DeploymentError::Database)?;
    if database_owner != config.migrate.role || schema_owner != config.migrate.role {
        return Err(DeploymentError::Contract(format!(
            "database and public schema must be owned by {}",
            config.migrate.role
        )));
    }
    Ok(())
}

async fn validate_current_bootstrap(
    repository: &PostgresRepository,
    expected_role: &str,
    require_canonical_attributes: bool,
) -> Result<(), DeploymentError> {
    let row = sqlx::query(
        "SELECT current_user AS role, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole,
                rolreplication, rolbypassrls, rolinherit, rolconnlimit,
                (rolvaliduntil IS NULL OR rolvaliduntil = 'infinity'::timestamptz) AS unlimited_validity,
                COALESCE(cardinality(rolconfig), 0) = 0 AS no_role_config
         FROM pg_roles WHERE rolname = current_user",
    )
    .fetch_one(&repository.pool)
    .await
    .map_err(DeploymentError::Database)?;
    let current_role: String = row
        .try_get("role")
        .map_err(|_| DeploymentError::Contract("invalid bootstrap role metadata".to_owned()))?;
    let can_login = row.try_get::<bool, _>("rolcanlogin").unwrap_or(false);
    let is_superuser = row.try_get::<bool, _>("rolsuper").unwrap_or(false);
    let creates_databases = row.try_get::<bool, _>("rolcreatedb").unwrap_or(false);
    let creates_roles = row.try_get::<bool, _>("rolcreaterole").unwrap_or(false);
    let canonical_attributes = is_superuser
        && creates_databases
        && creates_roles
        && !row.try_get::<bool, _>("rolreplication").unwrap_or(true)
        && !row.try_get::<bool, _>("rolbypassrls").unwrap_or(true)
        && row.try_get::<bool, _>("rolinherit").unwrap_or(false)
        && row.try_get::<i32, _>("rolconnlimit").unwrap_or(0) == -1
        && row
            .try_get::<bool, _>("unlimited_validity")
            .unwrap_or(false)
        && row.try_get::<bool, _>("no_role_config").unwrap_or(false);
    let valid_attributes = can_login
        && if require_canonical_attributes {
            canonical_attributes
        } else {
            is_superuser || (creates_databases && creates_roles)
        };
    if current_role != expected_role || !valid_attributes {
        return Err(DeploymentError::Contract(format!(
            "bootstrap connection must use the dedicated administrative login {expected_role}"
        )));
    }
    Ok(())
}

fn role_from_env(variable: &'static str, default: &'static str) -> Result<String, DeploymentError> {
    let role = env::var(variable)
        .unwrap_or_else(|_| default.to_owned())
        .trim()
        .to_owned();
    validate_role_name(&role)
        .map_err(|reason| DeploymentError::Configuration(format!("{variable} {reason}")))?;
    Ok(role)
}

fn login_role_from_env(
    role_variable: &'static str,
    default_role: &'static str,
    password_variable: &'static str,
    read_passwords: bool,
) -> Result<LoginRoleSecret, DeploymentError> {
    let role = role_from_env(role_variable, default_role)?;
    let password = if read_passwords {
        read_database_password(&required_path(password_variable)?, password_variable)?
    } else {
        Zeroizing::new(String::new())
    };
    Ok(LoginRoleSecret { role, password })
}

fn required_env(variable: &'static str) -> Result<String, DeploymentError> {
    env::var(variable)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| DeploymentError::Configuration(format!("{variable} is required")))
}

fn required_path(variable: &'static str) -> Result<PathBuf, DeploymentError> {
    required_env(variable).map(PathBuf::from)
}

fn read_database_password(
    path: &Path,
    logical_name: &'static str,
) -> Result<Zeroizing<String>, DeploymentError> {
    let bytes = read_secret_file(path).map_err(|_| DeploymentError::Secret(logical_name))?;
    let mut password = match String::from_utf8(bytes.to_vec()) {
        Ok(password) => Zeroizing::new(password),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            return Err(DeploymentError::Secret(logical_name));
        }
    };
    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }
    if !(32..=128).contains(&password.len())
        || !password
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte))
    {
        return Err(DeploymentError::Secret(logical_name));
    }
    Ok(password)
}

fn validate_proxy_secret(bytes: &[u8]) -> Result<(), DeploymentError> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| DeploymentError::Secret("admin-proxy-secret"))?;
    let secret = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    if !(32..=256).contains(&secret.len()) || !secret.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(DeploymentError::Secret("admin-proxy-secret"));
    }
    Ok(())
}

fn validate_role_name(role: &str) -> Result<(), &'static str> {
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
        Err("must be a lowercase PostgreSQL identifier")
    }
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_password_contract_is_strict_and_newline_tolerant() {
        let directory = tempfile::tempdir().expect("create password fixture");
        let path = directory.path().join("password");
        std::fs::write(&path, "A9._~-012345678901234567890123456789\r\n")
            .expect("write valid password");
        assert_eq!(
            read_database_password(&path, "fixture")
                .expect("valid password")
                .as_str(),
            "A9._~-012345678901234567890123456789"
        );
        std::fs::write(&path, "short-password\n").expect("write invalid password");
        assert!(read_database_password(&path, "fixture").is_err());
        std::fs::write(&path, "A9!0123456789012345678901234567890\n")
            .expect("write unsafe password");
        assert!(read_database_password(&path, "fixture").is_err());
    }

    #[test]
    fn database_role_names_are_injection_safe() {
        for valid in ["nexus_bootstrap", "nexus_migrate", "role1"] {
            assert!(validate_role_name(valid).is_ok());
        }
        for invalid in ["", "Nexus", "1role", "role-name", "role\";DROP ROLE owner"] {
            assert!(validate_role_name(invalid).is_err());
        }
    }

    #[test]
    fn proxy_secret_contract_matches_the_runtime_boundary() {
        assert!(validate_proxy_secret(b"01234567890123456789012345678901\n").is_ok());
        assert!(validate_proxy_secret(b"too-short").is_err());
        assert!(validate_proxy_secret(&[b'a'; 257]).is_err());
    }
}
