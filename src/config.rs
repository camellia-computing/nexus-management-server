use std::{env, net::SocketAddr, path::PathBuf, time::Duration};

use semver::Version;
use thiserror::Error;
use url::Url;
use zeroize::Zeroizing;

pub use crate::contracts::ClientVersionPolicy;
use crate::{
    crypto::{EntitlementSigner, sha256_hex},
    error::{ApiError, Result as ApiResult},
    secret_file::{MAX_SECRET_FILE_BYTES, read_secret_file},
    service::valid_redirect_uri,
    time_format::{parse_absolute_time, parse_expiry_time, unix_now},
};

const DEVELOPMENT_CLIENT_COMPATIBILITY_VERSION: &str = "1.0.0";

type ConfigResult<T> = std::result::Result<T, ConfigError>;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("invalid configuration for {key}: {reason}")]
pub struct ConfigError {
    key: &'static str,
    reason: &'static str,
}

impl ConfigError {
    const fn new(key: &'static str, reason: &'static str) -> Self {
        Self { key, reason }
    }
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    pub issuer: String,
    pub audience: String,
    pub environment: Environment,
    pub storage: StorageConfig,
    pub workspace_keyring_path: Option<PathBuf>,
    pub webhook_keyring_path: Option<PathBuf>,
    pub max_database_connections: u32,
    pub database_acquire_timeout: Duration,
    pub migrate_database: bool,
    pub time_max_forward_jump_seconds: i64,
    pub http: HttpServerConfig,
    pub maintenance_interval: Duration,
    pub cleanup_batch_size: u32,
    pub client_version_policy: ClientVersionPolicy,
    pub logging: LoggingConfig,
    pub cors_allowed_origins: Vec<String>,
    pub oauth: OAuthServerConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpServerConfig {
    pub request_timeout: Duration,
    pub max_in_flight: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatabasePoolConfig {
    pub max_connections: u32,
    pub acquire_timeout: Duration,
}

impl Default for HttpServerConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(15),
            max_in_flight: 256,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OAuthServerConfig {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    pub activation_codes: Vec<ActivationCode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivationCode {
    pub code: String,
    pub account_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Development,
    Production,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageConfig {
    Memory,
    Postgres { database_url: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Compact,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggingConfig {
    pub format: LogFormat,
    pub level: LogLevel,
    pub filter: Option<String>,
    pub http: HttpLogConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpLogConfig {
    pub level: LogLevel,
    pub failure_level: LogLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::Compact,
            level: LogLevel::Info,
            filter: None,
            http: HttpLogConfig::default(),
        }
    }
}

impl Default for HttpLogConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            failure_level: LogLevel::Warn,
        }
    }
}

impl Environment {
    pub fn from_env() -> ConfigResult<Self> {
        environment_from_env()
    }
}

impl LoggingConfig {
    pub fn from_env(environment: Environment) -> ConfigResult<Self> {
        Ok(Self {
            format: log_format_from_env(environment)?,
            level: log_level_from_env("CAMELLIA_NEXUS_LOG_LEVEL", LogLevel::Info)?,
            filter: env::var("CAMELLIA_NEXUS_LOG_FILTER")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty()),
            http: HttpLogConfig {
                level: log_level_from_env("CAMELLIA_NEXUS_HTTP_LOG_LEVEL", LogLevel::Info)?,
                failure_level: log_level_from_env(
                    "CAMELLIA_NEXUS_HTTP_FAILURE_LOG_LEVEL",
                    LogLevel::Warn,
                )?,
            },
        })
    }
}

impl LogLevel {
    pub fn as_filter(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }

    pub fn as_tracing_level(self) -> tracing::Level {
        match self {
            Self::Error => tracing::Level::ERROR,
            Self::Warn => tracing::Level::WARN,
            Self::Info => tracing::Level::INFO,
            Self::Debug => tracing::Level::DEBUG,
            Self::Trace => tracing::Level::TRACE,
        }
    }
}

impl ServerConfig {
    pub fn from_env() -> ConfigResult<(Self, EntitlementSigner)> {
        let environment = Environment::from_env()?;
        let bind = env::var("CAMELLIA_NEXUS_LICENSE_BIND")
            .unwrap_or_else(|_| default_bind(environment).to_owned())
            .parse()
            .map_err(|_| {
                ConfigError::new(
                    "CAMELLIA_NEXUS_LICENSE_BIND",
                    "expected a socket address such as 0.0.0.0:8088",
                )
            })?;
        let issuer = required_or_default(
            "CAMELLIA_NEXUS_LICENSE_ISSUER",
            "https://license.camellia-nexus.example",
            environment,
        )?;
        validate_issuer(&issuer, environment)?;
        let audience = required_or_default(
            "CAMELLIA_NEXUS_LICENSE_AUDIENCE",
            "camellia-nexus-desktop",
            environment,
        )?;
        let key_id = required_or_default(
            "CAMELLIA_NEXUS_LICENSE_KEY_ID",
            "entitlement-dev",
            environment,
        )?;
        validate_key_id(&key_id)?;
        let storage = storage_from_env(environment)?;
        let workspace_keyring_path = keyring_path_from_value(
            "CAMELLIA_NEXUS_WORKSPACE_KEYRING_PATH",
            env::var("CAMELLIA_NEXUS_WORKSPACE_KEYRING_PATH").ok(),
            environment,
        )?;
        let webhook_keyring_path = keyring_path_from_value(
            "CAMELLIA_NEXUS_WEBHOOK_KEYRING_PATH",
            env::var("CAMELLIA_NEXUS_WEBHOOK_KEYRING_PATH").ok(),
            environment,
        )?;
        let database_pool = database_pool_config_from_env()?;
        let max_database_connections = database_pool.max_connections;
        let database_acquire_timeout = database_pool.acquire_timeout;
        let migrate_database = env_bool(
            "CAMELLIA_NEXUS_DATABASE_MIGRATE",
            environment == Environment::Development,
        )?;
        let time_max_forward_jump_seconds = time_max_forward_jump_seconds_from_env()?;
        let http = HttpServerConfig {
            request_timeout: Duration::from_secs(u64::from(env_u32(
                "CAMELLIA_NEXUS_HTTP_REQUEST_TIMEOUT_SECONDS",
                15,
            )?)),
            max_in_flight: env_u32("CAMELLIA_NEXUS_HTTP_MAX_IN_FLIGHT", 256)? as usize,
        };
        if http.request_timeout.is_zero() || http.max_in_flight == 0 {
            let key = if http.request_timeout.is_zero() {
                "CAMELLIA_NEXUS_HTTP_REQUEST_TIMEOUT_SECONDS"
            } else {
                "CAMELLIA_NEXUS_HTTP_MAX_IN_FLIGHT"
            };
            return Err(ConfigError::new(key, "must be greater than zero"));
        }
        let maintenance_interval = Duration::from_secs(u64::from(env_u32(
            "CAMELLIA_NEXUS_MAINTENANCE_INTERVAL_SECONDS",
            60 * 60,
        )?));
        let cleanup_batch_size = env_u32("CAMELLIA_NEXUS_CLEANUP_BATCH_SIZE", 1_000)?;
        if maintenance_interval.is_zero() {
            return Err(ConfigError::new(
                "CAMELLIA_NEXUS_MAINTENANCE_INTERVAL_SECONDS",
                "must be greater than zero",
            ));
        }
        if cleanup_batch_size == 0 {
            return Err(ConfigError::new(
                "CAMELLIA_NEXUS_CLEANUP_BATCH_SIZE",
                "must be greater than zero",
            ));
        }
        let client_version_policy = client_version_policy_from_env(environment)?;
        let logging = LoggingConfig::from_env(environment)?;
        let cors_allowed_origins = cors_origins_from_env()?;
        let oauth = oauth_from_env(environment)?;
        let key_pem = match env::var("CAMELLIA_NEXUS_LICENSE_PRIVATE_KEY_PEM") {
            Ok(value) if !value.trim().is_empty() && environment == Environment::Development => {
                if value.len() > MAX_SECRET_FILE_BYTES as usize {
                    return Err(ConfigError::new(
                        "CAMELLIA_NEXUS_LICENSE_PRIVATE_KEY_PEM",
                        "must be no larger than 64 KiB",
                    ));
                }
                Zeroizing::new(value.into_bytes())
            }
            Ok(value) if !value.trim().is_empty() => {
                return Err(ConfigError::new(
                    "CAMELLIA_NEXUS_LICENSE_PRIVATE_KEY_PEM",
                    "inline signing keys are forbidden in production; mount a key file and set CAMELLIA_NEXUS_LICENSE_PRIVATE_KEY_PEM_PATH",
                ));
            }
            Ok(_) => {
                return Err(ConfigError::new(
                    "CAMELLIA_NEXUS_LICENSE_PRIVATE_KEY_PEM",
                    "must not be empty when set",
                ));
            }
            Err(_) => {
                let path = env::var("CAMELLIA_NEXUS_LICENSE_PRIVATE_KEY_PEM_PATH").ok();
                match path {
                    Some(path) if !path.trim().is_empty() => {
                        read_secret_file(path).map_err(|_| {
                            ConfigError::new(
                                "CAMELLIA_NEXUS_LICENSE_PRIVATE_KEY_PEM_PATH",
                                "must reference a readable regular file no larger than 64 KiB",
                            )
                        })?
                    }
                    Some(_) => {
                        return Err(ConfigError::new(
                            "CAMELLIA_NEXUS_LICENSE_PRIVATE_KEY_PEM_PATH",
                            "must not be empty when set",
                        ));
                    }
                    None if environment == Environment::Production => {
                        return Err(ConfigError::new(
                            "CAMELLIA_NEXUS_LICENSE_PRIVATE_KEY_PEM_PATH",
                            "is required in production",
                        ));
                    }
                    None => Zeroizing::new(ephemeral_development_key()),
                }
            }
        };
        let signer = EntitlementSigner::from_pem(key_id, key_pem.as_slice()).map_err(|_| {
            ConfigError::new(
                "CAMELLIA_NEXUS_LICENSE_PRIVATE_KEY_PEM_PATH",
                "must contain a valid ES256 PKCS#8 PEM private key",
            )
        })?;
        Ok((
            Self {
                bind,
                issuer,
                audience,
                environment,
                storage,
                workspace_keyring_path,
                webhook_keyring_path,
                max_database_connections,
                database_acquire_timeout,
                migrate_database,
                time_max_forward_jump_seconds,
                http,
                maintenance_interval,
                cleanup_batch_size,
                client_version_policy,
                logging,
                cors_allowed_origins,
                oauth,
            },
            signer,
        ))
    }
}

fn keyring_path_from_value(
    key: &'static str,
    value: Option<String>,
    environment: Environment,
) -> ConfigResult<Option<PathBuf>> {
    match value {
        Some(value) if !value.trim().is_empty() => Ok(Some(PathBuf::from(value))),
        Some(_) => Err(ConfigError::new(key, "must not be empty when set")),
        None if environment == Environment::Production => {
            Err(ConfigError::new(key, "is required in production"))
        }
        None => Ok(None),
    }
}

impl ClientVersionPolicy {
    pub fn development_default() -> Self {
        Self {
            minimum_version: DEVELOPMENT_CLIENT_COMPATIBILITY_VERSION.to_owned(),
            recommended_version: DEVELOPMENT_CLIENT_COMPATIBILITY_VERSION.to_owned(),
            enforce_after: 0,
        }
    }

    pub fn validate(&self) -> ApiResult<()> {
        let minimum = canonical_client_version(&self.minimum_version)?;
        let recommended = canonical_client_version(&self.recommended_version)?;
        if recommended < minimum || self.enforce_after < 0 {
            return Err(ApiError::InvalidRequest);
        }
        Ok(())
    }
}

pub(crate) fn canonical_client_version(value: &str) -> ApiResult<Version> {
    if value.is_empty() || value.len() > 64 {
        return Err(ApiError::InvalidRequest);
    }
    let parsed = Version::parse(value).map_err(|_| ApiError::InvalidRequest)?;
    if parsed.to_string() == value {
        Ok(parsed)
    } else {
        Err(ApiError::InvalidRequest)
    }
}

fn client_version_policy_from_env(environment: Environment) -> ConfigResult<ClientVersionPolicy> {
    client_version_policy_from_values(
        environment,
        env::var("CAMELLIA_NEXUS_CLIENT_MINIMUM_VERSION").ok(),
        env::var("CAMELLIA_NEXUS_CLIENT_RECOMMENDED_VERSION").ok(),
        env::var("CAMELLIA_NEXUS_CLIENT_VERSION_ENFORCE_AFTER").ok(),
        unix_now(),
    )
}

fn client_version_policy_from_values(
    environment: Environment,
    minimum_version: Option<String>,
    recommended_version: Option<String>,
    enforce_after: Option<String>,
    now: i64,
) -> ConfigResult<ClientVersionPolicy> {
    let value_or_default =
        |key, value: Option<String>| match value.filter(|value| !value.is_empty()) {
            Some(value) => Ok(value),
            None if environment == Environment::Production => {
                Err(ConfigError::new(key, "is required in production"))
            }
            None => Ok(DEVELOPMENT_CLIENT_COMPATIBILITY_VERSION.to_owned()),
        };
    let minimum_version =
        value_or_default("CAMELLIA_NEXUS_CLIENT_MINIMUM_VERSION", minimum_version)?;
    let recommended_version = value_or_default(
        "CAMELLIA_NEXUS_CLIENT_RECOMMENDED_VERSION",
        recommended_version,
    )?;
    let enforce_after = match enforce_after.filter(|value| !value.trim().is_empty()) {
        Some(value) if environment == Environment::Production => parse_absolute_time(&value)
            .map_err(|_| {
                ConfigError::new(
                    "CAMELLIA_NEXUS_CLIENT_VERSION_ENFORCE_AFTER",
                    "expected an absolute RFC3339 instant, UTC date/date-time, or Unix seconds; quote timestamps in YAML/Compose",
                )
            })?,
        Some(value) => parse_expiry_time(&value, now).map_err(|_| {
            ConfigError::new(
                "CAMELLIA_NEXUS_CLIENT_VERSION_ENFORCE_AFTER",
                "expected an absolute time or relative duration",
            )
        })?,
        None if environment == Environment::Production => {
            return Err(ConfigError::new(
                "CAMELLIA_NEXUS_CLIENT_VERSION_ENFORCE_AFTER",
                "is required in production",
            ));
        }
        None => 0,
    };
    let policy = ClientVersionPolicy {
        minimum_version,
        recommended_version,
        enforce_after,
    };
    let minimum = canonical_client_version(&policy.minimum_version).map_err(|_| {
        ConfigError::new(
            "CAMELLIA_NEXUS_CLIENT_MINIMUM_VERSION",
            "must be a canonical semantic version such as 1.2.3",
        )
    })?;
    let recommended = canonical_client_version(&policy.recommended_version).map_err(|_| {
        ConfigError::new(
            "CAMELLIA_NEXUS_CLIENT_RECOMMENDED_VERSION",
            "must be a canonical semantic version such as 1.2.3",
        )
    })?;
    if recommended < minimum {
        return Err(ConfigError::new(
            "CAMELLIA_NEXUS_CLIENT_RECOMMENDED_VERSION",
            "must not be lower than CAMELLIA_NEXUS_CLIENT_MINIMUM_VERSION",
        ));
    }
    Ok(policy)
}

pub fn time_max_forward_jump_seconds_from_env() -> ConfigResult<i64> {
    let seconds = i64::from(env_u32(
        "CAMELLIA_NEXUS_TIME_MAX_FORWARD_JUMP_SECONDS",
        24 * 60 * 60,
    )?);
    if seconds == 0 {
        Err(ConfigError::new(
            "CAMELLIA_NEXUS_TIME_MAX_FORWARD_JUMP_SECONDS",
            "must be greater than zero",
        ))
    } else {
        Ok(seconds)
    }
}

pub fn database_pool_config_from_env() -> Result<DatabasePoolConfig, ConfigError> {
    database_pool_config_from_values(
        env::var("CAMELLIA_NEXUS_DATABASE_MAX_CONNECTIONS").ok(),
        env::var("CAMELLIA_NEXUS_DATABASE_ACQUIRE_TIMEOUT_SECONDS").ok(),
    )
}

fn database_pool_config_from_values(
    max_connections: Option<String>,
    acquire_timeout_seconds: Option<String>,
) -> ConfigResult<DatabasePoolConfig> {
    let max_connections = env_u32_from_value(
        "CAMELLIA_NEXUS_DATABASE_MAX_CONNECTIONS",
        max_connections,
        8,
    )?;
    if max_connections == 0 {
        return Err(ConfigError::new(
            "CAMELLIA_NEXUS_DATABASE_MAX_CONNECTIONS",
            "must be greater than zero",
        ));
    }
    let acquire_timeout = Duration::from_secs(u64::from(env_u32_from_value(
        "CAMELLIA_NEXUS_DATABASE_ACQUIRE_TIMEOUT_SECONDS",
        acquire_timeout_seconds,
        5,
    )?));
    if acquire_timeout.is_zero() {
        return Err(ConfigError::new(
            "CAMELLIA_NEXUS_DATABASE_ACQUIRE_TIMEOUT_SECONDS",
            "must be greater than zero",
        ));
    }
    Ok(DatabasePoolConfig {
        max_connections,
        acquire_timeout,
    })
}

fn environment_from_env() -> ConfigResult<Environment> {
    match env::var("CAMELLIA_NEXUS_LICENSE_ENV")
        .unwrap_or_else(|_| "development".into())
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "development" | "dev" => Ok(Environment::Development),
        "production" | "prod" => Ok(Environment::Production),
        _ => Err(ConfigError::new(
            "CAMELLIA_NEXUS_LICENSE_ENV",
            "expected development/dev or production/prod",
        )),
    }
}

fn default_bind(environment: Environment) -> &'static str {
    match environment {
        Environment::Development => "127.0.0.1:8088",
        Environment::Production => "0.0.0.0:8088",
    }
}

fn storage_from_env(environment: Environment) -> ConfigResult<StorageConfig> {
    let storage = env::var("CAMELLIA_NEXUS_LICENSE_STORAGE").unwrap_or_else(|_| {
        if environment == Environment::Production {
            "postgres".into()
        } else {
            "memory".into()
        }
    });
    match storage.trim().to_ascii_lowercase().as_str() {
        "memory" if environment == Environment::Production => Err(ConfigError::new(
            "CAMELLIA_NEXUS_LICENSE_STORAGE",
            "in-memory storage is forbidden in production",
        )),
        "memory" => Ok(StorageConfig::Memory),
        "postgres" | "postgresql" => {
            let database_url = env::var("DATABASE_URL")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| ConfigError::new("DATABASE_URL", "is required for PostgreSQL"))?;
            Ok(StorageConfig::Postgres { database_url })
        }
        _ => Err(ConfigError::new(
            "CAMELLIA_NEXUS_LICENSE_STORAGE",
            "expected memory or postgres",
        )),
    }
}

fn oauth_from_env(environment: Environment) -> ConfigResult<OAuthServerConfig> {
    let client_id = required_or_default(
        "CAMELLIA_NEXUS_OAUTH_CLIENT_ID",
        "camellia-nexus-desktop",
        environment,
    )?;
    let redirect_uris = split_env("CAMELLIA_NEXUS_OAUTH_REDIRECT_URIS")
        .unwrap_or_else(|| vec!["camellia-nexus://auth/callback".to_owned()]);
    if redirect_uris.is_empty() || redirect_uris.iter().any(|uri| !valid_redirect_uri(uri)) {
        return Err(ConfigError::new(
            "CAMELLIA_NEXUS_OAUTH_REDIRECT_URIS",
            "expected camellia-nexus://auth/callback or loopback callback URIs",
        ));
    }
    let activation_codes = activation_codes_from_env(environment)?;
    Ok(OAuthServerConfig {
        client_id,
        redirect_uris,
        activation_codes,
    })
}

fn activation_codes_from_env(environment: Environment) -> ConfigResult<Vec<ActivationCode>> {
    let Some(values) =
        split_env("CAMELLIA_NEXUS_LICENSE_ACTIVATION_CODES").filter(|values| !values.is_empty())
    else {
        return match environment {
            Environment::Development => Ok(vec![ActivationCode {
                code: "dev-activation-code".to_owned(),
                account_id: "acct_local".to_owned(),
            }]),
            Environment::Production => Ok(Vec::new()),
        };
    };
    if environment == Environment::Production {
        return Err(ConfigError::new(
            "CAMELLIA_NEXUS_LICENSE_ACTIVATION_CODES",
            "static activation codes are forbidden in production; issue database-backed codes with the Admin CLI",
        ));
    }
    let allow_static_codes = env_bool("CAMELLIA_NEXUS_ALLOW_STATIC_ACTIVATION_CODES", true)?;
    if !allow_static_codes {
        return Err(ConfigError::new(
            "CAMELLIA_NEXUS_ALLOW_STATIC_ACTIVATION_CODES",
            "must be true when development static activation codes are configured",
        ));
    }
    let mut codes = Vec::new();
    for value in values {
        let (code, account_id) = value
            .split_once('=')
            .map(|(code, account)| (code.trim().to_owned(), account.trim().to_owned()))
            .unwrap_or_else(|| {
                let code = value.trim().to_owned();
                let account_id = format!("acct_{}", &sha256_hex(&code)[..24]);
                (code, account_id)
            });
        if code.len() < 8 || account_id.trim().is_empty() {
            return Err(ConfigError::new(
                "CAMELLIA_NEXUS_LICENSE_ACTIVATION_CODES",
                "each code must contain at least 8 bytes and map to a non-empty account id",
            ));
        }
        codes.push(ActivationCode { code, account_id });
    }
    Ok(codes)
}

fn split_env(key: &str) -> Option<Vec<String>> {
    env::var(key).ok().map(|value| split_list(&value))
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn env_bool(key: &'static str, default: bool) -> ConfigResult<bool> {
    let Some(value) = env::var(key).ok() else {
        return Ok(default);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(ConfigError::new(
            key,
            "expected a boolean: true/false, yes/no, on/off, or 1/0",
        )),
    }
}

fn env_u32(key: &'static str, default: u32) -> ConfigResult<u32> {
    env_u32_from_value(key, env::var(key).ok(), default)
}

fn env_u32_from_value(key: &'static str, value: Option<String>, default: u32) -> ConfigResult<u32> {
    match value {
        Some(value) => value
            .parse()
            .map_err(|_| ConfigError::new(key, "expected a non-negative 32-bit integer")),
        None => Ok(default),
    }
}

fn log_format_from_env(environment: Environment) -> ConfigResult<LogFormat> {
    let default = match environment {
        Environment::Development => "compact",
        Environment::Production => "json",
    };
    match env::var("CAMELLIA_NEXUS_LOG_FORMAT")
        .unwrap_or_else(|_| default.into())
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "compact" => Ok(LogFormat::Compact),
        "json" => Ok(LogFormat::Json),
        _ => Err(ConfigError::new(
            "CAMELLIA_NEXUS_LOG_FORMAT",
            "expected compact or json",
        )),
    }
}

fn log_level_from_env(key: &'static str, default: LogLevel) -> ConfigResult<LogLevel> {
    let value = env::var(key).unwrap_or_else(|_| default.as_filter().to_owned());
    match value.trim().to_ascii_lowercase().as_str() {
        "error" => Ok(LogLevel::Error),
        "warn" | "warning" => Ok(LogLevel::Warn),
        "info" => Ok(LogLevel::Info),
        "debug" => Ok(LogLevel::Debug),
        "trace" => Ok(LogLevel::Trace),
        _ => Err(ConfigError::new(
            key,
            "expected error, warn, info, debug, or trace",
        )),
    }
}

fn cors_origins_from_env() -> ConfigResult<Vec<String>> {
    let origins = split_env("CAMELLIA_NEXUS_CORS_ALLOWED_ORIGINS").unwrap_or_else(|| {
        vec![
            "camellia-nexus://localhost".into(),
            "http://127.0.0.1:1420".into(),
        ]
    });
    if origins
        .iter()
        .any(|origin| origin.parse::<axum::http::HeaderValue>().is_err())
    {
        return Err(ConfigError::new(
            "CAMELLIA_NEXUS_CORS_ALLOWED_ORIGINS",
            "contains a value that cannot be used as an HTTP Origin header",
        ));
    }
    Ok(origins)
}

fn required_or_default(
    key: &'static str,
    default: &str,
    environment: Environment,
) -> ConfigResult<String> {
    match env::var(key).ok().filter(|value| !value.trim().is_empty()) {
        Some(value) => Ok(value),
        None if environment == Environment::Production => {
            Err(ConfigError::new(key, "is required in production"))
        }
        None => Ok(default.to_owned()),
    }
}

fn validate_key_id(key_id: &str) -> ConfigResult<()> {
    if key_id.len() > 128
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ConfigError::new(
            "CAMELLIA_NEXUS_LICENSE_KEY_ID",
            "must contain at most 128 ASCII letters, digits, hyphens, underscores, dots, or colons",
        ));
    }
    Ok(())
}

fn validate_issuer(issuer: &str, environment: Environment) -> ConfigResult<()> {
    let url = Url::parse(issuer).map_err(|_| {
        ConfigError::new("CAMELLIA_NEXUS_LICENSE_ISSUER", "expected an absolute URL")
    })?;
    if environment == Environment::Production && url.scheme() != "https" {
        return Err(ConfigError::new(
            "CAMELLIA_NEXUS_LICENSE_ISSUER",
            "must use HTTPS in production",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(ConfigError::new(
            "CAMELLIA_NEXUS_LICENSE_ISSUER",
            "must not contain credentials or a fragment",
        ));
    }
    Ok(())
}

fn ephemeral_development_key() -> Vec<u8> {
    use p256::{ecdsa::SigningKey, elliptic_curve::Generate, pkcs8::EncodePrivateKey};

    tracing::warn!(
        "using an ephemeral development entitlement signing key; configure CAMELLIA_NEXUS_LICENSE_PRIVATE_KEY_PEM_PATH for stable clients"
    );
    SigningKey::generate()
        .to_pkcs8_pem(Default::default())
        .expect("ephemeral private key")
        .as_bytes()
        .to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_pool_configuration_rejects_invalid_and_zero_values() {
        assert!(database_pool_config_from_values(Some("invalid".into()), None).is_err());
        assert!(database_pool_config_from_values(Some("0".into()), None).is_err());
        assert!(database_pool_config_from_values(None, Some("0".into())).is_err());
        let config = database_pool_config_from_values(Some("12".into()), Some("9".into()))
            .expect("valid database pool settings");
        assert_eq!(config.max_connections, 12);
        assert_eq!(config.acquire_timeout, Duration::from_secs(9));
    }

    #[test]
    fn production_keyring_paths_are_required_and_empty_values_are_never_accepted() {
        assert!(
            keyring_path_from_value(
                "CAMELLIA_NEXUS_WEBHOOK_KEYRING_PATH",
                None,
                Environment::Production,
            )
            .is_err()
        );
        assert!(
            keyring_path_from_value(
                "CAMELLIA_NEXUS_WEBHOOK_KEYRING_PATH",
                Some("  ".into()),
                Environment::Development,
            )
            .is_err()
        );
        assert_eq!(
            keyring_path_from_value(
                "CAMELLIA_NEXUS_WEBHOOK_KEYRING_PATH",
                Some("/run/secrets/webhook-keyring.json".into()),
                Environment::Production,
            )
            .unwrap(),
            Some(PathBuf::from("/run/secrets/webhook-keyring.json"))
        );
        assert_eq!(
            keyring_path_from_value(
                "CAMELLIA_NEXUS_WEBHOOK_KEYRING_PATH",
                None,
                Environment::Development,
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn production_client_version_policy_requires_every_value() {
        for (minimum, recommended, enforce_after) in [
            (None, Some("2.0.0"), Some("2030-01-01T00:00:00Z")),
            (Some("1.0.0"), None, Some("2030-01-01T00:00:00Z")),
            (Some("1.0.0"), Some("2.0.0"), None),
        ] {
            assert!(
                client_version_policy_from_values(
                    Environment::Production,
                    minimum.map(str::to_owned),
                    recommended.map(str::to_owned),
                    enforce_after.map(str::to_owned),
                    1_000,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn client_version_policy_is_canonical_ordered_and_uses_shared_time_parser() {
        let policy = client_version_policy_from_values(
            Environment::Production,
            Some("1.2.3".into()),
            Some("2.0.0".into()),
            Some("2030-01-01T00:00:00Z".into()),
            1_000,
        )
        .expect("valid production client-version policy");
        assert_eq!(policy.enforce_after, 1_893_456_000);
        assert!(
            ClientVersionPolicy {
                minimum_version: "1.2".into(),
                ..policy.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            ClientVersionPolicy {
                minimum_version: "2.0.0".into(),
                recommended_version: "1.9.9".into(),
                ..policy
            }
            .validate()
            .is_err()
        );
        assert!(
            client_version_policy_from_values(
                Environment::Production,
                Some("1.2.3".into()),
                Some("2.0.0".into()),
                Some("30d".into()),
                1_000,
            )
            .is_err(),
            "production replicas must share one absolute enforcement instant"
        );
    }

    #[test]
    fn development_client_version_policy_has_a_safe_valid_default() {
        let policy =
            client_version_policy_from_values(Environment::Development, None, None, None, 1_000)
                .expect("development defaults");
        policy.validate().expect("valid development policy");
        assert_eq!(
            policy.minimum_version,
            DEVELOPMENT_CLIENT_COMPATIBILITY_VERSION
        );
        assert_eq!(
            policy.recommended_version,
            DEVELOPMENT_CLIENT_COMPATIBILITY_VERSION
        );
        assert_eq!(policy.enforce_after, 0);

        let relative = client_version_policy_from_values(
            Environment::Development,
            Some("1.0.0".into()),
            Some("1.0.0".into()),
            Some("30d".into()),
            1_000,
        )
        .expect("development may use relative enforcement times");
        assert_eq!(relative.enforce_after, 1_000 + 30 * 24 * 60 * 60);
    }

    #[test]
    fn empty_static_activation_code_lists_normalize_to_no_values() {
        assert!(split_list("").is_empty());
        assert!(split_list(" ,  , ").is_empty());
        assert_eq!(
            split_list(" first, ,second "),
            vec!["first".to_owned(), "second".to_owned()]
        );
    }

    #[test]
    fn production_policy_errors_name_the_invalid_setting() {
        let missing = client_version_policy_from_values(
            Environment::Production,
            None,
            Some("2.0.0".into()),
            Some("2030-01-01T00:00:00Z".into()),
            1_000,
        )
        .expect_err("minimum version must be configured");
        assert_eq!(
            missing.to_string(),
            "invalid configuration for CAMELLIA_NEXUS_CLIENT_MINIMUM_VERSION: is required in production"
        );

        let unordered = client_version_policy_from_values(
            Environment::Production,
            Some("2.0.0".into()),
            Some("1.9.9".into()),
            Some("2030-01-01T00:00:00Z".into()),
            1_000,
        )
        .expect_err("recommended version must not be older");
        assert_eq!(
            unordered.to_string(),
            "invalid configuration for CAMELLIA_NEXUS_CLIENT_RECOMMENDED_VERSION: must not be lower than CAMELLIA_NEXUS_CLIENT_MINIMUM_VERSION"
        );

        let yaml_coerced = client_version_policy_from_values(
            Environment::Production,
            Some("2.0.0".into()),
            Some("2.0.0".into()),
            Some("2026-08-01 00:00:00 +0000 UTC".into()),
            1_000,
        )
        .expect_err("YAML-coerced timestamps must be rejected with actionable guidance");
        assert!(yaml_coerced.to_string().contains("quote timestamps"));
    }
}
