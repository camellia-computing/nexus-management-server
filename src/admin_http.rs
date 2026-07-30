use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum::{
    Json, Router,
    body::Body,
    error_handling::HandleErrorLayer,
    extract::{DefaultBodyLimit, Multipart, Path as AxumPath, Query, State},
    http::{
        HeaderMap, HeaderValue, Request, Response, StatusCode,
        header::{self, HeaderName},
    },
    middleware::{self, Next},
    response::IntoResponse,
    routing::{get, patch, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::Row;
use thiserror::Error;
use tower::{BoxError, ServiceBuilder};
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    admin_app::{
        ActivationCodeBatchRequest, ActivationCodeDeliveryDraft, ActivationCodeExpiry,
        AdminAppError, AdminApplication, AdminPrincipal, MutationContext, NewLicense, PageRequest,
        apply_license_plan, validate_license_seats,
    },
    admin_auth::{
        AdminAuthError, AdminAuthService, AdminKeyring, AdminPermission, AdminRole, AdminUser,
        AuthenticatedAdmin, SessionCredentials,
    },
    admin_contracts::{
        AdminAccount, AdminActivationCode, AdminAuditEvent, AdminDashboard, AdminDevice,
        AdminItems, AdminLicense, AdminPage, AdminPaymentEvidence, AdminReadiness,
        AdminSessionInfo, AdminSystemStatus, AdminTeamInvitation, AdminTeamMember,
        AdminTeamWorkspace,
    },
    admin_identity::{AdminIdentityService, NewAdminUser, UpdateAdminUser},
    admin_jobs::{AdminJobError, AdminJobService, BulkJobKind, CreatePreview},
    admin_operation,
    admin_storage::{
        EvidenceScanner, ObjectStorageConfig, ObjectStorageError, ObjectStorageService,
        SecretDeliveryService, StoredObjectStatus, evidence_media_type,
    },
    billing::{
        CommercialOffer, ManualPaymentMethod, NewInvoice, PaymentClaimStatus,
        PaymentReviewDecision, validate_payment_review_override,
    },
    config::{Environment, database_pool_config_from_env, time_max_forward_jump_seconds_from_env},
    contracts::{DeviceState, Plan},
    domain::{AccountState, ActivationCodeStatus, AuditEventRecord, LicenseStatus},
    error::ApiError,
    metrics::{MetricsServer, RuntimeMetrics, RuntimeRole, track_http_metrics},
    secret_file::read_secret_file,
    store::{LicenseRepository, PostgresRepository},
    team::{WorkspaceMemberStatus, WorkspaceRole},
    time_format::parse_optional_expiry_time,
};

const SESSION_COOKIE: &str = "__Host-camellia_admin";
const CSRF_COOKIE: &str = "__Host-camellia_admin_csrf";
const DEVELOPMENT_SESSION_COOKIE: &str = "camellia_admin_development";
const DEVELOPMENT_CSRF_COOKIE: &str = "camellia_admin_csrf_development";
const IDEMPOTENCY_HEADER: &str = "idempotency-key";
const MAX_PAYMENT_EVIDENCE_ATTACHMENTS: i64 = 20;
const MIN_FORWARDED_FOR_SECRET_BYTES: usize = 32;
const MAX_FORWARDED_FOR_SECRET_BYTES: usize = 256;
const ADMIN_INDEX_FILE: &str = "index.html";
const ADMIN_FALLBACK_FILE: &str = "fallback.html";
const ADMIN_APPEARANCE_FILE: &str = "appearance-init.js";
const ADMIN_MANIFEST_FILE: &str = "manifest.webmanifest";
const ADMIN_SERVICE_WORKER_FILE: &str = "service-worker.js";
const ADMIN_ICON_DIRECTORY: &str = "icons";
const ADMIN_APPLICATION_ASSET_DIRECTORY: &str = "_app";
const ADMIN_VERSION_FILE: &str = "_app/version.json";
const ADMIN_IMMUTABLE_ASSET_DIRECTORY: &str = "_app/immutable";
const ADMIN_ICON_FILES: &[&str] = &[
    "icons/camellia-console.v1.svg",
    "icons/camellia-console.v1-192.png",
    "icons/camellia-console.v1-512.png",
    "icons/camellia-console-maskable.v1-512.png",
    "icons/camellia-console-apple.v1-180.png",
];

#[derive(Debug, Clone)]
pub struct AdminHttpConfig {
    pub bind: SocketAddr,
    pub public_origin: String,
    pub asset_dir: PathBuf,
    pub environment: Environment,
    pub database_url: String,
    pub database_connections: u32,
    pub database_acquire_timeout: Duration,
    pub request_timeout: Duration,
    pub max_in_flight: usize,
    pub keyring_path: Option<PathBuf>,
    pub forwarded_for_secret_hash: Option<[u8; 32]>,
}

impl AdminHttpConfig {
    pub fn from_env() -> Result<Self, String> {
        let environment = Environment::from_env().map_err(|error| error.to_string())?;
        let bind = env::var("CAMELLIA_NEXUS_ADMIN_BIND")
            .unwrap_or_else(|_| "127.0.0.1:8090".to_owned())
            .parse()
            .map_err(|_| "CAMELLIA_NEXUS_ADMIN_BIND must be a socket address".to_owned())?;
        let public_origin = env::var("CAMELLIA_NEXUS_ADMIN_PUBLIC_ORIGIN")
            .unwrap_or_else(|_| format!("http://{bind}"));
        validate_origin(&public_origin, environment)?;
        let database_url = env::var("DATABASE_URL")
            .map_err(|_| "DATABASE_URL is required for admin-web".to_owned())?;
        let database_pool = database_pool_config_from_env().map_err(|error| error.to_string())?;
        let database_connections = database_pool.max_connections;
        let database_acquire_timeout = database_pool.acquire_timeout;
        let request_timeout = Duration::from_secs(u64::from(admin_positive_u32_from_value(
            "CAMELLIA_NEXUS_ADMIN_REQUEST_TIMEOUT_SECONDS",
            env::var("CAMELLIA_NEXUS_ADMIN_REQUEST_TIMEOUT_SECONDS").ok(),
            180,
        )?));
        let max_in_flight = admin_positive_u32_from_value(
            "CAMELLIA_NEXUS_ADMIN_MAX_IN_FLIGHT",
            env::var("CAMELLIA_NEXUS_ADMIN_MAX_IN_FLIGHT").ok(),
            64,
        )? as usize;
        let asset_dir = env::var("CAMELLIA_NEXUS_ADMIN_ASSET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("admin-ui/build"));
        let keyring_path = env::var("CAMELLIA_NEXUS_ADMIN_KEYRING_PATH")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from);
        if environment == Environment::Production && keyring_path.is_none() {
            return Err("CAMELLIA_NEXUS_ADMIN_KEYRING_PATH is required in production".to_owned());
        }
        let forwarded_for_secret_hash = env::var("CAMELLIA_NEXUS_ADMIN_FORWARDED_FOR_SECRET_PATH")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|path| {
                let secret = read_secret_file(path).map_err(|_| {
                    "CAMELLIA_NEXUS_ADMIN_FORWARDED_FOR_SECRET_PATH must reference a readable regular file no larger than 64 KiB".to_owned()
                })?;
                hash_forwarded_for_secret(&secret)
            })
            .transpose()?;
        Ok(Self {
            bind,
            public_origin,
            asset_dir,
            environment,
            database_url,
            database_connections,
            database_acquire_timeout,
            request_timeout,
            max_in_flight,
            keyring_path,
            forwarded_for_secret_hash,
        })
    }
}

fn hash_forwarded_for_secret(bytes: &[u8]) -> Result<[u8; 32], String> {
    let text = std::str::from_utf8(bytes).map_err(|_| forwarded_for_secret_contract_error())?;
    let secret = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    if !(MIN_FORWARDED_FOR_SECRET_BYTES..=MAX_FORWARDED_FOR_SECRET_BYTES).contains(&secret.len())
        || !secret.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(forwarded_for_secret_contract_error());
    }
    Ok(Sha256::digest(secret.as_bytes()).into())
}

fn forwarded_for_secret_contract_error() -> String {
    "the admin forwarded-for proxy secret must contain 32 to 256 visible ASCII characters"
        .to_owned()
}

#[derive(Clone)]
struct AdminHttpState {
    application: AdminApplication,
    keyring: Arc<AdminKeyring>,
    auth: AdminAuthService,
    identity: AdminIdentityService,
    jobs: AdminJobService,
    storage: ObjectStorageService,
    evidence_scanner: EvidenceScanner,
    secret_deliveries: SecretDeliveryService,
    public_origin: String,
    secure_cookie: bool,
    started_at: i64,
    forwarded_for_secret_hash: Option<[u8; 32]>,
}

#[derive(Clone)]
struct AdminSecurityState {
    content_security_policy: HeaderValue,
}

pub async fn run_admin_web(config: AdminHttpConfig) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(error) = validate_admin_assets(&config.asset_dir) {
        return Err(error.into());
    }
    let repository = PostgresRepository::connect(
        &config.database_url,
        config.database_connections,
        config.database_acquire_timeout,
    )
    .await?;
    let runtime_metrics = RuntimeMetrics::new(RuntimeRole::AdminWeb);
    if let Err(error) = repository.readiness_check().await {
        runtime_metrics.record_readiness(false);
        return Err(error.into());
    }
    admin_schema_ready(&repository).await?;
    let keyring = match config.keyring_path {
        Some(path) => Arc::new(AdminKeyring::load(path)?),
        None => Arc::new(AdminKeyring::ephemeral()),
    };
    keyring.readiness_check(&repository).await?;
    runtime_metrics.record_readiness(true);
    let secret_deliveries = SecretDeliveryService::new(repository.clone(), keyring.clone());
    let evidence_scanner =
        EvidenceScanner::from_env(config.environment == Environment::Production)?;
    let application = AdminApplication::new(
        repository.clone(),
        time_max_forward_jump_seconds_from_env().map_err(|error| error.to_string())?,
    )
    .await?;
    let storage = ObjectStorageService::new(
        application.clone(),
        keyring.clone(),
        ObjectStorageConfig::from_env()?,
    )?;
    let auth = AdminAuthService::new(application.clone(), keyring.clone())?;
    let identity = AdminIdentityService::new(application.clone(), keyring.clone());
    let jobs = AdminJobService::new(application.clone());
    let started_at = application.trusted_now().await?;
    let state = AdminHttpState {
        application,
        keyring,
        auth,
        identity,
        jobs,
        storage,
        evidence_scanner,
        secret_deliveries,
        public_origin: config.public_origin.clone(),
        secure_cookie: config.environment == Environment::Production
            || config.public_origin.starts_with("https://"),
        started_at,
        forwarded_for_secret_hash: config.forwarded_for_secret_hash,
    };
    let security = AdminSecurityState {
        content_security_policy: admin_content_security_policy(&config.asset_dir)?,
    };
    let router = admin_router(
        state,
        security,
        &config.asset_dir,
        runtime_metrics.clone(),
        config.request_timeout,
        config.max_in_flight,
    );
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    let metrics_server =
        MetricsServer::from_env(config.environment, RuntimeRole::AdminWeb, runtime_metrics).await?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let metrics_task = metrics_server.map(|server| tokio::spawn(server.serve(shutdown_rx)));
    tracing::info!(
        bind = %config.bind,
        public_origin = %config.public_origin,
        asset_dir = %config.asset_dir.display(),
        "Camellia Nexus admin control plane listening"
    );
    let signal_tx = shutdown_tx.clone();
    let serve_result = axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            admin_shutdown_signal().await;
            let _ = signal_tx.send(true);
        })
        .await;
    let _ = shutdown_tx.send(true);
    let metrics_result = match metrics_task {
        Some(task) => task.await?,
        None => Ok(()),
    };
    serve_result?;
    metrics_result?;
    Ok(())
}

async fn admin_shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = terminate.recv() => {},
            },
            Err(error) => {
                tracing::warn!(%error, "SIGTERM handler is unavailable; waiting for Ctrl-C");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn admin_router(
    state: AdminHttpState,
    security: AdminSecurityState,
    asset_dir: &Path,
    metrics: RuntimeMetrics,
    request_timeout: Duration,
    max_in_flight: usize,
) -> Router {
    let api = Router::new()
        .route("/auth/enrollment", post(begin_enrollment))
        .route("/auth/enrollment/complete", post(complete_enrollment))
        .route("/auth/login", post(login))
        .route("/auth/recovery", post(begin_recovery))
        .route("/auth/step-up", post(step_up))
        .route("/auth/password", post(change_password))
        .route("/auth/me", get(me))
        .route("/auth/logout", post(logout))
        .route("/dashboard", get(dashboard))
        .route("/admin-users", get(admin_users).post(create_admin_user))
        .route("/admin-users/{id}", patch(update_admin_user))
        .route(
            "/admin-users/{id}/actions/disable",
            post(disable_admin_user),
        )
        .route(
            "/admin-users/{id}/actions/reset-enrollment",
            post(reset_admin_enrollment),
        )
        .route("/accounts", get(accounts).post(create_account))
        .route("/accounts/{id}", get(account))
        .route("/accounts/{id}/actions/set-state", post(set_account_state))
        .route("/licenses", get(licenses).post(create_license))
        .route("/licenses/{id}", get(license))
        .route(
            "/licenses/{id}/actions/set-status",
            post(set_license_status),
        )
        .route("/licenses/{id}/actions/set-plan", post(set_license_plan))
        .route(
            "/licenses/{id}/actions/set-expiry",
            post(set_license_expiry),
        )
        .route(
            "/activation-codes",
            get(activation_codes).post(issue_activation_codes),
        )
        .route("/secret-deliveries/{id}/claim", post(claim_secret_delivery))
        .route(
            "/secret-deliveries/{id}/acknowledge",
            post(acknowledge_secret_delivery),
        )
        .route(
            "/activation-codes/{reference}/actions/{action}",
            post(mutate_activation_code),
        )
        .route("/devices", get(devices))
        .route("/devices/{id}/actions/set-state", post(set_device_state))
        .route("/audit-events", get(audit_events))
        .route("/bulk-jobs", get(bulk_jobs).post(create_bulk_job))
        .route("/bulk-jobs/previews", post(create_bulk_preview))
        .route("/bulk-jobs/{id}", get(bulk_job))
        .route("/bulk-jobs/{id}/actions/cancel", post(cancel_bulk_job))
        .route(
            "/billing/offers",
            get(billing_offers).post(create_billing_offer),
        )
        .route(
            "/billing/payment-methods",
            get(payment_methods).post(create_payment_method),
        )
        .route("/billing/invoices", get(invoices).post(create_invoice))
        .route("/billing/payment-claims", get(payment_claims))
        .route(
            "/billing/payment-claims/{id}/actions/review",
            post(review_payment_claim),
        )
        .route(
            "/billing/payment-claims/{id}/evidence",
            get(payment_evidence)
                .merge(post(upload_payment_evidence).layer(DefaultBodyLimit::max(9 * 1024 * 1024))),
        )
        .route("/team-workspaces", get(team_workspaces))
        .route("/team-workspaces/{account_id}/members", get(team_members))
        .route(
            "/team-workspaces/{account_id}/invitations",
            get(team_invitations).post(create_team_invitation),
        )
        .route(
            "/team-workspaces/{account_id}/members/{member_id}/actions/update",
            post(update_team_member),
        )
        .route(
            "/team-workspaces/{account_id}/members/{member_id}/actions/complete-owner-profile",
            post(complete_team_owner_profile),
        )
        .route(
            "/team-workspaces/{account_id}/members/{member_id}/actions/transfer-ownership",
            post(transfer_team_ownership),
        )
        .route(
            "/team-workspaces/{account_id}/invitations/{invitation_id}/actions/revoke",
            post(revoke_team_invitation),
        )
        .route("/system/status", get(system_status))
        .fallback(admin_api_not_found)
        .method_not_allowed_fallback(admin_api_method_not_allowed)
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(handle_admin_middleware_error))
                .load_shed()
                .concurrency_limit(max_in_flight)
                .timeout(request_timeout),
        )
        .with_state(state.clone());
    Router::new()
        .route("/healthz", get(admin_healthz))
        .route("/readyz", get(admin_readyz))
        .nest("/api/v1", api)
        .merge(admin_asset_router(asset_dir))
        .layer(middleware::from_fn_with_state(
            security,
            admin_security_headers,
        ))
        .layer(middleware::from_fn_with_state(metrics, track_http_metrics))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(middleware::from_fn(crate::request_id::sanitize_request_id))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

fn admin_asset_router<S>(asset_dir: &Path) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .nest_service(
            "/_app",
            ServeDir::new(asset_dir.join(ADMIN_APPLICATION_ASSET_DIRECTORY)),
        )
        .nest_service(
            "/icons",
            ServeDir::new(asset_dir.join(ADMIN_ICON_DIRECTORY)),
        )
        .route_service(
            "/appearance-init.js",
            ServeFile::new(asset_dir.join(ADMIN_APPEARANCE_FILE)),
        )
        .route_service(
            "/manifest.webmanifest",
            ServeFile::new(asset_dir.join(ADMIN_MANIFEST_FILE)),
        )
        .route_service(
            "/service-worker.js",
            ServeFile::new(asset_dir.join(ADMIN_SERVICE_WORKER_FILE)),
        )
        .route_service("/", ServeFile::new(asset_dir.join(ADMIN_INDEX_FILE)))
        .fallback_service(ServeFile::new(asset_dir.join(ADMIN_FALLBACK_FILE)))
}

fn validate_admin_assets(asset_dir: &Path) -> Result<(), String> {
    for asset in [
        ADMIN_INDEX_FILE,
        ADMIN_FALLBACK_FILE,
        ADMIN_APPEARANCE_FILE,
        ADMIN_MANIFEST_FILE,
        ADMIN_SERVICE_WORKER_FILE,
        ADMIN_VERSION_FILE,
    ]
    .into_iter()
    .chain(ADMIN_ICON_FILES.iter().copied())
    {
        if !asset_dir.join(asset).is_file() {
            return Err(format!(
                "admin UI asset is missing ({asset}): {}",
                asset_dir.display()
            ));
        }
    }
    if !asset_dir.join(ADMIN_IMMUTABLE_ASSET_DIRECTORY).is_dir() {
        return Err(format!(
            "admin UI asset directory is missing ({ADMIN_IMMUTABLE_ASSET_DIRECTORY}): {}",
            asset_dir.display()
        ));
    }
    if !asset_dir.join(ADMIN_ICON_DIRECTORY).is_dir() {
        return Err(format!(
            "admin UI asset directory is missing ({ADMIN_ICON_DIRECTORY}): {}",
            asset_dir.display()
        ));
    }
    Ok(())
}

async fn admin_api_not_found() -> AdminHttpError {
    AdminHttpError::NotFound
}

async fn admin_api_method_not_allowed() -> Response<Body> {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(AdminErrorBody {
            code: "admin_method_not_allowed",
            message: "The requested administration API method is not allowed.".to_owned(),
            field: None,
        }),
    )
        .into_response()
}

async fn handle_admin_middleware_error(error: BoxError) -> Response<Body> {
    admin_middleware_error_response(error.is::<tower::timeout::error::Elapsed>())
}

fn admin_middleware_error_response(timed_out: bool) -> Response<Body> {
    let mut response = (
        if timed_out {
            StatusCode::GATEWAY_TIMEOUT
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(AdminErrorBody {
            code: if timed_out {
                "admin_request_timeout"
            } else {
                "admin_service_overloaded"
            },
            message: if timed_out {
                "The administration request timed out."
            } else {
                "The administration service is temporarily overloaded."
            }
            .to_owned(),
            field: None,
        }),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

async fn admin_healthz() -> &'static str {
    "ok"
}

async fn admin_readyz(State(state): State<AdminHttpState>) -> Response<Body> {
    let ready = tokio::time::timeout(Duration::from_secs(2), async {
        state
            .application
            .repository()
            .readiness_check()
            .await
            .is_ok()
            && admin_schema_ready(state.application.repository())
                .await
                .is_ok()
            && state
                .keyring
                .readiness_check(state.application.repository())
                .await
                .is_ok()
            && state.application.trusted_now().await.is_ok()
    })
    .await
    .unwrap_or(false);
    let (status, message) = if ready {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready")
    };
    let mut response = (status, message).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[derive(Debug, Error)]
enum AdminHttpError {
    #[error(transparent)]
    Auth(#[from] AdminAuthError),
    #[error(transparent)]
    Application(#[from] AdminAppError),
    #[error(transparent)]
    Job(#[from] AdminJobError),
    #[error(transparent)]
    Storage(#[from] ObjectStorageError),
    #[error("invalid request: {0}")]
    Invalid(String),
    #[error("{message}")]
    InvalidField {
        code: &'static str,
        field: &'static str,
        message: String,
    },
    #[error("resource not found")]
    NotFound,
    #[error("resource conflict: {0}")]
    Conflict(String),
    #[error("database unavailable")]
    Database,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminErrorBody {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<&'static str>,
}

impl IntoResponse for AdminHttpError {
    fn into_response(self) -> axum::response::Response {
        let field = match &self {
            Self::InvalidField { field, .. } => Some(*field),
            _ => None,
        };
        let (status, code) = match &self {
            Self::InvalidField { code, .. } => (StatusCode::UNPROCESSABLE_ENTITY, *code),
            Self::Auth(AdminAuthError::InvalidCredentials)
            | Self::Auth(AdminAuthError::InvalidSession) => {
                (StatusCode::UNAUTHORIZED, "admin_authentication_required")
            }
            Self::Auth(AdminAuthError::InvalidEnrollment) => {
                (StatusCode::BAD_REQUEST, "admin_enrollment_invalid")
            }
            Self::Auth(AdminAuthError::RateLimited) => {
                (StatusCode::TOO_MANY_REQUESTS, "admin_rate_limited")
            }
            Self::Auth(AdminAuthError::StepUpRequired) => {
                (StatusCode::FORBIDDEN, "admin_step_up_required")
            }
            Self::Auth(AdminAuthError::PermissionDenied)
            | Self::Application(AdminAppError::PermissionDenied)
            | Self::Job(AdminJobError::PermissionDenied) => {
                (StatusCode::FORBIDDEN, "admin_permission_denied")
            }
            Self::Auth(AdminAuthError::Conflict)
            | Self::Application(
                AdminAppError::IdempotencyConflict | AdminAppError::SecretReplayUnavailable,
            )
            | Self::Job(AdminJobError::Application(
                AdminAppError::IdempotencyConflict | AdminAppError::SecretReplayUnavailable,
            )) => (StatusCode::CONFLICT, "admin_conflict"),
            Self::Conflict(_) => (StatusCode::CONFLICT, "admin_resource_conflict"),
            Self::Auth(AdminAuthError::VersionConflict) => {
                (StatusCode::PRECONDITION_FAILED, "admin_version_conflict")
            }
            Self::Auth(AdminAuthError::NotFound) => (StatusCode::NOT_FOUND, "admin_not_found"),
            Self::Application(AdminAppError::VersionConflict) => {
                (StatusCode::PRECONDITION_FAILED, "admin_version_conflict")
            }
            Self::Job(AdminJobError::Application(AdminAppError::VersionConflict)) => {
                (StatusCode::PRECONDITION_FAILED, "admin_version_conflict")
            }
            Self::Application(AdminAppError::NotFound) | Self::NotFound => {
                (StatusCode::NOT_FOUND, "admin_not_found")
            }
            Self::Auth(AdminAuthError::Validation(_))
            | Self::Application(AdminAppError::Validation(_))
            | Self::Job(AdminJobError::Validation(_))
            | Self::Invalid(_) => (StatusCode::UNPROCESSABLE_ENTITY, "admin_validation_failed"),
            Self::Storage(ObjectStorageError::Validation(_)) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "admin_validation_failed")
            }
            Self::Storage(ObjectStorageError::NotFound) => {
                (StatusCode::NOT_FOUND, "admin_secret_delivery_not_found")
            }
            Self::Storage(ObjectStorageError::QuotaExceeded) => (
                StatusCode::INSUFFICIENT_STORAGE,
                "admin_storage_quota_exceeded",
            ),
            Self::Storage(ObjectStorageError::MalwareDetected) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "admin_upload_rejected")
            }
            Self::Storage(ObjectStorageError::ScannerUnavailable) => {
                (StatusCode::SERVICE_UNAVAILABLE, "admin_scanner_unavailable")
            }
            Self::Job(AdminJobError::NotFound) => (StatusCode::NOT_FOUND, "admin_job_not_found"),
            Self::Job(AdminJobError::Conflict | AdminJobError::PreviewUnavailable) => {
                (StatusCode::CONFLICT, "admin_job_conflict")
            }
            Self::Auth(AdminAuthError::Keyring)
            | Self::Auth(AdminAuthError::Service(_))
            | Self::Application(AdminAppError::Service(_))
            | Self::Application(AdminAppError::Serialization(_))
            | Self::Application(AdminAppError::SecretDelivery)
            | Self::Job(AdminJobError::Application(_) | AdminJobError::Service(_))
            | Self::Storage(
                ObjectStorageError::NotReady
                | ObjectStorageError::Integrity
                | ObjectStorageError::Backend
                | ObjectStorageError::Authentication(_)
                | ObjectStorageError::Service(_),
            )
            | Self::Database => (StatusCode::INTERNAL_SERVER_ERROR, "admin_internal"),
        };
        let public_message = if status.is_server_error() {
            "The administration service could not complete the request.".to_owned()
        } else {
            self.to_string()
        };
        (
            status,
            Json(AdminErrorBody {
                code,
                message: public_message,
                field,
            }),
        )
            .into_response()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EnrollmentInput {
    token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EnrollmentCompleteInput {
    token: String,
    password: String,
    totp: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LoginInput {
    username: String,
    password: String,
    totp: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StepUpInput {
    password: String,
    totp: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryInput {
    username: String,
    password: String,
    recovery_code: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthResponse<T> {
    user: T,
    expires_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_codes: Option<Vec<String>>,
}

async fn begin_enrollment(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Json(input): Json<EnrollmentInput>,
) -> Result<Json<crate::admin_auth::EnrollmentChallenge>, AdminHttpError> {
    require_same_origin(&state, &headers)?;
    Ok(Json(state.auth.begin_enrollment(&input.token).await?))
}

async fn complete_enrollment(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Json(input): Json<EnrollmentCompleteInput>,
) -> Result<Response<Body>, AdminHttpError> {
    require_same_origin(&state, &headers)?;
    let source_ip = source_ip(&state, &headers);
    let user_agent = header_text(&headers, header::USER_AGENT);
    let result = state
        .auth
        .complete_enrollment(
            &input.token,
            &input.password,
            &input.totp,
            source_ip.as_deref(),
            user_agent,
        )
        .await?;
    let session = result.session.ok_or(AdminHttpError::Database)?;
    let now = state.application.trusted_now().await?;
    auth_response(
        &state,
        AuthResponse {
            user: result.user,
            expires_at: session.expires_at,
            recovery_codes: Some(result.recovery_codes),
        },
        &session,
        now,
    )
}

async fn login(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Json(input): Json<LoginInput>,
) -> Result<Response<Body>, AdminHttpError> {
    require_same_origin(&state, &headers)?;
    let source_ip = source_ip(&state, &headers);
    let (user, session) = state
        .auth
        .login(
            &input.username,
            &input.password,
            &input.totp,
            source_ip.as_deref(),
            header_text(&headers, header::USER_AGENT),
        )
        .await?;
    let now = state.application.trusted_now().await?;
    auth_response(
        &state,
        AuthResponse {
            user,
            expires_at: session.expires_at,
            recovery_codes: None,
        },
        &session,
        now,
    )
}

async fn step_up(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Json(input): Json<StepUpInput>,
) -> Result<Json<Value>, AdminHttpError> {
    let admin = authenticate_csrf(&state, &headers).await?;
    let source_ip = source_ip(&state, &headers);
    let elevated_until = state
        .auth
        .step_up(&admin, &input.password, &input.totp, source_ip.as_deref())
        .await?;
    Ok(Json(json!({ "elevatedUntil": elevated_until })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChangePasswordInput {
    new_password: String,
    reason: String,
}

async fn change_password(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Json(input): Json<ChangePasswordInput>,
) -> Result<Response<Body>, AdminHttpError> {
    let admin = authenticate_mutation(&state, &headers).await?;
    admin.require_step_up(state.application.trusted_now().await?)?;
    let expected = required_if_match(&headers)?;
    let context = mutation_context(&state, &admin, &headers, input.reason)?;
    state
        .auth
        .change_password(&admin.user.id, &input.new_password, expected, &context)
        .await
        .map_err(|error| match error {
            AdminAuthError::Validation(message) => AdminHttpError::InvalidField {
                code: "admin_password_invalid",
                field: "newPassword",
                message,
            },
            error => AdminHttpError::Auth(error),
        })?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    append_clear_cookie(
        response.headers_mut(),
        session_cookie_name(&state),
        state.secure_cookie,
    );
    append_clear_cookie(
        response.headers_mut(),
        csrf_cookie_name(&state),
        state.secure_cookie,
    );
    Ok(response)
}

async fn begin_recovery(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Json(input): Json<RecoveryInput>,
) -> Result<Json<crate::admin_auth::RecoveryEnrollment>, AdminHttpError> {
    require_same_origin(&state, &headers)?;
    let source_ip = source_ip(&state, &headers);
    Ok(Json(
        state
            .auth
            .begin_recovery(
                &input.username,
                &input.password,
                &input.recovery_code,
                source_ip.as_deref(),
            )
            .await?,
    ))
}

async fn me(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
) -> Result<Json<AdminSessionInfo>, AdminHttpError> {
    let admin = authenticate(&state, &headers).await?;
    let permissions: Vec<_> = AdminPermission::ALL
        .into_iter()
        .chain(std::iter::once(AdminPermission::SystemRead))
        .filter(|permission| admin.user.allows(*permission))
        .map(|permission| permission.as_str().to_owned())
        .collect();
    Ok(Json(AdminSessionInfo {
        user: admin.user,
        permissions,
        expires_at: admin.expires_at,
        elevated_until: admin.elevated_until,
        server_version: env!("CARGO_PKG_VERSION").to_owned(),
    }))
}

async fn logout(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
) -> Result<Response<Body>, AdminHttpError> {
    let admin = authenticate_csrf(&state, &headers).await?;
    state.auth.logout(&admin.session_id).await?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    append_clear_cookie(
        response.headers_mut(),
        session_cookie_name(&state),
        state.secure_cookie,
    );
    append_clear_cookie(
        response.headers_mut(),
        csrf_cookie_name(&state),
        state.secure_cookie,
    );
    Ok(response)
}

async fn dashboard(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
) -> Result<Json<AdminDashboard>, AdminHttpError> {
    let admin = authenticate(&state, &headers).await?;
    admin.user.require(AdminPermission::SystemRead)?;
    let generated_at = state.application.trusted_now().await?;
    let row = sqlx::query(
        "SELECT
            (SELECT count(*) FROM accounts) AS accounts,
            (SELECT count(*) FROM licenses WHERE status = 'active') AS active_licenses,
            (SELECT count(*) FROM devices WHERE state = 'active') AS active_devices,
            (SELECT count(*) FROM devices WHERE state IN ('revoked', 'suspicious')) AS risky_devices,
            (SELECT count(*) FROM manual_payment_claims
             WHERE status IN ('submitted', 'under_review')) AS pending_payments,
            (SELECT count(*) FROM billing_invoices WHERE status IN ('open', 'overdue')) AS open_invoices",
    )
    .fetch_one(&state.application.repository().pool)
    .await
    .map_err(|_| AdminHttpError::Database)?;
    Ok(Json(AdminDashboard {
        generated_at,
        accounts: row
            .try_get("accounts")
            .map_err(|_| AdminHttpError::Database)?,
        active_licenses: row
            .try_get("active_licenses")
            .map_err(|_| AdminHttpError::Database)?,
        active_devices: row
            .try_get("active_devices")
            .map_err(|_| AdminHttpError::Database)?,
        risky_devices: row
            .try_get("risky_devices")
            .map_err(|_| AdminHttpError::Database)?,
        pending_payments: row
            .try_get("pending_payments")
            .map_err(|_| AdminHttpError::Database)?,
        open_invoices: row
            .try_get("open_invoices")
            .map_err(|_| AdminHttpError::Database)?,
    }))
}

async fn admin_users(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Query(request): Query<PageRequest>,
) -> Result<Json<Value>, AdminHttpError> {
    let admin = authenticate(&state, &headers).await?;
    admin.user.require(AdminPermission::IdentityManage)?;
    let page = request.validate()?;
    Ok(Json(serde_json::to_value(
        state
            .identity
            .admin_users(
                page.cursor.as_deref(),
                page.query.as_deref(),
                page.page_size,
            )
            .await?,
    )?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateAdminUserInput {
    username: String,
    display_name: String,
    roles: BTreeSet<AdminRole>,
    reason: String,
}

async fn create_admin_user(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Json(input): Json<CreateAdminUserInput>,
) -> Result<(StatusCode, Json<Value>), AdminHttpError> {
    let admin = authenticate_mutation(&state, &headers).await?;
    admin.user.require(AdminPermission::IdentityManage)?;
    admin.require_step_up(state.application.trusted_now().await?)?;
    let context = mutation_context(&state, &admin, &headers, input.reason)?;
    let result = state
        .identity
        .create_admin_user(
            NewAdminUser {
                username: input.username,
                display_name: input.display_name,
                roles: input.roles,
            },
            &context,
        )
        .await?;
    Ok((StatusCode::CREATED, Json(serde_json::to_value(result)?)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdateAdminUserInput {
    display_name: Option<String>,
    roles: Option<BTreeSet<AdminRole>>,
    reason: String,
}

async fn update_admin_user(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(input): Json<UpdateAdminUserInput>,
) -> Result<Response<Body>, AdminHttpError> {
    let admin = authenticate_mutation(&state, &headers).await?;
    if id == admin.user.id {
        if input.roles.is_some() {
            return Err(AdminAuthError::PermissionDenied.into());
        }
    } else {
        admin.user.require(AdminPermission::IdentityManage)?;
    }
    admin.require_step_up(state.application.trusted_now().await?)?;
    let expected_version = required_if_match(&headers)?;
    let context = mutation_context(&state, &admin, &headers, input.reason)?;
    let user = state
        .identity
        .update_admin_user(
            &id,
            UpdateAdminUser {
                display_name: input.display_name,
                roles: input.roles,
            },
            expected_version,
            &context,
        )
        .await?;
    admin_user_response(user)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdminIdentityActionInput {
    reason: String,
}

async fn disable_admin_user(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(input): Json<AdminIdentityActionInput>,
) -> Result<Response<Body>, AdminHttpError> {
    let admin = authenticate_mutation(&state, &headers).await?;
    admin.user.require(AdminPermission::IdentityManage)?;
    admin.require_step_up(state.application.trusted_now().await?)?;
    let expected_version = required_if_match(&headers)?;
    let context = mutation_context(&state, &admin, &headers, input.reason)?;
    admin_user_response(
        state
            .identity
            .disable_admin_user(&id, expected_version, &context)
            .await?,
    )
}

async fn reset_admin_enrollment(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(input): Json<AdminIdentityActionInput>,
) -> Result<Json<Value>, AdminHttpError> {
    let admin = authenticate_mutation(&state, &headers).await?;
    admin.user.require(AdminPermission::IdentityManage)?;
    admin.require_step_up(state.application.trusted_now().await?)?;
    let expected_version = required_if_match(&headers)?;
    let context = mutation_context(&state, &admin, &headers, input.reason)?;
    Ok(Json(serde_json::to_value(
        state
            .identity
            .reset_admin_enrollment(&id, expected_version, &context)
            .await?,
    )?))
}

async fn accounts(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Query(request): Query<PageRequest>,
) -> Result<Json<AdminPage<AdminAccount>>, AdminHttpError> {
    authenticate(&state, &headers)
        .await?
        .user
        .require(AdminPermission::AccountRead)?;
    Ok(Json(state.application.accounts(request).await?.into()))
}

async fn account(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Response<Body>, AdminHttpError> {
    authenticate(&state, &headers)
        .await?
        .user
        .require(AdminPermission::AccountRead)?;
    let value = state
        .application
        .account(&id)
        .await?
        .ok_or(AdminHttpError::NotFound)?;
    let row_version = value.row_version;
    versioned_response(AdminAccount::from(value), row_version)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateAccountInput {
    id: String,
    note: Option<String>,
    reason: String,
}

async fn create_account(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Json(input): Json<CreateAccountInput>,
) -> Result<(StatusCode, Json<AdminAccount>), AdminHttpError> {
    let admin = authenticate_mutation(&state, &headers).await?;
    admin.user.require(AdminPermission::AccountWrite)?;
    let context = mutation_context(&state, &admin, &headers, input.reason)?;
    let value = state
        .application
        .create_account(&input.id, input.note, &context)
        .await?;
    Ok((StatusCode::CREATED, Json(AdminAccount::new(value, 1))))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SetAccountStateInput {
    state: AccountState,
    reason: String,
}

async fn set_account_state(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(input): Json<SetAccountStateInput>,
) -> Result<Json<AdminAccount>, AdminHttpError> {
    let admin = authenticate_mutation(&state, &headers).await?;
    let permission = if input.state == AccountState::Denylisted {
        admin.require_step_up(state.application.trusted_now().await?)?;
        AdminPermission::AccountDenylist
    } else {
        AdminPermission::AccountWrite
    };
    admin.user.require(permission)?;
    let expected = required_if_match(&headers)?;
    let context = mutation_context(&state, &admin, &headers, input.reason)?;
    let value = state
        .application
        .set_account_state(&id, input.state, Some(expected), &context)
        .await?;
    Ok(Json(AdminAccount::new(
        value,
        incremented_row_version(expected)?,
    )))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LicenseQuery {
    account: Option<String>,
    cursor: Option<String>,
    #[serde(default = "default_admin_page_size")]
    page_size: u32,
    query: Option<String>,
}

async fn licenses(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Query(request): Query<LicenseQuery>,
) -> Result<Json<AdminPage<AdminLicense>>, AdminHttpError> {
    authenticate(&state, &headers)
        .await?
        .user
        .require(AdminPermission::LicenseRead)?;
    let page = admin_page_request(&request.cursor, request.page_size, &request.query);
    Ok(Json(
        state
            .application
            .licenses(request.account.as_deref(), page)
            .await?
            .into(),
    ))
}

async fn license(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Response<Body>, AdminHttpError> {
    authenticate(&state, &headers)
        .await?
        .user
        .require(AdminPermission::LicenseRead)?;
    let value = state
        .application
        .license(&id)
        .await?
        .ok_or(AdminHttpError::NotFound)?;
    let row_version = value.row_version;
    versioned_response(AdminLicense::from(value), row_version)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateLicenseInput {
    id: String,
    account_id: String,
    plan: Plan,
    #[serde(default = "default_license_status")]
    status: LicenseStatus,
    expires_at: Option<String>,
    #[serde(default)]
    purchased_seats: u32,
    reason: String,
}

async fn create_license(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Json(input): Json<CreateLicenseInput>,
) -> Result<(StatusCode, Json<AdminLicense>), AdminHttpError> {
    let admin = authenticate_mutation(&state, &headers).await?;
    admin.user.require(AdminPermission::LicenseWrite)?;
    validate_license_seats(input.plan, input.purchased_seats).map_err(|error| {
        AdminHttpError::InvalidField {
            code: "admin_license_seats_invalid",
            field: "purchasedSeats",
            message: error.to_string(),
        }
    })?;
    let now = state.application.trusted_now().await?;
    let expires_at = input
        .expires_at
        .as_deref()
        .map(|value| parse_optional_expiry_time(value, now))
        .transpose()
        .map_err(|error| AdminHttpError::Invalid(error.to_string()))?
        .flatten();
    let context = mutation_context(&state, &admin, &headers, input.reason)?;
    let value = state
        .application
        .create_license(
            NewLicense {
                id: input.id,
                account_id: input.account_id,
                plan: input.plan,
                status: input.status,
                expires_at,
                purchased_seats: input.purchased_seats,
            },
            &context,
        )
        .await?;
    let row_version = i64::try_from(value.row_version).map_err(|_| AdminHttpError::Database)?;
    Ok((
        StatusCode::CREATED,
        Json(AdminLicense::new(value, row_version)),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SetLicenseStatusInput {
    status: LicenseStatus,
    reason: String,
}

async fn set_license_status(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(input): Json<SetLicenseStatusInput>,
) -> Result<Json<AdminLicense>, AdminHttpError> {
    let admin = authenticate_mutation(&state, &headers).await?;
    admin.user.require(AdminPermission::LicenseWrite)?;
    if input.status == LicenseStatus::Canceled {
        admin.require_step_up(state.application.trusted_now().await?)?;
    }
    let expected = required_if_match(&headers)?;
    let context = mutation_context(&state, &admin, &headers, input.reason)?;
    let status = input.status;
    let value = state
        .application
        .mutate_license(
            &id,
            Some(expected),
            &context,
            json!({"status": status}),
            move |license| {
                if license.status != status {
                    license.status = status;
                    license.license_epoch = license.license_epoch.saturating_add(1);
                    license.row_version = license.row_version.saturating_add(1);
                }
                Ok(())
            },
            "license_status_set",
        )
        .await?;
    let row_version = i64::try_from(value.row_version).map_err(|_| AdminHttpError::Database)?;
    Ok(Json(AdminLicense::new(value, row_version)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SetLicensePlanInput {
    plan: Plan,
    purchased_seats: Option<u32>,
    reason: String,
}

async fn set_license_plan(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(input): Json<SetLicensePlanInput>,
) -> Result<Json<AdminLicense>, AdminHttpError> {
    let admin = authenticate_mutation(&state, &headers).await?;
    admin.user.require(AdminPermission::LicenseWrite)?;
    let expected = required_if_match(&headers)?;
    let context = mutation_context(&state, &admin, &headers, input.reason)?;
    let plan = input.plan;
    let purchased_seats = input.purchased_seats;
    let value = state
        .application
        .mutate_license(
            &id,
            Some(expected),
            &context,
            json!({"plan": plan, "purchasedSeats": purchased_seats}),
            move |license| apply_license_plan(license, plan, purchased_seats),
            "license_plan_set",
        )
        .await
        .map_err(|error| match error {
            AdminAppError::Validation(message) => AdminHttpError::InvalidField {
                code: "admin_license_seats_invalid",
                field: "purchasedSeats",
                message,
            },
            error => AdminHttpError::Application(error),
        })?;
    let row_version = i64::try_from(value.row_version).map_err(|_| AdminHttpError::Database)?;
    Ok(Json(AdminLicense::new(value, row_version)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SetLicenseExpiryInput {
    expires_at: String,
    reason: String,
}

async fn set_license_expiry(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(input): Json<SetLicenseExpiryInput>,
) -> Result<Json<AdminLicense>, AdminHttpError> {
    let admin = authenticate_mutation(&state, &headers).await?;
    admin.user.require(AdminPermission::LicenseWrite)?;
    let expected = required_if_match(&headers)?;
    let now = state.application.trusted_now().await?;
    let expires_at = parse_optional_expiry_time(&input.expires_at, now)
        .map_err(|error| AdminHttpError::Invalid(error.to_string()))?;
    let context = mutation_context(&state, &admin, &headers, input.reason)?;
    let value = state
        .application
        .mutate_license(
            &id,
            Some(expected),
            &context,
            json!({"expiresAt": expires_at}),
            move |license| {
                if license.expires_at != expires_at {
                    license.expires_at = expires_at;
                    license.license_epoch = license.license_epoch.saturating_add(1);
                    license.row_version = license.row_version.saturating_add(1);
                }
                Ok(())
            },
            "license_expiry_set",
        )
        .await?;
    let row_version = i64::try_from(value.row_version).map_err(|_| AdminHttpError::Database)?;
    Ok(Json(AdminLicense::new(value, row_version)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ActivationCodeQuery {
    account: Option<String>,
    status: Option<ActivationCodeStatus>,
    cursor: Option<String>,
    #[serde(default = "default_admin_page_size")]
    page_size: u32,
    query: Option<String>,
}

async fn activation_codes(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Query(request): Query<ActivationCodeQuery>,
) -> Result<Json<AdminPage<AdminActivationCode>>, AdminHttpError> {
    authenticate(&state, &headers)
        .await?
        .user
        .require(AdminPermission::CodeRead)?;
    let page = admin_page_request(&request.cursor, request.page_size, &request.query);
    Ok(Json(
        state
            .application
            .activation_codes(request.account.as_deref(), request.status, page)
            .await?
            .into(),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IssueActivationCodesInput {
    account_id: String,
    license_id: String,
    count: u32,
    #[serde(default = "default_max_redemptions")]
    max_redemptions: u32,
    expires_at: Option<String>,
    channel: Option<String>,
    note: Option<String>,
    reason: String,
}

async fn issue_activation_codes(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Json(input): Json<IssueActivationCodesInput>,
) -> Result<(StatusCode, Json<Value>), AdminHttpError> {
    let admin = authenticate_mutation(&state, &headers).await?;
    admin.user.require(AdminPermission::CodeIssue)?;
    admin.require_step_up(state.application.trusted_now().await?)?;
    let now = state.application.trusted_now().await?;
    let expires_at = input
        .expires_at
        .as_deref()
        .map(|value| parse_optional_expiry_time(value, now))
        .transpose()
        .map_err(|error| AdminHttpError::Invalid(error.to_string()))?
        .flatten();
    let context = mutation_context(&state, &admin, &headers, input.reason)?;
    let operation_id = context
        .operation_id
        .clone()
        .ok_or_else(|| AdminHttpError::Invalid("Idempotency-Key is required".to_owned()))?;
    let (delivery, _) = state.secret_deliveries.prepare_for_operation(
        now,
        &operation_id,
        &admin.user.id,
        &admin.session_id,
    )?;
    let draft = ActivationCodeDeliveryDraft {
        id: delivery.ticket.id.clone(),
        actor_id: admin.user.id.clone(),
        session_id: admin.session_id.clone(),
        claim_token_hash: delivery.claim_token_hash,
        expires_at: delivery.ticket.expires_at,
    };
    let receipt = state
        .application
        .issue_activation_codes_for_delivery(
            ActivationCodeBatchRequest {
                account_id: input.account_id,
                license_id: input.license_id,
                count: input.count,
                max_redemptions: input.max_redemptions,
                expiry: ActivationCodeExpiry::fixed(expires_at),
                channel: input.channel,
                note: input.note,
                operation_id: operation_id.clone(),
            },
            &context,
            draft,
            |id, plaintext| {
                state
                    .secret_deliveries
                    .seal(id, plaintext)
                    .map_err(|_| AdminAppError::SecretDelivery)
            },
        )
        .await?;
    let ticket = state.secret_deliveries.replay_operation_ticket(
        receipt.delivery_id,
        receipt.delivery_expires_at,
        &receipt.secret_key_id,
        &operation_id,
        &admin.user.id,
        &admin.session_id,
    )?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "delivery": ticket,
            "count": input.count,
            "acknowledgementRequired": true,
        })),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SecretDeliveryInput {
    claim_token: String,
}

async fn claim_secret_delivery(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(input): Json<SecretDeliveryInput>,
) -> Result<Json<Value>, AdminHttpError> {
    let admin = authenticate_csrf(&state, &headers).await?;
    let claimed = state
        .secret_deliveries
        .claim(
            &id,
            &input.claim_token,
            &admin.user.id,
            &admin.session_id,
            state.application.trusted_now().await?,
        )
        .await?;
    let permission = match claimed.purpose.as_str() {
        "activation_code_batch" => AdminPermission::CodeIssue,
        "team_invitation" => AdminPermission::TeamWrite,
        "admin_enrollment" => AdminPermission::IdentityManage,
        _ => return Err(AdminHttpError::NotFound),
    };
    admin.user.require(permission)?;
    Ok(Json(serde_json::from_slice(&claimed.plaintext)?))
}

async fn acknowledge_secret_delivery(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(input): Json<SecretDeliveryInput>,
) -> Result<StatusCode, AdminHttpError> {
    let admin = authenticate_csrf(&state, &headers).await?;
    let now = state.application.trusted_now().await?;
    let purpose = state
        .secret_deliveries
        .acknowledgement_purpose(
            &id,
            &input.claim_token,
            &admin.user.id,
            &admin.session_id,
            now,
        )
        .await?;
    let permission = match purpose.as_str() {
        "activation_code_batch" => AdminPermission::CodeIssue,
        "team_invitation" => AdminPermission::TeamWrite,
        "admin_enrollment" => AdminPermission::IdentityManage,
        _ => return Err(AdminHttpError::NotFound),
    };
    admin.user.require(permission)?;
    state
        .secret_deliveries
        .acknowledge(
            &id,
            &input.claim_token,
            &admin.user.id,
            &admin.session_id,
            now,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CodeActionInput {
    reason: String,
    max_redemptions: Option<u32>,
    expires_at: Option<String>,
}

async fn mutate_activation_code(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    AxumPath((reference, action)): AxumPath<(String, String)>,
    Json(input): Json<CodeActionInput>,
) -> Result<Json<AdminActivationCode>, AdminHttpError> {
    let admin = authenticate_mutation(&state, &headers).await?;
    admin.user.require(AdminPermission::CodeWrite)?;
    if action == "restore" {
        admin.require_step_up(state.application.trusted_now().await?)?;
    }
    let expected = required_if_match(&headers)?;
    let now = state.application.trusted_now().await?;
    let expires_at = input
        .expires_at
        .as_deref()
        .map(|value| parse_optional_expiry_time(value, now))
        .transpose()
        .map_err(|error| AdminHttpError::Invalid(error.to_string()))?
        .flatten();
    let context = mutation_context(&state, &admin, &headers, input.reason)?;
    let value = state
        .application
        .mutate_activation_code(
            &reference,
            Some(expected),
            &context,
            &action,
            input.max_redemptions,
            expires_at,
        )
        .await?;
    Ok(Json(AdminActivationCode::new(
        value,
        incremented_row_version(expected)?,
    )))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeviceQuery {
    account: Option<String>,
    cursor: Option<String>,
    #[serde(default = "default_admin_page_size")]
    page_size: u32,
    query: Option<String>,
}

async fn devices(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Query(request): Query<DeviceQuery>,
) -> Result<Json<AdminPage<AdminDevice>>, AdminHttpError> {
    authenticate(&state, &headers)
        .await?
        .user
        .require(AdminPermission::DeviceRead)?;
    let page = admin_page_request(&request.cursor, request.page_size, &request.query);
    Ok(Json(
        state
            .application
            .devices(request.account.as_deref(), page)
            .await?
            .into(),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SetDeviceStateInput {
    state: DeviceState,
    reason: String,
}

async fn set_device_state(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(input): Json<SetDeviceStateInput>,
) -> Result<Json<AdminDevice>, AdminHttpError> {
    let admin = authenticate_mutation(&state, &headers).await?;
    let permission = if matches!(input.state, DeviceState::Revoked | DeviceState::Suspicious) {
        admin.require_step_up(state.application.trusted_now().await?)?;
        AdminPermission::DeviceSecurity
    } else {
        AdminPermission::DeviceRemove
    };
    admin.user.require(permission)?;
    let expected = required_if_match(&headers)?;
    let context = mutation_context(&state, &admin, &headers, input.reason)?;
    let value = state
        .application
        .set_device_state(&id, input.state, Some(expected), &context)
        .await?;
    Ok(Json(AdminDevice::new(
        value,
        incremented_row_version(expected)?,
    )))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuditQuery {
    account: Option<String>,
    #[serde(default = "default_audit_limit")]
    limit: i64,
}

async fn audit_events(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Query(request): Query<AuditQuery>,
) -> Result<Json<Vec<AdminAuditEvent>>, AdminHttpError> {
    authenticate(&state, &headers)
        .await?
        .user
        .require(AdminPermission::AuditRead)?;
    if !(1..=500).contains(&request.limit) {
        return Err(AdminHttpError::Invalid(
            "limit must be between 1 and 500".to_owned(),
        ));
    }
    Ok(Json(
        state
            .application
            .repository()
            .audit_events(request.account.as_deref(), request.limit)
            .await
            .map_err(AdminAppError::from)?
            .into_iter()
            .map(AdminAuditEvent::from)
            .collect(),
    ))
}

async fn create_bulk_preview(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Json(input): Json<CreatePreview>,
) -> Result<(StatusCode, Json<Value>), AdminHttpError> {
    let admin = authenticate_csrf(&state, &headers).await?;
    admin.user.require(AdminPermission::JobManage)?;
    require_bulk_permission(&admin, &input)?;
    let preview = state.jobs.create_preview(&admin.user.id, input).await?;
    Ok((StatusCode::CREATED, Json(serde_json::to_value(preview)?)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateBulkJobInput {
    preview_id: String,
    reason: String,
}

async fn create_bulk_job(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Json(input): Json<CreateBulkJobInput>,
) -> Result<(StatusCode, Json<Value>), AdminHttpError> {
    let admin = authenticate_mutation(&state, &headers).await?;
    admin.user.require(AdminPermission::JobManage)?;
    admin.require_step_up(state.application.trusted_now().await?)?;
    let job = state
        .jobs
        .create_job(
            &admin.user.id,
            &admin.session_id,
            &input.preview_id,
            &input.reason,
            &required_idempotency_key(&headers)?,
        )
        .await?;
    Ok((StatusCode::ACCEPTED, Json(serde_json::to_value(job)?)))
}

async fn bulk_jobs(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Query(page): Query<PageRequest>,
) -> Result<Json<Value>, AdminHttpError> {
    authenticate(&state, &headers)
        .await?
        .user
        .require(AdminPermission::JobManage)?;
    Ok(Json(serde_json::to_value(state.jobs.jobs(page).await?)?))
}

async fn bulk_job(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, AdminHttpError> {
    authenticate(&state, &headers)
        .await?
        .user
        .require(AdminPermission::JobManage)?;
    Ok(Json(serde_json::to_value(state.jobs.job(&id).await?)?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CancelBulkJobInput {
    reason: String,
}

async fn cancel_bulk_job(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(input): Json<CancelBulkJobInput>,
) -> Result<Json<Value>, AdminHttpError> {
    let admin = authenticate_mutation(&state, &headers).await?;
    admin.user.require(AdminPermission::JobManage)?;
    let context = mutation_context(&state, &admin, &headers, input.reason)?;
    Ok(Json(serde_json::to_value(
        state.jobs.cancel(&id, &context).await?,
    )?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ActiveOnlyQuery {
    #[serde(default)]
    active_only: bool,
}

async fn billing_offers(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Query(query): Query<ActiveOnlyQuery>,
) -> Result<Json<Value>, AdminHttpError> {
    authenticate(&state, &headers)
        .await?
        .user
        .require(AdminPermission::BillingRead)?;
    Ok(Json(serde_json::to_value(
        state
            .application
            .repository()
            .commercial_offers(query.active_only)
            .await
            .map_err(AdminAppError::from)?,
    )?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateOfferInput {
    id: String,
    plan: Plan,
    duration_days: u32,
    currency: String,
    #[serde(with = "rust_decimal::serde::str")]
    base_amount: Decimal,
    #[serde(default, with = "rust_decimal::serde::str_option")]
    seat_amount: Option<Decimal>,
    name_en: String,
    name_zh: String,
    #[serde(default = "default_true")]
    active: bool,
    reason: String,
}

async fn create_billing_offer(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Json(input): Json<CreateOfferInput>,
) -> Result<(StatusCode, Json<Value>), AdminHttpError> {
    let admin = authenticate_mutation(&state, &headers).await?;
    admin.user.require(AdminPermission::BillingWrite)?;
    let context = mutation_context(&state, &admin, &headers, input.reason)?;
    let operation = admin_operation::prepare(
        "billing.offer.create",
        &json!({
            "offerId": input.id,
            "plan": input.plan,
            "durationDays": input.duration_days,
            "currency": input.currency,
            "baseAmount": input.base_amount,
            "seatAmount": input.seat_amount,
            "nameEn": input.name_en,
            "nameZh": input.name_zh,
            "active": input.active,
        }),
        &context,
    )?;
    if let Some(operation) = operation.as_ref()
        && let Some(offer) = admin_operation::replay::<CommercialOffer>(
            &state.application.repository().pool,
            operation,
        )
        .await?
    {
        return Ok((StatusCode::CREATED, Json(serde_json::to_value(offer)?)));
    }
    let now = state.application.trusted_now().await?;
    let offer = CommercialOffer {
        id: input.id,
        row_version: 1,
        plan: input.plan,
        plan_revision: crate::plan_catalog::CURRENT_PLAN_REVISION,
        duration_days: input.duration_days,
        currency: input.currency,
        base_amount: input.base_amount,
        seat_amount: input.seat_amount,
        name_en: input.name_en,
        name_zh: input.name_zh,
        active: input.active,
        created_at: now,
        updated_at: now,
    };
    let offer = state
        .application
        .repository()
        .create_commercial_offer(&offer, &admin.user.id, &context.reason, operation.as_ref())
        .await?;
    Ok((StatusCode::CREATED, Json(serde_json::to_value(offer)?)))
}

async fn payment_methods(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Query(query): Query<ActiveOnlyQuery>,
) -> Result<Json<Value>, AdminHttpError> {
    authenticate(&state, &headers)
        .await?
        .user
        .require(AdminPermission::BillingRead)?;
    Ok(Json(serde_json::to_value(
        state
            .application
            .repository()
            .manual_payment_methods(query.active_only)
            .await
            .map_err(AdminAppError::from)?,
    )?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreatePaymentMethodInput {
    id: String,
    name_en: String,
    name_zh: String,
    instructions_en: String,
    instructions_zh: String,
    settlement_asset: String,
    destination_hint: String,
    #[serde(default = "default_true")]
    active: bool,
    reason: String,
}

async fn create_payment_method(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Json(input): Json<CreatePaymentMethodInput>,
) -> Result<(StatusCode, Json<Value>), AdminHttpError> {
    let admin = authenticate_mutation(&state, &headers).await?;
    admin.user.require(AdminPermission::BillingWrite)?;
    let context = mutation_context(&state, &admin, &headers, input.reason)?;
    let operation = admin_operation::prepare(
        "billing.payment_method.create",
        &json!({
            "paymentMethodId": input.id,
            "nameEn": input.name_en,
            "nameZh": input.name_zh,
            "instructionsEn": input.instructions_en,
            "instructionsZh": input.instructions_zh,
            "settlementAsset": input.settlement_asset,
            "destinationHint": input.destination_hint,
            "active": input.active,
        }),
        &context,
    )?;
    if let Some(operation) = operation.as_ref()
        && let Some(method) = admin_operation::replay::<ManualPaymentMethod>(
            &state.application.repository().pool,
            operation,
        )
        .await?
    {
        return Ok((StatusCode::CREATED, Json(serde_json::to_value(method)?)));
    }
    let now = state.application.trusted_now().await?;
    let method = ManualPaymentMethod {
        id: input.id,
        row_version: 1,
        name_en: input.name_en,
        name_zh: input.name_zh,
        instructions_en: input.instructions_en,
        instructions_zh: input.instructions_zh,
        settlement_asset: input.settlement_asset,
        destination_hint: input.destination_hint,
        active: input.active,
        created_at: now,
        updated_at: now,
    };
    let method = state
        .application
        .repository()
        .create_manual_payment_method(&method, &admin.user.id, &context.reason, operation.as_ref())
        .await?;
    Ok((StatusCode::CREATED, Json(serde_json::to_value(method)?)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InvoiceQuery {
    account_id: Option<String>,
}

async fn invoices(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Query(query): Query<InvoiceQuery>,
) -> Result<Json<Value>, AdminHttpError> {
    authenticate(&state, &headers)
        .await?
        .user
        .require(AdminPermission::BillingRead)?;
    Ok(Json(serde_json::to_value(
        state
            .application
            .repository()
            .billing_invoices(query.account_id.as_deref())
            .await
            .map_err(AdminAppError::from)?,
    )?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateInvoiceInput {
    id: String,
    account_id: String,
    license_id: String,
    offer_id: String,
    seats: u32,
    due_at: String,
    reason: String,
}

fn create_invoice_error(error: AdminAppError) -> AdminHttpError {
    match error {
        AdminAppError::Validation(message) => AdminHttpError::InvalidField {
            code: "admin_invoice_seats_invalid",
            field: "seats",
            message,
        },
        error => AdminHttpError::Application(error),
    }
}

async fn create_invoice(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Json(input): Json<CreateInvoiceInput>,
) -> Result<(StatusCode, Json<Value>), AdminHttpError> {
    let admin = authenticate_mutation(&state, &headers).await?;
    admin.user.require(AdminPermission::BillingWrite)?;
    let context = mutation_context(&state, &admin, &headers, input.reason)?;
    let operation = admin_operation::prepare(
        "billing.invoice.create",
        &json!({
            "invoiceId": input.id,
            "accountId": input.account_id,
            "licenseId": input.license_id,
            "offerId": input.offer_id,
            "seats": input.seats,
            "dueAt": input.due_at,
        }),
        &context,
    )?;
    if let Some(operation) = operation.as_ref()
        && let Some(invoice) = admin_operation::replay::<crate::billing::BillingInvoice>(
            &state.application.repository().pool,
            operation,
        )
        .await?
    {
        return Ok((StatusCode::CREATED, Json(serde_json::to_value(invoice)?)));
    }
    let now = state.application.trusted_now().await?;
    let due_at = parse_optional_expiry_time(&input.due_at, now)
        .map_err(|error| AdminHttpError::Invalid(error.to_string()))?
        .ok_or_else(|| AdminHttpError::Invalid("invoice due time is required".to_owned()))?;
    let invoice = state
        .application
        .repository()
        .create_billing_invoice(
            NewInvoice {
                id: &input.id,
                account_id: &input.account_id,
                license_id: &input.license_id,
                offer_id: &input.offer_id,
                seats: input.seats,
                due_at,
            },
            &admin.user.id,
            &context.reason,
            now,
            operation.as_ref(),
        )
        .await
        .map_err(create_invoice_error)?;
    Ok((StatusCode::CREATED, Json(serde_json::to_value(invoice)?)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PaymentClaimQuery {
    status: Option<PaymentClaimStatus>,
}

async fn payment_claims(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Query(query): Query<PaymentClaimQuery>,
) -> Result<Json<Value>, AdminHttpError> {
    authenticate(&state, &headers)
        .await?
        .user
        .require(AdminPermission::BillingRead)?;
    Ok(Json(serde_json::to_value(
        state
            .application
            .repository()
            .manual_payment_claims(query.status)
            .await
            .map_err(AdminAppError::from)?,
    )?))
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReviewDecisionInput {
    Approve,
    Reject,
    RequestInformation,
}

impl From<ReviewDecisionInput> for PaymentReviewDecision {
    fn from(value: ReviewDecisionInput) -> Self {
        match value {
            ReviewDecisionInput::Approve => Self::Approve,
            ReviewDecisionInput::Reject => Self::Reject,
            ReviewDecisionInput::RequestInformation => Self::RequestInformation,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReviewPaymentInput {
    decision: ReviewDecisionInput,
    #[serde(default)]
    allow_amount_override: bool,
    reason: String,
}

async fn review_payment_claim(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(input): Json<ReviewPaymentInput>,
) -> Result<Response<Body>, AdminHttpError> {
    let admin = authenticate_mutation(&state, &headers).await?;
    admin.user.require(AdminPermission::BillingReview)?;
    let decision: PaymentReviewDecision = input.decision.into();
    validate_payment_review_override(decision, input.allow_amount_override).map_err(|_| {
        AdminHttpError::InvalidField {
            code: "admin_payment_override_invalid",
            field: "allowAmountOverride",
            message: "amount override is valid only when approving a payment claim".to_owned(),
        }
    })?;
    if input.allow_amount_override {
        admin.user.require(AdminPermission::BillingOverride)?;
        admin.require_step_up(state.application.trusted_now().await?)?;
    }
    let operation_id = required_idempotency_key(&headers)?;
    let expected_row_version = required_if_match(&headers)?;
    if expected_row_version <= 0 {
        return Err(AdminHttpError::Invalid(
            "If-Match must contain a positive row version".to_owned(),
        ));
    }
    let expected_row_version =
        u64::try_from(expected_row_version).map_err(|_| AdminHttpError::Database)?;
    let now = state.application.trusted_now().await?;
    let claim = state
        .application
        .repository()
        .review_manual_payment_claim(
            &id,
            expected_row_version,
            decision,
            &admin.user.id,
            &input.reason,
            &operation_id,
            input.allow_amount_override,
            now,
        )
        .await?;
    let row_version = i64::try_from(claim.row_version).map_err(|_| AdminHttpError::Database)?;
    versioned_response(claim, row_version)
}

async fn payment_evidence(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<AdminItems<AdminPaymentEvidence>>, AdminHttpError> {
    authenticate(&state, &headers)
        .await?
        .user
        .require(AdminPermission::BillingRead)?;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM manual_payment_claims WHERE id = $1)")
            .bind(&id)
            .fetch_one(&state.application.repository().pool)
            .await
            .map_err(|_| AdminHttpError::Database)?;
    if !exists {
        return Err(AdminHttpError::NotFound);
    }
    let rows = sqlx::query(
        "SELECT evidence.id, evidence.object_id, evidence.original_name, evidence.media_type,
                evidence.byte_length, evidence.sha256, evidence.scan_status,
                evidence.created_at, evidence.scanned_at
         FROM payment_evidence_attachments AS evidence
         WHERE evidence.claim_id = $1 ORDER BY evidence.created_at, evidence.id",
    )
    .bind(id)
    .fetch_all(&state.application.repository().pool)
    .await
    .map_err(|_| AdminHttpError::Database)?;
    let items = rows
        .into_iter()
        .map(|row| {
            Ok(AdminPaymentEvidence {
                id: row.try_get("id").map_err(|_| AdminHttpError::Database)?,
                object_id: row
                    .try_get("object_id")
                    .map_err(|_| AdminHttpError::Database)?,
                original_name: row
                    .try_get("original_name")
                    .map_err(|_| AdminHttpError::Database)?,
                media_type: row
                    .try_get("media_type")
                    .map_err(|_| AdminHttpError::Database)?,
                byte_length: row
                    .try_get("byte_length")
                    .map_err(|_| AdminHttpError::Database)?,
                sha256: row
                    .try_get("sha256")
                    .map_err(|_| AdminHttpError::Database)?,
                scan_status: row
                    .try_get("scan_status")
                    .map_err(|_| AdminHttpError::Database)?,
                created_at: row
                    .try_get("created_at")
                    .map_err(|_| AdminHttpError::Database)?,
                scanned_at: row
                    .try_get("scanned_at")
                    .map_err(|_| AdminHttpError::Database)?,
            })
        })
        .collect::<Result<Vec<_>, AdminHttpError>>()?;
    Ok(Json(AdminItems { items }))
}

async fn upload_payment_evidence(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    AxumPath(claim_id): AxumPath<String>,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<Value>), AdminHttpError> {
    let admin = authenticate_mutation(&state, &headers).await?;
    admin.user.require(AdminPermission::BillingWrite)?;
    let reason = header_text(&headers, HeaderName::from_static("x-admin-reason"))
        .ok_or_else(|| AdminHttpError::Invalid("X-Admin-Reason header is required".to_owned()))?;
    let context = mutation_context(&state, &admin, &headers, reason.to_owned())?;
    let mut upload = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| AdminHttpError::Invalid("invalid multipart upload".to_owned()))?
    {
        if field.name() != Some("file") || upload.is_some() {
            return Err(AdminHttpError::Invalid(
                "exactly one file field is required".to_owned(),
            ));
        }
        let name = field
            .file_name()
            .filter(|name| !name.is_empty() && name.chars().count() <= 255)
            .ok_or_else(|| AdminHttpError::Invalid("a valid filename is required".to_owned()))?
            .to_owned();
        let bytes = field
            .bytes()
            .await
            .map_err(|_| AdminHttpError::Invalid("file upload failed".to_owned()))?;
        upload = Some((name, bytes));
    }
    let (name, bytes) = upload
        .ok_or_else(|| AdminHttpError::Invalid("a payment evidence file is required".to_owned()))?;
    if bytes.is_empty() || bytes.len() > 8 * 1024 * 1024 {
        return Err(AdminHttpError::Invalid(
            "payment evidence must contain 1 to 8388608 bytes".to_owned(),
        ));
    }
    let media_type = evidence_media_type(&bytes)
        .ok_or_else(|| AdminHttpError::Invalid("only PNG, JPEG and PDF are accepted".to_owned()))?;
    let sha256 = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let operation = admin_operation::prepare(
        "billing.payment_evidence.upload",
        &json!({
            "claimId": claim_id,
            "originalName": name,
            "mediaType": media_type,
            "byteLength": bytes.len(),
            "sha256": sha256,
        }),
        &context,
    )?
    .ok_or_else(|| AdminHttpError::Invalid("Idempotency-Key header is required".to_owned()))?;
    if let Some(response) =
        admin_operation::replay::<Value>(&state.application.repository().pool, &operation).await?
    {
        return payment_evidence_upload_response(response);
    }
    if let Some(response) =
        load_payment_evidence_by_digest(&state.application.repository().pool, &claim_id, &sha256)
            .await?
    {
        let mut tx = state
            .application
            .repository()
            .pool
            .begin()
            .await
            .map_err(|_| AdminHttpError::Database)?;
        let response = match admin_operation::claim_prepared::<Value>(&mut tx, &operation).await? {
            Some(replayed) => replayed,
            None => {
                admin_operation::finish_prepared(&mut tx, &response, &operation).await?;
                response
            }
        };
        tx.commit().await.map_err(|_| AdminHttpError::Database)?;
        return payment_evidence_upload_response(response);
    }
    let claim_status: Option<String> =
        sqlx::query_scalar("SELECT status FROM manual_payment_claims WHERE id = $1")
            .bind(&claim_id)
            .fetch_optional(&state.application.repository().pool)
            .await
            .map_err(|_| AdminHttpError::Database)?;
    let claim_status = claim_status.ok_or(AdminHttpError::NotFound)?;
    if !payment_claim_accepts_evidence(&claim_status) {
        return Err(AdminHttpError::Conflict(
            "payment evidence cannot be added after the claim is closed".to_owned(),
        ));
    }
    let now = state.application.trusted_now().await?;
    let object = state
        .storage
        .put(
            "payment_evidence",
            media_type,
            Some(&name),
            &bytes,
            &admin.user.id,
            StoredObjectStatus::Quarantined,
        )
        .await?;
    let scan = state.evidence_scanner.scan(&bytes).await;
    let (scan_status, object_status) = match &scan {
        Ok(()) => ("clean", StoredObjectStatus::Ready),
        Err(ObjectStorageError::MalwareDetected) => ("rejected", StoredObjectStatus::Rejected),
        Err(_) => ("failed", StoredObjectStatus::Quarantined),
    };
    state.storage.set_status(&object.id, object_status).await?;
    let evidence_id = crate::crypto::random_id("evidence");
    let persisted: Result<Value, AdminHttpError> = async {
        let mut tx = state
            .application
            .repository()
            .pool
            .begin()
            .await
            .map_err(|_| AdminHttpError::Database)?;
        if let Some(response) =
            admin_operation::claim_prepared::<Value>(&mut tx, &operation).await?
        {
            tx.commit().await.map_err(|_| AdminHttpError::Database)?;
            return Ok(response);
        }
        if let Some(response) =
            load_payment_evidence_by_digest_tx(&mut tx, &claim_id, &sha256).await?
        {
            admin_operation::finish_prepared(&mut tx, &response, &operation).await?;
            tx.commit().await.map_err(|_| AdminHttpError::Database)?;
            return Ok(response);
        }
        let claim_status: Option<String> = sqlx::query_scalar(
            "SELECT status FROM manual_payment_claims WHERE id = $1 FOR UPDATE",
        )
        .bind(&claim_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| AdminHttpError::Database)?;
        let claim_status = claim_status.ok_or(AdminHttpError::NotFound)?;
        if !payment_claim_accepts_evidence(&claim_status) {
            return Err(AdminHttpError::Conflict(
                "payment evidence cannot be added after the claim is closed".to_owned(),
            ));
        }
        let attachment_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM payment_evidence_attachments WHERE claim_id = $1",
        )
        .bind(&claim_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| AdminHttpError::Database)?;
        if attachment_count >= MAX_PAYMENT_EVIDENCE_ATTACHMENTS {
            return Err(AdminHttpError::Conflict(format!(
                "a payment claim cannot contain more than {MAX_PAYMENT_EVIDENCE_ATTACHMENTS} evidence files"
            )));
        }
        sqlx::query(
            "INSERT INTO payment_evidence_attachments
             (id, claim_id, object_id, original_name, media_type, byte_length, sha256,
              scan_status, created_at, scanned_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)",
        )
        .bind(&evidence_id)
        .bind(&claim_id)
        .bind(&object.id)
        .bind(&name)
        .bind(media_type)
        .bind(object.byte_length)
        .bind(&object.sha256)
        .bind(scan_status)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| AdminHttpError::Database)?;
        insert_control_plane_audit(
            &mut tx,
            &context,
            "payment_evidence_uploaded",
            "payment_claim",
            &claim_id,
            None,
            now,
        )
        .await?;
        let mut response_object = object.clone();
        response_object.status = object_status;
        let response = json!({
            "id": evidence_id,
            "claimId": claim_id,
            "object": response_object,
            "scanStatus": scan_status,
        });
        admin_operation::finish_prepared(&mut tx, &response, &operation).await?;
        tx.commit().await.map_err(|_| AdminHttpError::Database)?;
        Ok(response)
    }
    .await;
    let response = match persisted {
        Ok(response) => response,
        Err(error) => {
            if let Err(cleanup_error) = state.storage.delete(&object.id).await {
                tracing::error!(object_id = object.id, %cleanup_error, "orphaned payment evidence cleanup failed");
            }
            return Err(error);
        }
    };
    if response
        .pointer("/object/id")
        .and_then(Value::as_str)
        .is_some_and(|id| id != object.id)
        && let Err(cleanup_error) = state.storage.delete(&object.id).await
    {
        tracing::error!(object_id = object.id, %cleanup_error, "orphaned payment evidence cleanup failed");
    }
    payment_evidence_upload_response(response)
}

fn payment_evidence_upload_response(
    response: Value,
) -> Result<(StatusCode, Json<Value>), AdminHttpError> {
    match response.get("scanStatus").and_then(Value::as_str) {
        Some("clean") => Ok((StatusCode::CREATED, Json(response))),
        Some("quarantined" | "failed") => Ok((StatusCode::ACCEPTED, Json(response))),
        Some("rejected") => Err(ObjectStorageError::MalwareDetected.into()),
        _ => Err(AdminHttpError::Database),
    }
}

fn payment_claim_accepts_evidence(status: &str) -> bool {
    matches!(status, "submitted" | "under_review" | "needs_information")
}

async fn load_payment_evidence_by_digest(
    pool: &sqlx::PgPool,
    claim_id: &str,
    sha256: &str,
) -> Result<Option<Value>, AdminHttpError> {
    payment_evidence_response_query(claim_id, sha256)
        .fetch_optional(pool)
        .await
        .map_err(|_| AdminHttpError::Database)?
        .map(|row| {
            row.try_get("response")
                .map_err(|_| AdminHttpError::Database)
        })
        .transpose()
}

async fn load_payment_evidence_by_digest_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    claim_id: &str,
    sha256: &str,
) -> Result<Option<Value>, AdminHttpError> {
    payment_evidence_response_query(claim_id, sha256)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| AdminHttpError::Database)?
        .map(|row| {
            row.try_get("response")
                .map_err(|_| AdminHttpError::Database)
        })
        .transpose()
}

fn payment_evidence_response_query<'a>(
    claim_id: &'a str,
    sha256: &'a str,
) -> sqlx::query::Query<'a, sqlx::Postgres, sqlx::postgres::PgArguments> {
    sqlx::query(
        "SELECT jsonb_build_object(
             'id', evidence.id,
             'claimId', evidence.claim_id,
             'object', jsonb_build_object(
                 'id', objects.id,
                 'namespace', objects.namespace,
                 'backend', objects.backend,
                 'mediaType', objects.media_type,
                 'originalName', objects.original_name,
                 'byteLength', objects.byte_length,
                 'sha256', objects.sha256,
                 'status', objects.status,
                 'createdBy', objects.created_by,
                 'createdAt', objects.created_at
             ),
             'scanStatus', evidence.scan_status
         ) AS response
         FROM payment_evidence_attachments AS evidence
         JOIN stored_objects AS objects ON objects.id = evidence.object_id
         WHERE evidence.claim_id = $1 AND evidence.sha256 = $2",
    )
    .bind(claim_id)
    .bind(sha256)
}

fn team_page_request(request: PageRequest) -> Result<(Option<String>, u32), AdminHttpError> {
    let request = request.validate()?;
    if request.query.is_some()
        || request.cursor.as_ref().is_some_and(|cursor| {
            cursor.len() > 128
                || !cursor
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        })
    {
        return Err(AdminHttpError::Invalid(
            "Team page cursor is invalid and search is not supported".to_owned(),
        ));
    }
    Ok((request.cursor, request.page_size))
}

async fn team_workspaces(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    Query(request): Query<PageRequest>,
) -> Result<Json<AdminPage<AdminTeamWorkspace>>, AdminHttpError> {
    authenticate(&state, &headers)
        .await?
        .user
        .require(AdminPermission::TeamRead)?;
    let (cursor, page_size) = team_page_request(request)?;
    let now = state.application.trusted_now().await?;
    let rows = sqlx::query(
        "SELECT accounts.id AS account_id, licenses.id AS license_id,
                licenses.purchased_seats,
                count(members.id)::bigint AS member_count,
                count(members.id) FILTER (WHERE members.status = 'active')::bigint AS active_members,
                count(members.id) FILTER (WHERE members.status IN ('active', 'suspended')
                    OR (members.status = 'invited' AND EXISTS (
                        SELECT 1 FROM team_invitations AS invitations
                        WHERE invitations.member_id = members.id
                          AND invitations.accepted_at IS NULL
                          AND invitations.revoked_at IS NULL
                          AND invitations.expires_at > $2
                    )))::bigint AS occupied_members
         FROM accounts
         JOIN licenses ON licenses.account_id = accounts.id AND licenses.plan = 'team'
         LEFT JOIN workspace_members AS members ON members.account_id = accounts.id
         WHERE ($1::TEXT IS NULL OR licenses.id > $1)
         GROUP BY accounts.id, licenses.id, licenses.purchased_seats
         ORDER BY licenses.id LIMIT $3",
    )
    .bind(cursor.as_deref())
    .bind(now)
    .bind(i64::from(page_size.saturating_add(1)))
    .fetch_all(&state.application.repository().pool)
    .await
    .map_err(|_| AdminHttpError::Database)?;
    let has_more = rows.len() > page_size as usize;
    let items = rows
        .into_iter()
        .take(page_size as usize)
        .map(|row| {
            Ok(AdminTeamWorkspace {
                account_id: row
                    .try_get("account_id")
                    .map_err(|_| AdminHttpError::Database)?,
                license_id: row
                    .try_get("license_id")
                    .map_err(|_| AdminHttpError::Database)?,
                purchased_seats: row
                    .try_get("purchased_seats")
                    .map_err(|_| AdminHttpError::Database)?,
                member_count: row
                    .try_get("member_count")
                    .map_err(|_| AdminHttpError::Database)?,
                active_members: row
                    .try_get("active_members")
                    .map_err(|_| AdminHttpError::Database)?,
                occupied_members: row
                    .try_get("occupied_members")
                    .map_err(|_| AdminHttpError::Database)?,
            })
        })
        .collect::<Result<Vec<_>, AdminHttpError>>()?;
    let next_cursor = items
        .last()
        .filter(|_| has_more)
        .map(|item| item.license_id.clone());
    Ok(Json(AdminPage { items, next_cursor }))
}

async fn team_members(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    AxumPath(account_id): AxumPath<String>,
    Query(request): Query<PageRequest>,
) -> Result<Json<AdminPage<AdminTeamMember>>, AdminHttpError> {
    authenticate(&state, &headers)
        .await?
        .user
        .require(AdminPermission::TeamRead)?;
    let (cursor, page_size) = team_page_request(request)?;
    let rows = sqlx::query(
        "SELECT id, email, display_name, role, status, row_version, created_at, updated_at,
                (role = 'owner'
                 AND id = 'member_owner_' || md5(account_id)
                 AND email = 'owner+' || md5(account_id) || '@local.invalid'
                 AND display_name = account_id) AS profile_pending
         FROM workspace_members WHERE account_id = $1 AND ($2::TEXT IS NULL OR id > $2)
         ORDER BY id LIMIT $3",
    )
    .bind(&account_id)
    .bind(cursor.as_deref())
    .bind(i64::from(page_size.saturating_add(1)))
    .fetch_all(&state.application.repository().pool)
    .await
    .map_err(|_| AdminHttpError::Database)?;
    let has_more = rows.len() > page_size as usize;
    let items = rows
        .into_iter()
        .take(page_size as usize)
        .map(|row| {
            Ok(AdminTeamMember {
                id: row.try_get("id").map_err(|_| AdminHttpError::Database)?,
                email: row.try_get("email").map_err(|_| AdminHttpError::Database)?,
                display_name: row
                    .try_get("display_name")
                    .map_err(|_| AdminHttpError::Database)?,
                role: parse_workspace_role(
                    &row.try_get::<String, _>("role")
                        .map_err(|_| AdminHttpError::Database)?,
                )?,
                status: parse_workspace_status(
                    &row.try_get::<String, _>("status")
                        .map_err(|_| AdminHttpError::Database)?,
                )?,
                row_version: row
                    .try_get("row_version")
                    .map_err(|_| AdminHttpError::Database)?,
                created_at: row
                    .try_get("created_at")
                    .map_err(|_| AdminHttpError::Database)?,
                updated_at: row
                    .try_get("updated_at")
                    .map_err(|_| AdminHttpError::Database)?,
                profile_pending: row
                    .try_get("profile_pending")
                    .map_err(|_| AdminHttpError::Database)?,
            })
        })
        .collect::<Result<Vec<_>, AdminHttpError>>()?;
    let next_cursor = items
        .last()
        .filter(|_| has_more)
        .map(|item| item.id.clone());
    Ok(Json(AdminPage { items, next_cursor }))
}

async fn team_invitations(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    AxumPath(account_id): AxumPath<String>,
    Query(request): Query<PageRequest>,
) -> Result<Json<AdminPage<AdminTeamInvitation>>, AdminHttpError> {
    authenticate(&state, &headers)
        .await?
        .user
        .require(AdminPermission::TeamRead)?;
    let (cursor, page_size) = team_page_request(request)?;
    let rows = sqlx::query(
        "SELECT invitations.id, invitations.member_id, members.email, members.display_name,
                members.role, invitations.expires_at, invitations.accepted_at,
                invitations.revoked_at, invitations.created_at
         FROM team_invitations AS invitations
         JOIN workspace_members AS members ON members.id = invitations.member_id
         WHERE invitations.account_id = $1 AND ($2::TEXT IS NULL OR invitations.id > $2)
         ORDER BY invitations.id LIMIT $3",
    )
    .bind(&account_id)
    .bind(cursor.as_deref())
    .bind(i64::from(page_size.saturating_add(1)))
    .fetch_all(&state.application.repository().pool)
    .await
    .map_err(|_| AdminHttpError::Database)?;
    let has_more = rows.len() > page_size as usize;
    let items = rows
        .into_iter()
        .take(page_size as usize)
        .map(|row| {
            Ok(AdminTeamInvitation {
                id: row.try_get("id").map_err(|_| AdminHttpError::Database)?,
                member_id: row
                    .try_get("member_id")
                    .map_err(|_| AdminHttpError::Database)?,
                email: row.try_get("email").map_err(|_| AdminHttpError::Database)?,
                display_name: row
                    .try_get("display_name")
                    .map_err(|_| AdminHttpError::Database)?,
                role: parse_workspace_role(
                    &row.try_get::<String, _>("role")
                        .map_err(|_| AdminHttpError::Database)?,
                )?,
                expires_at: row
                    .try_get("expires_at")
                    .map_err(|_| AdminHttpError::Database)?,
                accepted_at: row
                    .try_get("accepted_at")
                    .map_err(|_| AdminHttpError::Database)?,
                revoked_at: row
                    .try_get("revoked_at")
                    .map_err(|_| AdminHttpError::Database)?,
                created_at: row
                    .try_get("created_at")
                    .map_err(|_| AdminHttpError::Database)?,
            })
        })
        .collect::<Result<Vec<_>, AdminHttpError>>()?;
    let next_cursor = items
        .last()
        .filter(|_| has_more)
        .map(|item| item.id.clone());
    Ok(Json(AdminPage { items, next_cursor }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateTeamInvitationInput {
    email: String,
    display_name: String,
    role: WorkspaceRole,
    reason: String,
}

const TEAM_INVITATION_OPERATION: &str = "admin.team.invitation.create";
const TEAM_MEMBER_UPDATE_OPERATION: &str = "admin.team.member.update";
const TEAM_OWNER_PROFILE_OPERATION: &str = "admin.team.owner-profile.complete";
const TEAM_OWNERSHIP_TRANSFER_OPERATION: &str = "admin.team.ownership.transfer";
const TEAM_INVITATION_REVOKE_OPERATION: &str = "admin.team.invitation.revoke";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TeamInvitationOperationResponse {
    invitation: Value,
    delivery_id: String,
    delivery_expires_at: i64,
    secret_key_id: String,
}

async fn create_team_invitation(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    AxumPath(account_id): AxumPath<String>,
    Json(input): Json<CreateTeamInvitationInput>,
) -> Result<(StatusCode, Json<Value>), AdminHttpError> {
    let admin = authenticate_mutation(&state, &headers).await?;
    admin.user.require(AdminPermission::TeamWrite)?;
    if input.role == WorkspaceRole::Owner {
        admin.require_step_up(state.application.trusted_now().await?)?;
        return Err(AdminHttpError::Invalid(
            "workspace ownership cannot be granted by invitation".to_owned(),
        ));
    }
    let context = mutation_context(&state, &admin, &headers, input.reason)?;
    let operation_id = admin_operation::operation_id(&context)?;
    let email = normalize_admin_email(&input.email).map_err(|_| AdminHttpError::InvalidField {
        code: "admin_team_email_invalid",
        field: "email",
        message: "email address is invalid".to_owned(),
    })?;
    let display_name =
        bounded_admin_text(&input.display_name, 160, "display name").map_err(|_| {
            AdminHttpError::InvalidField {
                code: "admin_team_display_name_invalid",
                field: "displayName",
                message: "display name must contain 1 to 160 characters".to_owned(),
            }
        })?;
    let request_hash = admin_operation::request_hash(&json!({
        "accountId": account_id,
        "email": email,
        "displayName": display_name,
        "role": input.role,
    }))?;
    let now = state.application.trusted_now().await?;
    let mut tx = state
        .application
        .repository()
        .pool
        .begin()
        .await
        .map_err(|_| AdminHttpError::Database)?;
    if let Some(response) = admin_operation::claim::<TeamInvitationOperationResponse>(
        &mut tx,
        TEAM_INVITATION_OPERATION,
        &request_hash,
        &context,
    )
    .await?
    {
        tx.commit().await.map_err(|_| AdminHttpError::Database)?;
        let ticket = state.secret_deliveries.replay_operation_ticket(
            response.delivery_id,
            response.delivery_expires_at,
            &response.secret_key_id,
            operation_id,
            &admin.user.id,
            &admin.session_id,
        )?;
        return Ok((
            StatusCode::CREATED,
            Json(json!({
                "invitation": response.invitation,
                "delivery": ticket,
                "acknowledgementRequired": true,
            })),
        ));
    }
    let seats: i32 = sqlx::query_scalar(
        "SELECT purchased_seats FROM licenses
         WHERE account_id = $1 AND plan = 'team' AND status = 'active'
         ORDER BY created_at DESC LIMIT 1 FOR UPDATE",
    )
    .bind(&account_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| AdminHttpError::Database)?
    .ok_or(AdminHttpError::NotFound)?;
    let existing_member: Option<(String, String, String, String)> = sqlx::query_as(
        "SELECT id, status, display_name, role FROM workspace_members
         WHERE account_id = $1 AND email = $2 FOR UPDATE",
    )
    .bind(&account_id)
    .bind(&email)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| AdminHttpError::Database)?;
    let existing_member_id = existing_member.as_ref().map(|(id, _, _, _)| id.as_str());
    let occupied_other: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM workspace_members AS members
         WHERE members.account_id = $1 AND (
           members.status IN ('active', 'suspended')
           OR (members.status = 'invited' AND EXISTS (
             SELECT 1 FROM team_invitations AS invitations
             WHERE invitations.member_id = members.id
               AND invitations.accepted_at IS NULL
               AND invitations.revoked_at IS NULL
               AND invitations.expires_at > $2
           ))
         ) AND ($3::TEXT IS NULL OR members.id <> $3)",
    )
    .bind(&account_id)
    .bind(now)
    .bind(existing_member_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| AdminHttpError::Database)?;
    if occupied_other >= i64::from(seats.max(3)) {
        return Err(AdminHttpError::Conflict(
            "workspace member limit has been reached".to_owned(),
        ));
    }
    let invitation_token = Zeroizing::new(crate::crypto::random_secret());
    let (delivery, secret_key_id) = state.secret_deliveries.prepare_for_operation(
        now,
        operation_id,
        &admin.user.id,
        &admin.session_id,
    )?;
    let payload = Zeroizing::new(serde_json::to_vec(&json!({
        "invitationToken": invitation_token.as_str(),
        "accountId": account_id,
        "email": email,
    }))?);
    let (key_id, nonce, ciphertext) = state
        .secret_deliveries
        .seal(&delivery.ticket.id, payload.as_ref())?;
    let mut device_enrollment = false;
    let member_id = if let Some((member_id, status, current_name, current_role)) = existing_member {
        if status == "active" {
            if current_name != display_name || current_role != workspace_role_name(input.role) {
                return Err(AdminHttpError::Conflict(
                    "active member details must be updated before issuing a device enrollment"
                        .to_owned(),
                ));
            }
            device_enrollment = true;
        } else if status == "suspended" {
            return Err(AdminHttpError::Conflict(
                "a suspended workspace member cannot receive an invitation".to_owned(),
            ));
        }
        sqlx::query(
            "UPDATE team_invitations SET revoked_at = COALESCE(revoked_at, $2)
             WHERE member_id = $1 AND revoked_at IS NULL",
        )
        .bind(&member_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| AdminHttpError::Database)?;
        if !device_enrollment {
            let affected = sqlx::query(
                "UPDATE workspace_members
                 SET display_name = $2, role = $3, status = 'invited',
                     row_version = row_version + 1, updated_at = $4
                 WHERE id = $1 AND status IN ('invited', 'removed')",
            )
            .bind(&member_id)
            .bind(&display_name)
            .bind(workspace_role_name(input.role))
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|_| AdminHttpError::Database)?
            .rows_affected();
            if affected != 1 {
                return Err(AdminHttpError::Conflict(
                    "workspace member state changed while creating the invitation".to_owned(),
                ));
            }
        }
        member_id
    } else {
        let member_id = crate::crypto::random_id("member");
        sqlx::query(
            "INSERT INTO workspace_members
             (id, account_id, email, display_name, role, status, row_version, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, 'invited', 1, $6, $6)",
        )
        .bind(&member_id)
        .bind(&account_id)
        .bind(&email)
        .bind(&display_name)
        .bind(workspace_role_name(input.role))
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| AdminHttpError::Database)?;
        member_id
    };
    let invitation_id = crate::crypto::random_id("team_invite");
    let invitation_expires_at = now.saturating_add(7 * 24 * 60 * 60);
    sqlx::query(
        "INSERT INTO team_invitations
         (id, account_id, member_id, token_hash, invited_by_member_id,
          invited_by_admin_user_id, expires_at, accepted_at, created_at)
         VALUES ($1, $2, $3, $4, NULL, $5, $6, $7, $8)",
    )
    .bind(&invitation_id)
    .bind(&account_id)
    .bind(&member_id)
    .bind(crate::crypto::sha256_hex(&invitation_token))
    .bind(&admin.user.id)
    .bind(invitation_expires_at)
    .bind(device_enrollment.then_some(now))
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|_| AdminHttpError::Database)?;
    sqlx::query(
        "INSERT INTO admin_secret_deliveries
         (id, actor_id, session_id, purpose, key_id, nonce, ciphertext,
          claim_token_hash, expires_at, created_at)
         VALUES ($1, $2, $3, 'team_invitation', $4, $5, $6, $7, $8, $9)",
    )
    .bind(&delivery.ticket.id)
    .bind(&admin.user.id)
    .bind(&admin.session_id)
    .bind(key_id)
    .bind(nonce)
    .bind(ciphertext)
    .bind(delivery.claim_token_hash)
    .bind(delivery.ticket.expires_at)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|_| AdminHttpError::Database)?;
    insert_control_plane_audit(
        &mut tx,
        &context,
        if device_enrollment {
            "team_member_device_enrollment_created"
        } else {
            "team_invitation_created"
        },
        "workspace_member",
        &member_id,
        Some(&account_id),
        now,
    )
    .await?;
    let invitation = json!({
        "id": invitation_id,
        "memberId": member_id,
        "email": email,
        "displayName": display_name,
        "role": input.role,
        "expiresAt": invitation_expires_at,
        "deviceEnrollment": device_enrollment,
    });
    admin_operation::finish(
        &mut tx,
        &TeamInvitationOperationResponse {
            invitation: invitation.clone(),
            delivery_id: delivery.ticket.id.clone(),
            delivery_expires_at: delivery.ticket.expires_at,
            secret_key_id,
        },
        &context,
    )
    .await?;
    tx.commit().await.map_err(|_| AdminHttpError::Database)?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "invitation": invitation,
            "delivery": delivery.ticket,
            "acknowledgementRequired": true,
        })),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdateTeamMemberInput {
    role: WorkspaceRole,
    status: WorkspaceMemberStatus,
    reason: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompleteTeamOwnerProfileInput {
    email: String,
    display_name: String,
    reason: String,
}

async fn complete_team_owner_profile(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    AxumPath((account_id, member_id)): AxumPath<(String, String)>,
    Json(input): Json<CompleteTeamOwnerProfileInput>,
) -> Result<Json<AdminTeamMember>, AdminHttpError> {
    let admin = authenticate_mutation(&state, &headers).await?;
    admin.user.require(AdminPermission::TeamWrite)?;
    let now = state.application.trusted_now().await?;
    admin.require_step_up(now)?;
    let expected = required_if_match(&headers)?;
    let context = mutation_context(&state, &admin, &headers, input.reason)?;
    let email = normalize_admin_email(&input.email).map_err(|_| AdminHttpError::InvalidField {
        code: "admin_team_email_invalid",
        field: "email",
        message: "email address is invalid".to_owned(),
    })?;
    let display_name =
        bounded_admin_text(&input.display_name, 160, "display name").map_err(|_| {
            AdminHttpError::InvalidField {
                code: "admin_team_display_name_invalid",
                field: "displayName",
                message: "display name must contain 1 to 160 characters".to_owned(),
            }
        })?;
    let request_hash = admin_operation::request_hash(&json!({
        "accountId": account_id,
        "memberId": member_id,
        "expectedVersion": expected,
        "email": email,
        "displayName": display_name,
    }))?;
    let mut tx = state
        .application
        .repository()
        .pool
        .begin()
        .await
        .map_err(|_| AdminHttpError::Database)?;
    if let Some(response) = admin_operation::claim::<AdminTeamMember>(
        &mut tx,
        TEAM_OWNER_PROFILE_OPERATION,
        &request_hash,
        &context,
    )
    .await?
    {
        tx.commit().await.map_err(|_| AdminHttpError::Database)?;
        return Ok(Json(response));
    }
    let target = sqlx::query(
        "SELECT role, row_version,
                (id = 'member_owner_' || md5(account_id)
                 AND email = 'owner+' || md5(account_id) || '@local.invalid'
                 AND display_name = account_id) AS profile_pending
         FROM workspace_members
         WHERE account_id = $1 AND id = $2 FOR UPDATE",
    )
    .bind(&account_id)
    .bind(&member_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| AdminHttpError::Database)?
    .ok_or(AdminHttpError::NotFound)?;
    if target
        .try_get::<i64, _>("row_version")
        .map_err(|_| AdminHttpError::Database)?
        != expected
    {
        return Err(AdminAppError::VersionConflict.into());
    }
    let role: String = target
        .try_get("role")
        .map_err(|_| AdminHttpError::Database)?;
    let profile_pending: bool = target
        .try_get("profile_pending")
        .map_err(|_| AdminHttpError::Database)?;
    if role != "owner" || !profile_pending {
        return Err(AdminHttpError::Conflict(
            "the primary Owner profile has already been completed".to_owned(),
        ));
    }
    let duplicate: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM workspace_members
             WHERE account_id = $1 AND email = $2 AND id <> $3
         )",
    )
    .bind(&account_id)
    .bind(&email)
    .bind(&member_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| AdminHttpError::Database)?;
    if duplicate {
        return Err(AdminHttpError::Conflict(
            "the email address already belongs to another workspace member".to_owned(),
        ));
    }
    let row = sqlx::query(
        "UPDATE workspace_members
         SET email = $4, display_name = $5, row_version = row_version + 1, updated_at = $6
         WHERE account_id = $1 AND id = $2 AND row_version = $3 AND role = 'owner'
         RETURNING id, email, display_name, role, status, row_version, created_at, updated_at",
    )
    .bind(&account_id)
    .bind(&member_id)
    .bind(expected)
    .bind(&email)
    .bind(&display_name)
    .bind(now)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| AdminHttpError::Database)?
    .ok_or(AdminAppError::VersionConflict)?;
    let response = AdminTeamMember {
        id: row.try_get("id").map_err(|_| AdminHttpError::Database)?,
        email: row.try_get("email").map_err(|_| AdminHttpError::Database)?,
        display_name: row
            .try_get("display_name")
            .map_err(|_| AdminHttpError::Database)?,
        role: parse_workspace_role(
            &row.try_get::<String, _>("role")
                .map_err(|_| AdminHttpError::Database)?,
        )?,
        status: parse_workspace_status(
            &row.try_get::<String, _>("status")
                .map_err(|_| AdminHttpError::Database)?,
        )?,
        row_version: row
            .try_get("row_version")
            .map_err(|_| AdminHttpError::Database)?,
        created_at: row
            .try_get("created_at")
            .map_err(|_| AdminHttpError::Database)?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|_| AdminHttpError::Database)?,
        profile_pending: false,
    };
    insert_control_plane_audit(
        &mut tx,
        &context,
        "team_owner_profile_completed",
        "workspace_member",
        &member_id,
        Some(&account_id),
        now,
    )
    .await?;
    admin_operation::finish(&mut tx, &response, &context).await?;
    tx.commit().await.map_err(|_| AdminHttpError::Database)?;
    Ok(Json(response))
}

async fn update_team_member(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    AxumPath((account_id, member_id)): AxumPath<(String, String)>,
    Json(input): Json<UpdateTeamMemberInput>,
) -> Result<Json<Value>, AdminHttpError> {
    let admin = authenticate_mutation(&state, &headers).await?;
    admin.user.require(AdminPermission::TeamWrite)?;
    if input.role == WorkspaceRole::Owner {
        return Err(AdminHttpError::Invalid(
            "workspace ownership requires the dedicated ownership transfer flow".to_owned(),
        ));
    }
    if input.status == WorkspaceMemberStatus::Invited {
        return Err(AdminHttpError::Invalid(
            "invited members must be managed through the invitation flow".to_owned(),
        ));
    }
    let expected = required_if_match(&headers)?;
    let context = mutation_context(&state, &admin, &headers, input.reason)?;
    let request_hash = admin_operation::request_hash(&json!({
        "accountId": account_id,
        "memberId": member_id,
        "expectedVersion": expected,
        "role": input.role,
        "status": input.status,
    }))?;
    let now = state.application.trusted_now().await?;
    let mut tx = state
        .application
        .repository()
        .pool
        .begin()
        .await
        .map_err(|_| AdminHttpError::Database)?;
    if let Some(response) = admin_operation::claim::<Value>(
        &mut tx,
        TEAM_MEMBER_UPDATE_OPERATION,
        &request_hash,
        &context,
    )
    .await?
    {
        tx.commit().await.map_err(|_| AdminHttpError::Database)?;
        return Ok(Json(response));
    }
    let target = sqlx::query(
        "SELECT role, status, row_version FROM workspace_members
         WHERE account_id = $1 AND id = $2 FOR UPDATE",
    )
    .bind(&account_id)
    .bind(&member_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| AdminHttpError::Database)?
    .ok_or(AdminHttpError::NotFound)?;
    let current_role: String = target
        .try_get("role")
        .map_err(|_| AdminHttpError::Database)?;
    let current_status: String = target
        .try_get("status")
        .map_err(|_| AdminHttpError::Database)?;
    let current_version: i64 = target
        .try_get("row_version")
        .map_err(|_| AdminHttpError::Database)?;
    if current_version != expected {
        return Err(AdminAppError::VersionConflict.into());
    }
    if current_role == "owner" || current_status == "invited" || current_status == "removed" {
        return Err(AdminHttpError::Invalid(
            "owner, invited and removed members require dedicated workflows".to_owned(),
        ));
    }
    let requested_role = workspace_role_name(input.role);
    let requested_status = workspace_status_name(input.status);
    if (current_role == requested_role && current_status == requested_status)
        || (input.status == WorkspaceMemberStatus::Removed && current_role != requested_role)
    {
        return Err(AdminHttpError::Invalid(
            "workspace member update is not a valid state transition".to_owned(),
        ));
    }
    let row = sqlx::query(
        "UPDATE workspace_members
         SET role = $4, status = $5, row_version = row_version + 1, updated_at = $6
         WHERE account_id = $1 AND id = $2 AND row_version = $3 AND role <> 'owner'
         RETURNING id, email, display_name, role, status, row_version, created_at, updated_at",
    )
    .bind(&account_id)
    .bind(&member_id)
    .bind(expected)
    .bind(requested_role)
    .bind(requested_status)
    .bind(now)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| AdminHttpError::Database)?
    .ok_or(AdminAppError::VersionConflict)?;
    if input.status == WorkspaceMemberStatus::Suspended {
        sqlx::query(
            "UPDATE refresh_sessions SET active = false,
                 document = jsonb_set(document, '{active}', 'false'::jsonb, true),
                 updated_at = to_timestamp($2)
             WHERE device_id IN (
                 SELECT device_id FROM device_member_bindings WHERE member_id = $1
             ) AND active",
        )
        .bind(&member_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| AdminHttpError::Database)?;
    }
    if input.status == WorkspaceMemberStatus::Removed {
        crate::team::revoke_member_access(&mut tx, &member_id, now)
            .await
            .map_err(AdminAppError::from)?;
    }
    insert_control_plane_audit(
        &mut tx,
        &context,
        "team_member_updated",
        "workspace_member",
        &member_id,
        Some(&account_id),
        now,
    )
    .await?;
    let response = json!({
        "id": row.try_get::<String, _>("id").map_err(|_| AdminHttpError::Database)?,
        "email": row.try_get::<String, _>("email").map_err(|_| AdminHttpError::Database)?,
        "displayName": row.try_get::<String, _>("display_name").map_err(|_| AdminHttpError::Database)?,
        "role": row.try_get::<String, _>("role").map_err(|_| AdminHttpError::Database)?,
        "status": row.try_get::<String, _>("status").map_err(|_| AdminHttpError::Database)?,
        "rowVersion": row.try_get::<i64, _>("row_version").map_err(|_| AdminHttpError::Database)?,
        "createdAt": row.try_get::<i64, _>("created_at").map_err(|_| AdminHttpError::Database)?,
        "updatedAt": row.try_get::<i64, _>("updated_at").map_err(|_| AdminHttpError::Database)?,
        "profilePending": false,
    });
    admin_operation::finish(&mut tx, &response, &context).await?;
    tx.commit().await.map_err(|_| AdminHttpError::Database)?;
    Ok(Json(response))
}

async fn transfer_team_ownership(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    AxumPath((account_id, member_id)): AxumPath<(String, String)>,
    Json(input): Json<ReasonInput>,
) -> Result<Json<Value>, AdminHttpError> {
    let admin = authenticate_mutation(&state, &headers).await?;
    admin.user.require(AdminPermission::TeamWrite)?;
    let now = state.application.trusted_now().await?;
    admin.require_step_up(now)?;
    let expected = required_if_match(&headers)?;
    let context = mutation_context(&state, &admin, &headers, input.reason)?;
    let request_hash = admin_operation::request_hash(&json!({
        "accountId": account_id,
        "memberId": member_id,
        "expectedVersion": expected,
    }))?;
    let mut tx = state
        .application
        .repository()
        .pool
        .begin()
        .await
        .map_err(|_| AdminHttpError::Database)?;
    if let Some(response) = admin_operation::claim::<Value>(
        &mut tx,
        TEAM_OWNERSHIP_TRANSFER_OPERATION,
        &request_hash,
        &context,
    )
    .await?
    {
        tx.commit().await.map_err(|_| AdminHttpError::Database)?;
        return Ok(Json(response));
    }
    let rows = sqlx::query(
        "SELECT id, role, status, row_version FROM workspace_members
         WHERE account_id = $1 AND (id = $2 OR role = 'owner')
         ORDER BY id FOR UPDATE",
    )
    .bind(&account_id)
    .bind(&member_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| AdminHttpError::Database)?;
    let mut owner_id = None;
    let mut target = None;
    for row in rows {
        let id: String = row.try_get("id").map_err(|_| AdminHttpError::Database)?;
        let role: String = row.try_get("role").map_err(|_| AdminHttpError::Database)?;
        let status: String = row
            .try_get("status")
            .map_err(|_| AdminHttpError::Database)?;
        let row_version: i64 = row
            .try_get("row_version")
            .map_err(|_| AdminHttpError::Database)?;
        if role == "owner" {
            owner_id = Some(id.clone());
        }
        if id == member_id {
            target = Some((role, status, row_version));
        }
    }
    let owner_id = owner_id
        .ok_or_else(|| AdminHttpError::Conflict("workspace has no current owner".to_owned()))?;
    let (target_role, target_status, target_version) = target.ok_or(AdminHttpError::NotFound)?;
    if owner_id == member_id || target_role == "owner" {
        return Err(AdminHttpError::Conflict(
            "the selected member already owns the workspace".to_owned(),
        ));
    }
    if target_role != "admin" || target_status != "active" {
        return Err(AdminHttpError::Invalid(
            "workspace ownership can be transferred only to an active Admin".to_owned(),
        ));
    }
    if target_version != expected {
        return Err(AdminAppError::VersionConflict.into());
    }
    sqlx::query(
        "UPDATE workspace_members SET role = 'admin', row_version = row_version + 1, updated_at = $2
         WHERE id = $1 AND role = 'owner'",
    )
    .bind(&owner_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|_| AdminHttpError::Database)?;
    let row = sqlx::query(
        "UPDATE workspace_members SET role = 'owner', row_version = row_version + 1, updated_at = $4
         WHERE account_id = $1 AND id = $2 AND row_version = $3 AND status = 'active'
         RETURNING id, email, display_name, role, status, row_version, created_at, updated_at",
    )
    .bind(&account_id)
    .bind(&member_id)
    .bind(expected)
    .bind(now)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| AdminHttpError::Database)?
    .ok_or(AdminAppError::VersionConflict)?;
    insert_control_plane_audit(
        &mut tx,
        &context,
        "team_ownership_transferred",
        "workspace_member",
        &member_id,
        Some(&account_id),
        now,
    )
    .await?;
    let response = json!({
        "id": row.try_get::<String, _>("id").map_err(|_| AdminHttpError::Database)?,
        "email": row.try_get::<String, _>("email").map_err(|_| AdminHttpError::Database)?,
        "displayName": row.try_get::<String, _>("display_name").map_err(|_| AdminHttpError::Database)?,
        "role": row.try_get::<String, _>("role").map_err(|_| AdminHttpError::Database)?,
        "status": row.try_get::<String, _>("status").map_err(|_| AdminHttpError::Database)?,
        "rowVersion": row.try_get::<i64, _>("row_version").map_err(|_| AdminHttpError::Database)?,
        "createdAt": row.try_get::<i64, _>("created_at").map_err(|_| AdminHttpError::Database)?,
        "updatedAt": row.try_get::<i64, _>("updated_at").map_err(|_| AdminHttpError::Database)?,
        "profilePending": false,
        "previousOwnerId": owner_id,
    });
    admin_operation::finish(&mut tx, &response, &context).await?;
    tx.commit().await.map_err(|_| AdminHttpError::Database)?;
    Ok(Json(response))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReasonInput {
    reason: String,
}

async fn revoke_team_invitation(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
    AxumPath((account_id, invitation_id)): AxumPath<(String, String)>,
    Json(input): Json<ReasonInput>,
) -> Result<StatusCode, AdminHttpError> {
    let admin = authenticate_mutation(&state, &headers).await?;
    admin.user.require(AdminPermission::TeamWrite)?;
    let context = mutation_context(&state, &admin, &headers, input.reason)?;
    let request_hash = admin_operation::request_hash(&json!({
        "accountId": account_id,
        "invitationId": invitation_id,
    }))?;
    let now = state.application.trusted_now().await?;
    let mut tx = state
        .application
        .repository()
        .pool
        .begin()
        .await
        .map_err(|_| AdminHttpError::Database)?;
    if admin_operation::claim::<Value>(
        &mut tx,
        TEAM_INVITATION_REVOKE_OPERATION,
        &request_hash,
        &context,
    )
    .await?
    .is_some()
    {
        tx.commit().await.map_err(|_| AdminHttpError::Database)?;
        return Ok(StatusCode::NO_CONTENT);
    }
    let member_id: String = sqlx::query_scalar(
        "UPDATE team_invitations SET revoked_at = $3
         WHERE id = $1 AND account_id = $2 AND accepted_at IS NULL AND revoked_at IS NULL
         RETURNING member_id",
    )
    .bind(&invitation_id)
    .bind(&account_id)
    .bind(now)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| AdminHttpError::Database)?
    .ok_or(AdminHttpError::NotFound)?;
    let affected = sqlx::query(
        "UPDATE workspace_members SET status = 'removed', row_version = row_version + 1,
             updated_at = $2 WHERE id = $1 AND status = 'invited'",
    )
    .bind(&member_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|_| AdminHttpError::Database)?
    .rows_affected();
    if affected != 1 {
        return Err(AdminHttpError::Conflict(
            "workspace invitation member is no longer pending".to_owned(),
        ));
    }
    crate::team::revoke_member_access(&mut tx, &member_id, now)
        .await
        .map_err(AdminAppError::from)?;
    insert_control_plane_audit(
        &mut tx,
        &context,
        "team_invitation_revoked",
        "team_invitation",
        &invitation_id,
        Some(&account_id),
        now,
    )
    .await?;
    admin_operation::finish(&mut tx, &json!({"revoked": true}), &context).await?;
    tx.commit().await.map_err(|_| AdminHttpError::Database)?;
    Ok(StatusCode::NO_CONTENT)
}

fn require_bulk_permission(
    admin: &AuthenticatedAdmin,
    preview: &CreatePreview,
) -> Result<(), AdminHttpError> {
    admin.user.require(bulk_permission(preview)?)?;
    Ok(())
}

fn bulk_permission(preview: &CreatePreview) -> Result<AdminPermission, AdminHttpError> {
    let parameter = |name: &str| {
        preview
            .parameters
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| AdminHttpError::Invalid(format!("{name} must be a string")))
    };
    let permission = match preview.kind {
        BulkJobKind::AccountSetState => match parameter("state")? {
            "active" | "suspended" => AdminPermission::AccountWrite,
            "denylisted" => AdminPermission::AccountDenylist,
            _ => {
                return Err(AdminHttpError::Invalid("invalid account state".to_owned()));
            }
        },
        BulkJobKind::LicenseSetStatus => AdminPermission::LicenseWrite,
        BulkJobKind::ActivationCodeRevoke | BulkJobKind::ActivationCodeExpire => {
            AdminPermission::CodeWrite
        }
        BulkJobKind::DeviceSetState => match parameter("state")? {
            "removed" => AdminPermission::DeviceRemove,
            "revoked" | "suspicious" => AdminPermission::DeviceSecurity,
            _ => {
                return Err(AdminHttpError::Invalid("invalid device state".to_owned()));
            }
        },
    };
    Ok(permission)
}

async fn system_status(
    State(state): State<AdminHttpState>,
    headers: HeaderMap,
) -> Result<Json<AdminSystemStatus>, AdminHttpError> {
    authenticate(&state, &headers)
        .await?
        .user
        .require(AdminPermission::SystemRead)?;
    let time = state.application.trusted_now().await?;
    let storage = state.storage.status().await?;
    Ok(Json(AdminSystemStatus {
        status: AdminReadiness::Ready,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        server_unix: time,
        started_at: state.started_at,
        admin_origin: state.public_origin.clone(),
        database: AdminReadiness::Ready,
        time_authority: AdminReadiness::Ready,
        object_storage: storage,
    }))
}

async fn authenticate(
    state: &AdminHttpState,
    headers: &HeaderMap,
) -> Result<AuthenticatedAdmin, AdminHttpError> {
    let token =
        cookie(headers, session_cookie_name(state)).ok_or(AdminAuthError::InvalidSession)?;
    Ok(state.auth.authenticate(&token).await?)
}

async fn authenticate_mutation(
    state: &AdminHttpState,
    headers: &HeaderMap,
) -> Result<AuthenticatedAdmin, AdminHttpError> {
    let admin = authenticate_csrf(state, headers).await?;
    required_idempotency_key(headers)?;
    Ok(admin)
}

async fn authenticate_csrf(
    state: &AdminHttpState,
    headers: &HeaderMap,
) -> Result<AuthenticatedAdmin, AdminHttpError> {
    require_same_origin(state, headers)?;
    let admin = authenticate(state, headers).await?;
    let csrf = header_text(headers, HeaderName::from_static("x-csrf-token"))
        .ok_or(AdminAuthError::PermissionDenied)?;
    state.auth.verify_csrf(&admin, csrf)?;
    Ok(admin)
}

fn mutation_context(
    state: &AdminHttpState,
    admin: &AuthenticatedAdmin,
    headers: &HeaderMap,
    reason: String,
) -> Result<MutationContext, AdminHttpError> {
    let mut context = MutationContext::new(
        AdminPrincipal {
            id: admin.user.id.clone(),
            session_id: Some(admin.session_id.clone()),
            source_ip: source_ip(state, headers),
            user_agent_hash: header_text(headers, header::USER_AGENT)
                .map(crate::crypto::sha256_hex),
            request_id: header_text(headers, HeaderName::from_static("x-request-id"))
                .map(str::to_owned),
        },
        reason,
    )?;
    context.operation_id = Some(required_idempotency_key(headers)?);
    Ok(context)
}

fn require_same_origin(state: &AdminHttpState, headers: &HeaderMap) -> Result<(), AdminHttpError> {
    let origin = header_text(headers, header::ORIGIN)
        .ok_or_else(|| AdminHttpError::Invalid("Origin header is required".to_owned()))?;
    if origin != state.public_origin {
        return Err(AdminAuthError::PermissionDenied.into());
    }
    if let Some(site) = header_text(headers, HeaderName::from_static("sec-fetch-site"))
        && !matches!(site, "same-origin" | "none")
    {
        return Err(AdminAuthError::PermissionDenied.into());
    }
    Ok(())
}

fn required_idempotency_key(headers: &HeaderMap) -> Result<String, AdminHttpError> {
    let value = header_text(headers, HeaderName::from_static(IDEMPOTENCY_HEADER))
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or_else(|| AdminHttpError::Invalid("Idempotency-Key header is required".to_owned()))?;
    Ok(value.to_owned())
}

fn required_if_match(headers: &HeaderMap) -> Result<i64, AdminHttpError> {
    let value = header_text(headers, header::IF_MATCH)
        .ok_or_else(|| AdminHttpError::Invalid("If-Match header is required".to_owned()))?;
    value
        .trim_matches('"')
        .parse()
        .map_err(|_| AdminHttpError::Invalid("If-Match must contain a row version".to_owned()))
}

fn incremented_row_version(row_version: i64) -> Result<i64, AdminHttpError> {
    row_version.checked_add(1).ok_or(AdminHttpError::Database)
}

fn versioned_response<T: Serialize>(
    value: T,
    row_version: i64,
) -> Result<Response<Body>, AdminHttpError> {
    let etag = HeaderValue::from_str(&format!("\"{row_version}\""))
        .map_err(|_| AdminHttpError::Database)?;
    let mut response = Json(value).into_response();
    response.headers_mut().insert(header::ETAG, etag);
    Ok(response)
}

fn admin_user_response(user: AdminUser) -> Result<Response<Body>, AdminHttpError> {
    let etag = HeaderValue::from_str(&format!("\"{}\"", user.row_version))
        .map_err(|_| AdminHttpError::Database)?;
    let mut response = Json(user).into_response();
    response.headers_mut().insert(header::ETAG, etag);
    Ok(response)
}

fn auth_response<T: Serialize>(
    state: &AdminHttpState,
    body: AuthResponse<T>,
    session: &SessionCredentials,
    now: i64,
) -> Result<Response<Body>, AdminHttpError> {
    let mut response = Json(body).into_response();
    append_cookie(
        response.headers_mut(),
        session_cookie_name(state),
        &session.session_token,
        true,
        state.secure_cookie,
        session.expires_at,
        now,
    );
    append_cookie(
        response.headers_mut(),
        csrf_cookie_name(state),
        &session.csrf_token,
        false,
        state.secure_cookie,
        session.expires_at,
        now,
    );
    Ok(response)
}

fn append_cookie(
    headers: &mut HeaderMap,
    name: &str,
    value: &str,
    http_only: bool,
    secure: bool,
    expires_at: i64,
    now: i64,
) {
    let max_age = expires_at.saturating_sub(now).max(0);
    let mut cookie = format!("{name}={value}; Path=/; SameSite=Strict; Max-Age={max_age}");
    if secure {
        cookie.push_str("; Secure");
    }
    if http_only {
        cookie.push_str("; HttpOnly");
    }
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        headers.append(header::SET_COOKIE, value);
    }
}

fn append_clear_cookie(headers: &mut HeaderMap, name: &str, secure: bool) {
    let mut cookie = format!("{name}=; Path=/; SameSite=Strict; Max-Age=0; HttpOnly");
    if matches!(name, CSRF_COOKIE | DEVELOPMENT_CSRF_COOKIE) {
        cookie = format!("{name}=; Path=/; SameSite=Strict; Max-Age=0");
    }
    if secure {
        cookie.push_str("; Secure");
    }
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        headers.append(header::SET_COOKIE, value);
    }
}

fn session_cookie_name(state: &AdminHttpState) -> &'static str {
    if state.secure_cookie {
        SESSION_COOKIE
    } else {
        DEVELOPMENT_SESSION_COOKIE
    }
}

fn csrf_cookie_name(state: &AdminHttpState) -> &'static str {
    if state.secure_cookie {
        CSRF_COOKIE
    } else {
        DEVELOPMENT_CSRF_COOKIE
    }
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    header_text(headers, header::COOKIE).and_then(|cookies| {
        cookies.split(';').find_map(|cookie| {
            let (candidate, value) = cookie.trim().split_once('=')?;
            (candidate == name).then(|| value.to_owned())
        })
    })
}

fn header_text<N>(headers: &HeaderMap, name: N) -> Option<&str>
where
    N: axum::http::header::AsHeaderName,
{
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn source_ip(state: &AdminHttpState, headers: &HeaderMap) -> Option<String> {
    let expected = state.forwarded_for_secret_hash?;
    let supplied = header_text(headers, HeaderName::from_static("x-camellia-proxy-auth"))?;
    let supplied: [u8; 32] = Sha256::digest(supplied.as_bytes()).into();
    if !constant_time_equal(&expected, &supplied) {
        return None;
    }
    header_text(headers, HeaderName::from_static("x-forwarded-for"))
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .and_then(|value| value.parse::<std::net::IpAddr>().ok())
        .map(|value| value.to_string())
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn admin_content_security_policy(asset_dir: &Path) -> Result<HeaderValue, String> {
    let mut hashes = BTreeSet::new();
    for asset in [ADMIN_INDEX_FILE, ADMIN_FALLBACK_FILE] {
        let document = std::fs::read_to_string(asset_dir.join(asset))
            .map_err(|_| format!("admin UI {asset} could not be read"))?;
        for section in document.split("<script>").skip(1) {
            let script = section
                .split_once("</script>")
                .map(|(script, _)| script)
                .ok_or_else(|| format!("admin UI {asset} contains an unterminated script"))?;
            hashes.insert(STANDARD.encode(Sha256::digest(script.as_bytes())));
        }
    }
    if hashes.is_empty() {
        return Err("admin UI bootstrap script is missing".to_owned());
    }
    let script_hashes = hashes
        .into_iter()
        .map(|digest| format!(" 'sha256-{digest}'"))
        .collect::<String>();
    let policy = format!(
        "default-src 'none'; script-src 'self'{script_hashes}; style-src 'self'; connect-src 'self'; img-src 'self' data: blob:; font-src 'self'; manifest-src 'self'; worker-src 'self'; form-action 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'"
    );
    HeaderValue::from_str(&policy).map_err(|_| "admin UI CSP could not be built".to_owned())
}

async fn admin_security_headers(
    State(security): State<AdminSecurityState>,
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    let path = request.uri().path().to_owned();
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    let cache = if path.starts_with("/_app/immutable/")
        || (path.starts_with("/icons/") && path.contains(".v1"))
    {
        "public, max-age=31536000, immutable"
    } else {
        "no-store, max-age=0"
    };
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
    );
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        security.content_security_policy,
    );
    response
}

pub(crate) async fn admin_schema_ready(repository: &PostgresRepository) -> Result<(), ApiError> {
    let ready: bool = sqlx::query_scalar(
        "SELECT to_regclass('public.admin_users') IS NOT NULL
             AND to_regclass('public.admin_sessions') IS NOT NULL
             AND to_regclass('public.admin_role_bindings') IS NOT NULL
             AND to_regclass('public.admin_bulk_jobs') IS NOT NULL
             AND to_regclass('public.admin_bulk_job_items') IS NOT NULL
             AND to_regclass('public.stored_objects') IS NOT NULL
             AND to_regclass('public.admin_secret_deliveries') IS NOT NULL
             AND to_regclass('public.audit_events_global_keyset_idx') IS NOT NULL
             AND EXISTS (
                 SELECT 1 FROM information_schema.columns
                 WHERE table_schema = 'public' AND table_name = 'payment_evidence_attachments'
                   AND column_name = 'object_id'
             )
             AND EXISTS (
                 SELECT 1 FROM information_schema.columns
                 WHERE table_schema = 'public' AND table_name = 'accounts'
                   AND column_name = 'row_version'
             )
             AND EXISTS (
                 SELECT 1 FROM information_schema.columns
                 WHERE table_schema = 'public' AND table_name = 'admin_operations'
                   AND column_name = 'response_document'
             )",
    )
    .fetch_one(&repository.pool)
    .await
    .map_err(|_| ApiError::Database)?;
    if ready {
        Ok(())
    } else {
        Err(ApiError::DatabaseSchemaNotReady)
    }
}

fn validate_origin(value: &str, environment: Environment) -> Result<(), String> {
    let url = Url::parse(value)
        .map_err(|_| "CAMELLIA_NEXUS_ADMIN_PUBLIC_ORIGIN is invalid".to_owned())?;
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err(
            "CAMELLIA_NEXUS_ADMIN_PUBLIC_ORIGIN must contain only scheme and authority".to_owned(),
        );
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(
            "CAMELLIA_NEXUS_ADMIN_PUBLIC_ORIGIN must not contain user information".to_owned(),
        );
    }
    if environment == Environment::Production && url.scheme() != "https" {
        return Err("CAMELLIA_NEXUS_ADMIN_PUBLIC_ORIGIN must use HTTPS in production".to_owned());
    }
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err("CAMELLIA_NEXUS_ADMIN_PUBLIC_ORIGIN must be an HTTP(S) origin".to_owned());
    }
    Ok(())
}

fn admin_positive_u32_from_value(
    key: &'static str,
    value: Option<String>,
    default: u32,
) -> Result<u32, String> {
    let parsed = match value {
        Some(value) => value
            .parse::<u32>()
            .map_err(|_| format!("{key} must be a positive 32-bit integer"))?,
        None => default,
    };
    if parsed == 0 {
        Err(format!("{key} must be greater than zero"))
    } else {
        Ok(parsed)
    }
}

#[allow(clippy::too_many_arguments)]
async fn insert_control_plane_audit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    context: &MutationContext,
    event_type: &str,
    target_type: &str,
    target_id: &str,
    account_id: Option<&str>,
    now: i64,
) -> Result<(), AdminHttpError> {
    let mut metadata = BTreeMap::from([
        ("actor".to_owned(), context.principal.id.clone()),
        ("actor_type".to_owned(), "admin".to_owned()),
        ("reason".to_owned(), context.reason.clone()),
        ("target_type".to_owned(), target_type.to_owned()),
        ("target_id".to_owned(), target_id.to_owned()),
    ]);
    if let Some(operation_id) = &context.operation_id {
        metadata.insert("operation_id".to_owned(), operation_id.clone());
    }
    if let Some(job_id) = &context.job_id {
        metadata.insert("job_id".to_owned(), job_id.clone());
    }
    let record = AuditEventRecord {
        id: crate::crypto::random_id("audit"),
        event_type: event_type.to_owned(),
        outcome: "succeeded".to_owned(),
        occurred_at: now,
        account_id: account_id.map(str::to_owned),
        license_id: None,
        device_id: None,
        reason_code: Some("admin_operation".to_owned()),
        metadata,
    };
    sqlx::query(
        "INSERT INTO audit_events
         (id, event_type, outcome, occurred_at, account_id, reason_code, metadata, document,
          actor_type, actor_id, admin_session_id, request_id, source_ip, user_agent_hash,
          target_type, target_id, operation_id, job_id)
         VALUES ($1, $2, 'succeeded', $3, $4, 'admin_operation', $5, $6,
                 'admin', $7, $8, $9, $10, $11, $12, $13, $14, $15)",
    )
    .bind(&record.id)
    .bind(event_type)
    .bind(now)
    .bind(account_id)
    .bind(serde_json::to_value(&record.metadata)?)
    .bind(serde_json::to_value(&record)?)
    .bind(&context.principal.id)
    .bind(&context.principal.session_id)
    .bind(&context.principal.request_id)
    .bind(&context.principal.source_ip)
    .bind(&context.principal.user_agent_hash)
    .bind(target_type)
    .bind(target_id)
    .bind(&context.operation_id)
    .bind(&context.job_id)
    .execute(&mut **tx)
    .await
    .map_err(|_| AdminHttpError::Database)?;
    Ok(())
}

fn normalize_admin_email(value: &str) -> Result<String, AdminHttpError> {
    let value = value.trim().to_lowercase();
    let mut parts = value.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(AdminHttpError::Invalid(
            "email address is invalid".to_owned(),
        ));
    };
    let local_valid = (1..=64).contains(&local.len())
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".!#$%&'*+/=?^_`{|}~-".contains(&byte));
    let domain_valid = (1..=253).contains(&domain.len())
        && domain.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if value.len() > 254 || !local_valid || !domain_valid {
        return Err(AdminHttpError::Invalid(
            "email address is invalid".to_owned(),
        ));
    }
    Ok(value)
}

fn bounded_admin_text(value: &str, maximum: usize, label: &str) -> Result<String, AdminHttpError> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > maximum {
        return Err(AdminHttpError::Invalid(format!(
            "{label} must contain 1 to {maximum} characters"
        )));
    }
    Ok(value.to_owned())
}

fn parse_workspace_role(value: &str) -> Result<WorkspaceRole, AdminHttpError> {
    match value {
        "owner" => Ok(WorkspaceRole::Owner),
        "admin" => Ok(WorkspaceRole::Admin),
        "billing" => Ok(WorkspaceRole::Billing),
        "operator" => Ok(WorkspaceRole::Operator),
        "viewer" => Ok(WorkspaceRole::Viewer),
        "auditor" => Ok(WorkspaceRole::Auditor),
        _ => Err(AdminHttpError::Database),
    }
}

fn parse_workspace_status(value: &str) -> Result<WorkspaceMemberStatus, AdminHttpError> {
    match value {
        "invited" => Ok(WorkspaceMemberStatus::Invited),
        "active" => Ok(WorkspaceMemberStatus::Active),
        "suspended" => Ok(WorkspaceMemberStatus::Suspended),
        "removed" => Ok(WorkspaceMemberStatus::Removed),
        _ => Err(AdminHttpError::Database),
    }
}

const fn workspace_role_name(role: WorkspaceRole) -> &'static str {
    match role {
        WorkspaceRole::Owner => "owner",
        WorkspaceRole::Admin => "admin",
        WorkspaceRole::Billing => "billing",
        WorkspaceRole::Operator => "operator",
        WorkspaceRole::Viewer => "viewer",
        WorkspaceRole::Auditor => "auditor",
    }
}

const fn workspace_status_name(status: WorkspaceMemberStatus) -> &'static str {
    match status {
        WorkspaceMemberStatus::Invited => "invited",
        WorkspaceMemberStatus::Active => "active",
        WorkspaceMemberStatus::Suspended => "suspended",
        WorkspaceMemberStatus::Removed => "removed",
    }
}

const fn default_audit_limit() -> i64 {
    100
}

fn default_admin_page_size() -> u32 {
    PageRequest::default().page_size
}

fn admin_page_request(
    cursor: &Option<String>,
    page_size: u32,
    query: &Option<String>,
) -> PageRequest {
    PageRequest {
        cursor: cursor.clone(),
        page_size,
        query: query.clone(),
    }
}

const fn default_license_status() -> LicenseStatus {
    LicenseStatus::Active
}

const fn default_max_redemptions() -> u32 {
    1
}

const fn default_true() -> bool {
    true
}

impl From<serde_json::Error> for AdminHttpError {
    fn from(error: serde_json::Error) -> Self {
        Self::Application(AdminAppError::Serialization(error))
    }
}

impl From<Infallible> for AdminHttpError {
    fn from(value: Infallible) -> Self {
        match value {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    fn write_admin_asset_fixture(directory: &Path) {
        std::fs::create_dir_all(directory.join(ADMIN_IMMUTABLE_ASSET_DIRECTORY)).unwrap();
        std::fs::create_dir_all(directory.join(ADMIN_ICON_DIRECTORY)).unwrap();
        for asset in [
            ADMIN_INDEX_FILE,
            ADMIN_FALLBACK_FILE,
            ADMIN_APPEARANCE_FILE,
            ADMIN_MANIFEST_FILE,
            ADMIN_SERVICE_WORKER_FILE,
            ADMIN_VERSION_FILE,
        ]
        .into_iter()
        .chain(ADMIN_ICON_FILES.iter().copied())
        {
            let path = directory.join(asset);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(path, "fixture").unwrap();
        }
        std::fs::write(
            directory
                .join(ADMIN_IMMUTABLE_ASSET_DIRECTORY)
                .join("app.hash.js"),
            "export {};",
        )
        .unwrap();
    }

    #[test]
    fn invoice_seat_validation_is_exposed_as_a_field_error() {
        match create_invoice_error(AdminAppError::Validation("invalid seats".to_owned())) {
            AdminHttpError::InvalidField {
                code,
                field,
                message,
            } => {
                assert_eq!(code, "admin_invoice_seats_invalid");
                assert_eq!(field, "seats");
                assert_eq!(message, "invalid seats");
            }
            error => panic!("unexpected invoice error mapping: {error}"),
        }
    }

    #[test]
    fn payment_evidence_is_only_accepted_while_a_claim_can_change() {
        for status in ["submitted", "under_review", "needs_information"] {
            assert!(
                payment_claim_accepts_evidence(status),
                "{status} should accept evidence"
            );
        }
        for status in ["verified", "rejected", "withdrawn", "unknown"] {
            assert!(
                !payment_claim_accepts_evidence(status),
                "{status} should reject evidence"
            );
        }
    }

    #[test]
    fn bulk_permissions_match_single_resource_security_boundaries() {
        let preview = |kind, parameters| CreatePreview {
            kind,
            target_ids: vec!["target".to_owned()],
            parameters,
        };
        assert_eq!(
            bulk_permission(&preview(
                BulkJobKind::AccountSetState,
                json!({"state": "denylisted"}),
            ))
            .expect("denylist permission"),
            AdminPermission::AccountDenylist
        );
        assert_eq!(
            bulk_permission(&preview(
                BulkJobKind::AccountSetState,
                json!({"state": "suspended"}),
            ))
            .expect("account write permission"),
            AdminPermission::AccountWrite
        );
        assert_eq!(
            bulk_permission(&preview(
                BulkJobKind::DeviceSetState,
                json!({"state": "removed"}),
            ))
            .expect("device removal permission"),
            AdminPermission::DeviceRemove
        );
        assert_eq!(
            bulk_permission(&preview(
                BulkJobKind::DeviceSetState,
                json!({"state": "suspicious"}),
            ))
            .expect("device security permission"),
            AdminPermission::DeviceSecurity
        );
    }

    #[test]
    fn team_pages_are_bounded_and_use_canonical_cursors() {
        let (cursor, page_size) = team_page_request(PageRequest {
            cursor: Some("member_0123456789abcdef".to_owned()),
            page_size: 100,
            query: None,
        })
        .expect("valid Team page");
        assert_eq!(cursor.as_deref(), Some("member_0123456789abcdef"));
        assert_eq!(page_size, 100);
        assert!(
            team_page_request(PageRequest {
                cursor: Some("member/invalid".to_owned()),
                page_size: 100,
                query: None,
            })
            .is_err()
        );
        assert!(
            team_page_request(PageRequest {
                cursor: None,
                page_size: 201,
                query: None,
            })
            .is_err()
        );
        assert!(
            team_page_request(PageRequest {
                cursor: None,
                page_size: 100,
                query: Some("unsupported".to_owned()),
            })
            .is_err()
        );
    }

    #[test]
    fn composite_resource_queries_accept_canonical_page_fields() {
        let uri = "/?account=acct_example&pageSize=100&query=example"
            .parse()
            .expect("resource query URI");
        let Query(license) = Query::<LicenseQuery>::try_from_uri(&uri).expect("license query");
        assert_eq!(license.account.as_deref(), Some("acct_example"));
        assert_eq!(license.page_size, 100);
        assert_eq!(license.query.as_deref(), Some("example"));

        let uri = "/?account=acct_example&status=active&pageSize=100&query=example"
            .parse()
            .expect("activation-code query URI");
        let Query(codes) =
            Query::<ActivationCodeQuery>::try_from_uri(&uri).expect("activation-code query");
        assert_eq!(codes.account.as_deref(), Some("acct_example"));
        assert_eq!(codes.status, Some(ActivationCodeStatus::Active));
        assert_eq!(codes.page_size, 100);
        assert_eq!(codes.query.as_deref(), Some("example"));

        let uri = "/?account=acct_example&pageSize=100&query=example"
            .parse()
            .expect("device query URI");
        let Query(devices) = Query::<DeviceQuery>::try_from_uri(&uri).expect("device query");
        assert_eq!(devices.account.as_deref(), Some("acct_example"));
        assert_eq!(devices.page_size, 100);
        assert_eq!(devices.query.as_deref(), Some("example"));

        let unknown = "/?pageSize=100&unexpected=true"
            .parse()
            .expect("unknown query URI");
        assert!(Query::<DeviceQuery>::try_from_uri(&unknown).is_err());
    }

    #[test]
    fn production_admin_origin_requires_https() {
        assert!(validate_origin("http://admin.example.com", Environment::Production).is_err());
        assert!(validate_origin("https://admin.example.com", Environment::Production).is_ok());
        assert!(
            validate_origin(
                "https://operator:secret@admin.example.com",
                Environment::Production,
            )
            .is_err()
        );
    }

    #[test]
    fn administration_runtime_limits_reject_invalid_and_zero_values() {
        for value in ["invalid", "0"] {
            assert!(
                admin_positive_u32_from_value(
                    "CAMELLIA_NEXUS_ADMIN_REQUEST_TIMEOUT_SECONDS",
                    Some(value.into()),
                    180,
                )
                .is_err()
            );
            assert!(
                admin_positive_u32_from_value(
                    "CAMELLIA_NEXUS_ADMIN_MAX_IN_FLIGHT",
                    Some(value.into()),
                    64,
                )
                .is_err()
            );
        }
        assert_eq!(
            admin_positive_u32_from_value(
                "CAMELLIA_NEXUS_ADMIN_REQUEST_TIMEOUT_SECONDS",
                Some("240".into()),
                180,
            )
            .unwrap(),
            240
        );
    }

    #[tokio::test]
    async fn administration_timeout_and_overload_errors_are_machine_readable_and_retryable() {
        for (timed_out, status, code) in [
            (true, StatusCode::GATEWAY_TIMEOUT, "admin_request_timeout"),
            (
                false,
                StatusCode::SERVICE_UNAVAILABLE,
                "admin_service_overloaded",
            ),
        ] {
            let response = admin_middleware_error_response(timed_out);
            assert_eq!(response.status(), status);
            assert_eq!(
                response.headers().get(header::RETRY_AFTER),
                Some(&HeaderValue::from_static("1"))
            );
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE),
                Some(&HeaderValue::from_static("application/json"))
            );
            let body = axum::body::to_bytes(response.into_body(), 4 * 1024)
                .await
                .expect("admin error body");
            let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON error body");
            assert_eq!(body["code"], code);
        }
    }

    #[test]
    fn content_security_policy_allows_only_the_built_bootstrap_script() {
        let directory = std::env::temp_dir().join(crate::crypto::random_id("admin_ui_test"));
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join(ADMIN_INDEX_FILE),
            "<html><script>console.log('bootstrap')</script></html>",
        )
        .unwrap();
        std::fs::write(
            directory.join(ADMIN_FALLBACK_FILE),
            "<html><script>console.log('fallback')</script></html>",
        )
        .unwrap();
        let policy = admin_content_security_policy(&directory).unwrap();
        let policy = policy.to_str().unwrap();
        assert_eq!(policy.matches("'sha256-").count(), 2);
        assert!(!policy.contains("'unsafe-inline'"));
        assert!(policy.contains("worker-src 'self'"));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn administration_api_fallbacks_remain_machine_readable() {
        let response = admin_api_not_found().await.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&HeaderValue::from_static("application/json"))
        );

        let response = admin_api_method_not_allowed().await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE),
            Some(&HeaderValue::from_static("application/json"))
        );
    }

    #[test]
    fn administration_assets_must_form_a_complete_static_build() {
        let directory = std::env::temp_dir().join(crate::crypto::random_id("admin_assets_test"));
        std::fs::create_dir_all(&directory).unwrap();
        assert!(
            validate_admin_assets(&directory)
                .unwrap_err()
                .contains(ADMIN_INDEX_FILE)
        );

        write_admin_asset_fixture(&directory);
        validate_admin_assets(&directory).unwrap();
        for asset in [ADMIN_MANIFEST_FILE, ADMIN_SERVICE_WORKER_FILE]
            .into_iter()
            .chain(ADMIN_ICON_FILES.iter().copied())
        {
            std::fs::remove_file(directory.join(asset)).unwrap();
            assert!(
                validate_admin_assets(&directory)
                    .unwrap_err()
                    .contains(asset)
            );
            std::fs::write(directory.join(asset), "fixture").unwrap();
        }
        std::fs::remove_dir_all(directory.join(ADMIN_IMMUTABLE_ASSET_DIRECTORY)).unwrap();
        assert!(
            validate_admin_assets(&directory)
                .unwrap_err()
                .contains(ADMIN_IMMUTABLE_ASSET_DIRECTORY)
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn administration_static_assets_have_pwa_mime_cache_and_security_headers() {
        let directory = std::env::temp_dir().join(crate::crypto::random_id("admin_pwa_test"));
        write_admin_asset_fixture(&directory);
        std::fs::write(
            directory.join(ADMIN_INDEX_FILE),
            "<html><script>console.log('index')</script></html>",
        )
        .unwrap();
        std::fs::write(
            directory.join(ADMIN_FALLBACK_FILE),
            "<html><script>console.log('fallback')</script></html>",
        )
        .unwrap();
        let security = AdminSecurityState {
            content_security_policy: admin_content_security_policy(&directory).unwrap(),
        };
        let router = admin_asset_router::<()>(&directory).layer(middleware::from_fn_with_state(
            security,
            admin_security_headers,
        ));
        for (path, content_type, cache_control) in [
            (
                "/manifest.webmanifest",
                "application/manifest+json",
                "no-store, max-age=0",
            ),
            (
                "/service-worker.js",
                "text/javascript",
                "no-store, max-age=0",
            ),
            (
                "/icons/camellia-console.v1.svg",
                "image/svg+xml",
                "public, max-age=31536000, immutable",
            ),
            (
                "/icons/camellia-console.v1-192.png",
                "image/png",
                "public, max-age=31536000, immutable",
            ),
            (
                "/_app/immutable/app.hash.js",
                "text/javascript",
                "public, max-age=31536000, immutable",
            ),
            ("/client/route", "text/html", "no-store, max-age=0"),
        ] {
            let response = router
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(
                response.headers().get(header::CONTENT_TYPE),
                Some(&HeaderValue::from_static(content_type)),
                "{path}"
            );
            assert_eq!(
                response.headers().get(header::CACHE_CONTROL),
                Some(&HeaderValue::from_static(cache_control)),
                "{path}"
            );
            assert!(
                response
                    .headers()
                    .get("content-security-policy")
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| value.contains("worker-src 'self'")),
                "{path}"
            );
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn cookie_parser_does_not_match_prefixes() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("other=1; __Host-camellia_admin=secret"),
        );
        assert_eq!(cookie(&headers, SESSION_COOKIE).as_deref(), Some("secret"));
    }

    #[test]
    fn proxy_authentication_comparison_rejects_every_mismatch() {
        let expected = [0x5a; 32];
        assert!(constant_time_equal(&expected, &expected));
        for index in 0..expected.len() {
            let mut supplied = expected;
            supplied[index] ^= 1;
            assert!(!constant_time_equal(&expected, &supplied));
        }
    }

    #[test]
    fn proxy_authentication_secret_is_header_safe_and_bounded() {
        let generated = format!("{}\n", "5a".repeat(32));
        let expected: [u8; 32] = Sha256::digest("5a".repeat(32).as_bytes()).into();
        assert_eq!(
            hash_forwarded_for_secret(generated.as_bytes()).expect("generated proxy secret"),
            expected
        );
        assert!(hash_forwarded_for_secret("a".repeat(32).as_bytes()).is_ok());
        assert!(hash_forwarded_for_secret("a".repeat(256).as_bytes()).is_ok());
        for invalid in [
            "a".repeat(31),
            "a".repeat(257),
            format!("{} ", "a".repeat(32)),
            format!("{}\n\n", "a".repeat(32)),
            format!("{}é", "a".repeat(32)),
        ] {
            assert!(hash_forwarded_for_secret(invalid.as_bytes()).is_err());
        }
    }

    #[test]
    fn payment_evidence_scan_outcomes_have_stable_http_semantics() {
        let clean = payment_evidence_upload_response(json!({"scanStatus": "clean"}))
            .expect("clean evidence accepted");
        assert_eq!(clean.0, StatusCode::CREATED);
        let pending = payment_evidence_upload_response(json!({"scanStatus": "failed"}))
            .expect("scanner outage is accepted for retry");
        assert_eq!(pending.0, StatusCode::ACCEPTED);
        assert!(matches!(
            payment_evidence_upload_response(json!({"scanStatus": "rejected"})),
            Err(AdminHttpError::Storage(ObjectStorageError::MalwareDetected))
        ));
    }

    #[test]
    fn team_email_normalization_accepts_canonical_addresses_only() {
        assert_eq!(
            normalize_admin_email(" Owner+Billing@Example.COM ").unwrap(),
            "owner+billing@example.com"
        );
        for invalid in [
            "owner",
            "owner@@example.com",
            ".owner@example.com",
            "owner..billing@example.com",
            "owner@-example.com",
            "owner@example..com",
            "拥有者@example.com",
        ] {
            assert!(
                normalize_admin_email(invalid).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn admin_request_contract_matches_shared_admin_ui_golden() {
        let golden: Value =
            serde_json::from_str(include_str!("../admin-ui/tests/fixtures/admin-wire.json"))
                .expect("admin wire golden must be valid JSON");

        let account: CreateAccountInput =
            serde_json::from_value(golden["createAccountRequest"].clone())
                .expect("Admin UI account request must match the provider contract");
        assert_eq!(account.id, "acct_golden");
        assert_eq!(account.note.as_deref(), Some("Golden customer"));
        assert_eq!(account.reason, "contract fixture");

        let license: CreateLicenseInput =
            serde_json::from_value(golden["createLicenseRequest"].clone())
                .expect("Admin UI license request must match the provider contract");
        assert_eq!(license.id, "lic_golden");
        assert_eq!(license.account_id, "acct_golden");
        assert_eq!(license.plan, Plan::Team);
        assert_eq!(license.status, LicenseStatus::Active);
        assert_eq!(license.expires_at, None);
        assert_eq!(license.purchased_seats, 12);
        assert_eq!(license.reason, "contract fixture");

        let batch: IssueActivationCodesInput =
            serde_json::from_value(golden["issueActivationCodesRequest"].clone())
                .expect("Admin UI activation-code request must match the provider contract");
        assert_eq!(batch.account_id, "acct_golden");
        assert_eq!(batch.license_id, "lic_golden");
        assert_eq!(batch.count, 2);
        assert_eq!(batch.max_redemptions, 3);
        assert_eq!(batch.expires_at.as_deref(), Some("+30d"));
        assert_eq!(batch.channel.as_deref(), Some("contract_test"));
        assert_eq!(batch.note.as_deref(), Some("Golden batch"));
        assert_eq!(batch.reason, "contract fixture");

        let request: CodeActionInput =
            serde_json::from_value(golden["activationCodeExpireRequest"].clone())
                .expect("Admin UI expiry request must match the provider contract");
        assert_eq!(request.reason, "contract ended");
        assert_eq!(request.max_redemptions, None);
        assert_eq!(request.expires_at.as_deref(), Some("1700000500"));
        assert_eq!(
            request
                .expires_at
                .as_deref()
                .map(|value| parse_optional_expiry_time(value, 1_000))
                .transpose()
                .expect("golden expiry must parse")
                .flatten(),
            Some(1_700_000_500)
        );

        assert!(
            serde_json::from_value::<CodeActionInput>(json!({
                "reason": "contract ended",
                "maxRedemptions": null,
                "expiresAt": 1_700_000_500_i64,
            }))
            .is_err(),
            "expiresAt has one wire type: an expiry expression string"
        );
    }
}
