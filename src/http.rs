use std::sync::Arc;

use axum::{
    Form, Json, Router,
    body::Body,
    error_handling::HandleErrorLayer,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, Request, Response, StatusCode, header},
    middleware,
    middleware::Next,
    response::{Html, IntoResponse, Redirect},
    routing::{delete, get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use tower::{BoxError, ServiceBuilder};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::{DefaultOnFailure, DefaultOnRequest, DefaultOnResponse, TraceLayer},
};

use crate::{
    billing::CustomerPaymentSubmission,
    config::{HttpLogConfig, HttpServerConfig},
    contracts::{
        ActivationVerificationRequest, ChallengeRequest, DeviceProof, DeviceRegistrationRequest,
        DeviceRemovalRequest, EntitlementRefreshRequest, EntitlementStatusRequest, ErrorResponse,
        RefreshSession, RegisteredDevicePageRequest, SessionRecoveryChallengeRequest,
        SessionRecoveryRequest,
    },
    error::{ApiError, Result},
    metrics::{RuntimeMetrics, RuntimeRole, track_http_metrics},
    service::{LicenseService, OAuthAuthorizationRequest},
    team::{
        AcceptMemberDeviceEnrollment, AcceptTeamInvitation, CreateTeamInvitation, LeaveWorkspace,
        TeamMemberPageRequest, TeamOperationRequest, TransferWorkspaceOwnership,
        UpdateWorkspaceMember,
    },
    webhooks::{
        CreateWebhookEndpoint, DeleteWebhookEndpoint, RotateWebhookSecret, UpdateWebhookEndpoint,
    },
    workspace::{
        AdvanceWorkspaceCheckpoint, CONFIGURATION_HTTP_BODY_LIMIT, CreateSharedConfiguration,
        CreateWorkspaceAlertRule, PublishSharedConfiguration, ReviseSharedConfiguration,
        SharedConfigurationContentRequest, SharedConfigurationPageRequest,
        UpdateWorkspaceAlertRule, VersionedWorkspaceMutation, WorkspaceAlertRulePageRequest,
        WorkspaceAuditPageRequest, WorkspaceIncidentPageRequest, WorkspaceSyncFeedRequest,
    },
};

const DEVICE_PROOF_HEADER: &str = "x-camellia-device-proof";
const DEVICE_PROOF_HEADER_MAX_BYTES: usize = 4 * 1024;
const PUBLIC_CONTENT_SECURITY_POLICY: &str = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self' camellia-nexus: http://127.0.0.1:*/auth/callback; base-uri 'none'; frame-ancestors 'none'";

pub fn router(
    service: LicenseService,
    allowed_origins: Vec<String>,
    http_log: HttpLogConfig,
    runtime: HttpServerConfig,
) -> Router {
    router_with_metrics(
        service,
        allowed_origins,
        http_log,
        runtime,
        RuntimeMetrics::new(RuntimeRole::Public),
    )
}

pub fn router_with_metrics(
    service: LicenseService,
    allowed_origins: Vec<String>,
    http_log: HttpLogConfig,
    runtime: HttpServerConfig,
    metrics: RuntimeMetrics,
) -> Router {
    let state = Arc::new(service);
    let http_level = http_log.level.as_tracing_level();
    let failure_level = http_log.failure_level.as_tracing_level();
    let business = Router::new()
        .route(
            "/oauth/authorize",
            get(oauth_authorize).post(oauth_authorize_submit),
        )
        .route("/v1/devices/register", post(register_device))
        .route("/v1/activations/confirm", post(confirm_activation))
        .route("/v1/activations/verify", post(verify_activation))
        .route("/v1/entitlements/challenge", post(issue_challenge))
        .route("/v1/entitlements/refresh", post(refresh_entitlement))
        .route("/v1/entitlements/status", post(entitlement_status))
        .route(
            "/v1/session/recovery/challenge",
            post(issue_session_recovery_challenge),
        )
        .route("/v1/session/recovery", post(recover_session))
        .route("/v1/devices", get(list_devices))
        .route("/v1/devices/{device_id}", delete(remove_device))
        .route(
            "/v1/devices/{device_id}/removals/{operation_id}",
            get(device_removal_status),
        )
        .route("/v1/session/logout", post(logout))
        .route("/v1/billing/summary", get(customer_billing_summary))
        .route("/v1/billing/payment-claims", post(submit_customer_payment))
        .route("/v1/team/profile", get(team_profile))
        .route("/v1/team/members", get(team_members))
        .route(
            "/v1/team/members/{member_id}",
            axum::routing::patch(update_team_member),
        )
        .route(
            "/v1/team/members/{member_id}/device-enrollments",
            post(create_team_member_device_enrollment),
        )
        .route("/v1/team/invitations", post(create_team_invitation))
        .route("/v1/team/invitations/accept", post(accept_team_invitation))
        .route(
            "/v1/team/operations/{operation_id}",
            get(team_leave_operation_status),
        )
        .route(
            "/v1/team/device-enrollments",
            post(create_team_device_enrollment),
        )
        .route(
            "/v1/team/device-enrollments/accept",
            post(accept_team_device_enrollment),
        )
        .route("/v1/team/leave", post(leave_team_workspace))
        .route("/v1/team/ownership-transfer", post(transfer_team_ownership))
        .route(
            "/v1/workspace/configurations",
            get(workspace_configurations).merge(post(create_workspace_configuration).layer(
                axum::extract::DefaultBodyLimit::max(CONFIGURATION_HTTP_BODY_LIMIT),
            )),
        )
        .route(
            "/v1/workspace/configurations/{document_id}",
            get(workspace_configuration_content).delete(delete_workspace_configuration),
        )
        .route(
            "/v1/workspace/configurations/{document_id}/revisions",
            post(revise_workspace_configuration).layer(axum::extract::DefaultBodyLimit::max(
                CONFIGURATION_HTTP_BODY_LIMIT,
            )),
        )
        .route(
            "/v1/workspace/configurations/{document_id}/publish",
            post(publish_workspace_configuration),
        )
        .route(
            "/v1/workspace/configurations/{document_id}/restore",
            post(restore_workspace_configuration),
        )
        .route(
            "/v1/workspace/configurations/{document_id}/purge",
            post(purge_workspace_configuration),
        )
        .route("/v1/workspace/sync/changes", get(workspace_sync_feed))
        .route(
            "/v1/workspace/sync/checkpoint",
            get(workspace_device_checkpoint).post(advance_workspace_checkpoint),
        )
        .route(
            "/v1/workspace/alerts/rules",
            get(workspace_alert_rules).post(create_workspace_alert_rule),
        )
        .route(
            "/v1/workspace/alerts/rules/{rule_id}",
            axum::routing::patch(update_workspace_alert_rule).delete(delete_workspace_alert_rule),
        )
        .route(
            "/v1/workspace/alerts/incidents",
            get(workspace_alert_incidents),
        )
        .route(
            "/v1/workspace/alerts/incidents/{incident_id}/acknowledge",
            post(acknowledge_workspace_alert_incident),
        )
        .route(
            "/v1/workspace/alerts/incidents/{incident_id}/resolve",
            post(resolve_workspace_alert_incident),
        )
        .route(
            "/v1/workspace/audit/event-types",
            get(workspace_audit_event_types),
        )
        .route("/v1/workspace/audit/events", get(workspace_audit_events))
        .route("/v1/workspace/audit/export", get(workspace_audit_export))
        .route(
            "/v1/workspace/webhooks",
            get(workspace_webhook_endpoints).post(create_workspace_webhook_endpoint),
        )
        .route(
            "/v1/workspace/webhooks/deliveries",
            get(workspace_webhook_deliveries),
        )
        .route(
            "/v1/workspace/webhooks/{endpoint_id}",
            axum::routing::patch(update_workspace_webhook_endpoint)
                .delete(delete_workspace_webhook_endpoint),
        )
        .route(
            "/v1/workspace/webhooks/{endpoint_id}/rotate-secret",
            post(rotate_workspace_webhook_secret),
        )
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(handle_middleware_error))
                .load_shed()
                .concurrency_limit(runtime.max_in_flight)
                .timeout(runtime.request_timeout),
        );
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .merge(business)
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::map_response(normalize_framework_error))
        .layer(middleware::from_fn_with_state(metrics, track_http_metrics))
        .layer(middleware::from_fn(security_headers))
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(middleware::from_fn(crate::request_id::sanitize_request_id))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(move |request: &Request<Body>| {
                    crate::request_id::http_request_span(http_level, request)
                })
                .on_request(DefaultOnRequest::new().level(http_level))
                .on_response(DefaultOnResponse::new().level(http_level))
                .on_failure(DefaultOnFailure::new().level(failure_level)),
        )
        .layer(cors(allowed_origins))
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

async fn not_found() -> Response<Body> {
    framework_error_response(
        StatusCode::NOT_FOUND,
        "not_found",
        "The requested license service endpoint does not exist.",
    )
}

async fn method_not_allowed() -> Response<Body> {
    framework_error_response(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "The requested HTTP method is not allowed for this endpoint.",
    )
}

async fn normalize_framework_error(response: Response<Body>) -> Response<Body> {
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if content_type.starts_with("application/json") || content_type.starts_with("text/html") {
        return response;
    }
    match status {
        StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => framework_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The request body or query is invalid.",
        ),
        StatusCode::PAYLOAD_TOO_LARGE => framework_error_response(
            status,
            "request_too_large",
            "The request body exceeds the allowed size.",
        ),
        _ => response,
    }
}

fn framework_error_response(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
) -> Response<Body> {
    (
        status,
        Json(ErrorResponse {
            code,
            message,
            client_version_policy: None,
        }),
    )
        .into_response()
}

async fn readyz(State(service): State<Arc<LicenseService>>) -> Response<Body> {
    let ready = tokio::time::timeout(std::time::Duration::from_secs(2), service.readiness_check())
        .await
        .is_ok_and(|result| result.is_ok());
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

async fn handle_middleware_error(error: BoxError) -> Response<Body> {
    let timed_out = error.is::<tower::timeout::error::Elapsed>();
    let status = if timed_out {
        StatusCode::GATEWAY_TIMEOUT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let mut response = (
        status,
        Json(ErrorResponse {
            code: if timed_out {
                "request_timeout"
            } else {
                "service_overloaded"
            },
            message: if timed_out {
                "The license service request timed out."
            } else {
                "The license service is temporarily overloaded."
            },
            client_version_policy: None,
        }),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct OAuthAuthorizeParams {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct OAuthAuthorizeForm {
    activation_code: String,
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
    code_challenge: String,
    code_challenge_method: String,
}

impl OAuthAuthorizeParams {
    fn to_request(&self) -> OAuthAuthorizationRequest {
        OAuthAuthorizationRequest {
            response_type: self.response_type.clone().unwrap_or_default(),
            client_id: self.client_id.clone().unwrap_or_default(),
            redirect_uri: self.redirect_uri.clone().unwrap_or_default(),
            scope: self.scope.clone().unwrap_or_default(),
            state: self.state.clone().unwrap_or_default(),
            code_challenge: self.code_challenge.clone().unwrap_or_default(),
            code_challenge_method: self.code_challenge_method.clone().unwrap_or_default(),
        }
    }
}

impl OAuthAuthorizeForm {
    fn to_request(&self) -> OAuthAuthorizationRequest {
        OAuthAuthorizationRequest {
            response_type: self.response_type.clone(),
            client_id: self.client_id.clone(),
            redirect_uri: self.redirect_uri.clone(),
            scope: self.scope.clone(),
            state: self.state.clone(),
            code_challenge: self.code_challenge.clone(),
            code_challenge_method: self.code_challenge_method.clone(),
        }
    }
}

async fn oauth_authorize(
    State(service): State<Arc<LicenseService>>,
    Query(query): Query<OAuthAuthorizeParams>,
) -> Response<Body> {
    if service
        .validate_authorization_request(&query.to_request())
        .is_err()
    {
        return invalid_authorization_response();
    }
    Html(render_authorization_page(query, None)).into_response()
}

async fn oauth_authorize_submit(
    State(service): State<Arc<LicenseService>>,
    Form(form): Form<OAuthAuthorizeForm>,
) -> Response<Body> {
    let request = form.to_request();
    match service
        .create_authorization_redirect(&form.activation_code, request)
        .await
    {
        Ok(location) => authorization_success_response(&location),
        Err(ApiError::InvalidRequest) => invalid_authorization_response(),
        Err(error) if authorization_error_message(&error).is_some() => {
            let message = authorization_error_message(&error).expect("matched message");
            (
                StatusCode::BAD_REQUEST,
                Html(render_authorization_page(
                    OAuthAuthorizeParams {
                        response_type: Some(form.response_type),
                        client_id: Some(form.client_id),
                        redirect_uri: Some(form.redirect_uri),
                        scope: Some(form.scope),
                        state: Some(form.state),
                        code_challenge: Some(form.code_challenge),
                        code_challenge_method: Some(form.code_challenge_method),
                    },
                    Some(message),
                )),
            )
                .into_response()
        }
        Err(error) => error.into_response(),
    }
}

fn authorization_error_message(error: &ApiError) -> Option<&'static str> {
    match error {
        ApiError::AuthorizationRequired | ApiError::ActivationCodeInvalid => {
            Some("We could not verify this activation code. Check it and try again.")
        }
        ApiError::ActivationCodeExpired => {
            Some("This activation code has expired. Request a new code and try again.")
        }
        ApiError::ActivationCodeConsumed => Some(
            "This activation code has already been used. Request a new code or contact support.",
        ),
        ApiError::ActivationCodeRevoked => {
            Some("This activation code is no longer valid. Request a new code or contact support.")
        }
        ApiError::AccountSuspended => {
            Some("This license account is suspended. Contact the license administrator or support.")
        }
        ApiError::AccountDenylisted => {
            Some("This license account is disabled. Contact support if this is unexpected.")
        }
        ApiError::LicensePastDue => {
            Some("This license payment is past due. Update billing before trying again.")
        }
        ApiError::LicenseCanceled => {
            Some("This license has been canceled. Renew it or use another activation code.")
        }
        ApiError::LicenseExpired => {
            Some("This license has expired. Renew it or use another activation code.")
        }
        _ => None,
    }
}

fn invalid_authorization_response() -> Response<Body> {
    (
        StatusCode::BAD_REQUEST,
        Html(render_invalid_authorization_page()),
    )
        .into_response()
}

fn authorization_success_response(location: &str) -> Response<Body> {
    Redirect::to(location).into_response()
}

async fn register_device(
    State(service): State<Arc<LicenseService>>,
    Json(request): Json<DeviceRegistrationRequest>,
) -> Result<Json<crate::contracts::DeviceRegistrationResponse>> {
    service.register_device(request).await.map(Json)
}

async fn confirm_activation(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
) -> Result<Json<crate::contracts::DeviceActivationConfirmationResponse>> {
    service
        .confirm_activation(&bearer_session(&headers)?)
        .await
        .map(Json)
}

async fn verify_activation(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
    Json(request): Json<ActivationVerificationRequest>,
) -> Result<Json<crate::contracts::ActivationVerificationResponse>> {
    service
        .verify_activation(&bearer_session(&headers)?, request)
        .await
        .map(Json)
}

async fn issue_challenge(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
    Json(request): Json<ChallengeRequest>,
) -> Result<Json<crate::contracts::DeviceChallenge>> {
    service
        .issue_challenge(&bearer_session(&headers)?, request)
        .await
        .map(Json)
}

async fn refresh_entitlement(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
    Json(request): Json<EntitlementRefreshRequest>,
) -> Result<Json<crate::contracts::EntitlementRefreshResponse>> {
    service
        .refresh_entitlement(&bearer_session(&headers)?, request)
        .await
        .map(Json)
}

async fn entitlement_status(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
    Json(request): Json<EntitlementStatusRequest>,
) -> Result<Json<crate::contracts::EntitlementStatusResponse>> {
    service
        .entitlement_status(&bearer_session(&headers)?, request)
        .await
        .map(Json)
}

async fn customer_billing_summary(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
) -> Result<Json<crate::billing::BillingSummary>> {
    service
        .customer_billing_summary_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
        )
        .await
        .map(Json)
}

async fn submit_customer_payment(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
    Json(submission): Json<CustomerPaymentSubmission>,
) -> Result<Json<crate::billing::ManualPaymentClaim>> {
    service
        .submit_customer_payment_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            submission,
        )
        .await
        .map(Json)
}

async fn team_profile(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
) -> Result<Json<crate::team::TeamProfile>> {
    service
        .team_profile_authenticated(&bearer_session(&headers)?, &device_proof(&headers)?)
        .await
        .map(Json)
}

async fn team_members(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
    Query(request): Query<TeamMemberPageRequest>,
) -> Result<Json<crate::team::TeamMemberPage>> {
    service
        .team_members_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            request,
        )
        .await
        .map(Json)
}

async fn create_team_invitation(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
    Json(request): Json<CreateTeamInvitation>,
) -> Result<Json<crate::team::TeamInvitation>> {
    service
        .create_team_invitation_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            request,
        )
        .await
        .map(Json)
}

async fn accept_team_invitation(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
    Json(request): Json<AcceptTeamInvitation>,
) -> Result<Json<crate::team::TeamProfile>> {
    service
        .accept_team_invitation_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            request,
        )
        .await
        .map(Json)
}

async fn update_team_member(
    State(service): State<Arc<LicenseService>>,
    Path(member_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<UpdateWorkspaceMember>,
) -> Result<Json<crate::team::WorkspaceMember>> {
    service
        .update_team_member_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            &member_id,
            request,
        )
        .await
        .map(Json)
}

async fn create_team_device_enrollment(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
    Json(request): Json<TeamOperationRequest>,
) -> Result<Json<crate::team::MemberDeviceEnrollment>> {
    service
        .create_team_device_enrollment_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            request,
        )
        .await
        .map(Json)
}

async fn create_team_member_device_enrollment(
    State(service): State<Arc<LicenseService>>,
    Path(member_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<TeamOperationRequest>,
) -> Result<Json<crate::team::MemberDeviceEnrollment>> {
    service
        .create_team_member_device_enrollment_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            &member_id,
            request,
        )
        .await
        .map(Json)
}

async fn accept_team_device_enrollment(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
    Json(request): Json<AcceptMemberDeviceEnrollment>,
) -> Result<Json<crate::team::TeamProfile>> {
    service
        .accept_team_device_enrollment_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            request,
        )
        .await
        .map(Json)
}

async fn team_leave_operation_status(
    State(service): State<Arc<LicenseService>>,
    Path(operation_id): Path<String>,
    headers: HeaderMap,
    Query(request): Query<TeamLeaveOperationStatusQuery>,
) -> Result<Json<crate::team::TeamOperationStatusResponse>> {
    service
        .team_leave_operation_status(
            &bearer_session(&headers)?,
            &operation_id,
            &request.member_id,
            request.row_version,
        )
        .await
        .map(Json)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TeamLeaveOperationStatusQuery {
    member_id: String,
    row_version: u64,
}

async fn leave_team_workspace(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
    Json(request): Json<LeaveWorkspace>,
) -> Result<StatusCode> {
    service
        .leave_team_workspace_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            request,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn transfer_team_ownership(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
    Json(request): Json<TransferWorkspaceOwnership>,
) -> Result<Json<crate::team::OwnershipTransferResult>> {
    service
        .transfer_team_ownership_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            request,
        )
        .await
        .map(Json)
}

async fn workspace_configurations(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
    Query(request): Query<SharedConfigurationPageRequest>,
) -> Result<Json<crate::workspace::SharedConfigurationPage>> {
    service
        .shared_configurations_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            request,
        )
        .await
        .map(Json)
}

async fn workspace_configuration_content(
    State(service): State<Arc<LicenseService>>,
    Path(document_id): Path<String>,
    headers: HeaderMap,
    Query(request): Query<SharedConfigurationContentRequest>,
) -> Result<Json<crate::workspace::SharedConfigurationContent>> {
    service
        .shared_configuration_content_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            &document_id,
            request,
        )
        .await
        .map(Json)
}

async fn create_workspace_configuration(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
    Json(request): Json<CreateSharedConfiguration>,
) -> Result<Json<crate::workspace::WorkspaceMutationReceipt>> {
    service
        .create_shared_configuration_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            request,
        )
        .await
        .map(Json)
}

async fn revise_workspace_configuration(
    State(service): State<Arc<LicenseService>>,
    Path(document_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ReviseSharedConfiguration>,
) -> Result<Json<crate::workspace::WorkspaceMutationReceipt>> {
    service
        .revise_shared_configuration_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            &document_id,
            request,
        )
        .await
        .map(Json)
}

async fn publish_workspace_configuration(
    State(service): State<Arc<LicenseService>>,
    Path(document_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<PublishSharedConfiguration>,
) -> Result<Json<crate::workspace::WorkspaceMutationReceipt>> {
    service
        .publish_shared_configuration_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            &document_id,
            request,
        )
        .await
        .map(Json)
}

async fn delete_workspace_configuration(
    State(service): State<Arc<LicenseService>>,
    Path(document_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<VersionedWorkspaceMutation>,
) -> Result<Json<crate::workspace::WorkspaceMutationReceipt>> {
    service
        .delete_shared_configuration_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            &document_id,
            request,
        )
        .await
        .map(Json)
}

async fn restore_workspace_configuration(
    State(service): State<Arc<LicenseService>>,
    Path(document_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<VersionedWorkspaceMutation>,
) -> Result<Json<crate::workspace::WorkspaceMutationReceipt>> {
    service
        .restore_shared_configuration_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            &document_id,
            request,
        )
        .await
        .map(Json)
}

async fn purge_workspace_configuration(
    State(service): State<Arc<LicenseService>>,
    Path(document_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<VersionedWorkspaceMutation>,
) -> Result<Json<crate::workspace::WorkspaceMutationReceipt>> {
    service
        .purge_shared_configuration_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            &document_id,
            request,
        )
        .await
        .map(Json)
}

async fn workspace_sync_feed(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
    Query(request): Query<WorkspaceSyncFeedRequest>,
) -> Result<Json<crate::workspace::WorkspaceSyncFeed>> {
    service
        .workspace_sync_feed_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            request,
        )
        .await
        .map(Json)
}

async fn workspace_device_checkpoint(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
) -> Result<Json<Option<crate::workspace::WorkspaceDeviceCheckpoint>>> {
    service
        .workspace_device_checkpoint_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
        )
        .await
        .map(Json)
}

async fn advance_workspace_checkpoint(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
    Json(request): Json<AdvanceWorkspaceCheckpoint>,
) -> Result<Json<crate::workspace::WorkspaceMutationReceipt>> {
    service
        .advance_workspace_checkpoint_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            request,
        )
        .await
        .map(Json)
}

async fn workspace_alert_rules(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
    Query(request): Query<WorkspaceAlertRulePageRequest>,
) -> Result<Json<crate::workspace::WorkspaceAlertRulePage>> {
    service
        .workspace_alert_rules_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            request,
        )
        .await
        .map(Json)
}

async fn create_workspace_alert_rule(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
    Json(request): Json<CreateWorkspaceAlertRule>,
) -> Result<Json<crate::workspace::WorkspaceMutationReceipt>> {
    service
        .create_workspace_alert_rule_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            request,
        )
        .await
        .map(Json)
}

async fn update_workspace_alert_rule(
    State(service): State<Arc<LicenseService>>,
    Path(rule_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<UpdateWorkspaceAlertRule>,
) -> Result<Json<crate::workspace::WorkspaceMutationReceipt>> {
    service
        .update_workspace_alert_rule_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            &rule_id,
            request,
        )
        .await
        .map(Json)
}

async fn delete_workspace_alert_rule(
    State(service): State<Arc<LicenseService>>,
    Path(rule_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<VersionedWorkspaceMutation>,
) -> Result<Json<crate::workspace::WorkspaceMutationReceipt>> {
    service
        .delete_workspace_alert_rule_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            &rule_id,
            request,
        )
        .await
        .map(Json)
}

async fn workspace_alert_incidents(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
    Query(request): Query<WorkspaceIncidentPageRequest>,
) -> Result<Json<crate::workspace::WorkspaceIncidentPage>> {
    service
        .workspace_alert_incidents_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            request,
        )
        .await
        .map(Json)
}

async fn acknowledge_workspace_alert_incident(
    State(service): State<Arc<LicenseService>>,
    Path(incident_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<VersionedWorkspaceMutation>,
) -> Result<Json<crate::workspace::WorkspaceMutationReceipt>> {
    service
        .acknowledge_workspace_incident_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            &incident_id,
            request,
        )
        .await
        .map(Json)
}

async fn resolve_workspace_alert_incident(
    State(service): State<Arc<LicenseService>>,
    Path(incident_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<VersionedWorkspaceMutation>,
) -> Result<Json<crate::workspace::WorkspaceMutationReceipt>> {
    service
        .resolve_workspace_incident_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            &incident_id,
            request,
        )
        .await
        .map(Json)
}

async fn workspace_audit_events(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
    Query(request): Query<WorkspaceAuditPageRequest>,
) -> Result<Json<crate::workspace::WorkspaceAuditPage>> {
    service
        .workspace_audit_page_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            request,
        )
        .await
        .map(Json)
}

async fn workspace_audit_event_types(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
) -> Result<Json<crate::workspace::WorkspaceAuditEventTypes>> {
    service
        .workspace_audit_event_types_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
        )
        .await
        .map(Json)
}

async fn workspace_audit_export(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
    Query(request): Query<WorkspaceAuditPageRequest>,
) -> Result<Json<crate::workspace::WorkspaceAuditExport>> {
    service
        .workspace_audit_export_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            request,
        )
        .await
        .map(Json)
}

async fn workspace_webhook_endpoints(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
) -> Result<Json<Vec<crate::webhooks::WebhookEndpoint>>> {
    service
        .workspace_webhook_endpoints_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
        )
        .await
        .map(Json)
}

async fn create_workspace_webhook_endpoint(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
    Json(request): Json<CreateWebhookEndpoint>,
) -> Result<Json<crate::webhooks::WebhookSecretResult>> {
    service
        .create_workspace_webhook_endpoint_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            request,
        )
        .await
        .map(Json)
}

async fn update_workspace_webhook_endpoint(
    State(service): State<Arc<LicenseService>>,
    Path(endpoint_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<UpdateWebhookEndpoint>,
) -> Result<Json<crate::webhooks::WebhookEndpoint>> {
    service
        .update_workspace_webhook_endpoint_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            &endpoint_id,
            request,
        )
        .await
        .map(Json)
}

async fn rotate_workspace_webhook_secret(
    State(service): State<Arc<LicenseService>>,
    Path(endpoint_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<RotateWebhookSecret>,
) -> Result<Json<crate::webhooks::WebhookSecretResult>> {
    service
        .rotate_workspace_webhook_secret_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            &endpoint_id,
            request,
        )
        .await
        .map(Json)
}

async fn delete_workspace_webhook_endpoint(
    State(service): State<Arc<LicenseService>>,
    Path(endpoint_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<DeleteWebhookEndpoint>,
) -> Result<Json<crate::webhooks::WebhookDeletion>> {
    service
        .delete_workspace_webhook_endpoint_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            &endpoint_id,
            request,
        )
        .await
        .map(Json)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WebhookDeliveryQuery {
    endpoint_id: Option<String>,
    limit: u16,
}

async fn workspace_webhook_deliveries(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
    Query(request): Query<WebhookDeliveryQuery>,
) -> Result<Json<Vec<crate::webhooks::WebhookDeliverySummary>>> {
    service
        .workspace_webhook_deliveries_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            request.endpoint_id.as_deref(),
            request.limit,
        )
        .await
        .map(Json)
}

async fn issue_session_recovery_challenge(
    State(service): State<Arc<LicenseService>>,
    Json(request): Json<SessionRecoveryChallengeRequest>,
) -> Result<Json<crate::contracts::DeviceChallenge>> {
    service
        .issue_session_recovery_challenge(request)
        .await
        .map(Json)
}

async fn recover_session(
    State(service): State<Arc<LicenseService>>,
    Json(request): Json<SessionRecoveryRequest>,
) -> Result<Json<crate::contracts::SessionRecoveryResponse>> {
    service.recover_session(request).await.map(Json)
}

async fn list_devices(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
    request: std::result::Result<
        Query<RegisteredDevicePageRequest>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Result<Json<crate::contracts::RegisteredDevicePage>> {
    let Query(request) = request.map_err(|_| ApiError::InvalidRequest)?;
    service
        .list_devices_authenticated(
            &bearer_session(&headers)?,
            &device_proof(&headers)?,
            request,
        )
        .await
        .map(Json)
}

async fn remove_device(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
    Json(request): Json<DeviceRemovalRequest>,
) -> Result<()> {
    service
        .remove_device(&bearer_session(&headers)?, &device_id, request)
        .await
}

async fn device_removal_status(
    State(service): State<Arc<LicenseService>>,
    headers: HeaderMap,
    Path((device_id, operation_id)): Path<(String, String)>,
) -> Result<Json<crate::contracts::DeviceRemovalStatusResponse>> {
    service
        .device_removal_status(&bearer_session(&headers)?, &device_id, &operation_id)
        .await
        .map(Json)
}

async fn logout(State(service): State<Arc<LicenseService>>, headers: HeaderMap) -> Result<()> {
    service.logout(bearer_session(&headers)?).await
}

fn bearer_session(headers: &HeaderMap) -> Result<RefreshSession> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::AuthorizationRequired)?;
    let Some(token) = value.strip_prefix("Bearer ") else {
        return Err(ApiError::AuthorizationRequired);
    };
    Ok(RefreshSession(token.to_owned()))
}

fn device_proof(headers: &HeaderMap) -> Result<DeviceProof> {
    let mut values = headers.get_all(DEVICE_PROOF_HEADER).iter();
    let value = values.next().ok_or(ApiError::AuthorizationRequired)?;
    if values.next().is_some() {
        return Err(ApiError::InvalidRequest);
    }
    let encoded = value.to_str().map_err(|_| ApiError::InvalidRequest)?;
    if encoded.is_empty() || encoded.len() > DEVICE_PROOF_HEADER_MAX_BYTES {
        return Err(ApiError::InvalidRequest);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ApiError::InvalidRequest)?;
    serde_json::from_slice(&bytes).map_err(|_| ApiError::InvalidRequest)
}

fn cors(allowed_origins: Vec<String>) -> CorsLayer {
    let origins = allowed_origins
        .into_iter()
        .filter_map(|origin| origin.parse::<HeaderValue>().ok())
        .collect::<Vec<_>>();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PATCH,
            axum::http::Method::DELETE,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            header::HeaderName::from_static(DEVICE_PROOF_HEADER),
            header::HeaderName::from_static("x-request-id"),
        ])
}

async fn security_headers(request: Request<Body>, next: Next) -> Response<Body> {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(header::EXPIRES, HeaderValue::from_static("0"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-site"),
    );
    headers.insert(
        header::HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("interest-cohort=()"),
    );
    headers.insert(
        header::HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(PUBLIC_CONTENT_SECURITY_POLICY),
    );
    response
}

fn render_authorization_page(query: OAuthAuthorizeParams, error: Option<&str>) -> String {
    let request = query.to_request();
    let error = error
        .map(|message| format!("<div class=\"error\">{}</div>", escape_html(message)))
        .unwrap_or_default();
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Camellia Nexus Activation</title>
<style>
:root {{ color-scheme: light dark; --bg: #f5f5f2; --surface: rgba(255,255,255,.86); --text: #171a1f; --muted: #667085; --line: rgba(16,24,40,.12); --accent: #2563eb; --accent-press: #1d4ed8; --danger: #b42318; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg: #111317; --surface: rgba(28,31,36,.9); --text: #f4f6f8; --muted: #a7b0bd; --line: rgba(255,255,255,.12); --accent: #6ea8ff; --accent-press: #8bbaff; --danger: #ff9b91; }} }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; background: radial-gradient(circle at top left, rgba(37,99,235,.10), transparent 32rem), var(--bg); color: var(--text); font-family: "Segoe UI Variable", "Segoe UI", system-ui, sans-serif; }}
main {{ width: min(92vw, 430px); padding: 32px; border: 1px solid var(--line); border-radius: 22px; background: var(--surface); box-shadow: 0 22px 70px rgba(0,0,0,.18); backdrop-filter: blur(18px); }}
h1 {{ margin: 0 0 8px; font-size: 24px; letter-spacing: -.02em; }}
p {{ margin: 0 0 24px; color: var(--muted); line-height: 1.5; }}
label {{ display: block; margin: 0 0 8px; font-size: 13px; font-weight: 650; }}
input[type=text] {{ width: 100%; height: 42px; padding: 0 12px; border-radius: 12px; border: 1px solid var(--line); background: rgba(127,127,127,.08); color: var(--text); font: inherit; outline: none; transition: border-color .16s ease, box-shadow .16s ease, background .16s ease; }}
input[type=text]:focus {{ border-color: var(--accent); box-shadow: 0 0 0 4px color-mix(in srgb, var(--accent) 18%, transparent); background: transparent; }}
button {{ width: 100%; height: 42px; margin-top: 16px; border: 0; border-radius: 12px; background: var(--accent); color: white; font: inherit; font-weight: 700; cursor: pointer; transition: background .16s ease, transform .16s ease; }}
button:hover {{ background: var(--accent-press); }}
button:active {{ transform: translateY(1px); }}
.error {{ margin: 0 0 16px; padding: 10px 12px; border-radius: 12px; color: var(--danger); background: color-mix(in srgb, var(--danger) 11%, transparent); font-size: 13px; }}
.meta {{ margin-top: 18px; color: var(--muted); font-size: 12px; }}
</style>
</head>
<body>
<main>
<h1>Activate Camellia Nexus</h1>
<p>Enter the activation code issued for this license. The desktop app will complete registration after approval.</p>
{error}
<form method="post" action="/oauth/authorize" autocomplete="off">
<label for="activation_code">Activation code</label>
<input id="activation_code" name="activation_code" type="text" maxlength="256" required autofocus spellcheck="false">
<input type="hidden" name="response_type" value="{response_type}">
<input type="hidden" name="client_id" value="{client_id}">
<input type="hidden" name="redirect_uri" value="{redirect_uri}">
<input type="hidden" name="scope" value="{scope}">
<input type="hidden" name="state" value="{state}">
<input type="hidden" name="code_challenge" value="{code_challenge}">
<input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
<button type="submit">Continue</button>
</form>
<div class="meta">Camellia Computing License Service</div>
</main>
</body>
</html>"#,
        error = error,
        response_type = escape_html(&request.response_type),
        client_id = escape_html(&request.client_id),
        redirect_uri = escape_html(&request.redirect_uri),
        scope = escape_html(&request.scope),
        state = escape_html(&request.state),
        code_challenge = escape_html(&request.code_challenge),
        code_challenge_method = escape_html(&request.code_challenge_method),
    )
}

fn render_invalid_authorization_page() -> String {
    r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Invalid Camellia Nexus Activation Request</title>
<style>
:root { color-scheme: light dark; --bg: #f5f5f2; --surface: rgba(255,255,255,.86); --text: #171a1f; --muted: #667085; --line: rgba(16,24,40,.12); --danger: #b42318; }
@media (prefers-color-scheme: dark) { :root { --bg: #111317; --surface: rgba(28,31,36,.9); --text: #f4f6f8; --muted: #a7b0bd; --line: rgba(255,255,255,.12); --danger: #ff9b91; } }
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: var(--bg); color: var(--text); font-family: "Segoe UI Variable", "Segoe UI", system-ui, sans-serif; }
main { width: min(92vw, 430px); padding: 32px; border: 1px solid var(--line); border-radius: 22px; background: var(--surface); box-shadow: 0 22px 70px rgba(0,0,0,.18); }
h1 { margin: 0 0 8px; color: var(--danger); font-size: 24px; }
p { margin: 0; color: var(--muted); line-height: 1.5; }
</style>
</head>
<body>
<main>
<h1>Activation request invalid</h1>
<p>Return to the Camellia Nexus desktop app and restart activation. Do not enter an activation code on this page.</p>
</main>
</body>
</html>"#
        .to_owned()
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
