use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use camellia_nexus_management_server::{
    AuthorizationPolicy, EntitlementSigner, LicenseRepository, LicenseService, MemoryRepository,
    config::{HttpServerConfig, LoggingConfig},
    contracts::{
        ActivationProofClaims, ActivationVerificationRequest, ActivationVerificationResponse,
        ChallengeRequest, ClientVersionPolicy, DeviceActivationConfirmationResponse,
        DeviceChallenge, DeviceProof, DeviceRegistrationMetadata, DeviceRegistrationRequest,
        DeviceRegistrationResponse, DeviceState, EntitlementRefreshRequest,
        EntitlementRefreshResponse, EntitlementStatusRequest, EntitlementStatusResponse,
        RegisteredDevicePage, SecretValue, SessionRecoveryChallengeRequest, SessionRecoveryRequest,
        SessionRecoveryResponse,
    },
    crypto::{pkce_s256_challenge, proof_payload, sha256_hex},
    domain::{
        Account, AccountState, ActivationCodeRecord, ActivationCodeStatus, Device, License,
        LicenseStatus,
    },
    router,
    service::SystemClock,
};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    elliptic_curve::Generate,
    pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
};
use serde::de::DeserializeOwned;
use sha2::Digest;
use tower::ServiceExt;
use url::Url;

const PKCE_VERIFIER: &str = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
const OAUTH_STATE: &str = "0123456789abcdef0123456789abcdef";

fn test_signing_key() -> SigningKey {
    SigningKey::try_generate().expect("test signing key entropy")
}

#[tokio::test]
async fn all_http_responses_prevent_credential_caching() {
    let app = test_router();
    for uri in ["/healthz", "/v1/devices"] {
        let response = app
            .clone()
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store, max-age=0"
        );
        assert_eq!(response.headers().get(header::PRAGMA).unwrap(), "no-cache");
        assert_eq!(response.headers().get(header::EXPIRES).unwrap(), "0");
    }
}

#[tokio::test]
async fn request_ids_are_canonicalized_before_logging_and_propagation() {
    let response = test_router()
        .clone()
        .oneshot(
            Request::get("/healthz")
                .header("x-request-id", "untrusted-request-id")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let generated = response
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .expect("generated request id");
    assert_ne!(generated, "untrusted-request-id");
    assert_eq!(
        uuid::Uuid::parse_str(generated).unwrap().to_string(),
        generated
    );

    let supplied = "01234567-89ab-4def-8123-456789abcdef";
    let response = test_router()
        .oneshot(
            Request::get("/healthz")
                .header("x-request-id", supplied)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
        Some(supplied)
    );
}

#[tokio::test]
async fn framework_rejections_use_the_public_error_envelope() {
    let app = test_router();
    let requests = [
        (
            Request::post("/v1/devices/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{"))
                .unwrap(),
            StatusCode::BAD_REQUEST,
            "invalid_request",
        ),
        (
            Request::get("/v1/not-a-real-endpoint")
                .body(Body::empty())
                .unwrap(),
            StatusCode::NOT_FOUND,
            "not_found",
        ),
        (
            Request::get("/v1/devices/register")
                .body(Body::empty())
                .unwrap(),
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
        ),
        (
            Request::post("/v1/devices/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(vec![b' '; 64 * 1024 + 1]))
                .unwrap(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "request_too_large",
        ),
    ];
    for (request, expected_status, expected_code) in requests {
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), expected_status);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store, max-age=0"
        );
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let body: serde_json::Value = read_json(response).await;
        assert_eq!(body["code"], expected_code);
        assert!(
            body["message"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
    }
}

#[tokio::test]
async fn cors_preflight_allows_device_proof_and_team_member_updates() {
    let response = test_router()
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/v1/team/members/member_example")
                .header(header::ORIGIN, "http://127.0.0.1:1420")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "PATCH")
                .header(
                    header::ACCESS_CONTROL_REQUEST_HEADERS,
                    "authorization,content-type,x-camellia-device-proof",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let methods = response
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_METHODS)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(methods.split(',').any(|method| method.trim() == "PATCH"));
    let headers = response
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(
        headers
            .split(',')
            .any(|name| { name.trim().eq_ignore_ascii_case("x-camellia-device-proof") })
    );
}

#[tokio::test]
async fn http_registration_challenge_and_refresh_flow() {
    let app = test_router();
    let device_key = test_signing_key();
    let device_id = uuid::Uuid::new_v4().to_string();
    let authorization_code = authorize(app.clone()).await;
    let registration = register_request(&device_key, &device_id, authorization_code);
    let response = post_json(app.clone(), "/v1/devices/register", None, &registration).await;
    assert_eq!(response.status(), StatusCode::OK);
    let registered: DeviceRegistrationResponse = read_json(response).await;

    let challenge_request = ChallengeRequest {
        device_id: device_id.clone(),
        requested_scope: "entitlement:refresh".into(),
    };
    let response = post_json(
        app.clone(),
        "/v1/entitlements/challenge",
        Some(&registered.refresh_session.0),
        &challenge_request,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let challenge: DeviceChallenge = read_json(response).await;
    let proof = sign_challenge(&device_key, &challenge, &device_id, "1.0.0");

    let response = post_json(
        app.clone(),
        "/v1/entitlements/refresh",
        Some(&registered.refresh_session.0),
        &EntitlementRefreshRequest { proof },
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let refreshed: EntitlementRefreshResponse = read_json(response).await;
    assert!(refreshed.entitlement.expose().matches('.').count() == 2);
    assert_ne!(
        registered.refresh_session.0.as_str(),
        refreshed.rotated_refresh_session.0.as_str()
    );

    let response = post_json(
        app.clone(),
        "/v1/entitlements/challenge",
        Some(&refreshed.rotated_refresh_session.0),
        &ChallengeRequest {
            device_id: device_id.clone(),
            requested_scope: "entitlement:status".into(),
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let challenge: DeviceChallenge = read_json(response).await;
    let proof = sign_challenge(&device_key, &challenge, &device_id, "1.0.0");
    let response = post_json(
        app.clone(),
        "/v1/entitlements/status",
        Some(&refreshed.rotated_refresh_session.0),
        &EntitlementStatusRequest { proof },
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let status: EntitlementStatusResponse = read_json(response).await;
    assert_eq!(status.device_state, DeviceState::Active);

    let response = app
        .oneshot(
            Request::get("/v1/entitlements/status")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", refreshed.rotated_refresh_session.0),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn http_upgrade_error_carries_policy_without_consuming_authorization_code() {
    let policy = ClientVersionPolicy {
        minimum_version: "2.0.0".into(),
        recommended_version: "2.1.0".into(),
        enforce_after: 0,
    };
    let service = LicenseService::with_clock_authorization_and_client_version_policy(
        Arc::new(MemoryRepository::default()),
        test_signer(),
        "https://license.test",
        "camellia-nexus-desktop",
        Arc::new(SystemClock::default()),
        AuthorizationPolicy::development(),
        policy.clone(),
    )
    .expect("version-policy service");
    let app = router(
        service,
        vec!["http://127.0.0.1:1420".into()],
        LoggingConfig::default().http,
        HttpServerConfig::default(),
    );
    let device_key = test_signing_key();
    let device_id = uuid::Uuid::new_v4().to_string();
    let authorization_code = authorize(app.clone()).await;
    let mut registration = register_request(&device_key, &device_id, authorization_code);
    let response = post_json(app.clone(), "/v1/devices/register", None, &registration).await;
    assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store, max-age=0"
    );
    let error: serde_json::Value = read_json(response).await;
    assert_eq!(error["code"], "client_upgrade_required");
    assert_eq!(
        error["clientVersionPolicy"],
        serde_json::to_value(&policy).unwrap()
    );

    registration.device.app_version = "2.0.0".into();
    let response = post_json(app, "/v1/devices/register", None, &registration).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn http_device_listing_uses_the_paginated_contract_and_validates_queries() {
    let app = test_router();
    let device_key = test_signing_key();
    let device_id = uuid::Uuid::new_v4().to_string();
    let authorization_code = authorize(app.clone()).await;
    let registration = register_request(&device_key, &device_id, authorization_code);
    let registered: DeviceRegistrationResponse =
        read_json(post_json(app.clone(), "/v1/devices/register", None, &registration).await).await;
    let challenge: DeviceChallenge = read_json(
        post_json(
            app.clone(),
            "/v1/entitlements/challenge",
            Some(&registered.refresh_session.0),
            &ChallengeRequest {
                device_id: device_id.clone(),
                requested_scope: "entitlement:refresh".to_owned(),
            },
        )
        .await,
    )
    .await;
    let refreshed: EntitlementRefreshResponse = read_json(
        post_json(
            app.clone(),
            "/v1/entitlements/refresh",
            Some(&registered.refresh_session.0),
            &EntitlementRefreshRequest {
                proof: sign_challenge(&device_key, &challenge, &device_id, "1.0.0"),
            },
        )
        .await,
    )
    .await;
    let bearer = &refreshed.rotated_refresh_session.0;

    let response = get_with_bearer(app.clone(), "/v1/devices?pageSize=1", bearer).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let error: serde_json::Value = read_json(response).await;
    assert_eq!(error["code"], "authorization_required");

    let wrong_scope = issue_device_proof(
        app.clone(),
        &device_key,
        &device_id,
        bearer,
        "billing:summary",
    )
    .await;
    let response =
        get_with_device_proof(app.clone(), "/v1/devices?pageSize=1", bearer, &wrong_scope).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error: serde_json::Value = read_json(response).await;
    assert_eq!(error["code"], "invalid_challenge");

    let proof =
        issue_device_proof(app.clone(), &device_key, &device_id, bearer, "device:list").await;
    let response =
        get_with_device_proof(app.clone(), "/v1/devices?pageSize=1", bearer, &proof).await;
    assert_eq!(response.status(), StatusCode::OK);
    let page: RegisteredDevicePage = read_json(response).await;
    assert_eq!(page.devices.len(), 1);
    assert_eq!(page.devices[0].device_id, device_id);
    assert!(page.next_cursor.is_none());

    let response =
        get_with_device_proof(app.clone(), "/v1/devices?pageSize=1", bearer, &proof).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error: serde_json::Value = read_json(response).await;
    assert_eq!(error["code"], "challenge_replay");

    for path in [
        "/v1/devices?pageSize=0".to_owned(),
        "/v1/devices?pageSize=101".to_owned(),
        "/v1/devices?cursor=AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA".to_owned(),
        "/v1/devices?unexpected=true".to_owned(),
    ] {
        let proof =
            issue_device_proof(app.clone(), &device_key, &device_id, bearer, "device:list").await;
        let response = get_with_device_proof(app.clone(), &path, bearer, &proof).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "path: {path}");
    }
}

#[tokio::test]
async fn http_device_proof_recovers_session_without_a_bearer() {
    let app = test_router();
    let device_key = test_signing_key();
    let device_id = uuid::Uuid::new_v4().to_string();
    let authorization_code = authorize(app.clone()).await;
    let registration = register_request(&device_key, &device_id, authorization_code);
    let response = post_json(app.clone(), "/v1/devices/register", None, &registration).await;
    assert_eq!(response.status(), StatusCode::OK);
    let registered: DeviceRegistrationResponse = read_json(response).await;
    let response = post_empty(
        app.clone(),
        "/v1/session/logout",
        Some(&registered.refresh_session.0),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let response = post_json(
        app.clone(),
        "/v1/session/recovery/challenge",
        None,
        &SessionRecoveryChallengeRequest {
            device_id: device_id.clone(),
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let challenge: DeviceChallenge = read_json(response).await;
    assert_eq!(challenge.requested_scope, "session:recover");
    let proof = sign_challenge(&device_key, &challenge, &device_id, "1.0.0");
    let response = post_json(
        app.clone(),
        "/v1/session/recovery",
        None,
        &SessionRecoveryRequest { proof },
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let recovered: SessionRecoveryResponse = read_json(response).await;
    assert_eq!(recovered.device_state, DeviceState::Active);

    let response = post_json(
        app.clone(),
        "/v1/entitlements/challenge",
        Some(&recovered.refresh_session.0),
        &ChallengeRequest {
            device_id: device_id.clone(),
            requested_scope: "entitlement:refresh".into(),
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let challenge: DeviceChallenge = read_json(response).await;
    let proof = sign_challenge(&device_key, &challenge, &device_id, "1.0.0");
    let response = post_json(
        app,
        "/v1/entitlements/refresh",
        Some(&recovered.refresh_session.0),
        &EntitlementRefreshRequest { proof },
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn recovery_challenge_does_not_expose_device_account_or_license_state() {
    let repository = Arc::new(MemoryRepository::default());
    let account = Account::active("recovery-oracle", 1);
    let mut license = License::default_pro(&account.id, 1);
    repository.upsert_account(account.clone()).await.unwrap();
    repository.upsert_license(license.clone()).await.unwrap();
    let device_key = test_signing_key();
    let device_id = uuid::Uuid::new_v4().to_string();
    let public_key_pem = device_key
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .expect("device public key");
    let device = Device {
        account_id: account.id.clone(),
        license_id: license.id.clone(),
        metadata: DeviceRegistrationMetadata {
            device_id: device_id.clone(),
            public_key_pem,
            public_key_thumbprint: "sha256:oracle-fixture".into(),
            platform: "test".into(),
            app_version: "1.0.0".into(),
            display_name: None,
        },
        state: DeviceState::Active,
        pending_activation_code_hash: None,
        pending_activation_expires_at: None,
        created_at: 1,
        last_seen_at: None,
    };
    repository.upsert_device(device.clone()).await.unwrap();
    let app = router(
        LicenseService::new(
            repository.clone(),
            test_signer(),
            "https://license.test",
            "camellia-nexus-desktop",
        ),
        vec!["http://127.0.0.1:1420".into()],
        LoggingConfig::default().http,
        HttpServerConfig::default(),
    );

    let unknown_id = uuid::Uuid::new_v4().to_string();
    let baseline = recovery_challenge_response(app.clone(), &unknown_id).await;
    assert_recovery_challenge_shape(&baseline);

    for state in [
        DeviceState::Active,
        DeviceState::PendingActivation,
        DeviceState::Removed,
        DeviceState::Revoked,
        DeviceState::Suspicious,
    ] {
        let mut state_device = device.clone();
        state_device.metadata.device_id = uuid::Uuid::new_v4().to_string();
        state_device.state = state;
        state_device.pending_activation_code_hash =
            (state == DeviceState::PendingActivation).then(|| "expired".into());
        state_device.pending_activation_expires_at =
            (state == DeviceState::PendingActivation).then_some(1);
        repository
            .upsert_device(state_device.clone())
            .await
            .unwrap();
        let response =
            recovery_challenge_response(app.clone(), &state_device.metadata.device_id).await;
        assert_recovery_challenge_shape(&response);
        assert_eq!(json_field_shape(&response), json_field_shape(&baseline));
    }

    for state in [AccountState::Suspended, AccountState::Denylisted] {
        let mut changed = account.clone();
        changed.state = state;
        repository.upsert_account(changed).await.unwrap();
        let response = recovery_challenge_response(app.clone(), &device_id).await;
        assert_recovery_challenge_shape(&response);
        assert_eq!(json_field_shape(&response), json_field_shape(&baseline));
    }
    repository.upsert_account(account).await.unwrap();

    for (status, expires_at) in [
        (LicenseStatus::PastDue, Some(1)),
        (LicenseStatus::Canceled, Some(1)),
        (LicenseStatus::Active, Some(1)),
    ] {
        license.status = status;
        license.expires_at = expires_at;
        repository.upsert_license(license.clone()).await.unwrap();
        let response = recovery_challenge_response(app.clone(), &device_id).await;
        assert_recovery_challenge_shape(&response);
        assert_eq!(json_field_shape(&response), json_field_shape(&baseline));
    }
}

#[tokio::test]
async fn recovery_rejects_unknown_replayed_and_invalid_proofs_identically() {
    let app = test_router();
    let device_key = test_signing_key();
    let device_id = uuid::Uuid::new_v4().to_string();
    let authorization_code = authorize(app.clone()).await;
    let registration = register_request(&device_key, &device_id, authorization_code);
    let registration_response =
        post_json(app.clone(), "/v1/devices/register", None, &registration).await;
    assert_eq!(registration_response.status(), StatusCode::OK);

    let challenge: DeviceChallenge = read_json(
        post_json(
            app.clone(),
            "/v1/session/recovery/challenge",
            None,
            &SessionRecoveryChallengeRequest {
                device_id: device_id.clone(),
            },
        )
        .await,
    )
    .await;
    let attacker = test_signing_key();
    let invalid = sign_challenge(&attacker, &challenge, &device_id, "1.0.0");
    let invalid_response = post_json(
        app.clone(),
        "/v1/session/recovery",
        None,
        &SessionRecoveryRequest { proof: invalid },
    )
    .await;
    assert_eq!(invalid_response.status(), StatusCode::BAD_REQUEST);
    let invalid_body: serde_json::Value = read_json(invalid_response).await;

    let replay = sign_challenge(&device_key, &challenge, &device_id, "1.0.0");
    let replay_response = post_json(
        app.clone(),
        "/v1/session/recovery",
        None,
        &SessionRecoveryRequest { proof: replay },
    )
    .await;
    assert_eq!(replay_response.status(), StatusCode::BAD_REQUEST);
    let replay_body: serde_json::Value = read_json(replay_response).await;

    let unknown_id = uuid::Uuid::new_v4().to_string();
    let synthetic: DeviceChallenge = read_json(
        post_json(
            app.clone(),
            "/v1/session/recovery/challenge",
            None,
            &SessionRecoveryChallengeRequest {
                device_id: unknown_id.clone(),
            },
        )
        .await,
    )
    .await;
    let unknown_proof = sign_challenge(&attacker, &synthetic, &unknown_id, "1.0.0");
    let unknown_response = post_json(
        app.clone(),
        "/v1/session/recovery",
        None,
        &SessionRecoveryRequest {
            proof: unknown_proof.clone(),
        },
    )
    .await;
    assert_eq!(unknown_response.status(), StatusCode::BAD_REQUEST);
    let unknown_body: serde_json::Value = read_json(unknown_response).await;
    let unknown_replay = post_json(
        app,
        "/v1/session/recovery",
        None,
        &SessionRecoveryRequest {
            proof: unknown_proof,
        },
    )
    .await;
    assert_eq!(unknown_replay.status(), StatusCode::BAD_REQUEST);
    let unknown_replay_body: serde_json::Value = read_json(unknown_replay).await;

    assert_eq!(invalid_body, replay_body);
    assert_eq!(invalid_body, unknown_body);
    assert_eq!(invalid_body, unknown_replay_body);
    assert_eq!(invalid_body["code"], "invalid_challenge");
}

#[tokio::test]
async fn oauth_accepts_desktop_loopback_callback() {
    let app = test_router();
    let redirect_uri = "http://127.0.0.1:49152/auth/callback";
    let authorization_code = authorize_with_redirect(app.clone(), redirect_uri).await;
    let device_key = test_signing_key();
    let device_id = uuid::Uuid::new_v4().to_string();
    let registration =
        register_request_with_redirect(&device_key, &device_id, authorization_code, redirect_uri);
    let response = post_json(app, "/v1/devices/register", None, &registration).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn http_rejects_arbitrary_authorization_code() {
    let app = test_router();
    let device_key = test_signing_key();
    let device_id = uuid::Uuid::new_v4().to_string();
    let registration = register_request(
        &device_key,
        &device_id,
        "arbitrary-authorization-code-that-was-not-issued".into(),
    );
    let response = post_json(app, "/v1/devices/register", None, &registration).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn oauth_authorization_code_is_single_use() {
    let app = test_router();
    let authorization_code = authorize(app.clone()).await;
    let first_device = test_signing_key();
    let first_registration = register_request(
        &first_device,
        &uuid::Uuid::new_v4().to_string(),
        authorization_code.clone(),
    );
    let first = post_json(
        app.clone(),
        "/v1/devices/register",
        None,
        &first_registration,
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);

    let second_device = test_signing_key();
    let second_registration = register_request(
        &second_device,
        &uuid::Uuid::new_v4().to_string(),
        authorization_code,
    );
    let second = post_json(app, "/v1/devices/register", None, &second_registration).await;
    assert_eq!(second.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn oauth_registration_retry_is_idempotent_for_the_same_device_and_pkce_binding() {
    let app = test_router();
    let authorization_code = authorize(app.clone()).await;
    let device_key = test_signing_key();
    let registration = register_request(
        &device_key,
        &uuid::Uuid::new_v4().to_string(),
        authorization_code,
    );

    let first = post_json(app.clone(), "/v1/devices/register", None, &registration).await;
    assert_eq!(first.status(), StatusCode::OK);

    // A lost first response may be retried, but only with the exact device key,
    // device ID, redirect URI, and PKCE verifier bound to the original code.
    let retry = post_json(app, "/v1/devices/register", None, &registration).await;
    assert_eq!(retry.status(), StatusCode::OK);
}

#[tokio::test]
async fn activation_code_is_consumed_only_after_confirmation() {
    let repository = Arc::new(MemoryRepository::default());
    let now = 1_783_183_600;
    let account = Account::active("paid-test", now);
    repository.upsert_account(account).await.unwrap();
    let license = License::default_pro("paid-test", now);
    repository.upsert_license(license.clone()).await.unwrap();
    let activation_code = "paid-activation-code-0001";
    let activation_code_hash = sha256_hex(activation_code);
    repository
        .upsert_activation_code(ActivationCodeRecord {
            code_hash: activation_code_hash.clone(),
            code_prefix: "paid".into(),
            account_id: "paid-test".into(),
            license_id: Some(license.id.clone()),
            status: ActivationCodeStatus::Active,
            max_redemptions: 1,
            redeemed_count: 0,
            expires_at: None,
            consumed_at: None,
            consumed_device_id: None,
            last_redeemed_at: None,
            last_redeemed_device_id: None,
            created_at: now,
            updated_at: now,
            note: None,
            order_id: None,
            channel: None,
            issued_by: None,
            revoked_reason: None,
            last_admin_reason: None,
        })
        .await
        .unwrap();

    let key = test_signing_key();
    let private = key.to_pkcs8_pem(Default::default()).expect("private");
    let signer = EntitlementSigner::from_pem("entitlement-http-test", private.as_bytes()).unwrap();
    let app = router(
        LicenseService::with_authorization(
            repository.clone(),
            signer,
            "https://license.test",
            "camellia-nexus-desktop",
            camellia_nexus_management_server::AuthorizationPolicy::new(
                "camellia-nexus-desktop",
                ["camellia-nexus://auth/callback".to_owned()],
                [],
            )
            .unwrap(),
        ),
        vec!["http://127.0.0.1:1420".into()],
        LoggingConfig::default().http,
        HttpServerConfig::default(),
    );

    let device_key = test_signing_key();
    let device_id = uuid::Uuid::new_v4().to_string();
    let authorization_code = authorize_with_activation_code(
        app.clone(),
        activation_code,
        "camellia-nexus://auth/callback",
    )
    .await;
    let registration = register_request(&device_key, &device_id, authorization_code);
    let response = post_json(app.clone(), "/v1/devices/register", None, &registration).await;
    assert_eq!(response.status(), StatusCode::OK);
    let registered: DeviceRegistrationResponse = read_json(response).await;
    assert_eq!(registered.device_state, DeviceState::PendingActivation);
    let activation = repository
        .activation_code_by_hash(&activation_code_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(activation.status, ActivationCodeStatus::Active);
    assert!(activation.consumed_at.is_none());

    let challenge_request = ChallengeRequest {
        device_id: device_id.clone(),
        requested_scope: "entitlement:refresh".into(),
    };
    let response = post_json(
        app.clone(),
        "/v1/entitlements/challenge",
        Some(&registered.refresh_session.0),
        &challenge_request,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let challenge_request = ChallengeRequest {
        device_id: device_id.clone(),
        requested_scope: "activation:verify".into(),
    };
    let response = post_json(
        app.clone(),
        "/v1/entitlements/challenge",
        Some(&registered.refresh_session.0),
        &challenge_request,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let challenge: DeviceChallenge = read_json(response).await;
    let proof = sign_challenge(&device_key, &challenge, &device_id, "1.0.0");
    let response = post_json(
        app.clone(),
        "/v1/activations/verify",
        Some(&registered.refresh_session.0),
        &ActivationVerificationRequest { proof },
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let verified: ActivationVerificationResponse = read_json(response).await;
    assert_eq!(verified.device_state, DeviceState::PendingActivation);
    assert!(verified.activation.expose().matches('.').count() == 2);
    let activation_claims: ActivationProofClaims = decode_jws_payload(verified.activation.expose());
    assert_eq!(activation_claims.purpose, "activation_verify");
    assert_eq!(activation_claims.aud, "camellia-nexus-desktop:activation");
    assert_eq!(activation_claims.device_id, device_id.as_str());
    let activation = repository
        .activation_code_by_hash(&activation_code_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(activation.status, ActivationCodeStatus::Active);
    assert!(activation.consumed_at.is_none());

    let response = post_empty(
        app.clone(),
        "/v1/activations/confirm",
        Some(&verified.rotated_refresh_session.0),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let confirmed: DeviceActivationConfirmationResponse = read_json(response).await;
    assert_eq!(confirmed.device_state, DeviceState::Active);
    let activation = repository
        .activation_code_by_hash(&activation_code_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(activation.status, ActivationCodeStatus::Consumed);
    assert_eq!(activation.redeemed_count, 1);
    assert_eq!(
        activation.consumed_device_id.as_deref(),
        Some(device_id.as_str())
    );

    let response = post_empty(
        app,
        "/v1/activations/confirm",
        Some(&verified.rotated_refresh_session.0),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn browser_activation_errors_stay_on_the_recoverable_html_page() {
    let repository = Arc::new(MemoryRepository::default());
    let now = 1_783_183_600;
    repository
        .upsert_account(Account::active("browser-errors", now))
        .await
        .unwrap();
    let license = License::default_pro("browser-errors", now);
    repository.upsert_license(license.clone()).await.unwrap();
    for (code, status, expires_at, redeemed_count) in [
        (
            "expired-activation-code",
            ActivationCodeStatus::Active,
            Some(1),
            0,
        ),
        (
            "consumed-activation-code",
            ActivationCodeStatus::Consumed,
            None,
            1,
        ),
        (
            "revoked-activation-code",
            ActivationCodeStatus::Revoked,
            None,
            0,
        ),
    ] {
        repository
            .upsert_activation_code(activation_code_record(
                code,
                &license,
                status,
                expires_at,
                redeemed_count,
                now,
            ))
            .await
            .unwrap();
    }
    let app = router(
        LicenseService::with_authorization(
            repository,
            test_signer(),
            "https://license.test",
            "camellia-nexus-desktop",
            camellia_nexus_management_server::AuthorizationPolicy::new(
                "camellia-nexus-desktop",
                ["camellia-nexus://auth/callback".to_owned()],
                [],
            )
            .unwrap(),
        ),
        vec!["http://127.0.0.1:1420".into()],
        LoggingConfig::default().http,
        HttpServerConfig::default(),
    );

    for (code, message) in [
        (
            "unknown-activation-code",
            "We could not verify this activation code.",
        ),
        ("expired-activation-code", "activation code has expired"),
        (
            "consumed-activation-code",
            "activation code has already been used",
        ),
        (
            "revoked-activation-code",
            "activation code is no longer valid",
        ),
    ] {
        let response = submit_activation_code(app.clone(), code).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("text/html"))
        );
        let body = String::from_utf8(
            to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(body.contains("Activate Camellia Nexus"));
        assert!(body.contains(message));
        assert!(!body.contains("\"code\":\"activation_code_"));
    }
}

#[tokio::test]
async fn oauth_authorization_page_requires_the_exact_first_party_protocol() {
    let app = test_router();
    let challenge = pkce_s256_challenge(PKCE_VERIFIER);
    let valid_query = oauth_authorization_query("camellia.nexus.license", OAUTH_STATE, &challenge);
    let response = app
        .clone()
        .oneshot(
            Request::get(format!("/oauth/authorize?{valid_query}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let content_security_policy = response
        .headers()
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|value| value.to_str().ok())
        .expect("authorization page content security policy");
    assert!(content_security_policy.contains("form-action 'self' camellia-nexus:"));
    assert!(content_security_policy.contains("http://127.0.0.1:*/auth/callback"));
    assert!(!content_security_policy.contains("[::1]"));
    assert!(!content_security_policy.contains("https://*"));
    assert!(
        response_body(response)
            .await
            .contains("name=\"activation_code\"")
    );

    let invalid_queries = [
        oauth_authorization_query("", OAUTH_STATE, &challenge),
        oauth_authorization_query(
            "openid offline_access camellia.nexus.license",
            OAUTH_STATE,
            &challenge,
        ),
        oauth_authorization_query(
            "camellia.nexus.license camellia.nexus.license",
            OAUTH_STATE,
            &challenge,
        ),
        oauth_authorization_query(" camellia.nexus.license", OAUTH_STATE, &challenge),
        oauth_authorization_query("camellia.nexus.license", &"a".repeat(31), &challenge),
        oauth_authorization_query("camellia.nexus.license", &"a".repeat(129), &challenge),
        oauth_authorization_query(
            "camellia.nexus.license",
            &format!("{}+", "a".repeat(31)),
            &challenge,
        ),
        oauth_authorization_query("camellia.nexus.license", OAUTH_STATE, &"a".repeat(42)),
        oauth_authorization_query(
            "camellia.nexus.license",
            OAUTH_STATE,
            &format!("{}=", "a".repeat(42)),
        ),
    ];
    for query in invalid_queries {
        let response = app
            .clone()
            .oneshot(
                Request::get(format!("/oauth/authorize?{query}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            !response_body(response)
                .await
                .contains("name=\"activation_code\"")
        );
    }

    let query_with_unknown_field = format!("{valid_query}&prompt=consent");
    let response = app
        .clone()
        .oneshot(
            Request::get(format!("/oauth/authorize?{query_with_unknown_field}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_client_error());
    assert!(
        !response_body(response)
            .await
            .contains("name=\"activation_code\"")
    );

    let invalid_post = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("activation_code", "dev-activation-code")
        .append_pair("response_type", "code")
        .append_pair("client_id", "camellia-nexus-desktop")
        .append_pair("redirect_uri", "camellia-nexus://auth/callback")
        .append_pair("scope", "openid offline_access camellia.nexus.license")
        .append_pair("state", OAUTH_STATE)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();
    let response = app
        .oneshot(
            Request::post("/oauth/authorize")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(invalid_post))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        !response_body(response)
            .await
            .contains("name=\"activation_code\"")
    );
}

fn test_router() -> Router {
    router(
        LicenseService::new(
            Arc::new(MemoryRepository::default()),
            test_signer(),
            "https://license.test",
            "camellia-nexus-desktop",
        ),
        vec!["http://127.0.0.1:1420".into()],
        LoggingConfig::default().http,
        HttpServerConfig::default(),
    )
}

fn test_signer() -> EntitlementSigner {
    let key = test_signing_key();
    let private = key.to_pkcs8_pem(Default::default()).expect("private");
    EntitlementSigner::from_pem("entitlement-http-test", private.as_bytes()).unwrap()
}

async fn recovery_challenge_response(app: Router, device_id: &str) -> serde_json::Value {
    let response = post_json(
        app,
        "/v1/session/recovery/challenge",
        None,
        &SessionRecoveryChallengeRequest {
            device_id: device_id.to_owned(),
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    read_json(response).await
}

fn assert_recovery_challenge_shape(response: &serde_json::Value) {
    assert!(response["challengeId"].is_string());
    assert!(response["nonce"].is_string());
    assert_eq!(response["requestedScope"], "session:recover");
    assert!(response["issuedAt"].is_i64());
    assert!(response["expiresAt"].is_i64());
}

fn json_field_shape(response: &serde_json::Value) -> Vec<&str> {
    let mut fields = response
        .as_object()
        .expect("challenge JSON object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    fields.sort_unstable();
    fields
}

fn activation_code_record(
    code: &str,
    license: &License,
    status: ActivationCodeStatus,
    expires_at: Option<i64>,
    redeemed_count: u32,
    now: i64,
) -> ActivationCodeRecord {
    ActivationCodeRecord {
        code_hash: sha256_hex(code),
        code_prefix: code.chars().take(16).collect(),
        account_id: license.account_id.clone(),
        license_id: Some(license.id.clone()),
        status,
        max_redemptions: 1,
        redeemed_count,
        expires_at,
        consumed_at: (status == ActivationCodeStatus::Consumed).then_some(now),
        consumed_device_id: None,
        last_redeemed_at: None,
        last_redeemed_device_id: None,
        created_at: now,
        updated_at: now,
        note: None,
        order_id: None,
        channel: None,
        issued_by: None,
        revoked_reason: None,
        last_admin_reason: None,
    }
}

async fn submit_activation_code(app: Router, activation_code: &str) -> axum::response::Response {
    let challenge = pkce_s256_challenge(PKCE_VERIFIER);
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("activation_code", activation_code)
        .append_pair("response_type", "code")
        .append_pair("client_id", "camellia-nexus-desktop")
        .append_pair("redirect_uri", "camellia-nexus://auth/callback")
        .append_pair("scope", "camellia.nexus.license")
        .append_pair("state", OAUTH_STATE)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();
    app.oneshot(
        Request::post("/oauth/authorize")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(form))
            .unwrap(),
    )
    .await
    .unwrap()
}

fn oauth_authorization_query(scope: &str, state: &str, challenge: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", "camellia-nexus-desktop")
        .append_pair("redirect_uri", "camellia-nexus://auth/callback")
        .append_pair("scope", scope)
        .append_pair("state", state)
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256")
        .finish()
}

async fn response_body(response: axum::response::Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

async fn authorize(app: Router) -> String {
    authorize_with_redirect(app, "camellia-nexus://auth/callback").await
}

async fn authorize_with_redirect(app: Router, redirect_uri: &str) -> String {
    authorize_with_activation_code(app, "dev-activation-code", redirect_uri).await
}

async fn authorize_with_activation_code(
    app: Router,
    activation_code: &str,
    redirect_uri: &str,
) -> String {
    let encoded_redirect_uri: String =
        url::form_urlencoded::byte_serialize(redirect_uri.as_bytes()).collect();
    let authorization_url = format!(
        "/oauth/authorize?response_type=code&client_id=camellia-nexus-desktop&redirect_uri={encoded_redirect_uri}&scope=camellia.nexus.license&state={OAUTH_STATE}&code_challenge={}&code_challenge_method=S256",
        pkce_s256_challenge(PKCE_VERIFIER)
    );
    let page = app
        .clone()
        .oneshot(
            Request::get(&authorization_url)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);

    let form = format!(
        "activation_code={activation_code}&response_type=code&client_id=camellia-nexus-desktop&redirect_uri={encoded_redirect_uri}&scope=camellia.nexus.license&state={OAUTH_STATE}&code_challenge={}&code_challenge_method=S256",
        pkce_s256_challenge(PKCE_VERIFIER)
    );
    let response = app
        .oneshot(
            Request::post("/oauth/authorize")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("redirect location")
        .to_owned();
    let redirect = Url::parse(&location).expect("callback url");
    assert!(redirect.as_str().contains(&format!("state={OAUTH_STATE}")));
    redirect
        .query_pairs()
        .find_map(|(name, value)| (name == "code").then(|| value.into_owned()))
        .expect("authorization code")
}

fn register_request(
    key: &SigningKey,
    device_id: &str,
    authorization_code: String,
) -> DeviceRegistrationRequest {
    register_request_with_redirect(
        key,
        device_id,
        authorization_code,
        "camellia-nexus://auth/callback",
    )
}

fn register_request_with_redirect(
    key: &SigningKey,
    device_id: &str,
    authorization_code: String,
    redirect_uri: &str,
) -> DeviceRegistrationRequest {
    let public_key_pem = key
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .expect("public");
    let public_der = key.verifying_key().to_public_key_der().expect("der");
    let thumbprint = format!(
        "sha256:{}",
        sha2::Sha256::digest(public_der.as_ref())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    DeviceRegistrationRequest {
        device: DeviceRegistrationMetadata {
            device_id: device_id.to_owned(),
            public_key_pem,
            public_key_thumbprint: thumbprint,
            platform: "test".into(),
            app_version: "1.0.0".into(),
            display_name: Some("HTTP test".into()),
        },
        authorization_code: SecretValue(authorization_code),
        pkce_verifier: SecretValue(PKCE_VERIFIER.into()),
        redirect_uri: redirect_uri.into(),
    }
}

fn sign_challenge(
    key: &SigningKey,
    challenge: &DeviceChallenge,
    device_id: &str,
    app_version: &str,
) -> DeviceProof {
    let signature: Signature = key.sign(&proof_payload(
        &challenge.nonce,
        device_id,
        app_version,
        &challenge.requested_scope,
        challenge.issued_at,
    ));
    DeviceProof {
        challenge_id: challenge.challenge_id.clone(),
        device_id: device_id.to_owned(),
        app_version: app_version.to_owned(),
        requested_scope: challenge.requested_scope.clone(),
        issued_at: challenge.issued_at,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    }
}

async fn post_json<T: serde::Serialize>(
    app: Router,
    path: &str,
    bearer: Option<&str>,
    payload: &T,
) -> axum::response::Response {
    let mut request = Request::post(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(payload).unwrap()))
        .unwrap();
    if let Some(bearer) = bearer {
        request.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {bearer}").parse().unwrap(),
        );
    }
    app.oneshot(request).await.unwrap()
}

async fn post_empty(app: Router, path: &str, bearer: Option<&str>) -> axum::response::Response {
    let mut request = Request::post(path).body(Body::empty()).unwrap();
    if let Some(bearer) = bearer {
        request.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {bearer}").parse().unwrap(),
        );
    }
    app.oneshot(request).await.unwrap()
}

async fn get_with_bearer(app: Router, path: &str, bearer: &str) -> axum::response::Response {
    app.oneshot(
        Request::get(path)
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap()
}

async fn issue_device_proof(
    app: Router,
    key: &SigningKey,
    device_id: &str,
    bearer: &str,
    requested_scope: &str,
) -> DeviceProof {
    let response = post_json(
        app,
        "/v1/entitlements/challenge",
        Some(bearer),
        &ChallengeRequest {
            device_id: device_id.to_owned(),
            requested_scope: requested_scope.to_owned(),
        },
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let challenge: DeviceChallenge = read_json(response).await;
    sign_challenge(key, &challenge, device_id, "1.0.0")
}

async fn get_with_device_proof(
    app: Router,
    path: &str,
    bearer: &str,
    proof: &DeviceProof,
) -> axum::response::Response {
    let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(proof).unwrap());
    app.oneshot(
        Request::get(path)
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
            .header("x-camellia-device-proof", encoded)
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap()
}

async fn read_json<T: DeserializeOwned>(response: axum::response::Response) -> T {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn decode_jws_payload<T: DeserializeOwned>(jws: &str) -> T {
    let payload = jws.split('.').nth(1).expect("payload");
    let bytes = URL_SAFE_NO_PAD.decode(payload).expect("base64url payload");
    serde_json::from_slice(&bytes).expect("json payload")
}
