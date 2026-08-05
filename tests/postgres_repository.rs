use std::time::Duration;

use camellia_nexus_management_server::{
    LicenseRepository, PostgresRepository, TimeAuthorityStatus,
    contracts::{DeviceRegistrationMetadata, DeviceState},
    crypto::{random_id, sha256_hex},
    domain::{
        Account, AuditEventRecord, Device, License, RefreshSessionProofState, RefreshSessionRecord,
        StoredChallenge,
    },
    error::ApiError,
};
use sqlx::PgPool;
use std::collections::BTreeMap;

fn session(token_hash: &str, account_id: &str, device_id: &str) -> RefreshSessionRecord {
    RefreshSessionRecord {
        token_hash: token_hash.to_owned(),
        account_id: account_id.to_owned(),
        device_id: device_id.to_owned(),
        family_id: format!("family_{token_hash}"),
        family_created_at: 1_800_000_000,
        absolute_expires_at: 1_802_592_000,
        active: true,
        expires_at: 1_800_604_800,
        rotated_to_hash: None,
        rotated_at: None,
        pending_activation_code_hash: None,
        activation_verified_at: Some(1_800_000_000),
        activation_confirmation_consumed: false,
        proof_state: RefreshSessionProofState::DeviceProven,
    }
}

fn device(account_id: &str, license_id: &str, device_id: &str, now: i64) -> Device {
    Device {
        account_id: account_id.to_owned(),
        license_id: license_id.to_owned(),
        metadata: DeviceRegistrationMetadata {
            device_id: device_id.to_owned(),
            public_key_pem: "postgres-test-public-key".to_owned(),
            public_key_thumbprint: format!("sha256:{device_id}"),
            platform: "test".to_owned(),
            app_version: "1.0.0".to_owned(),
            display_name: Some("PostgreSQL integration test".to_owned()),
        },
        state: DeviceState::Active,
        pending_activation_code_hash: None,
        pending_activation_expires_at: None,
        created_at: now,
        last_seen_at: Some(now),
    }
}

fn audit(
    event_type: &str,
    account_id: &str,
    license_id: Option<&str>,
    device_id: Option<&str>,
    reason_code: Option<&str>,
    metadata: BTreeMap<String, String>,
) -> AuditEventRecord {
    AuditEventRecord {
        id: random_id("postgres_audit"),
        event_type: event_type.to_owned(),
        outcome: "succeeded".to_owned(),
        occurred_at: 1_800_000_000,
        account_id: Some(account_id.to_owned()),
        license_id: license_id.map(str::to_owned),
        device_id: device_id.map(str::to_owned),
        reason_code: reason_code.map(str::to_owned),
        metadata,
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL"]
async fn postgres_migrations_and_repository_readiness_are_exercised() {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL is required for the PostgreSQL integration test");
    let repository = PostgresRepository::connect(&database_url, 4, Duration::from_secs(5))
        .await
        .expect("connect PostgreSQL");
    repository.migrate().await.expect("run migrations");
    repository
        .readiness_check()
        .await
        .expect("repository ready");
    let schema_pool = PgPool::connect(&database_url)
        .await
        .expect("connect for schema inspection");
    let program_kind_constraint: String = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid)
         FROM pg_constraint
         WHERE conrelid = 'workspace_document_revisions'::regclass
           AND contype = 'c'
           AND pg_get_constraintdef(oid) LIKE '%program_kind%'",
    )
    .fetch_one(&schema_pool)
    .await
    .expect("inspect shared program kind constraint");
    assert!(program_kind_constraint.contains("mihomo"));
    let applied_migrations: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE success")
            .fetch_one(&schema_pool)
            .await
            .expect("inspect applied migrations");
    assert_eq!(
        applied_migrations, 2,
        "the baseline and append-only billing worker index migration must be applied"
    );
    let audit_index_definition: String =
        sqlx::query_scalar("SELECT pg_get_indexdef('audit_events_global_keyset_idx'::regclass)")
            .fetch_one(&schema_pool)
            .await
            .expect("inspect global Admin audit-listing index");
    assert!(audit_index_definition.contains("(occurred_at DESC, id DESC)"));
    let billing_worker_index_definition: String =
        sqlx::query_scalar("SELECT pg_get_indexdef('billing_invoices_open_due_idx'::regclass)")
            .fetch_one(&schema_pool)
            .await
            .expect("inspect overdue billing worker index");
    assert!(billing_worker_index_definition.contains("(due_at, id)"));
    assert!(billing_worker_index_definition.contains("WHERE (status = 'open'::text)"));
    schema_pool.close().await;

    let initial_time = repository
        .observe_time_authority(None, 24 * 60 * 60)
        .await
        .expect("initialize persistent time authority");
    let synthetic_device_id = uuid::Uuid::new_v4().to_string();
    let synthetic_challenge_id = random_id("synthetic_recovery");
    repository
        .insert_challenge(StoredChallenge {
            challenge_id: synthetic_challenge_id.clone(),
            nonce: random_id("nonce"),
            device_id: synthetic_device_id.clone(),
            requested_scope: "session:recover".to_owned(),
            issued_at: initial_time.trusted_unix,
            expires_at: initial_time.trusted_unix + 60,
            consumed: false,
        })
        .await
        .expect("persist a recovery challenge without a device foreign key");
    repository
        .consume_challenge(
            &synthetic_challenge_id,
            &synthetic_device_id,
            initial_time.trusted_unix,
        )
        .await
        .expect("consume a persisted synthetic recovery challenge");
    let advanced_time = repository
        .observe_time_authority(Some(initial_time.trusted_unix + 3_600), 24 * 60 * 60)
        .await
        .expect("advance persistent time authority");
    let restarted_repository =
        PostgresRepository::connect(&database_url, 1, Duration::from_secs(5))
            .await
            .expect("reconnect PostgreSQL");
    let after_restart = restarted_repository
        .observe_time_authority(None, 24 * 60 * 60)
        .await
        .expect("reload persistent time authority");
    assert_eq!(after_restart.trusted_unix, advanced_time.trusted_unix);
    assert_eq!(after_restart.status, TimeAuthorityStatus::RollbackHeld);
    restarted_repository.close().await;

    let control_pool = sqlx::PgPool::connect(&database_url)
        .await
        .expect("connect time-authority control pool");
    sqlx::query(
        "UPDATE service_time_authority
         SET high_water_unix = floor(extract(epoch FROM clock_timestamp()))::BIGINT - 3600,
             last_database_unix = floor(extract(epoch FROM clock_timestamp()))::BIGINT - 3600,
             status = 'healthy'
         WHERE singleton = 1",
    )
    .execute(&control_pool)
    .await
    .expect("simulate a database clock forward jump");
    control_pool.close().await;
    let rejected_time = repository
        .observe_time_authority(None, 10)
        .await
        .expect("record forward-jump anomaly");
    assert_eq!(rejected_time.status, TimeAuthorityStatus::ForwardJump);
    let recovered_time = repository
        .observe_time_authority(None, 7_200)
        .await
        .expect("explicitly accept bounded recovery window");
    assert_eq!(recovered_time.status, TimeAuthorityStatus::Healthy);

    let now = 1_800_000_000;
    let suffix = random_id("postgres_ci");
    let account = Account::active(format!("account_{suffix}"), now);
    repository
        .upsert_account(account.clone())
        .await
        .expect("upsert account");
    let license = License::default_pro(&account.id, now);
    repository
        .upsert_license(license.clone())
        .await
        .expect("upsert license");
    assert_eq!(
        repository
            .license_for_account(&account.id)
            .await
            .expect("query license")
            .expect("license exists")
            .id,
        license.id
    );

    let nullable_metadata_audit_id = random_id("postgres_nullable_metadata_audit");
    let camel_case_document_audit_id = random_id("postgres_camel_case_document_audit");
    let audit_pool = PgPool::connect(&database_url)
        .await
        .expect("connect for audit compatibility regression");
    sqlx::query(
        "INSERT INTO audit_events
         (id, event_type, outcome, occurred_at, account_id, reason_code, metadata, document)
         VALUES ($1, 'admin_login', 'failed', $2, NULL, 'admin_auth', $3, $4)",
    )
    .bind(&nullable_metadata_audit_id)
    .bind(now + 10)
    .bind(serde_json::json!({
        "actor": "anonymous",
        "reason": "unknown_user",
        "attempt": 3,
        "target_id": null
    }))
    .bind(serde_json::json!({
        "id": nullable_metadata_audit_id.clone(),
        "event_type": "admin_login",
        "outcome": "failed",
        "occurred_at": now + 10,
        "reason_code": "admin_auth",
        "metadata": {
            "actor": "anonymous",
            "reason": "unknown_user",
            "target_id": null
        }
    }))
    .execute(&audit_pool)
    .await
    .expect("insert legacy Admin login audit");
    sqlx::query(
        "INSERT INTO audit_events
         (id, event_type, outcome, occurred_at, account_id, metadata, document)
         VALUES ($1, 'webhook_endpoint_created', 'succeeded', $2, $3, $4, $5)",
    )
    .bind(&camel_case_document_audit_id)
    .bind(now + 11)
    .bind(&account.id)
    .bind(serde_json::json!({
        "actorMemberId": "member_legacy",
        "endpointId": "webhook_legacy"
    }))
    .bind(serde_json::json!({
        "id": camel_case_document_audit_id.clone(),
        "eventType": "webhook_endpoint_created",
        "outcome": "succeeded",
        "occurredAt": now + 11,
        "accountId": account.id.clone(),
        "metadata": {
            "actorMemberId": "member_legacy",
            "endpointId": "webhook_legacy"
        }
    }))
    .execute(&audit_pool)
    .await
    .expect("insert legacy camel-case Webhook audit");
    audit_pool.close().await;

    let audit_events = repository
        .audit_events(None, 500)
        .await
        .expect("read global audit events from normalized columns");
    let nullable_metadata_event = audit_events
        .iter()
        .find(|event| event.id == nullable_metadata_audit_id)
        .expect("legacy Admin login audit remains visible");
    assert_eq!(nullable_metadata_event.event_type, "admin_login");
    assert_eq!(
        nullable_metadata_event.reason_code.as_deref(),
        Some("admin_auth")
    );
    assert_eq!(
        nullable_metadata_event
            .metadata
            .get("attempt")
            .map(String::as_str),
        Some("3")
    );
    assert!(!nullable_metadata_event.metadata.contains_key("target_id"));
    let camel_case_document_event = audit_events
        .iter()
        .find(|event| event.id == camel_case_document_audit_id)
        .expect("legacy camel-case Webhook audit remains visible");
    assert_eq!(
        camel_case_document_event.event_type,
        "webhook_endpoint_created"
    );
    assert_eq!(
        camel_case_document_event
            .metadata
            .get("endpointId")
            .map(String::as_str),
        Some("webhook_legacy")
    );

    let first = repository.clone();
    let second = repository.clone();
    let device_id = format!("device_{suffix}");
    repository
        .upsert_device(device(&account.id, &license.id, &device_id, now))
        .await
        .expect("upsert device");
    repository
        .update_device_client_metadata(&device_id, "2.0.0", now + 60)
        .await
        .expect("update client metadata without a schema migration");
    repository
        .update_device_client_metadata(&device_id, "1.5.0", now + 30)
        .await
        .expect("ignore stale client metadata observation");
    let updated_device = repository
        .device(&device_id)
        .await
        .expect("query client metadata")
        .expect("updated device");
    assert_eq!(updated_device.metadata.app_version, "2.0.0");
    assert_eq!(updated_device.last_seen_at, Some(now + 60));
    let mut page_device_ids = vec![device_id.clone()];
    for _ in 0..3 {
        let page_device_id = uuid::Uuid::new_v4().to_string();
        repository
            .upsert_device(device(&account.id, &license.id, &page_device_id, now))
            .await
            .expect("upsert paginated device");
        page_device_ids.push(page_device_id);
    }
    let mut conflicting_license = License::default_pro(&account.id, now);
    conflicting_license.id = format!("conflicting_license_{suffix}");
    assert!(
        matches!(
            repository.upsert_license(conflicting_license).await,
            Err(ApiError::Database)
        ),
        "an account cannot own a second license"
    );
    let other_account = Account::active(format!("other_account_{suffix}"), now);
    repository
        .upsert_account(other_account.clone())
        .await
        .expect("upsert pagination-isolation account");
    let other_license = License::default_pro(&other_account.id, now);
    repository
        .upsert_license(other_license.clone())
        .await
        .expect("upsert other license");
    let other_device_id = uuid::Uuid::new_v4().to_string();
    repository
        .upsert_device(device(
            &other_account.id,
            &other_license.id,
            &other_device_id,
            now,
        ))
        .await
        .expect("upsert device for other license");

    page_device_ids.sort();
    let first_page = repository
        .devices_for_license_page(&license.id, None, 2)
        .await
        .expect("query first device page");
    assert_eq!(
        first_page
            .iter()
            .map(|device| device.metadata.device_id.clone())
            .collect::<Vec<_>>(),
        page_device_ids[..2]
    );
    let cursor = first_page.last().unwrap().metadata.device_id.as_str();
    let second_page = repository
        .devices_for_license_page(&license.id, Some(cursor), 3)
        .await
        .expect("query second device page");
    assert_eq!(
        second_page
            .iter()
            .map(|device| device.metadata.device_id.clone())
            .collect::<Vec<_>>(),
        page_device_ids[2..]
    );
    assert!(
        first_page
            .iter()
            .chain(second_page.iter())
            .all(|device| device.metadata.device_id != other_device_id)
    );
    let recovery_a = sha256_hex(&format!("recovery_a_{suffix}"));
    let recovery_b = sha256_hex(&format!("recovery_b_{suffix}"));
    let (first_result, second_result) = tokio::join!(
        first.replace_device_sessions_with_audit(
            session(&recovery_a, &account.id, &device_id),
            now,
            audit(
                "session_recovered",
                &account.id,
                Some(&license.id),
                Some(&device_id),
                Some("device_proof"),
                BTreeMap::new(),
            ),
        ),
        second.replace_device_sessions_with_audit(
            session(&recovery_b, &account.id, &device_id),
            now,
            audit(
                "session_recovered",
                &account.id,
                Some(&license.id),
                Some(&device_id),
                Some("device_proof"),
                BTreeMap::new(),
            ),
        ),
    );
    first_result.expect("first recovery replacement");
    second_result.expect("second recovery replacement");
    let (first_active, second_active) = tokio::join!(
        repository.session_by_hash(&recovery_a),
        repository.session_by_hash(&recovery_b),
    );
    let first_active = first_active
        .expect("query first replacement")
        .expect("first replacement exists")
        .active;
    let second_active = second_active
        .expect("query second replacement")
        .expect("second replacement exists")
        .active;
    assert_ne!(
        first_active, second_active,
        "exactly one replacement must remain active"
    );

    let active_hash = if first_active {
        &recovery_a
    } else {
        &recovery_b
    };
    let rollback_token = sha256_hex(&format!("rollback_recovery_{suffix}"));
    let duplicate_audit = audit(
        "session_recovered",
        &account.id,
        Some(&license.id),
        Some(&device_id),
        Some("device_proof"),
        BTreeMap::new(),
    );
    repository
        .insert_audit_event(duplicate_audit.clone())
        .await
        .expect("seed duplicate audit identifier");
    assert!(matches!(
        repository
            .replace_device_sessions_with_audit(
                session(&rollback_token, &account.id, &device_id),
                now,
                duplicate_audit,
            )
            .await,
        Err(ApiError::Database)
    ));
    assert!(
        repository
            .session_by_hash(active_hash)
            .await
            .expect("query active session after rollback")
            .expect("active session remains after rollback")
            .active
    );
    assert!(
        repository
            .session_by_hash(&rollback_token)
            .await
            .expect("query rolled-back session")
            .is_none()
    );
    repository
        .logout_device_sessions_with_audit(
            active_hash,
            now,
            audit(
                "session_logout",
                &account.id,
                None,
                Some(&device_id),
                Some("device_sessions_revoked"),
                BTreeMap::new(),
            ),
        )
        .await
        .expect("transactional logout")
        .expect("known logout session");
    for token_hash in [&recovery_a, &recovery_b] {
        assert!(
            !repository
                .session_by_hash(token_hash)
                .await
                .expect("query logged-out session")
                .expect("session exists")
                .active
        );
    }

    let before_removal = sha256_hex(&format!("before_removal_{suffix}"));
    repository
        .replace_device_sessions_with_audit(
            session(&before_removal, &account.id, &device_id),
            now,
            audit(
                "session_recovered",
                &account.id,
                Some(&license.id),
                Some(&device_id),
                Some("device_proof"),
                BTreeMap::new(),
            ),
        )
        .await
        .expect("restore active session before removal race");
    let requester_device_id = format!("requester_{suffix}");
    let requester_session = sha256_hex(&format!("requester_session_{suffix}"));
    repository
        .upsert_device(device(&account.id, &license.id, &requester_device_id, now))
        .await
        .expect("upsert removal requester");
    repository
        .replace_device_sessions_with_audit(
            session(&requester_session, &account.id, &requester_device_id),
            now,
            audit(
                "session_recovered",
                &account.id,
                Some(&license.id),
                Some(&requester_device_id),
                Some("device_proof"),
                BTreeMap::new(),
            ),
        )
        .await
        .expect("create removal requester session");
    let recovery = repository.clone();
    let removal = repository.clone();
    let concurrent_recovery = sha256_hex(&format!("concurrent_recovery_{suffix}"));
    let removal_audit = audit(
        "device_removed",
        &account.id,
        Some(&license.id),
        Some(&requester_device_id),
        None,
        BTreeMap::from([("target_device_id".to_owned(), device_id.clone())]),
    );
    let removal_operation_id = uuid::Uuid::new_v4().to_string();
    let (recovery_result, removal_result) = tokio::join!(
        recovery.replace_device_sessions_with_audit(
            session(&concurrent_recovery, &account.id, &device_id),
            now,
            audit(
                "session_recovered",
                &account.id,
                Some(&license.id),
                Some(&device_id),
                Some("device_proof"),
                BTreeMap::new(),
            ),
        ),
        removal.remove_device_with_audit(
            &requester_session,
            &requester_device_id,
            &device_id,
            &removal_operation_id,
            now,
            removal_audit,
        ),
    );
    assert!(removal_result.expect("device removal always completes"));
    let repeat_removal_operation_id = uuid::Uuid::new_v4().to_string();
    assert!(
        recovery_result.is_ok()
            || matches!(
                recovery_result,
                Err(ApiError::DeviceStateDenied(DeviceState::Removed))
            )
    );
    assert_eq!(
        repository
            .device(&device_id)
            .await
            .expect("query removed device")
            .expect("device exists")
            .state,
        DeviceState::Removed
    );
    for token_hash in [&before_removal, &concurrent_recovery] {
        if let Some(record) = repository
            .session_by_hash(token_hash)
            .await
            .expect("query removal-race session")
        {
            assert!(!record.active);
        }
    }
    assert!(
        !repository
            .remove_device_with_audit(
                &requester_session,
                &requester_device_id,
                &device_id,
                &repeat_removal_operation_id,
                now + 1,
                audit(
                    "device_removed",
                    &account.id,
                    Some(&license.id),
                    Some(&requester_device_id),
                    None,
                    BTreeMap::from([("target_device_id".to_owned(), device_id.clone())]),
                ),
            )
            .await
            .expect("repeated device removal is idempotent")
    );
    let removal_events = repository
        .audit_events(Some(&account.id), 500)
        .await
        .expect("query removal audit events")
        .into_iter()
        .filter(|event| {
            event.event_type == "device_removed"
                && event.metadata.get("target_device_id") == Some(&device_id)
        })
        .count();
    assert_eq!(
        removal_events, 1,
        "a repeated removal must not duplicate audit history"
    );

    let limiter_a = repository.clone();
    let limiter_b = repository.clone();
    let (allowed_a, allowed_b) = tokio::join!(
        limiter_a.consume_rate_limit("postgres_ci", &suffix, now, 1, 60),
        limiter_b.consume_rate_limit("postgres_ci", &suffix, now, 1, 60),
    );
    assert_ne!(
        allowed_a.expect("first rate-limit write"),
        allowed_b.expect("second rate-limit write"),
        "the distributed bucket must admit exactly one concurrent request"
    );
    repository.close().await;
}
