use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::{
    admin_app::{AdminAppError, AdminAppResult, MutationContext},
    crypto::sha256_hex,
    error::ApiError,
};

pub fn operation_id(context: &MutationContext) -> AdminAppResult<&str> {
    context
        .operation_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or_else(|| AdminAppError::Validation("an idempotency key is required".to_owned()))
}

pub fn request_hash(value: &Value) -> AdminAppResult<String> {
    serde_json::to_string(value)
        .map(|value| sha256_hex(&value))
        .map_err(Into::into)
}

#[derive(Debug, Clone)]
pub struct AdminOperationClaim {
    operation_id: String,
    command: String,
    request_hash: String,
    actor: String,
    reason: String,
}

pub fn prepare(
    command: &str,
    request: &Value,
    context: &MutationContext,
) -> AdminAppResult<Option<AdminOperationClaim>> {
    let Some(operation_id) = context.operation_id.as_deref() else {
        return Ok(None);
    };
    let operation_id = operation_id.trim();
    if operation_id.is_empty() || operation_id.len() > 128 {
        return Err(AdminAppError::Validation(
            "idempotency key must contain 1 to 128 characters".to_owned(),
        ));
    }
    Ok(Some(from_parts(
        operation_id,
        command,
        &request_hash(request)?,
        &context.principal.id,
        &context.reason,
    )?))
}

pub fn from_parts(
    operation_id: &str,
    command: &str,
    request_hash: &str,
    actor: &str,
    reason: &str,
) -> AdminAppResult<AdminOperationClaim> {
    let operation_id = operation_id.trim();
    if operation_id.is_empty()
        || operation_id.len() > 128
        || command.is_empty()
        || command.len() > 128
        || request_hash.len() != 64
        || actor.trim().is_empty()
        || reason.trim().is_empty()
    {
        return Err(AdminAppError::Validation(
            "admin operation metadata is invalid".to_owned(),
        ));
    }
    Ok(AdminOperationClaim {
        operation_id: operation_id.to_owned(),
        command: command.to_owned(),
        request_hash: request_hash.to_owned(),
        actor: actor.to_owned(),
        reason: reason.to_owned(),
    })
}

pub async fn replay<T: DeserializeOwned>(
    pool: &PgPool,
    operation: &AdminOperationClaim,
) -> AdminAppResult<Option<T>> {
    let Some(row) = sqlx::query(
        "SELECT command, request_hash, actor, reason, response_document
         FROM admin_operations WHERE operation_id = $1",
    )
    .bind(&operation.operation_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| ApiError::Database)?
    else {
        return Ok(None);
    };
    operation_response(row, operation).map(Some)
}

pub async fn claim_prepared<T: DeserializeOwned>(
    tx: &mut Transaction<'_, Postgres>,
    operation: &AdminOperationClaim,
) -> AdminAppResult<Option<T>> {
    let inserted = sqlx::query(
        "INSERT INTO admin_operations (operation_id, command, request_hash, actor, reason)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (operation_id) DO NOTHING",
    )
    .bind(&operation.operation_id)
    .bind(&operation.command)
    .bind(&operation.request_hash)
    .bind(&operation.actor)
    .bind(&operation.reason)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?
    .rows_affected();
    if inserted == 1 {
        return Ok(None);
    }
    let row = sqlx::query(
        "SELECT command, request_hash, actor, reason, response_document
         FROM admin_operations WHERE operation_id = $1",
    )
    .bind(&operation.operation_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    operation_response(row, operation).map(Some)
}

pub async fn finish_prepared<T: Serialize>(
    tx: &mut Transaction<'_, Postgres>,
    response: &T,
    operation: &AdminOperationClaim,
) -> AdminAppResult<()> {
    let document = serde_json::to_value(response)?;
    let updated = sqlx::query(
        "UPDATE admin_operations SET response_document = $2
         WHERE operation_id = $1 AND response_document IS NULL",
    )
    .bind(&operation.operation_id)
    .bind(document)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?
    .rows_affected();
    if updated == 1 {
        Ok(())
    } else {
        Err(AdminAppError::IdempotencyConflict)
    }
}

fn operation_response<T: DeserializeOwned>(
    row: sqlx::postgres::PgRow,
    operation: &AdminOperationClaim,
) -> AdminAppResult<T> {
    let same = row.try_get::<String, _>("command").ok().as_deref()
        == Some(operation.command.as_str())
        && row.try_get::<String, _>("request_hash").ok().as_deref()
            == Some(operation.request_hash.as_str())
        && row.try_get::<String, _>("actor").ok().as_deref() == Some(operation.actor.as_str())
        && row.try_get::<String, _>("reason").ok().as_deref() == Some(operation.reason.as_str());
    if !same {
        return Err(AdminAppError::IdempotencyConflict);
    }
    let response = row
        .try_get::<Option<Value>, _>("response_document")
        .map_err(|_| ApiError::Database)?
        .ok_or(AdminAppError::IdempotencyConflict)?;
    serde_json::from_value(response).map_err(Into::into)
}

pub async fn claim<T: DeserializeOwned>(
    tx: &mut Transaction<'_, Postgres>,
    command: &str,
    request_hash: &str,
    context: &MutationContext,
) -> AdminAppResult<Option<T>> {
    let operation = AdminOperationClaim {
        operation_id: operation_id(context)?.to_owned(),
        command: command.to_owned(),
        request_hash: request_hash.to_owned(),
        actor: context.principal.id.clone(),
        reason: context.reason.clone(),
    };
    claim_prepared(tx, &operation).await
}

pub async fn finish<T: Serialize>(
    tx: &mut Transaction<'_, Postgres>,
    response: &T,
    context: &MutationContext,
) -> AdminAppResult<()> {
    let operation = AdminOperationClaim {
        operation_id: operation_id(context)?.to_owned(),
        command: String::new(),
        request_hash: String::new(),
        actor: context.principal.id.clone(),
        reason: context.reason.clone(),
    };
    finish_prepared(tx, response, &operation).await
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::admin_app::AdminPrincipal;

    fn context(operation_id: Option<&str>) -> MutationContext {
        let mut context = MutationContext::new(
            AdminPrincipal {
                id: "admin_test".to_owned(),
                session_id: Some("session_test".to_owned()),
                source_ip: None,
                user_agent_hash: None,
                request_id: None,
            },
            "test operation",
        )
        .unwrap();
        context.operation_id = operation_id.map(str::to_owned);
        context
    }

    #[test]
    fn operation_identifiers_are_required_and_bounded() {
        assert!(operation_id(&context(None)).is_err());
        assert!(operation_id(&context(Some("operation-1"))).is_ok());
        assert!(operation_id(&context(Some(&"x".repeat(129)))).is_err());
    }

    #[test]
    fn request_hash_binds_every_canonical_field() {
        let first = request_hash(&json!({"accountId":"a", "role":"viewer"})).unwrap();
        let retry = request_hash(&json!({"accountId":"a", "role":"viewer"})).unwrap();
        let changed = request_hash(&json!({"accountId":"a", "role":"admin"})).unwrap();
        assert_eq!(first, retry);
        assert_ne!(first, changed);
    }

    #[test]
    fn prepared_operations_are_optional_for_cli_and_strict_when_present() {
        let without_key = context(None);
        assert!(
            prepare("account.create", &json!({"id": "a"}), &without_key)
                .unwrap()
                .is_none()
        );

        let with_key = context(Some(" operation-1 "));
        let prepared = prepare("account.create", &json!({"id": "a"}), &with_key)
            .unwrap()
            .expect("operation should be prepared");
        assert_eq!(prepared.operation_id, "operation-1");

        let invalid = context(Some("   "));
        assert!(prepare("account.create", &json!({"id": "a"}), &invalid).is_err());
    }
}
