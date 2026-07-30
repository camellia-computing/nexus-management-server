use std::{collections::BTreeMap, str::FromStr};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};

use crate::{
    admin_app::{AdminAppError, AdminAppResult, MutationContext, Page, PageRequest},
    admin_auth::{AdminPermission, authorize_admin_mutation},
    admin_operation::{self, AdminOperationClaim},
    contracts::Plan,
    crypto::random_id,
    domain::{AuditEventRecord, LicenseStatus},
    error::{ApiError, Result},
    plan_catalog::{
        CURRENT_PLAN_REVISION, TEAM_MAXIMUM_SEATS, TEAM_MINIMUM_SEATS, effective_policy,
        validate_purchased_seats,
    },
    store::PostgresRepository,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommercialOffer {
    pub id: String,
    pub row_version: u64,
    pub plan: Plan,
    pub plan_revision: u32,
    pub duration_days: u32,
    pub currency: String,
    #[serde(with = "rust_decimal::serde::str")]
    pub base_amount: Decimal,
    #[serde(default, with = "rust_decimal::serde::str_option")]
    pub seat_amount: Option<Decimal>,
    pub name_en: String,
    pub name_zh: String,
    pub active: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManualPaymentMethod {
    pub id: String,
    pub row_version: u64,
    pub name_en: String,
    pub name_zh: String,
    pub instructions_en: String,
    pub instructions_zh: String,
    pub settlement_asset: String,
    pub destination_hint: String,
    pub active: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvoiceStatus {
    Open,
    Paid,
    Overdue,
    Void,
    Refunded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BillingInvoice {
    pub id: String,
    pub row_version: u64,
    pub account_id: String,
    pub license_id: String,
    pub offer_id: String,
    pub plan: Plan,
    pub plan_revision: u32,
    pub seats: u32,
    pub duration_days: u32,
    pub currency: String,
    #[serde(with = "rust_decimal::serde::str")]
    pub amount_due: Decimal,
    pub payment_reference: String,
    pub status: InvoiceStatus,
    pub due_at: i64,
    pub paid_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentClaimStatus {
    Submitted,
    UnderReview,
    NeedsInformation,
    Verified,
    Rejected,
    Withdrawn,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManualPaymentClaim {
    pub id: String,
    pub row_version: u64,
    pub invoice_id: String,
    pub account_id: String,
    pub payment_method_id: String,
    pub external_transaction_id: String,
    #[serde(with = "rust_decimal::serde::str")]
    pub paid_amount: Decimal,
    pub paid_asset: String,
    pub paid_at: i64,
    pub payer_name: Option<String>,
    pub note: Option<String>,
    pub status: PaymentClaimStatus,
    pub submitted_by: String,
    pub reviewed_by: Option<String>,
    pub review_reason: Option<String>,
    pub submitted_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BillingCursor {
    created_at: i64,
    id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentReviewDecision {
    Approve,
    Reject,
    RequestInformation,
}

pub(crate) fn validate_payment_review_override(
    decision: PaymentReviewDecision,
    allow_amount_override: bool,
) -> Result<()> {
    if allow_amount_override && decision != PaymentReviewDecision::Approve {
        Err(ApiError::InvalidRequest)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct NewInvoice<'a> {
    pub id: &'a str,
    pub account_id: &'a str,
    pub license_id: &'a str,
    pub offer_id: &'a str,
    pub seats: u32,
    pub due_at: i64,
}

#[derive(Debug, Clone)]
pub struct NewPaymentClaim<'a> {
    pub id: &'a str,
    pub invoice_id: &'a str,
    pub payment_method_id: &'a str,
    pub external_transaction_id: &'a str,
    pub paid_amount: Decimal,
    pub paid_asset: &'a str,
    pub paid_at: i64,
    pub payer_name: Option<&'a str>,
    pub note: Option<&'a str>,
    pub submitted_by: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CustomerPaymentSubmission {
    pub operation_id: String,
    pub invoice_id: String,
    pub payment_method_id: String,
    pub external_transaction_id: String,
    #[serde(with = "rust_decimal::serde::str")]
    pub paid_amount: Decimal,
    pub paid_asset: String,
    pub paid_at: i64,
    pub payer_name: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
struct CanonicalCustomerPaymentSubmission {
    operation_id: String,
    invoice_id: String,
    payment_method_id: String,
    external_transaction_id: String,
    paid_amount: Decimal,
    paid_asset: String,
    paid_at: i64,
    payer_name: Option<String>,
    note: Option<String>,
}

impl CanonicalCustomerPaymentSubmission {
    fn as_new_claim<'a>(&'a self, id: &'a str, submitted_by: &'a str) -> NewPaymentClaim<'a> {
        NewPaymentClaim {
            id,
            invoice_id: &self.invoice_id,
            payment_method_id: &self.payment_method_id,
            external_transaction_id: &self.external_transaction_id,
            paid_amount: self.paid_amount,
            paid_asset: &self.paid_asset,
            paid_at: self.paid_at,
            payer_name: self.payer_name.as_deref(),
            note: self.note.as_deref(),
            submitted_by,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CustomerPaymentOperation<'a> {
    account_id: &'a str,
    operation_id: &'a str,
    request_hash: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BillingSummary {
    pub invoices: Vec<BillingInvoice>,
    pub payment_claims: Vec<ManualPaymentClaim>,
    pub payment_methods: Vec<ManualPaymentMethod>,
}

#[async_trait]
pub trait CommercialRepository: Send + Sync + 'static {
    async fn customer_billing_summary(&self, account_id: &str, now: i64) -> Result<BillingSummary>;
    async fn submit_customer_payment(
        &self,
        account_id: &str,
        submitted_by: &str,
        submission: CustomerPaymentSubmission,
        now: i64,
    ) -> Result<ManualPaymentClaim>;
}

#[async_trait]
impl CommercialRepository for PostgresRepository {
    async fn customer_billing_summary(
        &self,
        account_id: &str,
        _now: i64,
    ) -> Result<BillingSummary> {
        let invoice_rows = sqlx::query(
            "SELECT id, row_version, account_id, license_id, offer_id, plan, plan_revision, seats,
                    duration_days, currency, amount_due, payment_reference, status, due_at,
                    paid_at, created_at, updated_at
             FROM billing_invoices WHERE account_id = $1
             ORDER BY created_at DESC, id DESC LIMIT 100",
        )
        .bind(account_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        let rows = sqlx::query(
            "SELECT id, row_version, invoice_id, account_id, payment_method_id, external_transaction_id,
                    paid_amount, paid_asset, paid_at, payer_name, note, status, submitted_by,
                    reviewed_by, review_reason, submitted_at, created_at, updated_at
             FROM manual_payment_claims WHERE account_id = $1
             ORDER BY created_at DESC, id DESC LIMIT 100",
        )
        .bind(account_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        Ok(BillingSummary {
            invoices: invoice_rows
                .into_iter()
                .map(row_invoice)
                .collect::<Result<_>>()?,
            payment_claims: rows
                .into_iter()
                .map(row_payment_claim)
                .collect::<Result<_>>()?,
            payment_methods: self.manual_payment_methods(true).await?,
        })
    }

    async fn submit_customer_payment(
        &self,
        account_id: &str,
        submitted_by: &str,
        submission: CustomerPaymentSubmission,
        now: i64,
    ) -> Result<ManualPaymentClaim> {
        let submission = canonical_customer_payment_submission(submission, now)?;
        let request_hash = customer_payment_request_hash(&submission);
        let claim_id = random_id("payment_claim");
        self.submit_manual_payment_claim_for_account(
            submission.as_new_claim(&claim_id, submitted_by),
            Some(CustomerPaymentOperation {
                account_id,
                operation_id: &submission.operation_id,
                request_hash: &request_hash,
            }),
            now,
        )
        .await
    }
}

impl PostgresRepository {
    pub async fn create_commercial_offer(
        &self,
        offer: &CommercialOffer,
        actor: &str,
        reason: &str,
        operation: Option<&AdminOperationClaim>,
        context: Option<&MutationContext>,
    ) -> AdminAppResult<CommercialOffer> {
        validate_offer(offer)?;
        validate_admin_context(context, actor, reason)?;
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        if let Some(context) = context {
            authorize_admin_mutation(
                &mut tx,
                context,
                AdminPermission::BillingWrite,
                false,
                offer.created_at,
            )
            .await?;
        }
        if let Some(operation) = operation
            && let Some(response) =
                admin_operation::claim_prepared::<CommercialOffer>(&mut tx, operation).await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(response);
        }
        sqlx::query(
            "INSERT INTO commercial_offers
                (id, plan, plan_revision, duration_days, currency, base_amount, seat_amount,
                 name_en, name_zh, active, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(&offer.id)
        .bind(plan_name(offer.plan))
        .bind(i32::try_from(offer.plan_revision).map_err(|_| ApiError::InvalidRequest)?)
        .bind(i32::try_from(offer.duration_days).map_err(|_| ApiError::InvalidRequest)?)
        .bind(&offer.currency)
        .bind(offer.base_amount)
        .bind(offer.seat_amount)
        .bind(&offer.name_en)
        .bind(&offer.name_zh)
        .bind(offer.active)
        .bind(offer.created_at)
        .bind(offer.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(billing_admin_database_error)?;
        insert_billing_audit_tx(
            &mut tx,
            billing_audit(
                "commercial_offer_created",
                actor,
                reason,
                None,
                None,
                offer.created_at,
                BTreeMap::from([("offer_id".into(), offer.id.clone())]),
            ),
        )
        .await?;
        if let Some(operation) = operation {
            admin_operation::finish_prepared(&mut tx, offer, operation).await?;
        }
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(offer.clone())
    }

    pub async fn commercial_offers(&self, active_only: bool) -> Result<Vec<CommercialOffer>> {
        let rows = sqlx::query(
            "SELECT id, row_version, plan, plan_revision, duration_days, currency, base_amount, seat_amount,
                    name_en, name_zh, active, created_at, updated_at
             FROM commercial_offers
             WHERE NOT $1 OR active
             ORDER BY plan, duration_days, id",
        )
        .bind(active_only)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        rows.into_iter().map(row_offer).collect()
    }

    pub async fn create_manual_payment_method(
        &self,
        method: &ManualPaymentMethod,
        actor: &str,
        reason: &str,
        operation: Option<&AdminOperationClaim>,
        context: Option<&MutationContext>,
    ) -> AdminAppResult<ManualPaymentMethod> {
        validate_method(method)?;
        validate_admin_context(context, actor, reason)?;
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        if let Some(context) = context {
            authorize_admin_mutation(
                &mut tx,
                context,
                AdminPermission::BillingWrite,
                false,
                method.created_at,
            )
            .await?;
        }
        if let Some(operation) = operation
            && let Some(response) =
                admin_operation::claim_prepared::<ManualPaymentMethod>(&mut tx, operation).await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(response);
        }
        sqlx::query(
            "INSERT INTO manual_payment_methods
                (id, name_en, name_zh, instructions_en, instructions_zh, settlement_asset,
                 destination_hint, active, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(&method.id)
        .bind(&method.name_en)
        .bind(&method.name_zh)
        .bind(&method.instructions_en)
        .bind(&method.instructions_zh)
        .bind(&method.settlement_asset)
        .bind(&method.destination_hint)
        .bind(method.active)
        .bind(method.created_at)
        .bind(method.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(billing_admin_database_error)?;
        insert_billing_audit_tx(
            &mut tx,
            billing_audit(
                "manual_payment_method_created",
                actor,
                reason,
                None,
                None,
                method.created_at,
                BTreeMap::from([("payment_method_id".into(), method.id.clone())]),
            ),
        )
        .await?;
        if let Some(operation) = operation {
            admin_operation::finish_prepared(&mut tx, method, operation).await?;
        }
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(method.clone())
    }

    pub async fn manual_payment_methods(
        &self,
        active_only: bool,
    ) -> Result<Vec<ManualPaymentMethod>> {
        let rows = sqlx::query(
            "SELECT id, row_version, name_en, name_zh, instructions_en, instructions_zh, settlement_asset,
                    destination_hint, active, created_at, updated_at
             FROM manual_payment_methods
             WHERE NOT $1 OR active
             ORDER BY id",
        )
        .bind(active_only)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        rows.into_iter().map(row_payment_method).collect()
    }

    pub async fn create_billing_invoice(
        &self,
        request: NewInvoice<'_>,
        actor: &str,
        reason: &str,
        now: i64,
        operation: Option<&AdminOperationClaim>,
        context: Option<&MutationContext>,
    ) -> AdminAppResult<BillingInvoice> {
        validate_admin_context(context, actor, reason)?;
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        if let Some(context) = context {
            authorize_admin_mutation(&mut tx, context, AdminPermission::BillingWrite, false, now)
                .await?;
        }
        if let Some(operation) = operation
            && let Some(response) =
                admin_operation::claim_prepared::<BillingInvoice>(&mut tx, operation).await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(response);
        }
        if request.id.trim().is_empty() || request.due_at <= now {
            return Err(ApiError::InvalidRequest.into());
        }
        let offer = load_offer(&mut tx, request.offer_id).await?;
        if !offer.active {
            return Err(ApiError::InvalidRequest.into());
        }
        let license = load_license_policy(&mut tx, request.license_id).await?;
        if license.0 != request.account_id {
            return Err(ApiError::InvalidRequest.into());
        }
        validate_invoice_seats(offer.plan, request.seats)?;
        let seats = request.seats;
        effective_policy(offer.plan, offer.plan_revision, seats)?;
        let amount_due =
            offer.base_amount + offer.seat_amount.unwrap_or(Decimal::ZERO) * Decimal::from(seats);
        let invoice = BillingInvoice {
            id: request.id.to_owned(),
            row_version: 1,
            account_id: request.account_id.to_owned(),
            license_id: request.license_id.to_owned(),
            offer_id: offer.id,
            plan: offer.plan,
            plan_revision: offer.plan_revision,
            seats,
            duration_days: offer.duration_days,
            currency: offer.currency,
            amount_due,
            payment_reference: format!("CNX-{}", random_id("pay").to_ascii_uppercase()),
            status: InvoiceStatus::Open,
            due_at: request.due_at,
            paid_at: None,
            created_at: now,
            updated_at: now,
        };
        insert_invoice(&mut tx, &invoice).await?;
        insert_billing_audit_tx(
            &mut tx,
            billing_audit(
                "billing_invoice_created",
                actor,
                reason,
                Some(&invoice.account_id),
                Some(&invoice.license_id),
                now,
                BTreeMap::from([("invoice_id".into(), invoice.id.clone())]),
            ),
        )
        .await?;
        if let Some(operation) = operation {
            admin_operation::finish_prepared(&mut tx, &invoice, operation).await?;
        }
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(invoice)
    }

    pub async fn billing_invoices(
        &self,
        account_id: Option<&str>,
        request: PageRequest,
    ) -> AdminAppResult<Page<BillingInvoice>> {
        let request = request.validate()?;
        let cursor = request
            .cursor
            .as_deref()
            .map(decode_billing_cursor)
            .transpose()?;
        let rows = sqlx::query(
            "SELECT id, row_version, account_id, license_id, offer_id, plan, plan_revision, seats,
                    duration_days, currency, amount_due, payment_reference, status, due_at,
                    paid_at, created_at, updated_at
             FROM billing_invoices
             WHERE ($1::TEXT IS NULL OR account_id = $1)
               AND (
                 $2::BIGINT IS NULL
                 OR (created_at, id) < ($2, $3::TEXT)
               )
               AND (
                 $4::TEXT IS NULL
                 OR strpos(
                   lower(concat_ws(' ', id, account_id, license_id, offer_id,
                                   payment_reference, status, currency)),
                   lower($4)
                 ) > 0
               )
             ORDER BY created_at DESC, id DESC
             LIMIT $5",
        )
        .bind(account_id)
        .bind(cursor.as_ref().map(|cursor| cursor.created_at))
        .bind(cursor.as_ref().map(|cursor| cursor.id.as_str()))
        .bind(request.query.as_deref())
        .bind(i64::from(request.page_size) + 1)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        let has_more = rows.len() > request.page_size as usize;
        let items = rows
            .into_iter()
            .take(request.page_size as usize)
            .map(row_invoice)
            .collect::<Result<Vec<_>>>()?;
        let next_cursor = if has_more {
            items
                .last()
                .map(|invoice| {
                    encode_billing_cursor(&BillingCursor {
                        created_at: invoice.created_at,
                        id: invoice.id.clone(),
                    })
                })
                .transpose()?
        } else {
            None
        };
        Ok(Page { items, next_cursor })
    }

    pub async fn submit_manual_payment_claim(
        &self,
        request: NewPaymentClaim<'_>,
        now: i64,
    ) -> Result<ManualPaymentClaim> {
        self.submit_manual_payment_claim_for_account(request, None, now)
            .await
    }

    async fn submit_manual_payment_claim_for_account(
        &self,
        request: NewPaymentClaim<'_>,
        customer_operation: Option<CustomerPaymentOperation<'_>>,
        now: i64,
    ) -> Result<ManualPaymentClaim> {
        validate_payment_claim(&request, now)?;
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        if let Some(operation) = customer_operation
            && let Some(response) =
                claim_customer_payment_operation(&mut tx, operation, now).await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(response);
        }
        let expected_account_id = customer_operation.map(|operation| operation.account_id);
        let external_transaction_id = request.external_transaction_id.trim();
        if let Some(existing) = load_payment_claim_by_transaction(
            &mut tx,
            request.payment_method_id,
            external_transaction_id,
        )
        .await?
        {
            if let Some(operation) = customer_operation {
                if existing.account_id != operation.account_id
                    || existing.invoice_id != request.invoice_id
                    || existing.status != PaymentClaimStatus::NeedsInformation
                {
                    return Err(ApiError::InvalidRequest);
                }
            } else {
                if !same_payment_submission_identity(&existing, &request, None) {
                    return Err(ApiError::InvalidRequest);
                }
                if existing.status != PaymentClaimStatus::NeedsInformation {
                    tx.commit().await.map_err(|_| ApiError::Database)?;
                    return Ok(existing);
                }
            }
        }
        let invoice = load_invoice_for_update(&mut tx, request.invoice_id).await?;
        if expected_account_id.is_some_and(|account_id| account_id != invoice.account_id) {
            return Err(ApiError::InvalidRequest);
        }
        if invoice.status != InvoiceStatus::Open || invoice.due_at <= now {
            return Err(ApiError::InvalidRequest);
        }
        let method = load_payment_method(&mut tx, request.payment_method_id).await?;
        if !method.active || method.settlement_asset != request.paid_asset {
            return Err(ApiError::InvalidRequest);
        }
        let existing = sqlx::query(
            "SELECT id, row_version, invoice_id, account_id, payment_method_id, external_transaction_id,
                    paid_amount, paid_asset, paid_at, payer_name, note, status, submitted_by,
                    reviewed_by, review_reason, submitted_at, created_at, updated_at
             FROM manual_payment_claims
             WHERE invoice_id = $1 AND status = 'needs_information'
             FOR UPDATE",
        )
        .bind(&invoice.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| ApiError::Database)?
        .map(row_payment_claim)
        .transpose()?;
        ensure_unique_transaction(
            &mut tx,
            &method.id,
            external_transaction_id,
            existing.as_ref().map(|claim| claim.id.as_str()),
        )
        .await?;
        if let Some(mut claim) = existing {
            claim.payment_method_id = method.id;
            claim.external_transaction_id = external_transaction_id.to_owned();
            claim.paid_amount = request.paid_amount;
            claim.paid_asset = request.paid_asset.to_owned();
            claim.paid_at = request.paid_at;
            claim.payer_name = bounded_optional(request.payer_name, 256)?;
            claim.note = bounded_optional(request.note, 2_000)?;
            claim.status = PaymentClaimStatus::Submitted;
            claim.submitted_by = bounded(request.submitted_by, 256)?;
            claim.reviewed_by = None;
            claim.review_reason = None;
            claim.submitted_at = now;
            claim.updated_at = now;
            resubmit_payment_claim(&mut tx, &mut claim).await?;
            insert_billing_audit_tx(
                &mut tx,
                billing_audit(
                    "manual_payment_resubmitted",
                    &claim.submitted_by,
                    "customer supplied requested payment information",
                    Some(&claim.account_id),
                    Some(&invoice.license_id),
                    now,
                    BTreeMap::from([
                        ("invoice_id".into(), claim.invoice_id.clone()),
                        ("payment_claim_id".into(), claim.id.clone()),
                    ]),
                ),
            )
            .await?;
            if let Some(operation) = customer_operation {
                finish_customer_payment_operation(&mut tx, operation, &claim).await?;
            }
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(claim);
        }
        let claim = ManualPaymentClaim {
            id: request.id.to_owned(),
            row_version: 1,
            invoice_id: invoice.id,
            account_id: invoice.account_id,
            payment_method_id: method.id,
            external_transaction_id: external_transaction_id.to_owned(),
            paid_amount: request.paid_amount,
            paid_asset: request.paid_asset.to_owned(),
            paid_at: request.paid_at,
            payer_name: bounded_optional(request.payer_name, 256)?,
            note: bounded_optional(request.note, 2_000)?,
            status: PaymentClaimStatus::Submitted,
            submitted_by: bounded(request.submitted_by, 256)?,
            reviewed_by: None,
            review_reason: None,
            submitted_at: now,
            created_at: now,
            updated_at: now,
        };
        if !insert_payment_claim(&mut tx, &claim).await? {
            if customer_operation.is_some() {
                return Err(customer_payment_operation_conflict());
            }
            let existing = load_payment_claim_by_transaction(
                &mut tx,
                &claim.payment_method_id,
                &claim.external_transaction_id,
            )
            .await?
            .filter(|existing| {
                same_payment_submission_identity(existing, &request, expected_account_id)
            })
            .ok_or(ApiError::InvalidRequest)?;
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(existing);
        }
        insert_billing_audit_tx(
            &mut tx,
            billing_audit(
                "manual_payment_submitted",
                &claim.submitted_by,
                "customer submitted payment evidence",
                Some(&claim.account_id),
                Some(&invoice.license_id),
                now,
                BTreeMap::from([
                    ("invoice_id".into(), claim.invoice_id.clone()),
                    ("payment_claim_id".into(), claim.id.clone()),
                ]),
            ),
        )
        .await?;
        if let Some(operation) = customer_operation {
            finish_customer_payment_operation(&mut tx, operation, &claim).await?;
        }
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(claim)
    }

    pub async fn manual_payment_claims(
        &self,
        status: Option<PaymentClaimStatus>,
        request: PageRequest,
    ) -> AdminAppResult<Page<ManualPaymentClaim>> {
        let request = request.validate()?;
        let cursor = request
            .cursor
            .as_deref()
            .map(decode_billing_cursor)
            .transpose()?;
        let rows = sqlx::query(
            "SELECT id, row_version, invoice_id, account_id, payment_method_id, external_transaction_id,
                    paid_amount, paid_asset, paid_at, payer_name, note, status, submitted_by,
                    reviewed_by, review_reason, submitted_at, created_at, updated_at
             FROM manual_payment_claims
             WHERE ($1::TEXT IS NULL OR status = $1)
               AND (
                 $2::BIGINT IS NULL
                 OR (created_at, id) < ($2, $3::TEXT)
               )
               AND (
                 $4::TEXT IS NULL
                 OR strpos(
                   lower(concat_ws(' ', id, invoice_id, account_id, payment_method_id,
                                   external_transaction_id, paid_asset, payer_name,
                                   status, submitted_by, reviewed_by)),
                   lower($4)
                 ) > 0
               )
             ORDER BY created_at DESC, id DESC
             LIMIT $5",
        )
        .bind(status.map(payment_claim_status_name))
        .bind(cursor.as_ref().map(|cursor| cursor.created_at))
        .bind(cursor.as_ref().map(|cursor| cursor.id.as_str()))
        .bind(request.query.as_deref())
        .bind(i64::from(request.page_size) + 1)
        .fetch_all(&self.pool)
        .await
        .map_err(|_| ApiError::Database)?;
        let has_more = rows.len() > request.page_size as usize;
        let items = rows
            .into_iter()
            .take(request.page_size as usize)
            .map(row_payment_claim)
            .collect::<Result<Vec<_>>>()?;
        let next_cursor = if has_more {
            items
                .last()
                .map(|claim| {
                    encode_billing_cursor(&BillingCursor {
                        created_at: claim.created_at,
                        id: claim.id.clone(),
                    })
                })
                .transpose()?
        } else {
            None
        };
        Ok(Page { items, next_cursor })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn review_manual_payment_claim(
        &self,
        claim_id: &str,
        expected_row_version: u64,
        decision: PaymentReviewDecision,
        actor: &str,
        reason: &str,
        operation_id: &str,
        allow_amount_override: bool,
        now: i64,
        context: Option<&MutationContext>,
    ) -> AdminAppResult<ManualPaymentClaim> {
        if expected_row_version == 0 {
            return Err(ApiError::InvalidRequest.into());
        }
        validate_payment_review_override(decision, allow_amount_override)?;
        let actor = bounded(actor, 256)?;
        let reason = bounded(reason, 1_000)?;
        let operation_id = bounded(operation_id, 128)?;
        validate_admin_context(context, &actor, &reason)?;
        if context
            .and_then(|context| context.operation_id.as_deref())
            .is_some_and(|value| value != operation_id)
        {
            return Err(ApiError::InvalidRequest.into());
        }
        let request_hash = review_request_hash(
            claim_id,
            expected_row_version,
            decision,
            &actor,
            &reason,
            allow_amount_override,
        );
        let operation = admin_operation::from_parts(
            &operation_id,
            "billing.payment.review",
            &request_hash,
            &actor,
            &reason,
        )?;
        let mut tx = self.pool.begin().await.map_err(|_| ApiError::Database)?;
        if let Some(context) = context {
            authorize_admin_mutation(&mut tx, context, AdminPermission::BillingReview, false, now)
                .await?;
            if allow_amount_override {
                authorize_admin_mutation(
                    &mut tx,
                    context,
                    AdminPermission::BillingOverride,
                    true,
                    now,
                )
                .await?;
            }
        }
        if let Some(response) =
            admin_operation::claim_prepared::<ManualPaymentClaim>(&mut tx, &operation).await?
        {
            tx.commit().await.map_err(|_| ApiError::Database)?;
            return Ok(response);
        }
        let mut claim = load_payment_claim_for_update(&mut tx, claim_id).await?;
        if expected_row_version != claim.row_version {
            return Err(AdminAppError::VersionConflict);
        }
        if !matches!(
            claim.status,
            PaymentClaimStatus::Submitted
                | PaymentClaimStatus::UnderReview
                | PaymentClaimStatus::NeedsInformation
        ) {
            return Err(ApiError::InvalidRequest.into());
        }
        let mut invoice = load_invoice_for_update(&mut tx, &claim.invoice_id).await?;
        if invoice.status != InvoiceStatus::Open {
            return Err(ApiError::InvalidRequest.into());
        }
        claim.reviewed_by = Some(actor.clone());
        claim.review_reason = Some(reason.clone());
        claim.updated_at = now;
        let event_type = match decision {
            PaymentReviewDecision::RequestInformation => {
                claim.status = PaymentClaimStatus::NeedsInformation;
                "manual_payment_information_requested"
            }
            PaymentReviewDecision::Reject => {
                claim.status = PaymentClaimStatus::Rejected;
                "manual_payment_rejected"
            }
            PaymentReviewDecision::Approve => {
                if (claim.paid_asset != invoice.currency || claim.paid_amount != invoice.amount_due)
                    && !allow_amount_override
                {
                    return Err(ApiError::InvalidRequest.into());
                }
                ensure_clean_evidence(&mut tx, &claim.id).await?;
                claim.status = PaymentClaimStatus::Verified;
                invoice.status = InvoiceStatus::Paid;
                invoice.paid_at = Some(now);
                invoice.updated_at = now;
                apply_paid_invoice(&mut tx, &invoice, now).await?;
                update_invoice(&mut tx, &mut invoice).await?;
                "manual_payment_verified"
            }
        };
        update_payment_claim(&mut tx, &mut claim).await?;
        insert_billing_audit_tx(
            &mut tx,
            billing_audit(
                event_type,
                &actor,
                &reason,
                Some(&claim.account_id),
                Some(&invoice.license_id),
                now,
                BTreeMap::from([
                    ("invoice_id".into(), invoice.id),
                    ("payment_claim_id".into(), claim.id.clone()),
                    ("operation_id".into(), operation_id),
                ]),
            ),
        )
        .await?;
        admin_operation::finish_prepared(&mut tx, &claim, &operation).await?;
        tx.commit().await.map_err(|_| ApiError::Database)?;
        Ok(claim)
    }
}

fn validate_invoice_seats(plan: Plan, seats: u32) -> AdminAppResult<()> {
    validate_purchased_seats(plan, seats).map_err(|_| {
        AdminAppError::Validation(match plan {
            Plan::Team => format!(
                "Team invoice seats must be between {TEAM_MINIMUM_SEATS} and {TEAM_MAXIMUM_SEATS}"
            ),
            Plan::Free | Plan::Pro => "Non-Team invoice seats must be zero".to_owned(),
        })
    })
}

fn encode_billing_cursor(cursor: &BillingCursor) -> AdminAppResult<String> {
    Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(cursor)?))
}

fn decode_billing_cursor(value: &str) -> AdminAppResult<BillingCursor> {
    if value.is_empty() || value.len() > 512 {
        return Err(AdminAppError::Validation(
            "billing cursor is invalid".to_owned(),
        ));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AdminAppError::Validation("billing cursor is invalid".to_owned()))?;
    let cursor: BillingCursor = serde_json::from_slice(&bytes)
        .map_err(|_| AdminAppError::Validation("billing cursor is invalid".to_owned()))?;
    if cursor.created_at < 0
        || cursor.id.is_empty()
        || cursor.id.len() > 128
        || !cursor
            .id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
        || encode_billing_cursor(&cursor)? != value
    {
        return Err(AdminAppError::Validation(
            "billing cursor is invalid".to_owned(),
        ));
    }
    Ok(cursor)
}

fn validate_admin_context(
    context: Option<&MutationContext>,
    actor: &str,
    reason: &str,
) -> AdminAppResult<()> {
    if context.is_some_and(|context| {
        context.principal.id != actor.trim() || context.reason != reason.trim()
    }) {
        return Err(ApiError::InvalidRequest.into());
    }
    Ok(())
}

fn validate_offer(offer: &CommercialOffer) -> Result<()> {
    if offer.row_version != 1
        || !matches!(offer.plan, Plan::Pro | Plan::Team)
        || offer.plan_revision != CURRENT_PLAN_REVISION
        || !(1..=3_660).contains(&offer.duration_days)
        || offer.base_amount.is_sign_negative()
        || offer
            .seat_amount
            .is_some_and(|amount| amount.is_sign_negative())
        || !valid_asset(&offer.currency)
        || offer.id.trim().is_empty()
        || offer.name_en.trim().is_empty()
        || offer.name_zh.trim().is_empty()
        || (offer.plan == Plan::Team && offer.seat_amount.is_none())
        || (offer.plan == Plan::Pro && offer.seat_amount.is_some())
    {
        return Err(ApiError::InvalidRequest);
    }
    effective_policy(
        offer.plan,
        offer.plan_revision,
        if offer.plan == Plan::Team { 3 } else { 0 },
    )?;
    Ok(())
}

fn billing_admin_database_error(error: sqlx::Error) -> AdminAppError {
    if error
        .as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
    {
        AdminAppError::IdempotencyConflict
    } else {
        AdminAppError::Service(ApiError::Database)
    }
}

fn validate_method(method: &ManualPaymentMethod) -> Result<()> {
    if method.row_version != 1
        || method.id.trim().is_empty()
        || method.name_en.trim().is_empty()
        || method.name_zh.trim().is_empty()
        || method.instructions_en.trim().is_empty()
        || method.instructions_zh.trim().is_empty()
        || method.destination_hint.trim().is_empty()
        || !valid_asset(&method.settlement_asset)
    {
        return Err(ApiError::InvalidRequest);
    }
    Ok(())
}

fn validate_payment_claim(request: &NewPaymentClaim<'_>, now: i64) -> Result<()> {
    if request.id.trim().is_empty()
        || request.external_transaction_id.trim().is_empty()
        || request.external_transaction_id.len() > 256
        || request.paid_amount.is_sign_negative()
        || !valid_asset(request.paid_asset)
        || request.paid_at <= 0
        || request.paid_at > now.saturating_add(5 * 60)
    {
        return Err(ApiError::InvalidRequest);
    }
    Ok(())
}

fn canonical_customer_payment_submission(
    submission: CustomerPaymentSubmission,
    now: i64,
) -> Result<CanonicalCustomerPaymentSubmission> {
    let canonical = CanonicalCustomerPaymentSubmission {
        operation_id: canonical_customer_operation_id(&submission.operation_id)?,
        invoice_id: bounded(&submission.invoice_id, 256)?,
        payment_method_id: bounded(&submission.payment_method_id, 256)?,
        external_transaction_id: bounded(&submission.external_transaction_id, 256)?,
        paid_amount: submission.paid_amount,
        paid_asset: submission.paid_asset,
        paid_at: submission.paid_at,
        payer_name: bounded_optional(submission.payer_name.as_deref(), 256)?,
        note: bounded_optional(submission.note.as_deref(), 2_000)?,
    };
    validate_payment_claim(
        &canonical.as_new_claim("payment_claim_validation", "customer_payment_validation"),
        now,
    )?;
    Ok(canonical)
}

fn canonical_customer_operation_id(value: &str) -> Result<String> {
    let parsed = uuid::Uuid::parse_str(value).map_err(|_| ApiError::InvalidRequest)?;
    let bytes = value.as_bytes();
    if value.len() != 36
        || parsed.hyphenated().to_string() != value
        || bytes.get(14) != Some(&b'4')
        || !matches!(bytes.get(19), Some(b'8' | b'9' | b'a' | b'b'))
    {
        return Err(ApiError::InvalidRequest);
    }
    Ok(value.to_owned())
}

fn customer_payment_request_hash(submission: &CanonicalCustomerPaymentSubmission) -> String {
    let mut digest = Sha256::new();
    hash_customer_payment_field(&mut digest, b"camellia-nexus/customer-payment/v1");
    hash_customer_payment_field(&mut digest, submission.invoice_id.as_bytes());
    hash_customer_payment_field(&mut digest, submission.payment_method_id.as_bytes());
    hash_customer_payment_field(&mut digest, submission.external_transaction_id.as_bytes());
    hash_customer_payment_field(
        &mut digest,
        submission.paid_amount.normalize().to_string().as_bytes(),
    );
    hash_customer_payment_field(&mut digest, submission.paid_asset.as_bytes());
    hash_customer_payment_field(&mut digest, submission.paid_at.to_string().as_bytes());
    hash_optional_customer_payment_field(&mut digest, submission.payer_name.as_deref());
    hash_optional_customer_payment_field(&mut digest, submission.note.as_deref());
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hash_customer_payment_field(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

fn hash_optional_customer_payment_field(digest: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            digest.update([1]);
            hash_customer_payment_field(digest, value.as_bytes());
        }
        None => digest.update([0]),
    }
}

fn customer_payment_operation_conflict() -> ApiError {
    ApiError::IdempotencyConflict
}

fn valid_asset(value: &str) -> bool {
    (3..=16).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
}

fn bounded(value: &str, max: usize) -> Result<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        Err(ApiError::InvalidRequest)
    } else {
        Ok(value.to_owned())
    }
}

fn bounded_optional(value: Option<&str>, max: usize) -> Result<Option<String>> {
    value.map(|value| bounded(value, max)).transpose()
}

fn review_request_hash(
    claim_id: &str,
    expected_row_version: u64,
    decision: PaymentReviewDecision,
    actor: &str,
    reason: &str,
    allow_amount_override: bool,
) -> String {
    let decision = match decision {
        PaymentReviewDecision::Approve => "approve",
        PaymentReviewDecision::Reject => "reject",
        PaymentReviewDecision::RequestInformation => "request_information",
    };
    let payload = format!(
        "{claim_id}\n{expected_row_version}\n{decision}\n{actor}\n{reason}\n{allow_amount_override}"
    );
    Sha256::digest(payload)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn apply_paid_invoice(
    tx: &mut Transaction<'_, Postgres>,
    invoice: &BillingInvoice,
    now: i64,
) -> Result<()> {
    effective_policy(invoice.plan, invoice.plan_revision, invoice.seats)?;
    let row = sqlx::query(
        "SELECT plan, plan_revision, status, expires_at, license_epoch, row_version
         FROM licenses WHERE id = $1 AND account_id = $2 FOR UPDATE",
    )
    .bind(&invoice.license_id)
    .bind(&invoice.account_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?
    .ok_or(ApiError::LicenseUnavailable)?;
    let previous_expiry: Option<i64> = row.try_get("expires_at").map_err(|_| ApiError::Database)?;
    let base = previous_expiry.filter(|value| *value > now).unwrap_or(now);
    let expires_at = base.saturating_add(i64::from(invoice.duration_days) * 24 * 60 * 60);
    let epoch = row
        .try_get::<i64, _>("license_epoch")
        .map_err(|_| ApiError::Database)?
        .saturating_add(1);
    let row_version = row
        .try_get::<i64, _>("row_version")
        .map_err(|_| ApiError::Database)?
        .saturating_add(1);
    sqlx::query(
        "UPDATE licenses
         SET plan = $2, plan_revision = $3, status = 'active', expires_at = $4,
             license_epoch = $5, purchased_seats = $6, row_version = $7,
             updated_at = to_timestamp($8)
         WHERE id = $1",
    )
    .bind(&invoice.license_id)
    .bind(plan_name(invoice.plan))
    .bind(i32::try_from(invoice.plan_revision).map_err(|_| ApiError::InvalidRequest)?)
    .bind(expires_at)
    .bind(epoch)
    .bind(i32::try_from(invoice.seats).map_err(|_| ApiError::InvalidRequest)?)
    .bind(row_version)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    Ok(())
}

async fn ensure_clean_evidence(tx: &mut Transaction<'_, Postgres>, claim_id: &str) -> Result<()> {
    let unsafe_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM payment_evidence_attachments AS evidence
         LEFT JOIN stored_objects AS objects ON objects.id = evidence.object_id
         WHERE evidence.claim_id = $1
           AND (evidence.scan_status <> 'clean' OR objects.status IS DISTINCT FROM 'ready')",
    )
    .bind(claim_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    if unsafe_count == 0 {
        Ok(())
    } else {
        Err(ApiError::InvalidRequest)
    }
}

async fn load_license_policy(
    tx: &mut Transaction<'_, Postgres>,
    license_id: &str,
) -> Result<(String, LicenseStatus)> {
    let row = sqlx::query("SELECT account_id, status FROM licenses WHERE id = $1 FOR SHARE")
        .bind(license_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(ApiError::LicenseUnavailable)?;
    let status = match row
        .try_get::<String, _>("status")
        .map_err(|_| ApiError::Database)?
        .as_str()
    {
        "active" => LicenseStatus::Active,
        "past_due" => LicenseStatus::PastDue,
        "canceled" => LicenseStatus::Canceled,
        _ => return Err(ApiError::Database),
    };
    Ok((
        row.try_get("account_id").map_err(|_| ApiError::Database)?,
        status,
    ))
}

async fn load_offer(tx: &mut Transaction<'_, Postgres>, offer_id: &str) -> Result<CommercialOffer> {
    let row = sqlx::query(
        "SELECT id, row_version, plan, plan_revision, duration_days, currency, base_amount, seat_amount,
                name_en, name_zh, active, created_at, updated_at
         FROM commercial_offers WHERE id = $1 FOR SHARE",
    )
    .bind(offer_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?
    .ok_or(ApiError::InvalidRequest)?;
    row_offer(row)
}

async fn load_payment_method(
    tx: &mut Transaction<'_, Postgres>,
    method_id: &str,
) -> Result<ManualPaymentMethod> {
    let row = sqlx::query(
        "SELECT id, row_version, name_en, name_zh, instructions_en, instructions_zh, settlement_asset,
                destination_hint, active, created_at, updated_at
         FROM manual_payment_methods WHERE id = $1 FOR SHARE",
    )
    .bind(method_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?
    .ok_or(ApiError::InvalidRequest)?;
    row_payment_method(row)
}

async fn load_invoice_for_update(
    tx: &mut Transaction<'_, Postgres>,
    invoice_id: &str,
) -> Result<BillingInvoice> {
    let row = sqlx::query(
        "SELECT id, row_version, account_id, license_id, offer_id, plan, plan_revision, seats,
                duration_days, currency, amount_due, payment_reference, status, due_at,
                paid_at, created_at, updated_at
         FROM billing_invoices WHERE id = $1 FOR UPDATE",
    )
    .bind(invoice_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?
    .ok_or(ApiError::InvalidRequest)?;
    row_invoice(row)
}

async fn load_payment_claim_for_update(
    tx: &mut Transaction<'_, Postgres>,
    claim_id: &str,
) -> Result<ManualPaymentClaim> {
    let row = payment_claim_query(claim_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| ApiError::Database)?
        .ok_or(ApiError::InvalidRequest)?;
    row_payment_claim(row)
}

fn payment_claim_query(
    claim_id: &str,
) -> sqlx::query::Query<'_, Postgres, sqlx::postgres::PgArguments> {
    sqlx::query(
        "SELECT id, row_version, invoice_id, account_id, payment_method_id, external_transaction_id,
                paid_amount, paid_asset, paid_at, payer_name, note, status, submitted_by,
                reviewed_by, review_reason, submitted_at, created_at, updated_at
         FROM manual_payment_claims WHERE id = $1 FOR UPDATE",
    )
    .bind(claim_id)
}

async fn insert_invoice(
    tx: &mut Transaction<'_, Postgres>,
    invoice: &BillingInvoice,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO billing_invoices
            (id, account_id, license_id, offer_id, plan, plan_revision, seats, duration_days,
             currency, amount_due, payment_reference, status, due_at, paid_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
    )
    .bind(&invoice.id)
    .bind(&invoice.account_id)
    .bind(&invoice.license_id)
    .bind(&invoice.offer_id)
    .bind(plan_name(invoice.plan))
    .bind(i32::try_from(invoice.plan_revision).map_err(|_| ApiError::InvalidRequest)?)
    .bind(i32::try_from(invoice.seats).map_err(|_| ApiError::InvalidRequest)?)
    .bind(i32::try_from(invoice.duration_days).map_err(|_| ApiError::InvalidRequest)?)
    .bind(&invoice.currency)
    .bind(invoice.amount_due)
    .bind(&invoice.payment_reference)
    .bind(invoice_status_name(invoice.status))
    .bind(invoice.due_at)
    .bind(invoice.paid_at)
    .bind(invoice.created_at)
    .bind(invoice.updated_at)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    Ok(())
}

async fn update_invoice(
    tx: &mut Transaction<'_, Postgres>,
    invoice: &mut BillingInvoice,
) -> AdminAppResult<()> {
    let expected_row_version =
        i64::try_from(invoice.row_version).map_err(|_| ApiError::Database)?;
    let updated = sqlx::query(
        "UPDATE billing_invoices
         SET status = $2, paid_at = $3, updated_at = $4, row_version = row_version + 1
         WHERE id = $1 AND row_version = $5",
    )
    .bind(&invoice.id)
    .bind(invoice_status_name(invoice.status))
    .bind(invoice.paid_at)
    .bind(invoice.updated_at)
    .bind(expected_row_version)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?
    .rows_affected();
    if updated != 1 {
        return Err(AdminAppError::VersionConflict);
    }
    invoice.row_version = invoice
        .row_version
        .checked_add(1)
        .ok_or(ApiError::Database)?;
    Ok(())
}

async fn claim_customer_payment_operation(
    tx: &mut Transaction<'_, Postgres>,
    operation: CustomerPaymentOperation<'_>,
    submitted_at: i64,
) -> Result<Option<ManualPaymentClaim>> {
    let inserted = sqlx::query(
        "INSERT INTO customer_payment_operations
            (account_id, operation_id, request_hash, claim_id, response, submitted_at)
         VALUES ($1, $2, $3, NULL, NULL, $4)
         ON CONFLICT (account_id, operation_id) DO NOTHING",
    )
    .bind(operation.account_id)
    .bind(operation.operation_id)
    .bind(operation.request_hash)
    .bind(submitted_at)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?
    .rows_affected();
    if inserted == 1 {
        return Ok(None);
    }

    let row = sqlx::query(
        "SELECT request_hash, claim_id, response, submitted_at
         FROM customer_payment_operations
         WHERE account_id = $1 AND operation_id = $2
         FOR UPDATE",
    )
    .bind(operation.account_id)
    .bind(operation.operation_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    let stored_hash: String = row
        .try_get("request_hash")
        .map_err(|_| ApiError::Database)?;
    if stored_hash != operation.request_hash {
        return Err(customer_payment_operation_conflict());
    }
    let claim_id: Option<String> = row.try_get("claim_id").map_err(|_| ApiError::Database)?;
    let response: Option<serde_json::Value> =
        row.try_get("response").map_err(|_| ApiError::Database)?;
    let stored_submitted_at: i64 = row
        .try_get("submitted_at")
        .map_err(|_| ApiError::Database)?;
    let (claim_id, response) = claim_id.zip(response).ok_or(ApiError::Database)?;
    let response: ManualPaymentClaim =
        serde_json::from_value(response).map_err(|_| ApiError::Database)?;
    if response.id != claim_id
        || response.account_id != operation.account_id
        || response.submitted_at != stored_submitted_at
    {
        return Err(ApiError::Database);
    }
    Ok(Some(response))
}

async fn finish_customer_payment_operation(
    tx: &mut Transaction<'_, Postgres>,
    operation: CustomerPaymentOperation<'_>,
    response: &ManualPaymentClaim,
) -> Result<()> {
    if response.account_id != operation.account_id {
        return Err(ApiError::Internal);
    }
    let response_document = serde_json::to_value(response).map_err(|_| ApiError::Internal)?;
    let updated = sqlx::query(
        "UPDATE customer_payment_operations
         SET claim_id = $4, response = $5
         WHERE account_id = $1 AND operation_id = $2 AND request_hash = $3
           AND submitted_at = $6 AND claim_id IS NULL AND response IS NULL",
    )
    .bind(operation.account_id)
    .bind(operation.operation_id)
    .bind(operation.request_hash)
    .bind(&response.id)
    .bind(response_document)
    .bind(response.submitted_at)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?
    .rows_affected();
    if updated != 1 {
        return Err(ApiError::Database);
    }
    Ok(())
}

async fn insert_payment_claim(
    tx: &mut Transaction<'_, Postgres>,
    claim: &ManualPaymentClaim,
) -> Result<bool> {
    let inserted = sqlx::query(
        "INSERT INTO manual_payment_claims
            (id, invoice_id, account_id, payment_method_id, external_transaction_id,
             paid_amount, paid_asset, paid_at, payer_name, note, status, submitted_by,
             reviewed_by, review_reason, submitted_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
         ON CONFLICT DO NOTHING",
    )
    .bind(&claim.id)
    .bind(&claim.invoice_id)
    .bind(&claim.account_id)
    .bind(&claim.payment_method_id)
    .bind(&claim.external_transaction_id)
    .bind(claim.paid_amount)
    .bind(&claim.paid_asset)
    .bind(claim.paid_at)
    .bind(&claim.payer_name)
    .bind(&claim.note)
    .bind(payment_claim_status_name(claim.status))
    .bind(&claim.submitted_by)
    .bind(&claim.reviewed_by)
    .bind(&claim.review_reason)
    .bind(claim.submitted_at)
    .bind(claim.created_at)
    .bind(claim.updated_at)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?
    .rows_affected()
        == 1;
    Ok(inserted)
}

async fn load_payment_claim_by_transaction(
    tx: &mut Transaction<'_, Postgres>,
    payment_method_id: &str,
    external_transaction_id: &str,
) -> Result<Option<ManualPaymentClaim>> {
    sqlx::query(
        "SELECT id, row_version, invoice_id, account_id, payment_method_id, external_transaction_id,
                paid_amount, paid_asset, paid_at, payer_name, note, status, submitted_by,
                reviewed_by, review_reason, submitted_at, created_at, updated_at
         FROM manual_payment_claims
         WHERE payment_method_id = $1 AND external_transaction_id = $2
         FOR UPDATE",
    )
    .bind(payment_method_id)
    .bind(external_transaction_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?
    .map(row_payment_claim)
    .transpose()
}

fn same_payment_submission_identity(
    claim: &ManualPaymentClaim,
    request: &NewPaymentClaim<'_>,
    expected_account_id: Option<&str>,
) -> bool {
    expected_account_id.is_none_or(|account_id| claim.account_id == account_id)
        && claim.invoice_id == request.invoice_id
        && claim.payment_method_id == request.payment_method_id
        && claim.external_transaction_id == request.external_transaction_id.trim()
        && claim.paid_amount == request.paid_amount
        && claim.paid_asset == request.paid_asset
        && claim.paid_at == request.paid_at
        && claim.payer_name.as_deref() == request.payer_name.map(str::trim)
        && claim.note.as_deref() == request.note.map(str::trim)
        && claim.submitted_by == request.submitted_by.trim()
}

async fn resubmit_payment_claim(
    tx: &mut Transaction<'_, Postgres>,
    claim: &mut ManualPaymentClaim,
) -> Result<()> {
    let expected_row_version = i64::try_from(claim.row_version).map_err(|_| ApiError::Database)?;
    let updated = sqlx::query(
        "UPDATE manual_payment_claims
         SET payment_method_id = $2, external_transaction_id = $3, paid_amount = $4,
             paid_asset = $5, paid_at = $6, payer_name = $7, note = $8, status = 'submitted',
             submitted_by = $9, reviewed_by = NULL, review_reason = NULL,
             submitted_at = $10, updated_at = $11, row_version = row_version + 1
         WHERE id = $1 AND status = 'needs_information' AND row_version = $12",
    )
    .bind(&claim.id)
    .bind(&claim.payment_method_id)
    .bind(&claim.external_transaction_id)
    .bind(claim.paid_amount)
    .bind(&claim.paid_asset)
    .bind(claim.paid_at)
    .bind(&claim.payer_name)
    .bind(&claim.note)
    .bind(&claim.submitted_by)
    .bind(claim.submitted_at)
    .bind(claim.updated_at)
    .bind(expected_row_version)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?
    .rows_affected();
    if updated != 1 {
        return Err(ApiError::Database);
    }
    claim.row_version = claim.row_version.checked_add(1).ok_or(ApiError::Database)?;
    Ok(())
}

async fn ensure_unique_transaction(
    tx: &mut Transaction<'_, Postgres>,
    payment_method_id: &str,
    external_transaction_id: &str,
    excluded_claim_id: Option<&str>,
) -> Result<()> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM manual_payment_claims
             WHERE payment_method_id = $1 AND external_transaction_id = $2
               AND ($3::TEXT IS NULL OR id <> $3)
         )",
    )
    .bind(payment_method_id)
    .bind(external_transaction_id)
    .bind(excluded_claim_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    if exists {
        Err(ApiError::InvalidRequest)
    } else {
        Ok(())
    }
}

async fn update_payment_claim(
    tx: &mut Transaction<'_, Postgres>,
    claim: &mut ManualPaymentClaim,
) -> AdminAppResult<()> {
    let expected_row_version = i64::try_from(claim.row_version).map_err(|_| ApiError::Database)?;
    let updated = sqlx::query(
        "UPDATE manual_payment_claims
         SET status = $2, reviewed_by = $3, review_reason = $4, updated_at = $5,
             row_version = row_version + 1
         WHERE id = $1 AND row_version = $6",
    )
    .bind(&claim.id)
    .bind(payment_claim_status_name(claim.status))
    .bind(&claim.reviewed_by)
    .bind(&claim.review_reason)
    .bind(claim.updated_at)
    .bind(expected_row_version)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?
    .rows_affected();
    if updated != 1 {
        return Err(AdminAppError::VersionConflict);
    }
    claim.row_version = claim.row_version.checked_add(1).ok_or(ApiError::Database)?;
    Ok(())
}

fn row_offer(row: PgRow) -> Result<CommercialOffer> {
    Ok(CommercialOffer {
        id: row.try_get("id").map_err(|_| ApiError::Database)?,
        row_version: positive_u64(&row, "row_version")?,
        plan: parse_plan(
            &row.try_get::<String, _>("plan")
                .map_err(|_| ApiError::Database)?,
        )?,
        plan_revision: positive_u32(&row, "plan_revision")?,
        duration_days: positive_u32(&row, "duration_days")?,
        currency: row.try_get("currency").map_err(|_| ApiError::Database)?,
        base_amount: row.try_get("base_amount").map_err(|_| ApiError::Database)?,
        seat_amount: row.try_get("seat_amount").map_err(|_| ApiError::Database)?,
        name_en: row.try_get("name_en").map_err(|_| ApiError::Database)?,
        name_zh: row.try_get("name_zh").map_err(|_| ApiError::Database)?,
        active: row.try_get("active").map_err(|_| ApiError::Database)?,
        created_at: row.try_get("created_at").map_err(|_| ApiError::Database)?,
        updated_at: row.try_get("updated_at").map_err(|_| ApiError::Database)?,
    })
}

fn row_payment_method(row: PgRow) -> Result<ManualPaymentMethod> {
    Ok(ManualPaymentMethod {
        id: row.try_get("id").map_err(|_| ApiError::Database)?,
        row_version: positive_u64(&row, "row_version")?,
        name_en: row.try_get("name_en").map_err(|_| ApiError::Database)?,
        name_zh: row.try_get("name_zh").map_err(|_| ApiError::Database)?,
        instructions_en: row
            .try_get("instructions_en")
            .map_err(|_| ApiError::Database)?,
        instructions_zh: row
            .try_get("instructions_zh")
            .map_err(|_| ApiError::Database)?,
        settlement_asset: row
            .try_get("settlement_asset")
            .map_err(|_| ApiError::Database)?,
        destination_hint: row
            .try_get("destination_hint")
            .map_err(|_| ApiError::Database)?,
        active: row.try_get("active").map_err(|_| ApiError::Database)?,
        created_at: row.try_get("created_at").map_err(|_| ApiError::Database)?,
        updated_at: row.try_get("updated_at").map_err(|_| ApiError::Database)?,
    })
}

fn row_invoice(row: PgRow) -> Result<BillingInvoice> {
    Ok(BillingInvoice {
        id: row.try_get("id").map_err(|_| ApiError::Database)?,
        row_version: positive_u64(&row, "row_version")?,
        account_id: row.try_get("account_id").map_err(|_| ApiError::Database)?,
        license_id: row.try_get("license_id").map_err(|_| ApiError::Database)?,
        offer_id: row.try_get("offer_id").map_err(|_| ApiError::Database)?,
        plan: parse_plan(
            &row.try_get::<String, _>("plan")
                .map_err(|_| ApiError::Database)?,
        )?,
        plan_revision: positive_u32(&row, "plan_revision")?,
        seats: nonnegative_u32(&row, "seats")?,
        duration_days: positive_u32(&row, "duration_days")?,
        currency: row.try_get("currency").map_err(|_| ApiError::Database)?,
        amount_due: row.try_get("amount_due").map_err(|_| ApiError::Database)?,
        payment_reference: row
            .try_get("payment_reference")
            .map_err(|_| ApiError::Database)?,
        status: parse_invoice_status(
            &row.try_get::<String, _>("status")
                .map_err(|_| ApiError::Database)?,
        )?,
        due_at: row.try_get("due_at").map_err(|_| ApiError::Database)?,
        paid_at: row.try_get("paid_at").map_err(|_| ApiError::Database)?,
        created_at: row.try_get("created_at").map_err(|_| ApiError::Database)?,
        updated_at: row.try_get("updated_at").map_err(|_| ApiError::Database)?,
    })
}

fn row_payment_claim(row: PgRow) -> Result<ManualPaymentClaim> {
    Ok(ManualPaymentClaim {
        id: row.try_get("id").map_err(|_| ApiError::Database)?,
        row_version: positive_u64(&row, "row_version")?,
        invoice_id: row.try_get("invoice_id").map_err(|_| ApiError::Database)?,
        account_id: row.try_get("account_id").map_err(|_| ApiError::Database)?,
        payment_method_id: row
            .try_get("payment_method_id")
            .map_err(|_| ApiError::Database)?,
        external_transaction_id: row
            .try_get("external_transaction_id")
            .map_err(|_| ApiError::Database)?,
        paid_amount: row.try_get("paid_amount").map_err(|_| ApiError::Database)?,
        paid_asset: row.try_get("paid_asset").map_err(|_| ApiError::Database)?,
        paid_at: row.try_get("paid_at").map_err(|_| ApiError::Database)?,
        payer_name: row.try_get("payer_name").map_err(|_| ApiError::Database)?,
        note: row.try_get("note").map_err(|_| ApiError::Database)?,
        status: parse_payment_claim_status(
            &row.try_get::<String, _>("status")
                .map_err(|_| ApiError::Database)?,
        )?,
        submitted_by: row
            .try_get("submitted_by")
            .map_err(|_| ApiError::Database)?,
        reviewed_by: row.try_get("reviewed_by").map_err(|_| ApiError::Database)?,
        review_reason: row
            .try_get("review_reason")
            .map_err(|_| ApiError::Database)?,
        submitted_at: row
            .try_get("submitted_at")
            .map_err(|_| ApiError::Database)?,
        created_at: row.try_get("created_at").map_err(|_| ApiError::Database)?,
        updated_at: row.try_get("updated_at").map_err(|_| ApiError::Database)?,
    })
}

fn positive_u32(row: &PgRow, column: &str) -> Result<u32> {
    let value = row
        .try_get::<i32, _>(column)
        .map_err(|_| ApiError::Database)?;
    if value <= 0 {
        Err(ApiError::Database)
    } else {
        u32::try_from(value).map_err(|_| ApiError::Database)
    }
}

fn positive_u64(row: &PgRow, column: &str) -> Result<u64> {
    let value = row
        .try_get::<i64, _>(column)
        .map_err(|_| ApiError::Database)?;
    if value <= 0 {
        Err(ApiError::Database)
    } else {
        u64::try_from(value).map_err(|_| ApiError::Database)
    }
}

fn nonnegative_u32(row: &PgRow, column: &str) -> Result<u32> {
    u32::try_from(
        row.try_get::<i32, _>(column)
            .map_err(|_| ApiError::Database)?,
    )
    .map_err(|_| ApiError::Database)
}

fn parse_plan(value: &str) -> Result<Plan> {
    match value {
        "free" => Ok(Plan::Free),
        "pro" => Ok(Plan::Pro),
        "team" => Ok(Plan::Team),
        _ => Err(ApiError::Database),
    }
}

fn parse_invoice_status(value: &str) -> Result<InvoiceStatus> {
    match value {
        "open" => Ok(InvoiceStatus::Open),
        "paid" => Ok(InvoiceStatus::Paid),
        "overdue" => Ok(InvoiceStatus::Overdue),
        "void" => Ok(InvoiceStatus::Void),
        "refunded" => Ok(InvoiceStatus::Refunded),
        _ => Err(ApiError::Database),
    }
}

fn parse_payment_claim_status(value: &str) -> Result<PaymentClaimStatus> {
    match value {
        "submitted" => Ok(PaymentClaimStatus::Submitted),
        "under_review" => Ok(PaymentClaimStatus::UnderReview),
        "needs_information" => Ok(PaymentClaimStatus::NeedsInformation),
        "verified" => Ok(PaymentClaimStatus::Verified),
        "rejected" => Ok(PaymentClaimStatus::Rejected),
        "withdrawn" => Ok(PaymentClaimStatus::Withdrawn),
        _ => Err(ApiError::Database),
    }
}

const fn plan_name(plan: Plan) -> &'static str {
    match plan {
        Plan::Free => "free",
        Plan::Pro => "pro",
        Plan::Team => "team",
    }
}

const fn invoice_status_name(status: InvoiceStatus) -> &'static str {
    match status {
        InvoiceStatus::Open => "open",
        InvoiceStatus::Paid => "paid",
        InvoiceStatus::Overdue => "overdue",
        InvoiceStatus::Void => "void",
        InvoiceStatus::Refunded => "refunded",
    }
}

const fn payment_claim_status_name(status: PaymentClaimStatus) -> &'static str {
    match status {
        PaymentClaimStatus::Submitted => "submitted",
        PaymentClaimStatus::UnderReview => "under_review",
        PaymentClaimStatus::NeedsInformation => "needs_information",
        PaymentClaimStatus::Verified => "verified",
        PaymentClaimStatus::Rejected => "rejected",
        PaymentClaimStatus::Withdrawn => "withdrawn",
    }
}

fn billing_audit(
    event_type: &str,
    actor: &str,
    reason: &str,
    account_id: Option<&str>,
    license_id: Option<&str>,
    now: i64,
    mut metadata: BTreeMap<String, String>,
) -> AuditEventRecord {
    metadata.insert("actor".into(), actor.to_owned());
    metadata.insert("reason".into(), reason.to_owned());
    AuditEventRecord {
        id: random_id("audit"),
        event_type: event_type.to_owned(),
        outcome: "succeeded".into(),
        occurred_at: now,
        account_id: account_id.map(str::to_owned),
        license_id: license_id.map(str::to_owned),
        device_id: None,
        reason_code: None,
        metadata,
    }
}

async fn insert_billing_audit_tx(
    tx: &mut Transaction<'_, Postgres>,
    audit: AuditEventRecord,
) -> Result<()> {
    let document = serde_json::to_value(&audit).map_err(|_| ApiError::Internal)?;
    sqlx::query(
        "INSERT INTO audit_events
            (id, event_type, outcome, occurred_at, account_id, license_id, device_id,
             reason_code, metadata, document)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(&audit.id)
    .bind(&audit.event_type)
    .bind(&audit.outcome)
    .bind(audit.occurred_at)
    .bind(&audit.account_id)
    .bind(&audit.license_id)
    .bind(&audit.device_id)
    .bind(&audit.reason_code)
    .bind(serde_json::to_value(&audit.metadata).map_err(|_| ApiError::Internal)?)
    .bind(document)
    .execute(&mut **tx)
    .await
    .map_err(|_| ApiError::Database)?;
    Ok(())
}

impl FromStr for PaymentClaimStatus {
    type Err = ApiError;

    fn from_str(value: &str) -> Result<Self> {
        parse_payment_claim_status(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPERATION_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn customer_submission() -> CustomerPaymentSubmission {
        CustomerPaymentSubmission {
            operation_id: OPERATION_ID.into(),
            invoice_id: " invoice_test ".into(),
            payment_method_id: " payment_method_test ".into(),
            external_transaction_id: " bank-reference-001 ".into(),
            paid_amount: Decimal::new(9_900, 2),
            paid_asset: "USD".into(),
            paid_at: 1_000,
            payer_name: Some(" Example payer ".into()),
            note: Some(" Payment note ".into()),
        }
    }

    #[test]
    fn billing_cursor_is_canonical_bounded_and_tie_safe() {
        let cursor = BillingCursor {
            created_at: 1_785_376_419,
            id: "invoice_same_second_b".to_owned(),
        };
        let encoded = encode_billing_cursor(&cursor).expect("encode billing cursor");
        assert_eq!(
            decode_billing_cursor(&encoded).expect("decode billing cursor"),
            cursor
        );
        for invalid in [
            "",
            "not-base64!",
            &URL_SAFE_NO_PAD.encode(br#"{"createdAt":-1,"id":"invoice"}"#),
            &URL_SAFE_NO_PAD.encode(br#"{"createdAt":1,"id":"invalid id"}"#),
            &format!("{encoded}="),
        ] {
            assert!(decode_billing_cursor(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn invoice_seats_reject_ambiguous_plan_quantities() {
        assert!(validate_invoice_seats(Plan::Pro, 0).is_ok());
        assert!(validate_invoice_seats(Plan::Team, TEAM_MINIMUM_SEATS).is_ok());
        assert!(matches!(
            validate_invoice_seats(Plan::Team, 0),
            Err(AdminAppError::Validation(message)) if message.contains("between 3 and 10000")
        ));
        assert!(matches!(
            validate_invoice_seats(Plan::Pro, 3),
            Err(AdminAppError::Validation(message)) if message.contains("Non-Team")
        ));
    }

    #[test]
    fn offers_enforce_plan_specific_seat_pricing() {
        let pro = CommercialOffer {
            id: "pro-yearly".into(),
            row_version: 1,
            plan: Plan::Pro,
            plan_revision: CURRENT_PLAN_REVISION,
            duration_days: 365,
            currency: "USD".into(),
            base_amount: Decimal::new(9900, 2),
            seat_amount: None,
            name_en: "Pro yearly".into(),
            name_zh: "专业版年付".into(),
            active: true,
            created_at: 1,
            updated_at: 1,
        };
        assert!(validate_offer(&pro).is_ok());
        let mut invalid = pro.clone();
        invalid.plan = Plan::Team;
        assert!(validate_offer(&invalid).is_err());
    }

    #[test]
    fn amount_override_is_only_valid_for_approval() {
        assert!(validate_payment_review_override(PaymentReviewDecision::Approve, true).is_ok());
        assert!(validate_payment_review_override(PaymentReviewDecision::Approve, false).is_ok());
        assert!(validate_payment_review_override(PaymentReviewDecision::Reject, true).is_err());
        assert!(
            validate_payment_review_override(PaymentReviewDecision::RequestInformation, true)
                .is_err()
        );
    }

    #[test]
    fn review_hash_binds_every_commercial_decision_field() {
        let first = review_request_hash(
            "claim",
            3,
            PaymentReviewDecision::Approve,
            "operator",
            "verified",
            false,
        );
        let second = review_request_hash(
            "claim",
            3,
            PaymentReviewDecision::Reject,
            "operator",
            "verified",
            false,
        );
        assert_ne!(first, second);
        assert_ne!(
            first,
            review_request_hash(
                "claim",
                4,
                PaymentReviewDecision::Approve,
                "operator",
                "verified",
                false,
            )
        );
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn customer_payment_operation_id_requires_canonical_v4_uuid() {
        assert_eq!(
            canonical_customer_operation_id(OPERATION_ID).expect("canonical operation id"),
            OPERATION_ID
        );
        for invalid in [
            "550E8400-E29B-41D4-A716-446655440000",
            " 550e8400-e29b-41d4-a716-446655440000",
            "{550e8400-e29b-41d4-a716-446655440000}",
            "550e8400-e29b-11d4-a716-446655440000",
            "550e8400-e29b-41d4-7716-446655440000",
            "00000000-0000-0000-0000-000000000000",
        ] {
            assert!(
                canonical_customer_operation_id(invalid).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn customer_payment_hash_uses_canonical_business_payload_not_retry_time() {
        let first = canonical_customer_payment_submission(customer_submission(), 1_100)
            .expect("canonical first submission");
        let mut equivalent = customer_submission();
        equivalent.paid_amount = Decimal::new(990, 1);
        equivalent.invoice_id = "invoice_test".into();
        equivalent.payment_method_id = "payment_method_test".into();
        equivalent.external_transaction_id = "bank-reference-001".into();
        equivalent.payer_name = Some("Example payer".into());
        equivalent.note = Some("Payment note".into());
        let retry = canonical_customer_payment_submission(equivalent, 10_000)
            .expect("canonical retry submission");

        assert_eq!(
            customer_payment_request_hash(&first),
            customer_payment_request_hash(&retry)
        );
        let mut changed = retry.clone();
        changed.paid_at += 1;
        assert_ne!(
            customer_payment_request_hash(&first),
            customer_payment_request_hash(&changed),
            "paidAt is immutable payment evidence, while submittedAt is server-owned"
        );
        changed = retry.clone();
        changed.note = Some("different evidence".into());
        assert_ne!(
            customer_payment_request_hash(&first),
            customer_payment_request_hash(&changed)
        );
    }

    #[test]
    fn customer_payment_wire_contract_requires_operation_id() {
        let document = serde_json::to_value(customer_submission()).expect("serialize submission");
        assert_eq!(document["operationId"], OPERATION_ID);
        let mut missing_operation = document;
        missing_operation
            .as_object_mut()
            .expect("submission object")
            .remove("operationId");
        assert!(serde_json::from_value::<CustomerPaymentSubmission>(missing_operation).is_err());
        let conflict = customer_payment_operation_conflict();
        assert_eq!(conflict.code(), "idempotency_conflict");
        assert_eq!(
            axum::response::IntoResponse::into_response(conflict).status(),
            axum::http::StatusCode::CONFLICT
        );
    }

    #[test]
    fn payment_submission_identity_binds_the_full_canonical_payload() {
        let claim = ManualPaymentClaim {
            id: "payment_claim_test".into(),
            row_version: 1,
            invoice_id: "invoice_test".into(),
            account_id: "account_test".into(),
            payment_method_id: "payment_method_test".into(),
            external_transaction_id: "bank-reference-001".into(),
            paid_amount: Decimal::new(9900, 2),
            paid_asset: "USD".into(),
            paid_at: 1_000,
            payer_name: None,
            note: None,
            status: PaymentClaimStatus::Submitted,
            submitted_by: "device:test".into(),
            reviewed_by: None,
            review_reason: None,
            submitted_at: 1_000,
            created_at: 1_000,
            updated_at: 1_000,
        };
        let request = NewPaymentClaim {
            id: "unused-on-retry",
            invoice_id: "invoice_test",
            payment_method_id: "payment_method_test",
            external_transaction_id: " bank-reference-001 ",
            paid_amount: Decimal::new(9900, 2),
            paid_asset: "USD",
            paid_at: 1_000,
            payer_name: None,
            note: None,
            submitted_by: "device:test",
        };

        assert!(same_payment_submission_identity(
            &claim,
            &request,
            Some("account_test")
        ));
        assert!(!same_payment_submission_identity(
            &claim,
            &request,
            Some("another_account")
        ));
        let other_invoice = NewPaymentClaim {
            invoice_id: "invoice_other",
            ..request.clone()
        };
        assert!(!same_payment_submission_identity(
            &claim,
            &other_invoice,
            Some("account_test")
        ));
        let changed_amount = NewPaymentClaim {
            paid_amount: Decimal::new(10000, 2),
            ..request.clone()
        };
        assert!(!same_payment_submission_identity(
            &claim,
            &changed_amount,
            Some("account_test")
        ));
        let changed_metadata = NewPaymentClaim {
            paid_at: 1_001,
            payer_name: Some("Different payer"),
            note: Some("Different note"),
            ..request
        };
        assert!(!same_payment_submission_identity(
            &claim,
            &changed_metadata,
            Some("account_test")
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires TEST_DATABASE_URL"]
    async fn postgres_customer_payment_replays_concurrency_and_response_loss() {
        use std::{sync::Arc, time::Duration};

        let database_url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for the PostgreSQL integration test");
        let repository = PostgresRepository::connect(&database_url, 4, Duration::from_secs(5))
            .await
            .expect("connect PostgreSQL");
        repository.migrate().await.expect("run migrations");

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let account_id = format!("billing_idem_account_{suffix}");
        let license_id = format!("billing_idem_license_{suffix}");
        let offer_id = format!("billing_idem_offer_{suffix}");
        let payment_method_id = format!("billing_idem_method_{suffix}");
        let first_invoice_id = format!("billing_idem_invoice_a_{suffix}");
        let second_invoice_id = format!("billing_idem_invoice_b_{suffix}");
        let external_transaction_id = format!("billing-idem-transaction-{suffix}");
        let now = 2_000_000_000_i64;

        sqlx::query(
            "INSERT INTO accounts (id, document, created_at, updated_at)
             VALUES ($1, $2, to_timestamp($3), to_timestamp($3))",
        )
        .bind(&account_id)
        .bind(serde_json::json!({
            "id": account_id,
            "state": "active",
            "created_at": now,
            "updated_at": now
        }))
        .bind(now)
        .execute(&repository.pool)
        .await
        .expect("insert account");
        sqlx::query(
            "INSERT INTO licenses
                (id, account_id, plan, plan_revision, status, expires_at, license_epoch,
                 purchased_seats, row_version)
             VALUES ($1, $2, 'pro', $3, 'active', NULL, 1, 0, 1)",
        )
        .bind(&license_id)
        .bind(&account_id)
        .bind(i32::try_from(CURRENT_PLAN_REVISION).expect("plan revision fits in PostgreSQL"))
        .execute(&repository.pool)
        .await
        .expect("insert license");
        sqlx::query(
            "INSERT INTO commercial_offers
                (id, plan, plan_revision, duration_days, currency, base_amount, seat_amount,
                 name_en, name_zh, active, created_at, updated_at)
             VALUES ($1, 'pro', $2, 365, 'USD', 99, NULL, 'Test', 'Test', true, $3, $3)",
        )
        .bind(&offer_id)
        .bind(i32::try_from(CURRENT_PLAN_REVISION).expect("plan revision fits in PostgreSQL"))
        .bind(now)
        .execute(&repository.pool)
        .await
        .expect("insert offer");
        sqlx::query(
            "INSERT INTO manual_payment_methods
                (id, name_en, name_zh, instructions_en, instructions_zh, settlement_asset,
                 destination_hint, active, created_at, updated_at)
             VALUES ($1, 'Test', 'Test', 'Test', 'Test', 'USD', 'Test', true, $2, $2)",
        )
        .bind(&payment_method_id)
        .bind(now)
        .execute(&repository.pool)
        .await
        .expect("insert payment method");
        for (invoice_id, payment_reference) in [
            (&first_invoice_id, format!("CNX-IDEM-A-{suffix}")),
            (&second_invoice_id, format!("CNX-IDEM-B-{suffix}")),
        ] {
            sqlx::query(
                "INSERT INTO billing_invoices
                    (id, account_id, license_id, offer_id, plan, plan_revision, seats,
                     duration_days, currency, amount_due, payment_reference, status, due_at,
                     paid_at, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, 'pro', $5, 0, 365, 'USD', 99, $6, 'open', $7,
                         NULL, $8, $8)",
            )
            .bind(invoice_id)
            .bind(&account_id)
            .bind(&license_id)
            .bind(&offer_id)
            .bind(i32::try_from(CURRENT_PLAN_REVISION).expect("plan revision fits in PostgreSQL"))
            .bind(payment_reference)
            .bind(now + 3_600)
            .bind(now)
            .execute(&repository.pool)
            .await
            .expect("insert invoice");
        }

        let operation_id = uuid::Uuid::new_v4().to_string();
        let submission = CustomerPaymentSubmission {
            operation_id: operation_id.clone(),
            invoice_id: first_invoice_id.clone(),
            payment_method_id: payment_method_id.clone(),
            external_transaction_id: external_transaction_id.clone(),
            paid_amount: Decimal::new(9_900, 2),
            paid_asset: "USD".into(),
            paid_at: now - 60,
            payer_name: Some("Concurrent payer".into()),
            note: Some("response-loss retry".into()),
        };
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let first_repository = repository.clone();
        let first_barrier = Arc::clone(&barrier);
        let first_account_id = account_id.clone();
        let first_submission = submission.clone();
        let first = tokio::spawn(async move {
            first_barrier.wait().await;
            first_repository
                .submit_customer_payment(&first_account_id, "device:first", first_submission, now)
                .await
        });
        let second_repository = repository.clone();
        let second_barrier = Arc::clone(&barrier);
        let second_account_id = account_id.clone();
        let second_submission = submission.clone();
        let second = tokio::spawn(async move {
            second_barrier.wait().await;
            second_repository
                .submit_customer_payment(
                    &second_account_id,
                    "device:second",
                    second_submission,
                    now,
                )
                .await
        });
        barrier.wait().await;
        let first = first
            .await
            .expect("join first submit")
            .expect("first submit");
        let second = second
            .await
            .expect("join concurrent submit")
            .expect("concurrent replay");
        assert_eq!(first, second);
        assert_eq!(first.submitted_at, now);
        assert_eq!(first.row_version, 1);

        // Treat the first response as lost and retry later from another authorized device.
        let replay = repository
            .submit_customer_payment(&account_id, "device:retry", submission.clone(), now + 120)
            .await
            .expect("replay after response loss");
        assert_eq!(replay, first);

        let mut changed_payload = submission.clone();
        changed_payload.note = Some("different business evidence".into());
        assert!(matches!(
            repository
                .submit_customer_payment(&account_id, "device:retry", changed_payload, now + 121)
                .await,
            Err(ApiError::IdempotencyConflict)
        ));

        let mut reused_transaction = submission.clone();
        reused_transaction.operation_id = uuid::Uuid::new_v4().to_string();
        reused_transaction.invoice_id = second_invoice_id;
        assert!(matches!(
            repository
                .submit_customer_payment(&account_id, "device:retry", reused_transaction, now + 122)
                .await,
            Err(ApiError::InvalidRequest)
        ));

        let information_operation_id = uuid::Uuid::new_v4().to_string();
        let information_requested = repository
            .review_manual_payment_claim(
                &first.id,
                first.row_version,
                PaymentReviewDecision::RequestInformation,
                "admin:reviewer",
                "confirm the receipt identifier",
                &information_operation_id,
                false,
                now + 123,
                None,
            )
            .await
            .expect("request payment information");
        assert_eq!(information_requested.row_version, 2);
        assert_eq!(
            information_requested.status,
            PaymentClaimStatus::NeedsInformation
        );
        let information_replay = repository
            .review_manual_payment_claim(
                &first.id,
                first.row_version,
                PaymentReviewDecision::RequestInformation,
                "admin:reviewer",
                "confirm the receipt identifier",
                &information_operation_id,
                false,
                now + 124,
                None,
            )
            .await
            .expect("replay information request");
        assert_eq!(information_replay, information_requested);
        assert!(matches!(
            repository
                .review_manual_payment_claim(
                    &first.id,
                    first.row_version,
                    PaymentReviewDecision::Reject,
                    "admin:reviewer",
                    "stale review must fail",
                    &uuid::Uuid::new_v4().to_string(),
                    false,
                    now + 125,
                    None,
                )
                .await,
            Err(AdminAppError::VersionConflict)
        ));

        let mut resubmission = submission;
        resubmission.operation_id = uuid::Uuid::new_v4().to_string();
        resubmission.note = Some("receipt identifier confirmed".into());
        let resubmitted = repository
            .submit_customer_payment(&account_id, "device:retry", resubmission, now + 126)
            .await
            .expect("resubmit requested information");
        assert_eq!(resubmitted.row_version, 3);
        assert_eq!(resubmitted.status, PaymentClaimStatus::Submitted);

        let evidence_object_id = format!("billing_idem_object_{suffix}");
        let evidence_id = format!("billing_idem_evidence_{suffix}");
        let evidence_sha256 = "a".repeat(64);
        sqlx::query(
            "INSERT INTO stored_objects
                (id, namespace, backend, locator, media_type, original_name, byte_length,
                 sha256, key_id, wrapped_key_nonce, wrapped_key, content_nonce, status,
                 created_by, created_at, updated_at)
             VALUES ($1, 'payment-evidence', 'database', $1, 'image/png', 'receipt.png', 1,
                     $2, 'test-key', $3, $4, $3, 'ready', 'test', $5, $5)",
        )
        .bind(&evidence_object_id)
        .bind(&evidence_sha256)
        .bind(vec![0_u8; 12])
        .bind(vec![0_u8; 32])
        .bind(now + 126)
        .execute(&repository.pool)
        .await
        .expect("insert clean evidence object");
        sqlx::query(
            "INSERT INTO payment_evidence_attachments
                (id, claim_id, object_id, original_name, media_type, byte_length, sha256,
                 scan_status, created_at, scanned_at)
             VALUES ($1, $2, $3, 'receipt.png', 'image/png', 1, $4, 'clean', $5, $5)",
        )
        .bind(&evidence_id)
        .bind(&first.id)
        .bind(&evidence_object_id)
        .bind(&evidence_sha256)
        .bind(now + 126)
        .execute(&repository.pool)
        .await
        .expect("attach clean payment evidence");

        let approval_operation_id = uuid::Uuid::new_v4().to_string();
        let approved = repository
            .review_manual_payment_claim(
                &first.id,
                resubmitted.row_version,
                PaymentReviewDecision::Approve,
                "admin:reviewer",
                "payment verified",
                &approval_operation_id,
                false,
                now + 127,
                None,
            )
            .await
            .expect("approve payment");
        assert_eq!(approved.row_version, 4);
        assert_eq!(approved.status, PaymentClaimStatus::Verified);
        let invoice_state: (String, i64) =
            sqlx::query_as("SELECT status, row_version FROM billing_invoices WHERE id = $1")
                .bind(&first_invoice_id)
                .fetch_one(&repository.pool)
                .await
                .expect("load paid invoice version");
        assert_eq!(invoice_state, ("paid".to_owned(), 2));

        let invoice_page = repository
            .billing_invoices(
                Some(&account_id),
                PageRequest {
                    page_size: 1,
                    ..PageRequest::default()
                },
            )
            .await
            .expect("load first bounded invoice page");
        assert_eq!(invoice_page.items.len(), 1);
        let invoice_cursor = invoice_page
            .next_cursor
            .clone()
            .expect("first invoice page cursor");
        let next_invoice_page = repository
            .billing_invoices(
                Some(&account_id),
                PageRequest {
                    cursor: Some(invoice_cursor),
                    page_size: 1,
                    ..PageRequest::default()
                },
            )
            .await
            .expect("load next bounded invoice page");
        assert_eq!(next_invoice_page.items.len(), 1);
        assert_ne!(invoice_page.items[0].id, next_invoice_page.items[0].id);
        assert!(next_invoice_page.next_cursor.is_none());

        let claim_page = repository
            .manual_payment_claims(
                Some(PaymentClaimStatus::Verified),
                PageRequest {
                    query: Some(external_transaction_id),
                    page_size: 1,
                    ..PageRequest::default()
                },
            )
            .await
            .expect("search bounded payment-claim page");
        assert_eq!(claim_page.items, vec![approved.clone()]);
        assert!(claim_page.next_cursor.is_none());

        let claim_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM manual_payment_claims WHERE account_id = $1")
                .bind(&account_id)
                .fetch_one(&repository.pool)
                .await
                .expect("count claims");
        let operation_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM customer_payment_operations WHERE account_id = $1",
        )
        .bind(&account_id)
        .fetch_one(&repository.pool)
        .await
        .expect("count operations");
        assert_eq!(claim_count, 1);
        assert_eq!(operation_count, 2);

        sqlx::query("DELETE FROM admin_operations WHERE operation_id IN ($1, $2)")
            .bind(&information_operation_id)
            .bind(&approval_operation_id)
            .execute(&repository.pool)
            .await
            .expect("delete review operations");
        sqlx::query("DELETE FROM customer_payment_operations WHERE account_id = $1")
            .bind(&account_id)
            .execute(&repository.pool)
            .await
            .expect("delete payment operations");
        sqlx::query("DELETE FROM manual_payment_claims WHERE account_id = $1")
            .bind(&account_id)
            .execute(&repository.pool)
            .await
            .expect("delete claims");
        sqlx::query("DELETE FROM stored_objects WHERE id = $1")
            .bind(&evidence_object_id)
            .execute(&repository.pool)
            .await
            .expect("delete evidence object");
        sqlx::query("DELETE FROM billing_invoices WHERE account_id = $1")
            .bind(&account_id)
            .execute(&repository.pool)
            .await
            .expect("delete invoices");
        sqlx::query("DELETE FROM manual_payment_methods WHERE id = $1")
            .bind(&payment_method_id)
            .execute(&repository.pool)
            .await
            .expect("delete payment method");
        sqlx::query("DELETE FROM commercial_offers WHERE id = $1")
            .bind(&offer_id)
            .execute(&repository.pool)
            .await
            .expect("delete offer");
        sqlx::query("DELETE FROM licenses WHERE account_id = $1")
            .bind(&account_id)
            .execute(&repository.pool)
            .await
            .expect("delete license");
        sqlx::query("DELETE FROM accounts WHERE id = $1")
            .bind(&account_id)
            .execute(&repository.pool)
            .await
            .expect("delete account");
        repository.pool.close().await;
    }
}
