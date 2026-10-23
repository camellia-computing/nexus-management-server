use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::{Arc, Weak},
    time::{Duration, UNIX_EPOCH},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use reqwest::{StatusCode, header, redirect};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};
use thiserror::Error;
use tokio::{
    sync::{Mutex, Semaphore, watch},
    task::JoinSet,
};
use url::{Host, Url};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    contracts::{Capability, Plan},
    crypto::{random_id, random_secret},
    domain::AuditEventRecord,
    error::ApiError,
    plan_catalog::effective_policy,
    secret_file::{read_secret_file, valid_keyring_key_count},
    store::PostgresRepository,
    workspace::{WorkspaceAuthorization, require_permissions_tx},
};

const MAX_ENDPOINTS_PER_ACCOUNT: i64 = 5;
const MAX_ENDPOINT_NAME_BYTES: usize = 128;
const MAX_ENDPOINT_URL_BYTES: usize = 2_048;
const MAX_EVENT_TYPES: usize = 32;
const MAX_EVENT_TYPE_BYTES: usize = 64;
const MAX_EVENT_PAYLOAD_BYTES: usize = 128 * 1_024;
const MAX_EVENT_PAYLOAD_DEPTH: usize = 16;
const MAX_DELIVERY_LIST_LIMIT: u16 = 100;
const MAX_CLEANUP_BATCH_SIZE: u32 = 10_000;
const ACTIVE_DELIVERY_MAX_AGE_SECONDS: i64 = 7 * 24 * 60 * 60;
const WEBHOOK_HISTORY_RETENTION_SECONDS: i64 = 30 * 24 * 60 * 60;
const WEBHOOK_SECRET_LABEL: &[u8] = b"workspace-webhook-hmac-v1";
const WEBHOOK_KEYRING_DOMAIN: &[u8] = b"camellia-nexus-webhook-v1";
/// Version value sent in [`WEBHOOK_HEADER_VERSION`].
pub const WEBHOOK_SIGNATURE_VERSION: &str = "1";
/// Signature protocol version header.
pub const WEBHOOK_HEADER_VERSION: &str = "x-camellia-webhook-version";
/// Stable delivery identifier header. Receivers should use it for replay deduplication.
pub const WEBHOOK_HEADER_DELIVERY_ID: &str = "x-camellia-webhook-delivery-id";
/// Stable domain-event identifier header.
pub const WEBHOOK_HEADER_EVENT_ID: &str = "x-camellia-webhook-event-id";
/// Trusted Unix timestamp header covered by the signature.
pub const WEBHOOK_HEADER_TIMESTAMP: &str = "x-camellia-webhook-timestamp";
/// HMAC-SHA256 signature header in `v1=<lowercase hex>` form.
pub const WEBHOOK_HEADER_SIGNATURE: &str = "x-camellia-webhook-signature";
/// Endpoint secret generation header.
pub const WEBHOOK_HEADER_SECRET_VERSION: &str = "x-camellia-webhook-secret-version";

/// Closed set of domain events accepted by the outbox and endpoint subscriptions.
pub const SUPPORTED_WEBHOOK_EVENT_TYPES: &[&str] = &[
    "alert.incident.acknowledged",
    "alert.incident.opened",
    "alert.incident.resolved",
    "configuration.created",
    "configuration.deleted",
    "configuration.published",
    "configuration.purged",
    "configuration.restored",
    "configuration.revised",
    "sync.conflict",
];

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Error)]
#[error("webhook keyring configuration is invalid")]
pub struct WebhookKeyringError;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WebhookKeyringDocument {
    active_key_id: String,
    keys: BTreeMap<String, String>,
}

impl Drop for WebhookKeyringDocument {
    fn drop(&mut self) {
        self.active_key_id.zeroize();
        for (mut key_id, mut encoded_key) in std::mem::take(&mut self.keys) {
            key_id.zeroize();
            encoded_key.zeroize();
        }
    }
}

pub struct WebhookKeyring {
    active_key_id: String,
    keys: BTreeMap<String, [u8; 32]>,
}

impl Drop for WebhookKeyring {
    fn drop(&mut self) {
        self.active_key_id.zeroize();
        for key in self.keys.values_mut() {
            key.zeroize();
        }
    }
}

impl WebhookKeyring {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, WebhookKeyringError> {
        let bytes = read_secret_file(path).map_err(|_| WebhookKeyringError)?;
        let mut document: WebhookKeyringDocument =
            serde_json::from_slice(&bytes).map_err(|_| WebhookKeyringError)?;
        let active_key_id = canonical_webhook_key_id(&document.active_key_id)?;
        if !valid_keyring_key_count(document.keys.len()) {
            return Err(WebhookKeyringError);
        }
        let mut keys = BTreeMap::new();
        for (mut raw_id, encoded) in std::mem::take(&mut document.keys) {
            let key_id = canonical_webhook_key_id(&raw_id)?;
            raw_id.zeroize();
            let encoded = Zeroizing::new(encoded);
            if encoded.as_str() != encoded.trim() {
                return Err(WebhookKeyringError);
            }
            let decoded = Zeroizing::new(
                URL_SAFE_NO_PAD
                    .decode(encoded.as_bytes())
                    .map_err(|_| WebhookKeyringError)?,
            );
            let key: [u8; 32] = decoded
                .as_slice()
                .try_into()
                .map_err(|_| WebhookKeyringError)?;
            if keys.insert(key_id, key).is_some() {
                return Err(WebhookKeyringError);
            }
        }
        if !keys.contains_key(&active_key_id) {
            return Err(WebhookKeyringError);
        }
        Ok(Self {
            active_key_id,
            keys,
        })
    }

    pub fn ephemeral_for_development() -> Self {
        let mut key = [0_u8; 32];
        rand::fill(&mut key);
        Self {
            active_key_id: "ephemeral-development".to_owned(),
            keys: BTreeMap::from([("ephemeral-development".to_owned(), key)]),
        }
    }

    fn active_key_id(&self) -> &str {
        &self.active_key_id
    }

    fn contains_key_id(&self, key_id: &str) -> bool {
        self.keys.contains_key(key_id)
    }

    fn derive_key(&self, key_id: &str) -> WebhookResult<Zeroizing<[u8; 32]>> {
        let root_key = self
            .keys
            .get(key_id)
            .ok_or(WebhookError::KeyringUnavailable)?;
        let hkdf = Hkdf::<Sha256>::new(Some(WEBHOOK_KEYRING_DOMAIN), root_key);
        let mut derived = Zeroizing::new([0_u8; 32]);
        hkdf.expand(WEBHOOK_SECRET_LABEL, derived.as_mut())
            .map_err(|_| WebhookError::KeyringUnavailable)?;
        Ok(derived)
    }

    fn seal(&self, aad: &[u8], plaintext: &[u8]) -> WebhookResult<(String, Vec<u8>, Vec<u8>)> {
        let key = self.derive_key(&self.active_key_id)?;
        let mut nonce = [0_u8; 24];
        rand::fill(&mut nonce);
        let ciphertext = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| WebhookError::KeyringUnavailable)?
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| WebhookError::KeyringUnavailable)?;
        Ok((self.active_key_id.clone(), nonce.to_vec(), ciphertext))
    }

    fn open(
        &self,
        key_id: &str,
        aad: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> WebhookResult<Zeroizing<Vec<u8>>> {
        let nonce: [u8; 24] = nonce
            .try_into()
            .map_err(|_| WebhookError::KeyringUnavailable)?;
        let key = self.derive_key(key_id)?;
        XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| WebhookError::KeyringUnavailable)?
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| WebhookError::KeyringUnavailable)
    }
}

fn canonical_webhook_key_id(value: &str) -> Result<String, WebhookKeyringError> {
    if value != value.trim()
        || value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Err(WebhookKeyringError)
    } else {
        Ok(value.to_owned())
    }
}

#[derive(Debug, Error)]
pub enum WebhookError {
    #[error("invalid webhook request")]
    InvalidRequest,
    #[error("invalid webhook endpoint URL")]
    InvalidUrl,
    #[error("webhook permission denied")]
    PermissionDenied,
    #[error("webhook capability is unavailable")]
    CapabilityDenied,
    #[error("webhook account is suspended")]
    AccountSuspended,
    #[error("webhook account is denylisted")]
    AccountDenylisted,
    #[error("webhook license is unavailable")]
    LicenseUnavailable,
    #[error("webhook license payment is past due")]
    LicensePastDue,
    #[error("webhook license is canceled")]
    LicenseCanceled,
    #[error("webhook license is expired")]
    LicenseExpired,
    #[error("webhook endpoint not found")]
    NotFound,
    #[error("webhook endpoint limit reached")]
    EndpointLimitReached,
    #[error("webhook row version conflict")]
    VersionConflict,
    #[error("webhook idempotency conflict")]
    IdempotencyConflict,
    #[error("webhook keyring is unavailable")]
    KeyringUnavailable,
    #[error("webhook DNS target is not safe")]
    DnsRejected,
    #[error("webhook delivery lease was lost")]
    LeaseLost,
    #[error("webhook database operation failed")]
    Database,
    #[error("webhook database schema is not ready")]
    DatabaseSchemaNotReady,
    #[error("webhook serialization failed")]
    Serialization,
    #[error("webhook dispatcher configuration is invalid")]
    InvalidDispatcherConfiguration,
    #[error("webhook dispatcher stopped unexpectedly")]
    UnexpectedDispatcherExit,
    #[error("webhook delivery task panicked")]
    WorkerTaskPanicked,
    #[error("webhook trusted time is unavailable")]
    TimeAuthorityUnavailable,
}

impl WebhookError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidUrl => "webhook_invalid_url",
            Self::PermissionDenied => "permission_denied",
            Self::CapabilityDenied => "capability_denied",
            Self::AccountSuspended => "account_suspended",
            Self::AccountDenylisted => "account_denylisted",
            Self::LicenseUnavailable => "license_unavailable",
            Self::LicensePastDue => "license_past_due",
            Self::LicenseCanceled => "license_canceled",
            Self::LicenseExpired => "license_expired",
            Self::NotFound => "webhook_not_found",
            Self::EndpointLimitReached => "webhook_endpoint_limit",
            Self::VersionConflict => "workspace_version_conflict",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::KeyringUnavailable => "webhook_keyring_unavailable",
            Self::DnsRejected => "webhook_dns_rejected",
            Self::LeaseLost => "webhook_lease_lost",
            Self::Database => "database",
            Self::DatabaseSchemaNotReady => "database_schema_not_ready",
            Self::Serialization => "internal",
            Self::InvalidDispatcherConfiguration => "webhook_dispatcher_configuration",
            Self::UnexpectedDispatcherExit => "webhook_dispatcher_stopped",
            Self::WorkerTaskPanicked => "webhook_worker_panicked",
            Self::TimeAuthorityUnavailable => "time_authority_unavailable",
        }
    }
}

pub type WebhookResult<T> = Result<T, WebhookError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebhookEndpoint {
    pub id: String,
    pub name: String,
    pub url: String,
    pub event_types: Vec<String>,
    pub active: bool,
    pub secret_version: u32,
    pub row_version: u64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateWebhookEndpoint {
    pub operation_id: String,
    pub name: String,
    pub url: String,
    pub event_types: Vec<String>,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateWebhookEndpoint {
    pub operation_id: String,
    pub row_version: u64,
    pub name: String,
    pub url: String,
    pub event_types: Vec<String>,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RotateWebhookSecret {
    pub operation_id: String,
    pub row_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteWebhookEndpoint {
    pub operation_id: String,
    pub row_version: u64,
}

pub struct OneTimeWebhookSecret(String);

impl OneTimeWebhookSecret {
    fn new(secret: String) -> Self {
        Self(secret)
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OneTimeWebhookSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OneTimeWebhookSecret([REDACTED])")
    }
}

impl Serialize for OneTimeWebhookSecret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl Drop for OneTimeWebhookSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookSecretResult {
    pub endpoint: WebhookEndpoint,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<OneTimeWebhookSecret>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebhookDeletion {
    pub endpoint_id: String,
    pub deleted_at: i64,
    pub row_version: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WebhookDeliveryStatus {
    Pending,
    InFlight,
    Delivered,
    Retry,
    Dead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WebhookDeliverySummary {
    pub id: String,
    pub event_id: String,
    pub endpoint_id: String,
    pub event_type: String,
    pub status: WebhookDeliveryStatus,
    pub attempt_count: u32,
    pub next_attempt_at: i64,
    pub last_http_status: Option<u16>,
    pub last_error_category: Option<String>,
    pub delivered_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WebhookCleanupReport {
    pub expired_deliveries: u64,
    pub deleted_events: u64,
    pub deleted_operations: u64,
    pub deleted_endpoints: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NewWebhookEvent {
    pub event_id: String,
    pub event_type: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CanonicalEndpointInput {
    name: String,
    url: CanonicalWebhookUrl,
    event_types: Vec<String>,
    active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CanonicalWebhookUrl {
    serialized: String,
    host: String,
}

fn canonical_endpoint_input(
    name: &str,
    url: &str,
    event_types: &[String],
    active: bool,
) -> WebhookResult<CanonicalEndpointInput> {
    let name = bounded_text(name, MAX_ENDPOINT_NAME_BYTES)?;
    let url = canonical_webhook_url(url)?;
    let event_types = canonical_event_types(event_types)?;
    Ok(CanonicalEndpointInput {
        name,
        url,
        event_types,
        active,
    })
}

fn bounded_text(value: &str, max_bytes: usize) -> WebhookResult<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > max_bytes
        || value.chars().any(|character| character.is_control())
    {
        return Err(WebhookError::InvalidRequest);
    }
    Ok(value.to_owned())
}

fn canonical_event_types(values: &[String]) -> WebhookResult<Vec<String>> {
    if values.is_empty() || values.len() > MAX_EVENT_TYPES {
        return Err(WebhookError::InvalidRequest);
    }
    let mut canonical = BTreeSet::new();
    for value in values {
        let value = canonical_event_type(value)?;
        if !canonical.insert(value) {
            return Err(WebhookError::InvalidRequest);
        }
    }
    Ok(canonical.into_iter().collect())
}

fn canonical_event_type(value: &str) -> WebhookResult<String> {
    if value.is_empty()
        || value.len() > MAX_EVENT_TYPE_BYTES
        || !value.bytes().enumerate().all(|(index, byte)| {
            if index == 0 {
                byte.is_ascii_lowercase()
            } else {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'_' | b'-' | b'.')
            }
        })
    {
        return Err(WebhookError::InvalidRequest);
    }
    if SUPPORTED_WEBHOOK_EVENT_TYPES.binary_search(&value).is_err() {
        return Err(WebhookError::InvalidRequest);
    }
    Ok(value.to_owned())
}

fn canonical_uuid_v4(value: &str) -> WebhookResult<String> {
    let parsed = uuid::Uuid::parse_str(value).map_err(|_| WebhookError::InvalidRequest)?;
    let bytes = value.as_bytes();
    if value.len() != 36
        || parsed.hyphenated().to_string() != value
        || bytes.get(14) != Some(&b'4')
        || !matches!(bytes.get(19), Some(b'8' | b'9' | b'a' | b'b'))
    {
        return Err(WebhookError::InvalidRequest);
    }
    Ok(value.to_owned())
}

fn canonical_webhook_url(value: &str) -> WebhookResult<CanonicalWebhookUrl> {
    let value = value.trim();
    if value.is_empty() || value.len() > MAX_ENDPOINT_URL_BYTES {
        return Err(WebhookError::InvalidUrl);
    }
    let mut url = Url::parse(value).map_err(|_| WebhookError::InvalidUrl)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() != Some(443)
    {
        return Err(WebhookError::InvalidUrl);
    }
    let host = match url.host() {
        Some(Host::Domain(host)) => host.trim_end_matches('.').to_ascii_lowercase(),
        Some(Host::Ipv4(_) | Host::Ipv6(_)) | None => return Err(WebhookError::InvalidUrl),
    };
    if host.is_empty()
        || !host.contains('.')
        || host.len() > 253
        || host == "localhost"
        || [
            ".localhost",
            ".local",
            ".internal",
            ".invalid",
            ".test",
            ".example",
        ]
        .iter()
        .any(|suffix| host.ends_with(suffix))
    {
        return Err(WebhookError::InvalidUrl);
    }
    url.set_host(Some(&host))
        .map_err(|_| WebhookError::InvalidUrl)?;
    if url.port() == Some(443) {
        url.set_port(None).map_err(|_| WebhookError::InvalidUrl)?;
    }
    if url.path().is_empty() {
        url.set_path("/");
    }
    let serialized = url.to_string();
    if serialized.len() > MAX_ENDPOINT_URL_BYTES {
        return Err(WebhookError::InvalidUrl);
    }
    Ok(CanonicalWebhookUrl { serialized, host })
}

fn ipv4_in_prefix(address: Ipv4Addr, network: Ipv4Addr, prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(address) & mask == u32::from(network) & mask
}

fn ipv6_in_prefix(address: Ipv6Addr, network: Ipv6Addr, prefix: u32) -> bool {
    let address = u128::from(address);
    let network = u128::from(network);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    address & mask == network & mask
}

pub fn webhook_target_ip_is_safe(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => webhook_target_ipv4_is_safe(address),
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return webhook_target_ipv4_is_safe(mapped);
            }
            if !ipv6_in_prefix(address, Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3) {
                return false;
            }
            !ipv6_in_prefix(address, Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23)
                && !ipv6_in_prefix(address, Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32)
                && !ipv6_in_prefix(address, Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16)
                && !ipv6_in_prefix(address, Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20)
        }
    }
}

fn webhook_target_ipv4_is_safe(address: Ipv4Addr) -> bool {
    ![
        (Ipv4Addr::new(0, 0, 0, 0), 8),
        (Ipv4Addr::new(10, 0, 0, 0), 8),
        (Ipv4Addr::new(100, 64, 0, 0), 10),
        (Ipv4Addr::new(127, 0, 0, 0), 8),
        (Ipv4Addr::new(169, 254, 0, 0), 16),
        (Ipv4Addr::new(172, 16, 0, 0), 12),
        (Ipv4Addr::new(192, 0, 0, 0), 24),
        (Ipv4Addr::new(192, 0, 2, 0), 24),
        (Ipv4Addr::new(192, 88, 99, 0), 24),
        (Ipv4Addr::new(192, 168, 0, 0), 16),
        (Ipv4Addr::new(198, 18, 0, 0), 15),
        (Ipv4Addr::new(198, 51, 100, 0), 24),
        (Ipv4Addr::new(203, 0, 113, 0), 24),
        (Ipv4Addr::new(224, 0, 0, 0), 4),
        (Ipv4Addr::new(240, 0, 0, 0), 4),
    ]
    .into_iter()
    .any(|(network, prefix)| ipv4_in_prefix(address, network, prefix))
}

fn append_signature_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    output.extend_from_slice(value);
}

pub fn webhook_signature_payload(
    delivery_id: &str,
    event_id: &str,
    trusted_timestamp: i64,
    body: &[u8],
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(body.len().saturating_add(128));
    append_signature_field(&mut payload, WEBHOOK_SIGNATURE_VERSION.as_bytes());
    append_signature_field(&mut payload, delivery_id.as_bytes());
    append_signature_field(&mut payload, event_id.as_bytes());
    append_signature_field(&mut payload, trusted_timestamp.to_string().as_bytes());
    append_signature_field(&mut payload, body);
    payload
}

/// Signs the exact raw request body and routing metadata with HMAC-SHA256.
///
/// Receivers must verify the raw bytes before parsing JSON. The timestamp freshness window and
/// delivery-ID replay cache are receiver policy and must be checked separately.
///
/// ```
/// use camellia_nexus_management_server::webhooks::{
///     sign_webhook_payload, verify_webhook_signature,
/// };
///
/// let secret = b"32-byte-shared-webhook-secret!!!";
/// let delivery_id = "550e8400-e29b-41d4-a716-446655440000";
/// let event_id = "650e8400-e29b-41d4-a716-446655440000";
/// let timestamp = 1_700_000_000;
/// let body = br#"{"eventType":"configuration.created"}"#;
/// let signature = sign_webhook_payload(
///     secret,
///     delivery_id,
///     event_id,
///     timestamp,
///     body,
/// )?;
/// assert!(verify_webhook_signature(
///     secret,
///     &signature,
///     delivery_id,
///     event_id,
///     timestamp,
///     body,
/// ));
/// # Ok::<(), camellia_nexus_management_server::webhooks::WebhookError>(())
/// ```
pub fn sign_webhook_payload(
    secret: &[u8],
    delivery_id: &str,
    event_id: &str,
    trusted_timestamp: i64,
    body: &[u8],
) -> WebhookResult<String> {
    if secret.len() < 32 {
        return Err(WebhookError::InvalidRequest);
    }
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| WebhookError::InvalidRequest)?;
    mac.update(&webhook_signature_payload(
        delivery_id,
        event_id,
        trusted_timestamp,
        body,
    ));
    let digest = mac.finalize().into_bytes();
    let encoded = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("v{WEBHOOK_SIGNATURE_VERSION}={encoded}"))
}

/// Verifies a webhook signature with the HMAC implementation's constant-time tag comparison.
///
/// This does not enforce timestamp freshness or delivery-ID replay protection.
pub fn verify_webhook_signature(
    secret: &[u8],
    signature_header: &str,
    delivery_id: &str,
    event_id: &str,
    trusted_timestamp: i64,
    body: &[u8],
) -> bool {
    if secret.len() < 32 {
        return false;
    }
    let expected_prefix = format!("v{WEBHOOK_SIGNATURE_VERSION}=");
    let Some(encoded) = signature_header.strip_prefix(&expected_prefix) else {
        return false;
    };
    let Some(signature) = decode_signature_hex(encoded) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
        return false;
    };
    mac.update(&webhook_signature_payload(
        delivery_id,
        event_id,
        trusted_timestamp,
        body,
    ));
    mac.verify_slice(&signature).is_ok()
}

fn decode_signature_hex(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        output[index] = (high << 4) | low;
    }
    Some(output)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpDisposition {
    Delivered,
    Retry,
    Dead,
}

fn classify_http_status(status: StatusCode) -> HttpDisposition {
    if status.is_success() {
        HttpDisposition::Delivered
    } else if matches!(status.as_u16(), 408 | 409 | 425 | 429) || status.is_server_error() {
        HttpDisposition::Retry
    } else {
        HttpDisposition::Dead
    }
}

fn retry_after_seconds(value: &str, trusted_now: i64, maximum: i64) -> Option<i64> {
    if maximum <= 0 {
        return None;
    }
    if let Ok(seconds) = value.trim().parse::<i64>() {
        return Some(seconds.clamp(0, maximum));
    }
    let parsed = httpdate::parse_http_date(value.trim()).ok()?;
    let unix = parsed.duration_since(UNIX_EPOCH).ok()?.as_secs();
    let unix = i64::try_from(unix).ok()?;
    Some(unix.saturating_sub(trusted_now).clamp(0, maximum))
}

fn retry_delay_with_jitter(
    attempt: u32,
    base_seconds: i64,
    maximum_seconds: i64,
    random: u64,
) -> i64 {
    let exponent = attempt.saturating_sub(1).min(20);
    let exponential = base_seconds
        .saturating_mul(1_i64.checked_shl(exponent).unwrap_or(i64::MAX))
        .min(maximum_seconds);
    let jitter_window = exponential.saturating_div(4).max(1);
    let jitter = i64::try_from(random % u64::try_from(jitter_window).unwrap_or(u64::MAX))
        .unwrap_or_default();
    exponential.saturating_add(jitter).min(maximum_seconds)
}

fn secure_retry_delay(attempt: u32, base_seconds: i64, maximum_seconds: i64) -> i64 {
    let mut bytes = [0_u8; 8];
    rand::fill(&mut bytes);
    retry_delay_with_jitter(
        attempt,
        base_seconds,
        maximum_seconds,
        u64::from_le_bytes(bytes),
    )
}

fn valid_delivery_transition(from: WebhookDeliveryStatus, to: WebhookDeliveryStatus) -> bool {
    from == to
        || matches!(
            (from, to),
            (
                WebhookDeliveryStatus::Pending,
                WebhookDeliveryStatus::InFlight
            ) | (WebhookDeliveryStatus::Pending, WebhookDeliveryStatus::Dead)
                | (
                    WebhookDeliveryStatus::Retry,
                    WebhookDeliveryStatus::InFlight
                )
                | (WebhookDeliveryStatus::Retry, WebhookDeliveryStatus::Dead)
                | (
                    WebhookDeliveryStatus::InFlight,
                    WebhookDeliveryStatus::Delivered
                )
                | (
                    WebhookDeliveryStatus::InFlight,
                    WebhookDeliveryStatus::Retry
                )
                | (WebhookDeliveryStatus::InFlight, WebhookDeliveryStatus::Dead)
        )
}

#[derive(Clone)]
pub struct PostgresWebhookRepository {
    repository: PostgresRepository,
    keyring: Arc<WebhookKeyring>,
}

impl PostgresWebhookRepository {
    pub fn new(repository: PostgresRepository, keyring: Arc<WebhookKeyring>) -> Self {
        Self {
            repository,
            keyring,
        }
    }

    fn keyring(&self) -> &WebhookKeyring {
        &self.keyring
    }

    pub async fn readiness_check(&self) -> WebhookResult<()> {
        let ready: bool = sqlx::query_scalar(
            "SELECT to_regclass('public.workspace_webhook_endpoints') IS NOT NULL
                AND to_regclass('public.workspace_webhook_operations') IS NOT NULL
                AND to_regclass('public.workspace_webhook_events') IS NOT NULL
                AND to_regclass('public.workspace_webhook_deliveries') IS NOT NULL",
        )
        .fetch_one(&self.repository.pool)
        .await
        .map_err(|_| WebhookError::Database)?;
        if !ready {
            return Err(WebhookError::DatabaseSchemaNotReady);
        }
        let keyring = self.keyring();
        let active_key_id = keyring.active_key_id();
        if active_key_id.is_empty()
            || active_key_id.len() > 128
            || active_key_id
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
        {
            return Err(WebhookError::KeyringUnavailable);
        }
        let referenced_key_ids = sqlx::query_scalar::<_, String>(
            "SELECT DISTINCT secret_key_id FROM workspace_webhook_endpoints
             WHERE deleted_at IS NULL ORDER BY secret_key_id",
        )
        .fetch_all(&self.repository.pool)
        .await
        .map_err(|_| WebhookError::Database)?;
        if referenced_key_ids
            .iter()
            .any(|key_id| !keyring.contains_key_id(key_id))
        {
            return Err(WebhookError::KeyringUnavailable);
        }
        Ok(())
    }
}

const WEBHOOK_READ_PERMISSIONS: &[&str] = &["webhooks.read"];
const WEBHOOK_MANAGE_PERMISSIONS: &[&str] = &["webhooks.manage"];
const WEBHOOK_DELIVERY_READ_PERMISSIONS: &[&str] = &["webhooks.read", "webhooks.delivery.read"];

fn validate_repository_context(
    account_id: &str,
    device_id: &str,
    trusted_now: i64,
) -> WebhookResult<()> {
    if account_id.trim().is_empty() || device_id.trim().is_empty() || trusted_now <= 0 {
        return Err(WebhookError::InvalidRequest);
    }
    Ok(())
}

pub(crate) fn canonical_webhook_endpoint_id(value: &str) -> WebhookResult<String> {
    if !value.starts_with("webhook_endpoint_")
        || value.len() > 96
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'))
    {
        return Err(WebhookError::InvalidRequest);
    }
    Ok(value.to_owned())
}

fn authorization_error(error: ApiError) -> WebhookError {
    match error {
        ApiError::PermissionDenied => WebhookError::PermissionDenied,
        ApiError::CapabilityDenied => WebhookError::CapabilityDenied,
        ApiError::AccountSuspended => WebhookError::AccountSuspended,
        ApiError::AccountDenylisted => WebhookError::AccountDenylisted,
        ApiError::LicenseUnavailable => WebhookError::LicenseUnavailable,
        ApiError::LicensePastDue => WebhookError::LicensePastDue,
        ApiError::LicenseCanceled => WebhookError::LicenseCanceled,
        ApiError::LicenseExpired => WebhookError::LicenseExpired,
        ApiError::TimeAuthorityUnavailable => WebhookError::TimeAuthorityUnavailable,
        ApiError::InvalidRequest => WebhookError::InvalidRequest,
        ApiError::Database | ApiError::DatabaseSchemaNotReady => WebhookError::Database,
        _ => WebhookError::Database,
    }
}

async fn authorize_webhook_permission_tx(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    device_id: &str,
    permissions: &[&str],
    trusted_now: i64,
) -> WebhookResult<WorkspaceAuthorization> {
    let authorization = require_permissions_tx(tx, account_id, device_id, permissions, trusted_now)
        .await
        .map_err(authorization_error)?;
    let row = sqlx::query(
        "SELECT plan, plan_revision, purchased_seats
         FROM licenses WHERE account_id = $1 FOR SHARE",
    )
    .bind(account_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| WebhookError::Database)?
    .ok_or(WebhookError::LicenseUnavailable)?;
    let plan = match row.try_get::<String, _>("plan").as_deref() {
        Ok("free") => Plan::Free,
        Ok("pro") => Plan::Pro,
        Ok("team") => Plan::Team,
        _ => return Err(WebhookError::Database),
    };
    let revision = row
        .try_get::<i32, _>("plan_revision")
        .ok()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(WebhookError::Database)?;
    let seats = row
        .try_get::<i32, _>("purchased_seats")
        .ok()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(WebhookError::Database)?;
    let policy = effective_policy(plan, revision, seats).map_err(authorization_error)?;
    if !policy.capabilities.contains(&Capability::Webhooks) {
        return Err(WebhookError::CapabilityDenied);
    }
    Ok(authorization)
}

struct StoredWebhookEndpoint {
    endpoint: WebhookEndpoint,
}

fn row_webhook_endpoint(row: &PgRow) -> WebhookResult<WebhookEndpoint> {
    Ok(WebhookEndpoint {
        id: row.try_get("id").map_err(|_| WebhookError::Database)?,
        name: row.try_get("name").map_err(|_| WebhookError::Database)?,
        url: row.try_get("url").map_err(|_| WebhookError::Database)?,
        event_types: row
            .try_get("event_types")
            .map_err(|_| WebhookError::Database)?,
        active: row.try_get("active").map_err(|_| WebhookError::Database)?,
        secret_version: row
            .try_get::<i32, _>("secret_version")
            .ok()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(WebhookError::Database)?,
        row_version: row
            .try_get::<i64, _>("row_version")
            .ok()
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(WebhookError::Database)?,
        created_at: row
            .try_get("created_at")
            .map_err(|_| WebhookError::Database)?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|_| WebhookError::Database)?,
    })
}

async fn load_stored_endpoint_for_update(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    endpoint_id: &str,
) -> WebhookResult<StoredWebhookEndpoint> {
    let row = sqlx::query(
        "SELECT id, account_id, name, url, event_types, active, secret_version,
                row_version, created_at, updated_at
         FROM workspace_webhook_endpoints
         WHERE account_id = $1 AND id = $2 AND deleted_at IS NULL
         FOR UPDATE",
    )
    .bind(account_id)
    .bind(endpoint_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| WebhookError::Database)?
    .ok_or(WebhookError::NotFound)?;
    let endpoint = row_webhook_endpoint(&row)?;
    Ok(StoredWebhookEndpoint { endpoint })
}

fn webhook_secret_aad(account_id: &str, endpoint_id: &str, secret_version: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(account_id.len() + endpoint_id.len() + 32);
    append_signature_field(&mut aad, b"workspace-webhook-secret-v1");
    append_signature_field(&mut aad, account_id.as_bytes());
    append_signature_field(&mut aad, endpoint_id.as_bytes());
    append_signature_field(&mut aad, secret_version.to_string().as_bytes());
    aad
}

fn seal_webhook_secret(
    keyring: &WebhookKeyring,
    account_id: &str,
    endpoint_id: &str,
    secret_version: u32,
    secret: &[u8],
) -> WebhookResult<(String, Vec<u8>, Vec<u8>)> {
    keyring.seal(
        &webhook_secret_aad(account_id, endpoint_id, secret_version),
        secret,
    )
}

fn open_webhook_secret(
    keyring: &WebhookKeyring,
    account_id: &str,
    endpoint_id: &str,
    secret_version: u32,
    key_id: &str,
    nonce: &[u8],
    ciphertext: &[u8],
) -> WebhookResult<Zeroizing<Vec<u8>>> {
    keyring.open(
        key_id,
        &webhook_secret_aad(account_id, endpoint_id, secret_version),
        nonce,
        ciphertext,
    )
}

fn update_hash_field(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

fn endpoint_request_hash(
    command: &str,
    endpoint_id: Option<&str>,
    row_version: Option<u64>,
    input: Option<&CanonicalEndpointInput>,
) -> String {
    let mut digest = Sha256::new();
    update_hash_field(
        &mut digest,
        b"camellia-nexus/workspace-webhook-operation/v1",
    );
    update_hash_field(&mut digest, command.as_bytes());
    update_hash_field(&mut digest, endpoint_id.unwrap_or_default().as_bytes());
    update_hash_field(
        &mut digest,
        row_version
            .map(|version| version.to_string())
            .unwrap_or_default()
            .as_bytes(),
    );
    if let Some(input) = input {
        update_hash_field(&mut digest, input.name.as_bytes());
        update_hash_field(&mut digest, input.url.serialized.as_bytes());
        for event_type in &input.event_types {
            update_hash_field(&mut digest, event_type.as_bytes());
        }
        update_hash_field(&mut digest, if input.active { b"true" } else { b"false" });
    }
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn claim_webhook_operation<T: DeserializeOwned>(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    operation_id: &str,
    command: &str,
    request_hash: &str,
    trusted_now: i64,
) -> WebhookResult<Option<T>> {
    let inserted = sqlx::query(
        "INSERT INTO workspace_webhook_operations
            (account_id, operation_id, command, request_hash, endpoint_id, response,
             created_at, completed_at)
         VALUES ($1, $2, $3, $4, NULL, NULL, $5, NULL)
         ON CONFLICT (account_id, operation_id) DO NOTHING",
    )
    .bind(account_id)
    .bind(operation_id)
    .bind(command)
    .bind(request_hash)
    .bind(trusted_now)
    .execute(&mut **tx)
    .await
    .map_err(|_| WebhookError::Database)?
    .rows_affected();
    if inserted == 1 {
        return Ok(None);
    }
    let row = sqlx::query(
        "SELECT command, request_hash, response
         FROM workspace_webhook_operations
         WHERE account_id = $1 AND operation_id = $2
         FOR UPDATE",
    )
    .bind(account_id)
    .bind(operation_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| WebhookError::Database)?;
    let stored_command: String = row.try_get("command").map_err(|_| WebhookError::Database)?;
    let stored_hash: String = row
        .try_get("request_hash")
        .map_err(|_| WebhookError::Database)?;
    if stored_command != command || stored_hash != request_hash {
        return Err(WebhookError::IdempotencyConflict);
    }
    let response: Option<serde_json::Value> = row
        .try_get("response")
        .map_err(|_| WebhookError::Database)?;
    let response = response.ok_or(WebhookError::Database)?;
    serde_json::from_value(response)
        .map(Some)
        .map_err(|_| WebhookError::Serialization)
}

#[allow(clippy::too_many_arguments)]
async fn finish_webhook_operation<T: Serialize>(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    operation_id: &str,
    command: &str,
    request_hash: &str,
    endpoint_id: &str,
    response: &T,
    trusted_now: i64,
) -> WebhookResult<()> {
    let response = serde_json::to_value(response).map_err(|_| WebhookError::Serialization)?;
    let updated = sqlx::query(
        "UPDATE workspace_webhook_operations
         SET endpoint_id = $6, response = $7, completed_at = $8
         WHERE account_id = $1 AND operation_id = $2 AND command = $3 AND request_hash = $4
           AND created_at <= $5 AND endpoint_id IS NULL AND response IS NULL AND completed_at IS NULL",
    )
    .bind(account_id)
    .bind(operation_id)
    .bind(command)
    .bind(request_hash)
    .bind(trusted_now)
    .bind(endpoint_id)
    .bind(response)
    .bind(trusted_now)
    .execute(&mut **tx)
    .await
    .map_err(|_| WebhookError::Database)?
    .rows_affected();
    if updated == 1 {
        Ok(())
    } else {
        Err(WebhookError::Database)
    }
}

#[allow(clippy::too_many_arguments)]
async fn insert_webhook_audit_tx(
    tx: &mut Transaction<'_, Postgres>,
    event_type: &str,
    account_id: &str,
    member_id: &str,
    device_id: &str,
    endpoint_id: &str,
    operation_id: &str,
    trusted_now: i64,
) -> WebhookResult<()> {
    let record = AuditEventRecord {
        id: random_id("audit"),
        event_type: event_type.to_owned(),
        outcome: "succeeded".to_owned(),
        occurred_at: trusted_now,
        account_id: Some(account_id.to_owned()),
        license_id: None,
        device_id: Some(device_id.to_owned()),
        reason_code: None,
        metadata: BTreeMap::from([
            ("actorMemberId".to_owned(), member_id.to_owned()),
            ("endpointId".to_owned(), endpoint_id.to_owned()),
            ("operationId".to_owned(), operation_id.to_owned()),
        ]),
    };
    sqlx::query(
        "INSERT INTO audit_events
            (id, event_type, outcome, occurred_at, account_id, license_id, device_id,
             reason_code, metadata, document)
         VALUES ($1, $2, 'succeeded', $3, $4, NULL, $5, NULL, $6, $7)",
    )
    .bind(&record.id)
    .bind(event_type)
    .bind(trusted_now)
    .bind(account_id)
    .bind(device_id)
    .bind(serde_json::to_value(&record.metadata).map_err(|_| WebhookError::Serialization)?)
    .bind(serde_json::to_value(&record).map_err(|_| WebhookError::Serialization)?)
    .execute(&mut **tx)
    .await
    .map_err(|_| WebhookError::Database)?;
    Ok(())
}

impl PostgresWebhookRepository {
    pub async fn list_endpoints(
        &self,
        account_id: &str,
        device_id: &str,
        trusted_now: i64,
    ) -> WebhookResult<Vec<WebhookEndpoint>> {
        validate_repository_context(account_id, device_id, trusted_now)?;
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| WebhookError::Database)?;
        authorize_webhook_permission_tx(
            &mut tx,
            account_id,
            device_id,
            WEBHOOK_READ_PERMISSIONS,
            trusted_now,
        )
        .await?;
        let rows = sqlx::query(
            "SELECT id, account_id, name, url, event_types, active, secret_version,
                    row_version, created_at, updated_at
             FROM workspace_webhook_endpoints
             WHERE account_id = $1 AND deleted_at IS NULL
             ORDER BY created_at ASC, id ASC",
        )
        .bind(account_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| WebhookError::Database)?;
        let endpoints = rows
            .iter()
            .map(row_webhook_endpoint)
            .collect::<WebhookResult<Vec<_>>>()?;
        authorize_webhook_permission_tx(
            &mut tx,
            account_id,
            device_id,
            WEBHOOK_READ_PERMISSIONS,
            trusted_now,
        )
        .await?;
        tx.commit().await.map_err(|_| WebhookError::Database)?;
        Ok(endpoints)
    }

    pub async fn create_endpoint(
        &self,
        account_id: &str,
        device_id: &str,
        request: CreateWebhookEndpoint,
        trusted_now: i64,
    ) -> WebhookResult<WebhookSecretResult> {
        validate_repository_context(account_id, device_id, trusted_now)?;
        let operation_id = canonical_uuid_v4(&request.operation_id)?;
        let input = canonical_endpoint_input(
            &request.name,
            &request.url,
            &request.event_types,
            request.active,
        )?;
        let command = "endpoint.create";
        let request_hash = endpoint_request_hash(command, None, None, Some(&input));
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| WebhookError::Database)?;
        let actor = authorize_webhook_permission_tx(
            &mut tx,
            account_id,
            device_id,
            WEBHOOK_MANAGE_PERMISSIONS,
            trusted_now,
        )
        .await?;
        if let Some(endpoint) = claim_webhook_operation::<WebhookEndpoint>(
            &mut tx,
            account_id,
            &operation_id,
            command,
            &request_hash,
            trusted_now,
        )
        .await?
        {
            authorize_webhook_permission_tx(
                &mut tx,
                account_id,
                device_id,
                WEBHOOK_MANAGE_PERMISSIONS,
                trusted_now,
            )
            .await?;
            tx.commit().await.map_err(|_| WebhookError::Database)?;
            return Ok(WebhookSecretResult {
                endpoint,
                secret: None,
            });
        }
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 240024))")
            .bind(account_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| WebhookError::Database)?;
        let endpoint_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM workspace_webhook_endpoints
             WHERE account_id = $1 AND deleted_at IS NULL",
        )
        .bind(account_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| WebhookError::Database)?;
        if endpoint_count >= MAX_ENDPOINTS_PER_ACCOUNT {
            return Err(WebhookError::EndpointLimitReached);
        }

        let endpoint_id = random_id("webhook_endpoint");
        let secret = OneTimeWebhookSecret::new(random_secret());
        let secret_version = 1_u32;
        let (secret_key_id, secret_nonce, secret_ciphertext) = seal_webhook_secret(
            self.keyring(),
            account_id,
            &endpoint_id,
            secret_version,
            secret.expose_secret().as_bytes(),
        )?;
        let endpoint = WebhookEndpoint {
            id: endpoint_id.clone(),
            name: input.name,
            url: input.url.serialized,
            event_types: input.event_types,
            active: input.active,
            secret_version,
            row_version: 1,
            created_at: trusted_now,
            updated_at: trusted_now,
        };
        sqlx::query(
            "INSERT INTO workspace_webhook_endpoints
                (id, account_id, name, url, event_types, active, secret_version, secret_key_id,
                 secret_nonce, secret_ciphertext, row_version, created_at, updated_at, deleted_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 1, $11, $11, NULL)",
        )
        .bind(&endpoint.id)
        .bind(account_id)
        .bind(&endpoint.name)
        .bind(&endpoint.url)
        .bind(&endpoint.event_types)
        .bind(endpoint.active)
        .bind(i32::try_from(endpoint.secret_version).map_err(|_| WebhookError::InvalidRequest)?)
        .bind(secret_key_id)
        .bind(secret_nonce)
        .bind(secret_ciphertext)
        .bind(trusted_now)
        .execute(&mut *tx)
        .await
        .map_err(|_| WebhookError::Database)?;
        insert_webhook_audit_tx(
            &mut tx,
            "workspace_webhook_endpoint_created",
            account_id,
            &actor.member_id,
            device_id,
            &endpoint.id,
            &operation_id,
            trusted_now,
        )
        .await?;
        finish_webhook_operation(
            &mut tx,
            account_id,
            &operation_id,
            command,
            &request_hash,
            &endpoint.id,
            &endpoint,
            trusted_now,
        )
        .await?;
        authorize_webhook_permission_tx(
            &mut tx,
            account_id,
            device_id,
            WEBHOOK_MANAGE_PERMISSIONS,
            trusted_now,
        )
        .await?;
        tx.commit().await.map_err(|_| WebhookError::Database)?;
        Ok(WebhookSecretResult {
            endpoint,
            secret: Some(secret),
        })
    }

    pub async fn update_endpoint(
        &self,
        account_id: &str,
        device_id: &str,
        endpoint_id: &str,
        request: UpdateWebhookEndpoint,
        trusted_now: i64,
    ) -> WebhookResult<WebhookEndpoint> {
        validate_repository_context(account_id, device_id, trusted_now)?;
        canonical_webhook_endpoint_id(endpoint_id)?;
        if request.row_version == 0 {
            return Err(WebhookError::InvalidRequest);
        }
        let operation_id = canonical_uuid_v4(&request.operation_id)?;
        let input = canonical_endpoint_input(
            &request.name,
            &request.url,
            &request.event_types,
            request.active,
        )?;
        let command = "endpoint.update";
        let request_hash = endpoint_request_hash(
            command,
            Some(endpoint_id),
            Some(request.row_version),
            Some(&input),
        );
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| WebhookError::Database)?;
        let actor = authorize_webhook_permission_tx(
            &mut tx,
            account_id,
            device_id,
            WEBHOOK_MANAGE_PERMISSIONS,
            trusted_now,
        )
        .await?;
        if let Some(endpoint) = claim_webhook_operation::<WebhookEndpoint>(
            &mut tx,
            account_id,
            &operation_id,
            command,
            &request_hash,
            trusted_now,
        )
        .await?
        {
            authorize_webhook_permission_tx(
                &mut tx,
                account_id,
                device_id,
                WEBHOOK_MANAGE_PERMISSIONS,
                trusted_now,
            )
            .await?;
            tx.commit().await.map_err(|_| WebhookError::Database)?;
            return Ok(endpoint);
        }
        let mut stored = load_stored_endpoint_for_update(&mut tx, account_id, endpoint_id).await?;
        if stored.endpoint.row_version != request.row_version {
            return Err(WebhookError::VersionConflict);
        }
        let updated = sqlx::query(
            "UPDATE workspace_webhook_endpoints
             SET name = $3, url = $4, event_types = $5, active = $6,
                 row_version = row_version + 1, updated_at = $7
             WHERE account_id = $1 AND id = $2 AND row_version = $8 AND deleted_at IS NULL",
        )
        .bind(account_id)
        .bind(endpoint_id)
        .bind(&input.name)
        .bind(&input.url.serialized)
        .bind(&input.event_types)
        .bind(input.active)
        .bind(trusted_now)
        .bind(i64::try_from(request.row_version).map_err(|_| WebhookError::InvalidRequest)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| WebhookError::Database)?
        .rows_affected();
        if updated != 1 {
            return Err(WebhookError::VersionConflict);
        }
        if !input.active {
            sqlx::query(
                "UPDATE workspace_webhook_deliveries
                 SET state = 'dead', last_error_category = 'endpoint_inactive', updated_at = $3
                 WHERE account_id = $1 AND endpoint_id = $2 AND state IN ('pending', 'retry')",
            )
            .bind(account_id)
            .bind(endpoint_id)
            .bind(trusted_now)
            .execute(&mut *tx)
            .await
            .map_err(|_| WebhookError::Database)?;
        }
        stored.endpoint.name = input.name;
        stored.endpoint.url = input.url.serialized;
        stored.endpoint.event_types = input.event_types;
        stored.endpoint.active = input.active;
        stored.endpoint.row_version = stored.endpoint.row_version.saturating_add(1);
        stored.endpoint.updated_at = trusted_now;
        insert_webhook_audit_tx(
            &mut tx,
            "workspace_webhook_endpoint_updated",
            account_id,
            &actor.member_id,
            device_id,
            endpoint_id,
            &operation_id,
            trusted_now,
        )
        .await?;
        finish_webhook_operation(
            &mut tx,
            account_id,
            &operation_id,
            command,
            &request_hash,
            endpoint_id,
            &stored.endpoint,
            trusted_now,
        )
        .await?;
        authorize_webhook_permission_tx(
            &mut tx,
            account_id,
            device_id,
            WEBHOOK_MANAGE_PERMISSIONS,
            trusted_now,
        )
        .await?;
        tx.commit().await.map_err(|_| WebhookError::Database)?;
        Ok(stored.endpoint)
    }

    pub async fn rotate_endpoint_secret(
        &self,
        account_id: &str,
        device_id: &str,
        endpoint_id: &str,
        request: RotateWebhookSecret,
        trusted_now: i64,
    ) -> WebhookResult<WebhookSecretResult> {
        validate_repository_context(account_id, device_id, trusted_now)?;
        canonical_webhook_endpoint_id(endpoint_id)?;
        if request.row_version == 0 {
            return Err(WebhookError::InvalidRequest);
        }
        let operation_id = canonical_uuid_v4(&request.operation_id)?;
        let command = "endpoint.rotate_secret";
        let request_hash =
            endpoint_request_hash(command, Some(endpoint_id), Some(request.row_version), None);
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| WebhookError::Database)?;
        let actor = authorize_webhook_permission_tx(
            &mut tx,
            account_id,
            device_id,
            WEBHOOK_MANAGE_PERMISSIONS,
            trusted_now,
        )
        .await?;
        if let Some(endpoint) = claim_webhook_operation::<WebhookEndpoint>(
            &mut tx,
            account_id,
            &operation_id,
            command,
            &request_hash,
            trusted_now,
        )
        .await?
        {
            authorize_webhook_permission_tx(
                &mut tx,
                account_id,
                device_id,
                WEBHOOK_MANAGE_PERMISSIONS,
                trusted_now,
            )
            .await?;
            tx.commit().await.map_err(|_| WebhookError::Database)?;
            return Ok(WebhookSecretResult {
                endpoint,
                secret: None,
            });
        }
        let mut stored = load_stored_endpoint_for_update(&mut tx, account_id, endpoint_id).await?;
        if stored.endpoint.row_version != request.row_version {
            return Err(WebhookError::VersionConflict);
        }
        let secret_version = stored
            .endpoint
            .secret_version
            .checked_add(1)
            .ok_or(WebhookError::InvalidRequest)?;
        let secret = OneTimeWebhookSecret::new(random_secret());
        let (key_id, nonce, ciphertext) = seal_webhook_secret(
            self.keyring(),
            account_id,
            endpoint_id,
            secret_version,
            secret.expose_secret().as_bytes(),
        )?;
        let updated = sqlx::query(
            "UPDATE workspace_webhook_endpoints
             SET secret_version = $3, secret_key_id = $4, secret_nonce = $5,
                 secret_ciphertext = $6, row_version = row_version + 1, updated_at = $7
             WHERE account_id = $1 AND id = $2 AND row_version = $8 AND deleted_at IS NULL",
        )
        .bind(account_id)
        .bind(endpoint_id)
        .bind(i32::try_from(secret_version).map_err(|_| WebhookError::InvalidRequest)?)
        .bind(key_id)
        .bind(nonce)
        .bind(ciphertext)
        .bind(trusted_now)
        .bind(i64::try_from(request.row_version).map_err(|_| WebhookError::InvalidRequest)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| WebhookError::Database)?
        .rows_affected();
        if updated != 1 {
            return Err(WebhookError::VersionConflict);
        }
        stored.endpoint.secret_version = secret_version;
        stored.endpoint.row_version = stored.endpoint.row_version.saturating_add(1);
        stored.endpoint.updated_at = trusted_now;
        insert_webhook_audit_tx(
            &mut tx,
            "workspace_webhook_secret_rotated",
            account_id,
            &actor.member_id,
            device_id,
            endpoint_id,
            &operation_id,
            trusted_now,
        )
        .await?;
        finish_webhook_operation(
            &mut tx,
            account_id,
            &operation_id,
            command,
            &request_hash,
            endpoint_id,
            &stored.endpoint,
            trusted_now,
        )
        .await?;
        authorize_webhook_permission_tx(
            &mut tx,
            account_id,
            device_id,
            WEBHOOK_MANAGE_PERMISSIONS,
            trusted_now,
        )
        .await?;
        tx.commit().await.map_err(|_| WebhookError::Database)?;
        Ok(WebhookSecretResult {
            endpoint: stored.endpoint,
            secret: Some(secret),
        })
    }

    pub async fn delete_endpoint(
        &self,
        account_id: &str,
        device_id: &str,
        endpoint_id: &str,
        request: DeleteWebhookEndpoint,
        trusted_now: i64,
    ) -> WebhookResult<WebhookDeletion> {
        validate_repository_context(account_id, device_id, trusted_now)?;
        canonical_webhook_endpoint_id(endpoint_id)?;
        if request.row_version == 0 {
            return Err(WebhookError::InvalidRequest);
        }
        let operation_id = canonical_uuid_v4(&request.operation_id)?;
        let command = "endpoint.delete";
        let request_hash =
            endpoint_request_hash(command, Some(endpoint_id), Some(request.row_version), None);
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| WebhookError::Database)?;
        let actor = authorize_webhook_permission_tx(
            &mut tx,
            account_id,
            device_id,
            WEBHOOK_MANAGE_PERMISSIONS,
            trusted_now,
        )
        .await?;
        if let Some(deletion) = claim_webhook_operation::<WebhookDeletion>(
            &mut tx,
            account_id,
            &operation_id,
            command,
            &request_hash,
            trusted_now,
        )
        .await?
        {
            authorize_webhook_permission_tx(
                &mut tx,
                account_id,
                device_id,
                WEBHOOK_MANAGE_PERMISSIONS,
                trusted_now,
            )
            .await?;
            tx.commit().await.map_err(|_| WebhookError::Database)?;
            return Ok(deletion);
        }
        let stored = load_stored_endpoint_for_update(&mut tx, account_id, endpoint_id).await?;
        if stored.endpoint.row_version != request.row_version {
            return Err(WebhookError::VersionConflict);
        }
        let updated = sqlx::query(
            "UPDATE workspace_webhook_endpoints
             SET active = false, deleted_at = $3, row_version = row_version + 1, updated_at = $3
             WHERE account_id = $1 AND id = $2 AND row_version = $4 AND deleted_at IS NULL",
        )
        .bind(account_id)
        .bind(endpoint_id)
        .bind(trusted_now)
        .bind(i64::try_from(request.row_version).map_err(|_| WebhookError::InvalidRequest)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| WebhookError::Database)?
        .rows_affected();
        if updated != 1 {
            return Err(WebhookError::VersionConflict);
        }
        sqlx::query(
            "UPDATE workspace_webhook_deliveries
             SET state = 'dead', last_error_category = 'endpoint_deleted', updated_at = $3
             WHERE account_id = $1 AND endpoint_id = $2 AND state IN ('pending', 'retry')",
        )
        .bind(account_id)
        .bind(endpoint_id)
        .bind(trusted_now)
        .execute(&mut *tx)
        .await
        .map_err(|_| WebhookError::Database)?;
        let deletion = WebhookDeletion {
            endpoint_id: endpoint_id.to_owned(),
            deleted_at: trusted_now,
            row_version: stored.endpoint.row_version.saturating_add(1),
        };
        insert_webhook_audit_tx(
            &mut tx,
            "workspace_webhook_endpoint_deleted",
            account_id,
            &actor.member_id,
            device_id,
            endpoint_id,
            &operation_id,
            trusted_now,
        )
        .await?;
        finish_webhook_operation(
            &mut tx,
            account_id,
            &operation_id,
            command,
            &request_hash,
            endpoint_id,
            &deletion,
            trusted_now,
        )
        .await?;
        authorize_webhook_permission_tx(
            &mut tx,
            account_id,
            device_id,
            WEBHOOK_MANAGE_PERMISSIONS,
            trusted_now,
        )
        .await?;
        tx.commit().await.map_err(|_| WebhookError::Database)?;
        Ok(deletion)
    }

    pub async fn list_deliveries(
        &self,
        account_id: &str,
        device_id: &str,
        endpoint_id: Option<&str>,
        limit: u16,
        trusted_now: i64,
    ) -> WebhookResult<Vec<WebhookDeliverySummary>> {
        validate_repository_context(account_id, device_id, trusted_now)?;
        if limit == 0 || limit > MAX_DELIVERY_LIST_LIMIT {
            return Err(WebhookError::InvalidRequest);
        }
        if let Some(endpoint_id) = endpoint_id {
            canonical_webhook_endpoint_id(endpoint_id)?;
        }
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| WebhookError::Database)?;
        authorize_webhook_permission_tx(
            &mut tx,
            account_id,
            device_id,
            WEBHOOK_DELIVERY_READ_PERMISSIONS,
            trusted_now,
        )
        .await?;
        let rows = sqlx::query(
            "SELECT deliveries.id, deliveries.event_id, deliveries.endpoint_id,
                    events.event_type, deliveries.state, deliveries.attempt_count,
                    deliveries.next_attempt_at, deliveries.last_http_status,
                    deliveries.last_error_category, deliveries.delivered_at,
                    deliveries.created_at, deliveries.updated_at
             FROM workspace_webhook_deliveries AS deliveries
             JOIN workspace_webhook_events AS events
               ON events.account_id = deliveries.account_id
              AND events.event_id = deliveries.event_id
             WHERE deliveries.account_id = $1
               AND ($2::TEXT IS NULL OR deliveries.endpoint_id = $2)
             ORDER BY deliveries.created_at DESC, deliveries.id DESC
             LIMIT $3",
        )
        .bind(account_id)
        .bind(endpoint_id)
        .bind(i64::from(limit))
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| WebhookError::Database)?;
        let deliveries = rows
            .iter()
            .map(row_delivery_summary)
            .collect::<WebhookResult<Vec<_>>>()?;
        authorize_webhook_permission_tx(
            &mut tx,
            account_id,
            device_id,
            WEBHOOK_DELIVERY_READ_PERMISSIONS,
            trusted_now,
        )
        .await?;
        tx.commit().await.map_err(|_| WebhookError::Database)?;
        Ok(deliveries)
    }

    pub async fn cleanup_expired(
        &self,
        trusted_now: i64,
        batch_size: u32,
    ) -> WebhookResult<WebhookCleanupReport> {
        if trusted_now <= 0 || batch_size == 0 || batch_size > MAX_CLEANUP_BATCH_SIZE {
            return Err(WebhookError::InvalidRequest);
        }
        let active_cutoff = trusted_now.saturating_sub(ACTIVE_DELIVERY_MAX_AGE_SECONDS);
        let history_cutoff = trusted_now.saturating_sub(WEBHOOK_HISTORY_RETENTION_SECONDS);
        let batch_size = i64::from(batch_size);
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| WebhookError::Database)?;

        let expired_deliveries = sqlx::query(
            "WITH candidates AS (
                 SELECT id FROM workspace_webhook_deliveries
                 WHERE created_at <= $1
                   AND (
                       state IN ('pending', 'retry')
                       OR (state = 'in_flight' AND lease_until <= $2)
                   )
                 ORDER BY created_at, id
                 FOR UPDATE SKIP LOCKED
                 LIMIT $3
             )
             UPDATE workspace_webhook_deliveries AS deliveries
             SET state = 'dead', next_attempt_at = $2, lease_owner = NULL, lease_until = NULL,
                 last_error_category = 'delivery_expired', delivered_at = NULL, updated_at = $2
             FROM candidates WHERE deliveries.id = candidates.id",
        )
        .bind(active_cutoff)
        .bind(trusted_now)
        .bind(batch_size)
        .execute(&mut *tx)
        .await
        .map_err(|_| WebhookError::Database)?
        .rows_affected();

        let deleted_events = sqlx::query(
            "WITH candidates AS (
                 SELECT events.account_id, events.event_id
                 FROM workspace_webhook_events AS events
                 WHERE events.created_at <= $1
                   AND NOT EXISTS (
                       SELECT 1 FROM workspace_webhook_deliveries AS deliveries
                       WHERE deliveries.account_id = events.account_id
                         AND deliveries.event_id = events.event_id
                         AND (
                             deliveries.state IN ('pending', 'retry', 'in_flight')
                             OR deliveries.updated_at > $1
                         )
                   )
                 ORDER BY events.created_at, events.account_id, events.event_id
                 FOR UPDATE OF events SKIP LOCKED
                 LIMIT $2
             )
             DELETE FROM workspace_webhook_events AS events USING candidates
             WHERE events.account_id = candidates.account_id
               AND events.event_id = candidates.event_id",
        )
        .bind(history_cutoff)
        .bind(batch_size)
        .execute(&mut *tx)
        .await
        .map_err(|_| WebhookError::Database)?
        .rows_affected();

        let deleted_operations = sqlx::query(
            "WITH candidates AS (
                 SELECT account_id, operation_id FROM workspace_webhook_operations
                 WHERE completed_at <= $1
                 ORDER BY completed_at, account_id, operation_id
                 FOR UPDATE SKIP LOCKED
                 LIMIT $2
             )
             DELETE FROM workspace_webhook_operations AS operations USING candidates
             WHERE operations.account_id = candidates.account_id
               AND operations.operation_id = candidates.operation_id",
        )
        .bind(history_cutoff)
        .bind(batch_size)
        .execute(&mut *tx)
        .await
        .map_err(|_| WebhookError::Database)?
        .rows_affected();

        let deleted_endpoints = sqlx::query(
            "WITH candidates AS (
                 SELECT endpoints.account_id, endpoints.id
                 FROM workspace_webhook_endpoints AS endpoints
                 WHERE endpoints.deleted_at <= $1
                   AND NOT EXISTS (
                       SELECT 1 FROM workspace_webhook_deliveries AS deliveries
                       WHERE deliveries.account_id = endpoints.account_id
                         AND deliveries.endpoint_id = endpoints.id
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM workspace_webhook_operations AS operations
                       WHERE operations.account_id = endpoints.account_id
                         AND operations.endpoint_id = endpoints.id
                   )
                 ORDER BY endpoints.deleted_at, endpoints.account_id, endpoints.id
                 FOR UPDATE OF endpoints SKIP LOCKED
                 LIMIT $2
             )
             DELETE FROM workspace_webhook_endpoints AS endpoints USING candidates
             WHERE endpoints.account_id = candidates.account_id
               AND endpoints.id = candidates.id",
        )
        .bind(history_cutoff)
        .bind(batch_size)
        .execute(&mut *tx)
        .await
        .map_err(|_| WebhookError::Database)?
        .rows_affected();

        tx.commit().await.map_err(|_| WebhookError::Database)?;
        Ok(WebhookCleanupReport {
            expired_deliveries,
            deleted_events,
            deleted_operations,
            deleted_endpoints,
        })
    }
}

fn row_delivery_summary(row: &PgRow) -> WebhookResult<WebhookDeliverySummary> {
    let status = parse_delivery_status(
        &row.try_get::<String, _>("state")
            .map_err(|_| WebhookError::Database)?,
    )?;
    Ok(WebhookDeliverySummary {
        id: row.try_get("id").map_err(|_| WebhookError::Database)?,
        event_id: row
            .try_get("event_id")
            .map_err(|_| WebhookError::Database)?,
        endpoint_id: row
            .try_get("endpoint_id")
            .map_err(|_| WebhookError::Database)?,
        event_type: row
            .try_get("event_type")
            .map_err(|_| WebhookError::Database)?,
        status,
        attempt_count: row
            .try_get::<i32, _>("attempt_count")
            .ok()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(WebhookError::Database)?,
        next_attempt_at: row
            .try_get("next_attempt_at")
            .map_err(|_| WebhookError::Database)?,
        last_http_status: row
            .try_get::<Option<i32>, _>("last_http_status")
            .map_err(|_| WebhookError::Database)?
            .map(u16::try_from)
            .transpose()
            .map_err(|_| WebhookError::Database)?,
        last_error_category: row
            .try_get("last_error_category")
            .map_err(|_| WebhookError::Database)?,
        delivered_at: row
            .try_get("delivered_at")
            .map_err(|_| WebhookError::Database)?,
        created_at: row
            .try_get("created_at")
            .map_err(|_| WebhookError::Database)?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|_| WebhookError::Database)?,
    })
}

fn parse_delivery_status(value: &str) -> WebhookResult<WebhookDeliveryStatus> {
    match value {
        "pending" => Ok(WebhookDeliveryStatus::Pending),
        "in_flight" => Ok(WebhookDeliveryStatus::InFlight),
        "delivered" => Ok(WebhookDeliveryStatus::Delivered),
        "retry" => Ok(WebhookDeliveryStatus::Retry),
        "dead" => Ok(WebhookDeliveryStatus::Dead),
        _ => Err(WebhookError::Database),
    }
}

struct CanonicalWebhookEvent {
    event_id: String,
    event_type: String,
    body: Vec<u8>,
}

fn canonical_webhook_event(
    event: &NewWebhookEvent,
    trusted_now: i64,
) -> WebhookResult<CanonicalWebhookEvent> {
    if trusted_now <= 0 || !event.payload.is_object() {
        return Err(WebhookError::InvalidRequest);
    }
    let event_id = canonical_uuid_v4(&event.event_id)?;
    let event_type = canonical_event_type(&event.event_type)?;
    validate_event_payload_has_no_secrets(&event.payload)?;
    let body = serde_json::to_vec(&serde_json::json!({
        "eventId": event_id,
        "eventType": event_type,
        "occurredAt": trusted_now,
        "payload": event.payload,
    }))
    .map_err(|_| WebhookError::Serialization)?;
    if body.len() < 2 || body.len() > MAX_EVENT_PAYLOAD_BYTES {
        return Err(WebhookError::InvalidRequest);
    }
    Ok(CanonicalWebhookEvent {
        event_id,
        event_type,
        body,
    })
}

fn webhook_event_bodies_are_same_logical_event(
    stored: &[u8],
    candidate: &[u8],
) -> WebhookResult<bool> {
    let mut stored =
        serde_json::from_slice::<serde_json::Value>(stored).map_err(|_| WebhookError::Database)?;
    let mut candidate = serde_json::from_slice::<serde_json::Value>(candidate)
        .map_err(|_| WebhookError::Serialization)?;
    let stored = stored.as_object_mut().ok_or(WebhookError::Database)?;
    let candidate = candidate
        .as_object_mut()
        .ok_or(WebhookError::Serialization)?;
    if stored
        .remove("occurredAt")
        .and_then(|value| value.as_i64())
        .is_none()
    {
        return Err(WebhookError::Database);
    }
    if candidate
        .remove("occurredAt")
        .and_then(|value| value.as_i64())
        .is_none()
    {
        return Err(WebhookError::Serialization);
    }
    Ok(stored == candidate)
}

fn validate_event_payload_has_no_secrets(payload: &serde_json::Value) -> WebhookResult<()> {
    let mut pending = vec![(payload, 0_usize)];
    let mut visited = 0_usize;
    while let Some((value, depth)) = pending.pop() {
        visited = visited.saturating_add(1);
        if depth > MAX_EVENT_PAYLOAD_DEPTH || visited > 10_000 {
            return Err(WebhookError::InvalidRequest);
        }
        match value {
            serde_json::Value::Object(object) => {
                for (key, value) in object {
                    if event_payload_key_is_sensitive(key) {
                        return Err(WebhookError::InvalidRequest);
                    }
                    pending.push((value, depth.saturating_add(1)));
                }
            }
            serde_json::Value::Array(array) => {
                pending.extend(array.iter().map(|value| (value, depth.saturating_add(1))));
            }
            _ => {}
        }
    }
    Ok(())
}

fn event_payload_key_is_sensitive(key: &str) -> bool {
    let normalized = key
        .bytes()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect::<String>();
    [
        "secret",
        "password",
        "privatekey",
        "refreshtoken",
        "accesstoken",
        "sessiontoken",
        "authorization",
        "apikey",
        "paymenttoken",
        "entitlement",
    ]
    .iter()
    .any(|sensitive| normalized.contains(sensitive))
}

pub async fn enqueue_webhook_event_tx(
    tx: &mut Transaction<'_, Postgres>,
    account_id: &str,
    event: &NewWebhookEvent,
    trusted_now: i64,
) -> WebhookResult<u64> {
    if account_id.trim().is_empty() {
        return Err(WebhookError::InvalidRequest);
    }
    let event = canonical_webhook_event(event, trusted_now)?;
    let inserted = sqlx::query(
        "INSERT INTO workspace_webhook_events
            (account_id, event_id, event_type, payload, created_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (account_id, event_id) DO NOTHING",
    )
    .bind(account_id)
    .bind(&event.event_id)
    .bind(&event.event_type)
    .bind(&event.body)
    .bind(trusted_now)
    .execute(&mut **tx)
    .await
    .map_err(|_| WebhookError::Database)?
    .rows_affected();
    if inserted == 0 {
        let row = sqlx::query(
            "SELECT event_type, payload FROM workspace_webhook_events
             WHERE account_id = $1 AND event_id = $2 FOR SHARE",
        )
        .bind(account_id)
        .bind(&event.event_id)
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| WebhookError::Database)?;
        let stored_type: String = row
            .try_get("event_type")
            .map_err(|_| WebhookError::Database)?;
        let stored_body: Vec<u8> = row.try_get("payload").map_err(|_| WebhookError::Database)?;
        if stored_type != event.event_type
            || !webhook_event_bodies_are_same_logical_event(&stored_body, &event.body)?
        {
            return Err(WebhookError::IdempotencyConflict);
        }
    }
    let endpoint_ids = sqlx::query_scalar::<_, String>(
        "SELECT id FROM workspace_webhook_endpoints
         WHERE account_id = $1 AND active AND deleted_at IS NULL
           AND $2 = ANY(event_types)
         ORDER BY id
         FOR SHARE",
    )
    .bind(account_id)
    .bind(&event.event_type)
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| WebhookError::Database)?;
    let mut created = 0_u64;
    for endpoint_id in endpoint_ids {
        created = created.saturating_add(
            sqlx::query(
                "INSERT INTO workspace_webhook_deliveries
                    (id, account_id, event_id, endpoint_id, state, attempt_count,
                     next_attempt_at, lease_owner, lease_until, last_http_status,
                     last_error_category, delivered_at, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, 'pending', 0, $5, NULL, NULL, NULL, NULL, NULL, $5, $5)
                 ON CONFLICT (account_id, event_id, endpoint_id) DO NOTHING",
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(account_id)
            .bind(&event.event_id)
            .bind(endpoint_id)
            .bind(trusted_now)
            .execute(&mut **tx)
            .await
            .map_err(|_| WebhookError::Database)?
            .rows_affected(),
        );
    }
    Ok(created)
}

pub struct WebhookDispatcherConfig {
    pub poll_interval: Duration,
    pub dns_timeout: Duration,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub shutdown_grace: Duration,
    pub lease_seconds: i64,
    pub global_concurrency: usize,
    pub per_host_concurrency: usize,
    pub claim_batch_size: usize,
    pub max_attempts: u32,
    pub retry_base_seconds: i64,
    pub retry_max_seconds: i64,
    pub retry_after_max_seconds: i64,
}

impl Default for WebhookDispatcherConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(2),
            dns_timeout: Duration::from_secs(3),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(10),
            shutdown_grace: Duration::from_secs(20),
            lease_seconds: 180,
            global_concurrency: 32,
            per_host_concurrency: 4,
            claim_batch_size: 32,
            max_attempts: 8,
            retry_base_seconds: 5,
            retry_max_seconds: 60 * 60,
            retry_after_max_seconds: 6 * 60 * 60,
        }
    }
}

impl WebhookDispatcherConfig {
    pub fn validate(&self) -> WebhookResult<()> {
        if self.poll_interval.is_zero()
            || self.dns_timeout.is_zero()
            || self.connect_timeout.is_zero()
            || self.request_timeout.is_zero()
            || self.shutdown_grace.is_zero()
            || self.global_concurrency == 0
            || self.per_host_concurrency == 0
            || self.per_host_concurrency > self.global_concurrency
            || self.claim_batch_size == 0
            || self.claim_batch_size > self.global_concurrency
            || self.max_attempts == 0
            || self.max_attempts > 32
            || self.retry_base_seconds <= 0
            || self.retry_max_seconds < self.retry_base_seconds
            || self.retry_after_max_seconds <= 0
        {
            return Err(WebhookError::InvalidDispatcherConfiguration);
        }
        let queued_rounds = self
            .global_concurrency
            .div_ceil(self.per_host_concurrency)
            .saturating_add(2);
        let attempt_seconds = duration_seconds_ceil(self.dns_timeout)
            .saturating_add(duration_seconds_ceil(self.request_timeout));
        let minimum_lease =
            attempt_seconds.saturating_mul(u64::try_from(queued_rounds).unwrap_or(u64::MAX));
        if self.lease_seconds <= 0
            || u64::try_from(self.lease_seconds).unwrap_or_default() < minimum_lease
        {
            return Err(WebhookError::InvalidDispatcherConfiguration);
        }
        Ok(())
    }
}

fn dispatcher_error_is_transient(error: &WebhookError) -> bool {
    matches!(
        error,
        WebhookError::Database | WebhookError::TimeAuthorityUnavailable
    )
}

fn dispatcher_retry_delay(failure_count: u32, poll_interval: Duration) -> Duration {
    let multiplier = 1_u32 << failure_count.saturating_sub(1).min(4);
    poll_interval
        .checked_mul(multiplier)
        .unwrap_or(Duration::from_secs(30))
        .min(Duration::from_secs(30))
}

async fn wait_for_dispatcher_retry(shutdown: &mut watch::Receiver<bool>, delay: Duration) -> bool {
    tokio::select! {
        changed = shutdown.changed() => changed.is_err() || *shutdown.borrow(),
        () = tokio::time::sleep(delay) => false,
    }
}

fn duration_seconds_ceil(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_add(u64::from(duration.subsec_nanos() != 0))
}

#[async_trait]
pub trait WebhookTimeAuthority: Send + Sync + 'static {
    async fn trusted_now(&self) -> WebhookResult<i64>;
}

struct ClaimedWebhookDelivery {
    id: String,
    account_id: String,
    event_id: String,
    endpoint_id: String,
    endpoint_url: String,
    endpoint_row_version: u64,
    secret_version: u32,
    secret_key_id: String,
    secret_nonce: Vec<u8>,
    secret_ciphertext: Vec<u8>,
    body: Vec<u8>,
    attempt_count: u32,
    claimed_at: i64,
}

enum DeliveryAttemptOutcome {
    Delivered {
        status: u16,
    },
    Retry {
        status: Option<u16>,
        category: &'static str,
        retry_after_seconds: Option<i64>,
    },
    Dead {
        status: Option<u16>,
        category: &'static str,
    },
}

enum ClaimedEndpointState {
    Current,
    Changed,
    Inactive,
}

impl PostgresWebhookRepository {
    async fn claim_deliveries(
        &self,
        worker_id: &str,
        limit: usize,
        config: &WebhookDispatcherConfig,
        trusted_now: i64,
    ) -> WebhookResult<Vec<ClaimedWebhookDelivery>> {
        if trusted_now <= 0 || limit == 0 || limit > config.global_concurrency {
            return Err(WebhookError::InvalidRequest);
        }
        canonical_uuid_v4(worker_id)?;
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| WebhookError::Database)?;
        sqlx::query(
            "WITH expired AS (
                 SELECT id FROM workspace_webhook_deliveries
                 WHERE state = 'in_flight' AND lease_until <= $1
                 ORDER BY lease_until, id
                 FOR UPDATE SKIP LOCKED
                 LIMIT $3
             )
             UPDATE workspace_webhook_deliveries AS deliveries
             SET state = CASE WHEN attempt_count >= $2 THEN 'dead' ELSE 'retry' END,
                 next_attempt_at = $1, lease_owner = NULL, lease_until = NULL,
                 last_error_category = 'lease_expired', updated_at = $1
             FROM expired WHERE deliveries.id = expired.id",
        )
        .bind(trusted_now)
        .bind(i32::try_from(config.max_attempts).map_err(|_| WebhookError::InvalidRequest)?)
        .bind(i64::try_from(limit).map_err(|_| WebhookError::InvalidRequest)?)
        .execute(&mut *tx)
        .await
        .map_err(|_| WebhookError::Database)?;
        let lease_until = trusted_now.saturating_add(config.lease_seconds);
        let rows = sqlx::query(
            "WITH candidates AS (
                 SELECT deliveries.id
                 FROM workspace_webhook_deliveries AS deliveries
                 JOIN workspace_webhook_endpoints AS endpoints
                   ON endpoints.account_id = deliveries.account_id
                  AND endpoints.id = deliveries.endpoint_id
                 WHERE deliveries.state IN ('pending', 'retry')
                   AND deliveries.next_attempt_at <= $1
                   AND deliveries.attempt_count < $5
                   AND endpoints.active
                   AND endpoints.deleted_at IS NULL
                 ORDER BY deliveries.next_attempt_at, deliveries.created_at, deliveries.id
                 FOR UPDATE OF deliveries SKIP LOCKED
                 LIMIT $2
             ), claimed AS (
                 UPDATE workspace_webhook_deliveries AS deliveries
                 SET state = 'in_flight', attempt_count = attempt_count + 1,
                     lease_owner = $3, lease_until = $4, updated_at = $1
                 FROM candidates
                 WHERE deliveries.id = candidates.id
                 RETURNING deliveries.id, deliveries.account_id, deliveries.event_id,
                           deliveries.endpoint_id, deliveries.attempt_count
             )
             SELECT claimed.id, claimed.account_id, claimed.event_id, claimed.endpoint_id,
                    claimed.attempt_count, endpoints.url, endpoints.row_version,
                    endpoints.secret_version,
                    endpoints.secret_key_id, endpoints.secret_nonce,
                    endpoints.secret_ciphertext, events.payload
             FROM claimed
             JOIN workspace_webhook_endpoints AS endpoints
               ON endpoints.account_id = claimed.account_id AND endpoints.id = claimed.endpoint_id
             JOIN workspace_webhook_events AS events
               ON events.account_id = claimed.account_id AND events.event_id = claimed.event_id
             ORDER BY claimed.id",
        )
        .bind(trusted_now)
        .bind(i64::try_from(limit).map_err(|_| WebhookError::InvalidRequest)?)
        .bind(worker_id)
        .bind(lease_until)
        .bind(i32::try_from(config.max_attempts).map_err(|_| WebhookError::InvalidRequest)?)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| WebhookError::Database)?;
        let claims = rows
            .into_iter()
            .map(|row| {
                Ok(ClaimedWebhookDelivery {
                    id: row.try_get("id").map_err(|_| WebhookError::Database)?,
                    account_id: row
                        .try_get("account_id")
                        .map_err(|_| WebhookError::Database)?,
                    event_id: row
                        .try_get("event_id")
                        .map_err(|_| WebhookError::Database)?,
                    endpoint_id: row
                        .try_get("endpoint_id")
                        .map_err(|_| WebhookError::Database)?,
                    endpoint_url: row.try_get("url").map_err(|_| WebhookError::Database)?,
                    endpoint_row_version: row
                        .try_get::<i64, _>("row_version")
                        .ok()
                        .and_then(|value| u64::try_from(value).ok())
                        .ok_or(WebhookError::Database)?,
                    secret_version: row
                        .try_get::<i32, _>("secret_version")
                        .ok()
                        .and_then(|value| u32::try_from(value).ok())
                        .ok_or(WebhookError::Database)?,
                    secret_key_id: row
                        .try_get("secret_key_id")
                        .map_err(|_| WebhookError::Database)?,
                    secret_nonce: row
                        .try_get("secret_nonce")
                        .map_err(|_| WebhookError::Database)?,
                    secret_ciphertext: row
                        .try_get("secret_ciphertext")
                        .map_err(|_| WebhookError::Database)?,
                    body: row.try_get("payload").map_err(|_| WebhookError::Database)?,
                    attempt_count: row
                        .try_get::<i32, _>("attempt_count")
                        .ok()
                        .and_then(|value| u32::try_from(value).ok())
                        .ok_or(WebhookError::Database)?,
                    claimed_at: trusted_now,
                })
            })
            .collect::<WebhookResult<Vec<_>>>()?;
        tx.commit().await.map_err(|_| WebhookError::Database)?;
        Ok(claims)
    }

    async fn claimed_endpoint_state(
        &self,
        claim: &ClaimedWebhookDelivery,
    ) -> WebhookResult<ClaimedEndpointState> {
        let row = sqlx::query(
            "SELECT active, deleted_at, row_version
             FROM workspace_webhook_endpoints
             WHERE account_id = $1 AND id = $2",
        )
        .bind(&claim.account_id)
        .bind(&claim.endpoint_id)
        .fetch_optional(&self.repository.pool)
        .await
        .map_err(|_| WebhookError::Database)?;
        let Some(row) = row else {
            return Ok(ClaimedEndpointState::Inactive);
        };
        let active: bool = row.try_get("active").map_err(|_| WebhookError::Database)?;
        let deleted_at: Option<i64> = row
            .try_get("deleted_at")
            .map_err(|_| WebhookError::Database)?;
        if !active || deleted_at.is_some() {
            return Ok(ClaimedEndpointState::Inactive);
        }
        let row_version = row
            .try_get::<i64, _>("row_version")
            .ok()
            .and_then(|value| u64::try_from(value).ok())
            .ok_or(WebhookError::Database)?;
        Ok(if row_version == claim.endpoint_row_version {
            ClaimedEndpointState::Current
        } else {
            ClaimedEndpointState::Changed
        })
    }

    async fn complete_delivery(
        &self,
        worker_id: &str,
        claim: &ClaimedWebhookDelivery,
        outcome: DeliveryAttemptOutcome,
        config: &WebhookDispatcherConfig,
        trusted_now: i64,
    ) -> WebhookResult<()> {
        if trusted_now <= 0 {
            return Err(WebhookError::InvalidRequest);
        }
        let mut tx = self
            .repository
            .pool
            .begin()
            .await
            .map_err(|_| WebhookError::Database)?;
        let row = sqlx::query(
            "SELECT state, attempt_count, lease_owner
             FROM workspace_webhook_deliveries WHERE id = $1 FOR UPDATE",
        )
        .bind(&claim.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| WebhookError::Database)?
        .ok_or(WebhookError::LeaseLost)?;
        let state: String = row.try_get("state").map_err(|_| WebhookError::Database)?;
        let attempt_count = row
            .try_get::<i32, _>("attempt_count")
            .ok()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(WebhookError::Database)?;
        let lease_owner: Option<String> = row
            .try_get("lease_owner")
            .map_err(|_| WebhookError::Database)?;
        if state != "in_flight"
            || lease_owner.as_deref() != Some(worker_id)
            || attempt_count != claim.attempt_count
        {
            return Err(WebhookError::LeaseLost);
        }
        let (next_state, status, category, next_attempt_at, delivered_at) = match outcome {
            DeliveryAttemptOutcome::Delivered { status } => (
                "delivered",
                Some(status),
                None,
                trusted_now,
                Some(trusted_now),
            ),
            DeliveryAttemptOutcome::Dead { status, category } => {
                ("dead", status, Some(category), trusted_now, None)
            }
            DeliveryAttemptOutcome::Retry {
                status,
                category,
                retry_after_seconds: _,
            } if attempt_count >= config.max_attempts => {
                ("dead", status, Some(category), trusted_now, None)
            }
            DeliveryAttemptOutcome::Retry {
                status,
                category,
                retry_after_seconds,
            } => {
                let backoff = secure_retry_delay(
                    attempt_count,
                    config.retry_base_seconds,
                    config.retry_max_seconds,
                );
                let retry_after = retry_after_seconds.unwrap_or_default();
                (
                    "retry",
                    status,
                    Some(category),
                    trusted_now.saturating_add(backoff.max(retry_after)),
                    None,
                )
            }
        };
        if !valid_delivery_transition(
            WebhookDeliveryStatus::InFlight,
            parse_delivery_status(next_state)?,
        ) {
            return Err(WebhookError::Database);
        }
        let updated = sqlx::query(
            "UPDATE workspace_webhook_deliveries
             SET state = $4, next_attempt_at = $5, lease_owner = NULL, lease_until = NULL,
                 last_http_status = $6, last_error_category = $7, delivered_at = $8,
                 updated_at = $9
             WHERE id = $1 AND state = 'in_flight' AND lease_owner = $2 AND attempt_count = $3",
        )
        .bind(&claim.id)
        .bind(worker_id)
        .bind(i32::try_from(attempt_count).map_err(|_| WebhookError::Database)?)
        .bind(next_state)
        .bind(next_attempt_at)
        .bind(status.map(i32::from))
        .bind(category)
        .bind(delivered_at)
        .bind(trusted_now)
        .execute(&mut *tx)
        .await
        .map_err(|_| WebhookError::Database)?
        .rows_affected();
        if updated != 1 {
            return Err(WebhookError::LeaseLost);
        }
        tx.commit().await.map_err(|_| WebhookError::Database)?;
        tracing::info!(
            status = status,
            attempt = attempt_count,
            next_attempt_at,
            error_category = category,
            "workspace webhook delivery attempt completed"
        );
        Ok(())
    }
}

enum DnsResolutionError {
    Unavailable,
    Rejected,
}

async fn resolve_webhook_target(
    endpoint: &CanonicalWebhookUrl,
    timeout: Duration,
) -> Result<Vec<SocketAddr>, DnsResolutionError> {
    let lookup = tokio::net::lookup_host((endpoint.host.as_str(), 443));
    let resolved = tokio::time::timeout(timeout, lookup)
        .await
        .map_err(|_| DnsResolutionError::Unavailable)?
        .map_err(|_| DnsResolutionError::Unavailable)?;
    let addresses = resolved.collect::<BTreeSet<_>>();
    if addresses.is_empty() {
        return Err(DnsResolutionError::Unavailable);
    }
    if addresses.len() > 32
        || addresses
            .iter()
            .any(|address| !webhook_target_ip_is_safe(address.ip()))
    {
        return Err(DnsResolutionError::Rejected);
    }
    Ok(addresses.into_iter().collect())
}

fn normalized_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

fn peer_is_pinned(peer: SocketAddr, pinned: &[SocketAddr]) -> bool {
    webhook_target_ip_is_safe(peer.ip())
        && pinned
            .iter()
            .any(|address| normalized_ip(address.ip()) == normalized_ip(peer.ip()))
}

async fn dispatch_webhook_delivery(
    repository: &PostgresWebhookRepository,
    claim: &ClaimedWebhookDelivery,
    config: &WebhookDispatcherConfig,
    trusted_now: i64,
) -> DeliveryAttemptOutcome {
    let endpoint = match canonical_webhook_url(&claim.endpoint_url) {
        Ok(endpoint) => endpoint,
        Err(_) => {
            return DeliveryAttemptOutcome::Dead {
                status: None,
                category: "endpoint_invalid",
            };
        }
    };
    let addresses = match resolve_webhook_target(&endpoint, config.dns_timeout).await {
        Ok(addresses) => addresses,
        Err(DnsResolutionError::Unavailable) => {
            return DeliveryAttemptOutcome::Retry {
                status: None,
                category: "dns_unavailable",
                retry_after_seconds: None,
            };
        }
        Err(DnsResolutionError::Rejected) => {
            return DeliveryAttemptOutcome::Dead {
                status: None,
                category: "dns_rejected",
            };
        }
    };
    match repository.claimed_endpoint_state(claim).await {
        Ok(ClaimedEndpointState::Current) => {}
        Ok(ClaimedEndpointState::Changed) => {
            return DeliveryAttemptOutcome::Retry {
                status: None,
                category: "endpoint_changed",
                retry_after_seconds: None,
            };
        }
        Ok(ClaimedEndpointState::Inactive) => {
            return DeliveryAttemptOutcome::Dead {
                status: None,
                category: "endpoint_inactive",
            };
        }
        Err(_) => {
            return DeliveryAttemptOutcome::Retry {
                status: None,
                category: "endpoint_check_failed",
                retry_after_seconds: None,
            };
        }
    }
    let keyring = repository.keyring();
    let secret = match open_webhook_secret(
        keyring,
        &claim.account_id,
        &claim.endpoint_id,
        claim.secret_version,
        &claim.secret_key_id,
        &claim.secret_nonce,
        &claim.secret_ciphertext,
    ) {
        Ok(secret) => secret,
        Err(_) => {
            return DeliveryAttemptOutcome::Retry {
                status: None,
                category: "keyring_unavailable",
                retry_after_seconds: None,
            };
        }
    };
    let signature = match sign_webhook_payload(
        &secret,
        &claim.id,
        &claim.event_id,
        trusted_now,
        &claim.body,
    ) {
        Ok(signature) => signature,
        Err(_) => {
            return DeliveryAttemptOutcome::Dead {
                status: None,
                category: "signature_failed",
            };
        }
    };
    let client = match reqwest::Client::builder()
        .redirect(redirect::Policy::none())
        .no_proxy()
        .https_only(true)
        .connect_timeout(config.connect_timeout)
        .timeout(config.request_timeout)
        .pool_max_idle_per_host(0)
        .resolve_to_addrs(&endpoint.host, &addresses)
        .build()
    {
        Ok(client) => client,
        Err(_) => {
            return DeliveryAttemptOutcome::Retry {
                status: None,
                category: "client_unavailable",
                retry_after_seconds: None,
            };
        }
    };
    let response = client
        .post(&endpoint.serialized)
        .header(header::CONTENT_TYPE, "application/json")
        .header(WEBHOOK_HEADER_VERSION, WEBHOOK_SIGNATURE_VERSION)
        .header(WEBHOOK_HEADER_DELIVERY_ID, &claim.id)
        .header(WEBHOOK_HEADER_EVENT_ID, &claim.event_id)
        .header(WEBHOOK_HEADER_TIMESTAMP, trusted_now.to_string())
        .header(WEBHOOK_HEADER_SIGNATURE, signature)
        .header(
            WEBHOOK_HEADER_SECRET_VERSION,
            claim.secret_version.to_string(),
        )
        .body(claim.body.clone())
        .send()
        .await;
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            return DeliveryAttemptOutcome::Retry {
                status: None,
                category: if error.is_timeout() {
                    "request_timeout"
                } else if error.is_connect() {
                    "connect_failed"
                } else {
                    "request_failed"
                },
                retry_after_seconds: None,
            };
        }
    };
    let Some(peer) = response.remote_addr() else {
        return DeliveryAttemptOutcome::Dead {
            status: None,
            category: "peer_unverified",
        };
    };
    if !peer_is_pinned(peer, &addresses) {
        return DeliveryAttemptOutcome::Dead {
            status: None,
            category: "peer_mismatch",
        };
    }
    let status = response.status();
    let retry_after = response
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| retry_after_seconds(value, trusted_now, config.retry_after_max_seconds));
    match classify_http_status(status) {
        HttpDisposition::Delivered => DeliveryAttemptOutcome::Delivered {
            status: status.as_u16(),
        },
        HttpDisposition::Retry => DeliveryAttemptOutcome::Retry {
            status: Some(status.as_u16()),
            category: "remote_retry",
            retry_after_seconds: retry_after,
        },
        HttpDisposition::Dead => DeliveryAttemptOutcome::Dead {
            status: Some(status.as_u16()),
            category: "remote_rejected",
        },
    }
}

async fn host_semaphore(
    semaphores: &Mutex<HashMap<String, Weak<Semaphore>>>,
    host: String,
    limit: usize,
) -> Arc<Semaphore> {
    let mut semaphores = semaphores.lock().await;
    semaphores.retain(|_, semaphore| semaphore.strong_count() > 0);
    if let Some(semaphore) = semaphores.get(&host).and_then(Weak::upgrade) {
        return semaphore;
    }
    let semaphore = Arc::new(Semaphore::new(limit));
    semaphores.insert(host, Arc::downgrade(&semaphore));
    semaphore
}

pub async fn run_webhook_dispatcher(
    repository: Arc<PostgresWebhookRepository>,
    time_authority: Arc<dyn WebhookTimeAuthority>,
    config: Arc<WebhookDispatcherConfig>,
    mut shutdown: watch::Receiver<bool>,
) -> WebhookResult<()> {
    config.validate()?;
    let worker_id = uuid::Uuid::new_v4().to_string();
    let global_semaphore = Arc::new(Semaphore::new(config.global_concurrency));
    let host_semaphores = Arc::new(Mutex::new(HashMap::<String, Weak<Semaphore>>::new()));
    let mut tasks = JoinSet::<WebhookResult<()>>::new();
    let mut consecutive_claim_failures = 0_u32;

    'dispatcher: loop {
        if *shutdown.borrow() {
            break;
        }
        let available = config.global_concurrency.saturating_sub(tasks.len());
        let mut claimed_any = false;
        if available > 0 {
            let trusted_now = tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break 'dispatcher;
                    }
                    continue 'dispatcher;
                }
                result = time_authority.trusted_now() => result,
            };
            let trusted_now = match trusted_now {
                Ok(now) if now > 0 => now,
                Ok(_) => {
                    consecutive_claim_failures = consecutive_claim_failures.saturating_add(1);
                    let delay =
                        dispatcher_retry_delay(consecutive_claim_failures, config.poll_interval);
                    tracing::warn!(
                        error_category = WebhookError::TimeAuthorityUnavailable.code(),
                        failure_count = consecutive_claim_failures,
                        retry_milliseconds = delay.as_millis(),
                        "workspace webhook dispatcher could not obtain trusted time"
                    );
                    if wait_for_dispatcher_retry(&mut shutdown, delay).await {
                        break;
                    }
                    continue;
                }
                Err(error) if dispatcher_error_is_transient(&error) => {
                    consecutive_claim_failures = consecutive_claim_failures.saturating_add(1);
                    let delay =
                        dispatcher_retry_delay(consecutive_claim_failures, config.poll_interval);
                    tracing::warn!(
                        error_category = error.code(),
                        failure_count = consecutive_claim_failures,
                        retry_milliseconds = delay.as_millis(),
                        "workspace webhook dispatcher temporarily unavailable"
                    );
                    if wait_for_dispatcher_retry(&mut shutdown, delay).await {
                        break;
                    }
                    continue;
                }
                Err(error) => return Err(error),
            };
            let claim_limit = available.min(config.claim_batch_size);
            let claims = tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break 'dispatcher;
                    }
                    continue 'dispatcher;
                }
                result = repository.claim_deliveries(
                    &worker_id,
                    claim_limit,
                    &config,
                    trusted_now,
                ) => result,
            };
            let claims = match claims {
                Ok(claims) => {
                    consecutive_claim_failures = 0;
                    claims
                }
                Err(error) if dispatcher_error_is_transient(&error) => {
                    consecutive_claim_failures = consecutive_claim_failures.saturating_add(1);
                    let delay =
                        dispatcher_retry_delay(consecutive_claim_failures, config.poll_interval);
                    tracing::warn!(
                        error_category = error.code(),
                        failure_count = consecutive_claim_failures,
                        retry_milliseconds = delay.as_millis(),
                        "workspace webhook delivery claim temporarily unavailable"
                    );
                    if wait_for_dispatcher_retry(&mut shutdown, delay).await {
                        break;
                    }
                    continue;
                }
                Err(error) => return Err(error),
            };
            claimed_any = !claims.is_empty();
            for claim in claims {
                let host = canonical_webhook_url(&claim.endpoint_url)
                    .map(|url| url.host)
                    .unwrap_or_else(|_| "invalid".to_owned());
                let host_semaphore =
                    host_semaphore(&host_semaphores, host, config.per_host_concurrency).await;
                let repository = Arc::clone(&repository);
                let time_authority = Arc::clone(&time_authority);
                let config = Arc::clone(&config);
                let global_semaphore = Arc::clone(&global_semaphore);
                let worker_id = worker_id.clone();
                tasks.spawn(async move {
                    let _global_permit = global_semaphore
                        .acquire_owned()
                        .await
                        .map_err(|_| WebhookError::InvalidDispatcherConfiguration)?;
                    let _host_permit = host_semaphore
                        .acquire_owned()
                        .await
                        .map_err(|_| WebhookError::InvalidDispatcherConfiguration)?;
                    let attempt_now = match time_authority.trusted_now().await {
                        Ok(now) if now > 0 => now,
                        _ => {
                            return repository
                                .complete_delivery(
                                    &worker_id,
                                    &claim,
                                    DeliveryAttemptOutcome::Retry {
                                        status: None,
                                        category: "time_unavailable",
                                        retry_after_seconds: None,
                                    },
                                    &config,
                                    claim.claimed_at,
                                )
                                .await;
                        }
                    };
                    let outcome =
                        dispatch_webhook_delivery(&repository, &claim, &config, attempt_now).await;
                    let completed_at = time_authority
                        .trusted_now()
                        .await
                        .unwrap_or(attempt_now)
                        .max(attempt_now);
                    repository
                        .complete_delivery(&worker_id, &claim, outcome, &config, completed_at)
                        .await
                });
            }
        }

        if tasks.is_empty() && !claimed_any {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                () = tokio::time::sleep(config.poll_interval) => {}
            }
        } else {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                joined = tasks.join_next(), if !tasks.is_empty() => {
                    match joined {
                        Some(Err(error)) if error.is_panic() => {
                            return Err(WebhookError::WorkerTaskPanicked);
                        }
                        Some(Err(_)) | Some(Ok(Err(_))) => {
                            tracing::warn!(error_category = "worker_task_failed", "workspace webhook worker task failed");
                        }
                        Some(Ok(Ok(()))) | None => {}
                    }
                }
                () = tokio::time::sleep(config.poll_interval) => {}
            }
        }
    }

    let drained = tokio::time::timeout(config.shutdown_grace, async {
        while let Some(joined) = tasks.join_next().await {
            if let Err(_) | Ok(Err(_)) = joined {
                tracing::warn!(
                    error_category = "worker_task_failed",
                    "workspace webhook worker task failed during shutdown"
                );
            }
        }
    })
    .await
    .is_ok();
    if !drained {
        tracing::warn!(
            error_category = "shutdown_grace_expired",
            "workspace webhook worker aborted outstanding tasks during shutdown"
        );
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const UUID_V4: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn endpoint() -> WebhookEndpoint {
        WebhookEndpoint {
            id: "webhook_endpoint_test".into(),
            name: "Production events".into(),
            url: "https://hooks.vendor.com/v1/events".into(),
            event_types: vec!["configuration.created".into()],
            active: true,
            secret_version: 1,
            row_version: 1,
            created_at: 1_000,
            updated_at: 1_000,
        }
    }

    fn write_temporary_keyring(document: serde_json::Value) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "camellia-webhook-keyring-{}.json",
            uuid::Uuid::new_v4()
        ));
        fs::write(&path, serde_json::to_vec(&document).expect("keyring JSON"))
            .expect("write keyring");
        path
    }

    #[test]
    fn webhook_keyring_is_domain_specific_strict_and_rotation_safe() {
        let first = URL_SAFE_NO_PAD.encode([7_u8; 32]);
        let second = URL_SAFE_NO_PAD.encode([9_u8; 32]);
        let path = write_temporary_keyring(serde_json::json!({
            "activeKeyId": "webhook-2026-08",
            "keys": {
                "webhook-2026-07": first,
                "webhook-2026-08": second,
            },
        }));
        let keyring = WebhookKeyring::load(&path).expect("valid rotating keyring");
        fs::remove_file(&path).expect("remove keyring");
        assert_eq!(keyring.active_key_id(), "webhook-2026-08");
        assert!(keyring.contains_key_id("webhook-2026-07"));

        for invalid in [
            serde_json::json!({
                "activeKeyId": "webhook:invalid",
                "keys": {"webhook:invalid": second},
            }),
            serde_json::json!({
                "activeKeyId": "webhook-2026-08",
                "keys": {"webhook-2026-08": second},
                "unexpected": true,
            }),
            serde_json::json!({
                "activeKeyId": "webhook-missing",
                "keys": {"webhook-2026-08": second},
            }),
        ] {
            let path = write_temporary_keyring(invalid);
            assert!(WebhookKeyring::load(&path).is_err());
            fs::remove_file(path).expect("remove invalid keyring");
        }
    }

    #[test]
    fn endpoint_url_is_https_canonical_and_contains_no_auth_channel() {
        let canonical = canonical_webhook_url(" HTTPS://Hooks.Vendor.COM:443/a/../v1/events ")
            .expect("canonical URL");
        assert_eq!(canonical.host, "hooks.vendor.com");
        assert_eq!(canonical.serialized, "https://hooks.vendor.com/v1/events");

        for invalid in [
            "http://hooks.vendor.com/events",
            "https://user:password@hooks.vendor.com/events",
            "https://hooks.vendor.com/events?token=secret",
            "https://hooks.vendor.com/events#fragment",
            "https://hooks.vendor.com:8443/events",
            "https://127.0.0.1/events",
            "https://[::1]/events",
            "https://localhost/events",
            "https://service.internal/events",
            "https://single-label/events",
        ] {
            assert!(canonical_webhook_url(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn ssrf_filter_rejects_all_special_address_classes() {
        for address in [
            "0.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.31.255.255",
            "192.0.0.9",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001::1",
            "2001:db8::1",
            "2002::1",
            "3fff::1",
            "::ffff:127.0.0.1",
            "::ffff:192.0.2.1",
        ] {
            let address = address.parse::<IpAddr>().expect("test IP address");
            assert!(!webhook_target_ip_is_safe(address), "{address}");
        }
        for address in [
            "1.1.1.1",
            "8.8.8.8",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            let address = address.parse::<IpAddr>().expect("test public IP address");
            assert!(webhook_target_ip_is_safe(address), "{address}");
        }
    }

    #[test]
    fn signature_covers_all_fields_and_uses_constant_time_verification() {
        let secret = b"32-bytes-of-receiver-shared-key!!";
        let body = br#"{"event":"configuration.created"}"#;
        let signature = sign_webhook_payload(secret, UUID_V4, UUID_V4, 1_700_000_000, body)
            .expect("sign webhook");
        assert!(verify_webhook_signature(
            secret,
            &signature,
            UUID_V4,
            UUID_V4,
            1_700_000_000,
            body
        ));
        assert!(!verify_webhook_signature(
            secret,
            &signature,
            "650e8400-e29b-41d4-a716-446655440000",
            UUID_V4,
            1_700_000_000,
            body
        ));
        assert!(!verify_webhook_signature(
            secret,
            &signature,
            UUID_V4,
            UUID_V4,
            1_700_000_001,
            body
        ));
        assert!(!verify_webhook_signature(
            secret,
            &signature,
            UUID_V4,
            UUID_V4,
            1_700_000_000,
            b"different"
        ));
        assert!(!verify_webhook_signature(
            secret,
            "v1=not-hex",
            UUID_V4,
            UUID_V4,
            1_700_000_000,
            body
        ));
    }

    #[test]
    fn secret_encryption_aad_binds_tenant_endpoint_and_version() {
        let keyring = WebhookKeyring::ephemeral_for_development();
        let secret = b"one-time-webhook-secret";
        let (key_id, nonce, ciphertext) =
            seal_webhook_secret(&keyring, "account_a", "endpoint_a", 1, secret)
                .expect("seal webhook secret");
        let opened = open_webhook_secret(
            &keyring,
            "account_a",
            "endpoint_a",
            1,
            &key_id,
            &nonce,
            &ciphertext,
        )
        .expect("open webhook secret");
        assert_eq!(opened.as_slice(), secret);
        assert!(
            open_webhook_secret(
                &keyring,
                "account_b",
                "endpoint_a",
                1,
                &key_id,
                &nonce,
                &ciphertext,
            )
            .is_err()
        );
        assert!(
            open_webhook_secret(
                &keyring,
                "account_a",
                "endpoint_a",
                2,
                &key_id,
                &nonce,
                &ciphertext,
            )
            .is_err()
        );
    }

    #[test]
    fn ordinary_json_never_persists_or_replays_secret_material() {
        let one_time = OneTimeWebhookSecret::new("one-time-plaintext".into());
        assert_eq!(format!("{one_time:?}"), "OneTimeWebhookSecret([REDACTED])");
        let first = WebhookSecretResult {
            endpoint: endpoint(),
            secret: Some(one_time),
        };
        let first_json = serde_json::to_value(&first).expect("serialize first response");
        assert_eq!(first_json["secret"], "one-time-plaintext");

        let operation_json = serde_json::to_string(&first.endpoint).expect("operation snapshot");
        assert!(!operation_json.contains("one-time-plaintext"));
        assert!(!operation_json.contains("secretKeyId"));
        assert!(!operation_json.contains("secretNonce"));
        assert!(!operation_json.contains("secretCiphertext"));

        let replay = WebhookSecretResult {
            endpoint: endpoint(),
            secret: None,
        };
        let replay_json = serde_json::to_value(replay).expect("serialize replay");
        assert!(replay_json.get("secret").is_none());
    }

    #[test]
    fn event_payload_rejects_secret_fields_and_excessive_nesting() {
        let safe = NewWebhookEvent {
            event_id: UUID_V4.into(),
            event_type: "configuration.created".into(),
            payload: serde_json::json!({"programId": "program_a", "status": "running"}),
        };
        let canonical = canonical_webhook_event(&safe, 1_700_000_000).expect("safe event");
        let document: serde_json::Value =
            serde_json::from_slice(&canonical.body).expect("event JSON");
        assert_eq!(document["eventId"], UUID_V4);
        assert_eq!(document["occurredAt"], 1_700_000_000_i64);
        let retried = canonical_webhook_event(&safe, 1_700_000_100).expect("retried event");
        assert!(
            webhook_event_bodies_are_same_logical_event(&canonical.body, &retried.body)
                .expect("logical event comparison")
        );
        let changed = canonical_webhook_event(
            &NewWebhookEvent {
                payload: serde_json::json!({"programId": "program_b", "status": "running"}),
                ..safe.clone()
            },
            1_700_000_100,
        )
        .expect("changed event");
        assert!(
            !webhook_event_bodies_are_same_logical_event(&canonical.body, &changed.body)
                .expect("logical event comparison")
        );

        for sensitive in [
            serde_json::json!({"password": "value"}),
            serde_json::json!({"api_key": "value"}),
            serde_json::json!({"nested": {"refreshToken": "value"}}),
            serde_json::json!({"entitlementMaterial": "value"}),
        ] {
            assert!(validate_event_payload_has_no_secrets(&sensitive).is_err());
        }

        let mut nested = serde_json::json!({"value": true});
        for _ in 0..=MAX_EVENT_PAYLOAD_DEPTH {
            nested = serde_json::json!({"nested": nested});
        }
        assert!(validate_event_payload_has_no_secrets(&nested).is_err());
    }

    #[test]
    fn retry_and_state_machine_rules_are_bounded() {
        for status in [200, 204, 299] {
            assert_eq!(
                classify_http_status(StatusCode::from_u16(status).expect("status")),
                HttpDisposition::Delivered
            );
        }
        for status in [408, 409, 425, 429, 500, 503, 599] {
            assert_eq!(
                classify_http_status(StatusCode::from_u16(status).expect("status")),
                HttpDisposition::Retry
            );
        }
        for status in [300, 301, 400, 401, 403, 404, 422] {
            assert_eq!(
                classify_http_status(StatusCode::from_u16(status).expect("status")),
                HttpDisposition::Dead
            );
        }
        assert_eq!(retry_after_seconds("999", 1_000, 60), Some(60));
        assert_eq!(
            retry_after_seconds("Wed, 21 Oct 2015 07:28:00 GMT", 1_445_412_470, 60),
            Some(10)
        );
        assert!((10..=11).contains(&retry_delay_with_jitter(2, 5, 100, u64::MAX)));
        assert_eq!(retry_delay_with_jitter(20, 5, 100, 0), 100);

        assert!(valid_delivery_transition(
            WebhookDeliveryStatus::Pending,
            WebhookDeliveryStatus::InFlight
        ));
        assert!(valid_delivery_transition(
            WebhookDeliveryStatus::InFlight,
            WebhookDeliveryStatus::Retry
        ));
        assert!(valid_delivery_transition(
            WebhookDeliveryStatus::Retry,
            WebhookDeliveryStatus::Dead
        ));
        assert!(!valid_delivery_transition(
            WebhookDeliveryStatus::Delivered,
            WebhookDeliveryStatus::Retry
        ));
        assert!(!valid_delivery_transition(
            WebhookDeliveryStatus::Dead,
            WebhookDeliveryStatus::InFlight
        ));
    }

    #[test]
    fn canonical_inputs_and_dispatcher_limits_are_strict() {
        assert_eq!(canonical_uuid_v4(UUID_V4).expect("canonical UUID"), UUID_V4);
        for invalid in [
            "550E8400-E29B-41D4-A716-446655440000",
            "550e8400-e29b-11d4-a716-446655440000",
            "00000000-0000-0000-0000-000000000000",
        ] {
            assert!(canonical_uuid_v4(invalid).is_err());
        }
        assert_eq!(
            canonical_event_types(&[
                "configuration.revised".into(),
                "configuration.created".into(),
            ])
            .expect("canonical events"),
            ["configuration.created", "configuration.revised"]
        );
        assert!(canonical_event_types(&vec!["configuration.created".into(); 2]).is_err());
        assert!(canonical_event_type("configuration.unknown").is_err());

        assert!(WebhookDispatcherConfig::default().validate().is_ok());
        let invalid = WebhookDispatcherConfig {
            lease_seconds: 10,
            ..WebhookDispatcherConfig::default()
        };
        assert!(matches!(
            invalid.validate(),
            Err(WebhookError::InvalidDispatcherConfiguration)
        ));

        let mut subsecond = WebhookDispatcherConfig {
            dns_timeout: Duration::from_millis(500),
            request_timeout: Duration::from_millis(500),
            global_concurrency: 4,
            per_host_concurrency: 1,
            claim_batch_size: 4,
            lease_seconds: 5,
            ..WebhookDispatcherConfig::default()
        };
        assert!(matches!(
            subsecond.validate(),
            Err(WebhookError::InvalidDispatcherConfiguration)
        ));
        subsecond.lease_seconds = 12;
        assert!(subsecond.validate().is_ok());
    }

    #[test]
    fn baseline_has_webhook_tenant_keys_state_trigger_and_no_database_clock() {
        let migration = include_str!("../migrations/0001_prelaunch_baseline.sql");
        assert!(migration.contains("UNIQUE (account_id, event_id, endpoint_id)"));
        assert!(migration.contains(
            "FOR EACH ROW EXECUTE FUNCTION public.enforce_workspace_webhook_delivery_transition"
        ));
        assert!(migration.contains("secret_ciphertext bytea"));
        assert!(migration.contains("secret_nonce bytea"));
        for event_type in SUPPORTED_WEBHOOK_EVENT_TYPES {
            assert!(migration.contains(event_type), "missing {event_type}");
        }
        for table in [
            "workspace_webhook_deliveries",
            "workspace_webhook_endpoints",
            "workspace_webhook_events",
            "workspace_webhook_operations",
        ] {
            let start = migration
                .find(&format!("CREATE TABLE public.{table} ("))
                .expect("webhook table belongs in the prelaunch baseline");
            let definition = &migration[start..];
            let definition = &definition[..definition
                .find("\n);\n")
                .expect("webhook table definition is terminated")];
            assert!(
                !definition.contains("now()"),
                "{table} must use trusted service time"
            );
            assert!(
                !definition.contains("CURRENT_TIMESTAMP")
                    && !definition.contains("clock_timestamp"),
                "{table} must not use a database business clock"
            );
        }
    }
}
