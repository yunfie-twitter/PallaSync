use std::collections::HashMap;

use axum::{
    Json,
    extract::{
        Path, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderName, HeaderValue, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{crypto::verify::verify_signed_json, db::DbState};

const PROTOCOL_VERSION: &str = "2.0";
const VENDOR_MEDIA_TYPE: &str = "application/vnd.palleria.sync.v2+json";
const DEFAULT_PAGE_LIMIT: u32 = 200;
const MAX_PAGE_LIMIT: u32 = 500;
const MAX_CIPHERTEXT_BYTES: usize = 8 * 1024 * 1024;

static NEXT_SEQ_HEADER: HeaderName = HeaderName::from_static("pallasync-next-seq");
static HAS_MORE_HEADER: HeaderName = HeaderName::from_static("pallasync-has-more");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordQuery {
    pub after_seq: Option<i64>,
    pub since_ms: Option<i64>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SyncRecord {
    pub protocol_version: String,
    pub chain_id: String,
    pub record_id: String,
    pub collection_name: String,
    pub action: String,
    pub encrypted_payload: String,
    pub device_id: String,
    pub created_at_ms: i64,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRecord {
    pub protocol_version: String,
    pub chain_id: String,
    pub device_id: String,
    pub encrypted_device_name: String,
    pub device_public_key: String,
    pub created_at_ms: i64,
    pub signature: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    protocol_version: &'static str,
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            message: message.into(),
        }
    }

    fn invalid_signature(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_signature",
            message: message.into(),
        }
    }

    fn gone() -> Self {
        Self {
            status: StatusCode::GONE,
            code: "chain_deleted",
            message: "This chain has been permanently deleted".to_string(),
        }
    }

    fn database(error: sqlx::Error) -> Self {
        error!(%error, "database operation failed");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "database_error",
            message: "Database operation failed".to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(ErrorBody {
                error: self.code,
                message: self.message,
            }),
        )
            .into_response();
        set_vendor_content_type(&mut response);
        response
    }
}

pub async fn health(State(state): State<DbState>) -> Result<Response, ApiError> {
    sqlx::query("SELECT 1")
        .execute(&state.pool)
        .await
        .map_err(ApiError::database)?;
    Ok(vendor_json(HealthResponse {
        status: "ok",
        protocol_version: PROTOCOL_VERSION,
    }))
}

pub async fn post_records(
    State(state): State<DbState>,
    Path(chain_id): Path<String>,
    payload: Result<Json<Vec<SyncRecord>>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    validate_chain_id(&chain_id)?;
    ensure_not_deleted(&state, &chain_id).await?;
    let Json(records) = payload.map_err(|error| ApiError::bad_request(error.body_text()))?;
    info!(chain = %short_id(&chain_id), count = records.len(), "posting sync records");

    let chain_public_key =
        sqlx::query("SELECT device_public_key FROM chain_public_keys WHERE chain_id = ?")
            .bind(&chain_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(ApiError::database)?
            .map(|row| row.get::<String, _>("device_public_key"))
            .ok_or_else(|| ApiError::invalid_signature("The chain has no registered public key"))?;

    let mut public_keys = HashMap::<String, String>::new();
    for record in &records {
        validate_sync_record(record, &chain_id)?;
        let public_key = if let Some(key) = public_keys.get(&record.device_id) {
            key.clone()
        } else {
            let row = sqlx::query(
                "SELECT device_public_key FROM device_records \
                 WHERE chain_id = ? AND device_id = ?",
            )
            .bind(&chain_id)
            .bind(&record.device_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(ApiError::database)?
            .ok_or_else(|| {
                ApiError::invalid_signature(format!(
                    "Device {} is not registered for this chain",
                    record.device_id
                ))
            })?;
            let key = row.get::<String, _>("device_public_key");
            if key != chain_public_key {
                return Err(ApiError::invalid_signature(format!(
                    "Device {} does not use the chain public key",
                    record.device_id
                )));
            }
            public_keys.insert(record.device_id.clone(), key.clone());
            key
        };

        let value = serde_json::to_value(record)
            .map_err(|error| ApiError::bad_request(error.to_string()))?;
        let valid = verify_signed_json(&public_key, &record.signature, &value)
            .map_err(ApiError::bad_request)?;
        if !valid {
            return Err(ApiError::invalid_signature(format!(
                "Invalid signature for record {}",
                record.record_id
            )));
        }
    }

    let mut tx = state.pool.begin().await.map_err(ApiError::database)?;
    if is_deleted_in_transaction(&mut tx, &chain_id).await? {
        return Err(ApiError::gone());
    }
    for record in records {
        sqlx::query(
            "INSERT OR IGNORE INTO sync_records (\
                chain_id, record_id, collection_name, action, encrypted_payload,\
                device_id, created_at_ms, signature\
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&chain_id)
        .bind(&record.record_id)
        .bind(&record.collection_name)
        .bind(&record.action)
        .bind(&record.encrypted_payload)
        .bind(&record.device_id)
        .bind(record.created_at_ms)
        .bind(&record.signature)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::database)?;
    }
    tx.commit().await.map_err(ApiError::database)?;

    Ok(StatusCode::OK)
}

pub async fn get_records(
    State(state): State<DbState>,
    Path(chain_id): Path<String>,
    query: Result<Query<RecordQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|error| ApiError::bad_request(error.body_text()))?;
    validate_chain_id(&chain_id)?;
    ensure_not_deleted(&state, &chain_id).await?;
    if query.after_seq.is_some() && query.since_ms.is_some() {
        return Err(ApiError::bad_request(
            "after_seq and since_ms cannot be specified together",
        ));
    }
    if query.limit.is_some() && query.after_seq.is_none() {
        return Err(ApiError::bad_request(
            "limit can only be specified together with after_seq",
        ));
    }
    if query.after_seq.unwrap_or(0) < 0 || query.since_ms.unwrap_or(0) < 0 {
        return Err(ApiError::bad_request("Cursors must not be negative"));
    }
    if let Some(limit) = query.limit {
        if limit == 0 || limit > MAX_PAGE_LIMIT {
            return Err(ApiError::bad_request(format!(
                "limit must be between 1 and {MAX_PAGE_LIMIT}"
            )));
        }
    }

    let (records, next_seq, has_more) = if query.after_seq.is_none() {
        // Preserve the existing v2 timestamp endpoint exactly for old clients.
        // An omitted since_ms historically meant since_ms=0 and returned the
        // complete raw array, so query-less old clients must remain unlimited.
        // New clients explicitly send after_seq, which is immune to delayed arrivals.
        let since_ms = query.since_ms.unwrap_or(0);
        let rows = sqlx::query(
            "SELECT relay_seq, record_id, collection_name, action, encrypted_payload, \
                    device_id, created_at_ms, signature \
             FROM sync_records \
             WHERE chain_id = ? AND created_at_ms > ? \
             ORDER BY created_at_ms ASC, relay_seq ASC",
        )
        .bind(&chain_id)
        .bind(since_ms)
        .fetch_all(&state.pool)
        .await
        .map_err(ApiError::database)?;
        records_from_rows(rows, &chain_id, 0, PageLimit::Unlimited)?
    } else {
        let after_seq = query.after_seq.expect("checked as present above");
        let limit = query.limit.unwrap_or(DEFAULT_PAGE_LIMIT) as usize;
        let rows = sqlx::query(
            "SELECT relay_seq, record_id, collection_name, action, encrypted_payload, \
                    device_id, created_at_ms, signature \
             FROM sync_records \
             WHERE chain_id = ? AND relay_seq > ? \
             ORDER BY relay_seq ASC LIMIT ?",
        )
        .bind(&chain_id)
        .bind(after_seq)
        .bind((limit + 1) as i64)
        .fetch_all(&state.pool)
        .await
        .map_err(ApiError::database)?;
        records_from_rows(rows, &chain_id, after_seq, PageLimit::Limited(limit))?
    };

    info!(
        chain = %short_id(&chain_id),
        count = records.len(),
        next_seq,
        has_more,
        "returning sync records"
    );
    if query.after_seq.is_some() {
        Ok(paged_vendor_json(records, next_seq, has_more))
    } else {
        Ok(vendor_json(records))
    }
}

fn records_from_rows(
    mut rows: Vec<sqlx::sqlite::SqliteRow>,
    chain_id: &str,
    fallback_seq: i64,
    page_limit: PageLimit,
) -> Result<(Vec<SyncRecord>, i64, bool), ApiError> {
    let has_more = match page_limit {
        PageLimit::Unlimited => false,
        PageLimit::Limited(limit) => rows.len() > limit,
    };
    if let PageLimit::Limited(limit) = page_limit {
        rows.truncate(limit);
    }

    let mut next_seq = fallback_seq;
    let mut records = Vec::with_capacity(rows.len());
    for row in rows {
        let relay_seq = row.get::<i64, _>("relay_seq");
        next_seq = next_seq.max(relay_seq);
        records.push(SyncRecord {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: chain_id.to_string(),
            record_id: row.get("record_id"),
            collection_name: row.get("collection_name"),
            action: row.get("action"),
            encrypted_payload: row.get("encrypted_payload"),
            device_id: row.get("device_id"),
            created_at_ms: row.get("created_at_ms"),
            signature: row.get("signature"),
        });
    }
    Ok((records, next_seq, has_more))
}

#[derive(Clone, Copy)]
enum PageLimit {
    Unlimited,
    Limited(usize),
}

pub async fn post_devices(
    State(state): State<DbState>,
    Path(chain_id): Path<String>,
    payload: Result<Json<DeviceRecord>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    validate_chain_id(&chain_id)?;
    ensure_not_deleted(&state, &chain_id).await?;
    let Json(device) = payload.map_err(|error| ApiError::bad_request(error.body_text()))?;
    validate_device_record(&device, &chain_id)?;

    let value =
        serde_json::to_value(&device).map_err(|error| ApiError::bad_request(error.to_string()))?;
    let valid = verify_signed_json(&device.device_public_key, &device.signature, &value)
        .map_err(ApiError::bad_request)?;
    if !valid {
        return Err(ApiError::invalid_signature("Invalid device self-signature"));
    }

    let mut tx = state.pool.begin().await.map_err(ApiError::database)?;
    if is_deleted_in_transaction(&mut tx, &chain_id).await? {
        return Err(ApiError::gone());
    }
    let chain_public_key =
        sqlx::query("SELECT device_public_key FROM chain_public_keys WHERE chain_id = ?")
            .bind(&chain_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(ApiError::database)?
            .map(|row| row.get::<String, _>("device_public_key"));
    if let Some(chain_public_key) = chain_public_key {
        if chain_public_key != device.device_public_key {
            return Err(ApiError::invalid_signature(
                "Device public key does not match the chain public key",
            ));
        }
    } else {
        sqlx::query("INSERT INTO chain_public_keys (chain_id, device_public_key) VALUES (?, ?)")
            .bind(&chain_id)
            .bind(&device.device_public_key)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::database)?;
    }

    sqlx::query(
        "INSERT INTO device_records (\
            chain_id, device_id, encrypted_device_name, device_public_key, created_at_ms, signature\
         ) VALUES (?, ?, ?, ?, ?, ?) \
         ON CONFLICT(chain_id, device_id) DO UPDATE SET \
            encrypted_device_name = excluded.encrypted_device_name, \
            device_public_key = excluded.device_public_key, \
            created_at_ms = excluded.created_at_ms, \
            signature = excluded.signature",
    )
    .bind(&chain_id)
    .bind(&device.device_id)
    .bind(&device.encrypted_device_name)
    .bind(&device.device_public_key)
    .bind(device.created_at_ms)
    .bind(&device.signature)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::database)?;
    tx.commit().await.map_err(ApiError::database)?;

    info!(chain = %short_id(&chain_id), device = %device.device_id, "registered device");
    Ok(StatusCode::OK)
}

pub async fn get_devices(
    State(state): State<DbState>,
    Path(chain_id): Path<String>,
) -> Result<Response, ApiError> {
    validate_chain_id(&chain_id)?;
    ensure_not_deleted(&state, &chain_id).await?;
    let rows = sqlx::query(
        "SELECT device_id, encrypted_device_name, device_public_key, created_at_ms, signature \
         FROM device_records WHERE chain_id = ? ORDER BY created_at_ms ASC, device_id ASC",
    )
    .bind(&chain_id)
    .fetch_all(&state.pool)
    .await
    .map_err(ApiError::database)?;

    let devices = rows
        .into_iter()
        .map(|row| DeviceRecord {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: chain_id.clone(),
            device_id: row.get("device_id"),
            encrypted_device_name: row.get("encrypted_device_name"),
            device_public_key: row.get("device_public_key"),
            created_at_ms: row.get("created_at_ms"),
            signature: row.get("signature"),
        })
        .collect::<Vec<_>>();

    Ok(vendor_json(devices))
}

pub async fn delete_chain(
    State(state): State<DbState>,
    Path(chain_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    validate_chain_id(&chain_id)?;
    ensure_not_deleted(&state, &chain_id).await?;
    info!(chain = %short_id(&chain_id), "deleting chain");

    let mut tx = state.pool.begin().await.map_err(ApiError::database)?;
    let now = chrono::Utc::now().timestamp_millis();
    sqlx::query("INSERT INTO deleted_chains (chain_id, deleted_at_ms) VALUES (?, ?)")
        .bind(&chain_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::database)?;
    sqlx::query("DELETE FROM sync_records WHERE chain_id = ?")
        .bind(&chain_id)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::database)?;
    sqlx::query("DELETE FROM device_records WHERE chain_id = ?")
        .bind(&chain_id)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::database)?;
    tx.commit().await.map_err(ApiError::database)?;

    Ok(StatusCode::OK)
}

async fn ensure_not_deleted(state: &DbState, chain_id: &str) -> Result<(), ApiError> {
    let deleted = sqlx::query("SELECT 1 FROM deleted_chains WHERE chain_id = ?")
        .bind(chain_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(ApiError::database)?
        .is_some();
    if deleted {
        warn!(chain = %short_id(chain_id), "request for deleted chain");
        Err(ApiError::gone())
    } else {
        Ok(())
    }
}

async fn is_deleted_in_transaction(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    chain_id: &str,
) -> Result<bool, ApiError> {
    Ok(
        sqlx::query("SELECT 1 FROM deleted_chains WHERE chain_id = ?")
            .bind(chain_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(ApiError::database)?
            .is_some(),
    )
}

fn validate_sync_record(record: &SyncRecord, path_chain_id: &str) -> Result<(), ApiError> {
    validate_protocol_and_chain(&record.protocol_version, &record.chain_id, path_chain_id)?;
    validate_uuid("record_id", &record.record_id)?;
    validate_uuid("device_id", &record.device_id)?;
    if record.collection_name.is_empty() || record.collection_name.len() > 128 {
        return Err(ApiError::bad_request(
            "collection_name must contain between 1 and 128 bytes",
        ));
    }
    if record.action != "upsert" && record.action != "delete" {
        return Err(ApiError::bad_request("action must be upsert or delete"));
    }
    if record.created_at_ms < 0 {
        return Err(ApiError::bad_request("created_at_ms must not be negative"));
    }
    validate_base64url(
        "encrypted_payload",
        &record.encrypted_payload,
        Some(16),
        Some(MAX_CIPHERTEXT_BYTES),
    )?;
    validate_base64url("signature", &record.signature, Some(64), Some(64))?;
    Ok(())
}

fn validate_device_record(record: &DeviceRecord, path_chain_id: &str) -> Result<(), ApiError> {
    validate_protocol_and_chain(&record.protocol_version, &record.chain_id, path_chain_id)?;
    validate_uuid("device_id", &record.device_id)?;
    if record.created_at_ms < 0 {
        return Err(ApiError::bad_request("created_at_ms must not be negative"));
    }
    validate_base64url(
        "encrypted_device_name",
        &record.encrypted_device_name,
        Some(16),
        Some(64 * 1024),
    )?;
    validate_base64url(
        "device_public_key",
        &record.device_public_key,
        Some(32),
        Some(32),
    )?;
    validate_base64url("signature", &record.signature, Some(64), Some(64))?;
    Ok(())
}

fn validate_protocol_and_chain(
    protocol_version: &str,
    body_chain_id: &str,
    path_chain_id: &str,
) -> Result<(), ApiError> {
    if protocol_version != PROTOCOL_VERSION {
        return Err(ApiError::bad_request("protocol_version must be 2.0"));
    }
    if body_chain_id != path_chain_id {
        return Err(ApiError::bad_request(
            "chain_id in the path and body must match",
        ));
    }
    Ok(())
}

fn validate_chain_id(chain_id: &str) -> Result<(), ApiError> {
    validate_base64url("chain_id", chain_id, Some(32), Some(32))
}

fn validate_uuid(name: &str, value: &str) -> Result<(), ApiError> {
    let uuid = Uuid::parse_str(value)
        .map_err(|_| ApiError::bad_request(format!("{name} must be a UUID")))?;
    if uuid.to_string() != value.to_ascii_lowercase() {
        return Err(ApiError::bad_request(format!(
            "{name} must use canonical hyphenated UUID form"
        )));
    }
    Ok(())
}

fn validate_base64url(
    name: &str,
    value: &str,
    min_decoded_len: Option<usize>,
    max_decoded_len: Option<usize>,
) -> Result<(), ApiError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ApiError::bad_request(format!("{name} must be unpadded Base64URL")))?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(ApiError::bad_request(format!(
            "{name} must use canonical unpadded Base64URL"
        )));
    }
    if min_decoded_len.is_some_and(|minimum| decoded.len() < minimum)
        || max_decoded_len.is_some_and(|maximum| decoded.len() > maximum)
    {
        let expected = match (min_decoded_len, max_decoded_len) {
            (Some(minimum), Some(maximum)) if minimum == maximum => {
                format!("exactly {minimum}")
            }
            (Some(minimum), Some(maximum)) => format!("between {minimum} and {maximum}"),
            (Some(minimum), None) => format!("at least {minimum}"),
            (None, Some(maximum)) => format!("at most {maximum}"),
            (None, None) => "a valid number of".to_string(),
        };
        return Err(ApiError::bad_request(format!(
            "{name} must decode to {expected} bytes"
        )));
    }
    Ok(())
}

fn vendor_json<T: Serialize>(value: T) -> Response {
    let mut response = Json(value).into_response();
    set_vendor_content_type(&mut response);
    response
}

fn paged_vendor_json<T: Serialize>(value: T, next_seq: i64, has_more: bool) -> Response {
    let mut response = vendor_json(value);
    response.headers_mut().insert(
        NEXT_SEQ_HEADER.clone(),
        HeaderValue::from_str(&next_seq.to_string()).expect("i64 is always a header-safe value"),
    );
    response.headers_mut().insert(
        HAS_MORE_HEADER.clone(),
        HeaderValue::from_static(if has_more { "true" } else { "false" }),
    );
    response
}

fn set_vendor_content_type(response: &mut Response) {
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(VENDOR_MEDIA_TYPE));
}

fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}
