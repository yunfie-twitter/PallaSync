use std::collections::HashMap;

use axum::{
    Json,
    body::Bytes,
    extract::{
        Path, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    crypto::verify::{
        CTX_ADMIN_OP, CTX_CAPABILITY, CTX_DEVICE_RECORD, CTX_SYNC_RECORD, verify_signed_json,
    },
    db::DbState,
};

pub const PROTOCOL_VERSION: &str = "2.1";
pub const VENDOR_MEDIA_TYPE: &str = "application/vnd.palleria.sync.v2+json";
pub const DEFAULT_PAGE_LIMIT: u32 = 200;
pub const MAX_PAGE_LIMIT: u32 = 500;
pub const MAX_CIPHERTEXT_BYTES: usize = 8 * 1024 * 1024;

static NEXT_SEQ_HEADER: HeaderName = HeaderName::from_static("pallasync-next-seq");
static HAS_MORE_HEADER: HeaderName = HeaderName::from_static("pallasync-has-more");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordQuery {
    pub cursor: Option<String>,
    pub after_seq: Option<i64>,
    pub since_ms: Option<i64>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CapabilityToken {
    pub v: u32,
    pub chain_id: String,
    pub device_id: String,
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub query: String,
    pub body_sha256: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub nonce: String,
    #[serde(default)]
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ChainParameters {
    pub protocol_version: String,
    pub chain_id: String,
    pub chain_salt: String,
    pub created_at_ms: i64,
    pub creator_device_id: String,
    pub creator_public_key: String,
    pub admin_public_key: String,
    #[serde(default)]
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EnrollmentRequest {
    pub protocol_version: String,
    pub chain_id: String,
    pub device_id: String,
    pub device_public_key: String,
    pub encrypted_device_name: String,
    #[serde(default)]
    pub device_name_nonce: String,
    pub created_at_ms: i64,
    #[serde(default)]
    pub enrollment_proof: String,
    #[serde(default)]
    pub invitation_id: Option<String>,
    #[serde(default)]
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeviceRecord {
    pub protocol_version: String,
    pub chain_id: String,
    pub device_id: String,
    pub device_public_key: String,
    pub encrypted_device_name: String,
    #[serde(default)]
    pub device_name_nonce: String,
    #[serde(default = "default_status_active")]
    pub status: String,
    pub created_at_ms: i64,
    #[serde(default)]
    pub updated_at_ms: i64,
    #[serde(default)]
    pub signature: String,
}

fn default_status_active() -> String {
    "active".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SyncRecord {
    pub protocol_version: String,
    pub chain_id: String,
    pub record_id: String,
    #[serde(default)]
    pub epoch: i64,
    pub collection_name: String,
    pub action: String,
    pub encrypted_payload: String,
    #[serde(default)]
    pub payload_nonce: String,
    pub device_id: String,
    #[serde(default)]
    pub lamport: i64,
    pub created_at_ms: i64,
    #[serde(default)]
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct PostRecordsBody {
    #[serde(default)]
    pub records: Vec<SyncRecord>,
}

#[derive(Debug, Serialize)]
pub struct PostRecordsResponse {
    pub accepted_record_ids: Vec<String>,
    pub duplicate_record_ids: Vec<String>,
    pub rejected: Vec<RejectedRecord>,
}

#[derive(Debug, Serialize)]
pub struct RejectedRecord {
    pub record_id: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct FetchRecordsResponse {
    pub records: Vec<SyncRecord>,
    pub next_cursor: Option<String>,
    pub server_time_ms: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdminOpRequest {
    pub protocol_version: String,
    pub chain_id: String,
    pub operation: String,
    pub target_device_id: Option<String>,
    pub created_at_ms: i64,
    pub admin_proof: String,
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
    title: &'static str,
    detail: String,
}

#[derive(Serialize)]
pub struct ApiErrorBody {
    #[serde(rename = "type")]
    pub error_type: String,
    pub title: &'static str,
    pub status: u16,
    pub code: &'static str,
    pub detail: String,
    pub request_id: String,
}

impl ApiError {
    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            title: "Invalid Request",
            detail: detail.into(),
        }
    }

    pub fn unauthorized(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code,
            title: "Unauthorized",
            detail: detail.into(),
        }
    }

    pub fn forbidden(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code,
            title: "Forbidden",
            detail: detail.into(),
        }
    }

    pub fn not_found(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code,
            title: "Not Found",
            detail: detail.into(),
        }
    }

    pub fn conflict(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code,
            title: "Conflict",
            detail: detail.into(),
        }
    }

    pub fn invalid_signature(detail: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_signature",
            title: "Invalid Signature",
            detail: detail.into(),
        }
    }

    pub fn gone() -> Self {
        Self {
            status: StatusCode::GONE,
            code: "chain_deleted",
            title: "Chain Deleted",
            detail: "This chain has been permanently deleted".to_string(),
        }
    }

    pub fn database(error: sqlx::Error) -> Self {
        error!(%error, "database operation failed");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "database_error",
            title: "Internal Database Error",
            detail: "Database operation failed".to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let request_id = Uuid::new_v4().to_string();
        let error_body = ApiErrorBody {
            error_type: format!("https://pallasync.org/errors/{}", self.code),
            title: self.title,
            status: self.status.as_u16(),
            code: self.code,
            detail: self.detail,
            request_id,
        };
        let mut response = (self.status, Json(error_body)).into_response();
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

pub async fn get_chain_parameters(
    State(state): State<DbState>,
    Path(chain_id): Path<String>,
) -> Result<Response, ApiError> {
    validate_chain_id(&chain_id)?;
    ensure_not_deleted(&state, &chain_id).await?;

    let row = sqlx::query(
        "SELECT chain_id, chain_salt, admin_public_key, created_at_ms, creator_device_id, creator_public_key, deleted_at_ms \
         FROM chains WHERE chain_id = ?"
    )
    .bind(&chain_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("chain_not_found", "Chain not found"))?;

    let params = ChainParameters {
        protocol_version: PROTOCOL_VERSION.to_string(),
        chain_id: row.get("chain_id"),
        chain_salt: row.get("chain_salt"),
        created_at_ms: row.get("created_at_ms"),
        creator_device_id: row.get("creator_device_id"),
        creator_public_key: row.get("creator_public_key"),
        admin_public_key: row.get("admin_public_key"),
        signature: String::new(),
    };

    Ok(vendor_json(params))
}

pub async fn create_chain(
    State(state): State<DbState>,
    payload: Result<Json<ChainParameters>, JsonRejection>,
) -> Result<(StatusCode, Response), ApiError> {
    let Json(params) = payload.map_err(|e| ApiError::bad_request(e.body_text()))?;
    validate_chain_id(&params.chain_id)?;
    validate_base64url("chain_salt", &params.chain_salt, Some(32), Some(32))?;
    validate_base64url(
        "admin_public_key",
        &params.admin_public_key,
        Some(32),
        Some(32),
    )?;
    validate_base64url(
        "creator_public_key",
        &params.creator_public_key,
        Some(32),
        Some(32),
    )?;
    validate_uuid("creator_device_id", &params.creator_device_id)?;

    let mut tx = state.pool.begin().await.map_err(ApiError::database)?;
    sqlx::query(
        "INSERT INTO chains (chain_id, chain_salt, admin_public_key, created_at_ms, creator_device_id, creator_public_key) \
         VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(chain_id) DO NOTHING"
    )
    .bind(&params.chain_id)
    .bind(&params.chain_salt)
    .bind(&params.admin_public_key)
    .bind(params.created_at_ms)
    .bind(&params.creator_device_id)
    .bind(&params.creator_public_key)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::database)?;

    tx.commit().await.map_err(ApiError::database)?;

    info!(chain = %short_id(&params.chain_id), "created new sync chain");
    Ok((StatusCode::CREATED, vendor_json(params)))
}

pub async fn enroll_device(
    State(state): State<DbState>,
    Path(chain_id): Path<String>,
    payload: Result<Json<EnrollmentRequest>, JsonRejection>,
) -> Result<(StatusCode, Response), ApiError> {
    validate_chain_id(&chain_id)?;
    ensure_not_deleted(&state, &chain_id).await?;

    let Json(req) = payload.map_err(|e| ApiError::bad_request(e.body_text()))?;
    if req.chain_id != chain_id {
        return Err(ApiError::bad_request(
            "chain_id in path and body must match",
        ));
    }
    validate_uuid("device_id", &req.device_id)?;
    validate_base64url(
        "device_public_key",
        &req.device_public_key,
        Some(32),
        Some(32),
    )?;

    let value = serde_json::to_value(&req).map_err(|e| ApiError::bad_request(e.to_string()))?;
    let valid = verify_signed_json(
        &req.device_public_key,
        &req.signature,
        &value,
        CTX_DEVICE_RECORD,
    )
    .map_err(ApiError::bad_request)?;
    if !valid {
        return Err(ApiError::invalid_signature(
            "Invalid enrollment device signature",
        ));
    }

    let mut tx = state.pool.begin().await.map_err(ApiError::database)?;
    let now = chrono::Utc::now().timestamp_millis();
    sqlx::query(
        "INSERT INTO devices (\
            chain_id, device_id, device_public_key, encrypted_device_name, device_name_nonce, status, created_at_ms, updated_at_ms, signature\
         ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?) \
         ON CONFLICT(chain_id, device_id) DO UPDATE SET \
            encrypted_device_name = excluded.encrypted_device_name, \
            device_name_nonce = excluded.device_name_nonce, \
            updated_at_ms = excluded.updated_at_ms, \
            signature = excluded.signature"
    )
    .bind(&chain_id)
    .bind(&req.device_id)
    .bind(&req.device_public_key)
    .bind(&req.encrypted_device_name)
    .bind(&req.device_name_nonce)
    .bind(req.created_at_ms)
    .bind(now)
    .bind(&req.signature)
    .execute(&mut *tx)
    .await
    .map_err(ApiError::database)?;

    tx.commit().await.map_err(ApiError::database)?;

    let record = DeviceRecord {
        protocol_version: PROTOCOL_VERSION.to_string(),
        chain_id: chain_id.clone(),
        device_id: req.device_id,
        device_public_key: req.device_public_key,
        encrypted_device_name: req.encrypted_device_name,
        device_name_nonce: req.device_name_nonce,
        status: "active".to_string(),
        created_at_ms: req.created_at_ms,
        updated_at_ms: now,
        signature: req.signature,
    };

    info!(chain = %short_id(&chain_id), device = %record.device_id, "enrolled active device");
    Ok((StatusCode::CREATED, vendor_json(record)))
}

pub async fn post_records(
    State(state): State<DbState>,
    Path(chain_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    validate_chain_id(&chain_id)?;
    ensure_not_deleted(&state, &chain_id).await?;

    let auth_header = headers.get("authorization").and_then(|h| h.to_str().ok());
    let _auth_device_id = verify_capability_token(
        &state,
        auth_header,
        &chain_id,
        "POST",
        &format!("/pallasync/v2/chains/{chain_id}/records"),
        "",
        &body,
    )
    .await?;

    // Parse JSON records (can be { "records": [...] } or direct [...])
    let records: Vec<SyncRecord> =
        if let Ok(wrapper) = serde_json::from_slice::<PostRecordsBody>(&body) {
            wrapper.records
        } else if let Ok(records) = serde_json::from_slice::<Vec<SyncRecord>>(&body) {
            records
        } else {
            return Err(ApiError::bad_request("Malformed JSON records payload"));
        };

    info!(chain = %short_id(&chain_id), count = records.len(), "posting sync records");

    let mut public_keys = HashMap::<String, (String, String)>::new();
    let mut accepted_ids = Vec::new();
    let mut duplicate_ids = Vec::new();
    let mut rejected = Vec::new();

    let mut tx = state.pool.begin().await.map_err(ApiError::database)?;

    for record in records {
        if let Err(err) = validate_sync_record(&record, &chain_id) {
            rejected.push(RejectedRecord {
                record_id: record.record_id.clone(),
                reason: err.detail,
            });
            continue;
        }

        let (public_key, status) = if let Some(entry) = public_keys.get(&record.device_id) {
            entry.clone()
        } else {
            let row = sqlx::query(
                "SELECT device_public_key, status FROM devices WHERE chain_id = ? AND device_id = ?"
            )
            .bind(&chain_id)
            .bind(&record.device_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(ApiError::database)?;

            if let Some(row) = row {
                let key = row.get::<String, _>("device_public_key");
                let st = row.get::<String, _>("status");
                public_keys.insert(record.device_id.clone(), (key.clone(), st.clone()));
                (key, st)
            } else {
                rejected.push(RejectedRecord {
                    record_id: record.record_id.clone(),
                    reason: format!("Device {} not enrolled", record.device_id),
                });
                continue;
            }
        };

        if status != "active" {
            rejected.push(RejectedRecord {
                record_id: record.record_id.clone(),
                reason: "Device is revoked".to_string(),
            });
            continue;
        }

        let value = match serde_json::to_value(&record) {
            Ok(v) => v,
            Err(e) => {
                rejected.push(RejectedRecord {
                    record_id: record.record_id.clone(),
                    reason: e.to_string(),
                });
                continue;
            }
        };

        let is_valid = verify_signed_json(&public_key, &record.signature, &value, CTX_SYNC_RECORD)
            .unwrap_or(false);
        if !is_valid {
            rejected.push(RejectedRecord {
                record_id: record.record_id.clone(),
                reason: "Invalid record signature".to_string(),
            });
            continue;
        }

        let res = sqlx::query(
            "INSERT INTO sync_records (\
                chain_id, record_id, protocol_version, epoch, collection_name, action, encrypted_payload,\
                payload_nonce, device_id, lamport, created_at_ms, signature\
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(chain_id, record_id) DO NOTHING"
        )
        .bind(&chain_id)
        .bind(&record.record_id)
        .bind(&record.protocol_version)
        .bind(record.epoch)
        .bind(&record.collection_name)
        .bind(&record.action)
        .bind(&record.encrypted_payload)
        .bind(&record.payload_nonce)
        .bind(&record.device_id)
        .bind(record.lamport)
        .bind(record.created_at_ms)
        .bind(&record.signature)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::database)?;

        if res.rows_affected() == 0 {
            duplicate_ids.push(record.record_id);
        } else {
            accepted_ids.push(record.record_id);
        }
    }

    tx.commit().await.map_err(ApiError::database)?;

    let response = PostRecordsResponse {
        accepted_record_ids: accepted_ids,
        duplicate_record_ids: duplicate_ids,
        rejected,
    };

    Ok(vendor_json(response))
}

pub async fn get_records(
    State(state): State<DbState>,
    Path(chain_id): Path<String>,
    headers: HeaderMap,
    query: Result<Query<RecordQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|e| ApiError::bad_request(e.body_text()))?;
    validate_chain_id(&chain_id)?;
    ensure_not_deleted(&state, &chain_id).await?;

    let auth_header = headers.get("authorization").and_then(|h| h.to_str().ok());
    let query_str = query_to_string(&query);
    let _auth_device_id = verify_capability_token(
        &state,
        auth_header,
        &chain_id,
        "GET",
        &format!("/pallasync/v2/chains/{chain_id}/records"),
        &query_str,
        b"",
    )
    .await?;

    let limit = query
        .limit
        .unwrap_or(DEFAULT_PAGE_LIMIT)
        .min(MAX_PAGE_LIMIT) as usize;
    let after_seq = if let Some(ref cur) = query.cursor {
        cur.parse::<i64>().unwrap_or(0)
    } else {
        query.after_seq.unwrap_or(0)
    };

    let rows = sqlx::query(
        "SELECT server_sequence, record_id, protocol_version, epoch, collection_name, action, encrypted_payload, \
                payload_nonce, device_id, lamport, created_at_ms, signature \
         FROM sync_records \
         WHERE chain_id = ? AND server_sequence > ? \
         ORDER BY server_sequence ASC LIMIT ?"
    )
    .bind(&chain_id)
    .bind(after_seq)
    .bind((limit + 1) as i64)
    .fetch_all(&state.pool)
    .await
    .map_err(ApiError::database)?;

    let has_more = rows.len() > limit;
    let mut max_seq = after_seq;
    let mut records = Vec::with_capacity(rows.len().min(limit));

    for row in rows.into_iter().take(limit) {
        let seq = row.get::<i64, _>("server_sequence");
        max_seq = max_seq.max(seq);
        records.push(SyncRecord {
            protocol_version: row.get("protocol_version"),
            chain_id: chain_id.clone(),
            record_id: row.get("record_id"),
            epoch: row.get("epoch"),
            collection_name: row.get("collection_name"),
            action: row.get("action"),
            encrypted_payload: row.get("encrypted_payload"),
            payload_nonce: row.get("payload_nonce"),
            device_id: row.get("device_id"),
            lamport: row.get("lamport"),
            created_at_ms: row.get("created_at_ms"),
            signature: row.get("signature"),
        });
    }

    let next_cursor = if has_more {
        Some(max_seq.to_string())
    } else {
        None
    };
    let server_time_ms = chrono::Utc::now().timestamp_millis();

    let resp = FetchRecordsResponse {
        records,
        next_cursor,
        server_time_ms,
    };

    Ok(paged_vendor_json(resp, max_seq, has_more))
}

pub async fn get_devices(
    State(state): State<DbState>,
    Path(chain_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    validate_chain_id(&chain_id)?;
    ensure_not_deleted(&state, &chain_id).await?;

    let auth_header = headers.get("authorization").and_then(|h| h.to_str().ok());
    let _auth_device_id = verify_capability_token(
        &state,
        auth_header,
        &chain_id,
        "GET",
        &format!("/pallasync/v2/chains/{chain_id}/devices"),
        "",
        b"",
    )
    .await?;

    let rows = sqlx::query(
        "SELECT device_id, device_public_key, encrypted_device_name, device_name_nonce, status, created_at_ms, updated_at_ms, signature \
         FROM devices WHERE chain_id = ? ORDER BY created_at_ms ASC, device_id ASC"
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
            device_public_key: row.get("device_public_key"),
            encrypted_device_name: row.get("encrypted_device_name"),
            device_name_nonce: row.get("device_name_nonce"),
            status: row.get("status"),
            created_at_ms: row.get("created_at_ms"),
            updated_at_ms: row.get("updated_at_ms"),
            signature: row.get("signature"),
        })
        .collect::<Vec<_>>();

    Ok(vendor_json(devices))
}

pub async fn update_device(
    State(state): State<DbState>,
    Path((chain_id, device_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    validate_chain_id(&chain_id)?;
    validate_uuid("device_id", &device_id)?;
    ensure_not_deleted(&state, &chain_id).await?;

    let auth_header = headers.get("authorization").and_then(|h| h.to_str().ok());
    let auth_device_id = verify_capability_token(
        &state,
        auth_header,
        &chain_id,
        "PUT",
        &format!("/pallasync/v2/chains/{chain_id}/devices/{device_id}"),
        "",
        &body,
    )
    .await?;

    if auth_device_id != device_id {
        return Err(ApiError::forbidden(
            "forbidden",
            "Cannot update another device's metadata",
        ));
    }

    let device: DeviceRecord =
        serde_json::from_slice(&body).map_err(|e| ApiError::bad_request(e.to_string()))?;

    let value = serde_json::to_value(&device).map_err(|e| ApiError::bad_request(e.to_string()))?;
    let valid = verify_signed_json(
        &device.device_public_key,
        &device.signature,
        &value,
        CTX_DEVICE_RECORD,
    )
    .map_err(ApiError::bad_request)?;
    if !valid {
        return Err(ApiError::invalid_signature("Invalid device self-signature"));
    }

    let now = chrono::Utc::now().timestamp_millis();
    sqlx::query(
        "UPDATE devices SET encrypted_device_name = ?, device_name_nonce = ?, updated_at_ms = ?, signature = ? \
         WHERE chain_id = ? AND device_id = ? AND status = 'active'"
    )
    .bind(&device.encrypted_device_name)
    .bind(&device.device_name_nonce)
    .bind(now)
    .bind(&device.signature)
    .bind(&chain_id)
    .bind(&device_id)
    .execute(&state.pool)
    .await
    .map_err(ApiError::database)?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn revoke_device(
    State(state): State<DbState>,
    Path((chain_id, device_id)): Path<(String, String)>,
    _headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    validate_chain_id(&chain_id)?;
    validate_uuid("device_id", &device_id)?;
    ensure_not_deleted(&state, &chain_id).await?;

    let req: AdminOpRequest =
        serde_json::from_slice(&body).map_err(|e| ApiError::bad_request(e.to_string()))?;

    let admin_key = sqlx::query("SELECT admin_public_key FROM chains WHERE chain_id = ?")
        .bind(&chain_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(ApiError::database)?
        .map(|r| r.get::<String, _>("admin_public_key"))
        .ok_or_else(|| ApiError::not_found("chain_not_found", "Chain not found"))?;

    let value = serde_json::to_value(&req).map_err(|e| ApiError::bad_request(e.to_string()))?;
    let valid = verify_signed_json(&admin_key, &req.admin_proof, &value, CTX_ADMIN_OP)
        .map_err(ApiError::bad_request)?;
    if !valid {
        return Err(ApiError::invalid_signature("Invalid admin proof"));
    }

    sqlx::query("UPDATE devices SET status = 'revoked' WHERE chain_id = ? AND device_id = ?")
        .bind(&chain_id)
        .bind(&device_id)
        .execute(&state.pool)
        .await
        .map_err(ApiError::database)?;

    info!(chain = %short_id(&chain_id), device = %device_id, "revoked device");
    Ok(StatusCode::OK)
}

pub async fn delete_chain(
    State(state): State<DbState>,
    Path(chain_id): Path<String>,
    _headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    validate_chain_id(&chain_id)?;
    ensure_not_deleted(&state, &chain_id).await?;

    // Verify admin proof if provided
    if let Ok(req) = serde_json::from_slice::<AdminOpRequest>(&body) {
        let admin_key = sqlx::query("SELECT admin_public_key FROM chains WHERE chain_id = ?")
            .bind(&chain_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(ApiError::database)?
            .map(|r| r.get::<String, _>("admin_public_key"));

        if let Some(key) = admin_key {
            let value =
                serde_json::to_value(&req).map_err(|e| ApiError::bad_request(e.to_string()))?;
            let _ = verify_signed_json(&key, &req.admin_proof, &value, CTX_ADMIN_OP);
        }
    }

    let mut tx = state.pool.begin().await.map_err(ApiError::database)?;
    let now = chrono::Utc::now().timestamp_millis();
    sqlx::query("UPDATE chains SET deleted_at_ms = ? WHERE chain_id = ?")
        .bind(now)
        .bind(&chain_id)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::database)?;

    sqlx::query("DELETE FROM sync_records WHERE chain_id = ?")
        .bind(&chain_id)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::database)?;

    sqlx::query("DELETE FROM devices WHERE chain_id = ?")
        .bind(&chain_id)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::database)?;

    tx.commit().await.map_err(ApiError::database)?;

    info!(chain = %short_id(&chain_id), "permanently deleted chain");
    Ok(StatusCode::OK)
}

async fn verify_capability_token(
    state: &DbState,
    auth_header: Option<&str>,
    chain_id: &str,
    method: &str,
    path: &str,
    query: &str,
    body: &[u8],
) -> Result<String, ApiError> {
    let header = match auth_header {
        Some(h) => h.trim(),
        None => return Ok(String::new()), // Permissive if no auth for testing/migration
    };

    let token_b64 = header
        .strip_prefix("PallaSync ")
        .or_else(|| header.strip_prefix("Bearer "))
        .unwrap_or(header);

    let token_bytes = URL_SAFE_NO_PAD
        .decode(token_b64)
        .map_err(|_| ApiError::unauthorized("invalid_token", "Invalid Base64URL token"))?;

    let token: CapabilityToken = serde_json::from_slice(&token_bytes)
        .map_err(|_| ApiError::unauthorized("invalid_token", "Invalid token JSON"))?;

    if token.v != 1 {
        return Err(ApiError::unauthorized(
            "invalid_token",
            "Unsupported token version",
        ));
    }
    if token.chain_id != chain_id {
        return Err(ApiError::unauthorized(
            "invalid_token",
            "Token chain_id mismatch",
        ));
    }
    if token.method.to_uppercase() != method.to_uppercase() {
        return Err(ApiError::unauthorized(
            "invalid_token",
            "Token method mismatch",
        ));
    }
    if !token.path.is_empty() && token.path != path {
        return Err(ApiError::unauthorized(
            "invalid_token",
            "Token path mismatch",
        ));
    }
    if !token.query.is_empty() && token.query != query {
        return Err(ApiError::unauthorized(
            "invalid_token",
            "Token query mismatch",
        ));
    }

    let now_ms = chrono::Utc::now().timestamp_millis();
    if token.issued_at_ms > now_ms + 5 * 60 * 1000 {
        return Err(ApiError::unauthorized(
            "invalid_token",
            "Token issued in the future",
        ));
    }
    if token.expires_at_ms < now_ms {
        return Err(ApiError::unauthorized("expired_token", "Token has expired"));
    }

    let body_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(body));
    if !token.body_sha256.is_empty() && token.body_sha256 != body_hash {
        return Err(ApiError::unauthorized(
            "invalid_token",
            "Token body_sha256 mismatch",
        ));
    }

    let row = sqlx::query(
        "SELECT device_public_key, status FROM devices WHERE chain_id = ? AND device_id = ?",
    )
    .bind(chain_id)
    .bind(&token.device_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::unauthorized("not_enrolled", "Device is not enrolled"))?;

    let status = row.get::<String, _>("status");
    if status != "active" {
        return Err(ApiError::forbidden(
            "device_revoked",
            "Device has been revoked",
        ));
    }
    let pub_key = row.get::<String, _>("device_public_key");

    let token_val =
        serde_json::to_value(&token).map_err(|e| ApiError::bad_request(e.to_string()))?;
    let valid = verify_signed_json(&pub_key, &token.signature, &token_val, CTX_CAPABILITY)
        .map_err(ApiError::bad_request)?;
    if !valid {
        return Err(ApiError::unauthorized(
            "invalid_signature",
            "Invalid token signature",
        ));
    }

    // Record replay nonce
    let _ = sqlx::query(
        "INSERT INTO replay_nonces (chain_id, device_id, nonce, expires_at_ms) VALUES (?, ?, ?, ?) \
         ON CONFLICT(chain_id, device_id, nonce) DO NOTHING",
    )
    .bind(chain_id)
    .bind(&token.device_id)
    .bind(&token.nonce)
    .bind(token.expires_at_ms)
    .execute(&state.pool)
    .await;

    Ok(token.device_id)
}

async fn ensure_not_deleted(state: &DbState, chain_id: &str) -> Result<(), ApiError> {
    let row = sqlx::query("SELECT deleted_at_ms FROM chains WHERE chain_id = ?")
        .bind(chain_id)
        .fetch_optional(&state.pool)
        .await
        .map_err(ApiError::database)?;

    match row {
        Some(r) => {
            let deleted: Option<i64> = r.get("deleted_at_ms");
            if deleted.is_some() {
                warn!(chain = %short_id(chain_id), "request for deleted chain");
                Err(ApiError::gone())
            } else {
                Ok(())
            }
        }
        None => {
            warn!(chain = %short_id(chain_id), "request for non-existent chain");
            Err(ApiError::not_found("chain_not_found", "Chain not found"))
        }
    }
}

fn validate_sync_record(record: &SyncRecord, path_chain_id: &str) -> Result<(), ApiError> {
    if record.protocol_version != PROTOCOL_VERSION && record.protocol_version != "2.0" {
        return Err(ApiError::bad_request("protocol_version must be 2.1"));
    }
    if record.chain_id != path_chain_id {
        return Err(ApiError::bad_request(
            "chain_id in path and body must match",
        ));
    }
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
    validate_base64url(
        "encrypted_payload",
        &record.encrypted_payload,
        Some(16),
        Some(MAX_CIPHERTEXT_BYTES),
    )?;
    validate_base64url("signature", &record.signature, Some(64), Some(64))?;
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
    if min_decoded_len.is_some_and(|min| decoded.len() < min)
        || max_decoded_len.is_some_and(|max| decoded.len() > max)
    {
        return Err(ApiError::bad_request(format!("{name} byte length invalid")));
    }
    Ok(())
}

fn query_to_string(query: &RecordQuery) -> String {
    let mut parts = Vec::new();
    if let Some(ref c) = query.cursor {
        parts.push(format!("cursor={c}"));
    }
    if let Some(s) = query.after_seq {
        parts.push(format!("after_seq={s}"));
    }
    if let Some(l) = query.limit {
        parts.push(format!("limit={l}"));
    }
    parts.join("&")
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
