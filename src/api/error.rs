use axum::{
    Json,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

#[derive(Debug, Clone)]
pub struct ApiError {
    pub code: &'static str,
    pub context: Option<Value>,
}
pub type Result<T> = std::result::Result<T, ApiError>;
pub fn err(code: &'static str) -> ApiError {
    ApiError {
        code,
        context: None,
    }
}
pub fn now() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}
impl ApiError {
    pub fn context(mut self, v: Value) -> Self {
        self.context = Some(v);
        self
    }
    pub fn status(&self) -> StatusCode {
        StatusCode::from_u16(catalogue(self.code).0).unwrap()
    }
    pub fn retryable(&self) -> bool {
        catalogue(self.code).1
    }
}
fn catalogue(c: &str) -> (u16, bool) {
    match c {
        "INVALID_JSON" | "INVALID_FIELD" | "CURSOR_INVALID" | "FILTER_NOT_ALLOWED" => (400, false),
        "TOKEN_REQUIRED" | "TOKEN_NOT_YET_VALID" | "TOKEN_EXPIRED" | "TOKEN_REPLAYED" => {
            (401, true)
        }
        "TOKEN_TTL_TOO_LONG" | "TOKEN_SIGNATURE_INVALID" | "TOKEN_BINDING_MISMATCH" => (401, false),
        "ADMIN_REQUIRED"
        | "DEVICE_PENDING_KEYS"
        | "DEVICE_UNKNOWN"
        | "ENROLLMENT_NOT_ALLOWED"
        | "ROTATION_NOT_ALLOWED" => (403, true),
        "DEVICE_REVOKED" | "DEVICE_KEY_MISMATCH" | "ENVELOPE_ACCESS_DENIED" => (403, false),
        "ENDPOINT_NOT_FOUND" => (404, false),
        "CHAIN_NOT_FOUND"
        | "DEVICE_NOT_FOUND"
        | "EPOCH_NOT_FOUND"
        | "OFFER_NOT_FOUND"
        | "ENVELOPE_NOT_FOUND"
        | "SNAPSHOT_PART_NOT_FOUND"
        | "SNAPSHOT_NOT_FOUND"
        | "RECEIPT_NOT_FOUND" => (404, true),
        "METHOD_NOT_ALLOWED" => (405, false),
        "REQUEST_TIMEOUT" => (408, true),
        "CHAIN_EXISTS"
        | "RECORD_ID_CONFLICT"
        | "DEVICE_ID_CONFLICT"
        | "REQUEST_ID_CONFLICT"
        | "ENVELOPE_ID_CONFLICT"
        | "OPERATION_ID_CONFLICT"
        | "IMPORT_CONFLICT" => (409, false),
        "EPOCH_STALE"
        | "CAS_MISMATCH"
        | "GENERATION_MISMATCH"
        | "MEMBER_SET_MISMATCH"
        | "RECOVERY_ENVELOPE_REQUIRED"
        | "HISTORY_KEY_EXPIRED"
        | "CURSOR_EXPIRED"
        | "LOG_ID_MISMATCH"
        | "LOG_PRUNED"
        | "SNAPSHOT_INCOMPLETE"
        | "COMPACTION_UNSAFE"
        | "REPAIR_PROOF_REQUIRED"
        | "TRANSPARENCY_ID_MISMATCH"
        | "TRANSPARENCY_RANGE_UNAVAILABLE" => (409, true),
        "CHAIN_DELETED" => (410, false),
        "PAYLOAD_TOO_LARGE" | "DEVICE_LIMIT_REACHED" => (413, true),
        "UNSUPPORTED_MEDIA_TYPE" => (415, false),
        "OBJECT_SIGNATURE_INVALID" | "ENROLLMENT_CERTIFICATE_INVALID" | "EPOCH_CHAIN_INVALID" => {
            (422, false)
        }
        "RATE_LIMITED" => (429, true),
        "INTERNAL_ERROR" => (500, true),
        "BAD_GATEWAY" => (502, true),
        "RELAY_UNAVAILABLE" | "RELAY_SHUTTING_DOWN" => (503, true),
        "GATEWAY_TIMEOUT" => (504, true),
        "QUOTA_EXCEEDED" | "STORAGE_UNAVAILABLE" => (507, true),
        _ => unreachable!("uncatalogued protocol error: {c}"),
    }
}
impl From<sqlx::Error> for ApiError {
    fn from(_: sqlx::Error) -> Self {
        err("STORAGE_UNAVAILABLE")
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let mut body = json!({"type":"about:blank","title":status.canonical_reason().unwrap(),"status":status.as_u16(),"code":self.code,"retryable":self.retryable(),"server_time_ms":now()});
        if let Some(c) = &self.context {
            body["context"] = c.clone()
        }
        let mut response = (status, Json(body)).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/problem+json"),
        );
        if matches!(self.code, "RATE_LIMITED" | "TOKEN_NOT_YET_VALID") {
            let ms = self
                .context
                .as_ref()
                .and_then(|v| v["retry_after_ms"].as_u64())
                .unwrap_or(1000);
            response.headers_mut().insert(
                header::RETRY_AFTER,
                ((ms.div_ceil(1000)).clamp(1, 3600))
                    .to_string()
                    .parse()
                    .unwrap(),
            );
        }
        response
    }
}
