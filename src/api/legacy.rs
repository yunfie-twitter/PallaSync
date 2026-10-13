//! §0 D-02 / §9: frozen legacy reads and explicit legacy deletion only.
//! These are separate v2.1 objects, never aliases or authority for v3. No E2EE decryption.
use super::{auth, error::now, sync::AppState, wire::canonical_query};
use crate::crypto::{jcs, verify::*};
use axum::{
    body::{Body, to_bytes},
    http::{Request, Response, StatusCode, header},
};
use serde_json::{Value, json};
use sqlx::{Row, SqliteConnection};
use std::{collections::BTreeMap, time::Duration};

const MEDIA: &str = "application/vnd.palleria.sync.v2+json";
const TOKEN_CONTEXT: &[u8] = b"PALLASYNC-CAPABILITY-v2.1\0";
type Result<T> = std::result::Result<T, StatusCode>;

pub fn is_legacy(path: &str) -> bool {
    path == "/health" || path.starts_with("/pallasync/v2/")
}

fn response(status: StatusCode, value: Option<Value>) -> Response<Body> {
    let bytes = match value {
        Some(value) => match jcs::canonicalize_json(&value) {
            Ok(bytes) => bytes,
            Err(_) => return response(StatusCode::INTERNAL_SERVER_ERROR, None),
        },
        None => Vec::new(),
    };
    let mut out = Response::builder()
        .status(status)
        .body(Body::from(bytes))
        .unwrap();
    out.headers_mut()
        .insert(header::CONTENT_TYPE, MEDIA.parse().unwrap());
    out.headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    out.headers_mut().insert(
        header::DATE,
        httpdate::fmt_http_date(std::time::SystemTime::now())
            .parse()
            .unwrap(),
    );
    if status == StatusCode::TOO_MANY_REQUESTS {
        out.headers_mut()
            .insert(header::RETRY_AFTER, "3600".parse().unwrap());
    }
    out
}

pub async fn handle(state: &AppState, request: Request<Body>) -> Response<Body> {
    match run(state, request).await {
        Ok(out) => out,
        // Legacy documents define no v3 typed-error catalogue; do not invent a legacy code/schema.
        Err(status) => response(status, None),
    }
}

async fn run(state: &AppState, request: Request<Body>) -> Result<Response<Body>> {
    let (parts, body) = request.into_parts();
    if !["GET", "DELETE"].contains(&parts.method.as_str()) {
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }
    let body = tokio::time::timeout(
        Duration::from_secs(30),
        to_bytes(
            body,
            state.config.limits()["max_request_bytes"].as_u64().unwrap() as usize,
        ),
    )
    .await
    .map_err(|_| StatusCode::REQUEST_TIMEOUT)?
    .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
    if !body.is_empty()
        || parts
            .headers
            .get(header::CONTENT_ENCODING)
            .is_some_and(|v| v != "identity")
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let path = parts.uri.path();
    let method = parts.method.as_str();
    if path.ends_with("/health") || path.ends_with("/parameters") {
        let source = parts
            .extensions
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|v| v.0.ip().to_string())
            .unwrap_or_else(|| "local".into());
        let mut tx = state
            .db
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let limited = auth::rate(
            &mut tx,
            &state.config,
            "public_document_ip",
            &hash_bytes(source.as_bytes()),
        )
        .await;
        tx.commit()
            .await
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        limited.map_err(|e| e.status())?;
    }
    let query =
        canonical_query(parts.uri.query().unwrap_or("")).map_err(|_| StatusCode::BAD_REQUEST)?;
    if path == "/health" || path == "/pallasync/v2/health" {
        if method != "GET" {
            return Err(StatusCode::METHOD_NOT_ALLOWED);
        }
        if !query.is_empty() {
            return Err(StatusCode::BAD_REQUEST);
        }
        return Ok(response(
            StatusCode::OK,
            Some(json!({"status":"ok","protocol_version":"2.1"})),
        ));
    }
    let pieces: Vec<_> = path
        .strip_prefix("/pallasync/v2/chains/")
        .ok_or(StatusCode::NOT_FOUND)?
        .split('/')
        .collect();
    let (chain, route) = match pieces.as_slice() {
        [chain, "parameters"] => (*chain, "parameters"),
        [chain, "devices"] => (*chain, "devices"),
        [chain, "records"] => (*chain, "records"),
        [chain] => (*chain, "delete"),
        _ => return Err(StatusCode::NOT_FOUND),
    };
    if (route == "delete" && method != "DELETE") || (route != "delete" && method != "GET") {
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }
    decode(chain, Some(32)).map_err(|_| StatusCode::BAD_REQUEST)?;
    let query: BTreeMap<_, _> = query.into_iter().collect();
    if route != "records" && !query.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if route == "records"
        && (query
            .keys()
            .any(|k| !["after_seq", "cursor", "limit"].contains(&k.as_str()))
            || (query.contains_key("after_seq") && query.contains_key("cursor")))
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut tx = state
        .db
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='chains'",
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if exists == 0 {
        return Err(StatusCode::NOT_FOUND);
    }
    let row = sqlx::query("SELECT deleted_at_ms FROM chains WHERE chain_id=?")
        .bind(chain)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        .ok_or(StatusCode::NOT_FOUND)?;
    if row.get::<Option<i64>, _>("deleted_at_ms").is_some() {
        return Err(StatusCode::GONE);
    }
    let out = if route == "parameters" {
        // The old implementation discarded this signature. Never synthesize an empty one.
        let raw: Option<String> =
            sqlx::query_scalar("SELECT signed_json FROM v2_parameter_evidence WHERE chain_id=?")
                .bind(chain)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let value = jcs::parse(check_original_parameters(chain, raw.as_deref())?.as_bytes())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        response(StatusCode::OK, Some(value))
    } else {
        let id = authenticate(&mut tx, chain, &parts).await?;
        auth::rate(
            &mut tx,
            &state.config,
            "authorized_signer",
            &hash_bytes(format!("legacy:{chain}:{id}").as_bytes()),
        )
        .await
        .map_err(|e| e.status())?;
        match route {
            "devices" => devices(&mut tx, chain).await?,
            "records" => {
                records(
                    &mut tx,
                    chain,
                    &query,
                    state.config.limits()["page_limit"].as_u64().unwrap(),
                    state.config.limits()["max_request_bytes"].as_u64().unwrap(),
                )
                .await?
            }
            "delete" => {
                // §9.4 requires a separate legacy user action. This touches no v3 table.
                for table in [
                    "sync_records",
                    "devices",
                    "replay_nonces",
                    "cursors",
                    "v2_parameter_evidence",
                ] {
                    sqlx::query(&format!("DELETE FROM {table} WHERE chain_id=?"))
                        .bind(chain)
                        .execute(&mut *tx)
                        .await
                        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                }
                sqlx::query(
                    "UPDATE chains SET deleted_at_ms=? WHERE chain_id=? AND deleted_at_ms IS NULL",
                )
                .bind(now() as i64)
                .bind(chain)
                .execute(&mut *tx)
                .await
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
                response(StatusCode::OK, None)
            }
            _ => unreachable!(),
        }
    };
    tx.commit()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(out)
}

fn check_original_parameters(chain: &str, raw: Option<&str>) -> Result<String> {
    let raw = raw.ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let value = jcs::parse(raw.as_bytes()).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if value["protocol_version"] != "2.1"
        || value["chain_id"] != chain
        || !value["signature"]
            .as_str()
            .is_some_and(|s| decode(s, Some(64)).is_ok())
    {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    // Bytes are archived public input, not a newly certified parameter object.
    Ok(raw.to_owned())
}

/// Offline operator restoration of original public bytes, not root signing or an HTTP import API.
/// The legacy signature context is unspecified in v2.1 §4.1; this is not certification.
pub async fn retain_parameters(
    db: &crate::db::DbState,
    raw: &[u8],
) -> std::result::Result<(), String> {
    let value = jcs::parse(raw).map_err(|_| "Invalid original legacy JSON")?;
    let fields = [
        "protocol_version",
        "chain_id",
        "chain_salt",
        "created_at_ms",
        "creator_device_id",
        "creator_public_key",
        "admin_public_key",
        "signature",
    ];
    let object = value
        .as_object()
        .ok_or("Legacy parameters must be an object")?;
    if object.len() != fields.len()
        || fields.iter().any(|k| !object.contains_key(*k))
        || value["protocol_version"] != "2.1"
    {
        return Err("Invalid original legacy parameter fields".into());
    }
    for field in [
        "chain_id",
        "chain_salt",
        "creator_public_key",
        "admin_public_key",
        "signature",
    ] {
        decode(
            value[field].as_str().ok_or("Invalid legacy binary field")?,
            Some(if field == "signature" { 64 } else { 32 }),
        )
        .map_err(|_| "Invalid legacy binary field")?;
    }
    let chain = value["chain_id"].as_str().ok_or("Missing legacy chain")?;
    if !value["creator_device_id"]
        .as_str()
        .is_some_and(|v| uuid::Uuid::parse_str(v).is_ok())
        || !value["created_at_ms"]
            .as_u64()
            .is_some_and(|v| v <= jcs::MAX_INTEGER)
    {
        return Err("Invalid legacy creator/time".into());
    }
    let mut tx = db
        .pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| "Legacy store unavailable")?;
    let row = sqlx::query("SELECT chain_salt,admin_public_key,created_at_ms,creator_device_id,creator_public_key,deleted_at_ms FROM chains WHERE chain_id=?")
        .bind(chain).fetch_optional(&mut *tx).await.map_err(|_| "Original legacy authority fields unavailable")?.ok_or("Original legacy chain not found")?;
    if row.get::<Option<i64>, _>("deleted_at_ms").is_some() {
        return Err("Cannot restore parameters of a deleted legacy chain".into());
    }
    for field in [
        "chain_salt",
        "admin_public_key",
        "creator_device_id",
        "creator_public_key",
    ] {
        if value[field] != row.get::<String, _>(field) {
            return Err("Original parameters conflict with preserved legacy authority".into());
        }
    }
    if value["created_at_ms"] != row.get::<i64, _>("created_at_ms") {
        return Err("Original creation time conflicts with preserved legacy authority".into());
    }
    let canonical =
        String::from_utf8(jcs::canonicalize_json(&value).map_err(|_| "Invalid legacy JSON")?)
            .map_err(|_| "Invalid legacy UTF-8")?;
    sqlx::query("INSERT INTO v2_parameter_evidence(chain_id,signed_json) VALUES(?,?) ON CONFLICT DO NOTHING").bind(chain).bind(&canonical).execute(&mut *tx).await.map_err(|_| "Legacy evidence unavailable")?;
    let saved: String =
        sqlx::query_scalar("SELECT signed_json FROM v2_parameter_evidence WHERE chain_id=?")
            .bind(chain)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| "Legacy evidence unavailable")?;
    if jcs::parse(saved.as_bytes()).ok().as_ref() != Some(&value) {
        return Err("Refusing to replace original legacy parameter evidence".into());
    }
    tx.commit()
        .await
        .map_err(|_| "Legacy evidence commit failed")?;
    Ok(())
}

async fn authenticate(
    db: &mut SqliteConnection,
    chain: &str,
    request: &axum::http::request::Parts,
) -> Result<String> {
    let raw = request
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("PallaSync "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let bytes = decode(raw, None).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let token = jcs::parse(&bytes).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let object = token.as_object().ok_or(StatusCode::UNAUTHORIZED)?;
    let fields = [
        "v",
        "chain_id",
        "device_id",
        "method",
        "path",
        "query",
        "body_sha256",
        "issued_at_ms",
        "expires_at_ms",
        "nonce",
        "signature",
    ];
    if object.len() != fields.len()
        || fields.iter().any(|k| !object.contains_key(*k))
        || token["v"] != 1
        || token["chain_id"] != chain
        || token["method"] != request.method.as_str()
        || token["path"] != request.uri.path()
        || token["query"] != request.uri.query().unwrap_or("")
        || token["body_sha256"] != hash_bytes(b"")
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let issued = token["issued_at_ms"]
        .as_u64()
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let expires = token["expires_at_ms"]
        .as_u64()
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if issued > now() || expires <= now() || expires <= issued || expires > jcs::MAX_INTEGER {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let id = token["device_id"]
        .as_str()
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let nonce = token["nonce"].as_str().ok_or(StatusCode::UNAUTHORIZED)?;
    decode(nonce, Some(16)).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let row = sqlx::query(
        "SELECT device_public_key,status FROM devices WHERE chain_id=? AND device_id=?",
    )
    .bind(chain)
    .bind(id)
    .fetch_optional(&mut *db)
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
    .ok_or(StatusCode::FORBIDDEN)?;
    if row.get::<String, _>("status") != "active" {
        return Err(StatusCode::FORBIDDEN);
    }
    if !verify_signed_json(
        &row.get::<String, _>("device_public_key"),
        token["signature"]
            .as_str()
            .ok_or(StatusCode::UNAUTHORIZED)?,
        &token,
        TOKEN_CONTEXT,
    )
    .unwrap_or(false)
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    sqlx::query("DELETE FROM replay_nonces WHERE expires_at_ms<=?")
        .bind(now() as i64)
        .execute(&mut *db)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let inserted = sqlx::query("INSERT INTO replay_nonces(chain_id,device_id,nonce,expires_at_ms) VALUES(?,?,?,?) ON CONFLICT DO NOTHING").bind(chain).bind(id).bind(nonce).bind(expires as i64).execute(db).await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if inserted.rows_affected() != 1 {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(id.to_owned())
}

async fn devices(db: &mut SqliteConnection, chain: &str) -> Result<Response<Body>> {
    let rows = sqlx::query("SELECT * FROM devices WHERE chain_id=? ORDER BY device_id")
        .bind(chain)
        .fetch_all(db)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let devices: Vec<Value> = rows.iter().map(|r| json!({"protocol_version":"2.1","chain_id":chain,"device_id":r.get::<String,_>("device_id"),"device_public_key":r.get::<String,_>("device_public_key"),"encrypted_device_name":r.get::<String,_>("encrypted_device_name"),"device_name_nonce":r.get::<String,_>("device_name_nonce"),"status":r.get::<String,_>("status"),"created_at_ms":r.get::<i64,_>("created_at_ms"),"updated_at_ms":r.get::<i64,_>("updated_at_ms"),"signature":r.get::<String,_>("signature")})).collect();
    Ok(response(
        StatusCode::OK,
        Some(json!({"devices":devices,"next_cursor":null})),
    ))
}

fn decimal(input: &str) -> Result<u64> {
    if input.is_empty() || !input.bytes().all(|b| b.is_ascii_digit()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    input
        .parse::<u64>()
        .ok()
        .filter(|n| *n <= jcs::MAX_INTEGER)
        .ok_or(StatusCode::BAD_REQUEST)
}

async fn records(
    db: &mut SqliteConnection,
    chain: &str,
    query: &BTreeMap<String, String>,
    maximum: u64,
    byte_limit: u64,
) -> Result<Response<Body>> {
    let after = decimal(
        query
            .get("cursor")
            .or_else(|| query.get("after_seq"))
            .map(String::as_str)
            .unwrap_or("0"),
    )?;
    let limit = decimal(query.get("limit").map(String::as_str).unwrap_or("200"))?;
    if limit == 0 || limit > maximum {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut records = Vec::new();
    let mut next = after;
    let mut used = 128u64; // Outer JSON/cursor/time and commas remain inside the signed operator byte limit.
    let more = loop {
        let meta = sqlx::query("SELECT server_sequence,length(CAST(encrypted_payload AS BLOB))+length(CAST(signature AS BLOB))+length(CAST(payload_nonce AS BLOB))+length(CAST(record_id AS BLOB))+length(CAST(device_id AS BLOB))+length(CAST(collection_name AS BLOB))+length(CAST(action AS BLOB))+length(CAST(protocol_version AS BLOB)) AS string_bytes FROM sync_records WHERE chain_id=? AND server_sequence>? ORDER BY server_sequence LIMIT 1")
            .bind(chain).bind(next as i64).fetch_optional(&mut *db).await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let Some(meta) = meta else {
            break false;
        };
        if records.len() == limit as usize {
            break true;
        }
        let bytes = meta
            .try_get::<i64, _>("string_bytes")
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if bytes < 0 || bytes as u64 > byte_limit.saturating_sub(used) {
            if records.is_empty() {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            break true;
        }
        let sequence = meta.get::<i64, _>("server_sequence");
        let row = sqlx::query("SELECT protocol_version,record_id,epoch,collection_name,action,encrypted_payload,payload_nonce,device_id,lamport,created_at_ms,signature,server_sequence FROM sync_records WHERE chain_id=? AND server_sequence=?")
            .bind(chain).bind(sequence).fetch_one(&mut *db).await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        let value = legacy_record(chain, &row)?;
        let bytes = jcs::canonicalize_json(&value)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .len() as u64
            + 1;
        if bytes > byte_limit.saturating_sub(used) {
            if records.is_empty() {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            break true;
        }
        used += bytes;
        next = sequence as u64;
        records.push(value);
    };
    let mut out = response(
        StatusCode::OK,
        Some(
            json!({"records":records,"next_cursor":if more {Some(next.to_string())} else {None},"server_time_ms":now()}),
        ),
    );
    out.headers_mut()
        .insert("pallasync-next-seq", next.to_string().parse().unwrap());
    out.headers_mut().insert(
        "pallasync-has-more",
        if more { "true" } else { "false" }.parse().unwrap(),
    );
    Ok(out)
}

fn legacy_record(chain: &str, row: &sqlx::sqlite::SqliteRow) -> Result<Value> {
    let mut value = json!({"chain_id":chain});
    for field in [
        "protocol_version",
        "record_id",
        "collection_name",
        "action",
        "encrypted_payload",
        "payload_nonce",
        "device_id",
        "signature",
    ] {
        value[field] = row
            .try_get::<String, _>(field)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .into();
    }
    for field in ["epoch", "lamport", "created_at_ms"] {
        value[field] = row
            .try_get::<i64, _>(field)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .into();
    }
    let sequence = row
        .try_get::<i64, _>("server_sequence")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    value["relay_seq"] = sequence.into();
    value["server_sequence"] = sequence.into();
    Ok(value)
}
