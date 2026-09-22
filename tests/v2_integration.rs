use std::{
    path::PathBuf,
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, Response, StatusCode, header::CONTENT_TYPE},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use pallasync_server::{
    api::sync::{DeviceRecord, FetchRecordsResponse, PostRecordsResponse, SyncRecord},
    app,
    crypto::verify::{CTX_DEVICE_RECORD, CTX_SYNC_RECORD, verify_signed_json},
    db::{DbState, init_db_with_url},
};
use serde::Serialize;
use serde_json::Value;
use sqlx::sqlite::SqliteConnectOptions;
use tower::ServiceExt;
use tower_http::cors::CorsLayer;
use uuid::Uuid;

static TEMP_DATABASE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestContext {
    state: DbState,
    router: Router,
    database_url: String,
    path: PathBuf,
    chain_id: String,
    device_id: String,
    signing_key: SigningKey,
}

#[test]
fn accepts_the_shared_deterministic_protocol_fixture_and_rejects_tampering() {
    const PUBLIC_KEY: &str = "EGN7bhOUo9Qo73SP4QKcp7Pl7c5odsgadc0qwRjh1os";
    const SIGNATURE: &str =
        "S-u3uQoeJRWBHXZwsw9PKYgo7B_IoiEx1HA3dt3n9deA3z188srUNeX9uTvNm-RjNCUZXATOVKUDx3e9zISWBg";
    const UNSIGNED_JCS: &str = r#"{"action":"upsert","chain_id":"1wMbwFYE4yTAUyAvlIGEtoGpw1y4o8HbtjQ54BRp-1s","collection_name":"palleria.favorite_tag/2","created_at_ms":1700000000123,"device_id":"018f0c2a-7b9d-7000-8000-000000000002","encrypted_payload":"A3sX-YzzsMeGgcIoCrlhOj1hMDzoOtkjg8LXM65FB2kmzfyVDmYavlLAQrG0tYCe9FoQobALFWVg64fUnw","protocol_version":"2.0","record_id":"018f0c2a-7b9d-7000-8000-000000000001"}"#;
    let signed_value: Value = serde_json::from_str(UNSIGNED_JCS).unwrap();
    assert!(verify_signed_json(PUBLIC_KEY, SIGNATURE, &signed_value, CTX_SYNC_RECORD).unwrap());

    let mut tampered = signed_value;
    tampered["action"] = serde_json::json!("delete");
    assert!(!verify_signed_json(PUBLIC_KEY, SIGNATURE, &tampered, CTX_SYNC_RECORD,).unwrap());
}

impl TestContext {
    async fn new() -> Self {
        let (database_url, path) = temporary_database("api");
        let state = init_db_with_url(&database_url).await.unwrap();
        let router = app(state.clone(), CorsLayer::permissive());
        let chain_id = URL_SAFE_NO_PAD.encode([11_u8; 32]);
        let device_id = Uuid::from_u128(1).to_string();
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let public_key = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes());

        sqlx::query(
            "INSERT INTO chains (chain_id, chain_salt, admin_public_key, created_at_ms, creator_device_id, creator_public_key) \
             VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(&chain_id)
        .bind("test_salt")
        .bind(&public_key)
        .bind(100_i64)
        .bind(&device_id)
        .bind(&public_key)
        .execute(&state.pool)
        .await
        .unwrap();

        let context = Self {
            state,
            router,
            database_url,
            path,
            chain_id,
            device_id,
            signing_key,
        };
        let response = context
            .send_json(
                "POST",
                &format!("/pallasync/v2/chains/{}/devices", context.chain_id),
                &signed_device(
                    &context.chain_id,
                    &context.device_id,
                    100,
                    17,
                    &context.signing_key,
                ),
            )
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        context
    }

    async fn send_json<T: Serialize>(&self, method: &str, uri: &str, body: &T) -> Response<Body> {
        self.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn get(&self, uri: &str) -> Response<Body> {
        self.router
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn close(self) {
        self.state.pool.close().await;
        remove_database_files(&self.path);
    }
}

#[tokio::test]
async fn relay_cursor_returns_a_record_that_arrives_with_an_older_timestamp() {
    let context = TestContext::new().await;
    let first = signed_record(
        &context.chain_id,
        &context.device_id,
        Uuid::from_u128(10).to_string(),
        1_000_000,
        &context.signing_key,
    );
    let response = context
        .send_json(
            "POST",
            &format!("/pallasync/v2/chains/{}/records", context.chain_id),
            &vec![first],
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    let first_page = context
        .get(&format!(
            "/pallasync/v2/chains/{}/records?after_seq=0",
            context.chain_id
        ))
        .await;
    let cursor = header_i64(&first_page, "pallasync-next-seq");
    assert_eq!(cursor, 1);

    let delayed_id = Uuid::from_u128(11).to_string();
    let delayed = signed_record(
        &context.chain_id,
        &context.device_id,
        delayed_id.clone(),
        960_000,
        &context.signing_key,
    );
    let response = context
        .send_json(
            "POST",
            &format!("/pallasync/v2/chains/{}/records", context.chain_id),
            &vec![delayed],
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    let delayed_page = context
        .get(&format!(
            "/pallasync/v2/chains/{}/records?after_seq={cursor}",
            context.chain_id
        ))
        .await;
    assert_eq!(delayed_page.status(), StatusCode::OK);
    assert_eq!(
        delayed_page.headers()[CONTENT_TYPE],
        "application/vnd.palleria.sync.v2+json"
    );
    let delayed_resp: FetchRecordsResponse = json_body(delayed_page).await;
    assert_eq!(delayed_resp.records.len(), 1);
    assert_eq!(delayed_resp.records[0].record_id, delayed_id);

    // The compatibility endpoint intentionally retains its historic semantics.
    let legacy = context
        .get(&format!(
            "/pallasync/v2/chains/{}/records?since_ms=1000000",
            context.chain_id
        ))
        .await;
    let legacy_resp: FetchRecordsResponse = json_body(legacy).await;
    assert!(legacy_resp.records.is_empty());
    context.close().await;
}

#[tokio::test]
async fn queryless_legacy_get_remains_unlimited() {
    let context = TestContext::new().await;
    let records = (1_000_u128..1_205)
        .map(|id| {
            signed_record(
                &context.chain_id,
                &context.device_id,
                Uuid::from_u128(id).to_string(),
                id as i64,
                &context.signing_key,
            )
        })
        .collect::<Vec<_>>();
    let endpoint = format!("/pallasync/v2/chains/{}/records", context.chain_id);
    assert_eq!(
        context
            .send_json("POST", &endpoint, &records)
            .await
            .status(),
        StatusCode::OK
    );

    let response = context.get(&endpoint).await;
    assert_eq!(response.status(), StatusCode::OK);
    let returned: FetchRecordsResponse = json_body(response).await;
    assert_eq!(returned.records.len(), records.len());

    assert_eq!(
        context.get(&format!("{endpoint}?limit=100")).await.status(),
        StatusCode::BAD_REQUEST
    );
    context.close().await;
}

#[tokio::test]
async fn malformed_and_unknown_record_queries_return_vendor_json_errors() {
    let context = TestContext::new().await;
    let endpoint = format!("/pallasync/v2/chains/{}/records", context.chain_id);

    for query in ["after_seq=not-a-number", "after_seq=0&unexpected=true"] {
        let response = context.get(&format!("{endpoint}?{query}")).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers()[CONTENT_TYPE],
            "application/vnd.palleria.sync.v2+json"
        );
        let body: Value = json_body(response).await;
        assert_eq!(body["code"], "invalid_request");
        assert!(
            body["detail"]
                .as_str()
                .is_some_and(|detail| !detail.is_empty())
        );
    }

    context.close().await;
}

#[tokio::test]
async fn same_timestamp_duplicate_page_boundary_and_restart_are_stable() {
    let context = TestContext::new().await;
    let records = (20_u128..23)
        .map(|id| {
            signed_record(
                &context.chain_id,
                &context.device_id,
                Uuid::from_u128(id).to_string(),
                2_000,
                &context.signing_key,
            )
        })
        .collect::<Vec<_>>();
    let endpoint = format!("/pallasync/v2/chains/{}/records", context.chain_id);
    assert_eq!(
        context
            .send_json("POST", &endpoint, &records)
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        context
            .send_json("POST", &endpoint, &vec![records[0].clone()])
            .await
            .status(),
        StatusCode::OK
    );

    let first_page = context
        .get(&format!("{endpoint}?after_seq=0&limit=2"))
        .await;
    assert_eq!(first_page.headers()["pallasync-has-more"], "true");
    assert_eq!(header_i64(&first_page, "pallasync-next-seq"), 2);
    let first_records = json_body::<FetchRecordsResponse>(first_page).await.records;
    assert_eq!(first_records.len(), 2);

    let second_page = context
        .get(&format!("{endpoint}?after_seq=2&limit=2"))
        .await;
    assert_eq!(second_page.headers()["pallasync-has-more"], "false");
    assert_eq!(header_i64(&second_page, "pallasync-next-seq"), 3);
    let second_records = json_body::<FetchRecordsResponse>(second_page).await.records;
    assert_eq!(second_records.len(), 1);

    let TestContext {
        state,
        database_url,
        path,
        chain_id,
        ..
    } = context;
    state.pool.close().await;
    let restarted = init_db_with_url(&database_url).await.unwrap();
    let restarted_router = app(restarted.clone(), CorsLayer::permissive());
    let response = restarted_router
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/pallasync/v2/chains/{chain_id}/records?after_seq=0&limit=500"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(header_i64(&response, "pallasync-next-seq"), 3);
    let restarted_records = json_body::<FetchRecordsResponse>(response).await.records;
    assert_eq!(restarted_records.len(), 3);
    restarted.pool.close().await;
    remove_database_files(&path);
}

#[tokio::test]
async fn deleted_chain_is_the_only_chain_state_that_returns_gone() {
    let context = TestContext::new().await;
    let unknown_chain = URL_SAFE_NO_PAD.encode([99_u8; 32]);
    let unknown = context
        .get(&format!(
            "/pallasync/v2/chains/{unknown_chain}/records?after_seq=0"
        ))
        .await;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

    let response = context
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/pallasync/v2/chains/{}", context.chain_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let gone = context
        .get(&format!(
            "/pallasync/v2/chains/{}/records?after_seq=0",
            context.chain_id
        ))
        .await;
    assert_eq!(gone.status(), StatusCode::GONE);
    context.close().await;
}

#[tokio::test]
async fn rejects_path_body_mismatch_conflicting_cursors_and_invalid_signature() {
    let context = TestContext::new().await;
    let other_chain = URL_SAFE_NO_PAD.encode([12_u8; 32]);
    let mismatched = signed_record(
        &other_chain,
        &context.device_id,
        Uuid::from_u128(30).to_string(),
        3_000,
        &context.signing_key,
    );
    let endpoint = format!("/pallasync/v2/chains/{}/records", context.chain_id);
    let mismatch_response = context
        .send_json("POST", &endpoint, &vec![mismatched])
        .await;
    assert_eq!(mismatch_response.status(), StatusCode::OK);
    let body: PostRecordsResponse = json_body(mismatch_response).await;
    assert_eq!(body.rejected.len(), 1);

    let conflicting = context
        .get(&format!("{endpoint}?after_seq=0&since_ms=0"))
        .await;
    assert_eq!(conflicting.status(), StatusCode::BAD_REQUEST);
    let excessive_limit = context
        .get(&format!("{endpoint}?after_seq=0&limit=501"))
        .await;
    assert_eq!(excessive_limit.status(), StatusCode::BAD_REQUEST);

    let mut bad_signature = signed_record(
        &context.chain_id,
        &context.device_id,
        Uuid::from_u128(31).to_string(),
        3_001,
        &context.signing_key,
    );
    bad_signature.signature = URL_SAFE_NO_PAD.encode([0_u8; 64]);
    let invalid_response = context
        .send_json("POST", &endpoint, &vec![bad_signature])
        .await;
    assert_eq!(invalid_response.status(), StatusCode::OK);
    let body: PostRecordsResponse = json_body(invalid_response).await;
    assert_eq!(body.rejected.len(), 1);

    let other_signing_key = SigningKey::from_bytes(&[8_u8; 32]);
    let mut invalid_device = signed_device(
        &context.chain_id,
        &Uuid::from_u128(32).to_string(),
        3_002,
        44,
        &other_signing_key,
    );
    invalid_device.signature = URL_SAFE_NO_PAD.encode([0_u8; 64]);
    let key_mismatch = context
        .send_json(
            "POST",
            &format!("/pallasync/v2/chains/{}/devices", context.chain_id),
            &invalid_device,
        )
        .await;
    assert_eq!(key_mismatch.status(), StatusCode::BAD_REQUEST);
    context.close().await;
}

#[tokio::test]
async fn rejects_sync_record_signed_by_a_different_key() {
    let context = TestContext::new().await;
    let other_signing_key = SigningKey::from_bytes(&[8_u8; 32]);
    let record = signed_record(
        &context.chain_id,
        &context.device_id,
        Uuid::from_u128(33).to_string(),
        4_001,
        &other_signing_key,
    );
    let response = context
        .send_json(
            "POST",
            &format!("/pallasync/v2/chains/{}/records", context.chain_id),
            &vec![record],
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: PostRecordsResponse = json_body(response).await;
    assert_eq!(body.accepted_record_ids.len(), 0);
    assert_eq!(body.rejected.len(), 1);
    assert_eq!(body.rejected[0].reason, "Invalid record signature");

    context.close().await;
}

#[tokio::test]
async fn vendor_json_content_type_is_accepted_for_post_requests() {
    let context = TestContext::new().await;
    let record = signed_record(
        &context.chain_id,
        &context.device_id,
        Uuid::from_u128(34).to_string(),
        4_100,
        &context.signing_key,
    );
    let response = context
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/pallasync/v2/chains/{}/records", context.chain_id))
                .header(CONTENT_TYPE, "application/vnd.palleria.sync.v2+json")
                .body(Body::from(serde_json::to_vec(&vec![record]).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    context.close().await;
}

#[tokio::test]
async fn device_upsert_updates_every_signed_field_and_remains_verifiable() {
    let context = TestContext::new().await;
    let endpoint = format!("/pallasync/v2/chains/{}/devices", context.chain_id);
    let replacement = signed_device(
        &context.chain_id,
        &context.device_id,
        9_999,
        55,
        &context.signing_key,
    );
    assert_eq!(
        context
            .send_json("POST", &endpoint, &replacement)
            .await
            .status(),
        StatusCode::CREATED
    );
    let response = context.get(&endpoint).await;
    let devices: Vec<DeviceRecord> = json_body(response).await;
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].created_at_ms, 9_999);
    assert_eq!(devices[0].updated_at_ms, 9_999);
    assert_eq!(
        devices[0].encrypted_device_name,
        replacement.encrypted_device_name
    );
    let value = serde_json::to_value(&devices[0]).unwrap();
    assert!(
        verify_signed_json(
            &devices[0].device_public_key,
            &devices[0].signature,
            &value,
            CTX_DEVICE_RECORD
        )
        .unwrap()
    );
    context.close().await;
}

#[tokio::test]
async fn resets_legacy_database_tables_for_protocol_v2_1() {
    let (database_url, path) = temporary_database("migration");
    let options = SqliteConnectOptions::from_str(&database_url)
        .unwrap()
        .create_if_missing(true);
    let pool = sqlx::SqlitePool::connect_with(options).await.unwrap();
    sqlx::query(
        "CREATE TABLE sync_records (\
            chain_id TEXT NOT NULL, record_id TEXT NOT NULL, relay_seq INTEGER,\
            PRIMARY KEY(chain_id, record_id)\
        )",
    )
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;

    let migrated = init_db_with_url(&database_url).await.unwrap();
    let is_v2_1: bool = sqlx::query_scalar::<_, i32>(
        "SELECT COUNT(*) FROM pragma_table_info('sync_records') WHERE name = 'server_sequence'",
    )
    .fetch_one(&migrated.pool)
    .await
    .map(|count| count > 0)
    .unwrap_or(false);
    assert!(is_v2_1);
    migrated.pool.close().await;
    remove_database_files(&path);
}

#[tokio::test]
async fn health_advertises_protocol_and_vendor_media_type() {
    let context = TestContext::new().await;
    let response = context.get("/pallasync/v2/health").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[CONTENT_TYPE],
        "application/vnd.palleria.sync.v2+json"
    );
    let health: Value = json_body(response).await;
    assert_eq!(health["status"], "ok");
    assert_eq!(health["protocol_version"], "2.1");
    context.close().await;
}

fn signed_record(
    chain_id: &str,
    device_id: &str,
    record_id: String,
    created_at_ms: i64,
    signing_key: &SigningKey,
) -> SyncRecord {
    let mut record = SyncRecord {
        protocol_version: "2.1".to_string(),
        chain_id: chain_id.to_string(),
        record_id,
        epoch: 0,
        collection_name: "palleria.favorite_tag/2".to_string(),
        action: "upsert".to_string(),
        encrypted_payload: URL_SAFE_NO_PAD.encode([42_u8; 32]),
        payload_nonce: URL_SAFE_NO_PAD.encode([0_u8; 24]),
        device_id: device_id.to_string(),
        lamport: 0,
        created_at_ms,
        signature: String::new(),
    };
    record.signature = signature_for(&record, signing_key, CTX_SYNC_RECORD);
    record
}

fn signed_device(
    chain_id: &str,
    device_id: &str,
    created_at_ms: i64,
    ciphertext_byte: u8,
    signing_key: &SigningKey,
) -> DeviceRecord {
    let mut record = DeviceRecord {
        protocol_version: "2.1".to_string(),
        chain_id: chain_id.to_string(),
        device_id: device_id.to_string(),
        encrypted_device_name: URL_SAFE_NO_PAD.encode([ciphertext_byte; 32]),
        device_name_nonce: URL_SAFE_NO_PAD.encode([0_u8; 24]),
        device_public_key: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes()),
        status: "active".to_string(),
        created_at_ms,
        updated_at_ms: created_at_ms,
        signature: String::new(),
    };
    record.signature = signature_for(&record, signing_key, CTX_DEVICE_RECORD);
    record
}

fn signature_for<T: Serialize>(value: &T, signing_key: &SigningKey, context: &[u8]) -> String {
    let mut value = serde_json::to_value(value).unwrap();
    value.as_object_mut().unwrap().remove("signature");
    let canonical = serde_jcs::to_vec(&value).unwrap();
    let mut message = Vec::with_capacity(context.len() + canonical.len());
    message.extend_from_slice(context);
    message.extend_from_slice(&canonical);
    URL_SAFE_NO_PAD.encode(signing_key.sign(&message).to_bytes())
}

async fn json_body<T: serde::de::DeserializeOwned>(response: Response<Body>) -> T {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn header_i64(response: &Response<Body>, name: &str) -> i64 {
    response.headers()[name].to_str().unwrap().parse().unwrap()
}

fn temporary_database(label: &str) -> (String, PathBuf) {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let counter = TEMP_DATABASE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "pallasync-{label}-{}-{unique}-{counter}.sqlite",
        std::process::id(),
    ));
    let database_url = format!("sqlite:{}", path.to_string_lossy().replace('\\', "/"));
    (database_url, path)
}

fn remove_database_files(path: &PathBuf) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{}-wal", path.display()));
    let _ = std::fs::remove_file(format!("{}-shm", path.display()));
}
