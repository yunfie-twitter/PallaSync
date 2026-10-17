use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use pallasync_server::{
    api::{
        error::now,
        store,
        sync::{AppState, VENDOR_MEDIA_TYPE},
        wire,
    },
    app,
    config::RelayConfig,
    crypto::{jcs, verify::*},
    db::{self},
};
use serde_json::{Value, json};
use tower::ServiceExt;

const ORIGIN: &str = "https://relay.example.com";
const CHAIN: &str = "ODtLW4w27pD6LS9IpFBfmvByjEoBFddv2Fx1QJIMJoc";
const DEVICE: &str = "11111111-1111-4111-8111-111111111111";
fn b(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn sign(mut v: Value, k: &SigningKey, ctx: &[u8]) -> Value {
    v.as_object_mut().unwrap().remove("signature");
    let input = signing_bytes(&v, ctx, "signature");
    v["signature"] = b(k.sign(&input).to_bytes()).into();
    v
}
fn kex() -> String {
    b(curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped([12u8; 32]).as_bytes())
}
fn config(quota: Option<u64>) -> RelayConfig {
    let relay = key(160);
    let md = b"# Test operator\nExplicit test-only policy; not a deployment disclosure.\n".to_vec();
    let mut copies = serde_json::Map::new();
    for name in [
        "active_store",
        "replica",
        "wal",
        "snapshot_store",
        "backup",
        "staging",
        "temporary_export",
        "support",
        "cache",
        "operational_log",
        "attestations",
        "deletion_ledger",
    ] {
        let present = [
            "active_store",
            "wal",
            "snapshot_store",
            "staging",
            "cache",
            "attestations",
            "deletion_ledger",
        ]
        .contains(&name);
        let evidence = ["attestations", "deletion_ledger"].contains(&name);
        copies.insert(name.into(),if present {json!({"present":true,"content":if evidence{"authority_evidence"}else{"ciphertext"},"retention":{"mode":"until_chain_deletion"},"locations":["Test process persistent local disk"],"recipients":["Test operator"],"purpose":"Protocol storage","after_delete":{"mode":if evidence{"retain_authority_evidence"}else{"erase"},"max_ms":if evidence{Value::Null}else{json!(60000)}}})} else {json!({"present":false})});
    }
    let mut p = json!({"type":"PALLASYNC-RELAY-PRIVACY-v3","version":"3.0","disclosure_id":store::new_id(),"relay_origin":ORIGIN,"relay_key_id":hash_bytes(relay.verifying_key().as_bytes()),"revision":1,"published_at_ms":0,"effective_at_ms":0,"markdown_sha256":hash_bytes(&md),"operator":{"name":"Test operator","contact_url":"https://relay.example.com/contact"},"durability_tier":"single-durable","limits":{"max_request_bytes":8388608,"max_records_per_upload":64,"page_limit":1000,"max_devices":128},"quota":{"minimum_bytes":0,"maximum_bytes":null,"allow_unconfigured":true,"counted_components":["record","snapshot","envelope","device_meta","receipt","transparency","control"],"allocation_rule":"Sum of stored signed objects, log wrappers, receipts, heads, outcomes, cursors and offers"},"rate_limits":{"authorized_signer":{"requests_per_minute":120,"burst":30},"record_upload_device":{"requests_per_minute":30,"burst":10},"enrollment_source_ip":{"requests_per_minute":6,"burst":3},"enrollment_offer":{"requests_per_minute":3,"burst":1},"public_document_ip":{"requests_per_minute":240,"burst":60}},"backups":{"enabled":false},"copies":copies,"deletion":{"assurance":"backup-expiry","active_delete_max_ms":60000,"backup_delete_max_ms":null,"key_destroy_max_ms":null},"relay_key":{"protection":"os_keystore","replacement_mode":"explicit_trust_reestablishment","automatic_rotation":false,"new_transparency_id_required":true,"old_verification_keys_retained":true},"replay_protection":{"mode":"durable"},"metadata":{"retained_fields":[],"purposes":[],"retention":{"mode":"not_retained"},"recipients":[]},"change_notice":{"minimum_notice_ms":0,"notice_url":"https://relay.example.com/notice","archive_url":"https://relay.example.com/archive"}});
    p["copies"]["cache"]["content"] = "metadata".into();
    p["copies"]["cache"]["retention"] = json!({"mode":"indefinite"});
    p["copies"]["cache"]["after_delete"] = json!({"mode":"retain_metadata","max_ms":null});
    p["metadata"] = json!({"retained_fields":["ip","timing"],"purposes":["Persistent token-bucket accounting using source IP hashes and last update times"],"retention":{"mode":"indefinite"},"recipients":["Test operator"]});
    sign_relay(&relay, &mut p, CTX_PRIVACY).unwrap();
    RelayConfig::new(relay, md, p, quota).unwrap()
}
fn parameters() -> Value {
    sign(
        json!({"version":"3.0","chain_id":CHAIN,"admin_public_key":b(key(1).verifying_key().as_bytes()),"generation":0,"previous_parameters_hash":null,"policy":{"metadata_profile":"private","allow_device_chain_delete":false,"allow_peer_enrollment":true,"allow_device_rotation":true,"epoch_retention":"retain","epoch_window_ms":2592000000u64,"scheduled_rotation_ms":0}}),
        &key(1),
        CTX_PARAMETERS,
    )
}
fn device(id: &str, k: &SigningKey, generation: u64, epoch: u64, request: Option<&Value>) -> Value {
    let cert = sign(
        json!({"chain_id":CHAIN,"generation":generation,"certificate_id":store::new_id(),"device_id":id,"device_public_key":b(k.verifying_key().as_bytes()),"device_kex_public_key":kex(),"signer_kind":"admin","signer_device_id":null,"request_hash":request.map(object_hash),"approved_at_ms":now()}),
        &key(1),
        CTX_ENROLLMENT,
    );
    sign(
        json!({"version":"3.0","chain_id":CHAIN,"generation":generation,"device_id":id,"device_public_key":b(k.verifying_key().as_bytes()),"device_kex_public_key":kex(),"meta_epoch":epoch,"meta_nonce":b([13;24]),"encrypted_device_meta":b([42;1040]),"enrollment":cert}),
        k,
        CTX_DEVICE_RECORD,
    )
}
fn epoch_bundle(
    generation: u64,
    epoch: u64,
    previous: Option<String>,
    members: &[&str],
    revoked: &[&str],
    reason: &str,
) -> (Value, Vec<Value>) {
    let mut envelopes = Vec::new();
    for member in members {
        envelopes.push(sign(json!({"envelope_id":store::new_id(),"chain_id":CHAIN,"generation":generation,"epoch":epoch,"previous_epoch_hash":previous,"epoch_commitment":b([epoch as u8;32]),"recipient_kind":"device","recipient_device_id":member,"recipient_key_hash":hash_bytes(&decode(&kex(),Some(32)).unwrap()),"signer_kind":"admin","signer_device_id":null,"enc":kex(),"nonce":null,"ciphertext":b([7;48])}),&key(1),CTX_ENVELOPE));
    }
    let recovery = sign(
        json!({"envelope_id":store::new_id(),"chain_id":CHAIN,"generation":generation,"epoch":epoch,"previous_epoch_hash":previous,"epoch_commitment":b([epoch as u8;32]),"recipient_kind":"recovery","recipient_device_id":null,"recipient_key_hash":null,"signer_kind":"admin","signer_device_id":null,"enc":null,"nonce":b([epoch as u8;24]),"ciphertext":b([8;48])}),
        &key(1),
        CTX_ENVELOPE,
    );
    let e = sign(
        json!({"chain_id":CHAIN,"generation":generation,"epoch":epoch,"previous_epoch_hash":previous,"epoch_commitment":b([epoch as u8;32]),"reason":reason,"signer_kind":"admin","signer_device_id":null,"members":members,"revoked_device_ids":revoked,"recovery_envelope_hash":object_hash(&recovery)}),
        &key(1),
        CTX_EPOCH,
    );
    envelopes.push(recovery);
    (e, envelopes)
}
fn genesis() -> Value {
    let (e, es) = epoch_bundle(0, 0, None, &[DEVICE], &[], "genesis");
    json!({"parameters":parameters(),"device_record":device(DEVICE,&key(2),0,0,None),"epoch":e,"envelopes":es})
}
fn record(epoch: u64) -> Value {
    sign(
        json!({"version":"3.0","chain_id":CHAIN,"generation":0,"record_id":store::new_id(),"device_id":DEVICE,"epoch":epoch,"collection_tag":null,"payload_nonce":b([uuid::Uuid::new_v4().as_bytes().as_slice(),&[0u8;8]].concat()),"encrypted_payload":b([42;1040])}),
        &key(2),
        CTX_SYNC_RECORD,
    )
}
fn token(method: &str, path: &str, body: &[u8], device: bool) -> Value {
    let device_key = key(2);
    token_for(
        method,
        path,
        body,
        if device {
            Some((DEVICE, &device_key))
        } else {
            None
        },
    )
}
fn token_for(method: &str, path: &str, body: &[u8], device: Option<(&str, &SigningKey)>) -> Value {
    let (path, q) = path.split_once('?').unwrap_or((path, ""));
    let t = now();
    sign(
        json!({"v":3,"aud":ORIGIN,"chain_id":CHAIN,"signer_kind":if device.is_some(){"device"}else{"admin"},"device_id":device.map(|(id,_)|id),"method":method,"path":path,"query":wire::query_string(&wire::canonical_query(q).unwrap()),"body_sha256":hash_bytes(body),"issued_at_ms":t,"expires_at_ms":t+120000,"nonce":b(uuid::Uuid::new_v4().as_bytes())}),
        device.map(|(_, k)| k).unwrap_or(&key(1)),
        CTX_CAPABILITY,
    )
}
struct Context {
    state: AppState,
    router: axum::Router,
    path: std::path::PathBuf,
    genesis: Value,
}
impl Context {
    async fn new() -> Self {
        Self::with_quota(None).await
    }
    async fn with_quota(quota: Option<u64>) -> Self {
        Self::configured(config(quota)).await
    }
    async fn configured(config: RelayConfig) -> Self {
        let path = std::env::temp_dir().join(format!("pallasync-v3-{}.sqlite", store::new_id()));
        let db = db::init_db_with_url(&format!(
            "sqlite:{}",
            path.to_string_lossy().replace('\\', "/")
        ))
        .await
        .unwrap();
        let state = AppState::new(db, config).await.unwrap();
        let router = app(state.clone());
        let genesis = genesis();
        Self {
            state,
            router,
            path,
            genesis,
        }
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        v: Option<&Value>,
        device: bool,
    ) -> (StatusCode, Value) {
        let body = v
            .map(|v| serde_json::to_vec(v).unwrap())
            .unwrap_or_default();
        let mut t = token(method, path, &body, device);
        t["aud"] = self.state.config.origin.clone().into();
        let t = sign(t, &key(if device { 2 } else { 1 }), CTX_CAPABILITY);
        self.raw(method, path, body, Some(&t), VENDOR_MEDIA_TYPE)
            .await
    }
    async fn raw(
        &self,
        method: &str,
        path: &str,
        body: Vec<u8>,
        token: Option<&Value>,
        ct: &str,
    ) -> (StatusCode, Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", ct);
        if let Some(t) = token {
            req = req.header(
                "authorization",
                format!("PallaSync {}", b(jcs::canonicalize_json(t).unwrap())),
            )
        }
        let response = self
            .router
            .clone()
            .oneshot(req.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = response.status();
        assert_eq!(response.headers()["x-pallasync-protocol"], "pallasync/3");
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(response.headers().contains_key("date"));
        if status.is_client_error() || status.is_server_error() {
            assert_eq!(
                response.headers()["content-type"],
                "application/problem+json"
            )
        }
        let bytes = to_bytes(response.into_body(), 8 * 1024 * 1024)
            .await
            .unwrap();
        let v = jcs::parse(&bytes).unwrap();
        (status, v)
    }
    async fn create(&self) -> Value {
        let (s, v) = self
            .request("POST", "/pallasync/v3/chains", Some(&self.genesis), false)
            .await;
        assert_eq!(s, 201, "{v}");
        v
    }
    fn path(&self, resource: &str) -> String {
        format!("/pallasync/v3/chains/{CHAIN}/{resource}")
    }
    async fn close(self) {
        self.state.db.pool.close().await;
        let _ = std::fs::remove_file(self.path);
    }
}

#[test]
fn official_jcs_positive_and_negative_vectors() {
    let cases = [
        (
            r#"{"z":2,"a":1}"#,
            r#"{"a":1,"z":2}"#,
            "99168216144c7fed5d4c54916cf98d9c66096280c04a499822a99b6658bd177a",
        ),
        (
            r#"{"\uE000":1,"😀":2,"a":3}"#,
            "{\"a\":3,\"😀\":2,\"\u{e000}\":1}",
            "84495633024b0992798250783e7ccb01ab2875649ab22f353f14c0d6a8389fc2",
        ),
        (
            r#"{"text":"\u0000\b\t\n\f\r\"\\/"}"#,
            r#"{"text":"\u0000\b\t\n\f\r\"\\/"}"#,
            "997f29258dcf1c2af2af1cd2e02858e4c93dc4637189d62278a67426a6728fd2",
        ),
        (
            r#"{"z":"日本語","a":[true,false,null,9007199254740991]}"#,
            r#"{"a":[true,false,null,9007199254740991],"z":"日本語"}"#,
            "2eab9e896157ee9c86d967cedb96c09f95b0365051782611ea71351775a6e7ff",
        ),
    ];
    for (input, expected, digest) in cases {
        let value = jcs::parse(input.as_bytes()).unwrap();
        let bytes = jcs::canonicalize_json(&value).unwrap();
        assert_eq!(bytes, expected.as_bytes());
        assert_eq!(decode(&hash_bytes(&bytes), Some(32)).unwrap(), hex(digest));
    }
    for s in [
        r#"{"a":1,"a":2}"#,
        r#"{"a":-0}"#,
        r#"{"a":1e3}"#,
        r#"{"a":1.0}"#,
        r#"{"a":01}"#,
        r#"{"a":-1}"#,
        r#"{"a":9007199254740992}"#,
        r#"{"a":"\ud800"}"#,
    ] {
        assert!(jcs::parse(s.as_bytes()).is_err(), "{s}")
    }
    assert!(jcs::parse(&[192, 175]).is_err());
    assert!(jcs::parse(b"\xef\xbb\xbf{}").is_err());
    assert!(jcs::parse(format!("{}0{}", "[".repeat(33), "]".repeat(33)).as_bytes()).is_err());
    assert!(decode("AB", Some(1)).is_err());
    assert!(decode("AA=", Some(1)).is_err());
    assert!(!wire::id("e\u{301}"));
    assert!(wire::id("é"));
}
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn official_signature_and_attestation_vectors() {
    let r = jcs::parse(include_bytes!("fixtures/sig-01.json")).unwrap();
    wire::validate(&r, "record").unwrap();
    let public = b(hex(
        "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
    ));
    assert!(verify_signed_json(&public, wire::s(&r, "signature"), &r, CTX_SYNC_RECORD).unwrap());
    assert!(!verify_signed_json(&public, wire::s(&r, "signature"), &r, CTX_CAPABILITY).unwrap());
    assert_eq!(
        decode(
            &hash_bytes(&signing_bytes(&r, CTX_SYNC_RECORD, "signature")),
            Some(32)
        )
        .unwrap(),
        hex("b7f1fc1683e0c7afae54fa5419d597c6caa9647d98800b8ada1fb550495e2943")
    );
    let entry = json!({"relay_seq":7,"received_at_ms":1791684000000u64,"kind":"record","object":r});
    assert_eq!(
        object_hash(&entry),
        "eQkBDj_MnQbwW1LSjkwHmfTVRxUFYV0TxpYUFeeTqZo"
    );
    assert_eq!(
        store::link_hash(&b([171; 32]), 7, &entry, b""),
        "9rmeVaK9mN98hMLU6FDa4ZGL77Mgrd5fwceAipags-o"
    );
    let public = "T9CZzNR9eJPf6ewkQU7LDZtUICMqrTDZHEZb4zy-ZcQ";
    let t = jcs::parse(include_bytes!("fixtures/transparency-01.json")).unwrap();
    let receipt = jcs::parse(include_bytes!("fixtures/receipt-01.json")).unwrap();
    assert!(
        verify_signature(
            public,
            wire::s(&t, "relay_signature"),
            &signing_bytes(&t, CTX_TRANSPARENCY, "relay_signature")
        )
        .unwrap()
    );
    assert!(
        verify_signature(
            public,
            wire::s(&receipt, "relay_signature"),
            &signing_bytes(&receipt, CTX_RECEIPT, "relay_signature")
        )
        .unwrap()
    );
    assert_eq!(
        store::link_hash(
            wire::s(&t, "previous_transparency_hash"),
            1,
            &t,
            b"PALLASYNC-TRANSPARENCY-LINK-v3\0"
        ),
        receipt["transparency_hash"]
    );
    for raw in [[0u8; 32], {
        let mut b = [0; 32];
        b[0] = 1;
        b
    }] {
        assert!(!valid_ed_key(&b(raw)))
    }
    assert!(!valid_x_key(&b(hex(
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
    ))));
    assert!(!valid_x_key(&b([255u8; 32])));
    assert!(!valid_x_key(&b([0u8; 32])));
}

#[tokio::test]
async fn genesis_requires_admin_and_complete_atomic_bundle() {
    let c = Context::new().await;
    let (s, v) = c
        .raw(
            "POST",
            "/pallasync/v3/chains",
            serde_json::to_vec(&c.genesis).unwrap(),
            None,
            VENDOR_MEDIA_TYPE,
        )
        .await;
    assert_eq!(s, 401);
    assert_eq!(v["code"], "TOKEN_REQUIRED");
    let mut invalid = c.genesis.clone();
    invalid["envelopes"].as_array_mut().unwrap().pop();
    let (s, _) = c
        .request("POST", "/pallasync/v3/chains", Some(&invalid), false)
        .await;
    assert_eq!(s, 409);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM v3_chains")
        .fetch_one(&c.state.db.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    let created = c.create().await;
    assert_eq!(created["head_seq"], 5);
    assert_eq!(created["upload_receipts"].as_array().unwrap().len(), 5);
    let (s, again) = c
        .request("POST", "/pallasync/v3/chains", Some(&c.genesis), false)
        .await;
    assert_eq!(s, 200);
    assert_eq!(created, again);
    let (s, v) = c.request("GET", &c.path("parameters"), None, true).await;
    assert_eq!(s, 200);
    assert_eq!(v["parameters"], c.genesis["parameters"]);
    assert!(v["parameters"].get("chain_salt").is_none());
    c.close().await;
}

// Generated by Palleria rust/pallasync-core at 6247a2ee, using the public Appendix C KDF-01
// mnemonic. Fixture signing seeds are intentionally public test keys, never relay keys.
#[tokio::test]
async fn palleria_native_v3_genesis_and_records_interoperate_without_legacy_media() {
    let c = Context::new().await;
    let f = jcs::parse(include_bytes!("fixtures/palleria-v3-genesis.json")).unwrap();
    let genesis = &f["genesis"];
    let admin = SigningKey::from_bytes(
        decode(f["admin_signing_seed"].as_str().unwrap(), Some(32))
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap(),
    );
    let device_key = SigningKey::from_bytes(
        decode(f["device_signing_seed"].as_str().unwrap(), Some(32))
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap(),
    );
    let body = serde_json::to_vec(genesis).unwrap();
    let t = sign(
        token("POST", "/pallasync/v3/chains", &body, false),
        &admin,
        CTX_CAPABILITY,
    );
    let (status, error) = c
        .raw(
            "POST",
            "/pallasync/v3/chains",
            body.clone(),
            Some(&t),
            "application/vnd.palleria.sync.v2+json",
        )
        .await;
    assert_eq!(status, 415);
    assert_eq!(error["code"], "UNSUPPORTED_MEDIA_TYPE");
    let (status, created) = c
        .raw(
            "POST",
            "/pallasync/v3/chains",
            body,
            Some(&t),
            VENDOR_MEDIA_TYPE,
        )
        .await;
    assert_eq!(status, 201, "{created}");
    let device_id = f["genesis"]["device_record"]["device_id"].as_str().unwrap();
    for resource in ["devices", "records"] {
        let path = c.path(resource);
        let mut t = token("GET", &path, b"", true);
        t["device_id"] = device_id.into();
        let t = sign(t, &device_key, CTX_CAPABILITY);
        let (status, page) = c
            .raw("GET", &path, vec![], Some(&t), VENDOR_MEDIA_TYPE)
            .await;
        assert_eq!(status, 200, "{page}");
        assert!(page["items"].is_array());
        if resource == "devices" {
            assert_eq!(page["items"][0]["device_record"], genesis["device_record"]);
            assert_eq!(page["items"][0]["status"], "active");
        }
    }
    let mut invalid = f["record"].clone();
    invalid["record_id"] = store::new_id().into();
    invalid["signature"] = b([0; 64]).into();
    let upload = json!({"records":[f["record"].clone(),invalid]});
    let body = serde_json::to_vec(&upload).unwrap();
    let path = c.path("records");
    let mut t = token("POST", &path, &body, true);
    t["device_id"] = device_id.into();
    let t = sign(t, &device_key, CTX_CAPABILITY);
    let (status, result) = c
        .raw("POST", &path, body, Some(&t), VENDOR_MEDIA_TYPE)
        .await;
    assert_eq!(status, 200, "{result}");
    assert_eq!(result["accepted"][0]["receipt"]["object"], f["record"]);
    assert_eq!(result["rejected"][0]["code"], "OBJECT_SIGNATURE_INVALID");
    let mut v7_record = f["record"].clone();
    v7_record["record_id"] = "018f0c2a-7b9d-7000-8000-000000000001".into();
    let body = serde_json::to_vec(&json!({"records":[v7_record]})).unwrap();
    let mut t = token("POST", &path, &body, true);
    t["device_id"] = device_id.into();
    let t = sign(t, &device_key, CTX_CAPABILITY);
    let (status, problem) = c
        .raw("POST", &path, body, Some(&t), VENDOR_MEDIA_TYPE)
        .await;
    assert_eq!(status, 400);
    assert_eq!(problem["code"], "INVALID_FIELD");
    c.close().await;
}

#[tokio::test]
async fn raw_binding_freshness_replay_and_error_profile() {
    let c = Context::new().await;
    c.create().await;
    let path = c.path("parameters");
    let t = token("GET", &path, b"", true);
    let (s, _) = c
        .raw("GET", &path, vec![], Some(&t), VENDOR_MEDIA_TYPE)
        .await;
    assert_eq!(s, 200);
    let (s, v) = c
        .raw("GET", &path, vec![], Some(&t), VENDOR_MEDIA_TYPE)
        .await;
    assert_eq!(s, 401);
    assert_eq!(v["code"], "TOKEN_REPLAYED");
    assert_eq!(v["type"], "about:blank");
    for (field, value, code) in [
        (
            "aud",
            json!("https://other.example.com"),
            "TOKEN_BINDING_MISMATCH",
        ),
        ("expires_at_ms", json!(now() + 301000), "TOKEN_TTL_TOO_LONG"),
        ("issued_at_ms", json!(now() + 61000), "TOKEN_NOT_YET_VALID"),
    ] {
        let mut t = token("GET", &path, b"", true);
        t[field] = value;
        if field == "expires_at_ms" {
            t["issued_at_ms"] = (now() - 1000).into()
        }
        if field == "issued_at_ms" {
            t["expires_at_ms"] = (now() + 180001).into()
        }
        let t = sign(t, &key(2), CTX_CAPABILITY);
        let (_, v) = c
            .raw("GET", &path, vec![], Some(&t), VENDOR_MEDIA_TYPE)
            .await;
        assert_eq!(v["code"], code);
    }
    let p = c.path("records");
    let body = b"{\"records\":[],\"records\":[]}".to_vec();
    let t = token("POST", &p, &body, true);
    let (s, v) = c.raw("POST", &p, body, Some(&t), VENDOR_MEDIA_TYPE).await;
    assert_eq!(s, 400);
    assert_eq!(v["code"], "INVALID_JSON");
    assert_eq!(
        wire::query_string(&wire::canonical_query("z=%2f&a=+&x").unwrap()),
        "a=%2B&x=&z=%2F"
    );
    assert!(wire::canonical_query("x=1&%78=2").is_err());
    assert!(wire::canonical_query("x=%ZZ").is_err());
    let legacy = c
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/pallasync/v2/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(legacy.status(), 200);
    assert!(!legacy.headers().contains_key("x-pallasync-protocol"));
    let legacy_body = to_bytes(legacy.into_body(), 1024).await.unwrap();
    assert_eq!(
        jcs::parse(&legacy_body).unwrap(),
        json!({"status":"ok","protocol_version":"2.1"})
    );
    let (s, v) = c.request("PATCH", &path, Some(&json!({})), false).await;
    assert_eq!(s, 405);
    assert_eq!(v["code"], "METHOD_NOT_ALLOWED");
    c.close().await;
}

#[tokio::test]
async fn records_partial_results_immutable_receipts_and_nonce_reuse() {
    let c = Context::new().await;
    c.create().await;
    let good = record(0);
    let stale = record(1);
    let path = c.path("records");
    let (s, v) = c
        .request("POST", &path, Some(&json!({"records":[good,stale]})), true)
        .await;
    assert_eq!(s, 200);
    assert_eq!(v["accepted"].as_array().unwrap().len(), 1);
    assert_eq!(v["rejected"][0]["code"], "EPOCH_STALE");
    let original = v["accepted"][0]["receipt"].clone();
    let signed = v["upload_receipts"][0].clone();
    let (_, v) = c
        .request("POST", &path, Some(&json!({"records":[good]})), true)
        .await;
    assert_eq!(v["accepted"][0]["duplicate"], true);
    assert_eq!(v["accepted"][0]["receipt"], original);
    assert_eq!(v["upload_receipts"][0], signed);
    let mut conflict = good.clone();
    conflict["encrypted_payload"] = b([43; 1040]).into();
    conflict = sign(conflict, &key(2), CTX_SYNC_RECORD);
    let (_, v) = c
        .request("POST", &path, Some(&json!({"records":[conflict]})), true)
        .await;
    assert_eq!(v["rejected"][0]["code"], "RECORD_ID_CONFLICT");
    let mut reused = good.clone();
    reused["record_id"] = store::new_id().into();
    reused = sign(reused, &key(2), CTX_SYNC_RECORD);
    let (_, v) = c
        .request("POST", &path, Some(&json!({"records":[reused]})), true)
        .await;
    assert_eq!(v["rejected"][0]["code"], "INVALID_FIELD");
    let (_, v) = c
        .request("GET", &c.path("records?after_seq=0&limit=1"), None, true)
        .await;
    assert_eq!(v["items"][0], original);
    assert_eq!(v["scan_through_seq"], 6);
    assert_eq!(v["has_more"], false);
    let (_, head) = c
        .request("GET", &c.path("transparency/head"), None, true)
        .await;
    assert_eq!(head["head"]["entry_index"], 9);
    c.close().await;
}

#[tokio::test]
async fn local_recovery_artifacts_in_public_extensions_are_rejected_without_storage() {
    let c = Context::new().await;
    let before = c.create().await;
    let mut records = Vec::new();
    for kind in [
        "PALLASYNC-RECOVERY-BLOB-v3",
        "PALLASYNC-RECOVERY-SET-v3",
        "PALLASYNC-RECOVERY-STATUS-v3",
        "PALLASYNC-RECOVERY-SHARE-v3",
        "PALLASYNC-RECOVERY-PACKAGE-v3",
        "PALLASYNC-OFFLINE-SHARE-KEY-v3",
        "PALLASYNC-RECOVERY-SESSION-v3",
        "PALLASYNC-RECOVERY-TRANSFER-v3",
    ] {
        let mut item = record(0);
        item["ext"] = json!({"org.palleria.fixture":{"nested":[{"type":kind}]}});
        records.push(sign(item, &key(2), CTX_SYNC_RECORD));
    }
    let mut root_input = record(0);
    root_input["ext"] =
        json!({"org.palleria.fixture":{"mnemonic":"public fixture only","passphrase":""}});
    records.push(sign(root_input, &key(2), CTX_SYNC_RECORD));
    let forbidden = records.clone();
    let mut allowed = record(0);
    allowed["ext"] = json!({"org.palleria.fixture":{"text":"PSR3:debug","type":"example"}});
    allowed = sign(allowed, &key(2), CTX_SYNC_RECORD);
    records.push(allowed.clone());
    let (status, response) = c
        .request(
            "POST",
            &c.path("records"),
            Some(&json!({"records":records})),
            true,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(response["accepted"].as_array().unwrap().len(), 1);
    assert_eq!(response["accepted"][0]["record_id"], allowed["record_id"]);
    assert_eq!(response["rejected"].as_array().unwrap().len(), 9);
    assert!(
        response["rejected"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["code"] == "INVALID_FIELD")
    );
    assert_eq!(
        response["head_seq"].as_u64().unwrap(),
        before["head_seq"].as_u64().unwrap() + 1
    );
    for item in forbidden {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM v3_objects WHERE chain_id=? AND object_id=?")
                .bind(CHAIN)
                .bind(wire::s(&item, "record_id"))
                .fetch_one(&c.state.db.pool)
                .await
                .unwrap();
        assert_eq!(count, 0);
    }
    c.close().await;
}

#[tokio::test]
async fn concurrent_nonce_is_consumed_once_and_survives_restart() {
    let c = Context::new().await;
    c.create().await;
    let path = c.path("parameters");
    let t = token("GET", &path, b"", true);
    let (a, b) = tokio::join!(
        c.raw("GET", &path, vec![], Some(&t), VENDOR_MEDIA_TYPE),
        c.raw("GET", &path, vec![], Some(&t), VENDOR_MEDIA_TYPE)
    );
    let mut statuses = vec![a.0.as_u16(), b.0.as_u16()];
    statuses.sort();
    assert_eq!(statuses, vec![200, 401]);
    let log = c.request("GET", &c.path("log/head"), None, false).await.1;
    c.state.db.pool.close().await;
    let db = db::init_db_with_url(&format!(
        "sqlite:{}",
        c.path.to_string_lossy().replace('\\', "/")
    ))
    .await
    .unwrap();
    let state = AppState::new(db, (*c.state.config).clone()).await.unwrap();
    let restarted = Context {
        router: app(state.clone()),
        state,
        path: c.path,
        genesis: c.genesis,
    };
    let (s, v) = restarted
        .raw("GET", &path, vec![], Some(&t), VENDOR_MEDIA_TYPE)
        .await;
    assert_eq!(s, 401);
    assert_eq!(v["code"], "TOKEN_REPLAYED");
    assert_eq!(
        restarted
            .request("GET", &restarted.path("log/head"), None, false)
            .await
            .1,
        log
    );
    restarted.close().await;
}

#[tokio::test]
async fn snapshots_transparency_pagination_and_pruning_preserve_id_evidence() {
    let c = Context::new().await;
    let genesis = c.create().await;
    let event = record(0);
    c.request(
        "POST",
        &c.path("records"),
        Some(&json!({"records":[event]})),
        true,
    )
    .await;
    let part = record(0);
    let (_, p) = c
        .request(
            "POST",
            &c.path("snapshots/parts"),
            Some(&json!({"records":[part]})),
            true,
        )
        .await;
    assert!(p["upload_receipts"][0]["relay_seq"].is_null());
    let (_, head) = c.request("GET", &c.path("log/head"), None, false).await;
    let comp = sign(
        json!({"compaction_id":store::new_id(),"chain_id":CHAIN,"generation":0,"device_id":DEVICE,"log_id":head["log_id"],"covered_through_seq":head["head_seq"],"covered_log_hash":head["head_hash"],"epoch_hash":genesis["epoch_hash"],"snapshot_parts":[{"record_id":part["record_id"],"record_hash":object_hash(&part)}],"state_sha256":b([40;32])}),
        &key(2),
        CTX_COMPACTION,
    );
    let (s, v) = c
        .request(
            "POST",
            &c.path("snapshots"),
            Some(&json!({"compaction":comp})),
            true,
        )
        .await;
    assert_eq!(s, 201, "{v}");
    let started_export = export_page(&c, "export?limit=1&include_recovery=true", false).await;
    let export_cursor = started_export.last().unwrap()["next_cursor"]
        .as_str()
        .unwrap();
    let target = json!({"compaction_id":comp["compaction_id"],"through_seq":6});
    let op = admin(&genesis, "prune_log", &target);
    let (s,v)=c.request("POST",&c.path("log/prune"),Some(&json!({"compaction_id":comp["compaction_id"],"through_seq":6,"admin_operation":op})),false).await;
    assert_eq!(s, 200, "{v}");
    let (_, v) = c
        .request(
            "GET",
            &c.path(&format!(
                "export?limit=1&include_recovery=true&cursor={export_cursor}"
            )),
            None,
            false,
        )
        .await;
    assert_eq!(v["code"], "LOG_PRUNED");
    assert_eq!(v["context"]["compaction_id"], comp["compaction_id"]);
    let (_, v) = c
        .request(
            "POST",
            &c.path("records"),
            Some(&json!({"records":[event]})),
            true,
        )
        .await;
    assert_eq!(v["accepted"][0]["duplicate"], true);
    let (_, v) = c
        .request("GET", &c.path("records?after_seq=0"), None, true)
        .await;
    assert_eq!(v["code"], "LOG_PRUNED");
    let (_, head) = c
        .request("GET", &c.path("transparency/head"), None, false)
        .await;
    let id = wire::s(&head["head"], "transparency_id");
    let q = format!("transparency/entries?transparency_id={id}&limit=2");
    let (_, p1) = c.request("GET", &c.path(&q), None, false).await;
    assert_eq!(p1["items"].as_array().unwrap().len(), 2);
    assert!(p1["has_more"].as_bool().unwrap());
    let q = format!(
        "transparency/entries?transparency_id={id}&limit=2&cursor={}",
        p1["next_cursor"].as_str().unwrap()
    );
    let (_, p2) = c.request("GET", &c.path(&q), None, false).await;
    assert_eq!(p2["anchor_index"], 2);
    assert_eq!(p1["head"], p2["head"]);
    c.close().await;
}
fn admin(head: &Value, action: &str, target: &Value) -> Value {
    sign(
        json!({"operation_id":store::new_id(),"chain_id":CHAIN,"generation":0,"action":action,"expected_parameters_hash":head["parameters_hash"],"expected_epoch_hash":head["epoch_hash"],"target_hash":object_hash(target),"created_at_ms":now()}),
        &key(1),
        CTX_ADMIN_OP,
    )
}

#[tokio::test]
async fn deletion_needs_cas_admin_proof_denies_resurrection_and_erases_ciphertext() {
    let c = Context::new().await;
    let head = c.create().await;
    let chainpath = format!("/pallasync/v3/chains/{CHAIN}");
    let target = json!({"deletion_id":store::new_id(),"expected_parameters_hash":head["parameters_hash"],"expected_epoch_hash":head["epoch_hash"]});
    let mut body = target.clone();
    body["admin_operation"] = Value::Null;
    let (_, v) = c.request("DELETE", &chainpath, Some(&body), true).await;
    assert_eq!(v["code"], "ADMIN_REQUIRED");
    body["admin_operation"] = admin(&head, "delete_chain", &target);
    let (s, v) = c.request("DELETE", &chainpath, Some(&body), false).await;
    assert_eq!(s, 202, "{v}");
    let (_, proof) = c.request("GET", &c.path("deletion"), None, false).await;
    assert_eq!(proof["ledger"]["deletion_id"], body["deletion_id"]);
    assert!(proof["device_authorization"].is_null());
    let (s, gone) = c.request("GET", &c.path("parameters"), None, false).await;
    assert_eq!(s, 410);
    assert_eq!(gone["code"], "CHAIN_DELETED");
    let (s, _) = c
        .request("POST", "/pallasync/v3/chains", Some(&c.genesis), false)
        .await;
    assert_eq!(s, 410);
    let ciphertext: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM v3_objects WHERE chain_id=?")
        .bind(CHAIN)
        .fetch_one(&c.state.db.pool)
        .await
        .unwrap();
    assert_eq!(ciphertext, 0);
    let (s, retry) = c.request("DELETE", &chainpath, Some(&body), false).await;
    assert_eq!(s, 202);
    assert_eq!(retry, v);
    c.close().await;
}

#[tokio::test]
async fn storage_quota_and_legacy_preservation() {
    let c = Context::with_quota(Some(1)).await;
    let (s, v) = c
        .request("POST", "/pallasync/v3/chains", Some(&c.genesis), false)
        .await;
    assert_eq!(s, 507);
    assert_eq!(v["code"], "QUOTA_EXCEEDED");
    c.close().await;
    let path = std::env::temp_dir().join(format!("pallasync-legacy-{}.sqlite", store::new_id()));
    let url = format!("sqlite:{}", path.to_string_lossy().replace('\\', "/"));
    let state = db::init_db_with_url(&url).await.unwrap();
    sqlx::raw_sql(
        "CREATE TABLE chains(chain_id TEXT PRIMARY KEY); INSERT INTO chains VALUES('legacy');",
    )
    .execute(&state.pool)
    .await
    .unwrap();
    state.pool.close().await;
    let state = db::init_db_with_url(&url).await.unwrap();
    let count: String = sqlx::query_scalar("SELECT chain_id FROM chains")
        .fetch_one(&state.pool)
        .await
        .unwrap();
    assert_eq!(count, "legacy");
    state.pool.close().await;
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn enrollment_pending_access_pinned_registry_and_atomic_revocation() {
    let c = Context::new().await;
    let head = c.create().await;
    let subject = "22222222-2222-4222-8222-222222222222";
    let subject_key = key(3);
    let d = device(subject, &subject_key, 0, 0, None);
    let (_, mut envelopes) = epoch_bundle(0, 0, None, &[subject], &[], "genesis");
    envelopes.retain(|e| e["recipient_kind"] == "device");
    let target = json!({"device_record":d,"envelopes":envelopes});
    let op = admin(&head, "approve_enrollment", &target);
    let body = json!({"device_record":d,"envelopes":envelopes,"admin_operation":op});
    let (s, r) = c
        .request("POST", &c.path("devices/enroll"), Some(&body), false)
        .await;
    assert_eq!(s, 201, "{r}");
    assert_eq!(r["status"], "pending_keys");
    let path = c.path("parameters");
    let t = token_for("GET", &path, b"", Some((subject, &subject_key)));
    assert_eq!(
        c.raw("GET", &path, vec![], Some(&t), VENDOR_MEDIA_TYPE)
            .await
            .0,
        200
    );
    let path = c.path("records");
    let t = token_for("GET", &path, b"", Some((subject, &subject_key)));
    assert_eq!(
        c.raw("GET", &path, vec![], Some(&t), VENDOR_MEDIA_TYPE)
            .await
            .1["code"],
        "DEVICE_PENDING_KEYS"
    );
    let (_, page) = c
        .request("GET", &c.path("devices?limit=1"), None, false)
        .await;
    let path = c.path(&format!("devices/{subject}/keys/ack"));
    let ack = json!({"epoch_hash":head["epoch_hash"],"epoch_commitment":c.genesis["epoch"]["epoch_commitment"]});
    let body = serde_json::to_vec(&ack).unwrap();
    let t = token_for("POST", &path, &body, Some((subject, &subject_key)));
    assert_eq!(
        c.raw("POST", &path, body, Some(&t), VENDOR_MEDIA_TYPE)
            .await
            .0,
        200
    );
    let (_, next) = c
        .request(
            "GET",
            &c.path(&format!(
                "devices?limit=1&cursor={}",
                page["next_cursor"].as_str().unwrap()
            )),
            None,
            false,
        )
        .await;
    assert_eq!(next["items"][0]["status"], "pending_keys");
    let (epoch, envelopes) = epoch_bundle(
        0,
        1,
        Some(object_hash(&c.genesis["epoch"])),
        &[subject],
        &[DEVICE],
        "device_revocation",
    );
    let target = json!({"epoch":epoch,"envelopes":envelopes});
    let op = admin(&head, "revoke_device", &target);
    let request = json!({"expected_epoch_hash":head["epoch_hash"],"epoch":epoch,"envelopes":envelopes,"admin_operation":op});
    let path = c.path(&format!("devices/{DEVICE}/revoke"));
    let (s, r) = c.request("POST", &path, Some(&request), false).await;
    assert_eq!(s, 200, "{r}");
    assert_eq!(r["status"], "revoked");
    assert_eq!(r["upload_receipts"].as_array().unwrap().len(), 4);
    assert_eq!(
        c.request("GET", &c.path("parameters"), None, true).await.1["code"],
        "DEVICE_REVOKED"
    );
    let (_, same) = c.request("POST", &path, Some(&request), false).await;
    assert_eq!(r, same);
    c.close().await;
}

#[tokio::test]
async fn epoch_cas_no_incomplete_visibility_and_old_duplicate_before_epoch_check() {
    let c = Context::new().await;
    let head = c.create().await;
    let r = record(0);
    c.request(
        "POST",
        &c.path("records"),
        Some(&json!({"records":[r]})),
        true,
    )
    .await;
    let previous = object_hash(&c.genesis["epoch"]);
    let (epoch, envelopes) = epoch_bundle(0, 1, Some(previous.clone()), &[DEVICE], &[], "manual");
    let mut broken = envelopes.clone();
    broken.pop();
    let body = json!({"expected_epoch_hash":previous,"epoch":epoch,"envelopes":broken,"admin_operation":null});
    let (s, _) = c
        .request("POST", &c.path("epochs"), Some(&body), false)
        .await;
    assert_eq!(s, 409);
    assert_eq!(
        c.request("GET", &c.path("log/head"), None, false).await.1["epoch_hash"],
        head["epoch_hash"]
    );
    let body = json!({"expected_epoch_hash":previous,"epoch":epoch,"envelopes":envelopes,"admin_operation":null});
    let (s, winner) = c
        .request("POST", &c.path("epochs"), Some(&body), false)
        .await;
    assert_eq!(s, 201, "{winner}");
    let (other, es) = epoch_bundle(0, 1, Some(previous.clone()), &[DEVICE], &[], "manual");
    let body =
        json!({"expected_epoch_hash":previous,"epoch":other,"envelopes":es,"admin_operation":null});
    assert_eq!(
        c.request("POST", &c.path("epochs"), Some(&body), false)
            .await
            .1["code"],
        "CAS_MISMATCH"
    );
    let (_, v) = c
        .request(
            "POST",
            &c.path("records"),
            Some(&json!({"records":[r,record(0)]})),
            true,
        )
        .await;
    assert_eq!(v["accepted"][0]["duplicate"], true);
    assert_eq!(v["rejected"][0]["code"], "EPOCH_STALE");
    c.close().await;
}

#[tokio::test]
async fn peer_request_is_offer_bound_and_never_auto_enrolls() {
    let c = Context::new().await;
    c.create().await;
    let id = store::new_id();
    let nonce = b([13; 32]);
    let expires = now() + 240000;
    let offer = json!({"request_id":id,"offer_nonce":nonce,"expires_at_ms":expires});
    assert_eq!(
        c.request("POST", &c.path("enrollment-offers"), Some(&offer), true)
            .await
            .0,
        201
    );
    let prospective = store::new_id();
    let req = sign(
        json!({"request_id":id,"chain_id":CHAIN,"generation":0,"device_id":prospective,"device_public_key":b(key(3).verifying_key().as_bytes()),"device_kex_public_key":kex(),"offer_nonce":nonce,"created_at_ms":now(),"expires_at_ms":expires}),
        &key(3),
        CTX_REQUEST,
    );
    let (s, r) = c
        .raw(
            "POST",
            &c.path("enrollment-requests"),
            serde_json::to_vec(&req).unwrap(),
            None,
            VENDOR_MEDIA_TYPE,
        )
        .await;
    assert_eq!(s, 201, "{r}");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM v3_registry")
        .fetch_one(&c.state.db.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let (_, page) = c
        .request("GET", &c.path("enrollment-requests"), None, true)
        .await;
    assert_eq!(page["items"][0]["request"], req);
    let (_, r) = c
        .request(
            "POST",
            &c.path(&format!("enrollment-requests/{id}/reject")),
            Some(&json!({"request_hash":object_hash(&req)})),
            true,
        )
        .await;
    assert_eq!(r["status"], "rejected");
    let unknown = sign(
        json!({"request_id":store::new_id(),"chain_id":CHAIN,"generation":0,"device_id":prospective,"device_public_key":b(key(3).verifying_key().as_bytes()),"device_kex_public_key":kex(),"offer_nonce":nonce,"created_at_ms":now(),"expires_at_ms":expires}),
        &key(3),
        CTX_REQUEST,
    );
    assert_eq!(
        c.raw(
            "POST",
            &c.path("enrollment-requests"),
            serde_json::to_vec(&unknown).unwrap(),
            None,
            VENDOR_MEDIA_TYPE
        )
        .await
        .1["code"],
        "OFFER_NOT_FOUND"
    );
    c.close().await;
}

async fn export_page(c: &Context, q: &str, device: bool) -> Vec<Value> {
    let path = c.path(q);
    let mut t = token("GET", &path, b"", device);
    t["aud"] = c.state.config.origin.clone().into();
    let t = sign(t, &key(if device { 2 } else { 1 }), CTX_CAPABILITY);
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header(
            "authorization",
            format!("PallaSync {}", b(jcs::canonicalize_json(&t).unwrap())),
        )
        .body(Body::empty())
        .unwrap();
    let r = c.router.clone().oneshot(req).await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(
        r.headers()["content-type"],
        "application/vnd.palleria.sync.export.v3+jsonl"
    );
    let bytes = to_bytes(r.into_body(), 8388608).await.unwrap();
    std::str::from_utf8(&bytes)
        .unwrap()
        .lines()
        .map(|s| jcs::parse(s.as_bytes()).unwrap())
        .collect()
}
#[tokio::test]
async fn export_resumes_both_pinned_cuts_and_device_exports_omit_recovery() {
    let c = Context::new().await;
    c.create().await;
    let mut all = export_page(&c, "export?limit=4&include_recovery=true", false).await;
    let header = all[0].clone();
    let late = record(0);
    c.request(
        "POST",
        &c.path("records"),
        Some(&json!({"records":[late]})),
        true,
    )
    .await;
    for _ in 0..20 {
        let cursor = all.last().unwrap()["next_cursor"]
            .as_str()
            .map(str::to_owned);
        let Some(cursor) = cursor else { break };
        let next = export_page(
            &c,
            &format!("export?limit=4&include_recovery=true&cursor={cursor}"),
            false,
        )
        .await;
        assert_eq!(next[0], header);
        all.pop();
        all.extend(next.into_iter().skip(1));
    }
    assert_eq!(all.last().unwrap()["has_more"], false);
    assert!(!all.iter().any(|v| v["entry"]["object"] == late));
    assert_eq!(
        all.iter().filter(|v| v["kind"] == "upload_receipt").count(),
        5
    );
    assert_eq!(
        all.iter()
            .filter(|v| v["kind"] == "transparency_entry")
            .count(),
        5
    );
    let d = export_page(&c, "export?limit=100", true).await;
    assert!(d.iter().any(|v| v["kind"] == "omitted"));
    assert!(
        !d.iter()
            .any(|v| v["entry"]["object"]["recipient_kind"] == "recovery")
    );
    assert_eq!(
        c.request("GET", &c.path("log"), None, true).await.1["code"],
        "ENVELOPE_ACCESS_DENIED"
    );
    assert_eq!(
        c.request(
            "GET",
            &c.path(&format!(
                "receipts/4?log_id={}",
                header["log_id"].as_str().unwrap()
            )),
            None,
            true
        )
        .await
        .1["code"],
        "ENVELOPE_ACCESS_DENIED"
    );
    c.close().await;
}

#[tokio::test]
async fn import_reseed_installs_fresh_pending_members_and_preserves_source_authority() {
    let source = Context::new().await;
    let source_head = source.create().await;
    for live in [false, true] {
        let base = config(None);
        let mut privacy = base.privacy.clone();
        privacy["relay_origin"] = "https://target.example.com".into();
        privacy["relay_key_id"] = hash_bytes(key(161).verifying_key().as_bytes()).into();
        sign_relay(&key(161), &mut privacy, CTX_PRIVACY).unwrap();
        let mut target = Context::configured(
            RelayConfig::new(key(161), (*base.markdown).clone(), privacy, None).unwrap(),
        )
        .await;
        let old_record = record(0);
        if live {
            target.genesis = source.genesis.clone();
            target.create().await;
            target
                .request(
                    "POST",
                    &target.path("records"),
                    Some(&json!({"records":[old_record]})),
                    true,
                )
                .await;
        }
        let history = json!({"parameters_history":[source.genesis["parameters"]],"epoch_history":[source.genesis["epoch"]],"device_history":[source.genesis["device_record"]],"envelopes":source.genesis["envelopes"],"compactions":[]});
        let (s, staged) = target
            .request("POST", "/pallasync/v3/chains/import", Some(&history), false)
            .await;
        assert_eq!(s, 202, "{staged}");
        assert_eq!(
            target
                .request("GET", &target.path("parameters"), None, false)
                .await
                .0,
            if live { 200 } else { 404 }
        );
        let fresh = "22222222-2222-4222-8222-222222222222";
        let d = device(fresh, &key(3), 1, 1, None);
        let mut p = source.genesis["parameters"].clone();
        p["generation"] = 1.into();
        p["previous_parameters_hash"] = object_hash(&source.genesis["parameters"]).into();
        p = sign(p, &key(1), CTX_PARAMETERS);
        let (epoch, envelopes) = epoch_bundle(
            1,
            1,
            Some(object_hash(&source.genesis["epoch"])),
            &[fresh],
            &[DEVICE],
            "reseed",
        );
        let mut part = record(1);
        part["generation"] = 1.into();
        part["device_id"] = fresh.into();
        part = sign(part, &key(3), CTX_SYNC_RECORD);
        let (s, r) = target
            .request(
                "POST",
                &target.path("snapshots/parts"),
                Some(&json!({"records":[part]})),
                false,
            )
            .await;
        assert_eq!(s, 200, "{r}");
        assert!(r["rejected"].as_array().unwrap().is_empty());
        let comp = sign(
            json!({"compaction_id":store::new_id(),"chain_id":CHAIN,"generation":1,"device_id":fresh,"log_id":staged["log_id"],"covered_through_seq":0,"covered_log_hash":store::initial_hash(b"PALLASYNC-LOG-v3\0",CHAIN,staged["log_id"].as_str().unwrap(),None),"epoch_hash":object_hash(&epoch),"snapshot_parts":[{"record_id":part["record_id"],"record_hash":object_hash(&part)}],"state_sha256":b([40;32])}),
            &key(3),
            CTX_COMPACTION,
        );
        let payload = json!({"parameters":p,"epoch":epoch,"envelopes":envelopes,"compaction":comp,"device_records":[d]});
        let op = admin(&source_head, "reseed", &payload);
        let mut payload = payload;
        payload["admin_operation"] = op;
        let (s, r) = target
            .request("PUT", &target.path("parameters"), Some(&payload), false)
            .await;
        assert_eq!(s, 200, "{r}");
        assert_eq!(r["log_id"], staged["log_id"]);
        assert_eq!(
            target
                .request("GET", &target.path("parameters"), None, true)
                .await
                .1["code"],
            "GENERATION_MISMATCH"
        );
        let (_, registry) = target
            .request("GET", &target.path("devices"), None, false)
            .await;
        assert_eq!(registry["items"][0]["status"], "revoked");
        assert_eq!(registry["items"][1]["status"], "pending_keys");
        if live {
            let archive =
                export_page(&target, "export?limit=100&include_recovery=true", false).await;
            assert!(
                archive.iter().any(|line| line["kind"] == "source_receipt"
                    && line["receipt"]["object"] == old_record)
            );
        }
        let (s, r) = target
            .request("PUT", &target.path("parameters"), Some(&payload), false)
            .await;
        assert_eq!(s, 200, "{r}");
        target.close().await;
    }
    source.close().await;
}

#[tokio::test]
async fn import_accepts_consecutive_history_chunks_with_a_fixed_terminal_head() {
    let source = Context::new().await;
    source.create().await;
    let base = config(None);
    let mut privacy = base.privacy.clone();
    privacy["relay_origin"] = "https://target.example.com".into();
    privacy["relay_key_id"] = hash_bytes(key(161).verifying_key().as_bytes()).into();
    sign_relay(&key(161), &mut privacy, CTX_PRIVACY).unwrap();
    let target = Context::configured(
        RelayConfig::new(key(161), (*base.markdown).clone(), privacy, None).unwrap(),
    )
    .await;

    let p0 = source.genesis["parameters"].clone();
    let mut p1 = p0.clone();
    p1["generation"] = 1.into();
    p1["previous_parameters_hash"] = object_hash(&p0).into();
    let p1 = sign(p1, &key(1), CTX_PARAMETERS);
    let mut p2 = p1.clone();
    p2["generation"] = 2.into();
    p2["previous_parameters_hash"] = object_hash(&p1).into();
    let p2 = sign(p2, &key(1), CTX_PARAMETERS);
    let fixed_epoch = source.genesis["epoch"].clone();
    let other = json!({
        "epoch_history": [fixed_epoch],
        "device_history": [source.genesis["device_record"]],
        "envelopes": source.genesis["envelopes"],
        "compactions": [],
    });

    let mut first = other.clone();
    first["parameters_history"] = json!([p0.clone(), p2.clone()]);
    let (status, staged_first) = target
        .request("POST", "/pallasync/v3/chains/import", Some(&first), false)
        .await;
    assert_eq!(status, 202, "{staged_first}");

    let mut second = other;
    second["parameters_history"] = json!([p1, p2]);
    let (status, staged_second) = target
        .request("POST", "/pallasync/v3/chains/import", Some(&second), false)
        .await;
    assert_eq!(status, 202, "{staged_second}");
    assert_eq!(staged_first["log_id"], staged_second["log_id"]);
    target.close().await;

    let mut bad_privacy = base.privacy.clone();
    bad_privacy["relay_origin"] = "https://target.example.com".into();
    bad_privacy["relay_key_id"] = hash_bytes(key(161).verifying_key().as_bytes()).into();
    sign_relay(&key(161), &mut bad_privacy, CTX_PRIVACY).unwrap();
    let bad_target = Context::configured(
        RelayConfig::new(key(161), (*base.markdown).clone(), bad_privacy, None).unwrap(),
    )
    .await;
    let mut invalid_head = p1.clone();
    invalid_head["generation"] = 2.into();
    invalid_head["previous_parameters_hash"] = object_hash(&p0).into();
    let invalid_head = sign(invalid_head, &key(1), CTX_PARAMETERS);
    let mut invalid_first = json!({
        "parameters_history": [p0, invalid_head.clone()],
        "epoch_history": [source.genesis["epoch"]],
        "device_history": [source.genesis["device_record"]],
        "envelopes": source.genesis["envelopes"],
        "compactions": [],
    });
    let (status, _) = bad_target
        .request(
            "POST",
            "/pallasync/v3/chains/import",
            Some(&invalid_first),
            false,
        )
        .await;
    assert_eq!(status, 202);
    invalid_first["parameters_history"] = json!([p1, invalid_head]);
    let (status, response) = bad_target
        .request(
            "POST",
            "/pallasync/v3/chains/import",
            Some(&invalid_first),
            false,
        )
        .await;
    assert_eq!(status, 409, "{response}");
    assert_eq!(response["code"], "IMPORT_CONFLICT");
    bad_target.close().await;
    source.close().await;
}

#[tokio::test]
async fn policy_signature_schema_limits_and_restart_barrier_are_enforced() {
    let base = config(None);
    let mut invalid = base.privacy.clone();
    invalid["limits"]["page_limit"] = 1001.into();
    sign_relay(&key(160), &mut invalid, CTX_PRIVACY).unwrap();
    assert!(RelayConfig::new(key(160), (*base.markdown).clone(), invalid, None).is_err());
    let mut invalid = base.privacy.clone();
    invalid["operator"]["contact_url"] = "https://user:secret@example.com/".into();
    sign_relay(&key(160), &mut invalid, CTX_PRIVACY).unwrap();
    assert!(RelayConfig::new(key(160), (*base.markdown).clone(), invalid, None).is_err());
    let mut privacy = base.privacy.clone();
    privacy["replay_protection"] = json!({"mode":"restart_barrier","barrier_offset_ms":60000,"clock_skew_ms":60000,"coordination":"Shared SQLite barrier","recovery":"Fresh token with corrected time after indicated barrier"});
    sign_relay(&key(160), &mut privacy, CTX_PRIVACY).unwrap();
    let c = Context::configured(
        RelayConfig::new(key(160), (*base.markdown).clone(), privacy, None).unwrap(),
    )
    .await;
    let barrier: i64 = sqlx::query_scalar("SELECT barrier_ms FROM v3_restart_barrier")
        .fetch_one(&c.state.db.pool)
        .await
        .unwrap();
    let body = serde_json::to_vec(&c.genesis).unwrap();
    let mut t = token("POST", "/pallasync/v3/chains", &body, false);
    t["issued_at_ms"] = (barrier - 1).into();
    t["expires_at_ms"] = (barrier + 120000).into();
    let t = sign(t, &key(1), CTX_CAPABILITY);
    assert_eq!(
        c.raw(
            "POST",
            "/pallasync/v3/chains",
            body.clone(),
            Some(&t),
            VENDOR_MEDIA_TYPE
        )
        .await
        .1["code"],
        "TOKEN_NOT_YET_VALID"
    );
    let mut t = token("POST", "/pallasync/v3/chains", &body, false);
    t["issued_at_ms"] = barrier.into();
    t["expires_at_ms"] = (barrier + 120000).into();
    let t = sign(t, &key(1), CTX_CAPABILITY);
    assert_eq!(
        c.raw(
            "POST",
            "/pallasync/v3/chains",
            body,
            Some(&t),
            VENDOR_MEDIA_TYPE
        )
        .await
        .0,
        201
    );
    c.close().await;
}

#[tokio::test]
async fn old_envelopes_expire_only_after_current_snapshot_and_admin_handoff() {
    for profile in ["retain", "windowed", "immediate"] {
        let mut c = Context::new().await;
        let mut p = c.genesis["parameters"].clone();
        p["policy"]["epoch_retention"] = profile.into();
        p["policy"]["epoch_window_ms"] = 1.into();
        c.genesis["parameters"] = sign(p, &key(1), CTX_PARAMETERS);
        let initial = c.create().await;
        let (epoch, envelopes) = epoch_bundle(
            0,
            1,
            Some(object_hash(&c.genesis["epoch"])),
            &[DEVICE],
            &[],
            "manual",
        );
        let body = json!({"epoch":epoch,"envelopes":envelopes,"expected_epoch_hash":initial["epoch_hash"],"admin_operation":null});
        let (s, v) = c
            .request("POST", &c.path("epochs"), Some(&body), false)
            .await;
        assert_eq!(s, 201, "{v}");
        // Eligibility time alone cannot destroy an old key; no safe handoff exists yet.
        pallasync_server::api::retention::maintenance(&c.state.db, &c.state.config)
            .await
            .unwrap();
        assert_eq!(
            c.request("GET", &c.path("epochs/0/recovery-envelope"), None, false)
                .await
                .0,
            200
        );
        let event = record(1);
        assert_eq!(
            c.request(
                "POST",
                &c.path("records"),
                Some(&json!({"records":[event]})),
                true
            )
            .await
            .0,
            200
        );
        let part = record(1);
        let (s, v) = c
            .request(
                "POST",
                &c.path("snapshots/parts"),
                Some(&json!({"records":[part]})),
                true,
            )
            .await;
        assert_eq!(s, 200, "{v}");
        let (_, head) = c.request("GET", &c.path("log/head"), None, false).await;
        let comp = sign(
            json!({"compaction_id":store::new_id(),"chain_id":CHAIN,"generation":0,"device_id":DEVICE,"log_id":head["log_id"],"covered_through_seq":head["head_seq"],"covered_log_hash":head["head_hash"],"epoch_hash":object_hash(&epoch),"snapshot_parts":[{"record_id":part["record_id"],"record_hash":object_hash(&part)}],"state_sha256":b([40;32])}),
            &key(2),
            CTX_COMPACTION,
        );
        let (s, v) = c
            .request(
                "POST",
                &c.path("snapshots"),
                Some(&json!({"compaction":comp})),
                true,
            )
            .await;
        assert_eq!(s, 201, "{v}");
        assert_eq!(
            c.request("GET", &c.path("epochs/0/recovery-envelope"), None, false)
                .await
                .0,
            200
        );
        let target = json!({"compaction_id":comp["compaction_id"],"through_seq":head["head_seq"]});
        let mut body = target.clone();
        body["admin_operation"] = admin(&head, "prune_log", &target);
        let (s, v) = c
            .request("POST", &c.path("log/prune"), Some(&body), false)
            .await;
        assert_eq!(s, 200, "{v}");
        let (s, v) = c
            .request("GET", &c.path("epochs/0/recovery-envelope"), None, false)
            .await;
        if profile == "retain" {
            assert_eq!(s, 200, "{v}");
        } else {
            assert_eq!(v["code"], "HISTORY_KEY_EXPIRED");
            let old: i64=sqlx::query_scalar("SELECT COUNT(*) FROM v3_objects WHERE kind='envelope' AND json_extract(body,'$.epoch')=0").fetch_one(&c.state.db.pool).await.unwrap();
            assert_eq!(old, 0);
        }
        assert_eq!(
            c.request("GET", &c.path("epochs/1/recovery-envelope"), None, false)
                .await
                .0,
            200
        );
        let lines = export_page(&c, "export?limit=100&include_recovery=true", false).await;
        let kinds: Vec<_> = lines
            .iter()
            .map(|v| wire::s(v, "kind"))
            .filter(|k| {
                [
                    "boundary",
                    "compaction",
                    "control",
                    "removed_id",
                    "snapshot_part",
                ]
                .contains(k)
            })
            .collect();
        assert!(kinds.windows(2).all(|pair| pair[0] <= pair[1]), "{kinds:?}");
        assert!(kinds.contains(&"boundary"));
        assert!(kinds.contains(&"removed_id"));
        c.close().await;
    }
}

#[tokio::test]
async fn published_notice_and_write_freeze_preserve_read_export_and_token_consumption() {
    let mut c = Context::new().await;
    c.create().await;
    let (_, old_head) = c.request("GET", &c.path("log/head"), None, false).await;
    let (_, old_t) = c
        .request("GET", &c.path("transparency/head"), None, false)
        .await;
    let mut cfg = (*c.state.config).clone();
    cfg.shutdown_at_ms = Some(now() + 2592000000);
    cfg.migration_origin = Some("https://target.example.com".into());
    cfg.stop_writes = true;
    c.state = AppState::new(c.state.db.clone(), cfg).await.unwrap();
    c.router = app(c.state.clone());
    let (s, notice) = c.request("GET", &c.path("relay-notice"), None, false).await;
    assert_eq!(s, 200);
    assert_eq!(notice["migration_origin"], "https://target.example.com");
    assert_eq!(
        c.request("GET", &c.path("log/head"), None, false).await.1,
        old_head
    );
    let (_, t) = c
        .request("GET", &c.path("transparency/head"), None, false)
        .await;
    assert_eq!(
        wire::n(&t["head"], "entry_index"),
        wire::n(&old_t["head"], "entry_index") + 1
    );
    let latest: String =
        sqlx::query_scalar("SELECT entry FROM v3_transparency ORDER BY idx DESC LIMIT 1")
            .fetch_one(&c.state.db.pool)
            .await
            .unwrap();
    let latest = store::value(latest);
    assert_eq!(latest["operation"], "migrate");
    assert_eq!(latest["object_hash"], object_hash(&notice));
    let path = c.path("records");
    let body = serde_json::to_vec(&json!({"records":[record(0)]})).unwrap();
    let token = token("POST", &path, &body, true);
    assert_eq!(
        c.raw("POST", &path, body.clone(), Some(&token), VENDOR_MEDIA_TYPE)
            .await
            .0,
        503
    );
    assert_eq!(
        c.raw("POST", &path, body, Some(&token), VENDOR_MEDIA_TYPE)
            .await
            .1["code"],
        "TOKEN_REPLAYED"
    );
    assert!(
        !export_page(&c, "export?limit=100&include_recovery=true", false)
            .await
            .is_empty()
    );
    c.close().await;
}

#[tokio::test]
async fn malformed_authenticated_body_consumes_nonce_and_utf8_media_type_is_supported() {
    let c = Context::new().await;
    c.create().await;
    let path = c.path("records");
    let body = b"{\"records\": [".to_vec();
    let t = token("POST", &path, &body, true);
    assert_eq!(
        c.raw("POST", &path, body.clone(), Some(&t), VENDOR_MEDIA_TYPE)
            .await
            .1["code"],
        "INVALID_JSON"
    );
    assert_eq!(
        c.raw("POST", &path, body, Some(&t), VENDOR_MEDIA_TYPE)
            .await
            .1["code"],
        "TOKEN_REPLAYED"
    );
    let body = serde_json::to_vec(&json!({"records":[record(0)]})).unwrap();
    let t = token("POST", &path, &body, true);
    let (s, v) = c
        .raw(
            "POST",
            &path,
            body,
            Some(&t),
            "application/vnd.palleria.sync.v3+json; charset=UTF-8",
        )
        .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["accepted"].as_array().unwrap().len(), 1);
    c.close().await;
}

#[tokio::test]
async fn capacity_failure_after_one_item_returns_its_durable_original_receipt() {
    let mut c = Context::new().await;
    c.create().await;
    let before = store::used(&mut c.state.db.pool.acquire().await.unwrap(), CHAIN)
        .await
        .unwrap();
    c.request(
        "POST",
        &c.path("records"),
        Some(&json!({"records":[record(0)]})),
        true,
    )
    .await;
    let used = store::used(&mut c.state.db.pool.acquire().await.unwrap(), CHAIN)
        .await
        .unwrap();
    let mut cfg = (*c.state.config).clone();
    cfg.max_bytes = Some(used + (used - before) + 128);
    c.state.config = std::sync::Arc::new(cfg);
    c.router = app(c.state.clone());
    let first = record(0);
    let second = record(0);
    let (s, v) = c
        .request(
            "POST",
            &c.path("records"),
            Some(&json!({"records":[first,second]})),
            true,
        )
        .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["accepted"].as_array().unwrap().len(), 1);
    assert_eq!(v["rejected"][0]["code"], "QUOTA_EXCEEDED");
    assert_eq!(v["upload_receipts"].as_array().unwrap().len(), 1);
    let (s, retry) = c
        .request(
            "POST",
            &c.path("records"),
            Some(&json!({"records":[first]})),
            true,
        )
        .await;
    assert_eq!(s, 200, "{retry}");
    assert_eq!(retry["accepted"][0]["duplicate"], true);
    assert_eq!(retry["upload_receipts"], v["upload_receipts"]);
    c.close().await;
}

#[tokio::test]
async fn over_quota_enrollment_request_rolls_back_candidate_but_keeps_rate_accounting() {
    let mut c = Context::new().await;
    c.create().await;
    let id = store::new_id();
    let nonce = b([13; 32]);
    let expires = now() + 240000;
    let offer = json!({"request_id":id,"offer_nonce":nonce,"expires_at_ms":expires});
    assert_eq!(
        c.request("POST", &c.path("enrollment-offers"), Some(&offer), true)
            .await
            .0,
        201
    );
    let used = store::used(&mut c.state.db.pool.acquire().await.unwrap(), CHAIN)
        .await
        .unwrap();
    let mut cfg = (*c.state.config).clone();
    cfg.max_bytes = Some(used + 50);
    c.state.config = std::sync::Arc::new(cfg);
    c.router = app(c.state.clone());
    let req = sign(
        json!({"request_id":id,"chain_id":CHAIN,"generation":0,"device_id":store::new_id(),"device_public_key":b(key(3).verifying_key().as_bytes()),"device_kex_public_key":kex(),"offer_nonce":nonce,"created_at_ms":now(),"expires_at_ms":expires}),
        &key(3),
        CTX_REQUEST,
    );
    let (s, v) = c
        .raw(
            "POST",
            &c.path("enrollment-requests"),
            serde_json::to_vec(&req).unwrap(),
            None,
            VENDOR_MEDIA_TYPE,
        )
        .await;
    assert_eq!(s, 507, "{v}");
    assert_eq!(v["code"], "QUOTA_EXCEEDED");
    let stored: Option<String> =
        sqlx::query_scalar("SELECT request FROM v3_offers WHERE request_id=?")
            .bind(id)
            .fetch_one(&c.state.db.pool)
            .await
            .unwrap();
    assert!(stored.is_none());
    let rates: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM v3_rates WHERE scope='enrollment_offer'")
            .fetch_one(&c.state.db.pool)
            .await
            .unwrap();
    assert_eq!(rates, 1);
    c.close().await;
}

fn legacy_token(path: &str, nonce: u8) -> Value {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    sign(
        json!({"v":1,"chain_id":CHAIN,"device_id":DEVICE,"method":"GET","path":path,"query":query,
        "body_sha256":hash_bytes(b""),"issued_at_ms":now(),"expires_at_ms":now()+300000,
        "nonce":b([nonce;16])}),
        &key(2),
        b"PALLASYNC-CAPABILITY-v2.1\0",
    )
}

#[tokio::test]
async fn frozen_legacy_pages_obey_operator_byte_limits_without_skipping_archived_rows() {
    let mut cfg = config(None);
    cfg.privacy["limits"]["max_request_bytes"] = 8192.into();
    sign_relay(&key(160), &mut cfg.privacy, CTX_PRIVACY).unwrap();
    let cfg = RelayConfig::new(key(160), (*cfg.markdown).clone(), cfg.privacy, None).unwrap();
    let c = Context::configured(cfg).await;
    frozen_fixture(&c).await;
    let mut after = 0;
    let mut pages = 0;
    loop {
        let path = format!("/pallasync/v2/chains/{CHAIN}/records?after_seq={after}&limit=200");
        pages += 1;
        let (status, _, bytes) =
            legacy_request(&c.router, "GET", &path, Some(&legacy_token(&path, pages))).await;
        assert_eq!(status, 200);
        assert!(bytes.len() <= 8192);
        let value = jcs::parse(&bytes).unwrap();
        let records = value["records"].as_array().unwrap();
        assert!(!records.is_empty());
        for record in records {
            after += 1;
            assert_eq!(record["server_sequence"], after);
        }
        if value["next_cursor"].is_null() {
            break;
        }
    }
    assert_eq!(after, 201);
    assert!(pages > 1);
    sqlx::query("UPDATE sync_records SET encrypted_payload=? WHERE server_sequence=1")
        .bind("A".repeat(9000))
        .execute(&c.state.db.pool)
        .await
        .unwrap();
    let path = format!("/pallasync/v2/chains/{CHAIN}/records?after_seq=0&limit=1");
    assert_eq!(
        legacy_request(&c.router, "GET", &path, Some(&legacy_token(&path, 99)))
            .await
            .0,
        413
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sync_records")
        .fetch_one(&c.state.db.pool)
        .await
        .unwrap();
    assert_eq!(count, 201);
    c.close().await;
}

async fn legacy_request(
    router: &axum::Router,
    method: &str,
    path: &str,
    token: Option<&Value>,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        req = req.header(
            "authorization",
            format!("PallaSync {}", b(jcs::canonicalize_json(token).unwrap())),
        );
    }
    let out = router
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let (parts, body) = out.into_parts();
    let body = to_bytes(body, 8 * 1024 * 1024).await.unwrap().to_vec();
    assert_eq!(parts.headers["cache-control"], "no-store");
    assert!(parts.headers.contains_key("date"));
    assert!(!parts.headers.contains_key("x-pallasync-protocol"));
    (parts.status, parts.headers, body)
}

async fn frozen_fixture(c: &Context) {
    sqlx::raw_sql(include_str!("fixtures/frozen-v2-schema.sql"))
        .execute(&c.state.db.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO chains(chain_id,chain_salt,admin_public_key,created_at_ms,creator_device_id,creator_public_key) VALUES(?,?,?,0,?,?)")
        .bind(CHAIN).bind(b([9;32])).bind(b(key(1).verifying_key().as_bytes())).bind(DEVICE).bind(b(key(2).verifying_key().as_bytes())).execute(&c.state.db.pool).await.unwrap();
    sqlx::query("INSERT INTO devices(chain_id,device_id,device_public_key,encrypted_device_name,device_name_nonce,status,created_at_ms,updated_at_ms,signature) VALUES(?,?,?,?,?,'active',0,0,?)")
        .bind(CHAIN).bind(DEVICE).bind(b(key(2).verifying_key().as_bytes())).bind(b([4;80])).bind(b([5;24])).bind(b([6;64])).execute(&c.state.db.pool).await.unwrap();
    let mut tx = c.state.db.pool.begin().await.unwrap();
    for index in 1..=201 {
        // Opaque archived ciphertext. This test does not claim legacy AEAD/provenance validation.
        sqlx::query("INSERT INTO sync_records(chain_id,record_id,protocol_version,epoch,collection_name,action,encrypted_payload,payload_nonce,device_id,lamport,created_at_ms,signature) VALUES(?,?,'2.1',0,'palleria.search_history/2','upsert',?,?,?,1,0,?)")
            .bind(CHAIN).bind(format!("01990000-0000-7000-8000-{index:012x}")).bind(b([7;80])).bind(b([8;24])).bind(DEVICE).bind(b([9;64])).execute(&mut *tx).await.unwrap();
    }
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn frozen_legacy_is_bounded_context_separated_and_preserves_nonce_on_restart() {
    let c = Context::with_quota(None).await;
    frozen_fixture(&c).await;
    let path = format!("/pallasync/v2/chains/{CHAIN}/records?after_seq=0&limit=200");
    let token = legacy_token(&path, 41);
    let (status, headers, bytes) = legacy_request(&c.router, "GET", &path, Some(&token)).await;
    assert_eq!(status, 200);
    assert_eq!(headers["pallasync-next-seq"], "200");
    assert_eq!(headers["pallasync-has-more"], "true");
    let first = jcs::parse(&bytes).unwrap();
    assert_eq!(first["records"].as_array().unwrap().len(), 200);
    assert_eq!(first["next_cursor"], "200");
    assert_eq!(first["records"][0]["protocol_version"], "2.1");
    assert_eq!(first["records"][0]["encrypted_payload"], b([7; 80]));
    let second_path = format!("/pallasync/v2/chains/{CHAIN}/records?cursor=200&limit=200");
    let (status, headers, bytes) = legacy_request(
        &c.router,
        "GET",
        &second_path,
        Some(&legacy_token(&second_path, 42)),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(headers["pallasync-has-more"], "false");
    assert_eq!(
        jcs::parse(&bytes).unwrap()["records"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let wrong = sign(token.clone(), &key(2), CTX_CAPABILITY);
    assert_eq!(
        legacy_request(&c.router, "GET", &path, Some(&wrong))
            .await
            .0,
        401
    );
    assert_eq!(legacy_request(&c.router, "POST", &path, None).await.0, 405);
    let query_changed = format!("/pallasync/v2/chains/{CHAIN}/records?after_seq=1&limit=200");
    assert_eq!(
        legacy_request(&c.router, "GET", &query_changed, Some(&token))
            .await
            .0,
        401
    );
    let cfg = (*c.state.config).clone();
    c.state.db.pool.close().await;
    let db = db::init_db_with_url(&format!(
        "sqlite:{}",
        c.path.to_string_lossy().replace('\\', "/")
    ))
    .await
    .unwrap();
    let restarted = AppState::new(db, cfg).await.unwrap();
    let router = app(restarted.clone());
    assert_eq!(
        legacy_request(&router, "GET", &path, Some(&token)).await.0,
        401
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sync_records")
        .fetch_one(&restarted.db.pool)
        .await
        .unwrap();
    assert_eq!(count, 201);
    restarted.db.pool.close().await;
    c.close().await;
}

#[tokio::test]
async fn missing_legacy_parameters_are_not_fabricated_and_explicit_legacy_delete_cannot_delete_v3()
{
    let c = Context::with_quota(None).await;
    c.create().await;
    frozen_fixture(&c).await;
    let parameters = format!("/pallasync/v2/chains/{CHAIN}/parameters");
    let (status, _, body) = legacy_request(&c.router, "GET", &parameters, None).await;
    assert_eq!(status, 500);
    assert!(body.is_empty());
    // Archive/return original public input only; its undefined legacy signature context
    // is not certified by this storage test or reused as v3 authority.
    let original = json!({"protocol_version":"2.1","chain_id":CHAIN,"chain_salt":b([9;32]),"created_at_ms":0,
        "creator_device_id":DEVICE,"creator_public_key":b(key(2).verifying_key().as_bytes()),
        "admin_public_key":b(key(1).verifying_key().as_bytes()),"signature":b([10;64])});
    pallasync_server::api::legacy::retain_parameters(
        &c.state.db,
        &jcs::canonicalize_json(&original).unwrap(),
    )
    .await
    .unwrap();
    pallasync_server::api::legacy::retain_parameters(
        &c.state.db,
        &serde_json::to_vec_pretty(&original).unwrap(),
    )
    .await
    .unwrap();
    let (status, _, body) = legacy_request(&c.router, "GET", &parameters, None).await;
    assert_eq!(status, 200);
    assert_eq!(jcs::parse(&body).unwrap(), original);
    let mut mismatch = original.clone();
    mismatch["chain_salt"] = b([8; 32]).into();
    assert!(
        pallasync_server::api::legacy::retain_parameters(
            &c.state.db,
            &jcs::canonicalize_json(&mismatch).unwrap()
        )
        .await
        .is_err()
    );
    mismatch = original.clone();
    mismatch["signature"] = b([11; 64]).into();
    assert!(
        pallasync_server::api::legacy::retain_parameters(
            &c.state.db,
            &jcs::canonicalize_json(&mismatch).unwrap()
        )
        .await
        .is_err()
    );
    let path = format!("/pallasync/v2/chains/{CHAIN}");
    let mut token = legacy_token(&path, 43);
    token["method"] = "DELETE".into();
    token = sign(token, &key(2), b"PALLASYNC-CAPABILITY-v2.1\0");
    assert_eq!(
        legacy_request(&c.router, "DELETE", &path, Some(&token))
            .await
            .0,
        200
    );
    assert_eq!(
        legacy_request(&c.router, "GET", &parameters, None).await.0,
        410
    );
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sync_records")
        .fetch_one(&c.state.db.pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);
    let modern: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM v3_chains")
        .fetch_one(&c.state.db.pool)
        .await
        .unwrap();
    assert_eq!(modern, 1);
    assert_eq!(
        c.request("GET", &c.path("log/head"), None, true).await.0,
        200
    );
    c.close().await;
}
