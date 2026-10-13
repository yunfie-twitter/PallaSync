//! Exhaustive §10 endpoint catalogue. Raw method/path/query/body reach token validation unchanged.
use super::{
    auth::{self, Auth},
    batch, deletion,
    error::*,
    export, import, mutation, read,
    store::{self, Chain},
    wire::*,
};
use crate::{
    config::RelayConfig,
    crypto::{jcs, verify::*},
    db::DbState,
};
use axum::{
    body::{Body, to_bytes},
    extract::{ConnectInfo, State},
    http::{Request, Response, StatusCode, header},
    response::IntoResponse,
};
use serde_json::{Value, json};
use sqlx::Row;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::{Mutex, Semaphore};
pub const VENDOR_MEDIA_TYPE: &str = "application/vnd.palleria.sync.v3+json";
pub const EXPORT_MEDIA_TYPE: &str = "application/vnd.palleria.sync.export.v3+jsonl";
#[derive(Clone)]
pub struct AppState {
    pub db: DbState,
    pub config: Arc<RelayConfig>,
    pub transfers: Arc<Mutex<HashMap<String, Arc<Semaphore>>>>,
}
impl AppState {
    pub async fn new(db: DbState, config: RelayConfig) -> Result<Self> {
        if db.resolved_path == ":memory:" { /* Only test callers use in-memory storage; main refuses it. */
        }
        let mut tx = db.pool.begin_with("BEGIN IMMEDIATE").await?;
        if config.privacy["replay_protection"]["mode"] == "restart_barrier" {
            sqlx::query("INSERT INTO v3_restart_barrier(id,barrier_ms) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET barrier_ms=MAX(barrier_ms,excluded.barrier_ms)").bind((now()+60000) as i64).execute(&mut *tx).await?;
        }
        if let Some(row) = sqlx::query(
            "SELECT origin,relay_key_id,revision,disclosure_hash FROM v3_operator WHERE id=1",
        )
        .fetch_optional(&mut *tx)
        .await?
            && (row.get::<String, _>("origin") != config.origin
                || row.get::<String, _>("relay_key_id") != config.key_id
                || row.get::<i64, _>("revision") as u64 > n(&config.privacy, "revision")
                || (row.get::<i64, _>("revision") as u64 == n(&config.privacy, "revision")
                    && row.get::<String, _>("disclosure_hash") != object_hash(&config.privacy)))
        {
            return Err(err("INVALID_FIELD"));
        }
        sqlx::query("INSERT INTO v3_operator(id,origin,relay_key_id,revision,disclosure_hash) VALUES(1,?,?,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,disclosure_hash=excluded.disclosure_hash").bind(&config.origin).bind(&config.key_id).bind(n(&config.privacy,"revision") as i64).bind(object_hash(&config.privacy)).execute(&mut *tx).await?;
        tx.commit().await?;
        deletion::complete(&db, &config).await?;
        let mut tx = db.pool.begin_with("BEGIN IMMEDIATE").await?;
        let ids:Vec<String>=sqlx::query_scalar("SELECT chain_id FROM v3_chains WHERE chain_id NOT IN (SELECT chain_id FROM v3_deletions)").fetch_all(&mut *tx).await?;
        for id in ids {
            if let Some(mut c) = store::load(&mut tx, &id).await? {
                store::publish_notice(&mut tx, &mut c, &config).await?;
                store::save(&mut tx, &c, &config).await?;
            }
        }
        tx.commit().await?;
        Ok(Self {
            db,
            config: Arc::new(config),
            transfers: Arc::new(Mutex::new(HashMap::new())),
        })
    }
}
struct Endpoint {
    route: &'static str,
    chain: String,
    param: String,
    allow: &'static str,
}
fn endpoint(path: &str, method: &str) -> Result<Endpoint> {
    let parts: Vec<_> = path
        .strip_prefix("/pallasync/v3/")
        .ok_or_else(|| err("ENDPOINT_NOT_FOUND"))?
        .split('/')
        .collect();
    let (route, chain, param, allow) = match parts.as_slice() {
        ["health"] => ("health", "", "", "GET"),
        ["chains"] => ("genesis", "", "", "POST"),
        ["chains", "import"] => ("import", "", "", "POST"),
        ["chains", c] => ("delete", *c, "", "DELETE"),
        ["chains", c, "parameters"] => (
            if method == "PUT" {
                "reseed"
            } else {
                "parameters_get"
            },
            *c,
            "",
            "GET, PUT",
        ),
        ["chains", c, "devices", "enroll"] => ("enroll", *c, "", "POST"),
        ["chains", c, "devices"] => ("devices", *c, "", "GET"),
        ["chains", c, "devices", d, "revoke"] => ("revoke", *c, *d, "POST"),
        ["chains", c, "devices", d, "envelopes"] => ("own_envelopes", *c, *d, "GET"),
        ["chains", c, "devices", d, "keys", "ack"] => ("ack", *c, *d, "POST"),
        ["chains", c, "records"] => (
            if method == "POST" {
                "records_post"
            } else {
                "records_get"
            },
            *c,
            "",
            "GET, POST",
        ),
        ["chains", c, "records", "repair"] => ("repair", *c, "", "POST"),
        ["chains", c, "enrollment-offers"] => ("offer", *c, "", "POST"),
        ["chains", c, "enrollment-requests"] => (
            if method == "POST" {
                "request"
            } else {
                "requests_get"
            },
            *c,
            "",
            "GET, POST",
        ),
        ["chains", c, "enrollment-requests", id, "approve"] => ("approve", *c, *id, "POST"),
        ["chains", c, "enrollment-requests", id, "reject"] => ("reject", *c, *id, "POST"),
        ["chains", c, "epochs"] => (
            if method == "POST" {
                "epochs_post"
            } else {
                "epochs_get"
            },
            *c,
            "",
            "GET, POST",
        ),
        ["chains", c, "epochs", id] => ("epoch_get", *c, *id, "GET"),
        ["chains", c, "epochs", id, "recovery-envelope"] => ("recovery", *c, *id, "GET"),
        ["chains", c, "epochs", id, "envelopes"] => ("envelopes_post", *c, *id, "POST"),
        ["chains", c, "log"] => ("log", *c, "", "GET"),
        ["chains", c, "log", "head"] => ("head", *c, "", "GET"),
        ["chains", c, "log", "prune"] => ("prune", *c, "", "POST"),
        ["chains", c, "snapshots"] => (
            if method == "POST" {
                "snapshot"
            } else {
                "snapshots_get"
            },
            *c,
            "",
            "GET, POST",
        ),
        ["chains", c, "snapshots", "parts"] => ("parts_post", *c, "", "POST"),
        ["chains", c, "snapshots", "parts", id] => ("part_get", *c, *id, "GET"),
        ["chains", c, "snapshots", id] => ("snapshot_get", *c, *id, "GET"),
        ["chains", c, "export"] => ("export", *c, "", "GET"),
        ["chains", c, "relay-notice"] => ("notice", *c, "", "GET"),
        ["chains", c, "deletion"] => ("deletion", *c, "", "GET"),
        ["chains", c, "receipts", id] => ("receipt", *c, *id, "GET"),
        ["chains", c, "transparency", "head"] => ("transparency_head", *c, "", "GET"),
        ["chains", c, "transparency", "entries"] => ("transparency", *c, "", "GET"),
        _ => return Err(err("ENDPOINT_NOT_FOUND")),
    };
    if !allow.split(", ").any(|m| m == method) {
        return Err(err("METHOD_NOT_ALLOWED"));
    }
    if !chain.is_empty() {
        decode(chain, Some(32)).map_err(|_| err("INVALID_FIELD"))?;
    }
    let mut parameter = param.to_owned();
    if !param.is_empty() {
        if matches!(
            route,
            "epoch_get" | "recovery" | "envelopes_post" | "receipt"
        ) {
            parameter = read::decimal(
                param,
                if route == "receipt" { 1 } else { 0 },
                if route == "receipt" {
                    jcs::MAX_INTEGER
                } else {
                    u32::MAX as u64
                },
            )?
            .to_string();
        } else if !uuid(param) {
            return Err(err("INVALID_FIELD"));
        }
    }
    Ok(Endpoint {
        route,
        chain: chain.into(),
        param: parameter,
        allow,
    })
}
pub async fn handle(State(state): State<AppState>, request: Request<Body>) -> Response<Body> {
    if super::legacy::is_legacy(request.uri().path()) {
        return super::legacy::handle(&state, request).await;
    }
    let mut transfer_permit = None;
    let uri = request.uri().clone();
    let method = request.method().clone();
    let path = uri.path().to_owned();
    let source = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip().to_string())
        .unwrap_or_else(|| "local".into());
    let (parts, body) = request.into_parts();
    let result = async {
        let max = n(state.config.limits(), "max_request_bytes") as usize;
        let body = tokio::time::timeout(Duration::from_secs(30), to_bytes(body, max))
            .await
            .map_err(|_| err("REQUEST_TIMEOUT"))?
            .map_err(|_| err("PAYLOAD_TOO_LARGE"))?;
        if parts
            .headers
            .get(header::CONTENT_ENCODING)
            .is_some_and(|h| !h.to_str().is_ok_and(|h| h.eq_ignore_ascii_case("identity")))
        {
            return Err(err("INVALID_FIELD"));
        }
        let q = canonical_query(uri.query().unwrap_or(""))?;
        if matches!(path.as_str(), "/privacy.md" | "/privacy.json") {
            if method != "GET" {
                return Err(err("METHOD_NOT_ALLOWED"));
            }
            if !q.is_empty() || !body.is_empty() {
                return Err(err("INVALID_FIELD"));
            }
            let mut tx = state.db.pool.begin_with("BEGIN IMMEDIATE").await?;
            let limited = auth::rate(
                &mut tx,
                &state.config,
                "public_document_ip",
                &hash_bytes(source.as_bytes()),
            )
            .await;
            tx.commit().await?;
            limited?;
            return Ok(if path == "/privacy.md" {
                raw_response(
                    200,
                    "text/markdown;charset=utf-8",
                    (*state.config.markdown).clone(),
                )
            } else {
                raw_response(
                    200,
                    "application/json",
                    jcs::canonicalize_json(&state.config.privacy).unwrap(),
                )
            });
        }
        let mut ep = endpoint(&path, method.as_str())?;
        if ep.route == "health" {
            if !q.is_empty() || !body.is_empty() {
                return Err(err("FILTER_NOT_ALLOWED"));
            }
            return Ok(json_response(200, &state.config.health()));
        }
        let parsed = if method == "GET" {
            if body.is_empty() {
                Ok(Value::Null)
            } else {
                Err(err("INVALID_FIELD"))
            }
        } else {
            let ct = parts
                .headers
                .get(header::CONTENT_TYPE)
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");
            if !ct.parse::<mime::Mime>().is_ok_and(|m| {
                m.essence_str().eq_ignore_ascii_case(VENDOR_MEDIA_TYPE)
                    && m.get_param(mime::CHARSET)
                        .is_none_or(|c| c.as_str().eq_ignore_ascii_case("utf-8"))
            }) {
                Err(err("UNSUPPORTED_MEDIA_TYPE"))
            } else {
                jcs::parse(&body).map_err(|_| err("INVALID_JSON"))
            }
        };
        // Genesis/import need the proposed public admin key; existing chains authenticate raw bytes before parsing.
        let bootstrap = if matches!(ep.route, "genesis" | "import" | "request") {
            parsed.clone()?
        } else {
            Value::Null
        };
        let proposed = if ep.route == "genesis" {
            Some(&bootstrap["parameters"])
        } else if ep.route == "import" {
            a(&bootstrap, "parameters_history").last()
        } else {
            None
        };
        if let Some(p) = proposed {
            validate(p, "parameters")?;
            ep.chain = s(p, "chain_id").into();
        }
        if ep.chain.is_empty() {
            return Err(err("INVALID_FIELD"));
        }
        if ep.route == "request" {
            let value = bootstrap;
            state
                .config
                .write_guard()
                .map_err(|_| err("OFFER_NOT_FOUND"))?;
            let mut tx = state.db.pool.begin_with("BEGIN IMMEDIATE").await?;
            let r = async {
                auth::rate(
                    &mut tx,
                    &state.config,
                    "enrollment_source_ip",
                    &hash_bytes(source.as_bytes()),
                )
                .await?;
                auth::rate(
                    &mut tx,
                    &state.config,
                    "enrollment_offer",
                    &format!("{}:{}", ep.chain, s(&value, "request_id")),
                )
                .await?;
                sqlx::query("SAVEPOINT enrollment_candidate")
                    .execute(&mut *tx)
                    .await?;
                let candidate = async {
                    read::allowed(&q, &[])?;
                    if deletion::proof(&mut tx, &ep.chain).await?.is_some() {
                        return Err(err("OFFER_NOT_FOUND"));
                    }
                    let c = store::load(&mut tx, &ep.chain)
                        .await?
                        .filter(|c| c.writable)
                        .ok_or_else(|| err("OFFER_NOT_FOUND"))?;
                    let (status, v) = mutation::enrollment_request(&mut tx, &c, &value).await?;
                    store::quota(&mut tx, &ep.chain, &state.config).await?;
                    Ok((status, v))
                }
                .await;
                if candidate.is_err() {
                    sqlx::query("ROLLBACK TO enrollment_candidate")
                        .execute(&mut *tx)
                        .await?;
                }
                sqlx::query("RELEASE enrollment_candidate")
                    .execute(&mut *tx)
                    .await?;
                candidate
            }
            .await;
            // Preserve IP/offer rate accounting even for invalid unauthenticated offers.
            tx.commit().await?;
            let (status, v) = r?;
            return Ok(json_response(status, &v));
        }
        let mut tx = state.db.pool.begin_with("BEGIN IMMEDIATE").await?;
        let authorized = auth::authenticate(
            &mut tx,
            &state.config,
            auth::AuthRequest {
                headers: &parts.headers,
                method: &method,
                uri: &uri,
                body: &body,
                chain_id: &ep.chain,
                proposed_key: proposed.map(|p| s(p, "admin_public_key")),
                route: ep.route,
            },
        )
        .await;
        // An authenticated nonce is consumed even when later authorization/validation fails.
        tx.commit().await?;
        let authorized = authorized?;
        let value = parsed?;
        if method != "GET" && ep.route != "delete" {
            state.config.write_guard()?;
        }
        if matches!(
            ep.route,
            "records_post" | "parts_post" | "repair" | "envelopes_post"
        ) {
            read::allowed(&q, &[])?;
            if matches!(ep.route, "records_post" | "parts_post") {
                let mut tx = state.db.pool.begin_with("BEGIN IMMEDIATE").await?;
                let rate = auth::rate(
                    &mut tx,
                    &state.config,
                    "record_upload_device",
                    &format!(
                        "{}:{}",
                        ep.chain,
                        authorized.device.as_deref().unwrap_or("admin")
                    ),
                )
                .await;
                tx.commit().await?;
                rate?;
            }
            let v = batch::upload(
                &state.db,
                &state.config,
                &authorized,
                &ep.chain,
                ep.route,
                &ep.param,
                &value,
            )
            .await?;
            return Ok(json_response(200, &v));
        }
        transfer_permit = if matches!(ep.route, "export" | "part_get") {
            let sem = state
                .transfers
                .lock()
                .await
                .entry(ep.chain.clone())
                .or_insert_with(|| Arc::new(Semaphore::new(2)))
                .clone();
            Some(sem.try_acquire_owned().map_err(|_| {
                err("RATE_LIMITED")
                    .context(json!({"retry_after_ms":1000,"scope":"concurrent_transfers"}))
            })?)
        } else {
            None
        };
        let mut tx = state.db.pool.begin_with("BEGIN IMMEDIATE").await?;
        if let Some(proof) = deletion::proof(&mut tx, &ep.chain).await? {
            if ep.route == "deletion" {
                read::allowed(&q, &[])?;
                tx.commit().await?;
                return Ok(json_response(200, &proof));
            }
            if ep.route == "delete" {
                let row =
                    sqlx::query("SELECT request_hash,outcome FROM v3_deletions WHERE chain_id=?")
                        .bind(&ep.chain)
                        .fetch_one(&mut *tx)
                        .await?;
                if row.get::<String, _>("request_hash") == object_hash(&value) {
                    let v = store::value(row.get("outcome"));
                    tx.commit().await?;
                    return Ok(json_response(202, &v));
                }
            }
            return Err(deletion::gone(&proof));
        }
        let result = async {
            if ep.route == "genesis" {
                read::allowed(&q, &[])?;
                let (status, v, _) = mutation::genesis(&mut tx, &state.config, &value).await?;
                Ok(json_response(status, &v))
            } else if ep.route == "import" {
                authorized.require_admin()?;
                read::allowed(&q, &[])?;
                let (v, _) = import::stage(&mut tx, &state.config, &value).await?;
                Ok(json_response(202, &v))
            } else {
                let mut c = store::load(&mut tx, &ep.chain)
                    .await?
                    .ok_or_else(|| err("CHAIN_NOT_FOUND"))?;
                if !c.writable && !(authorized.admin() && ep.route == "reseed") {
                    return Err(err("CHAIN_NOT_FOUND"));
                }
                auth::check_state(&mut tx, &c, &authorized, ep.route).await?;
                let r =
                    dispatch(&mut tx, &mut c, &state.config, &authorized, &ep, &q, &value).await;
                match r {
                    Ok(response) => {
                        if method != "GET" {
                            store::save(&mut tx, &c, &state.config).await?;
                            store::quota(&mut tx, &c.chain_id, &state.config).await?;
                        }
                        Ok(response)
                    }
                    Err(e) => Err(e),
                }
            }
        }
        .await;
        match result {
            Ok(response) => {
                tx.commit().await?;
                if ep.route == "delete" {
                    // The initial immutable 202 receipt remains the retry result; completion is separately attested.
                    let _ = deletion::complete(&state.db, &state.config).await;
                }
                Ok(response)
            }
            Err(e) => {
                tx.rollback().await?;
                audit_reject(&state, &ep.chain, &value, e.code).await?;
                Err(e)
            }
        }
    }
    .await;
    let mut response = result.unwrap_or_else(IntoResponse::into_response);
    if let Some(permit) = transfer_permit
        && response.status().is_success()
    {
        let (parts, body) = response.into_parts();
        response = Response::from_parts(
            parts,
            Body::new(LeasedBody {
                body,
                _permit: permit,
            }),
        );
    }
    if response.status() == StatusCode::METHOD_NOT_ALLOWED {
        let allow = endpoint(&path, "GET")
            .or_else(|_| endpoint(&path, "POST"))
            .or_else(|_| endpoint(&path, "PUT"))
            .or_else(|_| endpoint(&path, "DELETE"))
            .map(|ep| ep.allow)
            .unwrap_or("GET");
        response
            .headers_mut()
            .insert(header::ALLOW, allow.parse().unwrap());
    }
    response.headers_mut().insert(
        header::DATE,
        httpdate::fmt_http_date(std::time::SystemTime::now())
            .parse()
            .unwrap(),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        "x-pallasync-protocol",
        header::HeaderValue::from_static("pallasync/3"),
    );
    response
}
struct LeasedBody {
    body: Body,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
impl http_body::Body for LeasedBody {
    type Data = axum::body::Bytes;
    type Error = axum::Error;
    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<std::result::Result<http_body::Frame<Self::Data>, Self::Error>>>
    {
        std::pin::Pin::new(&mut self.get_mut().body).poll_frame(cx)
    }
    fn size_hint(&self) -> http_body::SizeHint {
        self.body.size_hint()
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
}
fn raw_response(status: u16, ct: &str, bytes: Vec<u8>) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, ct)
        .body(Body::from(bytes))
        .unwrap()
}
pub fn json_response(status: u16, v: &Value) -> Response<Body> {
    raw_response(
        status,
        VENDOR_MEDIA_TYPE,
        jcs::canonicalize_json(v).unwrap(),
    )
}

async fn dispatch(
    db: &mut sqlx::SqliteConnection,
    c: &mut Chain,
    cfg: &RelayConfig,
    auth: &Auth,
    ep: &Endpoint,
    q: &[(String, String)],
    v: &Value,
) -> Result<Response<Body>> {
    if !matches!(
        ep.route,
        "devices"
            | "epochs_get"
            | "own_envelopes"
            | "snapshots_get"
            | "requests_get"
            | "records_get"
            | "log"
            | "export"
            | "transparency"
            | "receipt"
    ) {
        read::allowed(q, &[])?
    }
    let (status, value) = match ep.route {
        "parameters_get" => (
            200,
            json!({"parameters":c.parameters,"parameters_hash":c.parameters_hash(),"epoch_hash":c.epoch_hash(),"log_id":c.log_id,"generation":c.generation(),"head_seq":c.head_seq,"head_hash":c.head_hash,"server_time_ms":now(),"quota":{"used_bytes":store::used(db,&c.chain_id).await?,"max_bytes":cfg.max_bytes}}),
        ),
        "head" => (200, c.head()),
        "notice" => {
            let published: Option<String> =
                sqlx::query_scalar("SELECT notice FROM v3_notices WHERE chain_id=?")
                    .bind(&c.chain_id)
                    .fetch_optional(db)
                    .await?;
            (200,published.map(store::value).unwrap_or_else(||json!({"shutdown_at_ms":null,"migration_origin":null,"notice_id":c.notice_id,"server_time_ms":now()})))
        }
        "devices" | "epochs_get" | "snapshots_get" | "own_envelopes" => (
            200,
            read::objects(db, c, cfg, auth, ep.route, &ep.param, q).await?,
        ),
        "records_get" | "log" => (200, read::log(db, c, cfg, auth, ep.route, q).await?),
        "epoch_get" => {
            let epoch = store::object(&mut *db, &c.chain_id, "epoch", &ep.param)
                .await?
                .ok_or_else(|| err("EPOCH_NOT_FOUND"))?;
            (200, read::epoch_wrapper(db, c, &epoch).await?)
        }
        "recovery" => {
            auth.require_admin()
                .map_err(|_| err("ENVELOPE_ACCESS_DENIED"))?;
            if super::retention::expired(&mut *db, c, ep.param.parse().unwrap()).await? {
                return Err(err("HISTORY_KEY_EXPIRED"));
            }
            let epoch = store::object(&mut *db, &c.chain_id, "epoch", &ep.param)
                .await?
                .ok_or_else(|| err("EPOCH_NOT_FOUND"))?;
            let envelope:Option<String>=sqlx::query_scalar("SELECT body FROM v3_objects WHERE chain_id=? AND kind='envelope' AND object_hash=?").bind(&c.chain_id).bind(s(&epoch,"recovery_envelope_hash")).fetch_optional(db).await?.flatten();
            (
                200,
                json!({"envelope":envelope.map(store::value).ok_or_else(||err("ENVELOPE_NOT_FOUND"))?}),
            )
        }
        "part_get" => {
            let record = store::object(&mut *db, &c.chain_id, "snapshot_part", &ep.param)
                .await?
                .ok_or_else(|| err("SNAPSHOT_PART_NOT_FOUND"))?;
            if n(&record, "generation") > c.generation() {
                return Err(err("SNAPSHOT_PART_NOT_FOUND"));
            }
            (
                200,
                json!({"record":record,"upload_receipt":store::receipt(db,&c.chain_id,"snapshot_part",&ep.param).await?}),
            )
        }
        "snapshot_get" => (
            200,
            json!({"compaction":store::object(db,&c.chain_id,"compaction",&ep.param).await?.ok_or_else(||err("SNAPSHOT_NOT_FOUND"))?}),
        ),
        "transparency_head" => {
            let head: String = sqlx::query_scalar(
                "SELECT head FROM v3_heads WHERE chain_id=? AND transparency_id=? AND idx=?",
            )
            .bind(&c.chain_id)
            .bind(&c.transparency_id)
            .bind(c.transparency_index as i64)
            .fetch_one(db)
            .await?;
            (200, json!({"head":store::value(head)}))
        }
        "transparency" => (200, read::transparency(db, c, cfg, q).await?),
        "receipt" => {
            read::allowed(q, &["log_id"])?;
            let id = read::query(q, "log_id")
                .filter(|s| uuid(s))
                .ok_or_else(|| err("INVALID_FIELD"))?;
            if id != c.log_id {
                return Err(err("LOG_ID_MISMATCH"));
            }
            let row=sqlx::query("SELECT r.receipt,l.entry FROM v3_receipts r LEFT JOIN v3_log l ON l.chain_id=r.chain_id AND l.log_id=r.log_id AND l.seq=r.seq WHERE r.chain_id=? AND r.log_id=? AND r.seq=?").bind(&c.chain_id).bind(id).bind(ep.param.parse::<i64>().unwrap()).fetch_optional(db).await?.ok_or_else(||err("RECEIPT_NOT_FOUND"))?;
            let entry = row
                .get::<Option<String>, _>("entry")
                .map(store::value)
                .unwrap_or(Value::Null);
            if !auth.admin() && entry["object"]["recipient_kind"] == "recovery" {
                return Err(err("ENVELOPE_ACCESS_DENIED"));
            }
            (
                200,
                json!({"entry":entry,"receipt":store::value(row.get("receipt"))}),
            )
        }
        "export" => {
            return Ok(raw_response(
                200,
                EXPORT_MEDIA_TYPE,
                export::export(db, c, cfg, auth, q).await?.into_bytes(),
            ));
        }
        "enroll" => mutation::enroll(db, c, cfg, auth, v, None).await?,
        "epochs_post" | "revoke" => {
            mutation::epoch(
                db,
                c,
                cfg,
                auth,
                v,
                if ep.route == "revoke" {
                    Some(&ep.param)
                } else {
                    None
                },
            )
            .await?
        }
        "offer" => mutation::offer(db, c, auth, v).await?,
        "approve" | "reject" => {
            mutation::approve(db, c, cfg, auth, &ep.param, v, ep.route == "reject").await?
        }
        "ack" => (200, mutation::ack(db, c, auth, &ep.param, v).await?),
        "snapshot" => mutation::snapshot(db, c, cfg, v).await?,
        "prune" => (200, mutation::prune(db, c, cfg, auth, v).await?),
        "reseed" => (200, import::reseed(db, c, cfg, auth, v).await?),
        "delete" => (202, deletion::delete(db, c, cfg, auth, v).await?),
        "deletion" => return Err(err("CHAIN_NOT_FOUND")),
        "requests_get" => (200, requests(db, c, cfg, auth, q).await?),
        _ => unreachable!("exhaustive routes"),
    };
    let response = json_response(status, &value);
    if store::text(&value).len() > read::RESPONSE_MAX {
        return Err(err("PAYLOAD_TOO_LARGE"));
    }
    Ok(response)
}
async fn requests(
    db: &mut sqlx::SqliteConnection,
    c: &Chain,
    cfg: &RelayConfig,
    auth: &Auth,
    q: &[(String, String)],
) -> Result<Value> {
    read::allowed(q, &["cursor", "limit"])?;
    let mut page = read::page(
        &mut *db,
        c,
        cfg,
        "requests_get",
        q,
        json!({"device_id":auth.device}),
    )
    .await?;
    let rows=sqlx::query("SELECT request_id,request,offer,status FROM v3_offer_history h WHERE chain_id=? AND request_id>? AND request IS NOT NULL AND id=(SELECT MAX(id) FROM v3_offer_history WHERE chain_id=h.chain_id AND request_id=h.request_id AND id<=?) AND json_extract(offer,'$.generation')=? AND (json_extract(offer,'$.offering_device_id')=? OR ?=1) ORDER BY request_id LIMIT ?").bind(&c.chain_id).bind(&page.key).bind(n(&page.extra,"offer_version") as i64).bind(c.generation() as i64).bind(auth.device.as_deref().unwrap_or("")).bind(auth.admin()).bind(page.limit as i64+1).fetch_all(&mut *db).await?;
    let more = rows.len() > page.limit;
    let mut items = Vec::new();
    for r in rows.into_iter().take(page.limit) {
        page.key = r.get("request_id");
        let request = store::value(r.get("request"));
        let offer = store::value(r.get("offer"));
        items.push(json!({"request_hash":object_hash(&request),"request":request,"status":r.get::<String,_>("status"),"offering_device_id":offer["offering_device_id"]}))
    }
    let next = if more {
        Some(read::cursor(db, cfg, &page).await?)
    } else {
        None
    };
    Ok(
        json!({"items":items,"next_cursor":next,"has_more":more,"log_id":page.cut.log_id,"generation":page.cut.generation(),"head_seq":page.cut.head_seq}),
    )
}
async fn audit_reject(state: &AppState, chain: &str, v: &Value, code: &'static str) -> Result<()> {
    if matches!(
        code,
        "RATE_LIMITED" | "QUOTA_EXCEEDED" | "STORAGE_UNAVAILABLE" | "INVALID_JSON"
    ) {
        return Ok(());
    }
    let mut candidates = Vec::new();
    for (key, kind) in [
        ("parameters", "parameters"),
        ("device_record", "device"),
        ("epoch", "epoch"),
        ("compaction", "compaction"),
        ("admin_operation", "admin"),
    ] {
        if let Some(obj) = v.get(key)
            && validate(obj, kind).is_ok()
        {
            candidates.push(obj.clone())
        }
    }
    for key in ["envelopes", "device_records"] {
        for obj in a(v, key) {
            if validate(
                obj,
                if key == "envelopes" {
                    "envelope"
                } else {
                    "device"
                },
            )
            .is_ok()
            {
                candidates.push(obj.clone())
            }
        }
    }
    if candidates.is_empty() {
        return Ok(());
    }
    let mut tx = state.db.pool.begin_with("BEGIN IMMEDIATE").await?;
    if let Some(mut c) = store::load(&mut tx, chain).await? {
        for obj in candidates {
            store::transparency(
                &mut tx,
                &mut c,
                &state.config,
                "reject",
                &object_hash(&obj),
                None,
                Some(code),
            )
            .await?;
        }
        store::save(&mut tx, &c, &state.config).await?;
        tx.commit().await?;
    }
    Ok(())
}
