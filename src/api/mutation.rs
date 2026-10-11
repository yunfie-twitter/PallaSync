use super::{
    auth::{self, Auth},
    domain::*,
    error::*,
    store::{self, Chain},
    wire::*,
};
use crate::{config::RelayConfig, crypto::verify::*};
use serde_json::{Value, json};
use sqlx::{Row, SqliteConnection};

pub async fn genesis(
    db: &mut SqliteConnection,
    cfg: &RelayConfig,
    v: &Value,
) -> Result<(u16, Value, Chain)> {
    fields(
        v,
        &[
            ("parameters", "object"),
            ("device_record", "object"),
            ("epoch", "object"),
            ("envelopes", "array"),
        ],
        &[],
    )?;
    let p = &v["parameters"];
    validate(p, "parameters")?;
    verify(p, s(p, "admin_public_key"), CTX_PARAMETERS)?;
    let id = s(p, "chain_id");
    if let Some(response) = store::outcomes(&mut *db, id, "genesis", id, v).await? {
        return Ok((200, response, store::load(db, id).await?.unwrap()));
    }
    if store::load(&mut *db, id).await?.is_some() {
        return Err(err("CHAIN_EXISTS"));
    }
    if n(p, "generation") != 0 {
        return Err(err("GENERATION_MISMATCH"));
    }
    if n(&v["device_record"], "meta_epoch") != 0 {
        return Err(err("EPOCH_STALE"));
    }
    let mut c = Chain::new(p.clone(), v["epoch"].clone(), cfg, None);
    device(&mut *db, &c, &v["device_record"], None, true).await?;
    if s(&v["device_record"]["enrollment"], "signer_kind") != "admin" {
        return Err(err("ENROLLMENT_CERTIFICATE_INVALID"));
    }
    bundle(
        &mut *db,
        &c,
        &v["epoch"],
        a(v, "envelopes"),
        &[v["device_record"].clone()],
        true,
        false,
    )
    .await?;
    let mut receipts = vec![
        store::append(&mut *db, &mut c, cfg, "parameters", p)
            .await?
            .1,
    ];
    let (_, rs) = commit_epoch(
        &mut *db,
        &mut c,
        cfg,
        EpochCommit {
            epoch: &v["epoch"],
            envelopes: a(v, "envelopes"),
            staged: std::slice::from_ref(&v["device_record"]),
            admin: None,
            genesis: true,
        },
    )
    .await?;
    receipts.extend(rs);
    let mut response = c.result();
    response["device_status"] = "active".into();
    response["upload_receipts"] = receipts.into();
    store::publish_notice(&mut *db, &mut c, cfg).await?;
    store::outcome(&mut *db, id, "genesis", id, v, &response).await?;
    store::save(db, &c, cfg).await?;
    Ok((201, response, c))
}

pub async fn enroll(
    db: &mut SqliteConnection,
    c: &mut Chain,
    cfg: &RelayConfig,
    auth: &Auth,
    v: &Value,
    request: Option<&Value>,
) -> Result<(u16, Value)> {
    fields(
        v,
        &[
            ("device_record", "object"),
            ("envelopes", "array"),
            (
                "admin_operation",
                if request.is_some() {
                    "object?"
                } else {
                    "object"
                },
            ),
        ],
        &[],
    )?;
    if request.is_none() {
        auth.require_admin()?
    }
    if c.parameters["policy"]["epoch_retention"] == "immediate" && n(&c.epoch, "epoch") > 0 {
        let handoff: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM v3_handoffs WHERE chain_id=? AND epoch=?")
                .bind(&c.chain_id)
                .bind(n(&c.epoch, "epoch") as i64 - 1)
                .fetch_one(&mut *db)
                .await?;
        if handoff == 0 {
            return Err(err("ENROLLMENT_NOT_ALLOWED"));
        }
    }
    let d = &v["device_record"];
    validate(d, "device")?;
    let id = s(d, "device_id");
    if let Some(r) = store::outcomes(&mut *db, &c.chain_id, "enroll", id, v).await? {
        return Ok((200, r));
    }
    device(&mut *db, c, d, request, false).await?;
    if store::object_digest(&mut *db, &c.chain_id, "device", id)
        .await?
        .is_some()
    {
        return Err(err("DEVICE_ID_CONFLICT"));
    }
    if request.is_none() && s(&d["enrollment"], "signer_kind") != "admin" {
        return Err(err("ENROLLMENT_CERTIFICATE_INVALID"));
    }
    if !auth.admin()
        && (c.parameters["policy"]["allow_peer_enrollment"] != true
            || s(&d["enrollment"], "signer_device_id") != auth.device.as_deref().unwrap())
    {
        return Err(err("ENROLLMENT_NOT_ALLOWED"));
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM v3_registry WHERE chain_id=? AND generation=? AND status<>'revoked'",
    )
    .bind(&c.chain_id)
    .bind(c.generation() as i64)
    .fetch_one(&mut *db)
    .await?;
    if count as u64 >= n(cfg.limits(), "max_devices") {
        return Err(err("DEVICE_LIMIT_REACHED"));
    }
    let op = &v["admin_operation"];
    if auth.admin() {
        admin_operation(
            &mut *db,
            c,
            op,
            "approve_enrollment",
            &target(v, &["device_record", "envelopes"]),
        )
        .await?
    } else if !op.is_null() {
        return Err(err("INVALID_FIELD"));
    }
    if a(v, "envelopes").is_empty() || a(v, "envelopes").len() > 128 {
        return Err(err("INVALID_FIELD"));
    }
    let mut current = false;
    let mut ids = std::collections::HashSet::new();
    for e in a(v, "envelopes") {
        if s(e, "recipient_kind") != "device"
            || s(e, "recipient_device_id") != id
            || !ids.insert(s(e, "envelope_id"))
        {
            return Err(err("ENVELOPE_ACCESS_DENIED"));
        }
        let ep = store::object(&mut *db, &c.chain_id, "epoch", &n(e, "epoch").to_string())
            .await?
            .ok_or_else(|| err("EPOCH_STALE"))?;
        envelope(&mut *db, c, e, &ep, std::slice::from_ref(d)).await?;
        if n(e, "epoch") == n(&c.epoch, "epoch") {
            current = true
        }
        if n(e, "epoch") < n(&c.epoch, "epoch")
            && c.parameters["policy"]["epoch_retention"] != "retain"
        {
            // No old envelopes are removed until an authorized verified handoff is established.
            let exists=sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM v3_objects WHERE chain_id=? AND kind='envelope' AND json_extract(body,'$.epoch')=? AND json_extract(body,'$.recipient_kind')='recovery'").bind(&c.chain_id).bind(n(e,"epoch") as i64).fetch_one(&mut *db).await?;
            if exists == 0 {
                return Err(err("HISTORY_KEY_EXPIRED"));
            }
        }
    }
    if !current {
        return Err(err("EPOCH_STALE"));
    }
    let (entry, r) = store::append(&mut *db, c, cfg, "device", d).await?;
    register(&mut *db, c, d, n(&entry, "relay_seq"), "pending_keys").await?;
    let mut rs = vec![r];
    for e in a(v, "envelopes") {
        rs.push(store::append(&mut *db, c, cfg, "envelope", e).await?.1)
    }
    if auth.admin() {
        rs.push(store::append(&mut *db, c, cfg, "admin", op).await?.1)
    }
    let response = json!({"device_id":id,"status":"pending_keys","device_record_hash":object_hash(d),"upload_receipts":rs});
    store::outcome(db, &c.chain_id, "enroll", id, v, &response).await?;
    Ok((201, response))
}

pub async fn epoch(
    db: &mut SqliteConnection,
    c: &mut Chain,
    cfg: &RelayConfig,
    auth: &Auth,
    v: &Value,
    target_device: Option<&str>,
) -> Result<(u16, Value)> {
    fields(
        v,
        &[
            ("expected_epoch_hash", "b32"),
            ("epoch", "object"),
            ("envelopes", "array"),
            ("admin_operation", "object?"),
        ],
        &[("device_records", "array")],
    )?;
    let e = &v["epoch"];
    validate(e, "epoch")?;
    let id = object_hash(e);
    if let Some(r) = store::outcomes(&mut *db, &c.chain_id, "epoch", &id, v).await? {
        return Ok((200, r));
    }
    if s(v, "expected_epoch_hash") != c.epoch_hash() {
        return Err(err("CAS_MISMATCH"));
    }
    let staged = a(v, "device_records");
    if v.get("device_records").is_some() && (!auth.admin() || s(e, "reason") != "emergency") {
        return Err(err("ROTATION_NOT_ALLOWED"));
    }
    for d in staged {
        device(&mut *db, c, d, None, true).await?;
        if s(&d["enrollment"], "signer_kind") != "admin" {
            return Err(err("ENROLLMENT_CERTIFICATE_INVALID"));
        }
    }
    if !auth.admin()
        && (auth.device.as_deref() != Some(s(e, "signer_device_id"))
            || s(e, "signer_kind") != "device")
    {
        return Err(err("ROTATION_NOT_ALLOWED"));
    }
    if let Some(target) = target_device
        && (!a(e, "revoked_device_ids").contains(&Value::String(target.into()))
            || !["device_revocation", "emergency"].contains(&s(e, "reason")))
    {
        return Err(err("MEMBER_SET_MISMATCH"));
    }
    let op = &v["admin_operation"];
    let revoke = !a(e, "revoked_device_ids").is_empty();
    if auth.admin() && (revoke || target_device.is_some()) {
        admin_operation(
            &mut *db,
            c,
            op,
            "revoke_device",
            &target(v, &["epoch", "envelopes", "device_records"]),
        )
        .await?
    } else if !op.is_null() {
        return Err(err("INVALID_FIELD"));
    }
    bundle(&mut *db, c, e, a(v, "envelopes"), staged, false, false).await?;
    if a(e, "members").len() > n(cfg.limits(), "max_devices") as usize {
        return Err(err("DEVICE_LIMIT_REACHED"));
    }
    let (entry, rs) = commit_epoch(
        &mut *db,
        c,
        cfg,
        EpochCommit {
            epoch: e,
            envelopes: a(v, "envelopes"),
            staged,
            admin: if op.is_null() { None } else { Some(op) },
            genesis: false,
        },
    )
    .await?;
    let response = if let Some(id) = target_device {
        json!({"device_id":id,"status":"revoked","epoch_hash":c.epoch_hash(),"receipt":entry,"upload_receipts":rs})
    } else {
        json!({"epoch_hash":c.epoch_hash(),"receipt":entry,"upload_receipts":rs})
    };
    store::outcome(db, &c.chain_id, "epoch", &id, v, &response).await?;
    Ok((if target_device.is_some() { 200 } else { 201 }, response))
}

pub async fn offer(
    db: &mut SqliteConnection,
    c: &Chain,
    auth: &Auth,
    v: &Value,
) -> Result<(u16, Value)> {
    fields(
        v,
        &[
            ("request_id", "uuid"),
            ("offer_nonce", "b32"),
            ("expires_at_ms", "int"),
        ],
        &[],
    )?;
    if auth.admin() {
        return Err(err("ENROLLMENT_NOT_ALLOWED"));
    }
    if c.parameters["policy"]["allow_peer_enrollment"] != true {
        return Err(err("ENROLLMENT_NOT_ALLOWED"));
    }
    let id = s(v, "request_id");
    if let Some(r) = store::outcomes(&mut *db, &c.chain_id, "offer", id, v).await? {
        return Ok((200, r));
    }
    let expires = n(v, "expires_at_ms");
    if expires <= now() || expires > now() + 300000 {
        return Err(err("INVALID_FIELD"));
    }
    let offer = json!({"chain_id":c.chain_id,"generation":c.generation(),"request_id":id,"offer_nonce":v["offer_nonce"],"offering_device_id":auth.device,"expires_at_ms":expires});
    sqlx::query("INSERT INTO v3_offers(chain_id,request_id,offer,status,updated_seq) VALUES(?,?,?,'awaiting_approval',?)").bind(&c.chain_id).bind(id).bind(store::text(&offer)).bind(c.head_seq as i64).execute(&mut *db).await?;
    let response =
        json!({"request_id":id,"expires_at_ms":expires,"offer_hash":object_hash(&offer)});
    store::outcome(db, &c.chain_id, "offer", id, v, &response).await?;
    Ok((201, response))
}
pub async fn enrollment_request(
    db: &mut SqliteConnection,
    c: &Chain,
    v: &Value,
) -> Result<(u16, Value)> {
    validate(v, "request").map_err(|_| err("OFFER_NOT_FOUND"))?;
    let row =
        sqlx::query("SELECT offer,request,status FROM v3_offers WHERE chain_id=? AND request_id=?")
            .bind(&c.chain_id)
            .bind(s(v, "request_id"))
            .fetch_optional(&mut *db)
            .await?
            .ok_or_else(|| err("OFFER_NOT_FOUND"))?;
    let offer = store::value(row.get("offer"));
    if row.get::<String, _>("status") != "awaiting_approval"
        || c.generation() != n(&offer, "generation")
        || n(&offer, "expires_at_ms") + 60000 < now()
        || n(v, "expires_at_ms") > n(&offer, "expires_at_ms")
        || n(v, "created_at_ms") > now() + 60000
        || n(v, "expires_at_ms") + 60000 < now()
    {
        return Err(err("OFFER_NOT_FOUND"));
    }
    for k in ["chain_id", "generation", "request_id", "offer_nonce"] {
        if v[k] != offer[k] {
            return Err(err("OFFER_NOT_FOUND"));
        }
    }
    auth::active_device(&mut *db, c, s(&offer, "offering_device_id"))
        .await
        .map_err(|_| err("OFFER_NOT_FOUND"))?;
    verify(v, s(v, "device_public_key"), CTX_REQUEST).map_err(|_| err("OFFER_NOT_FOUND"))?;
    if let Some(old) = row.get::<Option<String>, _>("request") {
        if store::value(old) != *v {
            return Err(err("REQUEST_ID_CONFLICT"));
        }
        return Ok((
            200,
            json!({"request_id":v["request_id"],"status":"awaiting_approval","request_hash":object_hash(v)}),
        ));
    }
    sqlx::query("UPDATE v3_offers SET request=? WHERE chain_id=? AND request_id=?")
        .bind(store::text(v))
        .bind(&c.chain_id)
        .bind(s(v, "request_id"))
        .execute(db)
        .await?;
    Ok((
        201,
        json!({"request_id":v["request_id"],"status":"awaiting_approval","request_hash":object_hash(v)}),
    ))
}
pub async fn approve(
    db: &mut SqliteConnection,
    c: &mut Chain,
    cfg: &RelayConfig,
    auth: &Auth,
    id: &str,
    v: &Value,
    reject: bool,
) -> Result<(u16, Value)> {
    let row =
        sqlx::query("SELECT offer,request,status FROM v3_offers WHERE chain_id=? AND request_id=?")
            .bind(&c.chain_id)
            .bind(id)
            .fetch_optional(&mut *db)
            .await?
            .ok_or_else(|| err("OFFER_NOT_FOUND"))?;
    let offer = store::value(row.get("offer"));
    let r = store::value(
        row.get::<Option<String>, _>("request")
            .ok_or_else(|| err("OFFER_NOT_FOUND"))?,
    );
    if !auth.owns(s(&offer, "offering_device_id")) {
        return Err(err("ENROLLMENT_NOT_ALLOWED"));
    }
    let scope = if reject {
        "reject_request"
    } else {
        "approve_request"
    };
    if let Some(r) = store::outcomes(&mut *db, &c.chain_id, scope, id, v).await? {
        return Ok((200, r));
    }
    if row.get::<String, _>("status") != "awaiting_approval"
        || n(&r, "expires_at_ms") + 60000 < now()
    {
        return Err(err("OFFER_NOT_FOUND"));
    }
    if !reject && c.parameters["policy"]["allow_peer_enrollment"] != true {
        return Err(err("ENROLLMENT_NOT_ALLOWED"));
    }
    let result = if reject {
        fields(v, &[("request_hash", "b32")], &[])?;
        if s(v, "request_hash") != object_hash(&r) {
            return Err(err("REQUEST_ID_CONFLICT"));
        }
        (200, json!({"request_id":id,"status":"rejected"}))
    } else {
        enroll(&mut *db, c, cfg, auth, v, Some(&r)).await?
    };
    sqlx::query("UPDATE v3_offers SET status=?,updated_seq=? WHERE chain_id=? AND request_id=?")
        .bind(if reject { "rejected" } else { "approved" })
        .bind(c.head_seq as i64)
        .bind(&c.chain_id)
        .bind(id)
        .execute(&mut *db)
        .await?;
    store::outcome(db, &c.chain_id, scope, id, v, &result.1).await?;
    Ok(result)
}
pub async fn ack(
    db: &mut SqliteConnection,
    c: &Chain,
    auth: &Auth,
    id: &str,
    v: &Value,
) -> Result<Value> {
    fields(
        v,
        &[("epoch_hash", "b32"), ("epoch_commitment", "b32")],
        &[],
    )?;
    if auth.admin() || !auth.owns(id) {
        return Err(err("ENVELOPE_ACCESS_DENIED"));
    }
    if s(v, "epoch_hash") != c.epoch_hash() || v["epoch_commitment"] != c.epoch["epoch_commitment"]
    {
        return Err(err("EPOCH_STALE"));
    }
    let exists:i64=sqlx::query_scalar("SELECT COUNT(*) FROM v3_objects WHERE chain_id=? AND kind='envelope' AND json_extract(body,'$.recipient_device_id')=? AND json_extract(body,'$.epoch')=?").bind(&c.chain_id).bind(id).bind(n(&c.epoch,"epoch") as i64).fetch_one(&mut *db).await?;
    if exists == 0 {
        return Err(err("ENVELOPE_NOT_FOUND"));
    }
    sqlx::query("UPDATE v3_registry SET status='active' WHERE chain_id=? AND device_id=? AND status<>'revoked'").bind(&c.chain_id).bind(id).execute(db).await?;
    Ok(json!({"device_id":id,"status":"active","epoch_hash":c.epoch_hash()}))
}
pub async fn snapshot(
    db: &mut SqliteConnection,
    c: &mut Chain,
    cfg: &RelayConfig,
    v: &Value,
) -> Result<(u16, Value)> {
    fields(v, &[("compaction", "object")], &[])?;
    let comp = &v["compaction"];
    validate(comp, "compaction")?;
    let id = s(comp, "compaction_id");
    if let Some(r) = store::outcomes(&mut *db, &c.chain_id, "snapshot", id, v).await? {
        return Ok((200, r));
    }
    compaction(&mut *db, c, comp, &[]).await?;
    let (entry, r) = store::append(&mut *db, c, cfg, "compaction", comp).await?;
    let response = json!({"compaction_id":id,"receipt":entry,"upload_receipts":[r]});
    store::outcome(db, &c.chain_id, "snapshot", id, v, &response).await?;
    Ok((201, response))
}
pub async fn prune(
    db: &mut SqliteConnection,
    c: &mut Chain,
    cfg: &RelayConfig,
    auth: &Auth,
    v: &Value,
) -> Result<Value> {
    auth.require_admin()?;
    fields(
        v,
        &[
            ("compaction_id", "uuid"),
            ("through_seq", "int"),
            ("admin_operation", "object"),
        ],
        &[],
    )?;
    let op = &v["admin_operation"];
    let id = s(op, "operation_id");
    if let Some(r) = store::outcomes(&mut *db, &c.chain_id, "prune", id, v).await? {
        return Ok(r);
    }
    admin_operation(
        &mut *db,
        c,
        op,
        "prune_log",
        &target(v, &["compaction_id", "through_seq"]),
    )
    .await?;
    let comp = store::object(&mut *db, &c.chain_id, "compaction", s(v, "compaction_id"))
        .await?
        .ok_or_else(|| err("COMPACTION_UNSAFE"))?;
    let through = n(v, "through_seq");
    if through < c.min_available_seq - 1 || through > n(&comp, "covered_through_seq") {
        return Err(err("COMPACTION_UNSAFE"));
    }
    compaction(&mut *db, c, &comp, &[])
        .await
        .map_err(|_| err("COMPACTION_UNSAFE"))?;
    // Admin-signed pruning attests client semantic verification. Relay checks opaque coverage and preserves all authority evidence.
    let (_, r) = store::append(&mut *db, c, cfg, "admin", op).await?;
    sqlx::query("UPDATE v3_objects SET body=NULL WHERE chain_id=? AND kind='record' AND log_id=? AND relay_seq<=?").bind(&c.chain_id).bind(&c.log_id).bind(through as i64).execute(&mut *db).await?;
    sqlx::query("UPDATE v3_log SET entry=NULL WHERE chain_id=? AND log_id=? AND seq<=? AND json_extract(entry,'$.kind')='record'").bind(&c.chain_id).bind(&c.log_id).bind(through as i64).execute(&mut *db).await?;
    c.min_available_seq = through + 1;
    c.boundary_compaction_id = Some(s(&comp, "compaction_id").to_owned());
    super::retention::handoff(&mut *db, c, &comp, through).await?;
    store::transparency(
        &mut *db,
        c,
        cfg,
        "prune",
        &object_hash(&target(v, &["compaction_id", "through_seq"])),
        None,
        None,
    )
    .await?;
    let response = json!({"min_available_seq":c.min_available_seq,"compaction_id":v["compaction_id"],"upload_receipts":[r]});
    store::outcome(db, &c.chain_id, "prune", id, v, &response).await?;
    Ok(response)
}
