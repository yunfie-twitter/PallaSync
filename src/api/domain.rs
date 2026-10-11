use super::{
    auth::{self, Auth},
    error::*,
    store::{self, Chain},
    wire::*,
};
use crate::{config::RelayConfig, crypto::verify::*};
use serde_json::{Value, json};
use sqlx::{Row, SqliteConnection};

pub fn bound(v: &Value, c: &Chain) -> Result<()> {
    if s(v, "chain_id") != c.chain_id {
        return Err(err("INVALID_FIELD"));
    }
    if n(v, "generation") != c.generation() {
        return Err(err("GENERATION_MISMATCH"));
    }
    Ok(())
}
pub fn cas(c: &Chain, parameters: &Value, epoch: &Value) -> Result<()> {
    if parameters.as_str() != Some(c.parameters_hash().as_str())
        || epoch.as_str() != Some(c.epoch_hash().as_str())
    {
        return Err(err("CAS_MISMATCH"));
    }
    Ok(())
}
pub async fn admin_operation(
    db: &mut SqliteConnection,
    c: &Chain,
    op: &Value,
    action: &str,
    target: &Value,
) -> Result<()> {
    validate(op, "admin")?;
    bound(op, c)?;
    verify(op, s(&c.parameters, "admin_public_key"), CTX_ADMIN_OP)?;
    if s(op, "action") != action || s(op, "target_hash") != object_hash(target) {
        return Err(err("INVALID_FIELD"));
    }
    if let Some(old) =
        store::object_digest(&mut *db, &c.chain_id, "admin", s(op, "operation_id")).await?
        && old != object_hash(op)
    {
        return Err(err("OPERATION_ID_CONFLICT"));
    }
    cas(
        c,
        &op["expected_parameters_hash"],
        &op["expected_epoch_hash"],
    )
}
pub async fn device(
    db: &mut SqliteConnection,
    c: &Chain,
    d: &Value,
    request: Option<&Value>,
    genesis: bool,
) -> Result<()> {
    validate(d, "device")?;
    bound(d, c)?;
    let cert = &d["enrollment"];
    verify(d, s(d, "device_public_key"), CTX_DEVICE_RECORD)?;
    if request
        .map(object_hash)
        .map(Value::String)
        .unwrap_or(Value::Null)
        != cert["request_hash"]
    {
        return Err(err("ENROLLMENT_CERTIFICATE_INVALID"));
    }
    if let Some(r) = request {
        for k in [
            "device_id",
            "device_public_key",
            "device_kex_public_key",
            "chain_id",
            "generation",
        ] {
            if d[k] != r[k] {
                return Err(err("ENROLLMENT_CERTIFICATE_INVALID"));
            }
        }
    }
    if !genesis
        && store::object(
            &mut *db,
            &c.chain_id,
            "epoch",
            &n(d, "meta_epoch").to_string(),
        )
        .await?
        .is_none()
    {
        return Err(err("EPOCH_STALE"));
    }
    if genesis
        && n(d, "meta_epoch") != n(&c.epoch, "epoch")
        && n(d, "meta_epoch") != n(&c.epoch, "epoch") + 1
    {
        return Err(err("EPOCH_STALE"));
    }
    if s(cert, "signer_kind") == "device" {
        if c.parameters["policy"]["allow_peer_enrollment"] != true
            || request.is_none()
            || s(cert, "signer_device_id") == s(d, "device_id")
        {
            return Err(err("ENROLLMENT_CERTIFICATE_INVALID"));
        }
        let key = auth::signing_key(db, c, cert)
            .await
            .map_err(|_| err("ENROLLMENT_CERTIFICATE_INVALID"))?;
        verify(cert, &key, CTX_ENROLLMENT).map_err(|_| err("ENROLLMENT_CERTIFICATE_INVALID"))?;
    } else {
        verify(cert, s(&c.parameters, "admin_public_key"), CTX_ENROLLMENT)
            .map_err(|_| err("ENROLLMENT_CERTIFICATE_INVALID"))?
    }
    if let Some(old) =
        store::object_digest(&mut *db, &c.chain_id, "device", s(d, "device_id")).await?
        && old != object_hash(d)
    {
        return Err(err("DEVICE_ID_CONFLICT"));
    }
    let same_cert:i64=sqlx::query_scalar("SELECT COUNT(*) FROM v3_objects WHERE chain_id=? AND kind='device' AND json_extract(body,'$.enrollment.certificate_id')=? AND object_id<>?").bind(&c.chain_id).bind(s(cert,"certificate_id")).bind(s(d,"device_id")).fetch_one(db).await?;
    if same_cert != 0 {
        return Err(err("ENROLLMENT_CERTIFICATE_INVALID"));
    }
    Ok(())
}
pub async fn envelope(
    db: &mut SqliteConnection,
    c: &Chain,
    e: &Value,
    epoch: &Value,
    staged: &[Value],
) -> Result<()> {
    validate(e, "envelope")?;
    for k in [
        "chain_id",
        "generation",
        "epoch",
        "previous_epoch_hash",
        "epoch_commitment",
    ] {
        if e[k] != epoch[k] {
            return Err(err("EPOCH_CHAIN_INVALID"));
        }
    }
    let key = if s(e, "signer_kind") == "admin" {
        s(&c.parameters, "admin_public_key").to_owned()
    } else if let Some(d) = staged
        .iter()
        .find(|d| s(d, "device_id") == s(e, "signer_device_id"))
    {
        s(d, "device_public_key").to_owned()
    } else {
        auth::signing_key(&mut *db, c, e).await?
    };
    verify(e, &key, CTX_ENVELOPE)?;
    if s(e, "recipient_kind") == "device" {
        let id = s(e, "recipient_device_id");
        let d = if let Some(d) = staged.iter().find(|d| s(d, "device_id") == id) {
            d.clone()
        } else {
            let d = store::object(&mut *db, &c.chain_id, "device", id)
                .await?
                .ok_or_else(|| err("ENVELOPE_ACCESS_DENIED"))?;
            let status: String = sqlx::query_scalar(
                "SELECT status FROM v3_registry WHERE chain_id=? AND device_id=?",
            )
            .bind(&c.chain_id)
            .bind(id)
            .fetch_one(&mut *db)
            .await?;
            if status == "revoked" || n(&d, "generation") != c.generation() {
                return Err(err("ENVELOPE_ACCESS_DENIED"));
            }
            d
        };
        if e["recipient_key_hash"]
            != hash_bytes(&decode(s(&d, "device_kex_public_key"), Some(32)).unwrap())
        {
            return Err(err("ENVELOPE_ACCESS_DENIED"));
        }
    }
    Ok(())
}
pub async fn bundle(
    db: &mut SqliteConnection,
    c: &Chain,
    epoch: &Value,
    envelopes: &[Value],
    staged: &[Value],
    genesis: bool,
    reseed: bool,
) -> Result<()> {
    validate(epoch, "epoch")?;
    bound(epoch, c)?;
    if genesis {
        if n(epoch, "epoch") != 0
            || s(epoch, "reason") != "genesis"
            || s(epoch, "signer_kind") != "admin"
            || !a(epoch, "revoked_device_ids").is_empty()
        {
            return Err(err("EPOCH_CHAIN_INVALID"));
        }
    } else {
        if n(epoch, "epoch") != n(&c.epoch, "epoch") + 1
            || s(epoch, "previous_epoch_hash") != c.epoch_hash()
        {
            return Err(err("EPOCH_CHAIN_INVALID"));
        }
        if ["genesis", "reseed"].contains(&s(epoch, "reason")) && !reseed {
            return Err(err("EPOCH_CHAIN_INVALID"));
        }
        if !a(epoch, "revoked_device_ids").is_empty()
            && !["device_revocation", "key_rotation", "emergency", "reseed"]
                .contains(&s(epoch, "reason"))
        {
            return Err(err("EPOCH_CHAIN_INVALID"));
        }
    }
    if ["genesis", "emergency", "reseed"].contains(&s(epoch, "reason"))
        && s(epoch, "signer_kind") != "admin"
    {
        return Err(err("ROTATION_NOT_ALLOWED"));
    }
    if s(epoch, "signer_kind") == "device"
        && c.parameters["policy"]["allow_device_rotation"] != true
    {
        return Err(err("ROTATION_NOT_ALLOWED"));
    }
    let key = auth::signing_key(&mut *db, c, epoch).await?;
    verify(epoch, &key, CTX_EPOCH)?;
    let rows=sqlx::query("SELECT device_id,generation FROM v3_registry WHERE chain_id=? AND status<>'revoked' ORDER BY device_id").bind(&c.chain_id).fetch_all(&mut *db).await?;
    let existing: Vec<String> = rows
        .iter()
        .filter(|r| !genesis && (reseed || r.get::<i64, _>("generation") as u64 == c.generation()))
        .map(|r| r.get("device_id"))
        .collect();
    let revoked: Vec<String> = a(epoch, "revoked_device_ids")
        .iter()
        .map(|id| id.as_str().unwrap().to_owned())
        .collect();
    if revoked.iter().any(|id| !existing.contains(id)) || (reseed && revoked != existing) {
        return Err(err("MEMBER_SET_MISMATCH"));
    }
    let mut members: Vec<String> = if reseed {
        Vec::new()
    } else {
        existing
            .into_iter()
            .filter(|id| !revoked.contains(id))
            .collect()
    };
    for d in staged {
        if members.contains(&s(d, "device_id").to_owned()) {
            return Err(err("DEVICE_ID_CONFLICT"));
        }
        members.push(s(d, "device_id").into())
    }
    members.sort();
    let actual: Vec<String> = a(epoch, "members")
        .iter()
        .map(|id| id.as_str().unwrap().into())
        .collect();
    if members != actual || members.len() > 128 {
        return Err(err("MEMBER_SET_MISMATCH"));
    }
    if envelopes.len() != members.len() + 1 {
        return Err(err("MEMBER_SET_MISMATCH"));
    }
    let mut recipients = std::collections::HashSet::new();
    let mut recovery = false;
    let mut ids = std::collections::HashSet::new();
    for e in envelopes {
        envelope(&mut *db, c, e, epoch, staged).await?;
        if !ids.insert(s(e, "envelope_id")) {
            return Err(err("INVALID_FIELD"));
        }
        if s(e, "recipient_kind") == "recovery" {
            if recovery || object_hash(e) != s(epoch, "recovery_envelope_hash") {
                return Err(err("RECOVERY_ENVELOPE_REQUIRED"));
            }
            recovery = true;
        } else if !members.contains(&s(e, "recipient_device_id").to_owned())
            || !recipients.insert(s(e, "recipient_device_id"))
        {
            return Err(err("MEMBER_SET_MISMATCH"));
        }
    }
    if !recovery {
        return Err(err("RECOVERY_ENVELOPE_REQUIRED"));
    }
    Ok(())
}
pub async fn register(
    db: &mut SqliteConnection,
    c: &Chain,
    d: &Value,
    seq: u64,
    status: &str,
) -> Result<()> {
    sqlx::query("INSERT INTO v3_registry(chain_id,device_id,generation,status,enrolled_seq) VALUES(?,?,?,?,?)").bind(&c.chain_id).bind(s(d,"device_id")).bind(n(d,"generation") as i64).bind(status).bind(seq as i64).execute(db).await?;
    Ok(())
}
pub struct EpochCommit<'a> {
    pub epoch: &'a Value,
    pub envelopes: &'a [Value],
    pub staged: &'a [Value],
    pub admin: Option<&'a Value>,
    pub genesis: bool,
}
pub async fn commit_epoch(
    db: &mut SqliteConnection,
    c: &mut Chain,
    cfg: &RelayConfig,
    commit: EpochCommit<'_>,
) -> Result<(Value, Vec<Value>)> {
    let EpochCommit {
        epoch,
        envelopes,
        staged,
        admin,
        genesis,
    } = commit;
    let mut receipts = Vec::new();
    let mut ds = staged.to_vec();
    ds.sort_by_key(|d| s(d, "device_id").to_owned());
    for d in &ds {
        let (entry, r) = store::append(&mut *db, c, cfg, "device", d).await?;
        register(
            &mut *db,
            c,
            d,
            n(&entry, "relay_seq"),
            if genesis { "active" } else { "pending_keys" },
        )
        .await?;
        receipts.push(r)
    }
    let mut es = envelopes.to_vec();
    es.sort_by_key(|e| {
        (
            s(e, "recipient_kind").to_owned(),
            s(e, "recipient_device_id").to_owned(),
        )
    });
    for e in &es {
        receipts.push(store::append(&mut *db, c, cfg, "envelope", e).await?.1)
    }
    if let Some(op) = admin {
        receipts.push(store::append(&mut *db, c, cfg, "admin", op).await?.1)
    }
    let (entry, r) = store::append(&mut *db, c, cfg, "epoch", epoch).await?;
    receipts.push(r);
    for id in a(epoch, "revoked_device_ids") {
        sqlx::query("UPDATE v3_registry SET status='revoked',revoked_seq=? WHERE chain_id=? AND device_id=?").bind(n(&entry,"relay_seq") as i64).bind(&c.chain_id).bind(id.as_str().unwrap()).execute(&mut *db).await?;
    }
    c.epoch = epoch.clone();
    Ok((entry, receipts))
}
pub async fn record(
    db: &mut SqliteConnection,
    c: &Chain,
    v: &Value,
    auth: &Auth,
    snapshot: bool,
    staged: bool,
) -> Result<bool> {
    validate(v, "record")?;
    if s(v, "chain_id") != c.chain_id {
        return Err(err("INVALID_FIELD"));
    }
    let kind = if snapshot { "snapshot_part" } else { "record" };
    if !auth.admin() && auth.device.as_deref() != Some(s(v, "device_id")) {
        return Err(err("DEVICE_KEY_MISMATCH"));
    }
    if let Some(digest) =
        store::object_digest(&mut *db, &c.chain_id, kind, s(v, "record_id")).await?
    {
        if digest != object_hash(v) {
            return Err(err("RECORD_ID_CONFLICT"));
        }
        return Ok(true);
    }
    if staged && auth.admin() && n(v, "generation") == c.generation() + 1 {
        return Ok(false);
    }
    if snapshot && auth.admin() && n(v, "generation") <= c.generation() {
        let generation = n(v, "generation");
        let parameters =
            store::object(&mut *db, &c.chain_id, "parameters", &generation.to_string())
                .await?
                .ok_or_else(|| err("GENERATION_MISMATCH"))?;
        let epoch = store::object(&mut *db, &c.chain_id, "epoch", &n(v, "epoch").to_string())
            .await?
            .ok_or_else(|| err("EPOCH_NOT_FOUND"))?;
        let d = store::object(&mut *db, &c.chain_id, "device", s(v, "device_id"))
            .await?
            .ok_or_else(|| err("DEVICE_UNKNOWN"))?;
        if n(&d, "generation") != generation || n(&epoch, "generation") != generation {
            return Err(err("GENERATION_MISMATCH"));
        }
        verify(v, s(&d, "device_public_key"), CTX_SYNC_RECORD)?;
        if (parameters["policy"]["metadata_profile"] == "private") != v["collection_tag"].is_null()
        {
            return Err(err("INVALID_FIELD"));
        }
        let existing: Option<String> = sqlx::query_scalar(
            "SELECT record_id FROM v3_payload_nonces WHERE chain_id=? AND epoch=? AND nonce=?",
        )
        .bind(&c.chain_id)
        .bind(n(v, "epoch") as i64)
        .bind(s(v, "payload_nonce"))
        .fetch_optional(db)
        .await?;
        if existing.is_some_and(|id| id != s(v, "record_id")) {
            return Err(err("INVALID_FIELD"));
        }
        return Ok(false);
    }
    bound(v, c)?;
    if !auth.admin() && auth.device.as_deref() != Some(s(v, "device_id")) {
        return Err(err("DEVICE_KEY_MISMATCH"));
    }
    let key = auth::active_device(&mut *db, c, s(v, "device_id")).await?;
    verify(v, &key, CTX_SYNC_RECORD)?;
    if n(v, "epoch") != n(&c.epoch, "epoch") {
        return Err(err("EPOCH_STALE"));
    }
    if (c.parameters["policy"]["metadata_profile"] == "private") != v["collection_tag"].is_null() {
        return Err(err("INVALID_FIELD"));
    }
    let used: Option<String> = sqlx::query_scalar(
        "SELECT record_id FROM v3_payload_nonces WHERE chain_id=? AND epoch=? AND nonce=?",
    )
    .bind(&c.chain_id)
    .bind(n(v, "epoch") as i64)
    .bind(s(v, "payload_nonce"))
    .fetch_optional(db)
    .await?;
    if used.as_deref().is_some_and(|id| id != s(v, "record_id")) {
        return Err(err("INVALID_FIELD"));
    }
    Ok(false)
}
pub async fn reserve_payload_nonce(db: &mut SqliteConnection, c: &Chain, v: &Value) -> Result<()> {
    sqlx::query(
        "INSERT OR IGNORE INTO v3_payload_nonces(chain_id,epoch,nonce,record_id) VALUES(?,?,?,?)",
    )
    .bind(&c.chain_id)
    .bind(n(v, "epoch") as i64)
    .bind(s(v, "payload_nonce"))
    .bind(s(v, "record_id"))
    .execute(db)
    .await?;
    Ok(())
}
pub async fn compaction(
    db: &mut SqliteConnection,
    c: &Chain,
    v: &Value,
    staged: &[Value],
) -> Result<()> {
    validate(v, "compaction")?;
    bound(v, c)?;
    if s(v, "log_id") != c.log_id {
        return Err(err("LOG_ID_MISMATCH"));
    }
    if s(v, "epoch_hash") != c.epoch_hash() {
        return Err(err("EPOCH_STALE"));
    }
    let key = if let Some(d) = staged
        .iter()
        .find(|d| s(d, "device_id") == s(v, "device_id"))
    {
        s(d, "device_public_key").to_owned()
    } else {
        auth::active_device(&mut *db, c, s(v, "device_id")).await?
    };
    verify(v, &key, CTX_COMPACTION)?;
    let covered = n(v, "covered_through_seq");
    let hash = if covered == 0 {
        store::initial_hash(b"PALLASYNC-LOG-v3\0", &c.chain_id, &c.log_id, None)
    } else {
        sqlx::query_scalar::<_, String>(
            "SELECT head_hash FROM v3_log WHERE chain_id=? AND log_id=? AND seq=?",
        )
        .bind(&c.chain_id)
        .bind(&c.log_id)
        .bind(covered as i64)
        .fetch_optional(&mut *db)
        .await?
        .ok_or_else(|| err("COMPACTION_UNSAFE"))?
    };
    if covered > c.head_seq || s(v, "covered_log_hash") != hash {
        return Err(err("COMPACTION_UNSAFE"));
    }
    for p in a(v, "snapshot_parts") {
        let part = store::object(&mut *db, &c.chain_id, "snapshot_part", s(p, "record_id"))
            .await?
            .ok_or_else(|| err("SNAPSHOT_INCOMPLETE"))?;
        if object_hash(&part) != s(p, "record_hash")
            || n(&part, "generation") != c.generation()
            || n(&part, "epoch") != n(&c.epoch, "epoch")
        {
            return Err(err("SNAPSHOT_INCOMPLETE"));
        }
        let key = if let Some(d) = staged
            .iter()
            .find(|d| s(d, "device_id") == s(&part, "device_id"))
        {
            s(d, "device_public_key").to_owned()
        } else {
            auth::active_device(&mut *db, c, s(&part, "device_id")).await?
        };
        verify(&part, &key, CTX_SYNC_RECORD)?;
        if (c.parameters["policy"]["metadata_profile"] == "private")
            != part["collection_tag"].is_null()
        {
            return Err(err("INVALID_FIELD"));
        }
    }
    Ok(())
}
pub fn target(v: &Value, keys: &[&str]) -> Value {
    let mut o = serde_json::Map::new();
    for k in keys {
        if let Some(v) = v.get(*k) {
            o.insert((*k).into(), v.clone());
        }
    }
    Value::Object(o)
}
pub fn rejection(v: &Value, id: &str, e: &ApiError) -> Value {
    json!({id:v[id],"status":e.status().as_u16(),"code":e.code,"retryable":e.retryable()})
}
