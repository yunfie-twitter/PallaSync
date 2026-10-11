//! §12.2/§17: all evidence and acknowledgements share a durable SQLite transaction.
use super::{error::*, wire::*};
use crate::{
    config::RelayConfig,
    crypto::{
        jcs::{MAX_INTEGER, canonicalize_json},
        verify::*,
    },
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::TryStreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqliteConnection};

#[derive(Clone, Serialize, Deserialize)]
pub struct Chain {
    pub chain_id: String,
    pub parameters: Value,
    pub epoch: Value,
    pub log_id: String,
    pub head_seq: u64,
    pub head_hash: String,
    pub min_available_seq: u64,
    #[serde(default)]
    pub boundary_compaction_id: Option<String>,
    pub transparency_id: String,
    pub transparency_index: u64,
    pub transparency_hash: String,
    pub writable: bool,
    pub notice_id: String,
}
impl Chain {
    pub fn new(parameters: Value, epoch: Value, cfg: &RelayConfig, log_id: Option<String>) -> Self {
        let chain_id = s(&parameters, "chain_id").to_owned();
        let log_id = log_id.unwrap_or_else(new_id);
        let transparency_id = new_id();
        let head_hash = initial_hash(b"PALLASYNC-LOG-v3\0", &chain_id, &log_id, None);
        let transparency_hash = initial_hash(
            b"PALLASYNC-TRANSPARENCY-v3\0",
            &chain_id,
            &transparency_id,
            Some(&cfg.key_id),
        );
        Self {
            chain_id,
            parameters,
            epoch,
            log_id,
            head_seq: 0,
            head_hash,
            min_available_seq: 1,
            boundary_compaction_id: None,
            transparency_id,
            transparency_index: 0,
            transparency_hash,
            writable: true,
            notice_id: new_id(),
        }
    }
    pub fn generation(&self) -> u64 {
        n(&self.parameters, "generation")
    }
    pub fn parameters_hash(&self) -> String {
        object_hash(&self.parameters)
    }
    pub fn epoch_hash(&self) -> String {
        object_hash(&self.epoch)
    }
    pub fn head(&self) -> Value {
        json!({"log_id":self.log_id,"generation":self.generation(),"head_seq":self.head_seq,"head_hash":self.head_hash,"min_available_seq":self.min_available_seq,"epoch_hash":self.epoch_hash(),"parameters_hash":self.parameters_hash()})
    }
    pub fn result(&self) -> Value {
        json!({"parameters_hash":self.parameters_hash(),"epoch_hash":self.epoch_hash(),"log_id":self.log_id,"head_seq":self.head_seq,"head_hash":self.head_hash})
    }
}
pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}
pub fn initial_hash(ctx: &[u8], chain: &str, id: &str, key: Option<&str>) -> String {
    let mut bytes = ctx.to_vec();
    bytes.extend(decode(chain, Some(32)).unwrap());
    bytes.extend(uuid::Uuid::parse_str(id).unwrap().as_bytes());
    if let Some(k) = key {
        bytes.extend(decode(k, Some(32)).unwrap())
    }
    hash_bytes(&bytes)
}
pub fn link_hash(prev: &str, index: u64, entry: &Value, ctx: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(ctx);
    h.update(decode(prev, Some(32)).unwrap());
    h.update(index.to_be_bytes());
    h.update(decode(&object_hash(entry), Some(32)).unwrap());
    URL_SAFE_NO_PAD.encode(h.finalize())
}
pub fn text(v: &Value) -> String {
    String::from_utf8(canonicalize_json(v).expect("I-JSON")).unwrap()
}
pub fn value(v: String) -> Value {
    serde_json::from_str(&v).expect("stored validated value")
}
pub async fn load(db: &mut SqliteConnection, chain: &str) -> Result<Option<Chain>> {
    let body: Option<String> = sqlx::query_scalar("SELECT state FROM v3_chains WHERE chain_id=?")
        .bind(chain)
        .fetch_optional(db)
        .await?;
    Ok(body.map(|b| serde_json::from_str(&b).expect("stored chain")))
}
pub async fn save(db: &mut SqliteConnection, c: &Chain, cfg: &RelayConfig) -> Result<()> {
    sqlx::query("INSERT INTO v3_chains(chain_id,state) VALUES(?,?) ON CONFLICT(chain_id) DO UPDATE SET state=excluded.state").bind(&c.chain_id).bind(serde_json::to_string(c).unwrap()).execute(&mut *db).await?;
    let mut head = json!({"type":"PALLASYNC-TRANSPARENCY-HEAD-v3","version":"3.0","chain_id":c.chain_id,"log_id":c.log_id,"relay_key_id":cfg.key_id,"transparency_id":c.transparency_id,"entry_index":c.transparency_index,"transparency_hash":c.transparency_hash,"head_seq":c.head_seq,"head_hash":c.head_hash,"parameters_hash":c.parameters_hash(),"epoch_hash":c.epoch_hash(),"min_available_seq":c.min_available_seq,"timestamp":now()});
    sign_relay(&cfg.key, &mut head, CTX_HEAD).map_err(|_| err("INTERNAL_ERROR"))?;
    // One immutable published cut per index; if no evidence changed, preserve original time/signature.
    sqlx::query(
        "INSERT OR IGNORE INTO v3_heads(chain_id,transparency_id,idx,head) VALUES(?,?,?,?)",
    )
    .bind(&c.chain_id)
    .bind(&c.transparency_id)
    .bind(c.transparency_index as i64)
    .bind(text(&head))
    .execute(&mut *db)
    .await?;
    quota(db, &c.chain_id, cfg).await
}
pub async fn publish_notice(
    db: &mut SqliteConnection,
    c: &mut Chain,
    cfg: &RelayConfig,
) -> Result<()> {
    let existing: Option<String> =
        sqlx::query_scalar("SELECT notice FROM v3_notices WHERE chain_id=?")
            .bind(&c.chain_id)
            .fetch_optional(&mut *db)
            .await?;
    if let Some(existing) = existing {
        let old = value(existing);
        if old["shutdown_at_ms"] == serde_json::to_value(cfg.shutdown_at_ms).unwrap()
            && old["migration_origin"] == serde_json::to_value(&cfg.migration_origin).unwrap()
        {
            return Ok(());
        }
    } else if cfg.shutdown_at_ms.is_none() && cfg.migration_origin.is_none() {
        return Ok(());
    }
    let notice = json!({"shutdown_at_ms":cfg.shutdown_at_ms,"migration_origin":cfg.migration_origin,"notice_id":new_id(),"server_time_ms":now()});
    transparency(
        &mut *db,
        c,
        cfg,
        "migrate",
        &object_hash(&notice),
        None,
        None,
    )
    .await?;
    sqlx::query("INSERT INTO v3_notices(chain_id,notice) VALUES(?,?) ON CONFLICT(chain_id) DO UPDATE SET notice=excluded.notice").bind(&c.chain_id).bind(text(&notice)).execute(db).await?;
    Ok(())
}
pub async fn object(
    db: &mut SqliteConnection,
    c: &str,
    kind: &str,
    id: &str,
) -> Result<Option<Value>> {
    let b: Option<Option<String>> = sqlx::query_scalar(
        "SELECT body FROM v3_objects WHERE chain_id=? AND kind=? AND object_id=?",
    )
    .bind(c)
    .bind(kind)
    .bind(id)
    .fetch_optional(db)
    .await?;
    Ok(b.flatten().map(value))
}
pub async fn object_digest(
    db: &mut SqliteConnection,
    c: &str,
    kind: &str,
    id: &str,
) -> Result<Option<String>> {
    Ok(sqlx::query_scalar(
        "SELECT object_hash FROM v3_objects WHERE chain_id=? AND kind=? AND object_id=?",
    )
    .bind(c)
    .bind(kind)
    .bind(id)
    .fetch_optional(db)
    .await?)
}
pub fn object_id(v: &Value, kind: &str) -> String {
    match kind {
        "parameters" => n(v, "generation").to_string(),
        "epoch" => n(v, "epoch").to_string(),
        "device" => s(v, "device_id").into(),
        "envelope" => s(v, "envelope_id").into(),
        "compaction" => s(v, "compaction_id").into(),
        "admin" => s(v, "operation_id").into(),
        "record" | "snapshot_part" => s(v, "record_id").into(),
        _ => unreachable!(),
    }
}
pub fn conflict(kind: &str) -> ApiError {
    err(match kind {
        "record" | "snapshot_part" => "RECORD_ID_CONFLICT",
        "device" => "DEVICE_ID_CONFLICT",
        "envelope" => "ENVELOPE_ID_CONFLICT",
        "admin" => "OPERATION_ID_CONFLICT",
        _ => "IMPORT_CONFLICT",
    })
}
pub async fn put_object(
    db: &mut SqliteConnection,
    c: &str,
    kind: &str,
    v: &Value,
    log: Option<(&str, u64)>,
) -> Result<bool> {
    let id = object_id(v, kind);
    let digest = object_hash(v);
    if let Some(old) = object_digest(&mut *db, c, kind, &id).await? {
        if old != digest {
            return Err(conflict(kind));
        }
        return Ok(false);
    }
    if matches!(kind, "record" | "snapshot_part") {
        let other = if kind == "record" {
            "snapshot_part"
        } else {
            "record"
        };
        if object_digest(&mut *db, c, other, &id).await?.is_some() {
            return Err(conflict(kind));
        }
    }
    sqlx::query("INSERT INTO v3_objects(chain_id,kind,object_id,object_hash,body,log_id,relay_seq) VALUES(?,?,?,?,?,?,?)").bind(c).bind(kind).bind(&id).bind(digest).bind(text(v)).bind(log.map(|(id,_)|id)).bind(log.map(|(_,seq)|seq as i64)).execute(db).await?;
    Ok(true)
}
pub async fn transparency(
    db: &mut SqliteConnection,
    c: &mut Chain,
    cfg: &RelayConfig,
    op: &str,
    digest: &str,
    seq: Option<u64>,
    code: Option<&str>,
) -> Result<(Value, String)> {
    if c.transparency_index >= MAX_INTEGER {
        return Err(err("STORAGE_UNAVAILABLE"));
    }
    let i = c.transparency_index + 1;
    let mut entry = json!({"type":"PALLASYNC-TRANSPARENCY-ENTRY-v3","version":"3.0","transparency_id":c.transparency_id,"entry_index":i,"chain_id":c.chain_id,"log_id":c.log_id,"relay_key_id":cfg.key_id,"operation":op,"object_hash":digest,"relay_seq":seq,"resulting_head_hash":c.head_hash,"previous_transparency_hash":c.transparency_hash,"timestamp":now(),"code":code});
    sign_relay(&cfg.key, &mut entry, CTX_TRANSPARENCY).map_err(|_| err("INTERNAL_ERROR"))?;
    let hash = link_hash(
        &c.transparency_hash,
        i,
        &entry,
        b"PALLASYNC-TRANSPARENCY-LINK-v3\0",
    );
    sqlx::query(
        "INSERT INTO v3_transparency(chain_id,transparency_id,idx,entry,hash) VALUES(?,?,?,?,?)",
    )
    .bind(&c.chain_id)
    .bind(&c.transparency_id)
    .bind(i as i64)
    .bind(text(&entry))
    .bind(&hash)
    .execute(db)
    .await?;
    c.transparency_index = i;
    c.transparency_hash = hash.clone();
    Ok((entry, hash))
}
pub async fn receipt(db: &mut SqliteConnection, c: &str, kind: &str, id: &str) -> Result<Value> {
    let b: String = sqlx::query_scalar(
        "SELECT receipt FROM v3_receipts WHERE chain_id=? AND kind=? AND object_id=?",
    )
    .bind(c)
    .bind(kind)
    .bind(id)
    .fetch_one(db)
    .await?;
    Ok(value(b))
}
pub async fn append(
    db: &mut SqliteConnection,
    c: &mut Chain,
    cfg: &RelayConfig,
    kind: &str,
    v: &Value,
) -> Result<(Value, Value)> {
    let id = object_id(v, kind);
    if let Some(d) = object_digest(&mut *db, &c.chain_id, kind, &id).await? {
        if d != object_hash(v) {
            return Err(conflict(kind));
        }
        let receipt: Option<String> = sqlx::query_scalar(
            "SELECT receipt FROM v3_receipts WHERE chain_id=? AND kind=? AND object_id=?",
        )
        .bind(&c.chain_id)
        .bind(kind)
        .bind(&id)
        .fetch_optional(&mut *db)
        .await?;
        if let Some(receipt) = receipt {
            let receipt = value(receipt);
            let seq = n(&receipt, "relay_seq");
            let entry: Option<String> = sqlx::query_scalar(
                "SELECT entry FROM v3_log WHERE chain_id=? AND log_id=? AND seq=?",
            )
            .bind(&c.chain_id)
            .bind(s(&receipt, "log_id"))
            .bind(seq as i64)
            .fetch_one(&mut *db)
            .await?;
            return Ok((entry.map(value).unwrap_or(Value::Null), receipt));
        }
    }
    if c.head_seq >= MAX_INTEGER {
        return Err(err("STORAGE_UNAVAILABLE"));
    }
    let seq = c.head_seq + 1;
    let received = now();
    let previous = c.head_hash.clone();
    let mut entry = json!({"relay_seq":seq,"received_at_ms":received,"kind":kind,"object":v});
    if kind == "epoch" {
        entry["committed_at_ms"] = received.into()
    }
    put_object(&mut *db, &c.chain_id, kind, v, Some((&c.log_id, seq))).await?;
    sqlx::query("UPDATE v3_objects SET log_id=?,relay_seq=? WHERE chain_id=? AND kind=? AND object_id=? AND log_id IS NULL").bind(&c.log_id).bind(seq as i64).bind(&c.chain_id).bind(kind).bind(&id).execute(&mut *db).await?;
    c.head_hash = link_hash(&previous, seq, &entry, b"");
    c.head_seq = seq;
    sqlx::query("INSERT INTO v3_log(chain_id,log_id,seq,entry,head_hash) VALUES(?,?,?,?,?)")
        .bind(&c.chain_id)
        .bind(&c.log_id)
        .bind(seq as i64)
        .bind(text(&entry))
        .bind(&c.head_hash)
        .execute(&mut *db)
        .await?;
    let (_, hash) =
        transparency(&mut *db, c, cfg, "accept", &object_hash(v), Some(seq), None).await?;
    let r = make_receipt(
        c,
        cfg,
        v,
        ReceiptLink {
            seq: Some(seq),
            entry_hash: Some(object_hash(&entry)),
            previous: &previous,
            received,
            hash: &hash,
        },
    )?;
    store_receipt(db, c, kind, &id, &r).await?;
    Ok((entry, r))
}
struct ReceiptLink<'a> {
    seq: Option<u64>,
    entry_hash: Option<String>,
    previous: &'a str,
    received: u64,
    hash: &'a str,
}
fn make_receipt(c: &Chain, cfg: &RelayConfig, v: &Value, link: ReceiptLink<'_>) -> Result<Value> {
    let ReceiptLink {
        seq,
        entry_hash,
        previous,
        received,
        hash,
    } = link;
    let mut r = json!({"type":"PALLASYNC-UPLOAD-RECEIPT-v3","version":"3.0","receipt_id":new_id(),"chain_id":c.chain_id,"log_id":c.log_id,"relay_key_id":cfg.key_id,"relay_seq":seq,"object_hash":object_hash(v),"entry_hash":entry_hash,"previous_head_hash":previous,"resulting_head_hash":c.head_hash,"received_at_ms":received,"transparency_id":c.transparency_id,"transparency_index":c.transparency_index,"transparency_hash":hash});
    sign_relay(&cfg.key, &mut r, CTX_RECEIPT).map_err(|_| err("INTERNAL_ERROR"))?;
    Ok(r)
}
async fn store_receipt(
    db: &mut SqliteConnection,
    c: &Chain,
    kind: &str,
    id: &str,
    r: &Value,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO v3_receipts(chain_id,kind,object_id,log_id,seq,receipt) VALUES(?,?,?,?,?,?)",
    )
    .bind(&c.chain_id)
    .bind(kind)
    .bind(id)
    .bind(&c.log_id)
    .bind(r["relay_seq"].as_u64().map(|n| n as i64))
    .bind(text(r))
    .execute(db)
    .await?;
    Ok(())
}
pub async fn snapshot_part(
    db: &mut SqliteConnection,
    c: &mut Chain,
    cfg: &RelayConfig,
    v: &Value,
) -> Result<Value> {
    if !put_object(&mut *db, &c.chain_id, "snapshot_part", v, None).await? {
        return receipt(db, &c.chain_id, "snapshot_part", s(v, "record_id")).await;
    }
    let (_, hash) = transparency(&mut *db, c, cfg, "accept", &object_hash(v), None, None).await?;
    let r = make_receipt(
        c,
        cfg,
        v,
        ReceiptLink {
            seq: None,
            entry_hash: None,
            previous: &c.head_hash,
            received: now(),
            hash: &hash,
        },
    )?;
    store_receipt(db, c, "snapshot_part", s(v, "record_id"), &r).await?;
    Ok(r)
}
pub async fn used(db: &mut SqliteConnection, chain: &str) -> Result<u64> {
    let bytes:i64=sqlx::query_scalar("SELECT COALESCE(SUM(bytes),0) FROM (SELECT COALESCE(SUM(length(CAST(body AS BLOB))+length(object_id)+length(object_hash)),0) AS bytes FROM v3_objects WHERE chain_id=? UNION ALL SELECT COALESCE(SUM(length(CAST(entry AS BLOB))+length(head_hash)),0) FROM v3_log WHERE chain_id=? UNION ALL SELECT COALESCE(SUM(length(CAST(receipt AS BLOB))),0) FROM v3_receipts WHERE chain_id=? UNION ALL SELECT COALESCE(SUM(length(CAST(entry AS BLOB))+length(hash)),0) FROM v3_transparency WHERE chain_id=? UNION ALL SELECT COALESCE(SUM(length(CAST(head AS BLOB))),0) FROM v3_heads WHERE chain_id=? UNION ALL SELECT COALESCE(SUM(length(CAST(response AS BLOB))),0) FROM v3_outcomes WHERE chain_id=? UNION ALL SELECT COALESCE(SUM(length(CAST(state AS BLOB))),0) FROM v3_cursors WHERE chain_id=? UNION ALL SELECT COALESCE(SUM(length(CAST(offer AS BLOB))+COALESCE(length(CAST(request AS BLOB)),0)),0) FROM v3_offers WHERE chain_id=?)").bind(chain).bind(chain).bind(chain).bind(chain).bind(chain).bind(chain).bind(chain).bind(chain).fetch_one(db).await?;
    Ok(bytes.max(0) as u64)
}
pub async fn quota(db: &mut SqliteConnection, chain: &str, cfg: &RelayConfig) -> Result<()> {
    let used = used(db, chain).await?;
    if cfg.max_bytes.is_some_and(|max| used > max) {
        return Err(
            err("QUOTA_EXCEEDED").context(json!({"used_bytes":used,"max_bytes":cfg.max_bytes}))
        );
    }
    Ok(())
}
pub async fn outcomes(
    db: &mut SqliteConnection,
    chain: &str,
    scope: &str,
    id: &str,
    payload: &Value,
) -> Result<Option<Value>> {
    let row = sqlx::query(
        "SELECT digest,response FROM v3_outcomes WHERE chain_id=? AND scope=? AND operation_id=?",
    )
    .bind(chain)
    .bind(scope)
    .bind(id)
    .fetch_optional(db)
    .await?;
    if let Some(row) = row {
        if row.get::<String, _>("digest") != object_hash(payload) {
            return Err(err(if scope == "genesis" {
                "CHAIN_EXISTS"
            } else {
                "OPERATION_ID_CONFLICT"
            }));
        }
        return Ok(Some(value(row.get("response"))));
    }
    Ok(None)
}
pub async fn outcome(
    db: &mut SqliteConnection,
    chain: &str,
    scope: &str,
    id: &str,
    payload: &Value,
    response: &Value,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO v3_outcomes(chain_id,scope,operation_id,digest,response) VALUES(?,?,?,?,?)",
    )
    .bind(chain)
    .bind(scope)
    .bind(id)
    .bind(object_hash(payload))
    .bind(text(response))
    .execute(db)
    .await?;
    Ok(())
}

/// Bound RAM by serialized bytes even when a page contains large ciphertexts/compactions.
pub async fn bounded_rows<'q>(
    query: sqlx::query::Query<'q, sqlx::Sqlite, sqlx::sqlite::SqliteArguments<'q>>,
    db: &mut SqliteConnection,
    field: &str,
) -> Result<Vec<sqlx::sqlite::SqliteRow>> {
    let mut stream = query.fetch(db);
    let mut rows = Vec::new();
    let mut bytes = 0usize;
    while let Some(row) = stream.try_next().await? {
        let size = row
            .try_get::<Option<String>, _>(field)?
            .map_or(0, |s| s.len());
        if bytes + size > 8 * 1024 * 1024 {
            if rows.is_empty() {
                return Err(err("PAYLOAD_TOO_LARGE"));
            }
            break;
        }
        bytes += size;
        rows.push(row);
    }
    Ok(rows)
}
