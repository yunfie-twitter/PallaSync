use super::{
    auth::Auth,
    error::*,
    store::{self, Chain},
    wire::*,
};
use crate::{config::RelayConfig, crypto::verify::*};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sqlx::{Row, SqliteConnection};
pub const RESPONSE_MAX: usize = 8 * 1024 * 1024;
const PAGE_BYTES: usize = RESPONSE_MAX - 32768;
pub fn pruned(c: &Chain) -> ApiError {
    let mut context = json!({"min_available_seq":c.min_available_seq,"log_id":c.log_id});
    if let Some(id) = &c.boundary_compaction_id {
        context["compaction_id"] = id.clone().into();
    }
    err("LOG_PRUNED").context(context)
}

#[derive(Clone)]
pub struct Page {
    pub cut: Chain,
    pub position: u64,
    pub key: String,
    pub limit: usize,
    pub resource: String,
    pub filters: Value,
    pub expires: u64,
    pub extra: Value,
}
pub fn query(q: &[(String, String)], name: &str) -> Option<String> {
    q.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
}
pub fn decimal(s: &str, min: u64, max: u64) -> Result<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(err("INVALID_FIELD"));
    }
    s.parse::<u64>()
        .ok()
        .filter(|n| *n >= min && *n <= max)
        .ok_or_else(|| err("INVALID_FIELD"))
}
pub fn allowed(q: &[(String, String)], names: &[&str]) -> Result<()> {
    if q.iter().any(|(k, _)| !names.contains(&k.as_str())) {
        return Err(err("FILTER_NOT_ALLOWED"));
    }
    Ok(())
}
pub async fn page(
    db: &mut SqliteConnection,
    c: &Chain,
    cfg: &RelayConfig,
    resource: &str,
    q: &[(String, String)],
    filters: Value,
) -> Result<Page> {
    let limit = query(q, "limit")
        .map(|s| decimal(&s, 1, n(cfg.limits(), "page_limit")))
        .transpose()?
        .unwrap_or(200.min(n(cfg.limits(), "page_limit"))) as usize;
    if query(q, "cursor").is_some() && query(q, "after_seq").is_some() {
        return Err(err("CURSOR_INVALID"));
    }
    if let Some(token) = query(q, "cursor") {
        if token.len() > 2048 || decode(&token, None).is_err() {
            return Err(err("CURSOR_INVALID"));
        }
        let row = sqlx::query(
            "SELECT chain_id,binding,state,expires_at_ms FROM v3_cursors WHERE cursor=?",
        )
        .bind(token)
        .fetch_optional(&mut *db)
        .await?
        .ok_or_else(|| err("CURSOR_INVALID"))?;
        if row.get::<String, _>("chain_id") != c.chain_id
            || row.get::<String, _>("binding")
                != store::text(&json!({"origin":cfg.origin,"resource":resource,"filters":filters}))
        {
            return Err(err("CURSOR_INVALID"));
        }
        let expires = row.get::<i64, _>("expires_at_ms") as u64;
        if now() > expires {
            return Err(err("CURSOR_EXPIRED"));
        }
        let state = store::value(row.get("state"));
        let cut: Chain = serde_json::from_value(state["cut"].clone()).unwrap();
        if cut.log_id != c.log_id || cut.generation() != c.generation() {
            return Err(err("LOG_ID_MISMATCH"));
        }
        if cut.transparency_id != c.transparency_id {
            return Err(err("TRANSPARENCY_ID_MISMATCH"));
        }
        return Ok(Page {
            cut,
            position: n(&state, "position"),
            key: s(&state, "key").into(),
            limit,
            resource: resource.into(),
            filters,
            expires,
            extra: state["extra"].clone(),
        });
    }
    let position = query(q, "after_seq")
        .map(|s| decimal(&s, 0, crate::crypto::jcs::MAX_INTEGER))
        .transpose()?
        .unwrap_or(0);
    let registry_version: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(id),0) FROM v3_registry_history WHERE chain_id=?")
            .bind(&c.chain_id)
            .fetch_one(&mut *db)
            .await?;
    let offer_version: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(id),0) FROM v3_offer_history WHERE chain_id=?")
            .bind(&c.chain_id)
            .fetch_one(&mut *db)
            .await?;
    Ok(Page {
        cut: c.clone(),
        position,
        key: String::new(),
        limit,
        resource: resource.into(),
        filters,
        expires: now() + 86400000,
        extra: json!({"registry_version":registry_version,"offer_version":offer_version}),
    })
}
pub async fn cursor(db: &mut SqliteConnection, cfg: &RelayConfig, p: &Page) -> Result<String> {
    let mut random = Vec::new();
    random.extend(uuid::Uuid::new_v4().as_bytes());
    random.extend(uuid::Uuid::new_v4().as_bytes());
    let token = URL_SAFE_NO_PAD.encode(random);
    let state = json!({"cut":p.cut,"position":p.position,"key":p.key,"extra":p.extra});
    sqlx::query(
        "INSERT INTO v3_cursors(cursor,chain_id,binding,state,expires_at_ms) VALUES(?,?,?,?,?)",
    )
    .bind(&token)
    .bind(&p.cut.chain_id)
    .bind(store::text(
        &json!({"origin":cfg.origin,"resource":p.resource,"filters":p.filters}),
    ))
    .bind(store::text(&state))
    .bind(p.expires as i64)
    .execute(&mut *db)
    .await?;
    store::quota(db, &p.cut.chain_id, cfg).await?;
    Ok(token)
}
async fn finish(
    db: &mut SqliteConnection,
    cfg: &RelayConfig,
    p: &Page,
    items: Vec<Value>,
    more: bool,
    log: bool,
) -> Result<Value> {
    let next = if more {
        Some(cursor(db, cfg, p).await?)
    } else {
        None
    };
    let mut v = json!({"items":items,"next_cursor":next,"has_more":more,"log_id":p.cut.log_id,"generation":p.cut.generation(),"head_seq":p.cut.head_seq});
    if log {
        v["head_hash"] = p.cut.head_hash.clone().into();
        v["scan_through_seq"] = p.position.into()
    }
    Ok(v)
}
fn fits(items: &[Value], bytes: &mut usize, v: &Value) -> bool {
    let size = store::text(v).len() + 1;
    if *bytes + size > PAGE_BYTES {
        return false;
    }
    *bytes += size;
    let _ = items;
    true
}
pub async fn log(
    db: &mut SqliteConnection,
    c: &Chain,
    cfg: &RelayConfig,
    auth: &Auth,
    route: &str,
    q: &[(String, String)],
) -> Result<Value> {
    allowed(
        q,
        if route == "records_get" {
            &["after_seq", "cursor", "limit", "collection_tag", "epoch"]
        } else {
            &["after_seq", "cursor", "limit"]
        },
    )?;
    let tag = query(q, "collection_tag");
    let epoch = query(q, "epoch");
    if tag.is_some() != epoch.is_some()
        || (tag.is_some() && c.parameters["policy"]["metadata_profile"] != "queryable")
    {
        return Err(err("FILTER_NOT_ALLOWED"));
    }
    if let Some(t) = &tag {
        decode(t, Some(16)).map_err(|_| err("INVALID_FIELD"))?;
    }
    let ep = epoch.map(|s| decimal(&s, 0, u32::MAX as u64)).transpose()?;
    let mut p = page(
        &mut *db,
        c,
        cfg,
        route,
        q,
        json!({"collection_tag":tag,"epoch":ep}),
    )
    .await?;
    if p.position < c.min_available_seq - 1 {
        return Err(pruned(c));
    }
    let rows=store::bounded_rows(sqlx::query("SELECT seq,entry FROM v3_log WHERE chain_id=? AND log_id=? AND seq>? AND seq<=? ORDER BY seq LIMIT 1000").bind(&c.chain_id).bind(&c.log_id).bind(p.position as i64).bind(p.cut.head_seq as i64), &mut *db, "entry").await?;
    let mut items = Vec::new();
    let mut bytes = 0;
    for row in rows {
        let seq = row.get::<i64, _>("seq") as u64;
        let entry = store::value(
            row.get::<Option<String>, _>("entry")
                .ok_or_else(|| pruned(c))?,
        );
        let include = route == "log"
            || (s(&entry, "kind") == "record"
                && (tag.is_none()
                    || (entry["object"]["collection_tag"] == tag.clone().unwrap()
                        && n(&entry["object"], "epoch") == ep.unwrap())));
        if include {
            if items.len() >= p.limit || !fits(&items, &mut bytes, &entry) {
                break;
            }
            if !auth.admin()
                && s(&entry, "kind") == "envelope"
                && entry["object"]["recipient_kind"] == "recovery"
            {
                return Err(err("ENVELOPE_ACCESS_DENIED"));
            }
            items.push(entry)
        }
        p.position = seq;
    }
    let more = p.position < p.cut.head_seq;
    finish(db, cfg, &p, items, more, true).await
}
pub async fn objects(
    db: &mut SqliteConnection,
    c: &Chain,
    cfg: &RelayConfig,
    auth: &Auth,
    route: &str,
    param: &str,
    q: &[(String, String)],
) -> Result<Value> {
    allowed(
        q,
        if route == "own_envelopes" {
            &["epoch", "cursor", "limit"]
        } else {
            &["cursor", "limit"]
        },
    )?;
    if route == "own_envelopes" && !auth.owns(param) {
        return Err(err("ENVELOPE_ACCESS_DENIED"));
    }
    let epoch = query(q, "epoch")
        .map(|s| decimal(&s, 0, u32::MAX as u64))
        .transpose()?;
    if let Some(e) = epoch
        && super::retention::expired(&mut *db, c, e).await?
    {
        return Err(err("HISTORY_KEY_EXPIRED"));
    }
    let mut p=page(&mut *db,c,cfg,route,q,json!({"device_id":param,"epoch":epoch,"requester":if route=="requests_get" {auth.device.clone()} else {None}})).await?;
    if route == "epochs_get" && p.key.is_empty() {
        p.key = "-1".into()
    }
    let kind = match route {
        "devices" => "device",
        "epochs_get" => "epoch",
        "snapshots_get" => "compaction",
        "own_envelopes" => "envelope",
        _ => unreachable!(),
    };
    let rows=store::bounded_rows(sqlx::query("SELECT object_id,body,relay_seq,log_id FROM v3_objects WHERE chain_id=? AND kind=? AND (CASE WHEN kind='epoch' THEN CAST(object_id AS INTEGER) ELSE object_id END) > (CASE WHEN ?='epoch' THEN CAST(? AS INTEGER) ELSE ? END) AND body IS NOT NULL AND (log_id IS NULL OR log_id<>? OR relay_seq<=?) ORDER BY CASE WHEN kind='epoch' THEN CAST(object_id AS INTEGER) ELSE object_id END LIMIT 1001").bind(&c.chain_id).bind(kind).bind(kind).bind(&p.key).bind(&p.key).bind(&c.log_id).bind(p.cut.head_seq as i64), &mut *db, "body").await?;
    let mut items = Vec::new();
    let mut bytes = 0;
    let mut more = false;
    for row in rows {
        let id: String = row.get("object_id");
        let body = store::value(row.get("body"));
        if route == "own_envelopes"
            && (body["recipient_kind"] != "device"
                || s(&body, "recipient_device_id") != param
                || epoch.is_some_and(|e| n(&body, "epoch") != e))
        {
            p.key = id;
            continue;
        }
        let item = match route {
            "devices" => {
                let r=sqlx::query("SELECT status,enrolled_seq,revoked_seq FROM v3_registry_history WHERE chain_id=? AND device_id=? AND id<=? ORDER BY id DESC LIMIT 1").bind(&c.chain_id).bind(&id).bind(n(&p.extra,"registry_version") as i64).fetch_one(&mut *db).await?;
                let revoked = r
                    .get::<Option<i64>, _>("revoked_seq")
                    .filter(|s| *s as u64 <= p.cut.head_seq);
                json!({"device_record":body,"status":if revoked.is_some() {"revoked".to_owned()} else {r.get::<String,_>("status")},"enrolled_seq":r.get::<i64,_>("enrolled_seq"),"revoked_seq":revoked})
            }
            "epochs_get" => epoch_wrapper(&mut *db, c, &body).await?,
            _ => body,
        };
        if items.len() >= p.limit || !fits(&items, &mut bytes, &item) {
            if items.is_empty() {
                return Err(err("PAYLOAD_TOO_LARGE"));
            }
            more = true;
            break;
        }
        p.key = id;
        items.push(item);
    }
    if !more {
        let left:i64=sqlx::query_scalar("SELECT COUNT(*) FROM v3_objects WHERE chain_id=? AND kind=? AND (CASE WHEN kind='epoch' THEN CAST(object_id AS INTEGER) ELSE object_id END) > (CASE WHEN ?='epoch' THEN CAST(? AS INTEGER) ELSE ? END) AND body IS NOT NULL AND (log_id IS NULL OR log_id<>? OR relay_seq<=?)").bind(&c.chain_id).bind(kind).bind(kind).bind(&p.key).bind(&p.key).bind(&c.log_id).bind(p.cut.head_seq as i64).fetch_one(&mut *db).await?;
        more = left > 0;
    }
    finish(db, cfg, &p, items, more, false).await
}
pub async fn epoch_wrapper(db: &mut SqliteConnection, c: &Chain, epoch: &Value) -> Result<Value> {
    let row=sqlx::query("SELECT l.entry,o.relay_seq FROM v3_objects o LEFT JOIN v3_log l ON l.chain_id=o.chain_id AND l.log_id=o.log_id AND l.seq=o.relay_seq WHERE o.chain_id=? AND o.kind='epoch' AND o.object_id=?").bind(&c.chain_id).bind(n(epoch,"epoch").to_string()).fetch_one(db).await?;
    let seq: Option<i64> = row.get("relay_seq");
    let entry: Option<String> = row.get("entry");
    // Staged imported history has no relay-assigned source times and is not exposed as a live epoch.
    let entry = entry
        .map(store::value)
        .ok_or_else(|| err("REPAIR_PROOF_REQUIRED"))?;
    Ok(
        json!({"epoch":epoch,"epoch_hash":object_hash(epoch),"committed_at_ms":n(&entry,"committed_at_ms"),"relay_seq":seq.unwrap()}),
    )
}
pub async fn transparency(
    db: &mut SqliteConnection,
    c: &Chain,
    cfg: &RelayConfig,
    q: &[(String, String)],
) -> Result<Value> {
    allowed(
        q,
        &[
            "transparency_id",
            "after_index",
            "through_index",
            "cursor",
            "limit",
        ],
    )?;
    let id = query(q, "transparency_id").ok_or_else(|| err("INVALID_FIELD"))?;
    if !uuid(&id) {
        return Err(err("INVALID_FIELD"));
    }
    if id != c.transparency_id {
        return Err(err("TRANSPARENCY_ID_MISMATCH"));
    }
    let after = query(q, "after_index")
        .map(|s| decimal(&s, 0, crate::crypto::jcs::MAX_INTEGER))
        .transpose()?
        .unwrap_or(0);
    let through = query(q, "through_index")
        .map(|s| decimal(&s, 0, crate::crypto::jcs::MAX_INTEGER))
        .transpose()?;
    let filters = json!({"transparency_id":id,"after_index":after,"through_index":through});
    let mut p = page(&mut *db, c, cfg, "transparency", q, filters).await?;
    if query(q, "cursor").is_none() {
        let through = through.unwrap_or(c.transparency_index);
        if after > through || through > c.transparency_index {
            return Err(err("TRANSPARENCY_RANGE_UNAVAILABLE"));
        }
        let head: Option<String> = sqlx::query_scalar(
            "SELECT head FROM v3_heads WHERE chain_id=? AND transparency_id=? AND idx=?",
        )
        .bind(&c.chain_id)
        .bind(&id)
        .bind(through as i64)
        .fetch_optional(&mut *db)
        .await?;
        p.extra = head
            .map(store::value)
            .ok_or_else(|| err("TRANSPARENCY_RANGE_UNAVAILABLE"))?;
        p.position = after;
    }
    let anchor = p.position;
    let anchor_hash = if anchor == 0 {
        store::initial_hash(
            b"PALLASYNC-TRANSPARENCY-v3\0",
            &c.chain_id,
            &id,
            Some(&cfg.key_id),
        )
    } else {
        sqlx::query_scalar::<_, String>(
            "SELECT hash FROM v3_transparency WHERE chain_id=? AND transparency_id=? AND idx=?",
        )
        .bind(&c.chain_id)
        .bind(&id)
        .bind(anchor as i64)
        .fetch_optional(&mut *db)
        .await?
        .ok_or_else(|| err("TRANSPARENCY_RANGE_UNAVAILABLE"))?
    };
    let end = n(&p.extra, "entry_index");
    let rows=sqlx::query_scalar::<_,String>("SELECT entry FROM v3_transparency WHERE chain_id=? AND transparency_id=? AND idx>? AND idx<=? ORDER BY idx LIMIT ?").bind(&c.chain_id).bind(&id).bind(p.position as i64).bind(end as i64).bind(p.limit as i64).fetch_all(&mut *db).await?;
    let mut items = Vec::new();
    let mut bytes = 0;
    for row in rows {
        let entry = store::value(row);
        if !fits(&items, &mut bytes, &entry) {
            break;
        }
        p.position = n(&entry, "entry_index");
        items.push(entry)
    }
    if items.is_empty() && p.position < end {
        return Err(err("TRANSPARENCY_RANGE_UNAVAILABLE"));
    }
    let more = p.position < end;
    let next = if more {
        Some(cursor(db, cfg, &p).await?)
    } else {
        None
    };
    Ok(
        json!({"items":items,"head":p.extra,"anchor_index":anchor,"anchor_hash":anchor_hash,"next_cursor":next,"has_more":more}),
    )
}
