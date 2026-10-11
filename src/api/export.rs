//! §17.4/§17.10: bounded JCS JSONL chunks pin both data and transparency cuts.
use super::{
    auth::Auth,
    error::*,
    read::{self, Page},
    store::{self, Chain},
    wire::*,
};
use crate::{config::RelayConfig, crypto::verify::*};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sqlx::{Row, SqliteConnection};

pub async fn export(
    db: &mut SqliteConnection,
    c: &Chain,
    cfg: &RelayConfig,
    auth: &Auth,
    q: &[(String, String)],
) -> Result<String> {
    read::allowed(q, &["cursor", "limit", "include_recovery"])?;
    let include = read::query(q, "include_recovery")
        .map(|s| match s.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(err("INVALID_FIELD")),
        })
        .transpose()?
        .unwrap_or(false);
    if include && !auth.admin() {
        return Err(err("ENVELOPE_ACCESS_DENIED"));
    }
    let mut p = read::page(
        &mut *db,
        c,
        cfg,
        "export",
        q,
        json!({"include_recovery":include}),
    )
    .await?;
    if p.cut.min_available_seq < c.min_available_seq {
        return Err(read::pruned(c));
    }
    if read::query(q, "cursor").is_none() {
        let head: String = sqlx::query_scalar(
            "SELECT head FROM v3_heads WHERE chain_id=? AND transparency_id=? AND idx=?",
        )
        .bind(&c.chain_id)
        .bind(&c.transparency_id)
        .bind(c.transparency_index as i64)
        .fetch_one(&mut *db)
        .await?;
        p.extra = json!({"phase":0,"head":store::value(head)});
    }
    let header = json!({"kind":"header","protocol":"pallasync/3","chain_id":c.chain_id,"generation":p.cut.generation(),"log_id":p.cut.log_id,"head_seq":p.cut.head_seq,"head_hash":p.cut.head_hash,"include_recovery":include,"relay_public_key":URL_SAFE_NO_PAD.encode(cfg.key.verifying_key().as_bytes()),"relay_key_id":cfg.key_id,"transparency_id":p.cut.transparency_id,"transparency_head_index":p.cut.transparency_index,"transparency_head_hash":p.cut.transparency_hash});
    let mut out = store::text(&header) + "\n";
    let mut count = 0;
    loop {
        let phase = n(&p.extra, "phase");
        if phase >= 10 {
            break;
        }
        let rows = group(&mut *db, &p, phase).await?;
        let mut all = true;
        for (key, item) in rows {
            let item = protect(item, include);
            let line = item.map(|v| store::text(&v) + "\n");
            if let Some(line) = line {
                if count >= p.limit || out.len() + line.len() > read::RESPONSE_MAX - 4096 {
                    all = false;
                    break;
                }
                out.push_str(&line);
                count += 1;
            }
            p.key = key;
        }
        if !all {
            break;
        }
        // A bounded SQL page can end before a group does; continue from its stable key.
        let more = group(&mut *db, &p, phase).await?;
        if !more.is_empty() {
            if count >= p.limit {
                break;
            }
            continue;
        }
        p.extra["phase"] = (phase + 1).into();
        p.key.clear();
        if count >= p.limit {
            break;
        }
    }
    let more = n(&p.extra, "phase") < 10;
    let next = if more {
        Some(read::cursor(db, cfg, &p).await?)
    } else {
        None
    };
    out.push_str(
        &(store::text(&json!({"kind":"continuation","next_cursor":next,"has_more":more})) + "\n"),
    );
    if out.len() > read::RESPONSE_MAX {
        return Err(err("PAYLOAD_TOO_LARGE"));
    }
    Ok(out)
}
fn protect(item: Value, include: bool) -> Option<Value> {
    let object = if s(&item, "kind") == "log" {
        Some(&item["entry"]["object"])
    } else if s(&item, "kind") == "control" {
        Some(&item["object"])
    } else if s(&item, "kind") == "source_receipt" {
        Some(&item["receipt"]["object"])
    } else {
        None
    };
    if !include && object.is_some_and(|v| v["recipient_kind"] == "recovery") {
        if s(&item, "kind") == "log" {
            return Some(
                json!({"kind":"omitted","relay_seq":item["entry"]["relay_seq"],"object_hash":object_hash(&item["entry"]["object"]),"reason":"recovery_authority"}),
            );
        }
        return None;
    }
    Some(item)
}
async fn group(db: &mut SqliteConnection, p: &Page, phase: u64) -> Result<Vec<(String, Value)>> {
    let c = &p.cut;
    let limit = (p.limit + 1) as i64;
    let mut out = Vec::new();
    match phase {
        0 => {
            let seq = if p.key.is_empty() {
                0
            } else {
                p.key.parse::<u64>().unwrap()
            };
            let rows=store::bounded_rows(sqlx::query("SELECT seq,entry FROM v3_log WHERE chain_id=? AND log_id=? AND seq>? AND seq<=? AND entry IS NOT NULL ORDER BY seq LIMIT ?").bind(&c.chain_id).bind(&c.log_id).bind(seq as i64).bind(c.head_seq as i64).bind(limit), db, "entry").await?;
            for r in rows {
                out.push((
                    r.get::<i64, _>("seq").to_string(),
                    json!({"kind":"log","entry":store::value(r.get("entry"))}),
                ))
            }
        }
        1 | 2 | 5 => {
            let kind = if phase == 5 {
                "snapshot_part"
            } else {
                "compaction"
            };
            let rows=store::bounded_rows(sqlx::query("SELECT o.object_id,o.body FROM v3_objects o LEFT JOIN v3_receipts r ON r.chain_id=o.chain_id AND r.kind=o.kind AND r.object_id=o.object_id WHERE o.chain_id=? AND o.kind=? AND o.object_id>? AND o.body IS NOT NULL AND json_extract(o.body,'$.generation')<=? AND (r.receipt IS NULL OR json_extract(r.receipt,'$.transparency_index')<=?) AND (?=0 OR o.object_id=?) ORDER BY o.object_id LIMIT ?").bind(&c.chain_id).bind(kind).bind(&p.key).bind(c.generation() as i64).bind(c.transparency_index as i64).bind(i64::from(phase==1)).bind(&c.boundary_compaction_id).bind(limit), db, "body").await?;
            for r in rows {
                let body = store::value(r.get("body"));
                let item = if phase == 5 {
                    json!({"kind":"snapshot_part","record":body})
                } else if phase == 2 {
                    json!({"kind":"compaction","compaction":body})
                } else {
                    json!({"kind":"boundary","compaction":body})
                };
                out.push((r.get("object_id"), item))
            }
        }
        4 => {
            let rows=store::bounded_rows(sqlx::query("SELECT object_id,object_hash FROM v3_objects WHERE chain_id=? AND kind='record' AND body IS NULL AND object_id>? ORDER BY object_id LIMIT ?").bind(&c.chain_id).bind(&p.key).bind(limit), db, "object_hash").await?;
            for r in rows {
                out.push((r.get("object_id"),json!({"kind":"removed_id","record_id":r.get::<String,_>("object_id"),"record_hash":r.get::<String,_>("object_hash")})))
            }
        }
        3 => {
            let rows=store::bounded_rows(sqlx::query("SELECT kind,object_id,body FROM v3_objects WHERE chain_id=? AND kind IN ('parameters','device','epoch','envelope','admin') AND kind||':'||object_id>? AND body IS NOT NULL AND (log_id IS NULL OR log_id<>?) AND json_extract(body,'$.generation')<=? ORDER BY kind,object_id LIMIT ?").bind(&c.chain_id).bind(&p.key).bind(&c.log_id).bind(c.generation() as i64).bind(limit), db, "body").await?;
            for r in rows {
                let kind: String = r.get("kind");
                let id: String = r.get("object_id");
                out.push((format!("{kind}:{id}"),json!({"kind":"control","object_type":kind,"object":store::value(r.get("body"))})))
            }
        }
        6 => {
            let rows=store::bounded_rows(sqlx::query("SELECT l.entry,json_extract(r.receipt,'$.entry_hash') AS sort_key FROM v3_log l JOIN v3_receipts r ON r.chain_id=l.chain_id AND r.log_id=l.log_id AND r.seq=l.seq WHERE l.chain_id=? AND l.log_id<>? AND l.entry IS NOT NULL AND json_extract(r.receipt,'$.transparency_index')<=? AND json_extract(r.receipt,'$.entry_hash')>? ORDER BY sort_key LIMIT ?").bind(&c.chain_id).bind(&c.log_id).bind(c.transparency_index as i64).bind(&p.key).bind(limit),db,"entry").await?;
            for row in rows {
                let entry = store::value(row.get("entry"));
                out.push((
                    row.get("sort_key"),
                    json!({"kind":"source_receipt","receipt":entry}),
                ));
            }
        }
        7 => {
            let rows=store::bounded_rows(sqlx::query("SELECT receipt,CASE WHEN seq IS NULL THEN 'z'||json_extract(receipt,'$.receipt_id') ELSE printf('%016d',seq)||':'||log_id END AS sort_key FROM v3_receipts WHERE chain_id=? AND json_extract(receipt,'$.transparency_index')<=? AND CASE WHEN seq IS NULL THEN 'z'||json_extract(receipt,'$.receipt_id') ELSE printf('%016d',seq)||':'||log_id END>? ORDER BY sort_key LIMIT ?").bind(&c.chain_id).bind(c.transparency_index as i64).bind(&p.key).bind(limit), db, "receipt").await?;
            for r in rows {
                out.push((
                    r.get("sort_key"),
                    json!({"kind":"upload_receipt","receipt":store::value(r.get("receipt"))}),
                ))
            }
        }
        8 => {
            let index = if p.key.is_empty() {
                0
            } else {
                p.key.parse::<u64>().unwrap()
            };
            let rows=store::bounded_rows(sqlx::query("SELECT idx,entry FROM v3_transparency WHERE chain_id=? AND transparency_id=? AND idx>? AND idx<=? ORDER BY idx LIMIT ?").bind(&c.chain_id).bind(&c.transparency_id).bind(index as i64).bind(c.transparency_index as i64).bind(limit), db, "entry").await?;
            for r in rows {
                out.push((
                    r.get::<i64, _>("idx").to_string(),
                    json!({"kind":"transparency_entry","entry":store::value(r.get("entry"))}),
                ))
            }
        }
        9 => {
            if p.key.is_empty() {
                out.push((
                    "head".into(),
                    json!({"kind":"transparency_head","head":p.extra["head"]}),
                ))
            }
        }
        _ => unreachable!(),
    }
    Ok(out)
}
