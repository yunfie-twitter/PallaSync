use super::{
    auth::{self, Auth},
    domain::*,
    error::*,
    store::{self},
    wire::*,
};
use crate::{config::RelayConfig, crypto::verify::*, db::DbState};
use serde_json::{Value, json};

pub async fn upload(
    db: &DbState,
    cfg: &RelayConfig,
    auth: &Auth,
    chain: &str,
    route: &str,
    param: &str,
    v: &Value,
) -> Result<Value> {
    let envelope_route = route == "envelopes_post";
    let repair = route == "repair";
    let snapshot = route == "parts_post";
    let key = if envelope_route {
        "envelopes"
    } else {
        "records"
    };
    let id_key = if envelope_route {
        "envelope_id"
    } else {
        "record_id"
    };
    if repair {
        auth.require_admin()?;
        fields(
            v,
            &[
                ("source_log_id", "uuid"),
                ("records", "array"),
                ("receipts", "array"),
            ],
            &[],
        )?
    } else {
        fields(v, &[(key, "array")], &[])?
    }
    if route == "records_post" && auth.admin() {
        return Err(err("DEVICE_KEY_MISMATCH"));
    }
    let records = a(v, key);
    let max = if envelope_route {
        128
    } else {
        n(cfg.limits(), "max_records_per_upload") as usize
    };
    if records.is_empty()
        || records.len() > max
        || (repair && a(v, "receipts").len() != records.len())
    {
        return Err(err("INVALID_FIELD"));
    }
    let mut ids = std::collections::HashSet::new();
    for r in records {
        if !uuid(s(r, id_key)) || !ids.insert(s(r, id_key)) {
            return Err(err("INVALID_FIELD"));
        }
    }
    let mut conn = db.pool.acquire().await?;
    if cfg.max_bytes.is_some_and(|max| max == 0) {
        return Err(err("QUOTA_EXCEEDED"));
    }
    store::quota(&mut conn, chain, cfg).await?;
    drop(conn);
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    let mut receipts = Vec::new();
    let mut final_chain = None;
    for (index, r) in records.iter().enumerate() {
        let mut tx = match db.pool.begin_with("BEGIN IMMEDIATE").await {
            Ok(tx) => tx,
            Err(e) => {
                let e = ApiError::from(e);
                if accepted.is_empty() {
                    return Err(e);
                }
                for r in &records[index..] {
                    rejected.push(rejection(r, id_key, &e));
                }
                break;
            }
        };
        let mut c = match store::load(&mut tx, chain)
            .await
            .and_then(|c| c.ok_or_else(|| err("CHAIN_NOT_FOUND")))
        {
            Ok(c) => c,
            Err(e) => {
                let _ = tx.rollback().await;
                if accepted.is_empty() {
                    return Err(e);
                }
                for r in &records[index..] {
                    rejected.push(rejection(r, id_key, &e));
                }
                break;
            }
        };
        if final_chain.is_none() {
            final_chain = Some(c.clone());
        }
        let attempt=async {
            cfg.write_guard()?;
            if let Some(p)=super::deletion::proof(&mut tx,chain).await? {return Err(super::deletion::gone(&p))}
            if let Some(device)=&auth.device {auth::active_device(&mut tx,&c,device).await?;}
            if envelope_route {
                validate(r,"envelope")?;
                if s(r,"recipient_kind")!="device" {return Err(err("ENVELOPE_ACCESS_DENIED"))}
                if n(r,"epoch").to_string()!=param {return Err(err("INVALID_FIELD"))}
                if !auth.admin() && auth.device.as_deref()!=Some(s(r,"signer_device_id")) {return Err(err("DEVICE_KEY_MISMATCH"))}
                let ep=store::object(&mut tx,chain,"epoch",param).await?.ok_or_else(||err("EPOCH_NOT_FOUND"))?;
                if super::retention::expired(&mut tx,&c,n(r,"epoch")).await? {return Err(err("HISTORY_KEY_EXPIRED"))}
                envelope(&mut tx,&c,r,&ep,&[]).await?;
                let (_,receipt)=store::append(&mut tx,&mut c,cfg,"envelope",r).await?;
                Ok((Value::String(s(r,id_key).into()),Some(receipt)))
            } else if repair {
                validate(r,"record")?;bound(r,&c)?;
                let source=&a(v,"receipts")[index];
                fields(source,&[("relay_seq","int"),("received_at_ms","int"),("kind","record"),("object","object")],&[])?;
                if source["object"]!=*r {return Err(err("REPAIR_PROOF_REQUIRED"))}
                // A signature/backdated timestamp alone is never evidence of historical relay acceptance.
                let known:Option<String>=sqlx::query_scalar("SELECT entry FROM v3_log WHERE chain_id=? AND log_id=? AND seq=?").bind(chain).bind(s(v,"source_log_id")).bind(n(source,"relay_seq") as i64).fetch_optional(&mut *tx).await?.flatten();
                if known.map(store::value).as_ref()!=Some(source) {return Err(err("REPAIR_PROOF_REQUIRED"))}
                let duplicate=store::object_digest(&mut tx,chain,"record",s(r,"record_id")).await?.is_some();
                let (entry,receipt)=store::append(&mut tx,&mut c,cfg,"record",r).await?;
                Ok((json!({"record_id":r["record_id"],"duplicate":duplicate,"receipt":if entry.is_null() {source.clone()} else {entry}}),Some(receipt)))
            } else {
                if !c.writable && !snapshot {return Err(err("CHAIN_NOT_FOUND"))}
                let staged=sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM v3_imports WHERE chain_id=?").bind(chain).fetch_one(&mut *tx).await?>0;
                let duplicate=record(&mut tx,&c,r,auth,snapshot,staged).await?;
                reserve_payload_nonce(&mut tx,&c,r).await?;
                if snapshot {
                    let receipt=store::snapshot_part(&mut tx,&mut c,cfg,r).await?;
                    Ok((Value::String(s(r,id_key).into()),Some(receipt)))
                } else {
                    let (entry,receipt)=store::append(&mut tx,&mut c,cfg,"record",r).await?;
                    // Reconstruct a removed duplicate's original LogEntry from its signed object and immutable receipt.
                    let entry=if entry.is_null() {json!({"relay_seq":receipt["relay_seq"],"received_at_ms":receipt["received_at_ms"],"kind":"record","object":r})} else {entry};
                    Ok((json!({"record_id":r["record_id"],"duplicate":duplicate,"receipt":entry}),Some(receipt)))
                }
            }
        }.await;
        let attempt = match attempt {
            Ok(result) => store::save(&mut tx, &c, cfg).await.map(|_| result),
            Err(e) => Err(e),
        };
        match attempt {
            Ok((item, receipt)) => {
                if let Err(e) = tx.commit().await {
                    let e = ApiError::from(e);
                    if accepted.is_empty() {
                        return Err(e);
                    }
                    rejected.push(rejection(r, id_key, &e));
                    for r in &records[index + 1..] {
                        rejected.push(rejection(r, id_key, &e));
                    }
                    break;
                }
                accepted.push(item);
                if let Some(r) = receipt {
                    receipts.push(r)
                }
                final_chain = Some(c);
            }
            Err(e) => {
                if let Err(failure) = tx.rollback().await {
                    let failure = ApiError::from(failure);
                    if accepted.is_empty() {
                        return Err(failure);
                    }
                    for r in &records[index..] {
                        rejected.push(rejection(r, id_key, &failure));
                    }
                    break;
                }
                if accepted.is_empty() && matches!(e.code, "QUOTA_EXCEEDED" | "STORAGE_UNAVAILABLE")
                {
                    return Err(e);
                }
                rejected.push(rejection(r, id_key, &e));
                if !matches!(
                    e.code,
                    "QUOTA_EXCEEDED" | "STORAGE_UNAVAILABLE" | "CHAIN_DELETED"
                ) && validate(r, if envelope_route { "envelope" } else { "record" }).is_ok()
                {
                    match audit_reject(db, cfg, chain, r, e.code).await {
                        Ok(c) => final_chain = Some(c),
                        Err(failure) => {
                            if accepted.is_empty() {
                                return Err(failure);
                            }
                            *rejected.last_mut().unwrap() = rejection(r, id_key, &failure);
                            for r in &records[index + 1..] {
                                rejected.push(rejection(r, id_key, &failure));
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
    if snapshot {
        let ids: std::collections::HashMap<String, String> = records
            .iter()
            .map(|r| (object_hash(r), s(r, "record_id").to_owned()))
            .collect();
        receipts.sort_by_key(|r| ids.get(s(r, "object_hash")).cloned().unwrap());
    } else {
        receipts.sort_by_key(|r| n(r, "relay_seq"));
    }
    let mut response = json!({"accepted":accepted,"rejected":rejected,"upload_receipts":receipts});
    if !snapshot && !envelope_route {
        let c = if let Some(c) = final_chain {
            c
        } else {
            let mut conn = db.pool.acquire().await?;
            store::load(&mut conn, chain).await?.unwrap()
        };
        response["generation"] = c.generation().into();
        response["log_id"] = c.log_id.into();
        response["head_seq"] = c.head_seq.into();
        response["head_hash"] = c.head_hash.into();
        if repair {
            response["repair_required"] = (!rejected.is_empty()).into();
        }
    }
    Ok(response)
}

async fn audit_reject(
    db: &DbState,
    cfg: &RelayConfig,
    chain: &str,
    r: &Value,
    code: &str,
) -> Result<store::Chain> {
    let mut tx = db.pool.begin_with("BEGIN IMMEDIATE").await?;
    let mut c = store::load(&mut tx, chain)
        .await?
        .ok_or_else(|| err("CHAIN_NOT_FOUND"))?;
    store::transparency(
        &mut tx,
        &mut c,
        cfg,
        "reject",
        &object_hash(r),
        None,
        Some(code),
    )
    .await?;
    store::save(&mut tx, &c, cfg).await?;
    tx.commit().await?;
    Ok(c)
}
