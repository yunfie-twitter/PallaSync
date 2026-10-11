use super::{
    auth::Auth,
    domain::*,
    error::*,
    store::{self, Chain},
    wire::*,
};
use crate::{config::RelayConfig, crypto::verify::*};
use serde_json::{Value, json};
use sqlx::{Row, SqliteConnection};

pub async fn delete(
    db: &mut SqliteConnection,
    c: &mut Chain,
    cfg: &RelayConfig,
    auth: &Auth,
    v: &Value,
) -> Result<Value> {
    fields(
        v,
        &[
            ("deletion_id", "uuid"),
            ("expected_parameters_hash", "b32"),
            ("expected_epoch_hash", "b32"),
            ("admin_operation", "object?"),
        ],
        &[],
    )?;
    if !auth.admin() && c.parameters["policy"]["allow_device_chain_delete"] != true {
        return Err(err("ADMIN_REQUIRED"));
    }
    cas(c, &v["expected_parameters_hash"], &v["expected_epoch_hash"])?;
    let op = &v["admin_operation"];
    let authority = if auth.admin() {
        admin_operation(
            &mut *db,
            c,
            op,
            "delete_chain",
            &target(
                v,
                &[
                    "deletion_id",
                    "expected_parameters_hash",
                    "expected_epoch_hash",
                ],
            ),
        )
        .await?;
        object_hash(op)
    } else {
        if !op.is_null() {
            return Err(err("INVALID_FIELD"));
        }
        object_hash(&json!({"token":auth.token,"request":v}))
    };
    let mut receipts = Vec::new();
    if auth.admin() {
        receipts.push(store::append(&mut *db, c, cfg, "admin", op).await?.1)
    }
    let t = now();
    let deadline = t + n(&cfg.privacy["deletion"], "active_delete_max_ms");
    let mut ledger = json!({"chain_id":c.chain_id,"deletion_id":v["deletion_id"],"authorized_parameters_hash":c.parameters_hash(),"authorized_epoch_hash":c.epoch_hash(),"authorization_hash":authority,"requested_at_ms":t,"completed_at_ms":null,"assurance":"backup-expiry","delete_after_ms":deadline});
    ledger["receipt_hash"] = object_hash(&ledger).into();
    let (entry, _) = store::transparency(
        &mut *db,
        c,
        cfg,
        "delete",
        &object_hash(&ledger),
        None,
        None,
    )
    .await?;
    let receipt = delete_receipt(c, cfg, &ledger, c.transparency_index, &c.transparency_hash)?;
    let mut certificates = Vec::new();
    let mut device_key = None;
    if let Some(id) = &auth.device {
        let mut current = id.clone();
        let mut seen = std::collections::HashSet::new();
        loop {
            if !seen.insert(current.clone()) {
                return Err(err("ENROLLMENT_CERTIFICATE_INVALID"));
            }
            let d = store::object(&mut *db, &c.chain_id, "device", &current)
                .await?
                .ok_or_else(|| err("ENROLLMENT_CERTIFICATE_INVALID"))?;
            if device_key.is_none() {
                device_key = Some(s(&d, "device_public_key").to_owned())
            }
            let cert = d["enrollment"].clone();
            certificates.push(cert.clone());
            if s(&cert, "signer_kind") == "admin" {
                break;
            }
            current = s(&cert, "signer_device_id").into();
        }
    }
    let proof = json!({"ledger":ledger,"parameters":c.parameters,"epoch":c.epoch,"enrollment_chain":certificates,"admin_operation":op,"device_authorization":if auth.admin() {Value::Null} else {json!({"token":auth.token,"request":v})},"delete_receipt":receipt,"deletion_transparency_entry":entry});
    let response = json!({"deletion_id":v["deletion_id"],"state":"deleting","assurance":"backup-expiry","delete_after_ms":deadline,"receipt_hash":ledger["receipt_hash"],"delete_receipt":receipt,"upload_receipts":receipts});
    sqlx::query("INSERT INTO v3_deletions(chain_id,deleting_device_id,admin_public_key,device_public_key,proof,outcome,request_hash) VALUES(?,?,?,?,?,?,?)").bind(&c.chain_id).bind(&auth.device).bind(s(&c.parameters,"admin_public_key")).bind(device_key).bind(store::text(&proof)).bind(store::text(&response)).bind(object_hash(v)).execute(db).await?;
    Ok(response)
}
fn delete_receipt(
    c: &Chain,
    cfg: &RelayConfig,
    ledger: &Value,
    index: u64,
    hash: &str,
) -> Result<Value> {
    let mut r = json!({"type":"PALLASYNC-DELETE-RECEIPT-v3","version":"3.0","chain_id":c.chain_id,"log_id":c.log_id,"relay_key_id":cfg.key_id,"deletion_id":ledger["deletion_id"],"authorized_parameters_hash":ledger["authorized_parameters_hash"],"authorized_epoch_hash":ledger["authorized_epoch_hash"],"authorization_hash":ledger["authorization_hash"],"requested_at_ms":ledger["requested_at_ms"],"completed_at_ms":ledger["completed_at_ms"],"assurance":ledger["assurance"],"delete_after_ms":ledger["delete_after_ms"],"ledger_receipt_hash":ledger["receipt_hash"],"transparency_id":c.transparency_id,"transparency_index":index,"transparency_hash":hash});
    sign_relay(&cfg.key, &mut r, CTX_DELETE).map_err(|_| err("INTERNAL_ERROR"))?;
    Ok(r)
}
pub async fn proof(db: &mut SqliteConnection, chain: &str) -> Result<Option<Value>> {
    Ok(
        sqlx::query_scalar::<_, String>("SELECT proof FROM v3_deletions WHERE chain_id=?")
            .bind(chain)
            .fetch_optional(db)
            .await?
            .map(store::value),
    )
}
pub fn gone(proof: &Value) -> ApiError {
    let l = &proof["ledger"];
    err("CHAIN_DELETED").context(json!({"deletion_id":l["deletion_id"],"assurance":l["assurance"],"delete_after_ms":l["delete_after_ms"],"receipt_hash":l["receipt_hash"]}))
}
/// Ledger denial precedes erasure. secure_delete plus a successful WAL truncation remove this implementation's active copies.
/// A completion receipt is never fabricated before the storage checks succeed.
pub async fn erase(db: &crate::db::DbState) -> Result<()> {
    let mut tx = db.pool.begin_with("BEGIN IMMEDIATE").await?;
    let chains: Vec<String> = sqlx::query_scalar("SELECT chain_id FROM v3_deletions WHERE json_extract(proof,'$.ledger.completed_at_ms') IS NULL")
        .fetch_all(&mut *tx)
        .await?;
    if chains.is_empty() {
        tx.rollback().await?;
        return Ok(());
    }
    for chain in &chains {
        for table in [
            "v3_objects",
            "v3_log",
            "v3_registry",
            "v3_outcomes",
            "v3_offers",
            "v3_cursors",
            "v3_imports",
            "v3_payload_nonces",
            "v3_registry_history",
            "v3_offer_history",
            "v3_handoffs",
        ] {
            sqlx::query(&format!("DELETE FROM {table} WHERE chain_id=?"))
                .bind(chain)
                .execute(&mut *tx)
                .await?;
        }
        // Retain public hashes/receipts/transparency and authorization proof, never ciphertext-bearing LogEntries.
    }
    tx.commit().await?;
    let mut conn = db.pool.acquire().await?;
    let row = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .fetch_one(&mut *conn)
        .await?;
    if row.get::<i64, _>(0) != 0 {
        return Err(err("STORAGE_UNAVAILABLE"));
    }
    Ok(())
}

pub async fn complete(db: &crate::db::DbState, cfg: &RelayConfig) -> Result<()> {
    erase(db).await?;
    let mut tx = db.pool.begin_with("BEGIN IMMEDIATE").await?;
    let rows=sqlx::query("SELECT chain_id,proof FROM v3_deletions WHERE json_extract(proof,'$.ledger.completed_at_ms') IS NULL").fetch_all(&mut *tx).await?;
    for row in rows {
        let chain: String = row.get("chain_id");
        let mut proof = store::value(row.get("proof"));
        // Preserve the immutable initial deleting ledger/receipt and final delete-entry binding.
        sqlx::query(
            "INSERT OR IGNORE INTO v3_delete_versions(chain_id,receipt_hash,proof) VALUES(?,?,?)",
        )
        .bind(&chain)
        .bind(s(&proof["ledger"], "receipt_hash"))
        .bind(store::text(&proof))
        .execute(&mut *tx)
        .await?;
        proof["ledger"]["completed_at_ms"] = now().into();
        let mut unsigned = proof["ledger"].clone();
        unsigned.as_object_mut().unwrap().remove("receipt_hash");
        proof["ledger"]["receipt_hash"] = crate::crypto::verify::object_hash(&unsigned).into();
        proof["delete_receipt"]["completed_at_ms"] = proof["ledger"]["completed_at_ms"].clone();
        proof["delete_receipt"]["ledger_receipt_hash"] = proof["ledger"]["receipt_hash"].clone();
        sign_relay(&cfg.key, &mut proof["delete_receipt"], CTX_DELETE)
            .map_err(|_| err("INTERNAL_ERROR"))?;
        sqlx::query("UPDATE v3_deletions SET proof=? WHERE chain_id=?")
            .bind(store::text(&proof))
            .bind(chain)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}
