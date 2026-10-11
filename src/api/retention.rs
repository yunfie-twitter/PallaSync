//! §13.5: a blind relay removes old envelopes only after an explicitly admin-authorized snapshot handoff.
use super::{
    error::*,
    store::{self, Chain},
    wire::*,
};
use crate::config::RelayConfig;
use serde_json::Value;
use sqlx::{Row, SqliteConnection};
pub async fn handoff(
    db: &mut SqliteConnection,
    c: &Chain,
    comp: &Value,
    through: u64,
) -> Result<()> {
    if c.parameters["policy"]["epoch_retention"] == "retain" {
        return Ok(());
    }
    let rows=sqlx::query("SELECT body FROM v3_objects WHERE chain_id=? AND kind='epoch' AND CAST(object_id AS INTEGER)<? AND body IS NOT NULL").bind(&c.chain_id).bind(n(&c.epoch,"epoch") as i64).fetch_all(&mut *db).await?;
    for row in rows {
        let epoch = store::value(row.get("body"));
        let number = n(&epoch, "epoch");
        let late:i64=sqlx::query_scalar("SELECT COUNT(*) FROM v3_objects WHERE chain_id=? AND kind='envelope' AND json_extract(body,'$.epoch')=? AND (relay_seq>? OR log_id<>?)").bind(&c.chain_id).bind(number as i64).bind(through as i64).bind(&c.log_id).fetch_one(&mut *db).await?;
        if late != 0 {
            continue;
        }
        let successor = store::object(&mut *db, &c.chain_id, "epoch", &(number + 1).to_string())
            .await?
            .ok_or_else(|| err("COMPACTION_UNSAFE"))?;
        let committed:i64=sqlx::query_scalar("SELECT json_extract(l.entry,'$.committed_at_ms') FROM v3_log l JOIN v3_objects o ON o.chain_id=l.chain_id AND o.log_id=l.log_id AND o.relay_seq=l.seq WHERE o.chain_id=? AND o.kind='epoch' AND o.object_id=?").bind(&c.chain_id).bind(n(&successor,"epoch").to_string()).fetch_one(&mut *db).await?;
        let due = if c.parameters["policy"]["epoch_retention"] == "immediate" {
            now()
        } else {
            committed as u64 + n(&c.parameters["policy"], "epoch_window_ms")
        };
        sqlx::query("INSERT OR IGNORE INTO v3_handoffs(chain_id,epoch,compaction_id,due_at_ms) VALUES(?,?,?,?)").bind(&c.chain_id).bind(number as i64).bind(s(comp,"compaction_id")).bind(due as i64).execute(&mut *db).await?;
    }
    expire(db, c).await
}
pub async fn expire(db: &mut SqliteConnection, c: &Chain) -> Result<()> {
    let epochs: Vec<i64> = sqlx::query_scalar(
        "SELECT epoch FROM v3_handoffs WHERE chain_id=? AND due_at_ms<=? AND expired=0",
    )
    .bind(&c.chain_id)
    .bind(now() as i64)
    .fetch_all(&mut *db)
    .await?;
    for epoch in epochs {
        // The covering data prefix is already unavailable; hashes/receipts retain exact removed-object evidence.
        sqlx::query("UPDATE v3_log SET entry=NULL WHERE chain_id=? AND json_extract(entry,'$.kind')='envelope' AND json_extract(entry,'$.object.epoch')=? AND seq<?").bind(&c.chain_id).bind(epoch).bind(c.min_available_seq as i64).execute(&mut *db).await?;
        sqlx::query("UPDATE v3_objects SET body=NULL WHERE chain_id=? AND kind='envelope' AND json_extract(body,'$.epoch')=?").bind(&c.chain_id).bind(epoch).execute(&mut *db).await?;
        sqlx::query("UPDATE v3_handoffs SET expired=1 WHERE chain_id=? AND epoch=?")
            .bind(&c.chain_id)
            .bind(epoch)
            .execute(&mut *db)
            .await?;
    }
    Ok(())
}
pub async fn expired(db: &mut SqliteConnection, c: &Chain, epoch: u64) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM v3_handoffs WHERE chain_id=? AND epoch=? AND expired=1",
    )
    .bind(&c.chain_id)
    .bind(epoch as i64)
    .fetch_one(db)
    .await?
        > 0)
}
pub async fn maintenance(db: &crate::db::DbState, cfg: &RelayConfig) -> Result<()> {
    let mut tx = db.pool.begin_with("BEGIN IMMEDIATE").await?;
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT chain_id FROM v3_handoffs WHERE expired=0 AND due_at_ms<=?",
    )
    .bind(now() as i64)
    .fetch_all(&mut *tx)
    .await?;
    for id in ids {
        if let Some(c) = store::load(&mut tx, &id).await? {
            expire(&mut tx, &c).await?;
            store::quota(&mut tx, &id, cfg).await?;
        }
    }
    tx.commit().await?;
    Ok(())
}
