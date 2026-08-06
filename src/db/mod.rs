use sqlx::{
    Pool, Row, Sqlite,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use std::{collections::HashMap, env, path::PathBuf, str::FromStr, time::Duration};
use tracing::info;

#[derive(Clone)]
pub struct DbState {
    pub pool: Pool<Sqlite>,
    pub resolved_path: String,
}

pub async fn init_db() -> Result<DbState, sqlx::Error> {
    let database_url =
        env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:pallasync.sqlite".to_string());
    init_db_with_url(&database_url).await
}

pub async fn init_db_with_url(database_url: &str) -> Result<DbState, sqlx::Error> {
    let options = SqliteConnectOptions::from_str(database_url)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(5))
        .foreign_keys(true);

    // SQLite in-memory databases are connection-local, so tests and other callers
    // using one must keep the pool to a single connection.
    let max_connections = if database_url.contains(":memory:") {
        1
    } else {
        5
    };
    let pool = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .connect_with(options)
        .await?;

    migrate(&pool).await?;

    let resolved_path = resolve_database_path(database_url);
    info!(database_path = %resolved_path, "PallaSync database ready");

    Ok(DbState {
        pool,
        resolved_path,
    })
}

async fn migrate(pool: &Pool<Sqlite>) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;

    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS device_records (
            chain_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            encrypted_device_name TEXT NOT NULL,
            device_public_key TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            signature TEXT NOT NULL,
            PRIMARY KEY (chain_id, device_id)
        )"#,
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS chain_public_keys (
            chain_id TEXT PRIMARY KEY,
            device_public_key TEXT NOT NULL
        )"#,
    )
    .execute(&mut *tx)
    .await?;

    // Older databases inferred the chain key from whichever device happened to
    // sort first. Persist one stable anchor per chain before any UPSERT can
    // reorder devices. Majority wins, with legacy rowid as a deterministic tie-break.
    let legacy_device_keys = sqlx::query(
        "SELECT rowid, chain_id, device_public_key FROM device_records ORDER BY rowid ASC",
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut candidates = HashMap::<String, HashMap<String, (usize, i64)>>::new();
    for row in legacy_device_keys {
        let rowid = row.get::<i64, _>("rowid");
        let chain_id = row.get::<String, _>("chain_id");
        let public_key = row.get::<String, _>("device_public_key");
        candidates
            .entry(chain_id)
            .or_default()
            .entry(public_key)
            .and_modify(|entry| entry.0 += 1)
            .or_insert((1, rowid));
    }
    for (chain_id, keys) in candidates {
        let mut chosen: Option<(String, usize, i64)> = None;
        for (public_key, (count, first_rowid)) in keys {
            let replace = chosen
                .as_ref()
                .map(|(_, chosen_count, chosen_rowid)| {
                    count > *chosen_count || (count == *chosen_count && first_rowid < *chosen_rowid)
                })
                .unwrap_or(true);
            if replace {
                chosen = Some((public_key, count, first_rowid));
            }
        }
        if let Some((public_key, _, _)) = chosen {
            sqlx::query(
                "INSERT OR IGNORE INTO chain_public_keys (chain_id, device_public_key) VALUES (?, ?)",
            )
            .bind(chain_id)
            .bind(public_key)
            .execute(&mut *tx)
            .await?;
        }
    }
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS deleted_chains (
            chain_id TEXT PRIMARY KEY,
            deleted_at_ms INTEGER NOT NULL
        )"#,
    )
    .execute(&mut *tx)
    .await?;

    let sync_table_exists =
        sqlx::query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'sync_records'")
            .fetch_optional(&mut *tx)
            .await?
            .is_some();

    if !sync_table_exists {
        create_sync_records_table(&mut tx).await?;
    } else {
        let columns = sqlx::query("PRAGMA table_info(sync_records)")
            .fetch_all(&mut *tx)
            .await?;
        let has_relay_seq = columns
            .iter()
            .any(|row| row.get::<String, _>("name") == "relay_seq");

        if !has_relay_seq {
            // This migration is deliberately transactional and copies by legacy
            // rowid so the relay cursor preserves the relay's original arrival order.
            sqlx::query("DROP TABLE IF EXISTS sync_records_v2_migration")
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                r#"CREATE TABLE sync_records_v2_migration (
                    relay_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    chain_id TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    collection_name TEXT NOT NULL,
                    action TEXT NOT NULL,
                    encrypted_payload TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    created_at_ms INTEGER NOT NULL,
                    signature TEXT NOT NULL,
                    UNIQUE (chain_id, record_id)
                )"#,
            )
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                r#"INSERT INTO sync_records_v2_migration (
                    chain_id, record_id, collection_name, action, encrypted_payload,
                    device_id, created_at_ms, signature
                ) SELECT chain_id, record_id, collection_name, action, encrypted_payload,
                    device_id, created_at_ms, signature
                  FROM sync_records ORDER BY rowid ASC"#,
            )
            .execute(&mut *tx)
            .await?;
            sqlx::query("DROP TABLE sync_records")
                .execute(&mut *tx)
                .await?;
            sqlx::query("ALTER TABLE sync_records_v2_migration RENAME TO sync_records")
                .execute(&mut *tx)
                .await?;
        }
    }

    sqlx::query(
        r#"CREATE UNIQUE INDEX IF NOT EXISTS ux_sync_records_chain_record
         ON sync_records(chain_id, record_id)"#,
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        r#"CREATE INDEX IF NOT EXISTS ix_sync_records_chain_relay_seq
         ON sync_records(chain_id, relay_seq)"#,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await
}

async fn create_sync_records_table(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"CREATE TABLE sync_records (
            relay_seq INTEGER PRIMARY KEY AUTOINCREMENT,
            chain_id TEXT NOT NULL,
            record_id TEXT NOT NULL,
            collection_name TEXT NOT NULL,
            action TEXT NOT NULL,
            encrypted_payload TEXT NOT NULL,
            device_id TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            signature TEXT NOT NULL,
            UNIQUE (chain_id, record_id)
        )"#,
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn resolve_database_path(database_url: &str) -> String {
    if database_url.contains(":memory:") {
        return ":memory:".to_string();
    }

    let without_scheme = database_url
        .strip_prefix("sqlite://")
        .or_else(|| database_url.strip_prefix("sqlite:"))
        .unwrap_or(database_url);
    let path = without_scheme.split('?').next().unwrap_or(without_scheme);
    let path = PathBuf::from(path);
    let absolute = if path.is_absolute() {
        path
    } else {
        env::current_dir().unwrap_or_default().join(path)
    };
    absolute
        .canonicalize()
        .unwrap_or(absolute)
        .display()
        .to_string()
}
