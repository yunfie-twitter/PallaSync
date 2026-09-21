use sqlx::{
    Pool, Sqlite,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use std::{env, path::PathBuf, str::FromStr, time::Duration};
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

    // Detect legacy pre-v2.1 database schemas (e.g. sync_records with relay_seq or chains without chain_salt)
    let is_legacy_sync_records: bool = sqlx::query_scalar::<_, i32>(
        "SELECT COUNT(*) FROM pragma_table_info('sync_records') WHERE name = 'relay_seq'",
    )
    .fetch_one(&mut *tx)
    .await
    .map(|count| count > 0)
    .unwrap_or(false);

    let has_chains: bool = sqlx::query_scalar::<_, i32>(
        "SELECT COUNT(*) FROM pragma_table_info('chains') WHERE name = 'chain_id'",
    )
    .fetch_one(&mut *tx)
    .await
    .map(|count| count > 0)
    .unwrap_or(false);

    let is_legacy_chains: bool = if has_chains {
        sqlx::query_scalar::<_, i32>(
            "SELECT COUNT(*) FROM pragma_table_info('chains') WHERE name = 'chain_salt'",
        )
        .fetch_one(&mut *tx)
        .await
        .map(|count| count == 0)
        .unwrap_or(false)
    } else {
        false
    };

    if is_legacy_sync_records || is_legacy_chains {
        tracing::warn!(
            "Legacy pre-v2.1 database schema detected. Resetting database tables for Protocol v2.1 compatibility."
        );
        sqlx::raw_sql(
            "DROP TABLE IF EXISTS sync_records;
             DROP TABLE IF EXISTS device_records;
             DROP TABLE IF EXISTS chain_public_keys;
             DROP TABLE IF EXISTS deleted_chains;
             DROP TABLE IF EXISTS control_events;
             DROP TABLE IF EXISTS data_events;
             DROP TABLE IF EXISTS replay_nonces;
             DROP TABLE IF EXISTS cursors;
             DROP TABLE IF EXISTS devices;
             DROP TABLE IF EXISTS chains;",
        )
        .execute(&mut *tx)
        .await?;
    }

    sqlx::raw_sql(include_str!("schema.sql"))
        .execute(&mut *tx)
        .await?;

    tx.commit().await
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_init_fresh_db() {
        let db_state = init_db_with_url("sqlite::memory:").await.unwrap();
        let tables: Vec<(String,)> =
            sqlx::query_as("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
                .fetch_all(&db_state.pool)
                .await
                .unwrap();

        let table_names: Vec<String> = tables.into_iter().map(|(n,)| n).collect();
        assert!(table_names.contains(&"chains".to_string()));
        assert!(table_names.contains(&"devices".to_string()));
        assert!(table_names.contains(&"sync_records".to_string()));
        assert!(table_names.contains(&"replay_nonces".to_string()));
        assert!(table_names.contains(&"cursors".to_string()));
    }

    #[tokio::test]
    async fn test_migrate_from_legacy_schema_with_relay_seq() {
        // Setup in-memory DB with legacy pre-v2.1 tables
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        sqlx::raw_sql(
            "CREATE TABLE sync_records (
                relay_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                chain_id TEXT NOT NULL,
                record_id TEXT NOT NULL,
                collection_name TEXT NOT NULL,
                action TEXT NOT NULL,
                encrypted_payload TEXT NOT NULL,
                device_id TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE TABLE chains (
                chain_id TEXT PRIMARY KEY,
                created_at_ms INTEGER NOT NULL
            );",
        )
        .execute(&pool)
        .await
        .unwrap();

        // Run migrate on the legacy database
        migrate(&pool)
            .await
            .expect("migrate should succeed on legacy database");

        // Verify that server_sequence column now exists in sync_records
        let columns: Vec<(String,)> =
            sqlx::query_as("SELECT name FROM pragma_table_info('sync_records')")
                .fetch_all(&pool)
                .await
                .unwrap();

        let column_names: Vec<String> = columns.into_iter().map(|(n,)| n).collect();
        assert!(column_names.contains(&"server_sequence".to_string()));
        assert!(!column_names.contains(&"relay_seq".to_string()));
    }
}
