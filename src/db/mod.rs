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
