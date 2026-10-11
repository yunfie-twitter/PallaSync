use sqlx::{
    Pool, Sqlite,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use std::{env, path::PathBuf, str::FromStr, time::Duration};
#[derive(Clone)]
pub struct DbState {
    pub pool: Pool<Sqlite>,
    pub resolved_path: String,
}
pub async fn init_db() -> Result<DbState, sqlx::Error> {
    init_db_with_url(&env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:pallasync.sqlite".into()))
        .await
}
pub async fn init_db_with_url(database_url: &str) -> Result<DbState, sqlx::Error> {
    let options = SqliteConnectOptions::from_str(database_url)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full)
        .busy_timeout(Duration::from_secs(10))
        .foreign_keys(true)
        .pragma("secure_delete", "ON");
    let pool = SqlitePoolOptions::new()
        .max_connections(if database_url.contains(":memory:") {
            1
        } else {
            5
        })
        .connect_with(options)
        .await?;
    sqlx::raw_sql(include_str!("schema.sql"))
        .execute(&pool)
        .await?;
    let path = database_url
        .strip_prefix("sqlite://")
        .or_else(|| database_url.strip_prefix("sqlite:"))
        .unwrap_or(database_url)
        .split('?')
        .next()
        .unwrap_or("");
    let path = PathBuf::from(path);
    let resolved_path = if database_url.contains(":memory:") {
        ":memory:".into()
    } else {
        let path = if path.is_absolute() {
            path
        } else {
            env::current_dir().unwrap_or_default().join(path)
        };
        path.canonicalize().unwrap_or(path).display().to_string()
    };
    Ok(DbState {
        pool,
        resolved_path,
    })
}
