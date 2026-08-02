use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};
use std::fs;

#[derive(Clone)]
pub struct DbState {
    pub pool: Pool<Sqlite>,
}

pub async fn init_db() -> Result<DbState, sqlx::Error> {
    let db_path = "sqlite:pallasync.sqlite";
    
    // Create file if not exists
    if !std::path::Path::new("pallasync.sqlite").exists() {
        fs::File::create("pallasync.sqlite").expect("Failed to create db file");
    }

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(db_path)
        .await?;

    // Apply schema
    let schema = include_str!("schema.sql");
    sqlx::query(schema).execute(&pool).await?;

    Ok(DbState { pool })
}
