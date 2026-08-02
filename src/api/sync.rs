use axum::{
    extract::{Path, State, Query},
    Json,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use crate::db::DbState;
use sqlx::Row;

#[derive(Deserialize)]
pub struct EventPayload {
    #[serde(default)]
    pub control_events: Vec<serde_json::Value>,
    #[serde(default)]
    pub data_events: Vec<serde_json::Value>,
}

#[derive(Serialize)]
pub struct EventResponse {
    pub control_events: Vec<serde_json::Value>,
    pub data_events: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
pub struct SyncQuery {
    pub since: Option<u64>,
}

pub async fn post_events(
    State(state): State<DbState>,
    Path(chain_id): Path<String>,
    Json(payload): Json<EventPayload>,
) -> Result<StatusCode, StatusCode> {
    sqlx::query("INSERT OR IGNORE INTO chains (chain_id, created_at_ms) VALUES (?, ?)")
        .bind(&chain_id)
        .bind(chrono::Utc::now().timestamp_millis())
        .execute(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    for event in payload.control_events {
        let seq = event.get("control_seq").and_then(|v| v.as_u64()).ok_or(StatusCode::BAD_REQUEST)?;
        let json_str = event.to_string();
        let res = sqlx::query("INSERT INTO control_events (chain_id, control_seq, event_json) VALUES (?, ?, ?)")
            .bind(&chain_id)
            .bind(seq as i64)
            .bind(json_str)
            .execute(&state.pool)
            .await;
        
        if let Err(sqlx::Error::Database(db_err)) = res {
            if db_err.is_unique_violation() {
                return Err(StatusCode::CONFLICT);
            }
        }
    }

    for event in payload.data_events {
        let device_id = event.get("device_id").and_then(|v| v.as_str()).ok_or(StatusCode::BAD_REQUEST)?;
        let device_seq = event.get("device_seq").and_then(|v| v.as_u64()).ok_or(StatusCode::BAD_REQUEST)?;
        let json_str = event.to_string();
        
        let _ = sqlx::query("INSERT OR IGNORE INTO data_events (chain_id, device_id, device_seq, event_json) VALUES (?, ?, ?, ?)")
            .bind(&chain_id)
            .bind(device_id)
            .bind(device_seq as i64)
            .bind(json_str)
            .execute(&state.pool)
            .await;
    }

    Ok(StatusCode::OK)
}

pub async fn get_events(
    State(state): State<DbState>,
    Path(chain_id): Path<String>,
    Query(_query): Query<SyncQuery>,
) -> Result<Json<EventResponse>, StatusCode> {
    let control_rows = sqlx::query("SELECT event_json FROM control_events WHERE chain_id = ? ORDER BY control_seq ASC")
        .bind(&chain_id)
        .fetch_all(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut control_events = Vec::new();
    for row in control_rows {
        let json_str: String = row.get(0);
        if let Ok(val) = serde_json::from_str(&json_str) {
            control_events.push(val);
        }
    }

    let data_rows = sqlx::query("SELECT event_json FROM data_events WHERE chain_id = ? ORDER BY device_seq ASC")
        .bind(&chain_id)
        .fetch_all(&state.pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut data_events = Vec::new();
    for row in data_rows {
        let json_str: String = row.get(0);
        if let Ok(val) = serde_json::from_str(&json_str) {
            data_events.push(val);
        }
    }

    Ok(Json(EventResponse {
        control_events,
        data_events,
    }))
}
