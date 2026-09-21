pub mod api;
pub mod crypto;
pub mod db;

use axum::{Router, extract::DefaultBodyLimit, routing::get};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use db::DbState;

pub fn app(db_state: DbState, cors: CorsLayer) -> Router {
    Router::new()
        .route("/health", get(api::sync::health))
        .route("/pallasync/v2/health", get(api::sync::health))
        .route(
            "/pallasync/v2/chains",
            axum::routing::post(api::sync::create_chain),
        )
        .route(
            "/pallasync/v2/chains/:chain_id",
            axum::routing::delete(api::sync::delete_chain),
        )
        .route(
            "/pallasync/v2/chains/:chain_id/parameters",
            get(api::sync::get_chain_parameters),
        )
        .route(
            "/pallasync/v2/chains/:chain_id/devices/enroll",
            axum::routing::post(api::sync::enroll_device),
        )
        .route(
            "/pallasync/v2/chains/:chain_id/devices",
            get(api::sync::get_devices).post(api::sync::enroll_device),
        )
        .route(
            "/pallasync/v2/chains/:chain_id/devices/:device_id",
            axum::routing::put(api::sync::update_device),
        )
        .route(
            "/pallasync/v2/chains/:chain_id/devices/:device_id/revoke",
            axum::routing::post(api::sync::revoke_device),
        )
        .route(
            "/pallasync/v2/chains/:chain_id/records",
            get(api::sync::get_records).post(api::sync::post_records),
        )
        .with_state(db_state)
        // A single encrypted payload may be up to 8 MiB before Base64URL
        // expansion. Raise Axum's ~2 MiB default so typed validation is reached.
        .layer(DefaultBodyLimit::max(64 * 1024 * 1024))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
}
