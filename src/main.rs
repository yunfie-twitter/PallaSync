mod api;
mod db;

use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let db_state = db::init_db().await.expect("Failed to initialize database");

    let app = Router::new()
        .route("/pallasync/v1/events/:chain_id", get(api::sync::get_events))
        .route("/pallasync/v1/events/:chain_id", post(api::sync::post_events))
        .with_state(db_state)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::info!("Server listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
