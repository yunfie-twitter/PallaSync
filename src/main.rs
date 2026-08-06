use axum::http::{HeaderName, HeaderValue};
use dotenvy::dotenv;
use pallasync_server::{app, db};
use std::env;
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};

#[tokio::main]
async fn main() {
    dotenv().ok();

    tracing_subscriber::fmt::init();

    let db_state = db::init_db().await.expect("Failed to initialize database");
    tracing::info!(database_path = %db_state.resolved_path, "Using PallaSync database");

    let allowed_url = env::var("URL").unwrap_or_else(|_| "*".to_string());

    let cors = (if allowed_url == "*" {
        CorsLayer::permissive()
    } else {
        CorsLayer::new()
            .allow_origin(
                allowed_url
                    .parse::<HeaderValue>()
                    .expect("Invalid URL format for CORS origin"),
            )
            .allow_methods(Any)
            .allow_headers(Any)
    })
    .expose_headers([
        HeaderName::from_static("pallasync-next-seq"),
        HeaderName::from_static("pallasync-has-more"),
    ]);

    let port = env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse::<u16>()
        .expect("PORT must be an integer between 0 and 65535");
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("Server listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app(db_state, cors)).await.unwrap();
}
