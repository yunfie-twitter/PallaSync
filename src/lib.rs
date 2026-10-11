pub mod api;
pub mod config;
pub mod crypto;
pub mod db;
pub fn app(state: api::sync::AppState) -> axum::Router {
    axum::Router::new()
        .fallback(api::sync::handle)
        .with_state(state)
}
