use pallasync_server::{api::sync::AppState, app, config::RelayConfig, db};
use std::{env, net::SocketAddr};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // No HTTP tracing: token/query/chain/IP data must never enter relay logs (§6.3/§17.10).
    tracing_subscriber::fmt::init();
    let config = RelayConfig::from_env().map_err(std::io::Error::other)?;
    let db = db::init_db().await?;
    if db.resolved_path == ":memory:" {
        return Err("Public use requires persistent storage (§17.1)".into());
    }
    let state = AppState::new(db, config)
        .await
        .map_err(|e| std::io::Error::other(e.code))?;
    let maintenance = state.clone();
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            timer.tick().await;
            let _ = pallasync_server::api::deletion::complete(&maintenance.db, &maintenance.config)
                .await;
            let _ =
                pallasync_server::api::retention::maintenance(&maintenance.db, &maintenance.config)
                    .await;
        }
    });
    // The upstream TLS terminator is the only public entry point (§17.1).
    let bind = env::var("PALLASYNC_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:3000".into())
        .parse::<SocketAddr>()?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!("PallaSync pallasync/3 relay ready behind configured HTTPS origin");
    axum::serve(
        listener,
        app(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
