mod api;
mod encrypt;
mod state;
mod storage;

use std::sync::Arc;

use storage::LocalStorage;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let storage_dir = std::env::var("CCED_STORAGE_DIR").unwrap_or_else(|_| "/tmp/cced".into());
    let storage = Box::new(LocalStorage::new(&storage_dir));

    let state = Arc::new(state::AppState::dev(storage));

    let app = api::router(state);

    let addr = "0.0.0.0:3000";
    tracing::info!("cced listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
