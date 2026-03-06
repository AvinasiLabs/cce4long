use std::sync::Arc;

use cced::state::{JuiceFsBackend, JuiceFsConfig};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let jfs = JuiceFsConfig {
        meta_url: std::env::var("CCED_JFS_META_URL")
            .unwrap_or_else(|_| "redis://localhost:6379/1".into()),
        backend: JuiceFsBackend {
            storage_type: "gs".to_string(),
            bucket: std::env::var("GCS_BUCKET_URL").unwrap_or_default(),
            access_key: std::env::var("GCS_ACCESS_KEY").unwrap_or_default(),
            secret_key: std::env::var("GCS_SECRET_KEY").unwrap_or_default(),
        },
    };

    let state = match std::env::var("CCED_MODE").as_deref() {
        #[cfg(feature = "dstack")]
        Ok("dstack") => {
            let endpoint = std::env::var("DSTACK_SIMULATOR_ENDPOINT").ok();
            Arc::new(
                cced::state::AppState::dstack(endpoint.as_deref(), jfs)
                    .await
                    .expect("dstack initialization failed"),
            )
        }
        _ => Arc::new(cced::state::AppState::new(jfs)),
    };

    let app = cced::api::router(state);

    let addr = "0.0.0.0:3000";
    tracing::info!("cced listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
