use std::sync::Arc;

use cced::storage::{LocalStorage, S3Storage, Storage};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let backend = std::env::var("CCED_STORAGE_BACKEND").unwrap_or_else(|_| "local".into());

    let storage: Box<dyn Storage> = match backend.as_str() {
        "s3" => {
            let bucket =
                std::env::var("CCED_S3_BUCKET").expect("CCED_S3_BUCKET is required for s3 backend");
            let region = std::env::var("CCED_S3_REGION").unwrap_or_else(|_| "auto".into());
            let endpoint = std::env::var("CCED_S3_ENDPOINT")
                .unwrap_or_else(|_| "https://storage.googleapis.com".into());
            let access_key = std::env::var("CCED_S3_ACCESS_KEY")
                .expect("CCED_S3_ACCESS_KEY is required for s3 backend");
            let secret_key = std::env::var("CCED_S3_SECRET_KEY")
                .expect("CCED_S3_SECRET_KEY is required for s3 backend");

            tracing::info!(
                backend = "s3",
                bucket = %bucket,
                region = %region,
                endpoint = %endpoint,
                "initializing S3 storage"
            );

            Box::new(
                S3Storage::new(&bucket, &region, &endpoint, &access_key, &secret_key)
                    .expect("failed to initialize S3Storage"),
            )
        }
        _ => {
            let storage_dir =
                std::env::var("CCED_STORAGE_DIR").unwrap_or_else(|_| "/tmp/cced".into());
            tracing::info!(
                backend = "local",
                dir = %storage_dir,
                "initializing local storage"
            );
            Box::new(LocalStorage::new(&storage_dir))
        }
    };

    let state = match std::env::var("CCED_MODE").as_deref() {
        #[cfg(feature = "dstack")]
        Ok("dstack") => {
            let endpoint = std::env::var("DSTACK_SIMULATOR_ENDPOINT").ok();
            Arc::new(
                cced::state::AppState::dstack(storage, endpoint.as_deref())
                    .await
                    .expect("dstack initialization failed"),
            )
        }
        _ => Arc::new(cced::state::AppState::dev(storage)),
    };

    let app = cced::api::router(state);

    let addr = "0.0.0.0:3000";
    tracing::info!("cced listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
