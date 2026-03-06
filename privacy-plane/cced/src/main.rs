use std::sync::Arc;

use key_manager::RootKeyProvider;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // JuiceFS metadata URL — shared between PP-side Redis business DB
    // and CVM-side JuiceFS metadata connection
    let meta_url = std::env::var("CCED_JFS_META_URL")
        .unwrap_or_else(|_| "redis://localhost:6379/1".into());

    // CVM storage routing — sent to CVM via /v1/keys/request so the CVM
    // can mount the JuiceFS volume backed by cloud object storage
    let storage_routing = serde_json::json!({
        "meta_url": &meta_url,
        "backend": {
            "storage_type": "gs",
            "bucket": std::env::var("GCS_BUCKET_URL").unwrap_or_default(),
            "access_key": std::env::var("GCS_ACCESS_KEY").unwrap_or_default(),
            "secret_key": std::env::var("GCS_SECRET_KEY").unwrap_or_default(),
        }
    });

    // PP-side DatasetStore — reads/writes dataset files via JuiceFS Gateway's S3 interface.
    // JFS_* are the Gateway sidecar's S3 API credentials (unrelated to GCS_* above).
    let dataset_store = Box::new(
        cced::dataset_store::JuiceFsDatasetStore::new(
            &std::env::var("JFS_BUCKET").unwrap_or_else(|_| "avinasi".into()),
            &std::env::var("JFS_REGION").unwrap_or_else(|_| "auto".into()),
            &std::env::var("JFS_ENDPOINT").unwrap_or_else(|_| "http://localhost:9000".into()),
            &std::env::var("JFS_ACCESS_KEY").unwrap_or_else(|_| "admin".into()),
            &std::env::var("JFS_SECRET_KEY").unwrap_or_else(|_| "changeme123".into()),
            &meta_url,
            storage_routing,
        )
        .await
        .expect("dataset store initialization"),
    );

    // Root key from DStack (simulator or real TEE)
    let endpoint = std::env::var("DSTACK_SIMULATOR_ENDPOINT").ok();
    let root = key_manager::DstackRootKeyProvider::init(endpoint.as_deref())
        .await
        .expect("root key initialization");

    // TEE verifier
    #[allow(unused_mut)]
    let mut tee_verifier = tee_verifier::TeeVerifier::new()
        .register(tee_verifier::TeeType::Sample, tee_verifier::SampleVerifier);
    #[cfg(feature = "dcap")]
    if let Ok(pccs_url) = std::env::var("PCCS_URL") {
        tee_verifier = tee_verifier.register(
            tee_verifier::TeeType::Tdx,
            tee_verifier::DcapVerifier::new(pccs_url),
        );
    }

    let state = Arc::new(
        cced::state::AppState::new(root.root_key(), dataset_store, tee_verifier)
            .expect("AppState initialization"),
    );

    let app = cced::api::router(state);

    let addr = "0.0.0.0:3000";
    tracing::info!("cced listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
