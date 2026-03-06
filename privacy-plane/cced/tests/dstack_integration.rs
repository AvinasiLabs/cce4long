use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use key_manager::DatasetId;
use tower::ServiceExt;

use cced::dataset_store::InMemoryDatasetStore;
use cced::state::AppState;

fn dstack_endpoint() -> Option<String> {
    std::env::var("DSTACK_SIMULATOR_ENDPOINT").ok()
}

fn dev_root_key() -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(None, b"cce4long-dev-root-key");
    let mut key = [0u8; 32];
    hk.expand(b"dev-root", &mut key).expect("valid length");
    key
}

async fn dstack_state(endpoint: &str) -> Arc<AppState> {
    let root = key_manager::DstackRootKeyProvider::init(Some(endpoint))
        .await
        .unwrap();
    Arc::new(
        AppState::new(
            key_manager::RootKeyProvider::root_key(&root),
            Box::new(InMemoryDatasetStore::new()),
            tee_verifier::TeeVerifier::new()
                .register(tee_verifier::TeeType::Sample, tee_verifier::SampleVerifier),
        )
        .unwrap(),
    )
}

fn test_dataset_id(val: u8) -> DatasetId {
    DatasetId::from([val; 20])
}

#[tokio::test]
async fn dstack_upload_and_finalize() {
    let Some(endpoint) = dstack_endpoint() else {
        eprintln!("skipped: DSTACK_SIMULATOR_ENDPOINT not set");
        return;
    };

    let state = dstack_state(&endpoint).await;

    let wallet = test_dataset_id(0xAA);
    let ds = test_dataset_id(0x42);

    let token = cced::upload_token::issue_token(wallet, ds, &state.upload_hmac_key, 3600);

    // Upload
    let app = cced::api::router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri(&format!("/v1/datasets/{}/upload/data.csv", ds))
        .header("authorization", format!("Bearer {}", token))
        .body(Body::from("hello world"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Finalize
    let app = cced::api::router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri(&format!("/v1/datasets/{}/finalize", ds))
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let resp_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(resp_json["status"].as_str().unwrap(), "ready");
}

#[tokio::test]
async fn dstack_keys_differ_from_dev() {
    let Some(endpoint) = dstack_endpoint() else {
        eprintln!("skipped: DSTACK_SIMULATOR_ENDPOINT not set");
        return;
    };

    let dstack = dstack_state(&endpoint).await;

    let dev = Arc::new(
        AppState::new(
            &dev_root_key(),
            Box::new(InMemoryDatasetStore::new()),
            tee_verifier::TeeVerifier::new()
                .register(tee_verifier::TeeType::Sample, tee_verifier::SampleVerifier),
        )
        .unwrap(),
    );

    let ds = test_dataset_id(0x01);
    let dstack_dek = dstack.key_manager.derive_dek(&ds).unwrap();
    let dev_dek = dev.key_manager.derive_dek(&ds).unwrap();

    assert_ne!(
        dstack_dek.as_bytes(),
        dev_dek.as_bytes(),
        "dstack and dev root keys should differ"
    );
}
