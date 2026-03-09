#![allow(dead_code, unused_macros, unused_imports)]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use key_manager::DatasetId;
use tower::ServiceExt;

use cced::dataset_store::{
    DatasetMeta, DatasetReceipt, DatasetStatus, FileEntry, InMemoryDatasetStore,
};
use cced::state::AppState;

macro_rules! require_env {
    ($name:expr) => {
        match std::env::var($name) {
            Ok(v) => v,
            Err(_) => {
                eprintln!("skipped: {} not set", $name);
                return;
            }
        }
    };
}
pub(crate) use require_env;

pub fn dev_root_key() -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(None, b"cce4long-dev-root-key");
    let mut key = [0u8; 32];
    hk.expand(b"dev-root", &mut key).expect("valid length");
    key
}

pub fn dev_state() -> Arc<AppState> {
    Arc::new(
        AppState::new(
            &dev_root_key(),
            Box::new(InMemoryDatasetStore::new()),
            tee_verifier::TeeVerifier::new()
                .register(tee_verifier::TeeType::Sample, tee_verifier::SampleVerifier),
        )
        .unwrap(),
    )
}

pub fn test_dataset_id(val: u8) -> DatasetId {
    DatasetId::from([val; 20])
}

pub async fn post_json(
    state: Arc<AppState>,
    uri: &str,
    body: &serde_json::Value,
) -> axum::http::Response<Body> {
    let app = cced::api::router(state);
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap();
    app.oneshot(req).await.unwrap()
}

pub async fn upload_and_finalize_dataset(state: &AppState, dataset_id: &DatasetId) {
    state
        .dataset_store
        .put_file(dataset_id, "data.csv", b"col1,col2\n1,2\n")
        .await
        .unwrap();

    let meta = DatasetMeta {
        status: DatasetStatus::Ready,
        receipt: Some(DatasetReceipt {
            dataset_id: *dataset_id,
            files: vec![FileEntry {
                path: "data.csv".into(),
                size: 14,
                hash: "dummy".into(),
            }],
            total_size: 14,
            content_hash: "dummy".into(),
        }),
    };
    state
        .dataset_store
        .set_meta(dataset_id, &meta)
        .await
        .unwrap();
}

pub const TEST_WALLET: &str = "0x10c77Eb3C94D0129AF6626733CABf5d1a5811899";
pub const TEST_MESSAGE: &str =
    "Create job for datasets 0x4242424242424242424242424242424242424242";
pub const TEST_SIGNATURE: &str = "0xc0a6c6097a062229ba27c488cd9d5cd5b3ab16b93c54fbdf46feb16ce7df4753749c8a65039dd6d675e35c199718e75531c9dca02f16142637bb40c8bd19dda71c";
