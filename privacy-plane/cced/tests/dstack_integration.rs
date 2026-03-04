#![cfg(feature = "dstack")]

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use key_manager::DatasetId;
use tower::ServiceExt;

use cced::state::AppState;
use cced::storage::LocalStorage;

fn dstack_endpoint() -> Option<String> {
    std::env::var("DSTACK_SIMULATOR_ENDPOINT").ok()
}

fn test_dataset_id(val: u8) -> DatasetId {
    DatasetId::from([val; 20])
}

#[tokio::test]
#[ignore] // Requires dstack simulator
async fn dstack_upload_and_finalize() {
    let tmp = tempfile::tempdir().unwrap();
    let storage = Box::new(LocalStorage::new(tmp.path().to_str().unwrap()));
    let state = Arc::new(
        AppState::dstack(storage, dstack_endpoint().as_deref())
            .await
            .expect("dstack init"),
    );

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
#[ignore] // Requires dstack simulator
async fn dstack_keys_differ_from_dev() {
    let tmp = tempfile::tempdir().unwrap();
    let storage = Box::new(LocalStorage::new(tmp.path().to_str().unwrap()));
    let dstack_state = Arc::new(
        AppState::dstack(storage, dstack_endpoint().as_deref())
            .await
            .expect("dstack init"),
    );

    let tmp2 = tempfile::tempdir().unwrap();
    let storage2 = Box::new(LocalStorage::new(tmp2.path().to_str().unwrap()));
    let dev_state = Arc::new(AppState::dev(storage2));

    let ds = test_dataset_id(0x01);
    let dstack_dek = dstack_state.key_manager.derive_dek(&ds).unwrap();
    let dev_dek = dev_state.key_manager.derive_dek(&ds).unwrap();

    assert_ne!(
        dstack_dek.as_bytes(),
        dev_dek.as_bytes(),
        "dstack and dev root keys should differ"
    );
}
