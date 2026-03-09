mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use key_manager::DatasetId;
use tower::ServiceExt;

use cced::state::AppState;

use common::{
    dev_state, upload_and_finalize_dataset, TEST_MESSAGE, TEST_SIGNATURE, TEST_WALLET,
};

async fn post_create_job(
    state: Arc<AppState>,
    body: serde_json::Value,
) -> axum::http::Response<Body> {
    let app = cced::api::router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/jobs/create")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    app.oneshot(req).await.unwrap()
}

#[tokio::test]
async fn create_job_success() {
    let state = dev_state();
    let dataset_id = DatasetId::from([0x42; 20]);

    upload_and_finalize_dataset(&state, &dataset_id).await;

    let body = serde_json::json!({
        "wallet_address": TEST_WALLET,
        "dataset_ids": ["0x4242424242424242424242424242424242424242"],
        "job_spec": {"algorithm": "mean", "columns": ["col1"]},
        "signature": TEST_SIGNATURE,
        "message": TEST_MESSAGE
    });

    let resp = post_create_job(state.clone(), body).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert!(resp_json["job_id"].is_string());
    assert!(resp_json["credential"].is_object());
    assert!(resp_json["submit_credential"].is_object());
    assert_eq!(
        resp_json["dataset_ids"],
        serde_json::json!(["0x4242424242424242424242424242424242424242"])
    );
    assert_eq!(
        resp_json["job_spec"],
        serde_json::json!({"algorithm": "mean", "columns": ["col1"]})
    );

    assert_eq!(
        resp_json["credential"]["job_id"],
        resp_json["submit_credential"]["job_id"]
    );
    assert_ne!(
        resp_json["credential"]["nonce"],
        resp_json["submit_credential"]["nonce"]
    );
}

#[tokio::test]
async fn create_job_dataset_not_finalized() {
    let state = dev_state();

    let body = serde_json::json!({
        "wallet_address": TEST_WALLET,
        "dataset_ids": ["0x4242424242424242424242424242424242424242"],
        "job_spec": {},
        "signature": TEST_SIGNATURE,
        "message": TEST_MESSAGE
    });

    let resp = post_create_job(state, body).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn create_job_bad_signature() {
    let state = dev_state();
    let dataset_id = DatasetId::from([0x42; 20]);
    upload_and_finalize_dataset(&state, &dataset_id).await;

    let body = serde_json::json!({
        "wallet_address": TEST_WALLET,
        "dataset_ids": ["0x4242424242424242424242424242424242424242"],
        "job_spec": {},
        "signature": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefde1b",
        "message": TEST_MESSAGE
    });

    let resp = post_create_job(state, body).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
