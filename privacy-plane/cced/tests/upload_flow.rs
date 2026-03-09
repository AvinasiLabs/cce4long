mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use common::{dev_state, test_dataset_id};

#[tokio::test]
async fn upload_with_token() {
    let state = dev_state();

    let wallet = test_dataset_id(0xAA);
    let ds = test_dataset_id(0x42);

    let token = cced::upload_token::issue_token(wallet, ds, &state.upload_hmac_key, 3600);

    let app = cced::api::router(state);
    let req = Request::builder()
        .method("POST")
        .uri(&format!("/v1/datasets/{}/upload/data.csv", ds))
        .header("authorization", format!("Bearer {}", token))
        .body(Body::from("hello world"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn upload_without_token_rejected() {
    let state = dev_state();

    let ds = test_dataset_id(0x42);
    let app = cced::api::router(state);
    let req = Request::builder()
        .method("POST")
        .uri(&format!("/v1/datasets/{}/upload/data.csv", ds))
        .body(Body::from("hello world"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn upload_wrong_dataset_token_rejected() {
    let state = dev_state();

    let wallet = test_dataset_id(0xAA);
    let ds = test_dataset_id(0x42);
    let wrong_ds = test_dataset_id(0x99);

    let token = cced::upload_token::issue_token(wallet, wrong_ds, &state.upload_hmac_key, 3600);

    let app = cced::api::router(state);
    let req = Request::builder()
        .method("POST")
        .uri(&format!("/v1/datasets/{}/upload/data.csv", ds))
        .header("authorization", format!("Bearer {}", token))
        .body(Body::from("hello world"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn upload_and_finalize() {
    let state = dev_state();

    let wallet = test_dataset_id(0xAA);
    let ds = test_dataset_id(0x42);

    let token = cced::upload_token::issue_token(wallet, ds, &state.upload_hmac_key, 3600);

    let app = cced::api::router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri(&format!("/v1/datasets/{}/upload/data.csv", ds))
        .header("authorization", format!("Bearer {}", token))
        .body(Body::from("hello world"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

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
    assert_eq!(resp_json["receipt"]["files"].as_array().unwrap().len(), 1);

    let app = cced::api::router(state);
    let req = Request::builder()
        .method("POST")
        .uri(&format!("/v1/datasets/{}/upload/more.csv", ds))
        .header("authorization", format!("Bearer {}", token))
        .body(Body::from("more data"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn upload_batch_deep_dirs_and_finalize() {
    let state = dev_state();

    let wallet = test_dataset_id(0xAA);
    let ds = test_dataset_id(0x55);

    let token = cced::upload_token::issue_token(wallet, ds, &state.upload_hmac_key, 3600);

    let files = vec![
        (
            "raw/2024/01/sensors/temperature.csv",
            "ts,value\n1,23.5\n2,24.1",
        ),
        (
            "raw/2024/01/sensors/humidity.csv",
            "ts,value\n1,45.2\n2,44.8",
        ),
        (
            "raw/2024/01/sensors/pressure.csv",
            "ts,value\n1,1013\n2,1012",
        ),
        (
            "raw/2024/02/sensors/temperature.csv",
            "ts,value\n3,22.0\n4,21.5",
        ),
        (
            "raw/2024/02/sensors/humidity.csv",
            "ts,value\n3,50.1\n4,49.9",
        ),
        ("processed/2024/q1/summary.json", r#"{"avg_temp":23.0}"#),
        ("processed/2024/q1/report.txt", "Q1 2024 sensor report"),
        ("models/v1/weights.bin", "fake-binary-weights-data-here"),
        ("models/v1/config.yaml", "layers: 3\nhidden: 128"),
        ("README.md", "# Dataset 0x55\nSensor data collection."),
    ];

    for (path, content) in &files {
        let app = cced::api::router(state.clone());
        let req = Request::builder()
            .method("POST")
            .uri(&format!("/v1/datasets/{}/upload/{}", ds, path))
            .header("authorization", format!("Bearer {}", token))
            .body(Body::from(*content))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "failed uploading {}", path);
    }

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

    let receipt_files = resp_json["receipt"]["files"].as_array().unwrap();
    assert_eq!(receipt_files.len(), files.len());

    let receipt_paths: Vec<&str> = receipt_files
        .iter()
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    for (path, _) in &files {
        assert!(
            receipt_paths.contains(&format!("{}.avin", path).as_str())
                || receipt_paths
                    .iter()
                    .any(|rp| rp.contains(&path.split('/').last().unwrap().to_string())),
            "path {} not found in receipt: {:?}",
            path,
            receipt_paths
        );
    }

    let content_hash = resp_json["receipt"]["content_hash"].as_str().unwrap();
    assert_eq!(content_hash.len(), 64);

    let total_size = resp_json["receipt"]["total_size"].as_u64().unwrap();
    assert!(total_size > 0);
}
