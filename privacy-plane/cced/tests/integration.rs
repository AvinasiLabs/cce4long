use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use key_manager::DatasetId;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use tower::ServiceExt;
use x25519_dalek::{PublicKey, StaticSecret};

use cced::state::AppState;
use cced::storage::LocalStorage;

fn dev_state(dir: &str) -> Arc<AppState> {
    let storage = Box::new(LocalStorage::new(dir));
    Arc::new(AppState::dev(storage))
}

fn test_dataset_id(val: u8) -> DatasetId {
    DatasetId::from([val; 20])
}

/// Full CVM-side flow: issue credential → generate keypair → build evidence → request keys → unwrap → verify DEKs + REK
#[tokio::test]
async fn end_to_end_request_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let state = dev_state(tmp.path().to_str().unwrap());

    let ds1 = test_dataset_id(0x01);
    let ds2 = test_dataset_id(0x02);

    // 1. Issue credential
    let credential = state
        .credential_service
        .issue("job-42", "alice", vec![ds1, ds2]);

    // 2. CVM generates x25519 keypair
    let cvm_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let cvm_pk = PublicKey::from(&cvm_secret);

    // 3. Generate random request_id
    let mut request_id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut request_id);

    // 4. Compute reportdata = SHA512(eph_pk || request_id)
    let mut hasher = Sha512::new();
    hasher.update(cvm_pk.as_bytes());
    hasher.update(&request_id);
    let reportdata: [u8; 64] = hasher.finalize().into();

    // 5. Build sample evidence
    let evidence = tee_verifier::build_sample_evidence(&reportdata);

    // 6. POST /v1/keys/request
    let body = serde_json::json!({
        "credential": credential,
        "request_id": hex::encode(&request_id),
        "tee_type": "sample",
        "evidence": evidence,
        "eph_pk": hex::encode(cvm_pk.as_bytes()),
        "dataset_ids": [ds1, ds2]
    });

    let app = cced::api::router(state.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/v1/keys/request")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 7. Parse response
    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let resp_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    // Verify JuiceFS config is present
    assert!(resp_json["jfs"]["meta_url"].is_string());
    assert!(resp_json["jfs"]["backend"]["storage_type"].is_string());
    assert!(resp_json["jfs"]["backend"]["bucket"].is_string());
    assert!(resp_json["jfs"]["backend"]["access_key"].is_string());
    assert!(resp_json["jfs"]["backend"]["secret_key"].is_string());

    let ciphertext = hex::decode(resp_json["encrypted_keys"].as_str().unwrap()).unwrap();
    let nonce_bytes = hex::decode(resp_json["nonce"].as_str().unwrap()).unwrap();
    let pp_pk_bytes = hex::decode(resp_json["pp_pk"].as_str().unwrap()).unwrap();

    let bundle = key_manager::ecdhe::WrappedKeyBundle {
        ciphertext,
        nonce: nonce_bytes.try_into().unwrap(),
        pp_pk: pp_pk_bytes.try_into().unwrap(),
    };

    // 8. Unwrap keys
    let (deks, rek) = key_manager::ecdhe::unwrap_keys(&bundle, &cvm_secret).unwrap();

    // 9. Verify DEKs match what key_manager would derive
    assert_eq!(deks.len(), 2);
    let expected_dek1 = state.key_manager.derive_dek(&ds1).unwrap();
    let expected_dek2 = state.key_manager.derive_dek(&ds2).unwrap();
    assert_eq!(deks[0].0, expected_dek1.0);
    assert_eq!(deks[1].0, expected_dek2.0);

    // 10. Verify REK matches
    let expected_rek = state.key_manager.derive_rek("job-42").unwrap();
    assert_eq!(rek.0, expected_rek.0);
}

/// Upload requires a valid upload token bound to the dataset.
#[tokio::test]
async fn upload_with_token() {
    let tmp = tempfile::tempdir().unwrap();
    let state = dev_state(tmp.path().to_str().unwrap());

    let wallet = test_dataset_id(0xAA);
    let ds = test_dataset_id(0x42);

    // Issue a valid upload token
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

/// Upload without token returns 401.
#[tokio::test]
async fn upload_without_token_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let state = dev_state(tmp.path().to_str().unwrap());

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

/// Upload with token for wrong dataset returns 401.
#[tokio::test]
async fn upload_wrong_dataset_token_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let state = dev_state(tmp.path().to_str().unwrap());

    let wallet = test_dataset_id(0xAA);
    let ds = test_dataset_id(0x42);
    let wrong_ds = test_dataset_id(0x99);

    // Token is for wrong_ds, not ds
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

/// Finalize flow: upload files → finalize → dataset becomes ready.
#[tokio::test]
async fn upload_and_finalize() {
    let tmp = tempfile::tempdir().unwrap();
    let state = dev_state(tmp.path().to_str().unwrap());

    let wallet = test_dataset_id(0xAA);
    let ds = test_dataset_id(0x42);

    let token = cced::upload_token::issue_token(wallet, ds, &state.upload_hmac_key, 3600);

    // Upload a file
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
    assert_eq!(resp_json["receipt"]["files"].as_array().unwrap().len(), 1);

    // Upload after finalize should fail
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

/// Batch upload: many files with deep directory paths, then finalize.
#[tokio::test]
async fn upload_batch_deep_dirs_and_finalize() {
    let tmp = tempfile::tempdir().unwrap();
    let state = dev_state(tmp.path().to_str().unwrap());

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

    // Upload all files
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

    let receipt_files = resp_json["receipt"]["files"].as_array().unwrap();
    assert_eq!(receipt_files.len(), files.len());

    // Verify all paths are present in receipt
    let receipt_paths: Vec<&str> = receipt_files
        .iter()
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    for (path, _) in &files {
        assert!(
            receipt_paths.contains(&path.replace(".csv", ".csv.avin").as_str())
                || receipt_paths
                    .iter()
                    .any(|rp| rp.contains(&path.split('/').last().unwrap().to_string())),
            "path {} not found in receipt: {:?}",
            path,
            receipt_paths
        );
    }

    // content_hash should be non-empty
    let content_hash = resp_json["receipt"]["content_hash"].as_str().unwrap();
    assert_eq!(content_hash.len(), 64); // SHA256 hex

    // total_size should be > 0
    let total_size = resp_json["receipt"]["total_size"].as_u64().unwrap();
    assert!(total_size > 0);
}

/// Helper: build a valid submit_result request body
fn submit_result_body(state: &AppState, job_id: &str, result_hash: &[u8; 32]) -> serde_json::Value {
    let credential = state
        .credential_service
        .issue(job_id, "alice", vec![test_dataset_id(0x01)]);

    // REPORTDATA = SHA512(job_id || result_hash)
    let mut hasher = Sha512::new();
    hasher.update(job_id.as_bytes());
    hasher.update(result_hash);
    let reportdata: [u8; 64] = hasher.finalize().into();
    let evidence = tee_verifier::build_sample_evidence(&reportdata);

    serde_json::json!({
        "credential": credential,
        "job_id": job_id,
        "result_path": "/output/results",
        "result_hash": hex::encode(result_hash),
        "tee_type": "sample",
        "evidence": evidence,
    })
}

async fn post_json(
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

#[tokio::test]
async fn submit_result_success() {
    let tmp = tempfile::tempdir().unwrap();
    let state = dev_state(tmp.path().to_str().unwrap());

    let result_hash: [u8; 32] = Sha256::digest(b"encrypted result data").into();
    let body = submit_result_body(&state, "job-submit-1", &result_hash);

    let resp = post_json(state.clone(), "/v1/results/submit", &body).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let resp_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(resp_json["status"].as_str().unwrap(), "approved");
}

#[tokio::test]
async fn submit_result_invalid_quote_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let state = dev_state(tmp.path().to_str().unwrap());

    let result_hash = [0xAA; 32];
    let credential =
        state
            .credential_service
            .issue("job-bad-quote", "alice", vec![test_dataset_id(0x01)]);

    // Build evidence with WRONG reportdata
    let wrong_reportdata = [0xFF; 64];
    let evidence = tee_verifier::build_sample_evidence(&wrong_reportdata);

    let body = serde_json::json!({
        "credential": credential,
        "job_id": "job-bad-quote",
        "result_path": "/output/results",
        "result_hash": hex::encode(result_hash),
        "tee_type": "sample",
        "evidence": evidence,
    });

    let resp = post_json(state, "/v1/results/submit", &body).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn submit_result_duplicate_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let state = dev_state(tmp.path().to_str().unwrap());

    let result_hash: [u8; 32] = Sha256::digest(b"data").into();

    // First submit succeeds
    let body = submit_result_body(&state, "job-dup", &result_hash);
    let resp = post_json(state.clone(), "/v1/results/submit", &body).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Second submit with same job_id is rejected (duplicate)
    let body2 = submit_result_body(&state, "job-dup", &result_hash);
    let resp = post_json(state, "/v1/results/submit", &body2).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn get_result_returns_wrapped_rek() {
    let tmp = tempfile::tempdir().unwrap();
    let state = dev_state(tmp.path().to_str().unwrap());

    // 1. Submit a result first
    let result_hash: [u8; 32] = Sha256::digest(b"encrypted output").into();
    let body = submit_result_body(&state, "job-get-rek", &result_hash);
    let resp = post_json(state.clone(), "/v1/results/submit", &body).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // 2. Consumer generates ECDHE keypair
    let user_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let user_pk = PublicKey::from(&user_secret);

    // 3. GET result
    let get_body = serde_json::json!({
        "user_eph_pk": hex::encode(user_pk.as_bytes()),
    });
    let resp = post_json(state.clone(), "/v1/results/job-get-rek", &get_body).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let resp_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(resp_json["status"].as_str().unwrap(), "approved");
    assert_eq!(
        resp_json["result_hash"].as_str().unwrap(),
        hex::encode(result_hash)
    );

    // 4. Unwrap REK
    let ciphertext = hex::decode(resp_json["encrypted_rek"].as_str().unwrap()).unwrap();
    let nonce_bytes = hex::decode(resp_json["nonce"].as_str().unwrap()).unwrap();
    let pp_pk_bytes = hex::decode(resp_json["pp_pk"].as_str().unwrap()).unwrap();

    let bundle = key_manager::ecdhe::WrappedKeyBundle {
        ciphertext,
        nonce: nonce_bytes.try_into().unwrap(),
        pp_pk: pp_pk_bytes.try_into().unwrap(),
    };

    let (deks, rek) = key_manager::ecdhe::unwrap_keys(&bundle, &user_secret).unwrap();
    assert_eq!(deks.len(), 0); // No DEKs, only REK

    // 5. Verify REK matches
    let expected_rek = state.key_manager.derive_rek("job-get-rek").unwrap();
    assert_eq!(rek.0, expected_rek.0);
}

#[tokio::test]
async fn get_result_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let state = dev_state(tmp.path().to_str().unwrap());

    let user_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let user_pk = PublicKey::from(&user_secret);

    let body = serde_json::json!({
        "user_eph_pk": hex::encode(user_pk.as_bytes()),
    });
    let resp = post_json(state, "/v1/results/nonexistent-job", &body).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
