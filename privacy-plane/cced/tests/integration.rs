use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
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

/// Full CVM-side flow: issue credential → generate keypair → build quote → request keys → unwrap → verify DEKs + REK
#[tokio::test]
async fn end_to_end_request_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let state = dev_state(tmp.path().to_str().unwrap());

    // 1. Issue credential
    let credential = state.credential_service.issue("job-42", "alice", vec![1, 2]);

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

    // 5. Build dev quote
    let quote = tee_verifier::build_dev_quote(&reportdata);

    // 6. POST /v1/keys/request
    let body = serde_json::json!({
        "credential": credential,
        "request_id": hex::encode(&request_id),
        "quote": hex::encode(&quote),
        "eph_pk": hex::encode(cvm_pk.as_bytes()),
        "dataset_ids": [1, 2]
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
    let expected_dek1 = state.key_manager.derive_dek(1).unwrap();
    let expected_dek2 = state.key_manager.derive_dek(2).unwrap();
    assert_eq!(deks[0].0, expected_dek1.0);
    assert_eq!(deks[1].0, expected_dek2.0);

    // 10. Verify REK matches
    let expected_rek = state.key_manager.derive_rek("job-42").unwrap();
    assert_eq!(rek.0, expected_rek.0);
}

/// Regression: upload endpoint still works after AppState expansion
#[tokio::test]
async fn upload_still_works() {
    let tmp = tempfile::tempdir().unwrap();
    let state = dev_state(tmp.path().to_str().unwrap());

    let app = cced::api::router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/datasets/42/upload")
        .body(Body::from("hello world"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// --- Output Gate integration tests ---

/// Helper: build a valid submit_result request body
fn submit_result_body(
    state: &AppState,
    job_id: &str,
    result_hash: &[u8; 32],
) -> serde_json::Value {
    let credential = state.credential_service.issue(job_id, "alice", vec![1]);

    // REPORTDATA = SHA512(job_id || result_hash)
    let mut hasher = Sha512::new();
    hasher.update(job_id.as_bytes());
    hasher.update(result_hash);
    let reportdata: [u8; 64] = hasher.finalize().into();
    let quote = tee_verifier::build_dev_quote(&reportdata);

    serde_json::json!({
        "credential": credential,
        "job_id": job_id,
        "result_path": "/output/results",
        "result_hash": hex::encode(result_hash),
        "quote": hex::encode(&quote),
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
    let credential = state.credential_service.issue("job-bad-quote", "alice", vec![1]);

    // Build a quote with WRONG reportdata
    let wrong_reportdata = [0xFF; 64];
    let quote = tee_verifier::build_dev_quote(&wrong_reportdata);

    let body = serde_json::json!({
        "credential": credential,
        "job_id": "job-bad-quote",
        "result_path": "/output/results",
        "result_hash": hex::encode(result_hash),
        "quote": hex::encode(&quote),
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
    assert_eq!(resp_json["result_hash"].as_str().unwrap(), hex::encode(result_hash));

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
