use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use rand::RngCore;
use sha2::{Digest, Sha512};
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
