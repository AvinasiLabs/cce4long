mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use key_manager::DatasetId;
use rand::RngCore;
use sha2::{Digest, Sha512};
use tower::ServiceExt;
use x25519_dalek::{PublicKey, StaticSecret};

use cced::state::AppState;

use common::{dev_state, post_json, test_dataset_id};

#[tokio::test]
async fn end_to_end_request_keys() {
    let state = dev_state();

    let ds1 = test_dataset_id(0x01);
    let ds2 = test_dataset_id(0x02);

    let credential = state
        .credential_service
        .issue("job-42", "alice", vec![ds1, ds2]);

    let cvm_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let cvm_pk = PublicKey::from(&cvm_secret);

    let mut request_id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut request_id);

    let mut hasher = Sha512::new();
    hasher.update(cvm_pk.as_bytes());
    hasher.update(&request_id);
    let reportdata: [u8; 64] = hasher.finalize().into();

    let evidence = tee_verifier::build_sample_evidence(&reportdata);

    let body = serde_json::json!({
        "credential": credential,
        "request_id": hex::encode(&request_id),
        "tee_type": "sample",
        "evidence": evidence,
        "eph_pk": hex::encode(cvm_pk.as_bytes()),
        "dataset_ids": [ds1, ds2]
    });

    let resp = post_json(state.clone(), "/v1/keys/request", &body).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let resp_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert!(resp_json["storage"].is_object());

    let ciphertext = hex::decode(resp_json["encrypted_keys"].as_str().unwrap()).unwrap();
    let nonce_bytes = hex::decode(resp_json["nonce"].as_str().unwrap()).unwrap();
    let pp_pk_bytes = hex::decode(resp_json["pp_pk"].as_str().unwrap()).unwrap();

    let bundle = key_manager::ecdhe::WrappedKeyBundle {
        ciphertext,
        nonce: nonce_bytes.try_into().unwrap(),
        pp_pk: pp_pk_bytes.try_into().unwrap(),
    };

    let (deks, rek) = key_manager::ecdhe::unwrap_keys(&bundle, &cvm_secret).unwrap();

    assert_eq!(deks.len(), 2);
    let expected_dek1 = state.key_manager.derive_dek(&ds1).unwrap();
    let expected_dek2 = state.key_manager.derive_dek(&ds2).unwrap();
    assert_eq!(deks[0].0, expected_dek1.0);
    assert_eq!(deks[1].0, expected_dek2.0);

    let expected_rek = state.key_manager.derive_rek("job-42").unwrap();
    assert_eq!(rek.0, expected_rek.0);
}

fn valid_request(state: &AppState) -> serde_json::Value {
    let cvm_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let cvm_pk = PublicKey::from(&cvm_secret);

    let mut request_id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut request_id);

    let credential = state.credential_service.issue(
        "job-1",
        "alice",
        vec![DatasetId::from([0x01; 20]), DatasetId::from([0x02; 20])],
    );

    let mut hasher = Sha512::new();
    hasher.update(cvm_pk.as_bytes());
    hasher.update(&request_id);
    let reportdata: [u8; 64] = hasher.finalize().into();

    let evidence = tee_verifier::build_sample_evidence(&reportdata);

    serde_json::json!({
        "credential": credential,
        "request_id": hex::encode(&request_id),
        "tee_type": "sample",
        "evidence": evidence,
        "eph_pk": hex::encode(cvm_pk.as_bytes()),
        "dataset_ids": ["0x0101010101010101010101010101010101010101", "0x0202020202020202020202020202020202020202"]
    })
}

async fn post_request_keys(
    state: Arc<AppState>,
    body: serde_json::Value,
) -> axum::http::Response<Body> {
    let app = cced::api::router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/keys/request")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    app.oneshot(req).await.unwrap()
}

#[tokio::test]
async fn happy_path() {
    let state = dev_state();
    let body = valid_request(&state);
    let resp = post_request_keys(state, body).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn invalid_credential_signature() {
    let state = dev_state();
    let mut body = valid_request(&state);
    body["credential"]["job_id"] = serde_json::json!("tampered-job");
    let resp = post_request_keys(state, body).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_credential() {
    let state = dev_state();
    let mut body = valid_request(&state);
    body["credential"]["expires_at"] = serde_json::json!(0);
    let resp = post_request_keys(state, body).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn nonce_replay() {
    let state = dev_state();
    let body = valid_request(&state);
    let resp = post_request_keys(state.clone(), body.clone()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = post_request_keys(state, body).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unauthorized_dataset() {
    let state = dev_state();
    let mut body = valid_request(&state);
    body["dataset_ids"] = serde_json::json!(["0x0101010101010101010101010101010101010101", "0x9999999999999999999999999999999999999999"]);
    let resp = post_request_keys(state, body).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn request_id_replay() {
    let state = dev_state();

    let body1 = valid_request(&state);
    let resp = post_request_keys(state.clone(), body1.clone()).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let mut body2 = valid_request(&state);
    body2["request_id"] = body1["request_id"].clone();
    let resp = post_request_keys(state, body2).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn reportdata_mismatch() {
    let state = dev_state();
    let mut body = valid_request(&state);
    let wrong_rd = [0xFF; 64];
    let wrong_evidence = tee_verifier::build_sample_evidence(&wrong_rd);
    body["evidence"] = wrong_evidence;
    let resp = post_request_keys(state, body).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn invalid_hex_input() {
    let state = dev_state();
    let mut body = valid_request(&state);
    body["eph_pk"] = serde_json::json!("not-valid-hex!");
    let resp = post_request_keys(state, body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn wrong_length_request_id() {
    let state = dev_state();
    let mut body = valid_request(&state);
    body["request_id"] = serde_json::json!("aabb");
    let resp = post_request_keys(state, body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
