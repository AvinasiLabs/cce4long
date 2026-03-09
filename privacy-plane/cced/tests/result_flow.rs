mod common;

use axum::http::StatusCode;
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

use cced::state::AppState;

use common::{dev_state, post_json, test_dataset_id};

fn submit_result_body(state: &AppState, job_id: &str, result_hash: &[u8; 32]) -> serde_json::Value {
    let credential = state
        .credential_service
        .issue(job_id, "alice", vec![test_dataset_id(0x01)]);

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

#[tokio::test]
async fn submit_result_success() {
    let state = dev_state();

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
    let state = dev_state();

    let result_hash = [0xAA; 32];
    let credential =
        state
            .credential_service
            .issue("job-bad-quote", "alice", vec![test_dataset_id(0x01)]);

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
    let state = dev_state();

    let result_hash: [u8; 32] = Sha256::digest(b"data").into();

    let body = submit_result_body(&state, "job-dup", &result_hash);
    let resp = post_json(state.clone(), "/v1/results/submit", &body).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body2 = submit_result_body(&state, "job-dup", &result_hash);
    let resp = post_json(state, "/v1/results/submit", &body2).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn get_result_returns_wrapped_rek() {
    let state = dev_state();

    let result_hash: [u8; 32] = Sha256::digest(b"encrypted output").into();
    let body = submit_result_body(&state, "job-get-rek", &result_hash);
    let resp = post_json(state.clone(), "/v1/results/submit", &body).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let user_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let user_pk = PublicKey::from(&user_secret);

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

    let ciphertext = hex::decode(resp_json["encrypted_rek"].as_str().unwrap()).unwrap();
    let nonce_bytes = hex::decode(resp_json["nonce"].as_str().unwrap()).unwrap();
    let pp_pk_bytes = hex::decode(resp_json["pp_pk"].as_str().unwrap()).unwrap();

    let bundle = key_manager::ecdhe::WrappedKeyBundle {
        ciphertext,
        nonce: nonce_bytes.try_into().unwrap(),
        pp_pk: pp_pk_bytes.try_into().unwrap(),
    };

    let (deks, rek) = key_manager::ecdhe::unwrap_keys(&bundle, &user_secret).unwrap();
    assert_eq!(deks.len(), 0);

    let expected_rek = state.key_manager.derive_rek("job-get-rek").unwrap();
    assert_eq!(rek.0, expected_rek.0);
}

#[tokio::test]
async fn get_result_not_found() {
    let state = dev_state();

    let user_secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let user_pk = PublicKey::from(&user_secret);

    let body = serde_json::json!({
        "user_eph_pk": hex::encode(user_pk.as_bytes()),
    });
    let resp = post_json(state, "/v1/results/nonexistent-job", &body).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
