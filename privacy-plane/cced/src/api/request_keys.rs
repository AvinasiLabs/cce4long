use axum::extract::State;
use axum::Json;
use key_manager::DatasetId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::sync::Arc;
use tee_verifier::TeeType;

use compute_controller::JobCredential;
use key_manager::ecdhe;

use crate::state::AppState;

use super::error::ApiError;

#[derive(Deserialize)]
pub struct RequestKeysBody {
    pub credential: JobCredential,
    pub request_id: String,
    pub tee_type: TeeType,
    pub evidence: serde_json::Value,
    pub eph_pk: String,
    pub dataset_ids: Vec<DatasetId>,
}

#[derive(Serialize)]
pub struct RequestKeysResponse {
    pub encrypted_keys: String,
    pub nonce: String,
    pub pp_pk: String,
}

pub async fn request_keys(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RequestKeysBody>,
) -> Result<Json<RequestKeysResponse>, ApiError> {
    // 1. Verify and consume credential
    state.credential_service.verify_and_consume(&body.credential)?;

    // 2. Check credential.datasets ⊇ dataset_ids
    for ds_id in &body.dataset_ids {
        if !body.credential.datasets.contains(ds_id) {
            return Err(ApiError::DatasetNotAuthorized(format!(
                "dataset {} not in credential",
                ds_id
            )));
        }
    }

    // 3. Parse hex inputs
    let request_id_bytes = hex::decode(&body.request_id)
        .map_err(|e| ApiError::InvalidHex(format!("request_id: {}", e)))?;
    if request_id_bytes.len() != 16 {
        return Err(ApiError::InvalidRequestId);
    }
    let request_id: [u8; 16] = request_id_bytes.try_into().unwrap();

    let eph_pk_bytes = hex::decode(&body.eph_pk)
        .map_err(|e| ApiError::InvalidHex(format!("eph_pk: {}", e)))?;
    if eph_pk_bytes.len() != 32 {
        return Err(ApiError::InvalidEphPk);
    }
    let eph_pk: [u8; 32] = eph_pk_bytes.try_into().unwrap();

    // 4. Request ID replay detection
    {
        let mut tracker = state.request_id_tracker.lock().unwrap();
        if !tracker.insert(request_id) {
            return Err(ApiError::RequestIdReplay);
        }
    }

    // 5. Compute expected_reportdata = SHA512(eph_pk || request_id)
    let mut hasher = Sha512::new();
    hasher.update(eph_pk);
    hasher.update(request_id);
    let digest = hasher.finalize();
    let expected_reportdata: [u8; 64] = digest.into();

    // 6. Verify TEE evidence
    let verification = state
        .tee_verifier
        .verify(&body.tee_type, &body.evidence, &expected_reportdata)
        .await?;

    // 7. Check measurement trust
    if !state
        .measurement_registry
        .is_trusted(&verification.measurement)
        .await
    {
        return Err(ApiError::UntrustedMeasurement);
    }

    // 8. Derive DEKs for each dataset_id
    let mut deks = Vec::with_capacity(body.dataset_ids.len());
    for ds_id in &body.dataset_ids {
        let dek = state.key_manager.derive_dek(ds_id)?;
        deks.push(dek);
    }

    // 9. Derive REK for job_id
    let rek = state
        .key_manager
        .derive_rek(&body.credential.job_id)?;

    // 10. ECDHE wrap
    let bundle = ecdhe::wrap_keys(&deks, &rek, &eph_pk)?;

    // 11. Return hex-encoded response
    Ok(Json(RequestKeysResponse {
        encrypted_keys: hex::encode(&bundle.ciphertext),
        nonce: hex::encode(bundle.nonce),
        pp_pk: hex::encode(bundle.pp_pk),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::api;
    use crate::storage::LocalStorage;

    fn dev_state() -> Arc<AppState> {
        let dir = tempfile::tempdir().unwrap();
        let storage = Box::new(LocalStorage::new(dir.path().to_str().unwrap()));
        Arc::new(AppState::dev(storage))
    }

    /// Build a valid request body for testing.
    fn valid_request(state: &AppState) -> serde_json::Value {
        use rand::RngCore;
        use sha2::{Digest, Sha512};
        use x25519_dalek::{PublicKey, StaticSecret};

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
        let app = api::router(state);
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
}
