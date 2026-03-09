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
    pub storage: serde_json::Value,
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

    // 11. Return hex-encoded response with JuiceFS config
    Ok(Json(RequestKeysResponse {
        encrypted_keys: hex::encode(&bundle.ciphertext),
        nonce: hex::encode(bundle.nonce),
        pp_pk: hex::encode(bundle.pp_pk),
        storage: state.dataset_store.storage_access_config(),
    }))
}
