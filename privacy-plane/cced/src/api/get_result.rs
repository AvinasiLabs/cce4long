use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use key_manager::ecdhe;

use crate::state::AppState;

use super::error::ApiError;

#[derive(Deserialize)]
pub struct GetResultBody {
    pub user_eph_pk: String,
}

#[derive(Serialize)]
pub struct GetResultResponse {
    pub status: String,
    pub result_path: String,
    pub result_hash: String,
    pub encrypted_rek: String,
    pub nonce: String,
    pub pp_pk: String,
}

pub async fn get_result(
    State(state): State<Arc<AppState>>,
    Path(job_id): Path<String>,
    Json(body): Json<GetResultBody>,
) -> Result<Json<GetResultResponse>, ApiError> {
    // 1. Get result record and check it's approved
    let record = state
        .output_gate
        .get(&job_id)
        .map_err(ApiError::OutputGate)?;

    if record.status != output_gate::ResultStatus::Approved {
        return Err(ApiError::ResultNotApproved);
    }

    // 2. Parse user ephemeral public key
    let eph_pk_bytes = hex::decode(&body.user_eph_pk)
        .map_err(|e| ApiError::InvalidHex(format!("user_eph_pk: {}", e)))?;
    if eph_pk_bytes.len() != 32 {
        return Err(ApiError::InvalidEphPk);
    }
    let eph_pk: [u8; 32] = eph_pk_bytes.try_into().unwrap();

    // 3. Derive REK for this job
    let rek = state.key_manager.derive_rek(&job_id)?;

    // 4. ECDHE wrap: empty DEKs, only REK
    let bundle = ecdhe::wrap_keys(&[], &rek, &eph_pk)?;

    Ok(Json(GetResultResponse {
        status: "approved".to_string(),
        result_path: record.result_path,
        result_hash: hex::encode(record.result_hash),
        encrypted_rek: hex::encode(&bundle.ciphertext),
        nonce: hex::encode(bundle.nonce),
        pp_pk: hex::encode(bundle.pp_pk),
    }))
}
