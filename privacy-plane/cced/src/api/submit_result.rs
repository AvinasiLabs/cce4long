use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::sync::Arc;

use compute_controller::JobCredential;

use crate::state::AppState;

use super::error::ApiError;

#[derive(Deserialize)]
pub struct SubmitResultBody {
    pub credential: JobCredential,
    pub job_id: String,
    pub result_path: String,
    pub result_hash: String,
    pub quote: String,
}

#[derive(Serialize)]
pub struct SubmitResultResponse {
    pub status: String,
}

pub async fn submit_result(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SubmitResultBody>,
) -> Result<Json<SubmitResultResponse>, ApiError> {
    // 1. Verify and consume credential
    state.credential_service.verify_and_consume(&body.credential)?;

    // 2. Parse hex inputs
    let result_hash_bytes = hex::decode(&body.result_hash)
        .map_err(|e| ApiError::InvalidHex(format!("result_hash: {}", e)))?;
    if result_hash_bytes.len() != 32 {
        return Err(ApiError::InvalidResultHash);
    }
    let result_hash: [u8; 32] = result_hash_bytes.try_into().unwrap();

    let quote_bytes = hex::decode(&body.quote)
        .map_err(|e| ApiError::InvalidHex(format!("quote: {}", e)))?;

    // 3. Compute expected reportdata = SHA512(job_id || result_hash)
    let mut hasher = Sha512::new();
    hasher.update(body.job_id.as_bytes());
    hasher.update(result_hash);
    let expected_reportdata: [u8; 64] = hasher.finalize().into();

    // 4. Verify TEE quote
    let verification = state
        .tee_verifier
        .verify(&quote_bytes, &expected_reportdata)
        .await?;

    // 5. Check measurement trust
    if !state
        .measurement_registry
        .is_trusted(&verification.measurement)
        .await
    {
        return Err(ApiError::UntrustedMeasurement);
    }

    // 6. Submit to output gate
    let status = state
        .output_gate
        .submit(&body.job_id, &body.result_path, result_hash)
        .await
        .map_err(ApiError::OutputGate)?;

    let status_str = match status {
        output_gate::ResultStatus::Approved => "approved",
        output_gate::ResultStatus::PendingReview => "pending_review",
        output_gate::ResultStatus::Rejected { .. } => "rejected",
    };

    Ok(Json(SubmitResultResponse {
        status: status_str.to_string(),
    }))
}
