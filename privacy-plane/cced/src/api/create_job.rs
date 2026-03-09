use axum::extract::State;
use axum::Json;
use compute_controller::JobCredential;
use key_manager::DatasetId;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::state::AppState;

use super::auth::recover_address;
use super::error::ApiError;
use super::finalize::check_finalized;

#[derive(Deserialize)]
pub struct CreateJobRequest {
    pub wallet_address: DatasetId,
    pub dataset_ids: Vec<DatasetId>,
    pub job_spec: serde_json::Value,
    pub signature: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct CreateJobResponse {
    pub job_id: String,
    pub credential: JobCredential,
    pub submit_credential: JobCredential,
    pub dataset_ids: Vec<DatasetId>,
    pub job_spec: serde_json::Value,
}

/// POST /v1/jobs/create
///
/// Creates a compute job. Verifies wallet signature, checks dataset access and finalization,
/// then issues two credentials (one for key request, one for result submission).
pub async fn create_job(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateJobRequest>,
) -> Result<Json<CreateJobResponse>, ApiError> {
    // 1. Recover signer address from EIP-191 signature
    let recovered = recover_address(&body.message, &body.signature)
        .map_err(ApiError::SignatureRecoveryFailed)?;

    // 2. Compare recovered address with claimed wallet_address
    let claimed: [u8; 20] = body.wallet_address.into();
    if recovered != claimed {
        return Err(ApiError::SignatureRecoveryFailed(
            "recovered address does not match wallet_address".into(),
        ));
    }

    // 3. Check access for each dataset
    for dataset_id in &body.dataset_ids {
        let has_access = state
            .access_verifier
            .has_access(dataset_id, &recovered)
            .await
            .map_err(|e| ApiError::VerifierError(e.to_string()))?;
        if !has_access {
            return Err(ApiError::DatasetNotAuthorized(format!(
                "no access to dataset {}",
                dataset_id
            )));
        }
    }

    // 4. Check each dataset is finalized
    for dataset_id in &body.dataset_ids {
        check_finalized(&state, dataset_id).await?;
    }

    // 5. Generate job_id
    let job_id = Uuid::new_v4().to_string();
    let user = format!("0x{}", hex::encode(recovered));

    // 6. Issue two credentials (same job_id, different nonces)
    let credential = state
        .credential_service
        .issue(&job_id, &user, body.dataset_ids.clone());
    let submit_credential = state
        .credential_service
        .issue(&job_id, &user, body.dataset_ids.clone());

    tracing::info!(
        job_id = %job_id,
        user = %user,
        dataset_count = body.dataset_ids.len(),
        "job created"
    );

    Ok(Json(CreateJobResponse {
        job_id,
        credential,
        submit_credential,
        dataset_ids: body.dataset_ids,
        job_spec: body.job_spec,
    }))
}
