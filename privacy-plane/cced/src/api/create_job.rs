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

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use crate::api;
    use crate::dataset_store::{DatasetMeta, DatasetReceipt, DatasetStatus, FileEntry};

    use super::*;

    fn dev_root_key() -> [u8; 32] {
        use hkdf::Hkdf;
        use sha2::Sha256;
        let hk = Hkdf::<Sha256>::new(None, b"cce4long-dev-root-key");
        let mut key = [0u8; 32];
        hk.expand(b"dev-root", &mut key).expect("valid length");
        key
    }

    fn dev_state() -> Arc<AppState> {
        Arc::new(
            AppState::new(
                &dev_root_key(),
                Box::new(crate::dataset_store::InMemoryDatasetStore::new()),
                tee_verifier::TeeVerifier::new()
                    .register(tee_verifier::TeeType::Sample, tee_verifier::SampleVerifier),
            )
            .unwrap(),
        )
    }

    /// Pre-computed test wallet derived from private key:
    /// 0x33d4c7001aad4acf3ababc101d44cfcbc0637e42db75ff24d2f1789035795093
    const TEST_WALLET: &str = "0x10c77Eb3C94D0129AF6626733CABf5d1a5811899";
    const TEST_MESSAGE: &str =
        "Create job for datasets 0x4242424242424242424242424242424242424242";
    /// Signature of TEST_MESSAGE by the test private key (EIP-191 personal_sign)
    const TEST_SIGNATURE: &str = "0xc0a6c6097a062229ba27c488cd9d5cd5b3ab16b93c54fbdf46feb16ce7df4753749c8a65039dd6d675e35c199718e75531c9dca02f16142637bb40c8bd19dda71c";

    async fn post_create_job(
        state: Arc<AppState>,
        body: serde_json::Value,
    ) -> axum::http::Response<Body> {
        let app = api::router(state);
        let req = Request::builder()
            .method("POST")
            .uri("/v1/jobs/create")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        app.oneshot(req).await.unwrap()
    }

    /// Helper: upload a dummy file and finalize the dataset.
    async fn upload_and_finalize(state: &AppState, dataset_id: &DatasetId) {
        // Write a dummy file
        state
            .dataset_store
            .put_file(dataset_id, "data.csv", b"col1,col2\n1,2\n")
            .await
            .unwrap();

        // Write finalized metadata
        let meta = DatasetMeta {
            status: DatasetStatus::Ready,
            receipt: Some(DatasetReceipt {
                dataset_id: *dataset_id,
                files: vec![FileEntry {
                    path: "data.csv".into(),
                    size: 14,
                    hash: "dummy".into(),
                }],
                total_size: 14,
                content_hash: "dummy".into(),
            }),
        };
        state
            .dataset_store
            .set_meta(dataset_id, &meta)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_job_success() {
        let state = dev_state();
        let dataset_id = DatasetId::from([0x42; 20]);

        // Setup: upload + finalize
        upload_and_finalize(&state, &dataset_id).await;

        let body = serde_json::json!({
            "wallet_address": TEST_WALLET,
            "dataset_ids": ["0x4242424242424242424242424242424242424242"],
            "job_spec": {"algorithm": "mean", "columns": ["col1"]},
            "signature": TEST_SIGNATURE,
            "message": TEST_MESSAGE
        });

        let resp = post_create_job(state.clone(), body).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        // Verify response structure
        assert!(resp_json["job_id"].is_string());
        assert!(resp_json["credential"].is_object());
        assert!(resp_json["submit_credential"].is_object());
        assert_eq!(
            resp_json["dataset_ids"],
            serde_json::json!(["0x4242424242424242424242424242424242424242"])
        );
        assert_eq!(
            resp_json["job_spec"],
            serde_json::json!({"algorithm": "mean", "columns": ["col1"]})
        );

        // Two credentials should have the same job_id but different nonces
        assert_eq!(resp_json["credential"]["job_id"], resp_json["submit_credential"]["job_id"]);
        assert_ne!(resp_json["credential"]["nonce"], resp_json["submit_credential"]["nonce"]);
    }

    #[tokio::test]
    async fn create_job_dataset_not_finalized() {
        let state = dev_state();
        // Don't upload or finalize — dataset doesn't exist

        let body = serde_json::json!({
            "wallet_address": TEST_WALLET,
            "dataset_ids": ["0x4242424242424242424242424242424242424242"],
            "job_spec": {},
            "signature": TEST_SIGNATURE,
            "message": TEST_MESSAGE
        });

        let resp = post_create_job(state, body).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn create_job_bad_signature() {
        let state = dev_state();
        let dataset_id = DatasetId::from([0x42; 20]);
        upload_and_finalize(&state, &dataset_id).await;

        let body = serde_json::json!({
            "wallet_address": TEST_WALLET,
            "dataset_ids": ["0x4242424242424242424242424242424242424242"],
            "job_spec": {},
            "signature": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefde1b",
            "message": TEST_MESSAGE
        });

        let resp = post_create_job(state, body).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
