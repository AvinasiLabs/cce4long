use axum::extract::{Path, State};
use axum::Json;
use key_manager::DatasetId;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::dataset_store::{
    DatasetMeta, DatasetReceipt, DatasetStatus, DatasetStoreError, FileEntry,
};
use crate::state::AppState;
use crate::upload_token;

use super::error::ApiError;

#[derive(Serialize)]
pub struct FinalizeResponse {
    pub dataset_id: DatasetId,
    pub status: DatasetStatus,
    pub receipt: DatasetReceipt,
}

/// Ensure the dataset metadata exists (create as `uploading` if not).
pub async fn ensure_uploading(
    state: &AppState,
    dataset_id: &DatasetId,
) -> Result<(), ApiError> {
    match state.dataset_store.get_meta(dataset_id).await? {
        Some(meta) => {
            if meta.status == DatasetStatus::Ready {
                return Err(ApiError::DatasetAlreadyFinalized);
            }
            Ok(())
        }
        None => {
            // First upload — create metadata
            let meta = DatasetMeta {
                status: DatasetStatus::Uploading,
                receipt: None,
            };
            state.dataset_store.set_meta(dataset_id, &meta).await?;
            Ok(())
        }
    }
}

/// Check that a dataset is finalized (ready).
pub async fn check_finalized(
    state: &AppState,
    dataset_id: &DatasetId,
) -> Result<(), ApiError> {
    match state.dataset_store.get_meta(dataset_id).await? {
        Some(meta) if meta.status == DatasetStatus::Ready => Ok(()),
        _ => Err(ApiError::DatasetNotFinalized),
    }
}

/// POST /v1/datasets/{dataset_id}/finalize
///
/// Marks upload as complete. Scans all uploaded files, computes receipt, transitions to `ready`.
pub async fn finalize_dataset(
    State(state): State<Arc<AppState>>,
    Path(dataset_id): Path<DatasetId>,
    headers: axum::http::HeaderMap,
) -> Result<Json<FinalizeResponse>, ApiError> {
    // 1. Verify upload token from Authorization header
    let token = upload_token::extract_bearer(&headers)
        .map_err(|_| ApiError::AuthTokenMissing)?;
    let payload = upload_token::verify_token_for_dataset(
        token,
        &state.upload_hmac_key,
        &dataset_id,
    )
    .map_err(|e| ApiError::AuthTokenInvalid(e.to_string()))?;

    tracing::info!(
        dataset_id = %dataset_id,
        wallet = %payload.wallet,
        "finalize_dataset called"
    );

    // 2. Check current state — must be `uploading`
    match state.dataset_store.get_meta(&dataset_id).await? {
        Some(meta) => {
            if meta.status == DatasetStatus::Ready {
                return Err(ApiError::DatasetAlreadyFinalized);
            }
        }
        None => {
            return Err(ApiError::DatasetStore(DatasetStoreError::Backend(
                "no files uploaded for this dataset".into(),
            )));
        }
    }

    // 3. List all uploaded files under this dataset
    let file_paths = state.dataset_store.list_files(&dataset_id).await?;

    let mut files = Vec::new();
    let mut ordered_hashes = Vec::new();

    for path in &file_paths {
        let data = state.dataset_store.get_file(&dataset_id, path).await?;
        let hash = Sha256::digest(&data);
        let hash_hex = hex::encode(hash);

        files.push(FileEntry {
            path: path.clone(),
            size: data.len() as u64,
            hash: hash_hex.clone(),
        });
        ordered_hashes.push(hash_hex);
    }

    // Sort by path for deterministic ordering
    files.sort_by(|a, b| a.path.cmp(&b.path));
    ordered_hashes.sort();

    // 4. Compute content_hash: SHA256 of all sorted file hashes concatenated
    let mut content_hasher = Sha256::new();
    for h in &ordered_hashes {
        content_hasher.update(h.as_bytes());
    }
    let content_hash = hex::encode(content_hasher.finalize());

    let total_size: u64 = files.iter().map(|f| f.size).sum();

    let receipt = DatasetReceipt {
        dataset_id,
        files,
        total_size,
        content_hash,
    };

    // 5. Update metadata to `ready`
    let meta = DatasetMeta {
        status: DatasetStatus::Ready,
        receipt: Some(receipt.clone()),
    };
    state.dataset_store.set_meta(&dataset_id, &meta).await?;

    tracing::info!(
        dataset_id = %dataset_id,
        file_count = receipt.files.len(),
        total_size = receipt.total_size,
        "dataset finalized"
    );

    Ok(Json(FinalizeResponse {
        dataset_id,
        status: DatasetStatus::Ready,
        receipt,
    }))
}
