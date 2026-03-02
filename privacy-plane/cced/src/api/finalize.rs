use axum::extract::{Path, State};
use axum::Json;
use key_manager::DatasetId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::state::AppState;
use crate::upload_token;

use super::error::ApiError;

/// Metadata stored at `{dataset_id}/.meta.json`.
#[derive(Debug, Serialize, Deserialize)]
pub struct DatasetMeta {
    pub status: DatasetStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<DatasetReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DatasetStatus {
    Uploading,
    Ready,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetReceipt {
    pub dataset_id: DatasetId,
    pub files: Vec<FileEntry>,
    pub total_size: u64,
    pub content_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub hash: String,
}

#[derive(Serialize)]
pub struct FinalizeResponse {
    pub dataset_id: DatasetId,
    pub status: DatasetStatus,
    pub receipt: DatasetReceipt,
}

fn meta_key(dataset_id: &DatasetId) -> String {
    format!("{}/.meta.json", dataset_id)
}

/// Ensure the dataset metadata file exists (create as `uploading` if not).
pub async fn ensure_uploading(
    state: &AppState,
    dataset_id: &DatasetId,
) -> Result<(), ApiError> {
    let key = meta_key(dataset_id);
    match state.storage.get(&key).await {
        Ok(data) => {
            let meta: DatasetMeta = serde_json::from_slice(&data)
                .map_err(|e| ApiError::Storage(crate::storage::StorageError::Io(e.to_string())))?;
            if meta.status == DatasetStatus::Ready {
                return Err(ApiError::DatasetAlreadyFinalized);
            }
            Ok(())
        }
        Err(_) => {
            // First upload — create metadata
            let meta = DatasetMeta {
                status: DatasetStatus::Uploading,
                receipt: None,
            };
            let json = serde_json::to_vec(&meta).unwrap();
            state.storage.put(&key, &json).await?;
            Ok(())
        }
    }
}

/// Check that a dataset is finalized (ready).
pub async fn check_finalized(
    state: &AppState,
    dataset_id: &DatasetId,
) -> Result<(), ApiError> {
    let key = meta_key(dataset_id);
    let data = state.storage.get(&key).await
        .map_err(|_| ApiError::DatasetNotFinalized)?;
    let meta: DatasetMeta = serde_json::from_slice(&data)
        .map_err(|_| ApiError::DatasetNotFinalized)?;
    if meta.status != DatasetStatus::Ready {
        return Err(ApiError::DatasetNotFinalized);
    }
    Ok(())
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
    let mk = meta_key(&dataset_id);
    match state.storage.get(&mk).await {
        Ok(data) => {
            let meta: DatasetMeta = serde_json::from_slice(&data)
                .map_err(|e| ApiError::Storage(crate::storage::StorageError::Io(e.to_string())))?;
            if meta.status == DatasetStatus::Ready {
                return Err(ApiError::DatasetAlreadyFinalized);
            }
        }
        Err(_) => {
            return Err(ApiError::Storage(crate::storage::StorageError::Io(
                "no files uploaded for this dataset".into(),
            )));
        }
    }

    // 3. List all uploaded files under this dataset
    let prefix = format!("{}/", dataset_id);
    let all_keys = state.storage.list(&prefix).await?;

    let mut files = Vec::new();
    let mut ordered_hashes = Vec::new();

    for key in &all_keys {
        // Skip the metadata file itself
        if key.ends_with("/.meta.json") {
            continue;
        }
        let data = state.storage.get(key).await?;
        let hash = Sha256::digest(&data);
        let hash_hex = hex::encode(hash);

        // Derive relative path (strip prefix)
        let rel_path = key.strip_prefix(&prefix).unwrap_or(key);

        files.push(FileEntry {
            path: rel_path.to_string(),
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
    let json = serde_json::to_vec(&meta).unwrap();
    state.storage.put(&mk, &json).await?;

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

