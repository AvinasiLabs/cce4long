use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::Json;
use key_manager::DatasetId;
use serde::Serialize;
use std::sync::Arc;

use crate::encrypt::encrypt_chunked;
use crate::state::AppState;
use crate::upload_token;

use super::error::ApiError;
use super::finalize::ensure_uploading;

#[derive(Serialize)]
pub struct UploadResponse {
    pub dataset_id: DatasetId,
    pub path: String,
    pub chunks: u32,
    pub size_bytes: usize,
    pub stored_path: String,
}

pub async fn upload_dataset(
    State(state): State<Arc<AppState>>,
    Path((dataset_id, path)): Path<(DatasetId, String)>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Result<Json<UploadResponse>, ApiError> {
    // Verify upload token at request start (before body transfer)
    let token = upload_token::extract_bearer(&headers)
        .map_err(|_| ApiError::AuthTokenMissing)?;

    upload_token::verify_token_for_dataset(token, &state.upload_hmac_key, &dataset_id)
        .map_err(|e| ApiError::AuthTokenInvalid(e.to_string()))?;

    // Ensure dataset is in uploading state (not already finalized)
    ensure_uploading(&state, &dataset_id).await?;

    tracing::info!(dataset_id = %dataset_id, path = %path, body_size = body.len(), "upload_dataset called");

    let dek = state.key_manager.derive_dek(&dataset_id)?;

    let encrypted = encrypt_chunked(&dek, &body)?;
    tracing::debug!(dataset_id = %dataset_id, encrypted_size = encrypted.len(), "encryption complete");

    let chunk_count = if body.is_empty() {
        0
    } else {
        u32::from_be_bytes(encrypted[5..9].try_into().unwrap())
    };

    let key = format!("{}/{}.avin", dataset_id, path);
    let stored_path = state.storage.put(&key, &encrypted).await?;

    tracing::info!(
        dataset_id = %dataset_id,
        stored_path = %stored_path,
        chunks = chunk_count,
        "upload_dataset complete"
    );

    Ok(Json(UploadResponse {
        dataset_id,
        path,
        chunks: chunk_count,
        size_bytes: body.len(),
        stored_path,
    }))
}
