use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::Json;
use serde::Serialize;
use std::sync::Arc;

use crate::encrypt::encrypt_chunked;
use crate::state::AppState;

use super::error::ApiError;

#[derive(Serialize)]
pub struct UploadResponse {
    pub dataset_id: u64,
    pub chunks: u32,
    pub size_bytes: usize,
    pub stored_path: String,
}

pub async fn upload_dataset(
    State(state): State<Arc<AppState>>,
    Path(dataset_id): Path<u64>,
    body: Bytes,
) -> Result<Json<UploadResponse>, ApiError> {
    tracing::info!(dataset_id = dataset_id, body_size = body.len(), "upload_dataset called");

    let dek = state.key_manager.derive_dek(dataset_id)?;

    let encrypted = encrypt_chunked(&dek, &body)?;
    tracing::debug!(dataset_id = dataset_id, encrypted_size = encrypted.len(), "encryption complete");

    let chunk_count = if body.is_empty() {
        0
    } else {
        u32::from_be_bytes(encrypted[5..9].try_into().unwrap())
    };

    let key = format!("{}.avin", dataset_id);
    let stored_path = state.storage.put(&key, &encrypted).await?;

    tracing::info!(
        dataset_id = dataset_id,
        stored_path = %stored_path,
        chunks = chunk_count,
        "upload_dataset complete"
    );

    Ok(Json(UploadResponse {
        dataset_id,
        chunks: chunk_count,
        size_bytes: body.len(),
        stored_path,
    }))
}
