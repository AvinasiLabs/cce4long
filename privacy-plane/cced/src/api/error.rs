use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::encrypt::EncryptError;
use crate::storage::StorageError;

pub enum ApiError {
    KeyDerivation(key_manager::KeyError),
    Encryption(EncryptError),
    Storage(StorageError),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            ApiError::KeyDerivation(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            ApiError::Encryption(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            ApiError::Storage(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        };
        (status, msg).into_response()
    }
}

impl From<key_manager::KeyError> for ApiError {
    fn from(e: key_manager::KeyError) -> Self {
        ApiError::KeyDerivation(e)
    }
}

impl From<EncryptError> for ApiError {
    fn from(e: EncryptError) -> Self {
        ApiError::Encryption(e)
    }
}

impl From<StorageError> for ApiError {
    fn from(e: StorageError) -> Self {
        ApiError::Storage(e)
    }
}
