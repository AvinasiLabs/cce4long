use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::encrypt::EncryptError;
use crate::storage::StorageError;

pub enum ApiError {
    KeyDerivation(key_manager::KeyError),
    Encryption(EncryptError),
    Storage(StorageError),
    // RequestKeys errors
    InvalidSignature,
    CredentialExpired,
    NonceReused,
    DatasetNotAuthorized(String),
    UntrustedMeasurement,
    ReportdataMismatch,
    InvalidHex(String),
    InvalidRequestId,
    InvalidEphPk,
    RequestIdReplay,
    VerifierError(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            ApiError::KeyDerivation(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            ApiError::Encryption(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            ApiError::Storage(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            ApiError::InvalidSignature => (StatusCode::UNAUTHORIZED, "invalid credential signature".into()),
            ApiError::CredentialExpired => (StatusCode::UNAUTHORIZED, "credential expired".into()),
            ApiError::NonceReused => (StatusCode::UNAUTHORIZED, "credential nonce already used".into()),
            ApiError::DatasetNotAuthorized(msg) => (StatusCode::FORBIDDEN, msg),
            ApiError::UntrustedMeasurement => (StatusCode::FORBIDDEN, "untrusted measurement".into()),
            ApiError::ReportdataMismatch => (StatusCode::FORBIDDEN, "reportdata mismatch".into()),
            ApiError::InvalidHex(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::InvalidRequestId => (StatusCode::BAD_REQUEST, "invalid request_id: expected 32 hex chars (16 bytes)".into()),
            ApiError::InvalidEphPk => (StatusCode::BAD_REQUEST, "invalid eph_pk: expected 64 hex chars (32 bytes)".into()),
            ApiError::RequestIdReplay => (StatusCode::CONFLICT, "request_id already used".into()),
            ApiError::VerifierError(msg) => (StatusCode::FORBIDDEN, msg),
        };
        (status, axum::Json(json!({ "error": msg }))).into_response()
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

impl From<compute_controller::ControllerError> for ApiError {
    fn from(e: compute_controller::ControllerError) -> Self {
        match e {
            compute_controller::ControllerError::InvalidSignature => ApiError::InvalidSignature,
            compute_controller::ControllerError::Expired => ApiError::CredentialExpired,
            compute_controller::ControllerError::NonceReused => ApiError::NonceReused,
            compute_controller::ControllerError::DatasetNotAuthorized(id) => {
                ApiError::DatasetNotAuthorized(format!("dataset {} not authorized", id))
            }
            compute_controller::ControllerError::UntrustedMeasurement(_) => {
                ApiError::UntrustedMeasurement
            }
            other => ApiError::VerifierError(other.to_string()),
        }
    }
}

impl From<tee_verifier::VerifierError> for ApiError {
    fn from(e: tee_verifier::VerifierError) -> Self {
        match e {
            tee_verifier::VerifierError::ReportdataMismatch => ApiError::ReportdataMismatch,
            other => ApiError::VerifierError(other.to_string()),
        }
    }
}
