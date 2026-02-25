use thiserror::Error;

#[derive(Debug, Error)]
pub enum ControllerError {
    #[error("invalid credential signature")]
    InvalidSignature,
    #[error("credential expired")]
    Expired,
    #[error("nonce already consumed (replay)")]
    NonceReused,
    #[error("signing key derivation failed")]
    KeyDerivationFailed,
    #[error("dataset not authorized: {0}")]
    DatasetNotAuthorized(u64),
    #[error("untrusted measurement: {0}")]
    UntrustedMeasurement(String),
}
