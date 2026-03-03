use thiserror::Error;

#[derive(Debug, Error)]
pub enum DecryptFsError {
    #[error("invalid AVIN format: {0}")]
    InvalidFormat(String),

    #[error("decryption failed")]
    DecryptionFailed,

    #[error("encryption failed")]
    EncryptionFailed,

    #[error("I/O error: {0}")]
    Io(String),

    #[error("dataset {0} not mounted")]
    NotMounted(u64),
}
