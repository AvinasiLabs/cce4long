pub mod local;
pub mod s3;

use async_trait::async_trait;
use thiserror::Error;

pub use local::LocalStorage;
pub use s3::S3Storage;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("IO error: {0}")]
    Io(String),
    #[error("S3 error: {0}")]
    S3(String),
}

#[async_trait]
pub trait Storage: Send + Sync {
    /// Store data under the given key. Returns the stored path/identifier.
    async fn put(&self, key: &str, data: &[u8]) -> Result<String, StorageError>;

    /// Retrieve data stored under the given key.
    async fn get(&self, key: &str) -> Result<Vec<u8>, StorageError>;

    /// List all keys under the given prefix.
    async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError>;
}
