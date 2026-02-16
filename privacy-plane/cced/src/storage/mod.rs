pub mod local;

use async_trait::async_trait;
use thiserror::Error;

pub use local::LocalStorage;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("IO error: {0}")]
    Io(String),
}

#[async_trait]
pub trait Storage: Send + Sync {
    /// Store data under the given key. Returns the stored path/identifier.
    async fn put(&self, key: &str, data: &[u8]) -> Result<String, StorageError>;
}
