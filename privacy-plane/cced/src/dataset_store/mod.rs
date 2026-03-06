pub mod juicefs;
pub mod memory;

use async_trait::async_trait;
use key_manager::DatasetId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use juicefs::JuiceFsDatasetStore;
pub use memory::InMemoryDatasetStore;

#[derive(Debug, Error)]
pub enum DatasetStoreError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("backend error: {0}")]
    Backend(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

#[async_trait]
pub trait DatasetStore: Send + Sync {
    /// Store a file under dataset_id/path.
    async fn put_file(
        &self,
        id: &DatasetId,
        path: &str,
        data: &[u8],
    ) -> Result<(), DatasetStoreError>;

    /// Retrieve a file. Returns NotFound if the file doesn't exist.
    async fn get_file(
        &self,
        id: &DatasetId,
        path: &str,
    ) -> Result<Vec<u8>, DatasetStoreError>;

    /// List all data files under a dataset (relative paths, e.g. "data.csv.avin").
    async fn list_files(&self, id: &DatasetId) -> Result<Vec<String>, DatasetStoreError>;

    /// Get business metadata for a dataset. Returns None if no metadata exists.
    async fn get_meta(
        &self,
        id: &DatasetId,
    ) -> Result<Option<DatasetMeta>, DatasetStoreError>;

    /// Set business metadata for a dataset.
    async fn set_meta(
        &self,
        id: &DatasetId,
        meta: &DatasetMeta,
    ) -> Result<(), DatasetStoreError>;

    /// CVM storage access config — PP sends this via `/v1/keys/request` so the
    /// CVM can mount the object storage backend.
    fn storage_access_config(&self) -> serde_json::Value;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
