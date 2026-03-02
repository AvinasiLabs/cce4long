use std::path::{Path, PathBuf};

use async_trait::async_trait;

use super::{Storage, StorageError};

pub struct LocalStorage {
    dir: PathBuf,
}

impl LocalStorage {
    pub fn new(dir: impl AsRef<Path>) -> Self {
        Self {
            dir: dir.as_ref().to_path_buf(),
        }
    }
}

#[async_trait]
impl Storage for LocalStorage {
    async fn put(&self, key: &str, data: &[u8]) -> Result<String, StorageError> {
        let path = self.dir.join(key);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| StorageError::Io(e.to_string()))?;
        }
        tokio::fs::write(&path, data)
            .await
            .map_err(|e| StorageError::Io(e.to_string()))?;
        let stored = path.to_string_lossy().into_owned();
        tracing::info!(
            key = key,
            path = %stored,
            size_bytes = data.len(),
            "local put succeeded"
        );
        Ok(stored)
    }
}
