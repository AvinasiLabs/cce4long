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

    async fn get(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        let path = self.dir.join(key);
        tokio::fs::read(&path)
            .await
            .map_err(|e| StorageError::Io(e.to_string()))
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        let search_dir = self.dir.join(prefix);
        if !search_dir.exists() {
            return Ok(Vec::new());
        }
        let mut keys = Vec::new();
        let mut stack = vec![search_dir];
        while let Some(dir) = stack.pop() {
            let mut entries = tokio::fs::read_dir(&dir)
                .await
                .map_err(|e| StorageError::Io(e.to_string()))?;
            while let Some(entry) = entries
                .next_entry()
                .await
                .map_err(|e| StorageError::Io(e.to_string()))?
            {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if let Ok(rel) = path.strip_prefix(&self.dir) {
                    keys.push(rel.to_string_lossy().into_owned());
                }
            }
        }
        keys.sort();
        Ok(keys)
    }
}
