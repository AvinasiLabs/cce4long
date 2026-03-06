use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use key_manager::DatasetId;

use super::{DatasetMeta, DatasetStore, DatasetStoreError};

pub struct InMemoryDatasetStore {
    files: Mutex<HashMap<(DatasetId, String), Vec<u8>>>,
    metas: Mutex<HashMap<DatasetId, DatasetMeta>>,
}

impl Default for InMemoryDatasetStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryDatasetStore {
    pub fn new() -> Self {
        Self {
            files: Mutex::new(HashMap::new()),
            metas: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl DatasetStore for InMemoryDatasetStore {
    async fn put_file(
        &self,
        id: &DatasetId,
        path: &str,
        data: &[u8],
    ) -> Result<(), DatasetStoreError> {
        self.files
            .lock()
            .unwrap()
            .insert((*id, path.to_string()), data.to_vec());
        Ok(())
    }

    async fn get_file(
        &self,
        id: &DatasetId,
        path: &str,
    ) -> Result<Vec<u8>, DatasetStoreError> {
        self.files
            .lock()
            .unwrap()
            .get(&(*id, path.to_string()))
            .cloned()
            .ok_or_else(|| DatasetStoreError::NotFound(format!("{}/{}", id, path)))
    }

    async fn list_files(&self, id: &DatasetId) -> Result<Vec<String>, DatasetStoreError> {
        let files = self.files.lock().unwrap();
        let mut paths: Vec<String> = files
            .keys()
            .filter(|(ds_id, _)| ds_id == id)
            .map(|(_, path)| path.clone())
            .collect();
        paths.sort();
        Ok(paths)
    }

    async fn get_meta(
        &self,
        id: &DatasetId,
    ) -> Result<Option<DatasetMeta>, DatasetStoreError> {
        Ok(self.metas.lock().unwrap().get(id).cloned())
    }

    async fn set_meta(
        &self,
        id: &DatasetId,
        meta: &DatasetMeta,
    ) -> Result<(), DatasetStoreError> {
        self.metas.lock().unwrap().insert(*id, meta.clone());
        Ok(())
    }

    fn storage_access_config(&self) -> serde_json::Value {
        serde_json::json!({})
    }
}
