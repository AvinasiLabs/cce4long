use async_trait::async_trait;
use key_manager::DatasetId;
use redis::AsyncCommands;
use s3::creds::Credentials;
use s3::{Bucket, Region};

use super::{DatasetMeta, DatasetStore, DatasetStoreError};

pub struct JuiceFsDatasetStore {
    bucket: Box<Bucket>,
    redis: redis::aio::ConnectionManager,
    storage_routing: serde_json::Value,
}

impl JuiceFsDatasetStore {
    pub async fn new(
        bucket_name: &str,
        region: &str,
        endpoint: &str,
        access_key: &str,
        secret_key: &str,
        meta_url: &str,
        storage_routing: serde_json::Value,
    ) -> Result<Self, DatasetStoreError> {
        // S3 bucket
        let region = Region::Custom {
            region: region.into(),
            endpoint: endpoint.into(),
        };
        let credentials =
            Credentials::new(Some(access_key), Some(secret_key), None, None, None)
                .map_err(|e| DatasetStoreError::Backend(e.to_string()))?;
        let bucket = Bucket::new(bucket_name, region, credentials)
            .map_err(|e| DatasetStoreError::Backend(e.to_string()))?
            .with_path_style();

        // Redis — derive business DB from JuiceFS meta_url
        let redis_url = derive_business_redis_url(meta_url)?;
        let client = redis::Client::open(redis_url)
            .map_err(|e| DatasetStoreError::Backend(e.to_string()))?;
        let redis = client
            .get_connection_manager()
            .await
            .map_err(|e| DatasetStoreError::Backend(e.to_string()))?;

        Ok(Self {
            bucket: Box::new(*bucket),
            redis,
            storage_routing,
        })
    }
}

fn s3_key(id: &DatasetId, path: &str) -> String {
    format!("{}/{}", id, path)
}

fn redis_key(id: &DatasetId) -> String {
    format!("dataset:{}", id)
}

/// Derive a Redis URL for business metadata from the JuiceFS meta URL.
/// "redis://host:port/N" → "redis://host:port/(N+1)"
fn derive_business_redis_url(jfs_meta_url: &str) -> Result<String, DatasetStoreError> {
    // Find the last '/' that separates the DB number from the rest of the URL.
    // Expected format: "redis://host:port/N" or "redis://host:port"
    if let Some(slash_pos) = jfs_meta_url.rfind('/') {
        let after_slash = &jfs_meta_url[slash_pos + 1..];
        // Check if what's after the last slash is a DB number (digits only)
        if !after_slash.is_empty() && after_slash.chars().all(|c| c.is_ascii_digit()) {
            let db: u32 = after_slash
                .parse()
                .map_err(|e| DatasetStoreError::Backend(format!("invalid DB number: {}", e)))?;
            return Ok(format!("{}/{}", &jfs_meta_url[..slash_pos], db + 1));
        }
    }
    // No DB number found — append /1
    Ok(format!("{}/1", jfs_meta_url.trim_end_matches('/')))
}

#[async_trait]
impl DatasetStore for JuiceFsDatasetStore {
    async fn put_file(
        &self,
        id: &DatasetId,
        path: &str,
        data: &[u8],
    ) -> Result<(), DatasetStoreError> {
        let key = s3_key(id, path);
        let response = self
            .bucket
            .put_object(&key, data)
            .await
            .map_err(|e| DatasetStoreError::Backend(e.to_string()))?;

        let status = response.status_code();
        if status != 200 {
            return Err(DatasetStoreError::Backend(format!(
                "S3 put_object returned status {}",
                status
            )));
        }

        tracing::info!(
            key = key,
            status_code = status,
            size_bytes = data.len(),
            "put_file succeeded"
        );
        Ok(())
    }

    async fn get_file(
        &self,
        id: &DatasetId,
        path: &str,
    ) -> Result<Vec<u8>, DatasetStoreError> {
        let key = s3_key(id, path);
        let response = self
            .bucket
            .get_object(&key)
            .await
            .map_err(|e| DatasetStoreError::Backend(e.to_string()))?;

        let status = response.status_code();
        if status == 404 {
            return Err(DatasetStoreError::NotFound(key));
        }
        if status != 200 {
            return Err(DatasetStoreError::Backend(format!(
                "S3 get_object returned status {}",
                status
            )));
        }
        Ok(response.to_vec())
    }

    async fn list_files(&self, id: &DatasetId) -> Result<Vec<String>, DatasetStoreError> {
        let prefix = format!("{}/", id);
        let results = self
            .bucket
            .list(prefix.clone(), None)
            .await
            .map_err(|e| DatasetStoreError::Backend(e.to_string()))?;

        let mut paths: Vec<String> = results
            .into_iter()
            .flat_map(|page| page.contents.into_iter().map(|obj| obj.key))
            .filter_map(|key| key.strip_prefix(&prefix).map(|s| s.to_string()))
            .collect();
        paths.sort();
        Ok(paths)
    }

    async fn get_meta(
        &self,
        id: &DatasetId,
    ) -> Result<Option<DatasetMeta>, DatasetStoreError> {
        let key = redis_key(id);
        let mut conn = self.redis.clone();
        let val: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| DatasetStoreError::Backend(e.to_string()))?;

        match val {
            None => Ok(None),
            Some(json) => {
                let meta: DatasetMeta = serde_json::from_str(&json)
                    .map_err(|e| DatasetStoreError::Serialization(e.to_string()))?;
                Ok(Some(meta))
            }
        }
    }

    async fn set_meta(
        &self,
        id: &DatasetId,
        meta: &DatasetMeta,
    ) -> Result<(), DatasetStoreError> {
        let key = redis_key(id);
        let json = serde_json::to_string(meta)
            .map_err(|e| DatasetStoreError::Serialization(e.to_string()))?;
        let mut conn = self.redis.clone();
        conn.set::<_, _, ()>(&key, &json)
            .await
            .map_err(|e| DatasetStoreError::Backend(e.to_string()))?;
        Ok(())
    }

    fn storage_access_config(&self) -> serde_json::Value {
        self.storage_routing.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_business_redis_url_increments_db() {
        let url = derive_business_redis_url("redis://localhost:6379/1").unwrap();
        assert_eq!(url, "redis://localhost:6379/2");
    }

    #[test]
    fn derive_business_redis_url_no_db() {
        let url = derive_business_redis_url("redis://localhost:6379").unwrap();
        assert_eq!(url, "redis://localhost:6379/1");
    }

    #[test]
    fn derive_business_redis_url_with_db_zero() {
        let url = derive_business_redis_url("redis://localhost:6379/0").unwrap();
        assert_eq!(url, "redis://localhost:6379/1");
    }
}
