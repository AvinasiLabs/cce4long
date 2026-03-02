use async_trait::async_trait;
use s3::creds::Credentials;
use s3::{Bucket, Region};

use super::{Storage, StorageError};

pub struct S3Storage {
    bucket: Box<Bucket>,
}

impl S3Storage {
    pub fn new(
        bucket_name: &str,
        region: &str,
        endpoint: &str,
        access_key: &str,
        secret_key: &str,
    ) -> Result<Self, StorageError> {
        let region = Region::Custom {
            region: region.into(),
            endpoint: endpoint.into(),
        };
        let credentials = Credentials::new(Some(access_key), Some(secret_key), None, None, None)
            .map_err(|e| StorageError::S3(e.to_string()))?;

        let bucket = Bucket::new(bucket_name, region, credentials)
            .map_err(|e| StorageError::S3(e.to_string()))?
            .with_path_style();

        Ok(Self {
            bucket: Box::new(*bucket),
        })
    }
}

#[async_trait]
impl Storage for S3Storage {
    async fn put(&self, key: &str, data: &[u8]) -> Result<String, StorageError> {
        let response = self
            .bucket
            .put_object(key, data)
            .await
            .map_err(|e| StorageError::S3(e.to_string()))?;

        let status = response.status_code();
        if status != 200 {
            return Err(StorageError::S3(format!(
                "S3 put_object returned status {}",
                status
            )));
        }

        let uri = format!("s3://{}/{}", self.bucket.name(), key);
        tracing::info!(
            key = key,
            status_code = status,
            size_bytes = data.len(),
            "S3 put_object succeeded"
        );
        Ok(uri)
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, StorageError> {
        let response = self
            .bucket
            .get_object(key)
            .await
            .map_err(|e| StorageError::S3(e.to_string()))?;

        let status = response.status_code();
        if status != 200 {
            return Err(StorageError::S3(format!(
                "S3 get_object returned status {}",
                status
            )));
        }
        Ok(response.to_vec())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        let results = self
            .bucket
            .list(prefix.to_string(), None)
            .await
            .map_err(|e| StorageError::S3(e.to_string()))?;

        let mut keys: Vec<String> = results
            .into_iter()
            .flat_map(|page| page.contents.into_iter().map(|obj| obj.key))
            .collect();
        keys.sort();
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_constructs_without_panic() {
        let storage = S3Storage::new(
            "test-bucket",
            "auto",
            "https://storage.googleapis.com",
            "GOOG_ACCESS_KEY",
            "SECRET_KEY",
        );
        assert!(storage.is_ok());
    }
}
