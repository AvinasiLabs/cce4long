use std::collections::HashMap;

use key_manager::Key;

use crate::error::DecryptFsError;
use crate::mount::MountBackend;

/// Manages mounted datasets — pure lifecycle manager.
///
/// In prod, each mount spawns JuiceFS + Decrypt FUSE processes.
/// In dev, each mount decrypts .avin files to plaintext in the directory.
/// Either way, the algorithm reads plaintext via standard POSIX I/O.
pub struct DecryptFs<M: MountBackend> {
    backend: M,
    mounts: HashMap<u64, String>, // dataset_id → mount_point
}

impl<M: MountBackend> DecryptFs<M> {
    pub fn new(backend: M) -> Self {
        Self {
            backend,
            mounts: HashMap::new(),
        }
    }

    /// Mount a dataset, making plaintext available at the given path.
    pub async fn mount(
        &mut self,
        dataset_id: u64,
        dek: Key,
        mount_point: String,
    ) -> Result<(), DecryptFsError> {
        self.backend.mount(dataset_id, &dek, &mount_point).await?;
        self.mounts.insert(dataset_id, mount_point);
        Ok(())
    }

    /// Unmount a single dataset.
    pub async fn unmount(&mut self, dataset_id: u64) -> Result<(), DecryptFsError> {
        if let Some(mount_point) = self.mounts.remove(&dataset_id) {
            self.backend.unmount(dataset_id, &mount_point).await?;
        }
        Ok(())
    }

    /// Unmount all datasets.
    pub async fn cleanup(&mut self) {
        let entries: Vec<(u64, String)> = self.mounts.drain().collect();
        for (dataset_id, mount_point) in entries {
            let _ = self.backend.unmount(dataset_id, &mount_point).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decrypt::encrypt_avin;
    use crate::mount::DevMountBackend;
    use std::fs;

    fn test_key(val: u8) -> Key {
        Key([val; 32])
    }

    #[tokio::test]
    async fn mount_makes_plaintext_available() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();

        let dek = test_key(0x42);
        let plaintext = b"decrypted content here";
        let encrypted = encrypt_avin(&dek, plaintext);
        fs::write(tmp.path().join("data.avin"), &encrypted).unwrap();

        let mut dfs = DecryptFs::new(DevMountBackend);
        dfs.mount(1, dek, dir).await.unwrap();

        // After mount, plaintext file should be readable directly
        let result = fs::read(tmp.path().join("data")).unwrap();
        assert_eq!(result, plaintext);
    }

    #[tokio::test]
    async fn mount_unmount_lifecycle() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();
        let dek = test_key(0x42);

        let mut dfs = DecryptFs::new(DevMountBackend);
        dfs.mount(1, dek, dir).await.unwrap();
        assert!(dfs.mounts.contains_key(&1));

        dfs.unmount(1).await.unwrap();
        assert!(!dfs.mounts.contains_key(&1));
    }

    #[tokio::test]
    async fn multiple_datasets() {
        let tmp1 = tempfile::tempdir().unwrap();
        let tmp2 = tempfile::tempdir().unwrap();

        let dek1 = test_key(0x11);
        let dek2 = test_key(0x22);

        fs::write(
            tmp1.path().join("file1.avin"),
            encrypt_avin(&dek1, b"data-from-dataset-1"),
        )
        .unwrap();
        fs::write(
            tmp2.path().join("file2.avin"),
            encrypt_avin(&dek2, b"data-from-dataset-2"),
        )
        .unwrap();

        let mut dfs = DecryptFs::new(DevMountBackend);
        dfs.mount(1, dek1, tmp1.path().to_str().unwrap().to_string())
            .await
            .unwrap();
        dfs.mount(2, dek2, tmp2.path().to_str().unwrap().to_string())
            .await
            .unwrap();

        // Plaintext readable directly from filesystem
        assert_eq!(
            fs::read(tmp1.path().join("file1")).unwrap(),
            b"data-from-dataset-1"
        );
        assert_eq!(
            fs::read(tmp2.path().join("file2")).unwrap(),
            b"data-from-dataset-2"
        );
    }

    #[tokio::test]
    async fn cleanup_removes_all_mounts() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_str().unwrap().to_string();

        let mut dfs = DecryptFs::new(DevMountBackend);
        dfs.mount(1, test_key(0x11), dir.clone()).await.unwrap();
        dfs.mount(2, test_key(0x22), dir).await.unwrap();

        dfs.cleanup().await;
        assert!(dfs.mounts.is_empty());
    }
}
