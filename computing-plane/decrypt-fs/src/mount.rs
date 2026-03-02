use async_trait::async_trait;
use key_manager::DatasetId;
use key_manager::Key;

use crate::decrypt::decrypt_avin;
use crate::error::DecryptFsError;

/// Backend that makes decrypted data available at a mount point.
///
/// Dev mode: decrypts .avin files and writes plaintext to the directory.
/// Prod mode: spawns JuiceFS + Decrypt FUSE processes.
#[async_trait]
pub trait MountBackend: Send + Sync {
    /// Mount a dataset, making plaintext available at `mount_point`.
    async fn mount(
        &self,
        dataset_id: &DatasetId,
        dek: &Key,
        mount_point: &str,
    ) -> Result<(), DecryptFsError>;

    /// Unmount a dataset.
    async fn unmount(&self, dataset_id: &DatasetId, mount_point: &str) -> Result<(), DecryptFsError>;
}

/// Dev-mode mount backend: decrypts .avin files in-place,
/// writing plaintext files alongside them (stripping .avin extension).
pub struct DevMountBackend;

#[async_trait]
impl MountBackend for DevMountBackend {
    async fn mount(
        &self,
        _dataset_id: &DatasetId,
        dek: &Key,
        mount_point: &str,
    ) -> Result<(), DecryptFsError> {
        let entries = std::fs::read_dir(mount_point)
            .map_err(|e| DecryptFsError::Io(format!("{mount_point}: {e}")))?;

        for entry in entries {
            let entry = entry.map_err(|e| DecryptFsError::Io(e.to_string()))?;
            let path = entry.path();

            if !path.is_file() {
                continue;
            }

            let is_avin = path.extension().is_some_and(|ext| ext == "avin");
            if !is_avin {
                continue;
            }

            let raw = std::fs::read(&path)
                .map_err(|e| DecryptFsError::Io(format!("{}: {e}", path.display())))?;
            let plaintext = decrypt_avin(dek, &raw)?;

            // Write plaintext file without .avin extension
            let stem = path.file_stem().unwrap_or_default();
            let plaintext_path = path.with_file_name(stem);
            std::fs::write(&plaintext_path, plaintext)
                .map_err(|e| DecryptFsError::Io(format!("{}: {e}", plaintext_path.display())))?;
        }

        Ok(())
    }

    async fn unmount(&self, _dataset_id: &DatasetId, _mount_point: &str) -> Result<(), DecryptFsError> {
        // Dev mode: nothing to unmount (temp dirs handle cleanup)
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decrypt::encrypt_avin;
    use std::fs;

    fn test_key() -> Key {
        Key([0x42; 32])
    }

    fn test_id(val: u8) -> DatasetId {
        DatasetId::from([val; 20])
    }

    #[tokio::test]
    async fn dev_mount_decrypts_avin_files() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        let dek = test_key();
        let plaintext = b"hello decrypted world";
        let encrypted = encrypt_avin(&dek, plaintext);
        fs::write(dir.join("data.avin"), &encrypted).unwrap();

        let backend = DevMountBackend;
        backend
            .mount(&test_id(0x01), &dek, dir.to_str().unwrap())
            .await
            .unwrap();

        // Plaintext file should exist without .avin extension
        let result = fs::read(dir.join("data")).unwrap();
        assert_eq!(result, plaintext);
    }

    #[tokio::test]
    async fn dev_mount_multiple_avin_files() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        let dek = test_key();
        fs::write(dir.join("file1.avin"), encrypt_avin(&dek, b"content-1")).unwrap();
        fs::write(dir.join("file2.avin"), encrypt_avin(&dek, b"content-2")).unwrap();

        let backend = DevMountBackend;
        backend
            .mount(&test_id(0x01), &dek, dir.to_str().unwrap())
            .await
            .unwrap();

        assert_eq!(fs::read(dir.join("file1")).unwrap(), b"content-1");
        assert_eq!(fs::read(dir.join("file2")).unwrap(), b"content-2");
    }

    #[tokio::test]
    async fn dev_mount_skips_non_avin_files() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        let dek = test_key();
        fs::write(dir.join("data.avin"), encrypt_avin(&dek, b"encrypted")).unwrap();
        fs::write(dir.join("readme.txt"), b"not encrypted").unwrap();

        let backend = DevMountBackend;
        backend
            .mount(&test_id(0x01), &dek, dir.to_str().unwrap())
            .await
            .unwrap();

        assert_eq!(fs::read(dir.join("data")).unwrap(), b"encrypted");
        assert_eq!(fs::read(dir.join("readme.txt")).unwrap(), b"not encrypted");
    }

    #[tokio::test]
    async fn dev_mount_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();

        let backend = DevMountBackend;
        backend
            .mount(&test_id(0x01), &test_key(), tmp.path().to_str().unwrap())
            .await
            .unwrap();

        assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn dev_unmount_is_noop() {
        let backend = DevMountBackend;
        backend.unmount(&test_id(0x01), "/nonexistent").await.unwrap();
    }
}
