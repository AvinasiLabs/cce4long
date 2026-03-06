use std::sync::OnceLock;
use std::time::Duration;

use async_trait::async_trait;
use key_manager::DatasetId;
use key_manager::Key;
use tokio::process::Command;

use crate::decrypt::decrypt_avin;
use crate::error::DecryptFsError;

/// Backend that makes decrypted data available at a mount point.
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

    /// Set storage credentials received from the privacy plane.
    /// Called after acquire_keys, before mount. Default: no-op.
    fn set_storage_credentials(&self, _meta_url: &str, _access_key: &str, _secret_key: &str) {}
}

/// Mount backend that decrypts .avin files in-place,
/// writing plaintext files alongside them (stripping .avin extension).
pub struct InPlaceDecryptBackend;

#[async_trait]
impl MountBackend for InPlaceDecryptBackend {
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

struct JfsMountConfig {
    meta_url: String,
    access_key: String,
    secret_key: String,
}

/// JuiceFS mount backend: mounts a JuiceFS volume subdir, then decrypts .avin files.
///
/// Constructed empty; call `set_storage_credentials()` (from PP response) before `mount()`.
pub struct JuiceFsMountBackend {
    config: OnceLock<JfsMountConfig>,
}

impl Default for JuiceFsMountBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl JuiceFsMountBackend {
    pub fn new() -> Self {
        Self {
            config: OnceLock::new(),
        }
    }

    fn config(&self) -> &JfsMountConfig {
        self.config
            .get()
            .expect("JuiceFS config not set — call set_storage_credentials before mount")
    }
}

#[async_trait]
impl MountBackend for JuiceFsMountBackend {
    fn set_storage_credentials(&self, meta_url: &str, access_key: &str, secret_key: &str) {
        let _ = self.config.set(JfsMountConfig {
            meta_url: meta_url.to_string(),
            access_key: access_key.to_string(),
            secret_key: secret_key.to_string(),
        });
    }

    async fn mount(
        &self,
        dataset_id: &DatasetId,
        dek: &Key,
        mount_point: &str,
    ) -> Result<(), DecryptFsError> {
        let config = self.config();
        let jfs_mount = format!("/tmp/jfs_{dataset_id}");
        std::fs::create_dir_all(&jfs_mount)
            .map_err(|e| DecryptFsError::Io(format!("create {jfs_mount}: {e}")))?;
        std::fs::create_dir_all(mount_point)
            .map_err(|e| DecryptFsError::Io(format!("create {mount_point}: {e}")))?;

        let subdir = format!("/{dataset_id}");
        let mut child = Command::new("juicefs")
            .args([
                "mount", "-f", "--read-only",
                "--subdir", &subdir,
                "--cache-size", "4096",
                &config.meta_url, &jfs_mount,
            ])
            .env("ACCESS_KEY", &config.access_key)
            .env("SECRET_KEY", &config.secret_key)
            .spawn()
            .map_err(|e| DecryptFsError::Io(format!("spawn juicefs mount: {e}")))?;

        // Wait for the FUSE mount to become ready
        for _ in 0..30 {
            if let Some(status) = child
                .try_wait()
                .map_err(|e| DecryptFsError::Io(format!("juicefs wait: {e}")))?
            {
                return Err(DecryptFsError::Io(format!(
                    "juicefs mount exited with {status}"
                )));
            }
            let probe = std::path::Path::new(&jfs_mount).join(".");
            if std::fs::metadata(&probe).is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        decrypt_dir(&jfs_mount, mount_point, dek)
    }

    async fn unmount(&self, dataset_id: &DatasetId, _mount_point: &str) -> Result<(), DecryptFsError> {
        let jfs_mount = format!("/tmp/jfs_{dataset_id}");
        let status = Command::new("fusermount")
            .args(["-u", &jfs_mount])
            .status()
            .await
            .map_err(|e| DecryptFsError::Io(format!("fusermount: {e}")))?;
        if !status.success() {
            tracing::warn!("fusermount -u {jfs_mount} exited with {status}");
        }
        Ok(())
    }
}

/// Recursively decrypt .avin files from `src_dir` into `dst_dir`.
fn decrypt_dir(src_dir: &str, dst_dir: &str, dek: &Key) -> Result<(), DecryptFsError> {
    let entries = std::fs::read_dir(src_dir)
        .map_err(|e| DecryptFsError::Io(format!("{src_dir}: {e}")))?;

    for entry in entries {
        let entry = entry.map_err(|e| DecryptFsError::Io(e.to_string()))?;
        let path = entry.path();

        if path.is_dir() {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            let sub_dst = format!("{dst_dir}/{name}");
            std::fs::create_dir_all(&sub_dst)
                .map_err(|e| DecryptFsError::Io(format!("mkdir {sub_dst}: {e}")))?;
            decrypt_dir(path.to_str().unwrap_or_default(), &sub_dst, dek)?;
            continue;
        }

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

        let stem = path.file_stem().unwrap_or_default();
        let dst_path = format!("{dst_dir}/{}", stem.to_string_lossy());
        std::fs::write(&dst_path, plaintext)
            .map_err(|e| DecryptFsError::Io(format!("{dst_path}: {e}")))?;
    }

    Ok(())
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
        let encrypted = encrypt_avin(&dek, plaintext).unwrap();
        fs::write(dir.join("data.avin"), &encrypted).unwrap();

        let backend = InPlaceDecryptBackend;
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
        fs::write(dir.join("file1.avin"), encrypt_avin(&dek, b"content-1").unwrap()).unwrap();
        fs::write(dir.join("file2.avin"), encrypt_avin(&dek, b"content-2").unwrap()).unwrap();

        let backend = InPlaceDecryptBackend;
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
        fs::write(dir.join("data.avin"), encrypt_avin(&dek, b"encrypted").unwrap()).unwrap();
        fs::write(dir.join("readme.txt"), b"not encrypted").unwrap();

        let backend = InPlaceDecryptBackend;
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

        let backend = InPlaceDecryptBackend;
        backend
            .mount(&test_id(0x01), &test_key(), tmp.path().to_str().unwrap())
            .await
            .unwrap();

        assert_eq!(fs::read_dir(tmp.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn dev_unmount_is_noop() {
        let backend = InPlaceDecryptBackend;
        backend.unmount(&test_id(0x01), "/nonexistent").await.unwrap();
    }
}
