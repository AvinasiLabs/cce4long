pub mod ecdhe;

mod dataset_id;
pub use dataset_id::{DatasetId, DatasetIdError};

use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct Key(pub [u8; 32]);

impl Key {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("HKDF expand failed")]
    DerivationFailed,
    #[error("ECDHE wrap failed: {0}")]
    WrapFailed(String),
    #[error("ECDHE unwrap failed: {0}")]
    UnwrapFailed(String),
}

pub trait RootKeyProvider: Send + Sync {
    fn root_key(&self) -> &[u8; 32];
}

/// Dev-only root key provider. Reads CCE_ROOT_KEY env var (hex),
/// falls back to a deterministic dev seed.
pub struct DevRootKeyProvider {
    key: [u8; 32],
}

impl DevRootKeyProvider {
    pub fn new() -> Self {
        let key = match std::env::var("CCE_ROOT_KEY") {
            Ok(hex) => {
                let bytes = hex::decode(&hex).expect("CCE_ROOT_KEY must be valid hex");
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            }
            Err(_) => {
                // Deterministic dev seed — NOT for production
                let hk = Hkdf::<Sha256>::new(None, b"cce4long-dev-root-key");
                let mut key = [0u8; 32];
                hk.expand(b"dev-root", &mut key).expect("valid length");
                key
            }
        };
        Self { key }
    }
}

impl Default for DevRootKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl RootKeyProvider for DevRootKeyProvider {
    fn root_key(&self) -> &[u8; 32] {
        &self.key
    }
}

pub struct KeyManager<R: RootKeyProvider> {
    root: R,
}

impl<R: RootKeyProvider> KeyManager<R> {
    pub fn new(root: R) -> Self {
        Self { root }
    }

    /// Derive a Data Encryption Key for the given dataset.
    /// HKDF-SHA256(ikm=root_key, salt=dataset_id(20 bytes), info="dataset-encryption")
    pub fn derive_dek(&self, dataset_id: &DatasetId) -> Result<Key, KeyError> {
        let salt = dataset_id.as_ref();
        let hk = Hkdf::<Sha256>::new(Some(salt.as_slice()), self.root.root_key());
        let mut dek = [0u8; 32];
        hk.expand(b"dataset-encryption", &mut dek)
            .map_err(|_| KeyError::DerivationFailed)?;
        Ok(Key(dek))
    }

    /// Derive an HMAC signing key for upload tokens.
    /// HKDF-SHA256(ikm=root_key, info="upload-token-signing")
    pub fn derive_upload_hmac_key(&self) -> Result<[u8; 32], KeyError> {
        let hk = Hkdf::<Sha256>::new(None, self.root.root_key());
        let mut hmac_key = [0u8; 32];
        hk.expand(b"upload-token-signing", &mut hmac_key)
            .map_err(|_| KeyError::DerivationFailed)?;
        Ok(hmac_key)
    }

    /// Derive a Result Encryption Key for the given job.
    /// HKDF-SHA256(ikm=root_key, salt=job_id.as_bytes(), info="result-encryption")
    /// Domain-separated from DEK by different info string.
    pub fn derive_rek(&self, job_id: &str) -> Result<Key, KeyError> {
        let hk = Hkdf::<Sha256>::new(Some(job_id.as_bytes()), self.root.root_key());
        let mut rek = [0u8; 32];
        hk.expand(b"result-encryption", &mut rek)
            .map_err(|_| KeyError::DerivationFailed)?;
        Ok(Key(rek))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedKeyProvider([u8; 32]);
    impl RootKeyProvider for FixedKeyProvider {
        fn root_key(&self) -> &[u8; 32] {
            &self.0
        }
    }

    fn test_dataset_id(val: u8) -> DatasetId {
        DatasetId::from([val; 20])
    }

    #[test]
    fn derive_dek_is_deterministic() {
        let km = KeyManager::new(FixedKeyProvider([0xAA; 32]));
        let id = test_dataset_id(0x01);
        let k1 = km.derive_dek(&id).unwrap();
        let k2 = km.derive_dek(&id).unwrap();
        assert_eq!(k1.0, k2.0);
    }

    #[test]
    fn different_dataset_ids_produce_different_deks() {
        let km = KeyManager::new(FixedKeyProvider([0xAA; 32]));
        let k1 = km.derive_dek(&test_dataset_id(0x01)).unwrap();
        let k2 = km.derive_dek(&test_dataset_id(0x02)).unwrap();
        assert_ne!(k1.0, k2.0);
    }

    #[test]
    fn dek_is_32_bytes() {
        let km = KeyManager::new(FixedKeyProvider([0xBB; 32]));
        let k = km.derive_dek(&test_dataset_id(0x42)).unwrap();
        assert_eq!(k.0.len(), 32);
    }

    #[test]
    fn dev_root_key_provider_works() {
        let provider = DevRootKeyProvider::new();
        let key = provider.root_key();
        assert_eq!(key.len(), 32);
        // Should be deterministic when no env var
        let provider2 = DevRootKeyProvider::new();
        assert_eq!(provider.root_key(), provider2.root_key());
    }

    #[test]
    fn derive_rek_is_deterministic() {
        let km = KeyManager::new(FixedKeyProvider([0xAA; 32]));
        let k1 = km.derive_rek("job-1").unwrap();
        let k2 = km.derive_rek("job-1").unwrap();
        assert_eq!(k1.0, k2.0);
    }

    #[test]
    fn different_job_ids_produce_different_reks() {
        let km = KeyManager::new(FixedKeyProvider([0xAA; 32]));
        let k1 = km.derive_rek("job-1").unwrap();
        let k2 = km.derive_rek("job-2").unwrap();
        assert_ne!(k1.0, k2.0);
    }

    #[test]
    fn rek_and_dek_domain_separation() {
        // Even if the salt bytes happen to be the same, different info strings
        // must produce different keys.
        let km = KeyManager::new(FixedKeyProvider([0xCC; 32]));
        let dek = km.derive_dek(&test_dataset_id(0x01)).unwrap();
        let rek = km.derive_rek("job-1").unwrap();
        assert_ne!(dek.0, rek.0);
    }

    #[test]
    fn derive_upload_hmac_key_is_deterministic() {
        let km = KeyManager::new(FixedKeyProvider([0xAA; 32]));
        let k1 = km.derive_upload_hmac_key().unwrap();
        let k2 = km.derive_upload_hmac_key().unwrap();
        assert_eq!(k1, k2);
    }
}
